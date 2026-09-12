"""Scheduler service: evaluates cron schedules and triggers repo scans."""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter
from sqlalchemy import delete, func, select

from app.core.config import settings as app_settings
from app.models import (
    FindingRecord,
    PasswordResetToken,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    RiskRecord,
    ScanTrigger,
    SystemSetting,
    utcnow,
)
from app.services.finding_lifecycle import DEFAULT_FINDING_RETENTION, parse_int
from app.services.password_reset import RESET_TOKEN_PRUNE_GRACE_HOURS

logger = logging.getLogger(__name__)

# Scans running longer than this are considered stuck
STUCK_SCAN_TIMEOUT_MINUTES = 30


# ── Cron evaluation ───────────────────────────────────────────────────────────

def _resolve_tz(tz_str: str | None) -> ZoneInfo:
    """Return a ZoneInfo for tz_str, falling back to UTC for unknown/None values."""
    if not tz_str:
        return ZoneInfo("UTC")
    try:
        return ZoneInfo(tz_str)
    except ZoneInfoNotFoundError:
        logger.warning("unknown timezone %r — falling back to UTC", tz_str)
        return ZoneInfo("UTC")


def next_run_after(cron_expression: str, after: datetime, tz: ZoneInfo | None = None) -> datetime:
    """Return the next scheduled run time for `cron_expression` after `after`.

    `tz` controls the timezone in which the cron expression is evaluated.
    Defaults to UTC when None.
    """
    tz = tz or ZoneInfo("UTC")
    # Evaluate the cron expression in the target timezone
    after_local = after.astimezone(tz).replace(tzinfo=None)
    it = croniter(cron_expression, after_local)
    nxt_local = it.get_next(datetime)
    # Attach the zone and convert back to UTC
    return nxt_local.replace(tzinfo=tz).astimezone(UTC)


# After a failed launch, wait this long before retrying — independent of
# the cron schedule, so a transient failure on an infrequent cron (e.g.
# weekly) doesn't sit unretried for a week, and so a persistently failing
# launch (a bad setting, an outage) doesn't retry on every single poll tick.
FAILED_LAUNCH_BACKOFF_MINUTES = 10


def is_due(cron_expression: str, since: datetime, now: datetime, tz: ZoneInfo | None = None) -> bool:
    """Return True if the cron schedule has a due occurrence between `since` and `now`.

    `since` must be a real point in time to compute the next occurrence
    from — the scan's creation time if it has never completed a run. There
    is no "always due" case: a schedule like `0 7 * * 1` must wait for its
    own next Monday-07:00 occurrence, even for a scan created seconds ago.
    """
    nxt = next_run_after(cron_expression, since, tz)
    return nxt <= now


def should_trigger_scan(
    scan: Any,
    now: datetime,
    default_tz: ZoneInfo | None = None,
    last_failed_at: datetime | None = None,
) -> bool:
    """Return True if `scan` should be triggered at `now`.

    `last_failed_at` is when the most recent *failed* launch attempt for
    this scan was recorded as failed — `RepoScanResult.completed_at`,
    falling back to `started_at` (see `run_one_tick`). completed_at, not
    started_at, is what the backoff window must count from: started_at is
    stamped before the launch attempt even begins, so a launch that hangs
    longer than FAILED_LAUNCH_BACKOFF_MINUTES before finally raising would
    already be past its own backoff window the instant the failure is
    written, letting it retry on the very next tick regardless. It is
    intentionally not `scan.last_scan_at` — that field is only set on
    success, so relying on it alone would let a failing launch retry on
    every single poll tick forever, with no backoff, until it happens to
    succeed.
    """
    if not scan.is_enabled:
        return False
    if not scan.cron_schedule:
        return False
    if last_failed_at is not None:
        backoff_until = last_failed_at + timedelta(minutes=FAILED_LAUNCH_BACKOFF_MINUTES)
        if now < backoff_until:
            return False
    tz = _resolve_tz(scan.cron_timezone) if scan.cron_timezone else default_tz
    # The anchor must be the *later* of last_scan_at and enabled_at, not
    # just "prefer last_scan_at" — a scan disabled through one or more
    # scheduled occurrences and then re-enabled has a last_scan_at from
    # before that gap, which is older than enabled_at and would make it
    # look overdue and fire immediately on the next tick. enabled_at alone
    # (not created_at) covers a scan that has never had a successful run —
    # a scan created disabled, or re-enabled before ever completing one,
    # must wait for its next occurrence from when it actually became
    # enabled, since created_at would already be in the past for any
    # missed window. Falling back to created_at only covers scans that
    # predate the enabled_at column and somehow missed the migration's
    # backfill.
    candidates = [t for t in (scan.last_scan_at, scan.enabled_at) if t is not None]
    since = max(candidates) if candidates else scan.created_at
    return is_due(scan.cron_schedule, since, now, tz)


# ── Lock helpers ──────────────────────────────────────────────────────────────

async def _acquire_scan_lock(scan_id: int) -> bool:
    if not app_settings.valkey_url:
        return True
    from app.core.valkey import acquire_lock, get_valkey
    r = get_valkey(app_settings.valkey_url)
    try:
        return await acquire_lock(r, f"repo_scan:{scan_id}:lock", ttl_seconds=3600)
    finally:
        await r.aclose()


async def _release_scan_lock(scan_id: int) -> None:
    if not app_settings.valkey_url:
        return
    from app.core.valkey import get_valkey, release_lock
    r = get_valkey(app_settings.valkey_url)
    try:
        await release_lock(r, f"repo_scan:{scan_id}:lock")
    finally:
        await r.aclose()


# ── Task launch (ECS or local Docker) ────────────────────────────────────────

async def _launch_ecs_task(scan: Any, result_id: int, credential: Any = None) -> str:
    from app.core.aws import EcsClient, build_scan_task_env
    env = await build_scan_task_env(scan, result_id, credential)

    if app_settings.local_docker_scan:
        from app.core.docker_runner import run_local_scan
        return await run_local_scan(
            app_settings.scan_task_image, env, app_settings.resolved_scan_task_fleet_url
        )

    client = EcsClient(region_name=app_settings.aws_region)
    return await client.run_scan_task(
        cluster_arn=app_settings.ecs_cluster_arn,
        task_definition_arn=app_settings.scan_task_definition_arn,
        subnet_ids=[s for s in app_settings.scan_task_subnet_ids.split(",") if s],
        security_group_ids=[s for s in app_settings.scan_task_security_group_ids.split(",") if s],
        environment=env,
    )


# ── Trigger a single scan ─────────────────────────────────────────────────────

async def trigger_scan(scan: Any, db_factory: Any) -> None:
    """Acquire lock, create a RepoScanResult row, and launch the ECS task."""
    acquired = await _acquire_scan_lock(scan.id)
    if not acquired:
        logger.info("scan %d already in progress — skipping", scan.id)
        return

    async with db_factory() as session:
        from app.models import RepoCredential
        # Re-fetch inside this session so SQLAlchemy tracks mutations on the object.
        tracked_scan = await session.get(RepoScan, scan.id)
        if not tracked_scan:
            await _release_scan_lock(scan.id)
            return
        credential = await session.get(RepoCredential, tracked_scan.credential_id) if tracked_scan.credential_id else None

        result = RepoScanResult(
            repo_scan_id=tracked_scan.id,
            status=RepoScanStatus.running,
            triggered_by=ScanTrigger.scheduled,
            started_at=utcnow(),
            scan_config_hash=tracked_scan.scan_config_hash,
        )
        session.add(result)
        await session.flush()
        await session.refresh(result)

        try:
            task_arn = await _launch_ecs_task(tracked_scan, result.id, credential)
            result.ecs_task_arn = task_arn
            tracked_scan.last_scan_at = utcnow()
            await session.commit()
            # Lock is intentionally NOT released here — it is held until the scan
            # task posts its result to ingest_repo_scan_result (or recover_stuck_scans
            # expires it), preventing overlapping runs while the task is in flight.
            logger.info("launched ECS task %s for scan %d result %d", task_arn, tracked_scan.id, result.id)
        except Exception as exc:  # noqa: BLE001
            result.status = RepoScanStatus.failed
            result.error_message = str(exc)
            result.completed_at = utcnow()
            await session.commit()
            # Task never started — release lock now since ingest will never be called.
            await _release_scan_lock(tracked_scan.id)
            logger.error("failed to launch ECS task for scan %d: %s", tracked_scan.id, exc)


# ── Main tick ─────────────────────────────────────────────────────────────────

async def run_one_tick(db_factory: Any) -> None:
    """Load all enabled scans, trigger those that are due."""
    now = utcnow()
    async with db_factory() as session:
        rows = await session.execute(select(RepoScan))
        scans = rows.scalars().all()
        tz_setting = await session.get(SystemSetting, "default_cron_timezone")
        default_tz = _resolve_tz(tz_setting.value if tz_setting else None)

        # Only scans that could actually be triggered this tick need a
        # backoff lookup — should_trigger_scan already returns False before
        # reaching it for anything disabled or scheduleless. Restricting the
        # window query to these scans keeps it bounded by the number of
        # active schedules rather than the whole (ever-growing) results
        # table, which run_one_tick otherwise scans in full every poll tick.
        # Filtered via IN (SELECT ...) against RepoScan directly rather than
        # an IN-list of literal ids: a literal list needs one bind parameter
        # per candidate scan, which can exceed the driver's bind-parameter
        # ceiling (SQLite's default is 32766) once the fleet has enough
        # active schedules — at that point every tick would fail outright
        # instead of launching anything. The subquery form has no such
        # ceiling regardless of candidate count.
        has_candidate_scans = any(s.is_enabled and s.cron_schedule for s in scans)

        last_failed_attempt_by_scan: dict[int, datetime] = {}
        if has_candidate_scans:
            # Details of each candidate scan's most recent result, keyed by
            # scan — needed to tell whether that most recent attempt was a
            # launch failure (see should_trigger_scan's
            # last_failed_at docstring). A plain MAX(started_at)
            # WHERE status='failed' would be wrong here: if a scan failed
            # and then later succeeded, that query would still return the
            # old failure and incorrectly hold the scan in backoff even
            # though its most recent attempt actually succeeded. Ranking is
            # still by started_at (identifies which result is the most
            # recent *attempt*, regardless of outcome) — but the timestamp
            # used for the backoff window itself must be completed_at, when
            # the failure was actually recorded. A launch that hangs for
            # longer than FAILED_LAUNCH_BACKOFF_MINUTES before raising would
            # otherwise already be past its own backoff window the instant
            # the failure is written, since started_at predates the launch
            # attempt entirely. started_at is kept as a fallback for a
            # failed result that somehow has no completed_at.
            result_rank = (
                func.row_number()
                .over(
                    partition_by=RepoScanResult.repo_scan_id,
                    order_by=(RepoScanResult.started_at.desc(), RepoScanResult.id.desc()),
                )
                .label("rank")
            )
            ranked_results = (
                select(
                    RepoScanResult.repo_scan_id,
                    RepoScanResult.status,
                    RepoScanResult.started_at,
                    RepoScanResult.completed_at,
                    result_rank,
                )
                .where(
                    RepoScanResult.repo_scan_id.in_(
                        select(RepoScan.id).where(
                            RepoScan.is_enabled.is_(True),
                            # Must match should_trigger_scan's `if not
                            # scan.cron_schedule: return False` exactly —
                            # that's falsy for both NULL and "" (the API
                            # schema allows cron_schedule="" through as a
                            # plain str | None with no validator rejecting
                            # it). Excluding only NULL here would rank
                            # every enabled scan with an empty schedule too,
                            # re-creating the full-table cost this filter
                            # exists to avoid once such scans have
                            # substantial manual-trigger history.
                            RepoScan.cron_schedule.isnot(None),
                            RepoScan.cron_schedule != "",
                        )
                    )
                )
                .subquery()
            )
            latest_rows = await session.execute(
                select(
                    ranked_results.c.repo_scan_id,
                    ranked_results.c.status,
                    ranked_results.c.started_at,
                    ranked_results.c.completed_at,
                )
                .where(ranked_results.c.rank == 1)
            )
            last_failed_attempt_by_scan = {
                scan_id: completed_at or started_at
                for scan_id, status, started_at, completed_at in latest_rows
                if status == RepoScanStatus.failed
            }

    for scan in scans:
        if should_trigger_scan(scan, now, default_tz, last_failed_attempt_by_scan.get(scan.id)):
            await trigger_scan(scan, db_factory)


# ── Stuck job recovery ────────────────────────────────────────────────────────

async def recover_stuck_scans(db_factory: Any) -> None:
    """Mark running results older than STUCK_SCAN_TIMEOUT_MINUTES as failed."""
    cutoff = utcnow() - timedelta(minutes=STUCK_SCAN_TIMEOUT_MINUTES)
    async with db_factory() as session:
        rows = await session.execute(
            select(RepoScanResult).where(
                RepoScanResult.status == RepoScanStatus.running,
                RepoScanResult.started_at < cutoff,
            )
        )
        stuck = rows.scalars().all()
        for result in stuck:
            logger.warning("marking stuck scan result %d as failed", result.id)
            result.status = RepoScanStatus.failed
            result.error_message = "Scan timed out (stuck job recovery)"
            result.completed_at = utcnow()
            await _release_scan_lock(result.repo_scan_id)
        if stuck:
            await session.commit()


# ── Result retention pruning ──────────────────────────────────────────────────

async def prune_old_results(db_factory: Any) -> None:
    """Delete scan results beyond configured retention limits."""
    async with db_factory() as session:
        rows = await session.execute(select(SystemSetting))
        settings = {s.key: s.value for s in rows.scalars().all()}

    retention_days = settings.get("scan_result_retention_days")
    retention_count = settings.get("scan_result_retention_count")

    async with db_factory() as session:
        if retention_days:
            try:
                days = int(retention_days)
            except (TypeError, ValueError):
                days = None
            # days == 0 intentionally disables day-based retention; a negative
            # value would compute a cutoff in the future and delete every
            # historical result, so it's treated the same as absent/invalid
            # rather than acted on. Write-time validation (system_settings.py)
            # already rejects negative values — this is defense in depth.
            if days is not None and days > 0:
                cutoff = utcnow() - timedelta(days=days)
                rows = await session.execute(
                    select(RepoScanResult).where(RepoScanResult.started_at < cutoff)
                )
                for old in rows.scalars().all():
                    await session.delete(old)

        if retention_count:
            try:
                keep = int(retention_count)
            except (TypeError, ValueError):
                keep = None
            if keep and keep > 0:
                # For each scan, delete results beyond the most recent `keep` rows.
                scan_id_rows = await session.execute(
                    select(RepoScanResult.repo_scan_id).distinct()
                )
                for (scan_id,) in scan_id_rows.all():
                    cutoff_row = await session.execute(
                        select(RepoScanResult.id)
                        .where(RepoScanResult.repo_scan_id == scan_id)
                        .order_by(RepoScanResult.started_at.desc())
                        .offset(keep)
                        .limit(1)
                    )
                    oldest_kept_id = cutoff_row.scalar_one_or_none()
                    if oldest_kept_id is not None:
                        excess = await session.execute(
                            select(RepoScanResult).where(
                                RepoScanResult.repo_scan_id == scan_id,
                                RepoScanResult.id <= oldest_kept_id,
                            )
                        )
                        for old in excess.scalars().all():
                            await session.delete(old)

        # Purge old closed finding records
        finding_days = parse_int(settings.get("finding_retention_days"), DEFAULT_FINDING_RETENTION)
        finding_cutoff = utcnow() - timedelta(days=finding_days)
        await session.execute(
            delete(FindingRecord)
            .where(FindingRecord.closed_at.isnot(None))
            .where(FindingRecord.closed_at < finding_cutoff)
        )

        # Purge old closed risk records — mirrors the FindingRecord retention
        # policy above using the same finding_retention_days setting (risks
        # have no separate retention setting of their own).
        await session.execute(
            delete(RiskRecord)
            .where(RiskRecord.closed_at.isnot(None))
            .where(RiskRecord.closed_at < finding_cutoff)
        )

        # Purge spent password reset tokens. The grace period past expiry is
        # deliberate: a user clicking a link a little too late should be told
        # it expired, which needs the row to still exist. Used tokens are
        # pruned on the same schedule — they are dead either way, and keeping
        # them briefly gives the same clearer message on a double-click.
        await session.execute(
            delete(PasswordResetToken).where(
                PasswordResetToken.expires_at
                < utcnow() - timedelta(hours=RESET_TOKEN_PRUNE_GRACE_HOURS)
            )
        )

        await session.commit()
