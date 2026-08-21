from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RepoScanResult, RepoScanStatus, RiskRecord, utcnow
from app.schemas import RiskRecordOut

_VALID_LEVELS = {"critical", "warning", "info"}


def is_accepted(record: RiskRecord, now: datetime | None = None) -> bool:
    if record.accepted_at is None:
        return False
    if record.accepted_until is not None:
        today = (now or utcnow()).date()
        if record.accepted_until <= today:
            return False
    return True


def build_risk_out(
    record: RiskRecord,
    now: datetime,
    scan_name: str | None = None,
) -> RiskRecordOut:
    return RiskRecordOut(
        id=record.id,
        repo_scan_id=record.repo_scan_id,
        package=record.package,
        ecosystem=record.ecosystem,
        package_version=record.package_version,
        score=record.score,
        level=record.level,
        signals=record.signals,
        first_found_at=record.first_found_at,
        closed_at=record.closed_at,
        closed_reason=record.closed_reason,
        reopen_count=record.reopen_count,
        accepted_by_id=record.accepted_by_id,
        accepted_at=record.accepted_at,
        accepted_reason=record.accepted_reason,
        accepted_until=record.accepted_until,
        is_accepted=is_accepted(record, now),
        days_open=(now - record.first_found_at).days,
        scan_name=scan_name,
    )


def _str_or_none(v: object, max_len: int | None = None) -> str | None:
    if v is None or isinstance(v, (dict, list)):
        return None
    s = str(v)
    return s[:max_len] if max_len and len(s) > max_len else s


async def update_risk_records(db: AsyncSession, result: RepoScanResult) -> None:
    """Diff incoming risks against open records; open new, close gone, refresh persisting.

    Identity key is (package, ecosystem) — risks have no advisory_id equivalent.
    Unlike update_finding_records, a persisting row's score/level/signals are
    refreshed in place every scan: the heuristic engine's own inputs (popularity
    data, calibration) can legitimately move a package's score scan-to-scan, and
    freezing it at first appearance (as findings do) would show a stale number.

    If result.risk_failures > 0, package-alert's own risk pass only partially
    completed — an empty or short `risks` list may mean "failed to score",
    not "no longer risky". package-alert has no per-package breakdown of which
    packages failed, so there is no way to tell a genuine resolution apart from
    a scoring failure at the identity-key level. Closing is therefore skipped
    entirely for this scan when any failures occurred; whatever risks DID come
    back are still opened/refreshed normally, so a fully successful package
    isn't held hostage by an unrelated package's scoring failure.

    result.risks is None is a distinct, stronger case than an empty list: it
    means no risk pass was reported at all (an older package-alert binary
    that predates risk scoring, or any other producer that omits the field)
    rather than "the risk pass ran and found nothing". An empty *list* is
    still a real, positive signal — package-alert 0.7.0+ always includes the
    key, even for a clean scan, so `[]` legitimately means zero risks. But
    `None` carries no information either way, so the whole diff is skipped:
    no closes, no opens, no refreshes. Existing open records are left exactly
    as they were, rather than silently reading "no data" as "all resolved".
    """
    if result.risks is None:
        return

    incoming: dict[tuple[str, str], dict] = {}
    # Counts rows dropped for being unparseable (bad type, blank package, or
    # non-numeric score) — distinct from result.risk_failures, which reflects
    # package-alert's own scoring failures. A malformed row is skipped the
    # same way, but it must equally suppress absence-based closure below:
    # otherwise a previously open risk whose row failed to parse on this scan
    # (while risk_failures is legitimately 0, since package-alert itself
    # scored fine) would be misread as "no longer present" and closed.
    malformed_count = 0
    for r in result.risks:
        # risks is only validated as list[dict] at the API boundary, so
        # package/ecosystem can be any JSON type — a non-string value would
        # raise AttributeError on .strip() below and turn an otherwise-
        # successful ingest into a 500. Skip the malformed risk instead,
        # same as the invalid-score handling further down.
        raw_package = r.get("package")
        raw_ecosystem = r.get("ecosystem")
        if raw_package is not None and not isinstance(raw_package, str):
            malformed_count += 1
            continue
        if raw_ecosystem is not None and not isinstance(raw_ecosystem, str):
            malformed_count += 1
            continue
        # Truncate to the RiskRecord column widths before building the identity
        # key: a key built from the untruncated value would never match the
        # open row's (already-truncated) package/ecosystem on a later scan,
        # closing and recreating a long-named package's record every time.
        package = (raw_package or "").strip()[:200]
        ecosystem = (raw_ecosystem or "").strip()[:100]
        if not package:
            malformed_count += 1
            continue
        raw_score = r.get("score")
        try:
            score = int(raw_score)
        except (TypeError, ValueError):
            malformed_count += 1
            continue
        key = (package, ecosystem)
        if key not in incoming:
            incoming[key] = {**r, "package": package, "ecosystem": ecosystem, "_score": score}

    # Config-change reset: same policy as update_finding_records — if this
    # result's config hash differs from the last successful result's, the
    # baseline resets so config-driven differences aren't misread as risk churn.
    if result.scan_config_hash is not None:
        prev_hash_row = await db.execute(
            select(RepoScanResult.scan_config_hash)
            .where(RepoScanResult.repo_scan_id == result.repo_scan_id)
            .where(RepoScanResult.id != result.id)
            .where(RepoScanResult.status == RepoScanStatus.success)
            .where(RepoScanResult.scan_config_hash.isnot(None))
            .order_by(RepoScanResult.completed_at.desc())
            .limit(1)
        )
        prev_hash = prev_hash_row.scalar_one_or_none()
        if prev_hash is not None and prev_hash != result.scan_config_hash:
            close_time = result.completed_at or datetime.now(UTC)
            await db.execute(
                update(RiskRecord)
                .where(RiskRecord.repo_scan_id == result.repo_scan_id)
                .where(RiskRecord.closed_at.is_(None))
                .values(closed_at=close_time, closed_reason="config_change")
                .execution_options(synchronize_session="fetch")
            )

    open_rows = await db.execute(
        select(RiskRecord)
        .where(RiskRecord.repo_scan_id == result.repo_scan_id)
        .where(RiskRecord.closed_at.is_(None))
    )
    open_records: dict[tuple[str, str], RiskRecord] = {
        (r.package, r.ecosystem): r for r in open_rows.scalars().all()
    }

    now = result.completed_at or datetime.now(UTC)

    # Close risks no longer present — but only when this scan's risk pass
    # completed cleanly AND every row parsed. A nonzero risk_failures means
    # some packages could not be scored, and package-alert gives no way to
    # tell which ones; a nonzero malformed_count is the same situation caused
    # by our own parsing rather than package-alert's, but carries the same
    # risk — closing here could misread "failed to score/parse" as "no longer
    # risky" and silently resolve a still-active risk.
    if not result.risk_failures and not malformed_count:
        for key, record in open_records.items():
            if key not in incoming:
                record.closed_at = now

    # Reopen-count lookup for truly new keys
    new_keys = [key for key in incoming if key not in open_records]
    prior_reopen: dict[tuple[str, str], int] = {}
    if new_keys:
        prior_rows = await db.execute(
            select(
                RiskRecord.package,
                RiskRecord.ecosystem,
                func.max(RiskRecord.reopen_count).label("max_reopen"),
            )
            .where(RiskRecord.repo_scan_id == result.repo_scan_id)
            .where(RiskRecord.closed_at.isnot(None))
            .where(RiskRecord.closed_reason.is_(None))
            .where(tuple_(RiskRecord.package, RiskRecord.ecosystem).in_(new_keys))
            .group_by(RiskRecord.package, RiskRecord.ecosystem)
        )
        for package, ecosystem, max_reopen in prior_rows.all():
            prior_reopen[(package, ecosystem)] = max_reopen

    for key, risk in incoming.items():
        package, ecosystem = key
        raw_level = risk.get("level")
        level = raw_level.strip().lower() if isinstance(raw_level, str) and raw_level.strip() else "info"
        if level not in _VALID_LEVELS:
            level = "info"
        # RiskRecordOut.signals is list[dict] — a non-dict element (e.g. a
        # payload of "signals": ["bad"]) would be stored successfully (JSON
        # column has no element-level constraint) and only fail later, when
        # /api/risks or /api/repo-scans/{id}/risks tries to serialise it
        # through that schema. Filter non-dict entries out before persisting.
        raw_signals = risk.get("signals")
        signals = [s for s in raw_signals if isinstance(s, dict)] if isinstance(raw_signals, list) else []
        version = _str_or_none(risk.get("version"), 200)

        if key in open_records:
            # Persisting — refresh score/level/signals/version in place.
            record = open_records[key]
            record.score = risk["_score"]
            record.level = level
            record.signals = signals
            record.package_version = version
            continue

        reopen_count = (prior_reopen[key] + 1) if key in prior_reopen else 0
        record = RiskRecord(
            repo_scan_id=result.repo_scan_id,
            # package/ecosystem are already truncated to column width — see
            # the identity-key construction above.
            package=package,
            ecosystem=ecosystem,
            package_version=version,
            score=risk["_score"],
            level=level,
            signals=signals,
            first_found_at=now,
            reopen_count=reopen_count,
        )
        # Savepoint so a concurrent-ingest conflict on the partial unique index
        # doesn't abort the whole transaction — same pattern as update_finding_records.
        sp = await db.begin_nested()
        try:
            db.add(record)
            await db.flush([record])
            await sp.commit()
        except IntegrityError:
            await sp.rollback()
            db.expunge(record)
        except Exception:
            await sp.rollback()
            raise
