from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import and_, func, or_, select, tuple_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertSeverity, FindingRecord, RepoScan, RepoScanResult, RepoScanStatus, SystemSetting, utcnow
from app.schemas import FindingRecordOut

def in_breach_sql_expr(now: datetime) -> ColumnElement[bool]:
    """SQL expression: finding is currently in breach.

    Uses sla_breach_cutoff_at (first_found_at + timedelta(days=sla_days + 1),
    snapshotted at ingest). NULL means no SLA — those findings are never in
    breach, matching Python in_breach() returning False when sla_days is None.

    The +1 day offset in the stored cutoff ensures `sla_breach_cutoff_at <= now`
    is exactly equivalent to Python's `(now - first_found_at).days > sla_days`,
    which truncates fractional days. At exactly sla_days+1 days elapsed,
    cutoff == now, so the inclusive `<=` fires correctly. `<` would miss this
    boundary moment and diverge from Python.

    now is normalised to naive UTC before binding because sla_breach_cutoff_at is
    stored as a naive UTC datetime (UtcDateTime strips tzinfo on write). Passing an
    aware datetime directly would bypass UtcDateTime.process_bind_param and cause
    an aware/naive mismatch in SQLite.
    """
    now_naive = now.astimezone(timezone.utc).replace(tzinfo=None)
    return and_(
        FindingRecord.closed_at.is_(None),
        FindingRecord.sla_breach_cutoff_at.isnot(None),
        FindingRecord.sla_breach_cutoff_at <= now_naive,
        not_accepted_sql_expr(now.date()),
    )


def not_in_breach_sql_expr(now: datetime) -> ColumnElement[bool]:
    """SQL expression: finding is NOT currently in breach.

    Covers: no SLA (sla_breach_cutoff_at IS NULL), within SLA, or accepted.
    Does not filter closed findings — callers are expected to restrict to
    open findings (closed_at IS NULL) before applying this expression.

    now is normalised to naive UTC — see in_breach_sql_expr for rationale.
    """
    now_naive = now.astimezone(timezone.utc).replace(tzinfo=None)
    return or_(
        FindingRecord.sla_breach_cutoff_at.is_(None),
        FindingRecord.sla_breach_cutoff_at > now_naive,
        accepted_sql_expr(now.date()),
    )


def accepted_sql_expr(today: date) -> ColumnElement[bool]:
    """SQL expression: finding is currently accepted (accepted_at set and not expired).

    Accepts an explicit UTC date so the SQL filter matches the Python is_accepted()
    function exactly, regardless of the DB session timezone.
    """
    return and_(
        FindingRecord.accepted_at.isnot(None),
        or_(
            FindingRecord.accepted_until.is_(None),
            FindingRecord.accepted_until > today,
        ),
    )


def not_accepted_sql_expr(today: date) -> ColumnElement[bool]:
    """SQL expression: finding is NOT currently accepted (complement of accepted_sql_expr)."""
    return or_(
        FindingRecord.accepted_at.is_(None),
        and_(
            FindingRecord.accepted_until.isnot(None),
            FindingRecord.accepted_until <= today,
        ),
    )


DEFAULT_SLA_HIGH = 14
DEFAULT_SLA_MEDIUM = 90
DEFAULT_FINDING_RETENTION = 365


def compute_scan_config_hash(
    scan_flags: str | None,
    subfolder: str | None,
    config_template_id: int | None,
) -> str:
    raw = json.dumps([scan_flags, subfolder, config_template_id], separators=(',', ':'))
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_int(value: str | None, default: int) -> int:
    try:
        parsed = int(value) if value else default
        return parsed if parsed >= 1 else default
    except (ValueError, TypeError):
        return default


async def get_global_sla(db: AsyncSession) -> tuple[int, int, int]:
    """Return (sla_high_days, sla_medium_days, finding_retention_days) from SystemSettings."""
    rows = await db.execute(
        select(SystemSetting).where(
            SystemSetting.key.in_(["sla_high_days", "sla_medium_days", "finding_retention_days"])
        )
    )
    settings = {s.key: s.value for s in rows.scalars().all()}
    high = parse_int(settings.get("sla_high_days"), DEFAULT_SLA_HIGH)
    medium = parse_int(settings.get("sla_medium_days"), DEFAULT_SLA_MEDIUM)
    retention = parse_int(settings.get("finding_retention_days"), DEFAULT_FINDING_RETENTION)
    return high, medium, retention


def compute_sla_days(
    severity: AlertSeverity, sla_high: int, sla_medium: int
) -> int | None:
    if severity in (AlertSeverity.critical, AlertSeverity.high):
        return sla_high
    if severity == AlertSeverity.medium:
        return sla_medium
    return None


def is_accepted(record: FindingRecord, now: datetime | None = None) -> bool:
    if record.accepted_at is None:
        return False
    if record.accepted_until is not None:
        today = (now or utcnow()).date()
        if record.accepted_until <= today:
            return False
    return True


def in_breach(record: FindingRecord, now: datetime) -> bool:
    """Return True if the finding is currently in breach of its SLA.

    Derived from sla_breach_cutoff_at so the result is consistent with the
    SQL breach filter (in_breach_sql_expr), which also requires the column to
    be non-NULL. A NULL cutoff (no SLA, or pre-migration row) is treated as
    not in breach — matching the SQL filter's behaviour of excluding such rows
    from breach=true results.
    """
    if record.sla_breach_cutoff_at is None:
        return False
    if record.closed_at is not None:
        return False
    if is_accepted(record, now):
        return False
    cutoff = record.sla_breach_cutoff_at
    # UtcDateTime returns an aware UTC datetime on read from DB; ensure now is also UTC.
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    return cutoff <= now.astimezone(timezone.utc)


def _compute_breach_cutoff(
    severity: AlertSeverity, sla_high: int, sla_medium: int, first_found_at: datetime
) -> datetime | None:
    """Return first_found_at + timedelta(days=sla_days + 1), or None if no SLA.

    The +1 aligns the SQL comparison `sla_breach_cutoff_at <= now` with Python's
    `(now - first_found_at).days > sla_days`, which truncates fractional days.
    At exactly sla_days+1 elapsed, cutoff == now: the inclusive <= fires and
    .days == sla_days+1 > sla_days, so both paths agree.
    """
    sla = compute_sla_days(severity, sla_high, sla_medium)
    return (first_found_at + timedelta(days=sla + 1)) if sla is not None else None


def get_effective_sla(
    repo_scan: RepoScan, global_high: int, global_medium: int
) -> tuple[int, int]:
    effective_high = repo_scan.sla_high_days if repo_scan.sla_high_days is not None else global_high
    effective_medium = repo_scan.sla_medium_days if repo_scan.sla_medium_days is not None else global_medium
    return effective_high, effective_medium


def build_finding_out(
    record: FindingRecord,
    sla_high: int,
    sla_medium: int,
    now: datetime,
    scan_name: str | None = None,
) -> FindingRecordOut:
    sla_days = compute_sla_days(record.severity, sla_high, sla_medium)
    return FindingRecordOut(
        id=record.id,
        repo_scan_id=record.repo_scan_id,
        advisory_id=record.advisory_id,
        package=record.package,
        ecosystem=record.ecosystem,
        severity=record.severity.value,
        first_found_at=record.first_found_at,
        closed_at=record.closed_at,
        closed_reason=record.closed_reason,
        reopen_count=record.reopen_count,
        accepted_by_id=record.accepted_by_id,
        accepted_at=record.accepted_at,
        accepted_reason=record.accepted_reason,
        accepted_until=record.accepted_until,
        summary=record.summary,
        details=record.details,
        package_version=record.package_version,
        fixed_versions=record.fixed_versions,
        url=record.url,
        is_malicious=record.is_malicious,
        is_accepted=is_accepted(record, now),
        days_open=(now - record.first_found_at).days,
        sla_days=sla_days,
        in_breach=in_breach(record, now),
        scan_name=scan_name,
    )


async def update_finding_records(db: AsyncSession, result: RepoScanResult) -> None:
    """Diff incoming findings against open records; open new, close gone.

    sla_breach_cutoff_at is set on new findings using the effective SLA at ingest
    time (per-scan override if set, else global default). This snapshot enables
    SQL-level breach filtering without per-row SLA joins at query time.
    """
    incoming: dict[tuple[str, str, str], dict] = {}
    for f in (result.findings or []):
        advisory_id = (f.get("advisory_id") or "").strip()
        package = (f.get("package") or "").strip()
        ecosystem = (f.get("ecosystem") or "").strip()
        if not advisory_id or not package:
            continue
        key = (advisory_id, package, ecosystem)
        if key not in incoming:
            incoming[key] = f

    # Fetch effective SLA for this scan once; used when snapshotting sla_breach_cutoff_at on new findings.
    global_high, global_medium, _ = await get_global_sla(db)
    scan = await db.get(RepoScan, result.repo_scan_id)
    eff_high, eff_medium = get_effective_sla(scan, global_high, global_medium) if scan else (global_high, global_medium)

    # Detect config change: compare this result's hash against the most recent
    # prior successful result. NULL hashes are treated as "unknown" — no reset
    # (conservative; covers pre-upgrade rows).
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
            close_time = result.completed_at or datetime.now(timezone.utc)
            await db.execute(
                update(FindingRecord)
                .where(FindingRecord.repo_scan_id == result.repo_scan_id)
                .where(FindingRecord.closed_at.is_(None))
                .values(closed_at=close_time, closed_reason="config_change")
                .execution_options(synchronize_session="fetch")
            )

    open_rows = await db.execute(
        select(FindingRecord)
        .where(FindingRecord.repo_scan_id == result.repo_scan_id)
        .where(FindingRecord.closed_at.is_(None))
    )
    open_records: dict[tuple[str, str, str], FindingRecord] = {
        (r.advisory_id, r.package, r.ecosystem): r
        for r in open_rows.scalars().all()
    }

    now = result.completed_at or datetime.now(timezone.utc)

    # Close findings no longer present
    for key, record in open_records.items():
        if key not in incoming:
            record.closed_at = now

    # For all truly new findings, fetch the max reopen_count from prior closed
    # episodes in a single query, then look up per-key in Python.
    new_keys = [key for key in incoming if key not in open_records]
    prior_reopen: dict[tuple[str, str, str], int] = {}
    if new_keys:
        prior_rows = await db.execute(
            select(
                FindingRecord.advisory_id,
                FindingRecord.package,
                FindingRecord.ecosystem,
                func.max(FindingRecord.reopen_count).label("max_reopen"),
            )
            .where(FindingRecord.repo_scan_id == result.repo_scan_id)
            .where(FindingRecord.closed_at.isnot(None))
            .where(FindingRecord.closed_reason.is_(None))
            .where(
                tuple_(
                    FindingRecord.advisory_id,
                    FindingRecord.package,
                    FindingRecord.ecosystem,
                ).in_(new_keys)
            )
            .group_by(
                FindingRecord.advisory_id,
                FindingRecord.package,
                FindingRecord.ecosystem,
            )
        )
        for advisory_id, package, ecosystem, max_reopen in prior_rows.all():
            prior_reopen[(advisory_id, package, ecosystem)] = max_reopen

    # Open new findings
    for key, finding in incoming.items():
        if key in open_records:
            continue  # persisting — no action

        advisory_id, package, ecosystem = key
        reopen_count = (prior_reopen[key] + 1) if key in prior_reopen else 0

        raw_severity = finding.get("severity")
        if isinstance(raw_severity, str) and raw_severity.strip():
            normalised = raw_severity.lower()
        else:
            normalised = "info"
        try:
            severity = AlertSeverity(normalised)
        except ValueError:
            severity = AlertSeverity.info

        raw_fixed = finding.get("fixed_versions")
        if isinstance(raw_fixed, list):
            fixed_versions = ", ".join(str(v) for v in raw_fixed if v is not None and v != "") or None
        elif isinstance(raw_fixed, str):
            fixed_versions = raw_fixed or None
        else:
            fixed_versions = None
        def _str_or_none(v: object, max_len: int | None = None) -> str | None:
            if v is None or isinstance(v, (dict, list)):
                return None
            s = str(v)
            return s[:max_len] if max_len and len(s) > max_len else s

        raw_is_malicious = finding.get("is_malicious")
        is_malicious: bool | None = bool(raw_is_malicious) if isinstance(raw_is_malicious, bool) else None

        record = FindingRecord(
            repo_scan_id=result.repo_scan_id,
            advisory_id=advisory_id[:200],
            package=package[:200],
            ecosystem=ecosystem[:100],
            severity=severity,
            summary=_str_or_none(finding.get("summary"), 2000),
            details=_str_or_none(finding.get("details")),
            package_version=_str_or_none(finding.get("version"), 200),
            fixed_versions=fixed_versions,
            url=_str_or_none(finding.get("url"), 500),
            is_malicious=is_malicious,
            first_found_at=now,
            reopen_count=reopen_count,
            sla_breach_cutoff_at=_compute_breach_cutoff(severity, eff_high, eff_medium, now),
        )
        # Use a savepoint so a concurrent-ingest conflict on the partial unique
        # index doesn't abort the whole transaction — just skip the duplicate.
        # Explicit begin/rollback avoids async-CM re-entrancy issues with the
        # SQLAlchemy after_transaction_end hook used in the test fixture.
        sp = await db.begin_nested()
        try:
            db.add(record)
            await db.flush([record])
            await sp.commit()
        except IntegrityError:
            # The open record already exists (concurrent ingest); treat as persisting.
            await sp.rollback()
            # Expunge the pending instance so SQLAlchemy won't try to flush it
            # again on the outer commit and re-raise the same IntegrityError.
            db.expunge(record)
        except Exception:
            await sp.rollback()
            raise
