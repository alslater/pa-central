from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sqlalchemy import and_, func, or_, select, tuple_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.elements import ClauseElement
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertSeverity, FindingRecord, RepoScan, RepoScanResult, SystemSetting, utcnow
from app.schemas import FindingRecordOut

def accepted_sql_expr() -> ClauseElement:
    """SQL expression: finding is currently accepted (accepted_at set and not expired)."""
    return and_(
        FindingRecord.accepted_at.isnot(None),
        or_(
            FindingRecord.accepted_until.is_(None),
            FindingRecord.accepted_until > func.current_date(),
        ),
    )


def not_accepted_sql_expr() -> ClauseElement:
    """SQL expression: finding is NOT currently accepted (complement of accepted_sql_expr)."""
    return or_(
        FindingRecord.accepted_at.is_(None),
        and_(
            FindingRecord.accepted_until.isnot(None),
            FindingRecord.accepted_until <= func.current_date(),
        ),
    )


DEFAULT_SLA_HIGH = 14
DEFAULT_SLA_MEDIUM = 90
DEFAULT_FINDING_RETENTION = 365

# Aliases from upstream scanners that don't map 1:1 to AlertSeverity values.
_SEVERITY_ALIASES: dict[str, str] = {
    "moderate": "medium",
}


def compute_scan_config_hash(
    scan_flags: str | None,
    subfolder: str | None,
    config_template_id: int | None,
) -> str:
    raw = f"{scan_flags or ''}|{subfolder or ''}|{config_template_id or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _parse_int(value: str | None, default: int) -> int:
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
    high = _parse_int(settings.get("sla_high_days"), DEFAULT_SLA_HIGH)
    medium = _parse_int(settings.get("sla_medium_days"), DEFAULT_SLA_MEDIUM)
    retention = _parse_int(settings.get("finding_retention_days"), DEFAULT_FINDING_RETENTION)
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


def in_breach(record: FindingRecord, sla_days: int | None, now: datetime) -> bool:
    if sla_days is None:
        return False
    if record.closed_at is not None:
        return False
    if is_accepted(record, now):
        return False
    return (now - record.first_found_at).days > sla_days


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
        in_breach=in_breach(record, sla_days, now),
        scan_name=scan_name,
    )


async def update_finding_records(db: AsyncSession, result: RepoScanResult) -> None:
    """Diff incoming findings against open records; open new, close gone."""
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
            normalised = _SEVERITY_ALIASES.get(raw_severity.lower(), raw_severity.lower())
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
        def _str_or_none(v: object) -> str | None:
            return str(v) if v is not None and not isinstance(v, (dict, list)) else None

        raw_is_malicious = finding.get("is_malicious")
        is_malicious: bool | None = bool(raw_is_malicious) if isinstance(raw_is_malicious, bool) else None

        record = FindingRecord(
            repo_scan_id=result.repo_scan_id,
            advisory_id=advisory_id,
            package=package,
            ecosystem=ecosystem,
            severity=severity,
            summary=_str_or_none(finding.get("summary")),
            details=_str_or_none(finding.get("details")),
            package_version=_str_or_none(finding.get("version")),
            fixed_versions=fixed_versions,
            url=_str_or_none(finding.get("url")),
            is_malicious=is_malicious,
            first_found_at=now,
            reopen_count=reopen_count,
        )
        # Use a savepoint so a concurrent-ingest conflict on the partial unique
        # index doesn't abort the whole transaction — just skip the duplicate.
        async with await db.begin_nested():
            try:
                db.add(record)
                await db.flush([record])
            except IntegrityError:
                # The open record already exists (concurrent ingest); treat as persisting.
                pass
