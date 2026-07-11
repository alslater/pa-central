"""Findings API — cross-repo finding lifecycle management."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import (
    AlertSeverity, FindingRecord, RepoScan, SettingValueType, SystemSetting,
    User, utcnow,
)
from app.schemas import FindingAcceptBody, FindingRecordOut, FindingSettingsOut, FindingSettingsPut, PaginatedFindingsOut
from app.api.deps import require_admin
from app.services.finding_lifecycle import (
    accepted_sql_expr, build_finding_out, get_effective_sla, get_global_sla,
    in_breach_sql_expr, not_accepted_sql_expr, not_in_breach_sql_expr,
)

router = APIRouter(tags=["findings"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_admin)]



# Severity ordering for SQL sort (lower value = higher severity).
_SEVERITY_RANK = case(
    (FindingRecord.severity == AlertSeverity.critical, 0),
    (FindingRecord.severity == AlertSeverity.high, 1),
    (FindingRecord.severity == AlertSeverity.medium, 2),
    (FindingRecord.severity == AlertSeverity.warning, 3),
    (FindingRecord.severity == AlertSeverity.low, 4),
    (FindingRecord.severity == AlertSeverity.info, 5),
    else_=6,
)


def _apply_sort(
    stmt,
    sort: Literal["severity", "days_open", "repo"],
    sort_dir: Literal["asc", "desc"],
):
    """Return stmt with ORDER BY clause for the requested sort key.

    The secondary tiebreaker is always FindingRecord.id ASC regardless of
    sort_dir. This gives a stable absolute page order — every row has a unique
    position — without making the tiebreaker direction dependent on the primary
    sort, which would yield different (but equally arbitrary) orderings for ties.
    """
    asc = sort_dir == "asc"
    if sort == "severity":
        col = _SEVERITY_RANK
    elif sort == "days_open":
        # days_open = now - first_found_at; ascending means fewer days open first,
        # so ascending days_open ↔ descending first_found_at.
        col = FindingRecord.first_found_at
        asc = not asc
    else:
        assert sort == "repo"
        col = RepoScan.name
    return stmt.order_by(col.asc() if asc else col.desc(), FindingRecord.id.asc())


@router.get("/findings", response_model=PaginatedFindingsOut)
async def list_findings(
    db: DbDep,
    _: AdminDep,
    severity: Annotated[list[AlertSeverity] | None, Query()] = None,
    breach: bool | None = None,
    accepted: bool | None = None,
    repo_scan_id: int | None = None,
    page: int = Query(0, ge=0),
    page_size: int = Query(50, ge=1, le=200),
    sort: Literal["severity", "days_open", "repo"] = Query("severity"),
    sort_dir: Literal["asc", "desc"] = Query("asc"),
) -> PaginatedFindingsOut:
    if breach is True and accepted is True:
        raise HTTPException(422, "breach=true and accepted=true are mutually exclusive: accepted findings are never in breach")
    global_high, global_medium, _retention = await get_global_sla(db)
    now = utcnow()

    base_stmt = (
        select(FindingRecord, RepoScan.name.label("scan_name"), RepoScan.sla_high_days, RepoScan.sla_medium_days)
        .join(RepoScan, RepoScan.id == FindingRecord.repo_scan_id)
        .where(FindingRecord.closed_at.is_(None))
    )
    if severity:
        base_stmt = base_stmt.where(FindingRecord.severity.in_(severity))
    if repo_scan_id is not None:
        base_stmt = base_stmt.where(FindingRecord.repo_scan_id == repo_scan_id)
    if accepted is True:
        base_stmt = base_stmt.where(accepted_sql_expr(now.date()))
    elif accepted is False:
        base_stmt = base_stmt.where(not_accepted_sql_expr(now.date()))

    # Apply breach filter in SQL using the sla_breach_cutoff_at column.
    # Findings with NULL sla_breach_cutoff_at (no SLA or pre-migration rows) are
    # excluded from breach=true and included in breach=false — consistent with
    # the Python in_breach() function, which also treats NULL cutoff as not in breach.
    if breach is True:
        base_stmt = base_stmt.where(in_breach_sql_expr(now))
    elif breach is False:
        base_stmt = base_stmt.where(not_in_breach_sql_expr(now))

    # Derive count by wrapping base_stmt as a subquery so filters and JOINs
    # cannot drift. with_only_columns() is avoided: in SA 2.0 it drops FROM
    # clauses by default, which would silently lose the RepoScan join if filters
    # were added that reference RepoScan columns.
    count_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    page_stmt = _apply_sort(base_stmt, sort, sort_dir).offset(page * page_size).limit(page_size)
    items = []
    for record, sname, scan_sla_high, scan_sla_medium in await db.execute(page_stmt):
        eff_high = scan_sla_high if scan_sla_high is not None else global_high
        eff_medium = scan_sla_medium if scan_sla_medium is not None else global_medium
        items.append(build_finding_out(record, eff_high, eff_medium, now, scan_name=sname))

    return PaginatedFindingsOut(items=items, total=total, page=page, page_size=page_size)


@router.post("/findings/{finding_id}/accept", response_model=FindingRecordOut)
async def accept_finding(
    finding_id: int,
    body: FindingAcceptBody,
    db: DbDep,
    user: AdminDep,
) -> FindingRecordOut:
    record = await db.get(FindingRecord, finding_id)
    if not record:
        raise HTTPException(404, "Finding record not found")
    if record.closed_at is not None:
        raise HTTPException(409, "Cannot accept a closed finding")
    now = utcnow()
    record.accepted_by_id = user.id
    record.accepted_at = now
    record.accepted_reason = body.reason
    record.accepted_until = body.accepted_until
    await db.commit()
    await db.refresh(record)
    global_high, global_medium, _retention = await get_global_sla(db)
    scan = await db.get(RepoScan, record.repo_scan_id)
    eff_high, eff_medium = get_effective_sla(scan, global_high, global_medium) if scan else (global_high, global_medium)
    return build_finding_out(record, eff_high, eff_medium, now, scan_name=scan.name if scan else None)


@router.delete("/findings/{finding_id}/accept", response_model=FindingRecordOut)
async def revoke_accept(
    finding_id: int,
    db: DbDep,
    _: AdminDep,
) -> FindingRecordOut:
    record = await db.get(FindingRecord, finding_id)
    if not record:
        raise HTTPException(404, "Finding record not found")
    if record.closed_at is not None:
        raise HTTPException(409, "Cannot revoke acceptance on a closed finding")
    record.accepted_by_id = None
    record.accepted_at = None
    record.accepted_reason = None
    record.accepted_until = None
    await db.commit()
    await db.refresh(record)
    global_high, global_medium, _retention = await get_global_sla(db)
    scan = await db.get(RepoScan, record.repo_scan_id)
    eff_high, eff_medium = get_effective_sla(scan, global_high, global_medium) if scan else (global_high, global_medium)
    now = utcnow()
    return build_finding_out(record, eff_high, eff_medium, now, scan_name=scan.name if scan else None)


@router.get("/settings/findings", response_model=FindingSettingsOut)
async def get_finding_settings(db: DbDep, _: AdminDep) -> FindingSettingsOut:
    high, medium, retention = await get_global_sla(db)
    return FindingSettingsOut(sla_high_days=high, sla_medium_days=medium, finding_retention_days=retention)


@router.put("/settings/findings", response_model=FindingSettingsOut)
async def put_finding_settings(body: FindingSettingsPut, db: DbDep, user: AdminDep) -> FindingSettingsOut:
    now = utcnow()
    for key, value in [
        ("sla_high_days", str(body.sla_high_days)),
        ("sla_medium_days", str(body.sla_medium_days)),
        ("finding_retention_days", str(body.finding_retention_days)),
    ]:
        existing = await db.get(SystemSetting, key)
        if existing:
            existing.value = value
            existing.updated_at = now
            existing.updated_by_id = user.id
        else:
            db.add(SystemSetting(
                key=key, value=value, value_type=SettingValueType.int,
                updated_at=now, updated_by_id=user.id,
            ))
    await db.commit()
    return FindingSettingsOut(
        sla_high_days=body.sla_high_days,
        sla_medium_days=body.sla_medium_days,
        finding_retention_days=body.finding_retention_days,
    )
