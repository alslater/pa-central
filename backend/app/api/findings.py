"""Findings API — cross-repo finding lifecycle management."""
from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import (
    AlertSeverity, FindingRecord, RepoScan, SettingValueType, SystemSetting,
    User, utcnow,
)
from app.schemas import FindingAcceptBody, FindingRecordOut, FindingSettingsOut, FindingSettingsPut
from app.api.deps import require_admin
from app.services.finding_lifecycle import (
    accepted_sql_expr, build_finding_out, get_effective_sla, get_global_sla,
    not_accepted_sql_expr,
)

router = APIRouter(tags=["findings"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_admin)]



@router.get("/findings", response_model=list[FindingRecordOut])
async def list_findings(
    db: DbDep,
    _: AdminDep,
    severity: Annotated[list[AlertSeverity] | None, Query()] = None,
    breach: bool | None = None,
    accepted: bool | None = None,
    repo_scan_id: int | None = None,
    limit: int = Query(200, ge=1, le=500),
) -> list[FindingRecordOut]:
    if breach is True and accepted is True:
        raise HTTPException(422, "breach=true and accepted=true are mutually exclusive: accepted findings are never in breach")
    global_high, global_medium, _ = await get_global_sla(db)
    now = utcnow()

    stmt = (
        select(FindingRecord, RepoScan.name.label("scan_name"), RepoScan.sla_high_days, RepoScan.sla_medium_days)
        .join(RepoScan, RepoScan.id == FindingRecord.repo_scan_id)
        .where(FindingRecord.closed_at.is_(None))
    )
    if severity:
        stmt = stmt.where(FindingRecord.severity.in_(severity))
    if repo_scan_id is not None:
        stmt = stmt.where(FindingRecord.repo_scan_id == repo_scan_id)
    # accepted is portable SQL; push it into the query.
    if accepted is True:
        stmt = stmt.where(accepted_sql_expr(now.date()))
    elif accepted is False:
        stmt = stmt.where(not_accepted_sql_expr(now.date()))
    # breach depends on per-scan SLA overrides and date arithmetic that differs
    # across databases, so it is evaluated in Python after fetching candidates.
    # For breach/accepted filtering we apply a SQL cap of limit * 10 — large
    # enough to absorb per-scan SLA variance while preventing unbounded scans.
    # The Python break() still exits as soon as `limit` results are collected.
    if breach is None:
        stmt = stmt.limit(limit)
    elif breach is True:
        # Accepted findings are never in breach; exclude them in SQL so they
        # don't consume slots in the limit*10 cap (unless the caller already
        # applied an accepted filter, which the 422 guard above ensures only
        # happens when accepted=False — the same direction, so safe to skip).
        if accepted is None:
            stmt = stmt.where(not_accepted_sql_expr(now.date()))
        # Only severities with an SLA can ever be in breach.
        _high_sevs = {AlertSeverity.critical, AlertSeverity.high}
        _med_sevs = {AlertSeverity.medium}
        _sla_severities = [AlertSeverity.critical, AlertSeverity.high, AlertSeverity.medium]
        if not severity:
            stmt = stmt.where(FindingRecord.severity.in_(_sla_severities))
            _active_high = True
            _active_medium = True
        else:
            _active_high = bool(set(severity) & _high_sevs)
            _active_medium = bool(set(severity) & _med_sevs)
            if not _active_high and not _active_medium:
                return []

        # Apply a safe age cutoff using only SLA tiers relevant to the requested
        # severities. Including a strict high-tier SLA (e.g. 14d) when only
        # medium is requested would widen the candidate set unnecessarily.
        if repo_scan_id is not None:
            sla_row = (await db.execute(
                select(RepoScan.sla_high_days, RepoScan.sla_medium_days)
                .where(RepoScan.id == repo_scan_id)
            )).one_or_none()
            if sla_row is not None:
                scan_high = sla_row[0] if sla_row[0] is not None else global_high
                scan_medium = sla_row[1] if sla_row[1] is not None else global_medium
                candidates = ([scan_high] if _active_high else []) + ([scan_medium] if _active_medium else [])
                if candidates:
                    stmt = stmt.where(FindingRecord.first_found_at <= now - timedelta(days=min(candidates) + 1))
        else:
            # Aggregate only over scans that have open findings matching the
            # current filters (severity, repo_scan_id). This prevents a single
            # scan with a very strict SLA override from widening the candidate
            # set for an unrelated breach query.
            # Scope to the severities actually active for this query so that
            # scans with only low/info/warning findings (no SLA) don't pull their
            # SLA overrides into the aggregate cutoff.
            _base_sevs = [s for s in (severity or _sla_severities)
                          if (_active_high and s in _high_sevs) or (_active_medium and s in _med_sevs)]
            base_subq = (
                select(FindingRecord.repo_scan_id).distinct()
                .where(FindingRecord.closed_at.is_(None))
                .where(not_accepted_sql_expr(now.date()))
                .where(FindingRecord.severity.in_(_base_sevs))
            )
            agg_cols = []
            if _active_high:
                agg_cols.append(func.min(func.coalesce(RepoScan.sla_high_days, global_high)))
            if _active_medium:
                agg_cols.append(func.min(func.coalesce(RepoScan.sla_medium_days, global_medium)))
            if agg_cols:
                agg_row = (await db.execute(select(*agg_cols).where(RepoScan.id.in_(base_subq)))).one()
                candidates = [v for v in agg_row if v is not None]
                if candidates:
                    stmt = stmt.where(FindingRecord.first_found_at <= now - timedelta(days=min(candidates) + 1))

    # Oldest-first: most likely breaching, and makes early-break deterministic.
    stmt = stmt.order_by(FindingRecord.first_found_at)
    if breach is not None:
        # breach is evaluated in Python (per-scan SLA variance), so we can't
        # push an exact limit into SQL. Cap at limit*10 to avoid unbounded scans.
        # Can return fewer than `limit` results when matches are sparse in the
        # oldest limit*10 rows. Proper fix: server-side pagination
        # (see ROADMAP.md — "Server-side pagination and sorting for GET /findings").
        stmt = stmt.limit(limit * 10)

    results = []
    for record, sname, scan_sla_high, scan_sla_medium in await db.execute(stmt):
        eff_high = scan_sla_high if scan_sla_high is not None else global_high
        eff_medium = scan_sla_medium if scan_sla_medium is not None else global_medium
        out = build_finding_out(record, eff_high, eff_medium, now, scan_name=sname)
        if breach is True and not out.in_breach:
            continue
        if breach is False and out.in_breach:
            continue
        results.append(out)
        if len(results) == limit:
            break

    return results


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
    global_high, global_medium, _ = await get_global_sla(db)
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
    global_high, global_medium, _ = await get_global_sla(db)
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
