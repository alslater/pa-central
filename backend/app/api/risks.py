"""Risks API — cross-repo risk-signal lifecycle management."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.database import get_db
from app.models import RepoScan, RiskRecord, User, utcnow
from app.schemas import PaginatedRisksOut, RiskAcceptBody, RiskRecordOut
from app.services.risk_lifecycle import build_risk_out

router = APIRouter(tags=["risks"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_admin)]

# Kept in sync with risk_lifecycle._VALID_LEVELS — the set of levels a
# RiskRecord can actually hold.
RiskLevel = Literal["critical", "warning", "info"]


# Level ordering for SQL sort (lower value = higher urgency).
_LEVEL_RANK = case(
    (RiskRecord.level == "critical", 0),
    (RiskRecord.level == "warning", 1),
    (RiskRecord.level == "info", 2),
    else_=3,
)


def _accepted_expr(today):
    from sqlalchemy import and_, or_
    return and_(
        RiskRecord.accepted_at.isnot(None),
        or_(RiskRecord.accepted_until.is_(None), RiskRecord.accepted_until > today),
    )


def _not_accepted_expr(today):
    from sqlalchemy import and_, or_
    return or_(
        RiskRecord.accepted_at.is_(None),
        and_(RiskRecord.accepted_until.isnot(None), RiskRecord.accepted_until <= today),
    )


def _apply_sort(
    stmt,
    sort: Literal["level", "days_open", "repo", "score"],
    sort_dir: Literal["asc", "desc"],
):
    """ORDER BY for the requested sort key. RiskRecord.id is always the stable
    tiebreaker, matching the findings router's _apply_sort."""
    asc = sort_dir == "asc"
    if sort == "level":
        col = _LEVEL_RANK
    elif sort == "score":
        col = RiskRecord.score
    elif sort == "days_open":
        col = RiskRecord.first_found_at
        asc = not asc
    else:
        assert sort == "repo"
        col = RepoScan.name
    return stmt.order_by(col.asc() if asc else col.desc(), RiskRecord.id.asc())


@router.get("/risks", response_model=PaginatedRisksOut)
async def list_risks(
    db: DbDep,
    _: AdminDep,
    level: Annotated[list[RiskLevel] | None, Query()] = None,
    accepted: bool | None = None,
    repo_scan_id: int | None = None,
    page: int = Query(0, ge=0),
    page_size: int = Query(50, ge=1, le=200),
    sort: Literal["level", "days_open", "repo", "score"] = Query("level"),
    sort_dir: Literal["asc", "desc"] = Query("asc"),
) -> PaginatedRisksOut:
    now = utcnow()

    base_stmt = (
        select(RiskRecord, RepoScan.name.label("scan_name"))
        .join(RepoScan, RepoScan.id == RiskRecord.repo_scan_id)
        .where(RiskRecord.closed_at.is_(None))
    )
    if level:
        base_stmt = base_stmt.where(RiskRecord.level.in_(level))
    if repo_scan_id is not None:
        base_stmt = base_stmt.where(RiskRecord.repo_scan_id == repo_scan_id)
    if accepted is True:
        base_stmt = base_stmt.where(_accepted_expr(now.date()))
    elif accepted is False:
        base_stmt = base_stmt.where(_not_accepted_expr(now.date()))

    count_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = (await db.execute(count_stmt)).scalar_one()

    page_stmt = _apply_sort(base_stmt, sort, sort_dir).offset(page * page_size).limit(page_size)
    items = [
        build_risk_out(record, now, scan_name=sname)
        for record, sname in await db.execute(page_stmt)
    ]

    return PaginatedRisksOut(items=items, total=total, page=page, page_size=page_size)


@router.post("/risks/{risk_id}/accept", response_model=RiskRecordOut)
async def accept_risk(
    risk_id: int,
    body: RiskAcceptBody,
    db: DbDep,
    user: AdminDep,
) -> RiskRecordOut:
    record = await db.get(RiskRecord, risk_id)
    if not record:
        raise HTTPException(404, "Risk record not found")
    if record.closed_at is not None:
        raise HTTPException(409, "Cannot accept a closed risk")
    now = utcnow()
    record.accepted_by_id = user.id
    record.accepted_at = now
    record.accepted_reason = body.reason
    record.accepted_until = body.accepted_until
    await db.commit()
    await db.refresh(record)
    scan = await db.get(RepoScan, record.repo_scan_id)
    return build_risk_out(record, now, scan_name=scan.name if scan else None)


@router.delete("/risks/{risk_id}/accept", response_model=RiskRecordOut)
async def revoke_risk_accept(
    risk_id: int,
    db: DbDep,
    _: AdminDep,
) -> RiskRecordOut:
    record = await db.get(RiskRecord, risk_id)
    if not record:
        raise HTTPException(404, "Risk record not found")
    if record.closed_at is not None:
        raise HTTPException(409, "Cannot revoke acceptance on a closed risk")
    record.accepted_by_id = None
    record.accepted_at = None
    record.accepted_reason = None
    record.accepted_until = None
    await db.commit()
    await db.refresh(record)
    now = utcnow()
    scan = await db.get(RepoScan, record.repo_scan_id)
    return build_risk_out(record, now, scan_name=scan.name if scan else None)
