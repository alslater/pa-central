"""The fix plan of each repo scan's latest successful result: the plan its open findings came from."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RepoScanResult, RepoScanStatus
from app.schemas import FixPlanResultOut


async def latest_fix_plans(
    db: AsyncSession, scan_ids: list[int],
) -> dict[int, tuple[int, datetime | None, FixPlanResultOut | None]]:
    """scan id -> (result id, completed_at, fix plan) for each scan with a successful result.

    The plan is None when that result has none (fix plans off, or no findings). A stored plan is
    re-validated leniently, as on ingest, so a row written by an older version still renders.
    """
    if not scan_ids:
        return {}
    rank = (
        func.row_number()
        .over(partition_by=RepoScanResult.repo_scan_id,
              order_by=(RepoScanResult.started_at.desc(), RepoScanResult.id.desc()))
        .label("rank")
    )
    # Rank ids only, then join the winners back for their JSON: carrying fix_plan through the
    # window would read every historical result's plan to return one per scan.
    ranked = (
        select(RepoScanResult.id, rank)
        .where(RepoScanResult.repo_scan_id.in_(scan_ids))
        .where(RepoScanResult.status == RepoScanStatus.success)
        .subquery()
    )
    rows = await db.execute(
        select(RepoScanResult.repo_scan_id, RepoScanResult.id, RepoScanResult.completed_at, RepoScanResult.fix_plan)
        .join(ranked, ranked.c.id == RepoScanResult.id)
        .where(ranked.c.rank == 1)
    )
    out: dict[int, tuple[int, datetime | None, FixPlanResultOut | None]] = {}
    for scan_id, result_id, completed_at, raw in rows:
        plan = FixPlanResultOut.model_validate(raw) if isinstance(raw, dict) else None
        out[scan_id] = (result_id, completed_at, plan)
    return out


def planned_count(plan: FixPlanResultOut | None) -> int | None:
    """How many upgrades the plan proposes, or None when there is no usable plan to count."""
    if plan is None or plan.status != "planned" or plan.plan is None:
        return None
    return len(plan.plan.planned)
