from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin, require_operator
from app.core.database import get_db
from app.models import Host, Scan, User, UserRole
from app.schemas import HostOut, HostUpdate, ScanOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=list[HostOut])
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[HostOut]:
    if user.role == UserRole.admin:
        result = await db.execute(select(Host).order_by(Host.name))
    else:
        result = await db.execute(
            select(Host).where(Host.owner_user_id == user.id).order_by(Host.name)
        )
    return result.scalars().all()


@router.get("/{host_id}", response_model=HostOut)
async def get_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> HostOut:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")
    return host


@router.get("/{host_id}/latest-scans", response_model=list[ScanOut])
async def get_host_latest_scans(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ScanOut]:
    """One row per distinct project_path on this host — its most recent scan.

    GET /scans applies a default/max row limit (it's also the package-alert
    CLI's live surface and must not change shape), so grouping its results
    client-side silently drops projects once a host has more scans than that
    limit. This ranks per project in SQL instead, with no row cap, so every
    project on the host is represented regardless of total scan history depth.

    Ranked primarily by scanned_at desc, with received_at desc and id desc as
    tie-breakers for equal scanned_at (e.g. a retried/resubmitted scan) — this
    preserves the previous client-side behaviour, which iterated GET /scans'
    received_at-desc-ordered rows and kept the first (i.e. most recently
    received) match per project.
    """
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")

    rank = (
        func.row_number()
        .over(
            partition_by=Scan.project_path,
            order_by=(Scan.scanned_at.desc(), Scan.received_at.desc(), Scan.id.desc()),
        )
        .label("rank")
    )
    ranked = (
        select(Scan.id, rank)
        .where(Scan.host_id == host_id)
        .subquery()
    )
    latest_ids = select(ranked.c.id).where(ranked.c.rank == 1)
    result = await db.execute(
        select(Scan).where(Scan.id.in_(latest_ids)).order_by(Scan.project_path)
    )
    return result.scalars().all()


@router.patch("/{host_id}", response_model=HostOut)
async def update_host(
    host_id: int,
    body: HostUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
) -> HostOut:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(host, k, v)
    await db.commit()
    await db.refresh(host)
    return host


@router.delete("/{host_id}", status_code=204)
async def delete_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> None:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    await db.delete(host)
    await db.commit()
