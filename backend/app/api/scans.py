from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Scan, Host, User, UserRole
from app.schemas import ScanOut
from app.api.deps import get_current_user_or_api_key

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[ScanOut])
async def list_scans(
    host_id: int | None = Query(None),
    hostname: str | None = Query(None),
    project_path: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user_or_api_key),
):
    scoped = user.role not in (UserRole.admin, UserRole.operator)
    owned_subq = select(Host.id).where(Host.owner_user_id == user.id).scalar_subquery()

    q = select(Scan).order_by(Scan.received_at.desc()).limit(limit).offset(offset)

    if host_id is not None:
        q = q.where(Scan.host_id == host_id)
        if scoped:
            q = q.where(Scan.host_id.in_(owned_subq))
    elif scoped:
        q = q.where(Scan.host_id.in_(owned_subq))

    if hostname is not None:
        host_q = select(Host).where(Host.hostname == hostname)
        if scoped:
            host_q = host_q.where(Host.owner_user_id == user.id)
        host_row = (await db.execute(host_q)).scalar_one_or_none()
        if not host_row:
            return []
        q = q.where(Scan.host_id == host_row.id)

    if project_path is not None:
        q = q.where(Scan.project_path == project_path)

    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user_or_api_key),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if user.role not in (UserRole.admin, UserRole.operator):
        host = await db.get(Host, scan.host_id)
        if not host or host.owner_user_id != user.id:
            raise HTTPException(404, "Scan not found")
    return scan
