from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Host, User
from app.schemas import HostUpdate, HostOut
from app.models import UserRole
from app.api.deps import get_current_user, require_operator, require_admin

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("", response_model=list[HostOut])
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
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
):
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    if user.role != UserRole.admin and host.owner_user_id != user.id:
        raise HTTPException(404, "Host not found")
    return host


@router.patch("/{host_id}", response_model=HostOut)
async def update_host(
    host_id: int,
    body: HostUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
):
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
):
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(404, "Host not found")
    await db.delete(host)
    await db.commit()
