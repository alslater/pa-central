from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_operator
from app.core.database import get_db
from app.models import CooldownEntry, User
from app.schemas import CooldownCreate, CooldownOut

router = APIRouter(prefix="/cooldown", tags=["cooldown"])


@router.get("", response_model=list[CooldownOut])
async def list_cooldowns(
    host_id: int | None = Query(None),
    fleet_wide: bool | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[CooldownOut]:
    q = select(CooldownEntry).order_by(CooldownEntry.created_at.desc())
    if fleet_wide is True:
        q = q.where(CooldownEntry.host_id.is_(None))
    elif host_id is not None:
        q = q.where(CooldownEntry.host_id == host_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("", response_model=CooldownOut, status_code=201)
async def create_cooldown(
    body: CooldownCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_operator),
) -> CooldownOut:
    entry = CooldownEntry(**body.model_dump(), created_by_id=user.id)
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


@router.delete("/{entry_id}", status_code=204)
async def delete_cooldown(
    entry_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_operator),
) -> None:
    entry = await db.get(CooldownEntry, entry_id)
    if not entry:
        raise HTTPException(404, "Entry not found")
    await db.delete(entry)
    await db.commit()
