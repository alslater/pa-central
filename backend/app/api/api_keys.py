from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import generate_api_key
from app.models import ApiKey, User
from app.schemas import ApiKeyCreate, ApiKeyOut, ApiKeyCreated
from app.api.deps import get_current_user

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Admins see all keys; others see only their own."""
    from app.models import UserRole
    if user.role == UserRole.admin:
        result = await db.execute(select(ApiKey).order_by(ApiKey.created_at.desc()))
    else:
        result = await db.execute(
            select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc())
        )
    return result.scalars().all()


@router.post("", response_model=ApiKeyCreated, status_code=201)
async def create_key(
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    raw, hashed = generate_api_key()
    key = ApiKey(
        name=body.name,
        key_hash=hashed,
        user_id=user.id,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return ApiKeyCreated(
        id=key.id,
        name=key.name,
        is_active=key.is_active,
        last_used_at=key.last_used_at,
        created_at=key.created_at,
        raw_key=raw,
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.models import UserRole
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(404, "Key not found")
    if user.role != UserRole.admin and key.user_id != user.id:
        raise HTTPException(403, "Not your key")
    key.is_active = False
    await db.commit()
