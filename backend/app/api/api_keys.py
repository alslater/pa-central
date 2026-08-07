from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.security import generate_api_key
from app.models import ApiKey, User
from app.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut

router = APIRouter(prefix="/api-keys", tags=["api-keys"])


@router.get("", response_model=list[ApiKeyOut])
async def list_keys(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ApiKeyOut]:
    """Admins see all keys; others see only their own.

    Returns serialised ``ApiKeyOut`` objects rather than ORM rows, since
    ``owner_display_name`` is joined in from the related user.
    """
    from app.models import UserRole
    q = select(ApiKey).options(selectinload(ApiKey.user)).order_by(ApiKey.created_at.desc())
    if user.role != UserRole.admin:
        q = q.where(ApiKey.user_id == user.id)
    result = await db.execute(q)
    keys = result.scalars().all()
    return [ApiKeyOut.from_orm_with_owner(k, k.user.display_name) for k in keys]


@router.post("", response_model=ApiKeyCreated, status_code=201)
async def create_key(
    body: ApiKeyCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> ApiKeyCreated:
    raw, hashed = generate_api_key()
    key = ApiKey(
        name=body.name,
        key_hash=hashed,
        user_id=user.id,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    base = ApiKeyOut.from_orm_with_owner(key, user.display_name)
    return ApiKeyCreated(**base.model_dump(), raw_key=raw)


@router.delete("/{key_id}", status_code=204, response_class=Response)
async def revoke_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    from app.models import UserRole
    key = await db.get(ApiKey, key_id)
    if not key:
        raise HTTPException(404, "Key not found")
    if user.role != UserRole.admin and key.user_id != user.id:
        raise HTTPException(403, "Not your key")
    key.is_active = False
    await db.commit()
    return Response(status_code=204)
