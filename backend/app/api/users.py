from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import hash_password
from app.models import User
from app.schemas import UserOut, UserUpdate
from app.api.deps import get_current_user, require_admin

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    result = await db.execute(select(User).order_by(User.display_name))
    return result.scalars().all()


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
):
    from app.models import UserRole
    if current.role != UserRole.admin and current.id != user_id:
        raise HTTPException(403, "Forbidden")
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
):
    from app.models import UserRole
    # Check permission before DB lookup to avoid leaking whether user_id exists
    if current.role != UserRole.admin:
        if current.id != user_id:
            raise HTTPException(403, "Forbidden")
        body = UserUpdate(display_name=body.display_name, password=body.password)
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    data = body.model_dump(exclude_none=True)
    if "password" in data:
        data["hashed_password"] = hash_password(data.pop("password"))
    for k, v in data.items():
        setattr(user, k, v)
    await db.commit()
    await db.refresh(user)
    return user
