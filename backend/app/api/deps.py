"""FastAPI dependencies for authentication and authorization."""
import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token, hash_api_key
from app.models import (
    ApiKey,
    ConfigAssignment,
    ConfigTemplate,
    Host,
    User,
    UserRole,
    utcnow,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    token: Annotated[str | None, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
) -> User:
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    user_id = decode_access_token(token)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    try:
        uid = int(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = await db.get(User, uid)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def require_role(*roles: UserRole):
    async def _check(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return _check


require_admin = require_role(UserRole.admin)
require_operator = require_role(UserRole.admin, UserRole.operator)
require_viewer = require_role(UserRole.admin, UserRole.operator, UserRole.developer, UserRole.viewer)


async def get_current_user_or_api_key(
    token: Annotated[str | None, Depends(oauth2_scheme)],
    api_key: Annotated[str | None, Security(api_key_header)],
    db: AsyncSession = Depends(get_db),
) -> User:
    """Accept either a JWT bearer token or an X-API-Key. Returns the owning User."""
    if token:
        user_id = decode_access_token(token)
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        try:
            uid = int(user_id)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = await db.get(User, uid)
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    if api_key:
        key_hash = hash_api_key(api_key)
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
        )
        key_obj = result.scalar_one_or_none()
        if not key_obj:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        key_obj.last_used_at = utcnow()
        await db.commit()
        user = await db.get(User, key_obj.user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def get_api_key(
    api_key: Annotated[str | None, Security(api_key_header)],
    db: AsyncSession = Depends(get_db),
) -> tuple[ApiKey, AsyncSession]:
    """Authenticate an agent request. Returns (api_key, db). Host resolution is done per-endpoint."""
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-API-Key required")
    key_hash = hash_api_key(api_key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active.is_(True))
    )
    key_obj = result.scalar_one_or_none()
    if not key_obj:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    key_obj.last_used_at = utcnow()
    await db.commit()
    return key_obj, db


async def require_system_key(
    api_key: Annotated[str | None, Security(api_key_header)],
) -> None:
    """Accept only the fleet system API key. Used by scan-task ingest endpoints."""
    from app.core.config import settings as app_settings
    system_key = app_settings.fleet_system_api_key
    if not api_key or not system_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="X-API-Key required")
    if not hmac.compare_digest(api_key, system_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


async def resolve_host(hostname: str, key_obj: ApiKey, db: AsyncSession) -> Host:
    """Find-or-create a host by (owner_user_id, hostname). Flushes but does not commit; caller owns the transaction."""
    result = await db.execute(
        select(Host).where(Host.owner_user_id == key_obj.user_id, Host.hostname == hostname)
    )
    host = result.scalar_one_or_none()
    if not host:
        user = await db.get(User, key_obj.user_id)
        username = user.email if user else str(key_obj.user_id)
        name = f"{username}/{hostname}"[:100]
        host = Host(owner_user_id=key_obj.user_id, name=name, hostname=hostname)
        db.add(host)
        await db.flush()
        default_tmpl = (await db.execute(
            select(ConfigTemplate).where(ConfigTemplate.is_default.is_(True))
        )).scalar_one_or_none()
        if default_tmpl:
            db.add(ConfigAssignment(
                host_id=host.id,
                template_id=default_tmpl.id,
                assigned_by_id=key_obj.user_id,
            ))
    return host
