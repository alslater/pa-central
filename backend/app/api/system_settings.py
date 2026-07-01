"""System-wide settings — admin only."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings as app_settings
from app.core.encryption import encrypt_value
from app.models import SystemSetting, SettingValueType, User, utcnow
from app.schemas import SystemSettingOut, SystemSettingPatch
from app.api.deps import require_admin

router = APIRouter(prefix="/system-settings", tags=["system-settings"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_admin)]

# Known key → value_type mapping for auto-typing on upsert
KEY_TYPES: dict[str, SettingValueType] = {
    "pa_version": SettingValueType.string,
    "smtp_host": SettingValueType.string,
    "smtp_port": SettingValueType.int,
    "smtp_username": SettingValueType.string,
    "smtp_password": SettingValueType.secret,
    "smtp_from": SettingValueType.string,
    "smtp_tls_mode": SettingValueType.string,
    "scan_result_retention_days": SettingValueType.int,
    "scan_result_retention_count": SettingValueType.int,
    "app_base_url": SettingValueType.string,
    "default_cron_timezone": SettingValueType.string,
    "sla_high_days": SettingValueType.int,
    "sla_medium_days": SettingValueType.int,
    "finding_retention_days": SettingValueType.int,
}


def _redact(s: SystemSetting) -> SystemSettingOut:
    return SystemSettingOut(
        key=s.key,
        value=None if s.value_type == SettingValueType.secret else s.value,
        value_type=s.value_type,
        updated_at=s.updated_at,
        updated_by_id=s.updated_by_id,
    )


@router.get("", response_model=list[SystemSettingOut])
async def get_settings(db: DbDep, _: AdminDep):
    result = await db.execute(select(SystemSetting).order_by(SystemSetting.key))
    return [_redact(s) for s in result.scalars().all()]


@router.patch("", response_model=list[SystemSettingOut])
async def patch_settings(body: SystemSettingPatch, db: DbDep, user: AdminDep):
    now = utcnow()
    for key, raw_value in body.updates.items():
        vtype = KEY_TYPES.get(key, SettingValueType.string)
        if vtype == SettingValueType.int and raw_value is not None:
            try:
                int(raw_value)
            except (ValueError, TypeError):
                raise HTTPException(400, f"Setting '{key}' requires an integer value, got: {raw_value!r}")
        if vtype == SettingValueType.secret and raw_value is not None:
            stored_value = encrypt_value(raw_value, app_settings.settings_encryption_key)
        else:
            stored_value = raw_value
        existing = await db.get(SystemSetting, key)
        if existing:
            existing.value = stored_value
            existing.value_type = vtype
            existing.updated_at = now
            existing.updated_by_id = user.id
        else:
            db.add(SystemSetting(
                key=key, value=stored_value, value_type=vtype,
                updated_at=now, updated_by_id=user.id,
            ))
    await db.commit()
    result = await db.execute(select(SystemSetting).order_by(SystemSetting.key))
    return [_redact(s) for s in result.scalars().all()]
