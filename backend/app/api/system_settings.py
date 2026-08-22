"""System-wide settings — admin only."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.config import settings as app_settings
from app.core.database import get_db
from app.core.encryption import encrypt_value
from app.models import SettingValueType, SystemSetting, User, utcnow
from app.schemas import SystemSettingOut, SystemSettingPatch

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

# Keys whose runtime consumer (get_global_sla's parse_int) silently discards
# non-positive values and substitutes a default — so a PATCH accepting 0 or a
# negative value would report success while the stored value is ignored at
# read time. Enforced here since this is the only place these keys are
# validated on write.
POSITIVE_INT_KEYS = frozenset({"sla_high_days", "sla_medium_days", "finding_retention_days"})

# scan_result_retention_days treats 0 as "day-based retention disabled" (see
# scheduler.prune_old_results), so unlike POSITIVE_INT_KEYS, 0 is a valid,
# meaningful value here — only negative values are rejected. A negative value
# would make the pruning worker compute a cutoff in the future and delete
# every historical scan result.
NON_NEGATIVE_INT_KEYS = frozenset({"scan_result_retention_days", "scan_result_retention_count"})


def _redact(s: SystemSetting) -> SystemSettingOut:
    return SystemSettingOut(
        key=s.key,
        value=None if s.value_type == SettingValueType.secret else s.value,
        value_type=s.value_type,
        updated_at=s.updated_at,
        updated_by_id=s.updated_by_id,
    )


@router.get("", response_model=list[SystemSettingOut])
async def get_settings(db: DbDep, _: AdminDep) -> list[SystemSettingOut]:
    result = await db.execute(select(SystemSetting).order_by(SystemSetting.key))
    return [_redact(s) for s in result.scalars().all()]


@router.patch("", response_model=list[SystemSettingOut])
async def patch_settings(body: SystemSettingPatch, db: DbDep, user: AdminDep) -> list[SystemSettingOut]:
    now = utcnow()
    for key, raw_value in body.updates.items():
        vtype = KEY_TYPES.get(key, SettingValueType.string)
        if vtype == SettingValueType.int and raw_value is not None:
            try:
                int_value = int(raw_value)
            except (ValueError, TypeError):
                raise HTTPException(400, f"Setting '{key}' requires an integer value, got: {raw_value!r}")
            if key in POSITIVE_INT_KEYS and int_value < 1:
                raise HTTPException(400, f"Setting '{key}' requires a positive integer, got: {raw_value!r}")
            if key in NON_NEGATIVE_INT_KEYS and int_value < 0:
                raise HTTPException(400, f"Setting '{key}' requires a non-negative integer, got: {raw_value!r}")
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
