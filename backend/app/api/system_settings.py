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
from app.services.finding_lifecycle import (
    DEFAULT_FINDING_RETENTION,
    DEFAULT_SLA_HIGH,
    DEFAULT_SLA_MEDIUM,
)

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

# Keys whose runtime consumer (get_global_sla's parse_int) silently applies a
# numeric default when no row exists, rather than treating absence itself as
# meaningful (contrast scan_result_retention_days/_count, where "no row"
# means "no day/count-based pruning" — not a hidden number). Without this,
# GET /system-settings shows these fields blank on a fresh database even
# though the application is actively enforcing the value on the right.
RUNTIME_DEFAULTS: dict[str, int] = {
    "sla_high_days": DEFAULT_SLA_HIGH,
    "sla_medium_days": DEFAULT_SLA_MEDIUM,
    "finding_retention_days": DEFAULT_FINDING_RETENTION,
}


def _redact(s: SystemSetting) -> SystemSettingOut:
    return SystemSettingOut(
        key=s.key,
        value=None if s.value_type == SettingValueType.secret else s.value,
        value_type=s.value_type,
        updated_at=s.updated_at,
        updated_by_id=s.updated_by_id,
    )


def _disagrees_with_parse_int(value: str | None) -> bool:
    """True when parse_int() would silently discard this stored value and
    substitute its default at runtime — i.e. anything that isn't a positive
    integer: NULL, "0", a negative value, or a non-numeric string. Mirrors
    parse_int()'s own validity rule exactly, so a row that would be ignored
    at runtime is never displayed here as if it were the effective value."""
    if value is None:
        return True
    try:
        return int(value) < 1
    except (ValueError, TypeError):
        return True


async def _list_settings_with_defaults(db: AsyncSession) -> list[SystemSettingOut]:
    """All persisted settings, plus a synthesized row for any RUNTIME_DEFAULTS
    key with no persisted row, or a persisted row whose value parse_int()
    would ignore at runtime (NULL, "0", negative, or non-numeric) — shared by
    GET and PATCH so the two can't drift (PATCH's own final query previously
    bypassed this synthesis entirely, so clearing a key back to its default
    showed the stale blank value until the next unrelated GET).

    Such a row is treated the same as a missing row, not just excluded
    outright: patch_settings validates on write for these specific keys (see
    POSITIVE_INT_KEYS) and deletes the row on clear rather than saving one
    with value=NULL, but any row already left in an invalid shape by a prior
    version of that logic, a direct DB write, or any future write path this
    file doesn't control, must still read back as the default rather than a
    value that silently disagrees with what parse_int() applies at runtime.
    """
    result = await db.execute(select(SystemSetting).order_by(SystemSetting.key))
    persisted = list(result.scalars().all())
    out = [
        _redact(s) for s in persisted
        if not (s.key in RUNTIME_DEFAULTS and _disagrees_with_parse_int(s.value))
    ]
    present_keys = {s.key for s in out}
    for key, default in RUNTIME_DEFAULTS.items():
        if key not in present_keys:
            out.append(SystemSettingOut(
                key=key, value=str(default), value_type=SettingValueType.int,
                updated_at=None, updated_by_id=None, is_default=True,
            ))
    out.sort(key=lambda s: s.key)
    return out


@router.get("", response_model=list[SystemSettingOut])
async def get_settings(db: DbDep, _: AdminDep) -> list[SystemSettingOut]:
    return await _list_settings_with_defaults(db)


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
        # For keys with a runtime default (see RUNTIME_DEFAULTS/get_settings),
        # clearing the field back to NULL must remove the row entirely, not
        # leave one behind with value=NULL — get_settings() only synthesizes
        # the default for a *missing* key, so a present-but-NULL row would
        # otherwise render as a blank field even though parse_int() is
        # actively applying 14/90/365 at runtime. Other keys keep the
        # existing NULL-row behavior (preserves updated_at/updated_by_id
        # for who cleared it and when).
        if raw_value is None and key in RUNTIME_DEFAULTS and existing:
            await db.delete(existing)
        elif existing:
            existing.value = stored_value
            existing.value_type = vtype
            existing.updated_at = now
            existing.updated_by_id = user.id
        elif not (raw_value is None and key in RUNTIME_DEFAULTS):
            db.add(SystemSetting(
                key=key, value=stored_value, value_type=vtype,
                updated_at=now, updated_by_id=user.id,
            ))
    await db.commit()
    return await _list_settings_with_defaults(db)
