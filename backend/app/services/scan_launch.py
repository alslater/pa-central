"""The environment a scan task is launched with: one builder for manual and scheduled scans.

Before this existed the two launch paths built it separately and drifted (the scheduler never
sent PA_CONFIG_TOML, and each read pa_version from a different place).
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ConfigTemplate, CredentialType, SystemSetting
from app.services.fix_plan_budget import get_fix_plan_timeout
from app.services.package_indexes import index_credentials

_LOCAL = "local://"


async def get_pa_version(db: AsyncSession) -> str:
    row = await db.get(SystemSetting, "pa_version")
    # Stripped on read too: a value stored before the setting was normalised on write.
    return (row.value or "").strip() if row is not None else ""


async def effective_pa_version(db: AsyncSession, scan: Any) -> str:
    """The scan's own pinned version, else the pa_version system setting, else "" (latest)."""
    return scan.pa_version or await get_pa_version(db)


def _secret_fields(arn: str | None) -> dict[str, str]:
    arn = arn or ""
    return {"value": arn[len(_LOCAL):]} if arn.startswith(_LOCAL) else {"secret_arn": arn}


async def build_scan_task_env(db: AsyncSession, scan: Any, result_id: int, credential: Any = None) -> dict[str, str]:
    from app.core.config import settings as app_settings

    cred_type = credential.credential_type if credential else CredentialType.none
    cred_arn = credential.credential_secret_arn if credential else None
    local_arn = (cred_arn or "").startswith(_LOCAL)
    config_toml = ""
    if scan.config_template_id:
        tmpl = await db.get(ConfigTemplate, scan.config_template_id)
        if tmpl:
            config_toml = tmpl.toml_content
    indexes = [
        {"url": c.index_url, "username": c.index_username, **_secret_fields(c.credential_secret_arn)}
        for c in await index_credentials(db, scan.id)
    ]
    return {
        "PA_VERSION": await effective_pa_version(db, scan),
        "REPO_SCAN_RESULT_ID": str(result_id),
        "REPO_URL": scan.url,
        "BRANCH": scan.branch,
        "CREDENTIAL_TYPE": cred_type.value,
        "CREDENTIAL_SECRET_ARN": "" if local_arn else (cred_arn or ""),
        "CREDENTIAL_VALUE": cred_arn[len(_LOCAL):] if local_arn and cred_arn else "",
        "FLEET_API_URL": app_settings.resolved_scan_task_fleet_url,
        "FLEET_SYSTEM_API_KEY": app_settings.fleet_system_api_key or "",
        "PA_CONFIG_TOML": config_toml,
        "PA_SCAN_FLAGS": scan.scan_flags or "",
        "PA_SUBFOLDER": scan.subfolder or "",
        "FIX_PLANS": "1" if scan.fix_plans_enabled else "",
        "FIX_PLAN_TIMEOUT": str(await get_fix_plan_timeout(db)),
        "PACKAGE_INDEXES": json.dumps(indexes) if indexes else "",
    }
