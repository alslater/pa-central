"""The fix-plan time budget, and the task timeouts derived from it.

One parser serves the PATCH check and every runtime read, so the two cannot disagree on
what a usable value is (a stored value that is invalid anyway is logged and replaced by
the default at read time, never silently used).
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SystemSetting

log = logging.getLogger(__name__)

FIX_PLAN_TIMEOUT_KEY = "fix_plan_timeout_seconds"
DEFAULT_FIX_PLAN_TIMEOUT = 900
MIN_FIX_PLAN_TIMEOUT = 120
MAX_FIX_PLAN_TIMEOUT = 3600
# pa scan-project's own timeout in the scan task, plus clone/install/login margin.
SCAN_SECONDS = 600
TASK_MARGIN_SECONDS = 300
# Never below the 30 minutes stuck-scan recovery always allowed.
MIN_TASK_SECONDS = 1800
# A run that used this much of its budget is flagged near_timeout.
NEAR_TIMEOUT_FRACTION = 0.8


def fix_plan_timeout_is_usable(value: int) -> bool:
    return MIN_FIX_PLAN_TIMEOUT <= value <= MAX_FIX_PLAN_TIMEOUT


def parse_fix_plan_timeout(raw: str | None) -> int:
    """The stored budget in seconds, or the default for a missing or unusable value."""
    if raw is None or not str(raw).strip():
        return DEFAULT_FIX_PLAN_TIMEOUT
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        log.warning("Ignoring non-integer %s=%r; using %d", FIX_PLAN_TIMEOUT_KEY, raw, DEFAULT_FIX_PLAN_TIMEOUT)
        return DEFAULT_FIX_PLAN_TIMEOUT
    if not fix_plan_timeout_is_usable(value):
        log.warning("Ignoring out-of-range %s=%r; using %d", FIX_PLAN_TIMEOUT_KEY, raw, DEFAULT_FIX_PLAN_TIMEOUT)
        return DEFAULT_FIX_PLAN_TIMEOUT
    return value


async def get_fix_plan_timeout(db: AsyncSession) -> int:
    row = await db.get(SystemSetting, FIX_PLAN_TIMEOUT_KEY)
    return parse_fix_plan_timeout(row.value if row is not None else None)


def max_task_seconds(fix_plan_timeout: int) -> int:
    """The longest a scan task may legitimately run: lock TTLs and stuck recovery use this."""
    return max(MIN_TASK_SECONDS, SCAN_SECONDS + fix_plan_timeout + TASK_MARGIN_SECONDS)
