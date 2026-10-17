"""fix_plan_timeout_seconds: one parser for the PATCH check and every runtime read."""
import logging

import pytest

from app.models import SystemSetting
from app.services.fix_plan_budget import (
    DEFAULT_FIX_PLAN_TIMEOUT,
    MAX_FIX_PLAN_TIMEOUT,
    MIN_FIX_PLAN_TIMEOUT,
    get_fix_plan_timeout,
    max_task_seconds,
    parse_fix_plan_timeout,
)
from tests.conftest import auth


@pytest.mark.parametrize("raw, expected", [
    ("900", 900), ("120", 120), ("3600", 3600), (" 600 ", 600),
])
def test_parse_accepts_in_range(raw, expected):
    assert parse_fix_plan_timeout(raw) == expected


@pytest.mark.parametrize("raw", [None, "", "119", "3601", "-5", "abc", "1.5"])
def test_parse_falls_back(raw, caplog):
    with caplog.at_level(logging.WARNING):
        assert parse_fix_plan_timeout(raw) == DEFAULT_FIX_PLAN_TIMEOUT
    if raw not in (None, ""):
        assert "fix_plan_timeout_seconds" in caplog.text


@pytest.mark.parametrize("budget, expected", [(120, 1800), (900, 1800), (1200, 2100), (3600, 4500)])
def test_max_task_seconds(budget, expected):
    assert max_task_seconds(budget) == expected


@pytest.mark.asyncio
async def test_get_reads_the_row_and_defaults_without_one(db):
    assert await get_fix_plan_timeout(db) == DEFAULT_FIX_PLAN_TIMEOUT
    db.add(SystemSetting(key="fix_plan_timeout_seconds", value="1500", value_type="int"))
    await db.commit()
    assert await get_fix_plan_timeout(db) == 1500


@pytest.mark.asyncio
class TestPatch:
    async def test_in_range_is_saved(self, client, admin_token):
        r = await client.patch("/api/system-settings", json={"updates": {"fix_plan_timeout_seconds": "1200"}},
                               headers=auth(admin_token))
        assert r.status_code == 200, r.text
        assert {s["key"]: s["value"] for s in r.json()}["fix_plan_timeout_seconds"] == "1200"

    @pytest.mark.parametrize("value", [str(MIN_FIX_PLAN_TIMEOUT - 1), str(MAX_FIX_PLAN_TIMEOUT + 1), "0", "-1"])
    async def test_out_of_range_is_rejected(self, client, admin_token, value):
        r = await client.patch("/api/system-settings", json={"updates": {"fix_plan_timeout_seconds": value}},
                               headers=auth(admin_token))
        assert r.status_code == 400
        assert "120" in r.text and "3600" in r.text

    async def test_non_integer_is_rejected(self, client, admin_token):
        r = await client.patch("/api/system-settings", json={"updates": {"fix_plan_timeout_seconds": "fast"}},
                               headers=auth(admin_token))
        assert r.status_code == 400

    async def test_requires_admin(self, client, operator_token):
        r = await client.patch("/api/system-settings", json={"updates": {"fix_plan_timeout_seconds": "900"}},
                               headers=auth(operator_token))
        assert r.status_code == 403
