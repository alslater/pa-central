"""One task environment for manual and scheduled scans; budget-driven timeouts."""
import json
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.config import settings as app_settings
from app.models import (
    ConfigTemplate,
    CredentialType,
    RepoCredential,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    ScanTrigger,
    SystemSetting,
    repo_scan_package_indexes,
    utcnow,
)
from app.services.scan_launch import build_scan_task_env
from tests.conftest import auth


@pytest.fixture
async def scan(db, admin_user):
    tmpl = ConfigTemplate(name="t", toml_content="[osv]\ncache_ttl_hours = 1\n", created_by_id=admin_user.id)
    db.add(tmpl)
    await db.flush()
    s = RepoScan(name="s", url="https://github.com/x/s", branch="main", min_notify_severity="medium",
                 created_by_id=admin_user.id, config_template_id=tmpl.id, fix_plans_enabled=True)
    db.add(s)
    db.add(SystemSetting(key="pa_version", value="0.10.0", value_type="string"))
    db.add(SystemSetting(key="fix_plan_timeout_seconds", value="1200", value_type="int"))
    await db.commit()
    return s


async def _link(db, scan, url, arn, username=None):
    c = RepoCredential(name=url, credential_type=CredentialType.package_index, index_url=url,
                       index_username=username, credential_secret_arn=arn)
    db.add(c)
    await db.flush()
    await db.execute(repo_scan_package_indexes.insert().values(repo_scan_id=scan.id, credential_id=c.id))
    await db.commit()


@pytest.mark.asyncio
class TestBuildEnv:
    async def test_includes_config_version_budget_and_flag(self, db, scan):
        env = await build_scan_task_env(db, scan, 7)
        assert env["PA_VERSION"] == "0.10.0"
        assert env["PA_CONFIG_TOML"].startswith("[osv]")
        assert env["FIX_PLANS"] == "1"
        assert env["FIX_PLAN_TIMEOUT"] == "1200"
        assert env["PACKAGE_INDEXES"] == ""
        assert env["REPO_SCAN_RESULT_ID"] == "7"

    async def test_flag_off(self, db, scan):
        scan.fix_plans_enabled = False
        assert (await build_scan_task_env(db, scan, 1))["FIX_PLANS"] == ""

    async def test_package_indexes_arn_and_local(self, db, scan):
        await _link(db, scan, "https://a.example/simple", "arn:aws:secretsmanager:x:1:secret:a", "reader")
        await _link(db, scan, "https://b.example/simple", "local://tok")
        indexes = json.loads((await build_scan_task_env(db, scan, 1))["PACKAGE_INDEXES"])
        assert indexes == [
            {"url": "https://a.example/simple", "username": "reader",
             "secret_arn": "arn:aws:secretsmanager:x:1:secret:a"},
            {"url": "https://b.example/simple", "username": None, "value": "tok"},
        ]


@pytest.fixture
def ecs_launches(monkeypatch):
    """The ECS launch path, with EcsClient replaced by a recorder: no AWS, and not the local-Docker
    workaround (CLAUDE.md). Returns the environments the scan tasks would be launched with."""
    sent = []

    class FakeEcs:
        def __init__(self, *a, **kw):
            pass

        async def run_scan_task(self, *, environment, **_kw):
            sent.append(dict(environment))
            return "arn:aws:ecs:eu-west-1:000000000000:task/pa/x"

    monkeypatch.setattr(app_settings, "local_docker_scan", False)
    monkeypatch.setattr(app_settings, "scan_task_fleet_url", "https://pa-central.example")
    monkeypatch.setattr("app.api.repo_scans.EcsClient", FakeEcs)  # manual trigger
    monkeypatch.setattr("app.core.aws.EcsClient", FakeEcs)  # the scheduler imports it at call time
    return sent


@pytest.mark.asyncio
@pytest.mark.parametrize("pin, expected", [(None, "0.10.0"), ("0.10.0rc1", "0.10.0rc1")])
async def test_manual_and_scheduled_send_the_same_env(db, scan, client, admin_token, monkeypatch, pin, expected,
                                                      ecs_launches):
    """Both paths launch, and record, the scan's pinned version, else the pa_version setting."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.scheduler import scheduler as sched

    scan.pa_version = pin
    await db.commit()
    scan_id = scan.id
    sent = ecs_launches
    with patch("app.api.repo_scans._get_valkey") as mv:
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=None)
        ctx.__aexit__ = AsyncMock(return_value=None)
        mv.return_value = ctx
        r = await client.post(f"/api/repo-scans/{scan.id}/trigger", headers=auth(admin_token))
    assert r.status_code == 202, r.text
    factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
    monkeypatch.setattr(sched, "_acquire_scan_lock", AsyncMock(return_value=True))
    await sched.trigger_scan(scan, factory)
    manual, scheduled = sent
    for key in ("REPO_SCAN_RESULT_ID",):
        manual.pop(key)
        scheduled.pop(key)
    assert manual == scheduled
    assert scheduled["PA_CONFIG_TOML"] and scheduled["PA_VERSION"] == expected
    recorded = (await db.execute(select(RepoScanResult.pa_version)
                                 .where(RepoScanResult.repo_scan_id == scan_id)
                                 .execution_options(populate_existing=True))).scalars()
    assert list(recorded) == [expected, expected]


@pytest.mark.asyncio
async def test_manual_lock_ttl_follows_the_budget(db, scan, client, admin_token, monkeypatch, ecs_launches):
    seen = {}

    async def fake_acquire(r, key, ttl_seconds):
        seen["ttl"] = ttl_seconds
        return True

    monkeypatch.setattr("app.api.repo_scans.acquire_lock", fake_acquire)
    with patch("app.api.repo_scans._get_valkey") as mv:
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=MagicMock())
        ctx.__aexit__ = AsyncMock(return_value=None)
        mv.return_value = ctx
        await client.post(f"/api/repo-scans/{scan.id}/trigger", headers=auth(admin_token))
    assert seen["ttl"] == 600 + 1200 + 300


@pytest.mark.asyncio
async def test_scheduler_lock_ttl_follows_the_budget(db, scan, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.scheduler import scheduler as sched

    acquire = AsyncMock(return_value=False)
    monkeypatch.setattr(sched, "_acquire_scan_lock", acquire)
    factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
    await sched.trigger_scan(scan, factory)
    acquire.assert_awaited_once_with(scan.id, 2100)


@pytest.mark.asyncio
@pytest.mark.parametrize("budget, minutes_old, stuck", [
    (None, 31, True), (None, 29, False), ("3600", 70, False), ("3600", 76, True), ("", 31, True),
])
async def test_stuck_recovery_uses_the_budget(db, admin_user, budget, minutes_old, stuck):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.scheduler.scheduler import recover_stuck_scans

    if budget is not None:
        db.add(SystemSetting(key="fix_plan_timeout_seconds", value=budget, value_type="int"))
    s = RepoScan(name="s", url="https://github.com/x/s", branch="main", min_notify_severity="medium",
                 created_by_id=admin_user.id)
    db.add(s)
    await db.flush()
    res = RepoScanResult(repo_scan_id=s.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual,
                         started_at=utcnow() - timedelta(minutes=minutes_old))
    db.add(res)
    await db.commit()
    factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
    await recover_stuck_scans(factory)
    await db.refresh(res)
    assert (res.status == RepoScanStatus.failed) is stuck


@pytest.mark.asyncio
async def test_a_stored_pa_version_with_whitespace_is_stripped(db, scan):
    # Stored before the setting was normalised on write.
    from sqlalchemy import update

    await db.execute(update(SystemSetting).where(SystemSetting.key == "pa_version").values(value="  0.10.0 "))
    await db.commit()
    env = await build_scan_task_env(db, scan, 7)
    assert env["PA_VERSION"] == "0.10.0"
