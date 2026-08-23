"""Tests for the scheduler service."""
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import (
    AlertSeverity,
    FindingAcceptanceEvent,
    FindingRecord,
    RepoScan,
    RiskRecord,
    utcnow,
)
from app.scheduler.scheduler import (
    is_due,
    next_run_after,
    should_trigger_scan,
)

# ── Unit: cron evaluation ─────────────────────────────────────────────────────

def test_is_due_hourly_cron():
    expr = "0 * * * *"
    last_run = datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)
    now = datetime(2026, 6, 9, 11, 0, 0, tzinfo=UTC)
    assert is_due(expr, last_run, now) is True


def test_is_due_hourly_cron_not_yet():
    expr = "0 * * * *"
    last_run = datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)
    now = datetime(2026, 6, 9, 10, 30, 0, tzinfo=UTC)
    assert is_due(expr, last_run, now) is False


def test_is_due_when_no_last_run():
    assert is_due("0 * * * *", None, datetime.now(UTC)) is True


def test_is_due_with_grace_period():
    expr = "0 * * * *"
    last_run = datetime(2026, 6, 9, 8, 0, 0, tzinfo=UTC)
    now = datetime(2026, 6, 9, 11, 30, 0, tzinfo=UTC)
    assert is_due(expr, last_run, now) is True


def test_next_run_after():
    expr = "0 * * * *"
    after = datetime(2026, 6, 9, 10, 15, 0, tzinfo=UTC)
    nxt = next_run_after(expr, after)
    assert nxt == datetime(2026, 6, 9, 11, 0, 0, tzinfo=UTC)


def test_should_trigger_scan_enabled():
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 * * * *"
    scan.cron_timezone = None
    scan.last_scan_at = None
    assert should_trigger_scan(scan, datetime.now(UTC)) is True


def test_should_trigger_scan_disabled():
    scan = MagicMock()
    scan.is_enabled = False
    scan.cron_schedule = "0 * * * *"
    scan.cron_timezone = None
    scan.last_scan_at = None
    assert should_trigger_scan(scan, datetime.now(UTC)) is False


def test_should_trigger_scan_no_schedule():
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = None
    scan.cron_timezone = None
    scan.last_scan_at = None
    assert should_trigger_scan(scan, datetime.now(UTC)) is False


# ── Integration: trigger loop ─────────────────────────────────────────────────

@pytest.fixture
def mock_db_factory():
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock()
    factory.return_value = session
    return factory, session


@pytest.fixture
def due_scan():
    from app.models import AlertSeverity, CredentialType
    scan = MagicMock()
    scan.id = 1
    scan.name = "test-repo"
    scan.url = "https://github.com/test/repo"
    scan.branch = "main"
    scan.is_enabled = True
    scan.cron_schedule = "0 * * * *"
    scan.cron_timezone = None
    scan.last_scan_at = None
    scan.config_template_id = None
    scan.pa_version = "1.0.0"
    scan.credential_type = CredentialType.https_token
    scan.credential_secret_arn = None
    scan.min_notify_severity = AlertSeverity.medium
    scan.notify_recipients = []
    return scan


@pytest.mark.asyncio
async def test_run_one_tick_triggers_due_scans(mock_db_factory, due_scan):
    factory, session = mock_db_factory
    tz_setting = MagicMock()
    tz_setting.value = None
    session.get = AsyncMock(return_value=tz_setting)
    session.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[due_scan])))
    ))
    with patch("app.scheduler.scheduler.trigger_scan") as mock_trigger:
        mock_trigger.return_value = None
        from app.scheduler.scheduler import run_one_tick
        await run_one_tick(factory)
    mock_trigger.assert_called_once_with(due_scan, factory)


@pytest.mark.asyncio
async def test_run_one_tick_skips_disabled_scans(mock_db_factory, due_scan):
    due_scan.is_enabled = False
    factory, session = mock_db_factory
    tz_setting = MagicMock()
    tz_setting.value = None
    session.get = AsyncMock(return_value=tz_setting)
    session.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[due_scan])))
    ))
    with patch("app.scheduler.scheduler.trigger_scan") as mock_trigger:
        from app.scheduler.scheduler import run_one_tick
        await run_one_tick(factory)
    mock_trigger.assert_not_called()


@pytest.mark.asyncio
async def test_trigger_scan_creates_result_and_locks(mock_db_factory, due_scan):
    factory, session = mock_db_factory
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()

    with patch("app.scheduler.scheduler._acquire_scan_lock", return_value=True) as mock_lock, \
         patch("app.scheduler.scheduler._launch_ecs_task", return_value="arn:test") as mock_ecs:
        from app.scheduler.scheduler import trigger_scan
        await trigger_scan(due_scan, factory)

    mock_lock.assert_called_once()
    mock_ecs.assert_called_once()
    session.add.assert_called_once()


@pytest.mark.asyncio
async def test_trigger_scan_skips_if_lock_not_acquired(mock_db_factory, due_scan):
    factory, _session = mock_db_factory
    with patch("app.scheduler.scheduler._acquire_scan_lock", return_value=False), \
         patch("app.scheduler.scheduler._launch_ecs_task") as mock_ecs:
        from app.scheduler.scheduler import trigger_scan
        await trigger_scan(due_scan, factory)
    mock_ecs.assert_not_called()


# ── Stuck job recovery ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_recover_stuck_scans_marks_failed(mock_db_factory):
    from app.models import RepoScanStatus
    factory, session = mock_db_factory

    stuck = MagicMock()
    stuck.id = 10
    stuck.repo_scan_id = 5
    stuck.status = RepoScanStatus.running
    stuck.started_at = datetime.now(UTC) - timedelta(minutes=45)

    session.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[stuck])))
    ))
    session.commit = AsyncMock()

    with patch("app.scheduler.scheduler._release_scan_lock") as mock_release:
        from app.scheduler.scheduler import recover_stuck_scans
        await recover_stuck_scans(factory)

    assert stuck.status == RepoScanStatus.failed
    session.commit.assert_called_once()
    mock_release.assert_called_once_with(5)


# ── Retention pruning ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_prune_by_days_deletes_old_results(mock_db_factory):
    factory, session = mock_db_factory
    old = MagicMock()
    old.id = 100
    session.execute = AsyncMock(side_effect=[
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[
            MagicMock(key="scan_result_retention_days", value="30"),
            MagicMock(key="scan_result_retention_count", value=None),
        ])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[old])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
        MagicMock(),  # FindingRecord delete
        MagicMock(),  # RiskRecord delete
    ])
    session.delete = AsyncMock()
    session.commit = AsyncMock()

    from app.scheduler.scheduler import prune_old_results
    await prune_old_results(factory)

    session.delete.assert_called_once_with(old)
    session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_prune_by_days_ignores_negative_retention_days(mock_db_factory):
    """A negative scan_result_retention_days would compute a cutoff in the
    future (utcnow() - timedelta(days=-5)), matching every historical result.
    Write-time validation in system_settings.py already rejects negative
    values, but the worker defensively requires days > 0 too — this asserts
    a negative value reaching the worker (e.g. stored before that validation
    existed) is treated as absent rather than acted on. A row is present in
    the mocked "old results" query so a broken `if days:` guard (true for
    -5) would genuinely reach session.delete — this fails without the fix."""
    factory, session = mock_db_factory
    old = MagicMock()
    old.id = 100
    session.execute = AsyncMock(side_effect=[
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[
            MagicMock(key="scan_result_retention_days", value="-5"),
            MagicMock(key="scan_result_retention_count", value=None),
        ])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[old])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
        MagicMock(),  # FindingRecord delete
        MagicMock(),  # RiskRecord delete
    ])
    session.delete = AsyncMock()
    session.commit = AsyncMock()

    from app.scheduler.scheduler import prune_old_results
    await prune_old_results(factory)

    session.delete.assert_not_called()


@pytest.mark.asyncio
async def test_prune_by_days_ignores_zero_retention_days(mock_db_factory):
    """days == 0 intentionally disables day-based retention — must not be
    treated as "delete everything with age > 0". A row is present in the
    mocked "old results" query; if 0 were ever treated as "no limit" rather
    than "disabled", it would be deleted."""
    factory, session = mock_db_factory
    old = MagicMock()
    old.id = 101
    session.execute = AsyncMock(side_effect=[
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[
            MagicMock(key="scan_result_retention_days", value="0"),
            MagicMock(key="scan_result_retention_count", value=None),
        ])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[old])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
        MagicMock(),  # FindingRecord delete
        MagicMock(),  # RiskRecord delete
    ])
    session.delete = AsyncMock()
    session.commit = AsyncMock()

    from app.scheduler.scheduler import prune_old_results
    await prune_old_results(factory)

    session.delete.assert_not_called()


@pytest.mark.asyncio
async def test_prune_findings_default_when_no_scan_retention_settings(mock_db_factory):
    """When no scan_result retention settings exist, findings are still purged
    at the default 365-day threshold. The early-return no-op was removed;
    prune_old_results always runs finding purge."""
    from sqlalchemy.sql.dml import Delete
    factory, session = mock_db_factory
    session.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    ))
    session.delete = AsyncMock()
    from app.scheduler.scheduler import prune_old_results
    await prune_old_results(factory)

    # ORM-level delete() must not be called (no individual record deletions).
    session.delete.assert_not_called()

    # The bulk finding-purge DELETE must have been executed.
    delete_calls = [
        call for call in session.execute.call_args_list
        if call.args and isinstance(call.args[0], Delete)
    ]
    assert delete_calls, "expected a bulk DELETE statement for finding retention purge"


# ── Finding retention pruning ─────────────────────────────────────────────────

def _make_finding(repo_scan_id, closed_days_ago=None):
    now = datetime.now(UTC)
    return FindingRecord(
        repo_scan_id=repo_scan_id,
        advisory_id="GHSA-r", package="pkg", ecosystem="pypi",
        severity=AlertSeverity.high,
        first_found_at=now - timedelta(days=400),
        closed_at=(now - timedelta(days=closed_days_ago)) if closed_days_ago is not None else None,
        reopen_count=0,
    )


@pytest.mark.asyncio
class TestFindingRetentionPrune:
    async def test_old_closed_finding_pruned(self, db, admin_user):
        scan = RepoScan(name="rs", url="https://g.com/r.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        old_finding = _make_finding(scan.id, closed_days_ago=400)
        db.add(old_finding)
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert all(r.id != old_finding.id for r in rows)

    async def test_recent_closed_finding_not_pruned(self, db, admin_user):
        scan = RepoScan(name="rs2", url="https://g.com/r2.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        recent_finding = _make_finding(scan.id, closed_days_ago=10)
        db.add(recent_finding)
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert any(r.id == recent_finding.id for r in rows)

    async def test_open_finding_never_pruned(self, db, admin_user):
        scan = RepoScan(name="rs3", url="https://g.com/r3.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        open_finding = _make_finding(scan.id, closed_days_ago=None)
        db.add(open_finding)
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        rows = (await db.execute(select(FindingRecord).where(FindingRecord.closed_at.is_(None)))).scalars().all()
        assert any(r.id == open_finding.id for r in rows)


# ── Risk retention pruning ────────────────────────────────────────────────────

def _make_risk(repo_scan_id, closed_days_ago=None):
    now = datetime.now(UTC)
    closed_at = now - timedelta(days=closed_days_ago) if closed_days_ago is not None else None
    return RiskRecord(
        repo_scan_id=repo_scan_id,
        package="pkg", ecosystem="pypi", package_version="1.0",
        score=80, level="critical", signals=[],
        first_found_at=now - timedelta(days=(closed_days_ago or 0) + 5),
        closed_at=closed_at,
        reopen_count=0,
    )


@pytest.mark.asyncio
class TestRiskRetentionPrune:
    async def test_old_closed_risk_pruned(self, db, admin_user):
        scan = RepoScan(name="risk-rs", url="https://g.com/rr.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        old_risk = _make_risk(scan.id, closed_days_ago=400)
        db.add(old_risk)
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert all(r.id != old_risk.id for r in rows)

    async def test_recent_closed_risk_not_pruned(self, db, admin_user):
        scan = RepoScan(name="risk-rs2", url="https://g.com/rr2.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        recent_risk = _make_risk(scan.id, closed_days_ago=10)
        db.add(recent_risk)
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert any(r.id == recent_risk.id for r in rows)

    async def test_open_risk_never_pruned(self, db, admin_user):
        scan = RepoScan(name="risk-rs3", url="https://g.com/rr3.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        open_risk = _make_risk(scan.id, closed_days_ago=None)
        db.add(open_risk)
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        rows = (await db.execute(select(RiskRecord).where(RiskRecord.closed_at.is_(None)))).scalars().all()
        assert any(r.id == open_risk.id for r in rows)


# ── Acceptance Event cascade delete ───────────────────────────────────────────

@pytest.mark.asyncio
class TestAcceptanceEventCascadeDelete:
    async def test_finding_acceptance_events_deleted_with_parent_record(self, db, admin_user):
        scan = RepoScan(name="cascade-rs", url="https://g.com/c.git", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        old_finding = _make_finding(scan.id, closed_days_ago=400)
        db.add(old_finding)
        await db.commit()
        await db.refresh(old_finding)

        db.add(FindingAcceptanceEvent(
            finding_record_id=old_finding.id, action="accepted",
            at=utcnow(), by_user_id=admin_user.id,
        ))
        await db.commit()

        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        from app.scheduler.scheduler import prune_old_results
        factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
        await prune_old_results(factory)

        from sqlalchemy import select
        events = (await db.execute(
            select(FindingAcceptanceEvent).where(FindingAcceptanceEvent.finding_record_id == old_finding.id)
        )).scalars().all()
        assert events == []
