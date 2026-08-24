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


def test_is_due_since_creation_when_no_last_run():
    """A scan created just before its first cron occurrence is due once
    that occurrence passes — it does not fire immediately regardless of
    schedule."""
    expr = "0 * * * *"
    created_at = datetime(2026, 6, 9, 10, 30, 0, tzinfo=UTC)
    not_yet = datetime(2026, 6, 9, 10, 45, 0, tzinfo=UTC)
    due = datetime(2026, 6, 9, 11, 0, 0, tzinfo=UTC)
    assert is_due(expr, created_at, not_yet) is False
    assert is_due(expr, created_at, due) is True


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
    scan.enabled_at = datetime(2026, 6, 9, 9, 0, 0, tzinfo=UTC)
    scan.created_at = scan.enabled_at
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)) is True


def test_should_trigger_scan_not_yet_due_from_enabling():
    """A freshly enabled scan waits for its own next cron occurrence — it
    does not fire immediately just because it has never run."""
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 7 * * 1"  # Monday 07:00
    scan.cron_timezone = None
    scan.last_scan_at = None
    scan.enabled_at = datetime(2026, 6, 9, 8, 0, 0, tzinfo=UTC)  # Tuesday
    scan.created_at = scan.enabled_at
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 8, 1, 0, tzinfo=UTC)) is False


def test_should_trigger_scan_anchors_to_enabled_at_not_created_at():
    """A scan created disabled (or re-enabled after missing an occurrence)
    must wait for its next occurrence from when it actually became enabled
    — created_at alone would already be in the past for that missed window
    and fire immediately on the very next tick."""
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 7 * * 1"  # Monday 07:00
    scan.cron_timezone = None
    scan.last_scan_at = None
    scan.created_at = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)  # long before any Monday 07:00
    scan.enabled_at = datetime(2026, 6, 9, 8, 0, 0, tzinfo=UTC)  # Tuesday, just re-enabled
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 8, 1, 0, tzinfo=UTC)) is False


def test_should_trigger_scan_falls_back_to_created_at_when_enabled_at_missing():
    """Defensive fallback for a scan that somehow predates both a
    successful run and the enabled_at column/backfill."""
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 7 * * 1"  # Monday 07:00
    scan.cron_timezone = None
    scan.last_scan_at = None
    scan.enabled_at = None
    scan.created_at = datetime(2026, 6, 9, 8, 0, 0, tzinfo=UTC)  # Tuesday
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 8, 1, 0, tzinfo=UTC)) is False
    assert should_trigger_scan(scan, datetime(2026, 6, 15, 7, 0, 0, tzinfo=UTC)) is True


def test_should_trigger_scan_re_enabling_a_previously_successful_scan_waits_for_next_occurrence():
    """A scan that already ran successfully once, then was disabled through
    one or more scheduled occurrences, then re-enabled, must not use its
    stale last_scan_at as the anchor — that predates the gap and would look
    overdue the instant it's turned back on. The anchor must be the later
    of last_scan_at and enabled_at, not "prefer last_scan_at" outright."""
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 7 * * 1"  # Monday 07:00
    scan.cron_timezone = None
    # Ran successfully two Mondays ago...
    scan.last_scan_at = datetime(2026, 5, 25, 7, 0, 5, tzinfo=UTC)
    # ...then was disabled through last Monday's occurrence, and only
    # re-enabled this Tuesday — after the missed occurrence, not before it.
    scan.enabled_at = datetime(2026, 6, 9, 8, 0, 0, tzinfo=UTC)
    scan.created_at = datetime(2026, 5, 1, 0, 0, 0, tzinfo=UTC)
    # Without the fix: next_run_after(last_scan_at) is last Monday (06-08,
    # already passed) => due immediately. With the fix: next_run_after
    # picks up from enabled_at (this Tuesday) => next Monday (06-15).
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 8, 1, 0, tzinfo=UTC)) is False
    assert should_trigger_scan(scan, datetime(2026, 6, 15, 7, 0, 0, tzinfo=UTC)) is True


def test_should_trigger_scan_disabled():
    scan = MagicMock()
    scan.is_enabled = False
    scan.cron_schedule = "0 * * * *"
    scan.cron_timezone = None
    scan.last_scan_at = None
    scan.enabled_at = None
    scan.created_at = datetime(2026, 6, 9, 9, 0, 0, tzinfo=UTC)
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)) is False


def test_should_trigger_scan_no_schedule():
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = None
    scan.cron_timezone = None
    scan.last_scan_at = None
    scan.enabled_at = datetime(2026, 6, 9, 9, 0, 0, tzinfo=UTC)
    scan.created_at = scan.enabled_at
    assert should_trigger_scan(scan, datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)) is False


def test_should_trigger_scan_withholds_during_failure_backoff():
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 * * * *"
    scan.cron_timezone = None
    scan.last_scan_at = datetime(2026, 6, 9, 9, 0, 0, tzinfo=UTC)
    scan.enabled_at = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    scan.created_at = scan.enabled_at
    now = datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)  # cron-due
    last_failed_attempt_at = datetime(2026, 6, 9, 9, 55, 0, tzinfo=UTC)  # 5 min ago
    assert should_trigger_scan(scan, now, last_failed_at=last_failed_attempt_at) is False


def test_should_trigger_scan_retries_after_backoff_expires():
    scan = MagicMock()
    scan.is_enabled = True
    scan.cron_schedule = "0 * * * *"
    scan.cron_timezone = None
    scan.last_scan_at = datetime(2026, 6, 9, 9, 0, 0, tzinfo=UTC)
    scan.enabled_at = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    scan.created_at = scan.enabled_at
    now = datetime(2026, 6, 9, 10, 0, 0, tzinfo=UTC)  # cron-due
    last_failed_attempt_at = datetime(2026, 6, 9, 9, 45, 0, tzinfo=UTC)  # 15 min ago
    assert should_trigger_scan(scan, now, last_failed_at=last_failed_attempt_at) is True


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
    scan.enabled_at = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    scan.created_at = scan.enabled_at
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
async def test_run_one_tick_withholds_scan_in_failure_backoff(mock_db_factory, due_scan):
    """A scan whose most recent result is a recent launch failure must not
    be retried on the very next tick — see should_trigger_scan's backoff."""
    from app.models import RepoScanStatus
    due_scan.enabled_at = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    factory, session = mock_db_factory
    tz_setting = MagicMock()
    tz_setting.value = None
    session.get = AsyncMock(return_value=tz_setting)
    now = datetime.now(UTC)
    failed_at = now - timedelta(minutes=1)
    session.execute = AsyncMock(side_effect=[
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[due_scan])))),
        MagicMock(__iter__=lambda self: iter([
            (due_scan.id, RepoScanStatus.failed, failed_at - timedelta(seconds=30), failed_at)
        ])),
    ])
    with patch("app.scheduler.scheduler.trigger_scan") as mock_trigger, \
         patch("app.scheduler.scheduler.utcnow", return_value=now):
        from app.scheduler.scheduler import run_one_tick
        await run_one_tick(factory)
    mock_trigger.assert_not_called()


@pytest.mark.asyncio
async def test_run_one_tick_backoff_counts_from_completion_not_launch_start(mock_db_factory, due_scan):
    """A launch that hangs before finally raising must back off from when
    the failure was recorded (completed_at), not from started_at — which is
    stamped before the launch attempt even begins. Otherwise a hang longer
    than FAILED_LAUNCH_BACKOFF_MINUTES would already be past its own
    backoff window the instant the failure is written, and the very next
    tick could retry immediately."""
    from app.models import RepoScanStatus
    from app.scheduler.scheduler import FAILED_LAUNCH_BACKOFF_MINUTES
    due_scan.enabled_at = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)
    factory, session = mock_db_factory
    tz_setting = MagicMock()
    tz_setting.value = None
    session.get = AsyncMock(return_value=tz_setting)
    now = datetime.now(UTC)
    # started_at is old enough that backoff-from-started_at would already
    # have expired; completed_at (when it actually failed) is recent.
    started_at = now - timedelta(minutes=FAILED_LAUNCH_BACKOFF_MINUTES + 5)
    completed_at = now - timedelta(minutes=1)
    session.execute = AsyncMock(side_effect=[
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[due_scan])))),
        MagicMock(__iter__=lambda self: iter([
            (due_scan.id, RepoScanStatus.failed, started_at, completed_at)
        ])),
    ])
    with patch("app.scheduler.scheduler.trigger_scan") as mock_trigger, \
         patch("app.scheduler.scheduler.utcnow", return_value=now):
        from app.scheduler.scheduler import run_one_tick
        await run_one_tick(factory)
    mock_trigger.assert_not_called()


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
async def test_run_one_tick_skips_the_ranked_results_query_with_no_candidate_scans(mock_db_factory, due_scan):
    """The row_number() window over repo_scan_results must not run at all
    when nothing could possibly be triggered this tick — otherwise every
    poll pays for a query proportional to the whole (ever-growing) results
    table just to answer a backoff check that has no scans to apply to."""
    due_scan.is_enabled = False
    factory, session = mock_db_factory
    tz_setting = MagicMock()
    tz_setting.value = None
    session.get = AsyncMock(return_value=tz_setting)
    session.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[due_scan])))
    ))
    with patch("app.scheduler.scheduler.trigger_scan"):
        from app.scheduler.scheduler import run_one_tick
        await run_one_tick(factory)
    # Only the initial `select(RepoScan)` should have run — no second
    # execute() for the ranked-results subquery.
    assert session.execute.call_count == 1


@pytest.mark.asyncio
async def test_run_one_tick_restricts_ranked_results_to_candidate_scan_ids(mock_db_factory, due_scan):
    """The ranked-results query must filter to enabled, scheduled scans —
    not scan every row in repo_scan_results — so its cost tracks the number
    of active schedules rather than total historical result volume. The
    filter must be a correlated subquery against RepoScan, not an IN-list of
    literal ids: a literal list needs one bind parameter per candidate scan,
    which can exceed the driver's bind-parameter ceiling (SQLite defaults to
    32766) once there are enough active schedules, failing every tick
    outright instead of launching anything."""
    factory, session = mock_db_factory
    tz_setting = MagicMock()
    tz_setting.value = None
    session.get = AsyncMock(return_value=tz_setting)
    session.execute = AsyncMock(side_effect=[
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[due_scan])))),
        MagicMock(__iter__=lambda self: iter([])),
    ])
    with patch("app.scheduler.scheduler.trigger_scan"):
        from app.scheduler.scheduler import run_one_tick
        await run_one_tick(factory)
    assert session.execute.call_count == 2
    ranked_query = session.execute.call_args_list[1].args[0]
    ranked_subquery = ranked_query.selected_columns[0].table.element
    where_clause = str(ranked_subquery.whereclause)
    assert "repo_scan_id IN" in where_clause

    compiled = ranked_subquery.compile()
    # A literal IN-list renders one bind parameter per candidate id; a
    # correlated subquery renders none for this filter regardless of how
    # many scans are enabled — bind-parameter count must not scale with
    # candidate count.
    assert not any(name.startswith("repo_scan_id_") for name in compiled.params)


@pytest.mark.asyncio
async def test_run_one_tick_candidate_filter_excludes_empty_string_schedule(db, admin_user):
    """should_trigger_scan treats cron_schedule="" the same as None (`if not
    scan.cron_schedule: return False`) — the API's schema is `str | None`
    with no validator rejecting an empty string, so a scan can genuinely end
    up with cron_schedule="". The SQL candidate filter must exclude it too,
    not just NULL: otherwise every enabled scan with an empty schedule gets
    ranked in the results window on every tick regardless of how much
    manual-trigger history it has, defeating the point of restricting the
    query to scans that could actually be triggered."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from app.models import RepoScanResult, RepoScanStatus, ScanTrigger
    from app.scheduler.scheduler import run_one_tick

    valid = RepoScan(
        name="valid", url="https://g.com/valid.git", branch="main",
        min_notify_severity="medium", is_enabled=True, cron_schedule="0 * * * *",
        enabled_at=datetime(2026, 1, 1, tzinfo=UTC), created_by_id=admin_user.id,
    )
    empty_schedule = RepoScan(
        name="empty-schedule", url="https://g.com/empty.git", branch="main",
        min_notify_severity="medium", is_enabled=True, cron_schedule="",
        enabled_at=datetime(2026, 1, 1, tzinfo=UTC), created_by_id=admin_user.id,
    )
    db.add_all([valid, empty_schedule])
    await db.commit()
    await db.refresh(valid)
    await db.refresh(empty_schedule)

    # A recent failed result for the empty-schedule scan — if it were
    # wrongly included by the candidate filter, it would show up in the
    # ranked results this tick even though it can never be triggered.
    recent_failure = utcnow() - timedelta(minutes=1)
    db.add(RepoScanResult(
        repo_scan_id=empty_schedule.id, status=RepoScanStatus.failed,
        triggered_by=ScanTrigger.scheduled, started_at=recent_failure, completed_at=recent_failure,
    ))
    await db.commit()

    factory = async_sessionmaker(bind=db.bind, class_=AsyncSession, expire_on_commit=False)
    seen_last_failed_at: dict[int, object] = {}

    def _recording_should_trigger_scan(scan, now, default_tz=None, last_failed_at=None):
        seen_last_failed_at[scan.id] = last_failed_at
        return should_trigger_scan(scan, now, default_tz, last_failed_at)

    with patch("app.scheduler.scheduler.trigger_scan"), \
         patch("app.scheduler.scheduler.should_trigger_scan", side_effect=_recording_should_trigger_scan):
        await run_one_tick(factory)

    # The empty-schedule scan's recent failure must never surface as a
    # last_failed_at, whether or not should_trigger_scan itself would have
    # ignored it — proving the SQL candidate filter excluded it upstream.
    assert seen_last_failed_at.get(empty_schedule.id) is None
    # Sanity check should_trigger_scan was actually invoked for both scans.
    assert set(seen_last_failed_at) == {valid.id, empty_schedule.id}


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
