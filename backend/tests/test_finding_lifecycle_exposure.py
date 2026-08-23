"""Tests for exposure-history scoring logic in finding_lifecycle.py."""
from datetime import UTC, date, datetime
from types import SimpleNamespace

from app.models import AlertSeverity
from app.services.finding_lifecycle import (
    EXPOSURE_WEIGHTS,
    compute_exposure_history,
    is_accepted_as_of,
)

_next_id = iter(range(1, 10_000))


def _make_record(**kwargs) -> SimpleNamespace:
    defaults = {
        "id": next(_next_id),
        "severity": AlertSeverity.critical,
        "first_found_at": datetime(2026, 1, 1, tzinfo=UTC),
        "closed_at": None,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _history_for(record, events, window_days, today):
    """Convenience wrapper: run compute_exposure_history for a single record
    with its events, building the events_by_record_id dict for it."""
    return compute_exposure_history(
        [record], events_by_record_id={record.id: events}, window_days=window_days, today=today
    )


class TestExposureWeights:
    def test_weights_match_spec(self):
        assert EXPOSURE_WEIGHTS[AlertSeverity.critical] == 81
        assert EXPOSURE_WEIGHTS[AlertSeverity.high] == 27
        assert EXPOSURE_WEIGHTS[AlertSeverity.medium] == 9
        assert EXPOSURE_WEIGHTS[AlertSeverity.warning] == 5
        assert EXPOSURE_WEIGHTS[AlertSeverity.low] == 3
        assert EXPOSURE_WEIGHTS[AlertSeverity.info] == 1


def _event(action, at, accepted_until=None):
    return SimpleNamespace(action=action, at=at, accepted_until=accepted_until)


class TestIsAcceptedAsOf:
    def test_no_events_is_not_accepted(self):
        assert is_accepted_as_of([], date(2026, 6, 1)) is False

    def test_accepted_no_expiry_is_accepted_on_any_later_day(self):
        events = [_event("accepted", datetime(2026, 1, 1, tzinfo=UTC))]
        assert is_accepted_as_of(events, date(2026, 6, 1)) is True

    def test_accepted_before_event_day_is_not_accepted(self):
        events = [_event("accepted", datetime(2026, 6, 1, tzinfo=UTC))]
        assert is_accepted_as_of(events, date(2026, 1, 1)) is False

    def test_accepted_with_future_expiry_is_accepted(self):
        events = [_event("accepted", datetime(2026, 1, 1, tzinfo=UTC), accepted_until=date(2026, 12, 31))]
        assert is_accepted_as_of(events, date(2026, 6, 1)) is True

    def test_accepted_with_past_expiry_is_not_accepted(self):
        events = [_event("accepted", datetime(2026, 1, 1, tzinfo=UTC), accepted_until=date(2026, 3, 1))]
        assert is_accepted_as_of(events, date(2026, 6, 1)) is False

    def test_accepted_until_equal_to_day_is_lapsed(self):
        events = [_event("accepted", datetime(2026, 1, 1, tzinfo=UTC), accepted_until=date(2026, 6, 1))]
        assert is_accepted_as_of(events, date(2026, 6, 1)) is False

    def test_accepted_then_revoked_is_accepted_only_between_the_two_events(self):
        # This is the regression test for P2: revocation must not erase the
        # historical acceptance window between the accept and revoke events.
        events = [
            _event("accepted", datetime(2026, 1, 5, tzinfo=UTC)),
            _event("revoked", datetime(2026, 1, 20, tzinfo=UTC)),
        ]
        assert is_accepted_as_of(events, date(2026, 1, 4)) is False   # before accept
        assert is_accepted_as_of(events, date(2026, 1, 5)) is True    # on accept day
        assert is_accepted_as_of(events, date(2026, 1, 15)) is True   # during acceptance
        assert is_accepted_as_of(events, date(2026, 1, 20)) is False  # on revoke day
        assert is_accepted_as_of(events, date(2026, 1, 25)) is False  # after revoke

    def test_accepted_revoked_then_accepted_again(self):
        events = [
            _event("accepted", datetime(2026, 1, 5, tzinfo=UTC)),
            _event("revoked", datetime(2026, 1, 20, tzinfo=UTC)),
            _event("accepted", datetime(2026, 2, 1, tzinfo=UTC)),
        ]
        assert is_accepted_as_of(events, date(2026, 1, 15)) is True   # first acceptance
        assert is_accepted_as_of(events, date(2026, 1, 25)) is False  # revoked, before re-accept
        assert is_accepted_as_of(events, date(2026, 2, 5)) is True    # second acceptance


class TestComputeExposureHistory:
    def test_finding_open_across_full_window_contributes_every_day(self):
        record = _make_record(
            severity=AlertSeverity.critical,
            first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
            closed_at=None,
        )
        today = date(2026, 1, 10)
        history = _history_for(record, events=[], window_days=5, today=today)
        assert len(history) == 5
        assert [day for day, _ in history] == [
            date(2026, 1, 6), date(2026, 1, 7), date(2026, 1, 8),
            date(2026, 1, 9), date(2026, 1, 10),
        ]
        assert all(exposure == 81 for _, exposure in history)

    def test_finding_closed_mid_window_stops_contributing(self):
        record = _make_record(
            severity=AlertSeverity.high,
            first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
            closed_at=datetime(2026, 1, 8, tzinfo=UTC),
        )
        today = date(2026, 1, 10)
        history = _history_for(record, events=[], window_days=5, today=today)
        by_day = dict(history)
        assert by_day[date(2026, 1, 6)] == 27
        assert by_day[date(2026, 1, 7)] == 27
        assert by_day[date(2026, 1, 8)] == 0  # closed_at.date() == this day → not open
        assert by_day[date(2026, 1, 9)] == 0
        assert by_day[date(2026, 1, 10)] == 0

    def test_finding_not_yet_found_does_not_contribute_early(self):
        record = _make_record(
            severity=AlertSeverity.medium,
            first_found_at=datetime(2026, 1, 8, tzinfo=UTC),
            closed_at=None,
        )
        today = date(2026, 1, 10)
        history = _history_for(record, events=[], window_days=5, today=today)
        by_day = dict(history)
        assert by_day[date(2026, 1, 6)] == 0
        assert by_day[date(2026, 1, 7)] == 0
        assert by_day[date(2026, 1, 8)] == 9
        assert by_day[date(2026, 1, 9)] == 9
        assert by_day[date(2026, 1, 10)] == 9

    def test_accepted_mid_window_then_unaccepted_contributes_on_both_sides(self):
        record = _make_record(
            severity=AlertSeverity.low,
            first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
            closed_at=None,
        )
        events = [_event("accepted", datetime(2026, 1, 6, tzinfo=UTC), accepted_until=date(2026, 1, 8))]
        today = date(2026, 1, 10)
        history = _history_for(record, events, window_days=5, today=today)
        by_day = dict(history)
        assert by_day[date(2026, 1, 6)] == 0  # accepted, no expiry yet reached
        assert by_day[date(2026, 1, 7)] == 0  # still accepted
        assert by_day[date(2026, 1, 8)] == 3  # accepted_until == this day → lapsed, open again
        assert by_day[date(2026, 1, 9)] == 3
        assert by_day[date(2026, 1, 10)] == 3

    def test_accepting_today_does_not_retroactively_clear_past_exposure(self):
        # Regression test: accepted_at must gate acceptance so that accepting
        # a finding TODAY does not erase its exposure on every day before the
        # acceptance happened. A prior bug omitted this check entirely, so
        # is_accepted_as_of only looked at accepted_until (expiry), making
        # every day back to first_found_at read as "accepted" the moment
        # accepted_at was set at all.
        record = _make_record(
            severity=AlertSeverity.high,
            first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
            closed_at=None,
        )
        events = [_event("accepted", datetime(2026, 1, 10, tzinfo=UTC))]
        today = date(2026, 1, 10)
        history = _history_for(record, events, window_days=10, today=today)
        by_day = dict(history)
        # Every day before acceptance started must still show the finding as open.
        assert by_day[date(2026, 1, 1)] == 27
        assert by_day[date(2026, 1, 5)] == 27
        assert by_day[date(2026, 1, 9)] == 27
        # The day acceptance takes effect, and today, it's accepted (excluded).
        assert by_day[date(2026, 1, 10)] == 0

    def test_accepted_then_revoked_shows_exposed_again_after_revoke(self):
        # Regression test for P2 through compute_exposure_history itself (not
        # just is_accepted_as_of in isolation): a revoked acceptance must not
        # erase exposure during the window it was actually accepted, and must
        # correctly resume showing exposure after the revoke.
        record = _make_record(
            severity=AlertSeverity.high,
            first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
            closed_at=None,
        )
        events = [
            _event("accepted", datetime(2026, 1, 5, tzinfo=UTC)),
            _event("revoked", datetime(2026, 1, 8, tzinfo=UTC)),
        ]
        today = date(2026, 1, 10)
        history = _history_for(record, events, window_days=10, today=today)
        by_day = dict(history)
        assert by_day[date(2026, 1, 1)] == 27  # before acceptance
        assert by_day[date(2026, 1, 4)] == 27  # still before acceptance
        assert by_day[date(2026, 1, 5)] == 0   # accepted
        assert by_day[date(2026, 1, 7)] == 0   # still accepted
        assert by_day[date(2026, 1, 8)] == 27  # revoked — exposed again
        assert by_day[date(2026, 1, 10)] == 27  # today, still exposed

    def test_weights_sum_across_mixed_severities_same_day(self):
        records = [
            _make_record(severity=AlertSeverity.critical, first_found_at=datetime(2026, 1, 1, tzinfo=UTC)),
            _make_record(severity=AlertSeverity.high, first_found_at=datetime(2026, 1, 1, tzinfo=UTC)),
            _make_record(severity=AlertSeverity.info, first_found_at=datetime(2026, 1, 1, tzinfo=UTC)),
        ]
        today = date(2026, 1, 3)
        history = compute_exposure_history(
            records, events_by_record_id={}, window_days=1, today=today
        )
        assert history == [(date(2026, 1, 3), 81 + 27 + 1)]

    def test_empty_records_gives_zero_every_day(self):
        history = compute_exposure_history(
            [], events_by_record_id={}, window_days=3, today=date(2026, 1, 3)
        )
        assert [exposure for _, exposure in history] == [0, 0, 0]
