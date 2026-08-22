"""Tests for the RiskRecord model, schemas, and /api/risks endpoints."""
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models import AlertSeverity, RepoScan, RiskRecord
from tests.conftest import auth


@pytest.fixture
async def repo_scan(db, admin_user):
    scan = RepoScan(
        name="test-repo",
        url="https://github.com/test/repo",
        branch="main",
        min_notify_severity=AlertSeverity.medium,
        created_by_id=admin_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@pytest.mark.asyncio
class TestRiskRecordModel:
    async def test_create_and_query_risk_record(self, db, repo_scan):
        now = datetime.now(UTC)
        record = RiskRecord(
            repo_scan_id=repo_scan.id,
            package="reqeusts",
            ecosystem="pypi",
            package_version="1.0.0",
            score=46,
            level="warning",
            signals=[{"name": "typosquat", "score": 15, "reason": "resembles 'requests'"}],
            first_found_at=now,
            reopen_count=0,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        assert record.id is not None
        assert record.closed_at is None
        assert record.score == 46
        assert record.signals[0]["name"] == "typosquat"


async def _make_scan_and_risk(db, admin_user, days_old=5, level="warning", score=46,
                               closed=False, accepted=False, accepted_until=None,
                               scan_name="risk-test"):
    """Helper: create a RepoScan + open RiskRecord, return (scan, record)."""
    scan = RepoScan(
        name=scan_name, url="https://github.com/t/r", branch="main",
        min_notify_severity="medium", created_by_id=admin_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    now = datetime.now(UTC)
    first_found = now - timedelta(days=days_old)
    record = RiskRecord(
        repo_scan_id=scan.id,
        package="reqeusts", ecosystem="pypi", package_version="1.0.0",
        score=score, level=level,
        signals=[{"name": "typosquat", "score": 15, "reason": "resembles 'requests'"}],
        first_found_at=first_found,
        reopen_count=0,
    )
    if closed:
        record.closed_at = now
    if accepted:
        record.accepted_by_id = admin_user.id
        record.accepted_at = now
        record.accepted_reason = "known false positive"
        record.accepted_until = accepted_until
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return scan, record


@pytest.mark.asyncio
class TestRisksAPI:
    async def test_list_risks_returns_open_only(self, client, db, admin_user, admin_token):
        _, open_rec = await _make_scan_and_risk(db, admin_user, days_old=5)
        _, closed_rec = await _make_scan_and_risk(db, admin_user, days_old=20, closed=True, scan_name="risk-test-2")
        r = await client.get("/api/risks", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        ids = [x["id"] for x in data["items"]]
        assert open_rec.id in ids
        assert closed_rec.id not in ids

    async def test_list_risks_returns_pagination_envelope(self, client, db, admin_user, admin_token):
        r = await client.get("/api/risks", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) >= {"items", "total", "page", "page_size"}

    async def test_list_risks_level_filter(self, client, db, admin_user, admin_token):
        _, critical = await _make_scan_and_risk(db, admin_user, level="critical", scan_name="c1")
        _, info = await _make_scan_and_risk(db, admin_user, level="info", scan_name="c2")
        r = await client.get("/api/risks?level=critical", headers=auth(admin_token))
        ids = [x["id"] for x in r.json()["items"]]
        assert critical.id in ids
        assert info.id not in ids

    async def test_list_risks_invalid_level_returns_422(self, client, db, admin_user, admin_token):
        """A typo like level=critcal must fail validation, not silently match
        nothing — RiskRecord.level.in_(["critcal"]) is a valid SQL query that
        simply returns zero rows, which reads identically to "no critical risks
        exist" even though the filter itself was malformed."""
        await _make_scan_and_risk(db, admin_user, level="critical", scan_name="c3")
        r = await client.get("/api/risks?level=critcal", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_list_risks_accepted_filter(self, client, db, admin_user, admin_token):
        _, accepted = await _make_scan_and_risk(db, admin_user, accepted=True, scan_name="a1")
        _, unaccepted = await _make_scan_and_risk(db, admin_user, scan_name="a2")
        r = await client.get("/api/risks?accepted=true", headers=auth(admin_token))
        ids = [x["id"] for x in r.json()["items"]]
        assert accepted.id in ids
        assert unaccepted.id not in ids

    async def test_sort_score_desc_orders_highest_first(self, client, db, admin_user, admin_token):
        # sort_dir must behave the same way it does for every other sort key:
        # desc = highest value first. score is a stored column, not a derived
        # one, so it needs no inversion the way days_open does.
        _, low = await _make_scan_and_risk(db, admin_user, score=10, scan_name="s1")
        _, high = await _make_scan_and_risk(db, admin_user, score=90, scan_name="s2")
        r = await client.get("/api/risks?sort=score&sort_dir=desc", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [x["id"] for x in r.json()["items"]]
        assert ids.index(high.id) < ids.index(low.id)

    async def test_sort_score_asc_orders_lowest_first(self, client, db, admin_user, admin_token):
        _, low = await _make_scan_and_risk(db, admin_user, score=10, scan_name="s3")
        _, high = await _make_scan_and_risk(db, admin_user, score=90, scan_name="s4")
        r = await client.get("/api/risks?sort=score&sort_dir=asc", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [x["id"] for x in r.json()["items"]]
        assert ids.index(low.id) < ids.index(high.id)

    async def test_accept_risk(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_risk(db, admin_user)
        r = await client.post(
            f"/api/risks/{record.id}/accept",
            json={"reason": "internal fork, verified safe"},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["is_accepted"] is True

    async def test_accept_risk_blank_reason_returns_422(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_risk(db, admin_user)
        r = await client.post(
            f"/api/risks/{record.id}/accept",
            json={"reason": "   "},
            headers=auth(admin_token),
        )
        assert r.status_code == 422
        detail = r.json()["detail"]
        errors = detail if isinstance(detail, list) else [detail]
        assert any("reason must not be blank" in str(e) for e in errors)

    async def test_accept_risk_trims_reason(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_risk(db, admin_user)
        r = await client.post(
            f"/api/risks/{record.id}/accept",
            json={"reason": "  internal fork, verified safe  "},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["accepted_reason"] == "internal fork, verified safe"

    async def test_accept_closed_risk_conflict(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_risk(db, admin_user, closed=True)
        r = await client.post(
            f"/api/risks/{record.id}/accept",
            json={"reason": "x"},
            headers=auth(admin_token),
        )
        assert r.status_code == 409

    async def test_revoke_accept_risk(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_risk(db, admin_user, accepted=True)
        r = await client.delete(f"/api/risks/{record.id}/accept", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["is_accepted"] is False

    async def test_accept_risk_creates_acceptance_event(self, client, db, admin_user, admin_token):
        from app.models import RiskAcceptanceEvent
        _, record = await _make_scan_and_risk(db, admin_user)
        r = await client.post(
            f"/api/risks/{record.id}/accept",
            json={"reason": "internal fork, verified safe", "accepted_until": "2027-01-01"},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        events = (await db.execute(
            select(RiskAcceptanceEvent).where(RiskAcceptanceEvent.risk_record_id == record.id)
        )).scalars().all()
        assert len(events) == 1
        assert events[0].action == "accepted"
        assert events[0].by_user_id == admin_user.id
        assert events[0].reason == "internal fork, verified safe"
        assert events[0].accepted_until == date(2027, 1, 1)

    async def test_revoke_risk_accept_creates_revoked_event(self, client, db, admin_user, admin_token):
        from app.models import RiskAcceptanceEvent
        _, record = await _make_scan_and_risk(db, admin_user, accepted=True)
        r = await client.delete(f"/api/risks/{record.id}/accept", headers=auth(admin_token))
        assert r.status_code == 200
        events = (await db.execute(
            select(RiskAcceptanceEvent)
            .where(RiskAcceptanceEvent.risk_record_id == record.id)
            .order_by(RiskAcceptanceEvent.at)
        )).scalars().all()
        # _make_scan_and_risk(accepted=True) doesn't itself insert an event
        # (it directly sets the live columns to seed test state) — so the only
        # event expected here is the one this revoke call creates.
        assert len(events) == 1
        assert events[0].action == "revoked"
        assert events[0].by_user_id == admin_user.id

    async def test_accept_then_revoke_risk_creates_two_events_in_order(self, client, db, admin_user, admin_token):
        from app.models import RiskAcceptanceEvent
        _, record = await _make_scan_and_risk(db, admin_user)
        await client.post(
            f"/api/risks/{record.id}/accept",
            json={"reason": "internal fork, verified safe"},
            headers=auth(admin_token),
        )
        await client.delete(f"/api/risks/{record.id}/accept", headers=auth(admin_token))
        events = (await db.execute(
            select(RiskAcceptanceEvent)
            .where(RiskAcceptanceEvent.risk_record_id == record.id)
            .order_by(RiskAcceptanceEvent.at)
        )).scalars().all()
        assert [e.action for e in events] == ["accepted", "revoked"]

    async def test_accept_missing_risk_404(self, client, admin_token):
        r = await client.post("/api/risks/999999/accept", json={"reason": "x"}, headers=auth(admin_token))
        assert r.status_code == 404

    async def test_repo_scan_risks_endpoint(self, client, db, admin_user, admin_token):
        scan, record = await _make_scan_and_risk(db, admin_user)
        r = await client.get(f"/api/repo-scans/{scan.id}/risks", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [x["id"] for x in r.json()]
        assert record.id in ids
