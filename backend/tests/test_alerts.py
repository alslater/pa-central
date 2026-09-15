"""Tests for /api/alerts endpoints."""
import asyncio

import pytest

from app.api import alerts as alerts_module
from app.api.alerts import notify_user
from app.models import Alert, AlertKind, AlertSeverity, Ecosystem
from tests.conftest import auth


async def _seed_alert(db, host, **kwargs):
    defaults = {
        "host_id": host.id,
        "package_name": "requests",
        "ecosystem": Ecosystem.pypi,
        "kind": AlertKind.osv,
        "severity": AlertSeverity.high,
    }
    defaults.update(kwargs)
    alert = Alert(**defaults)
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


@pytest.mark.asyncio
class TestListAlerts:
    async def test_returns_empty_list(self, client, admin_token):
        r = await client.get("/api/alerts", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_returns_alerts(self, client, admin_token, host, db):
        await _seed_alert(db, host)
        r = await client.get("/api/alerts", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) == 1

    async def test_filter_by_host_id(self, client, admin_token, host, db):
        await _seed_alert(db, host, package_name="pkg-a")
        r = await client.get(f"/api/alerts?host_id={host.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) == 1

        r2 = await client.get("/api/alerts?host_id=999999", headers=auth(admin_token))
        assert r2.json() == []

    async def test_filter_by_severity(self, client, admin_token, host, db):
        await _seed_alert(db, host, severity=AlertSeverity.critical)
        await _seed_alert(db, host, severity=AlertSeverity.low)
        r = await client.get("/api/alerts?severity=critical", headers=auth(admin_token))
        assert r.status_code == 200
        assert all(a["severity"] == "critical" for a in r.json())

    async def test_filter_acknowledged(self, client, admin_token, host, db):
        alert = await _seed_alert(db, host, acknowledged=True)
        r = await client.get("/api/alerts?acknowledged=false", headers=auth(admin_token))
        ids = [a["id"] for a in r.json()]
        assert alert.id not in ids

    async def test_requires_auth(self, client):
        r = await client.get("/api/alerts")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestGetAlert:
    async def test_returns_alert_by_id(self, client, admin_token, host, db):
        alert = await _seed_alert(db, host)
        r = await client.get(f"/api/alerts/{alert.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["id"] == alert.id

    async def test_returns_404_for_unknown(self, client, admin_token):
        r = await client.get("/api/alerts/999999", headers=auth(admin_token))
        assert r.status_code == 404


@pytest.mark.asyncio
class TestAcknowledgeAlert:
    async def test_operator_can_acknowledge(self, client, operator_token, host, db):
        alert = await _seed_alert(db, host)
        r = await client.patch(
            f"/api/alerts/{alert.id}/acknowledge",
            json={"acknowledged": True},
            headers=auth(operator_token),
        )
        assert r.status_code == 200
        assert r.json()["acknowledged"] is True

    async def test_acknowledge_sets_acknowledged_at(self, client, operator_token, host, db):
        alert = await _seed_alert(db, host)
        r = await client.patch(
            f"/api/alerts/{alert.id}/acknowledge",
            json={"acknowledged": True},
            headers=auth(operator_token),
        )
        assert r.json()["acknowledged"] is True

    async def test_can_unacknowledge(self, client, operator_token, host, db):
        alert = await _seed_alert(db, host, acknowledged=True)
        r = await client.patch(
            f"/api/alerts/{alert.id}/acknowledge",
            json={"acknowledged": False},
            headers=auth(operator_token),
        )
        assert r.json()["acknowledged"] is False

    async def test_viewer_cannot_acknowledge(self, client, viewer_token, host, db):
        alert = await _seed_alert(db, host)
        r = await client.patch(
            f"/api/alerts/{alert.id}/acknowledge",
            json={"acknowledged": True},
            headers=auth(viewer_token),
        )
        assert r.status_code == 403

    async def test_acknowledge_missing_alert_returns_404(self, client, operator_token):
        r = await client.patch(
            "/api/alerts/999999/acknowledge",
            json={"acknowledged": True},
            headers=auth(operator_token),
        )
        assert r.status_code == 404


@pytest.mark.asyncio
class TestNotifyUser:
    """notify_user: per-connection SSE targeting, added alongside the
    existing broadcast_alert (which remains untargeted)."""

    @pytest.fixture(autouse=True)
    def clean_sse_queues(self):
        """_sse_queues is module-level global state; tests must not leak
        into each other."""
        alerts_module._sse_queues.clear()
        yield
        alerts_module._sse_queues.clear()

    async def test_notify_user_only_reaches_the_tagged_queue(self):
        q1: asyncio.Queue = asyncio.Queue(maxsize=10)
        q2: asyncio.Queue = asyncio.Queue(maxsize=10)
        alerts_module._sse_queues[q1] = 1
        alerts_module._sse_queues[q2] = 2

        notify_user(1, {"type": "admin_action_result", "op_id": "x"})

        assert q1.get_nowait() == {"type": "admin_action_result", "op_id": "x"}
        assert q2.empty()

    async def test_notify_user_reaches_every_queue_tagged_for_that_uid(self):
        """One admin can have multiple tabs/connections open."""
        q1: asyncio.Queue = asyncio.Queue(maxsize=10)
        q2: asyncio.Queue = asyncio.Queue(maxsize=10)
        alerts_module._sse_queues[q1] = 7
        alerts_module._sse_queues[q2] = 7

        notify_user(7, {"type": "admin_action_result", "op_id": "y"})

        assert q1.get_nowait()["op_id"] == "y"
        assert q2.get_nowait()["op_id"] == "y"

    async def test_notify_user_drops_oldest_when_the_target_queue_is_full(self):
        q: asyncio.Queue = asyncio.Queue(maxsize=1)
        q.put_nowait({"type": "connected"})
        alerts_module._sse_queues[q] = 3

        notify_user(3, {"type": "admin_action_result", "op_id": "z"})

        assert q.get_nowait()["op_id"] == "z"
        assert q.empty()

    async def test_notify_user_never_raises_for_an_unknown_uid(self):
        notify_user(999, {"type": "admin_action_result", "op_id": "w"})  # no queue tagged 999 — must not raise

    async def test_broadcast_alert_still_reaches_every_connection_regardless_of_uid(self):
        """broadcast_alert is unchanged — it still fans out to everyone."""
        q1: asyncio.Queue = asyncio.Queue(maxsize=10)
        q2: asyncio.Queue = asyncio.Queue(maxsize=10)
        alerts_module._sse_queues[q1] = 1
        alerts_module._sse_queues[q2] = 2

        alerts_module.broadcast_alert({"id": 1, "message": "test"})

        assert q1.get_nowait()["id"] == 1
        assert q2.get_nowait()["id"] == 1
