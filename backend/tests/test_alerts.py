"""Tests for /api/alerts endpoints."""
import pytest

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
