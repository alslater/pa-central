"""Tests for /api/dashboard endpoint."""
from datetime import UTC, datetime

import pytest

from app.models import Alert, AlertKind, AlertSeverity, Ecosystem
from tests.conftest import auth


@pytest.mark.asyncio
class TestDashboard:
    async def test_returns_stats(self, client, admin_token):
        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert "total_hosts" in data
        assert "hosts_online" in data
        assert "hosts_offline" in data
        assert "unacknowledged_alerts" in data
        assert "critical_alerts" in data
        assert "scans_with_findings" in data
        assert "recent_alerts" in data

    async def test_counts_hosts(self, client, admin_token, host):
        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.json()["total_hosts"] >= 1

    async def test_counts_online_hosts(self, client, admin_token, host, db):
        host.last_seen_at = datetime.now(UTC)
        await db.commit()
        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.json()["hosts_online"] >= 1

    async def test_counts_unacknowledged_alerts(self, client, admin_token, host, db):
        alert = Alert(
            host_id=host.id,
            package_name="vuln-pkg",
            ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv,
            severity=AlertSeverity.high,
            acknowledged=False,
        )
        db.add(alert)
        await db.commit()
        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.json()["unacknowledged_alerts"] >= 1

    async def test_counts_critical_alerts(self, client, admin_token, host, db):
        alert = Alert(
            host_id=host.id,
            package_name="crit-pkg",
            ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv,
            severity=AlertSeverity.critical,
            acknowledged=False,
        )
        db.add(alert)
        await db.commit()
        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.json()["critical_alerts"] >= 1

    async def test_recent_alerts_only_unacknowledged(self, client, admin_token, host, db):
        acked = Alert(host_id=host.id, package_name="acked",
                      ecosystem=Ecosystem.pypi, kind=AlertKind.osv,
                      severity=AlertSeverity.low, acknowledged=True)
        unacked = Alert(host_id=host.id, package_name="unacked",
                        ecosystem=Ecosystem.pypi, kind=AlertKind.osv,
                        severity=AlertSeverity.medium, acknowledged=False)
        db.add(acked)
        db.add(unacked)
        await db.commit()

        r = await client.get("/api/dashboard", headers=auth(admin_token))
        recent = r.json()["recent_alerts"]
        assert all(not a["acknowledged"] for a in recent)

    async def test_requires_auth(self, client):
        r = await client.get("/api/dashboard")
        assert r.status_code == 401
