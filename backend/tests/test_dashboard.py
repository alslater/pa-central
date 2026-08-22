"""Tests for /api/dashboard endpoint."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.models import (
    Alert,
    AlertKind,
    AlertSeverity,
    Ecosystem,
    FindingAcceptanceEvent,
    FindingRecord,
    RepoScan,
    SettingValueType,
    SystemSetting,
)
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
        assert "outstanding_scans_by_severity" in data
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


@pytest.mark.asyncio
class TestOutstandingScansBySeverity:
    async def test_admin_sees_per_severity_counts(self, client, admin_token, db, admin_user):
        scan_a = RepoScan(name="repo-a", url="https://x/a", branch="main", created_by_id=admin_user.id)
        scan_b = RepoScan(name="repo-b", url="https://x/b", branch="main", created_by_id=admin_user.id)
        db.add_all([scan_a, scan_b])
        await db.flush()
        db.add_all([
            FindingRecord(repo_scan_id=scan_a.id, advisory_id="GHSA-1", package="p1",
                          ecosystem="pypi", severity=AlertSeverity.critical,
                          first_found_at=datetime.now(UTC)),
            FindingRecord(repo_scan_id=scan_b.id, advisory_id="GHSA-2", package="p2",
                          ecosystem="pypi", severity=AlertSeverity.critical,
                          first_found_at=datetime.now(UTC)),
            FindingRecord(repo_scan_id=scan_a.id, advisory_id="GHSA-3", package="p3",
                          ecosystem="pypi", severity=AlertSeverity.high,
                          first_found_at=datetime.now(UTC)),
        ])
        await db.commit()

        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.status_code == 200
        counts = r.json()["outstanding_scans_by_severity"]
        assert counts["critical"] == 2  # 2 distinct repo scans
        assert counts["high"] == 1
        assert counts["medium"] == 0

    async def test_closed_finding_not_counted(self, client, admin_token, db, admin_user):
        scan = RepoScan(name="repo-c", url="https://x/c", branch="main", created_by_id=admin_user.id)
        db.add(scan)
        await db.flush()
        db.add(FindingRecord(
            repo_scan_id=scan.id, advisory_id="GHSA-4", package="p4",
            ecosystem="pypi", severity=AlertSeverity.critical,
            first_found_at=datetime.now(UTC), closed_at=datetime.now(UTC),
        ))
        await db.commit()

        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.json()["outstanding_scans_by_severity"]["critical"] == 0

    async def test_accepted_finding_not_counted(self, client, admin_token, db, admin_user):
        scan = RepoScan(name="repo-d", url="https://x/d", branch="main", created_by_id=admin_user.id)
        db.add(scan)
        await db.flush()
        db.add(FindingRecord(
            repo_scan_id=scan.id, advisory_id="GHSA-5", package="p5",
            ecosystem="pypi", severity=AlertSeverity.critical,
            first_found_at=datetime.now(UTC),
            accepted_by_id=admin_user.id, accepted_at=datetime.now(UTC),
            accepted_reason="known issue",
        ))
        await db.commit()

        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.json()["outstanding_scans_by_severity"]["critical"] == 0

    async def test_non_admin_gets_none(self, client, operator_token):
        r = await client.get("/api/dashboard", headers=auth(operator_token))
        assert r.status_code == 200
        assert r.json()["outstanding_scans_by_severity"] is None


@pytest.mark.asyncio
class TestExposureHistory:
    async def test_returns_points_for_window(self, client, admin_token, db, admin_user):
        scan = RepoScan(name="exposure-repo", url="https://x/e", branch="main", created_by_id=admin_user.id)
        db.add(scan)
        await db.flush()
        db.add(FindingRecord(
            repo_scan_id=scan.id, advisory_id="GHSA-e1", package="p1",
            ecosystem="pypi", severity=AlertSeverity.critical,
            first_found_at=datetime.now(UTC) - timedelta(days=3),
        ))
        await db.commit()

        r = await client.get("/api/dashboard/exposure-history?days=5", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["window_days"] == 5
        assert len(data["points"]) == 5
        # the finding is 3 days old, so the last 4 days (including today) should show exposure=81
        exposures = [p["exposure"] for p in data["points"]]
        assert exposures[-1] == 81
        assert exposures[0] == 0  # 5th day back predates first_found_at

    async def test_days_param_clamps_to_finding_retention_days(self, client, admin_token, db):
        setting = await db.get(SystemSetting, "finding_retention_days")
        if setting:
            setting.value = "30"
        else:
            db.add(SystemSetting(key="finding_retention_days", value="30", value_type=SettingValueType.int))
        await db.commit()

        r = await client.get("/api/dashboard/exposure-history?days=365", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["window_days"] == 30

    async def test_revoked_acceptance_does_not_erase_past_exposure(
        self, client, admin_token, db, admin_user
    ):
        """End-to-end regression test for the P2 bug.

        A finding accepted for part of the window, then revoked, must still
        show as NOT exposed for the days it *was* accepted. Before the
        event-sourcing fix, revoking nulled out accepted_at/accepted_until on
        the record, so the history recomputed every past day as "never
        accepted" — erasing the acceptance window entirely.
        """
        scan = RepoScan(name="p2-repo", url="https://x/p2", branch="main", created_by_id=admin_user.id)
        db.add(scan)
        await db.flush()
        finding = FindingRecord(
            repo_scan_id=scan.id, advisory_id="GHSA-p2", package="p2pkg",
            ecosystem="pypi", severity=AlertSeverity.high,
            first_found_at=datetime.now(UTC) - timedelta(days=10),
        )
        db.add(finding)
        await db.commit()
        await db.refresh(finding)

        accept_at = datetime.now(UTC) - timedelta(days=8)
        accept_r = await client.post(
            f"/api/findings/{finding.id}/accept",
            json={"reason": "temp"}, headers=auth(admin_token),
        )
        assert accept_r.status_code == 200, accept_r.text
        # Backdate the just-created event: the endpoint always stamps utcnow().
        accept_event = (await db.execute(
            select(FindingAcceptanceEvent)
            .where(FindingAcceptanceEvent.finding_record_id == finding.id)
            .where(FindingAcceptanceEvent.action == "accepted")
        )).scalar_one()
        accept_event.at = accept_at
        await db.commit()

        revoke_at = datetime.now(UTC) - timedelta(days=3)
        revoke_r = await client.delete(
            f"/api/findings/{finding.id}/accept", headers=auth(admin_token)
        )
        assert revoke_r.status_code == 200, revoke_r.text
        revoke_event = (await db.execute(
            select(FindingAcceptanceEvent)
            .where(FindingAcceptanceEvent.finding_record_id == finding.id)
            .where(FindingAcceptanceEvent.action == "revoked")
        )).scalar_one()
        revoke_event.at = revoke_at
        await db.commit()

        r = await client.get("/api/dashboard/exposure-history?days=10", headers=auth(admin_token))
        assert r.status_code == 200, r.text
        points = {p["date"]: p["exposure"] for p in r.json()["points"]}
        today = datetime.now(UTC).date()
        # Before the acceptance ever happened: exposed (high == 27).
        assert points[str(today - timedelta(days=9))] == 27
        # During the (since-revoked) acceptance window: NOT exposed. This is
        # the assertion the pre-fix code got wrong — after revoke, the record's
        # accepted_at is NULL, so every past day looked un-accepted.
        assert points[str(today - timedelta(days=6))] == 0
        assert points[str(today - timedelta(days=4))] == 0
        # After the revoke: exposed again.
        assert points[str(today - timedelta(days=2))] == 27
        assert points[str(today)] == 27

    async def test_requires_admin(self, client, operator_token):
        r = await client.get("/api/dashboard/exposure-history", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_requires_auth(self, client):
        r = await client.get("/api/dashboard/exposure-history")
        assert r.status_code == 401
