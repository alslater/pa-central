"""Tests for /api/hosts endpoints."""
from datetime import UTC, datetime, timedelta

import pytest

from app.models import Scan
from tests.conftest import auth


@pytest.mark.asyncio
class TestListHosts:
    async def test_returns_empty_list_when_no_hosts(self, client, admin_token):
        r = await client.get("/api/hosts", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_returns_hosts(self, client, admin_token, host):
        r = await client.get("/api/hosts", headers=auth(admin_token))
        assert r.status_code == 200
        names = [h["name"] for h in r.json()]
        assert "test-host" in names

    async def test_requires_auth(self, client):
        r = await client.get("/api/hosts")
        assert r.status_code == 401

    async def test_non_admin_sees_only_own_hosts(self, client, operator_token, operator_user, host, db):
        """Hosts owned by the admin should not appear for the operator."""
        r = await client.get("/api/hosts", headers=auth(operator_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_admin_sees_all_hosts(self, client, admin_token, host):
        r = await client.get("/api/hosts", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) >= 1


@pytest.mark.asyncio
class TestGetHost:
    async def test_returns_host_by_id(self, client, admin_token, host):
        r = await client.get(f"/api/hosts/{host.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["name"] == "test-host"

    async def test_returns_404_for_unknown_host(self, client, admin_token):
        r = await client.get("/api/hosts/999999", headers=auth(admin_token))
        assert r.status_code == 404

    async def test_requires_auth(self, client, host):
        r = await client.get(f"/api/hosts/{host.id}")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestHostLatestScans:
    """GET /hosts/{id}/latest-scans — one row per project_path, ranked in
    SQL, with no row cap. Regression coverage for grouping previously being
    done client-side against GET /scans, which caps at 100 rows by default
    and silently dropped projects once a host had more total scan rows than
    that cap. GET /scans itself must not change — it's the package-alert
    CLI's live surface — so this is a dedicated endpoint instead."""

    async def test_returns_latest_scan_per_project(self, client, admin_token, host, db):
        now = datetime.now(UTC)
        db.add_all([
            Scan(host_id=host.id, project_path="proj-a", scanned_at=now - timedelta(days=2), finding_count=3),
            Scan(host_id=host.id, project_path="proj-a", scanned_at=now, finding_count=0),
            Scan(host_id=host.id, project_path="proj-b", scanned_at=now - timedelta(days=1), finding_count=1),
        ])
        await db.commit()

        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(admin_token))
        assert r.status_code == 200
        rows = {s["project_path"]: s for s in r.json()}
        assert set(rows) == {"proj-a", "proj-b"}
        assert rows["proj-a"]["finding_count"] == 0  # the more recent proj-a scan, not the older one

    async def test_tied_scanned_at_prefers_latest_received_at(self, client, admin_token, host, db):
        """A retried/resubmitted scan can share the same scanned_at as an
        earlier attempt for the same project. The previous client-side
        behaviour iterated GET /scans' received_at-desc-ordered rows and kept
        the first match per project — i.e. among equal scanned_at, the one
        with the greatest received_at won. Ranking by scanned_at alone would
        let the database pick either row nondeterministically."""
        tied = datetime.now(UTC).replace(microsecond=0)
        db.add_all([
            Scan(host_id=host.id, project_path="proj-retry", scanned_at=tied,
                 received_at=tied - timedelta(minutes=5), finding_count=3),
            Scan(host_id=host.id, project_path="proj-retry", scanned_at=tied,
                 received_at=tied, finding_count=0),
        ])
        await db.commit()

        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(admin_token))
        assert r.status_code == 200
        rows = {s["project_path"]: s for s in r.json()}
        assert rows["proj-retry"]["finding_count"] == 0  # the row with the greater received_at

    async def test_project_not_dropped_when_host_has_over_100_scans(self, client, admin_token, host, db):
        """The bug this endpoint exists to fix: with a 100-row default cap on
        GET /scans ordered by received_at desc, a project scanned only once
        long ago could fall outside that window once another project on the
        same host accumulates 100+ more-recent scans. This endpoint must
        still surface it."""
        now = datetime.now(UTC)
        db.add(Scan(
            host_id=host.id, project_path="rarely-scanned",
            scanned_at=now - timedelta(days=200), received_at=now - timedelta(days=200),
        ))
        db.add_all([
            Scan(
                host_id=host.id, project_path="frequently-scanned",
                scanned_at=now - timedelta(hours=i), received_at=now - timedelta(hours=i),
            )
            for i in range(120)
        ])
        await db.commit()

        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(admin_token))
        assert r.status_code == 200
        rows = {s["project_path"] for s in r.json()}
        assert "rarely-scanned" in rows
        assert "frequently-scanned" in rows

    async def test_returns_empty_list_when_no_scans(self, client, admin_token, host):
        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_returns_404_for_unknown_host(self, client, admin_token):
        r = await client.get("/api/hosts/999999/latest-scans", headers=auth(admin_token))
        assert r.status_code == 404

    async def test_non_owner_gets_404(self, client, operator_token, host):
        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(operator_token))
        assert r.status_code == 404

    async def test_requires_auth(self, client, host):
        r = await client.get(f"/api/hosts/{host.id}/latest-scans")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestUpdateHost:
    async def test_operator_cannot_update_admin_owned_host(self, client, operator_token, host):
        # host is owned by admin — operator must get 404, not 200
        r = await client.patch(
            f"/api/hosts/{host.id}",
            json={"description": "updated"},
            headers=auth(operator_token),
        )
        assert r.status_code == 404

    async def test_operator_can_update_own_host(self, client, operator_token, operator_user, db):
        from app.models import Host
        own_host = Host(
            owner_user_id=operator_user.id,
            name="operator-host",
            hostname="operator-host.local",
        )
        db.add(own_host)
        await db.commit()
        await db.refresh(own_host)
        r = await client.patch(
            f"/api/hosts/{own_host.id}",
            json={"description": "updated by owner"},
            headers=auth(operator_token),
        )
        assert r.status_code == 200
        assert r.json()["description"] == "updated by owner"

    async def test_update_tags(self, client, admin_token, host):
        r = await client.patch(
            f"/api/hosts/{host.id}",
            json={"tags": ["prod", "eu"]},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["prod", "eu"]

    async def test_viewer_cannot_update(self, client, viewer_token, host):
        r = await client.patch(
            f"/api/hosts/{host.id}",
            json={"description": "nope"},
            headers=auth(viewer_token),
        )
        assert r.status_code == 403

    async def test_update_missing_host_returns_404(self, client, admin_token):
        r = await client.patch(
            "/api/hosts/999999",
            json={"description": "x"},
            headers=auth(admin_token),
        )
        assert r.status_code == 404


@pytest.mark.asyncio
class TestDeleteHost:
    async def test_admin_can_delete_host(self, client, admin_token, host):
        r = await client.delete(f"/api/hosts/{host.id}", headers=auth(admin_token))
        assert r.status_code == 204
        r2 = await client.get(f"/api/hosts/{host.id}", headers=auth(admin_token))
        assert r2.status_code == 404

    async def test_operator_cannot_delete_host(self, client, operator_token, host):
        r = await client.delete(f"/api/hosts/{host.id}", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_delete_missing_host_returns_404(self, client, admin_token):
        r = await client.delete("/api/hosts/999999", headers=auth(admin_token))
        assert r.status_code == 404
