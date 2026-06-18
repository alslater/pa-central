"""Authorization gap tests — covers endpoints missing 401/403 checks in other test files."""
import pytest
from unittest.mock import patch
from tests.conftest import auth

REPO_PAYLOAD = {
    "name": "auth-gap-repo",
    "url": "https://github.com/example/repo.git",
    "branch": "main",
    "min_notify_severity": "high",
}


# ── /api/repo-scans ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestRepoScansAuthGaps:
    async def test_list_requires_auth(self, client):
        r = await client.get("/api/repo-scans")
        assert r.status_code == 401

    async def test_list_viewer_forbidden(self, client, viewer_token):
        r = await client.get("/api/repo-scans", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_delete_requires_auth(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.delete(f"/api/repo-scans/{created['id']}")
        assert r.status_code == 401

    async def test_delete_operator_forbidden(self, client, admin_token, operator_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.delete(f"/api/repo-scans/{created['id']}", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_all_results_requires_auth(self, client):
        r = await client.get("/api/repo-scans/results")
        assert r.status_code == 401


# ── /api/scans ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestScanAuthGaps:
    async def test_get_scan_requires_auth(self, client, admin_token, host, db):
        from app.models import Scan
        from datetime import datetime, timezone
        scan = Scan(host_id=host.id, scan_type="project", project_path="/repo", received_at=datetime.now(timezone.utc))
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        r = await client.get(f"/api/scans/{scan.id}")
        assert r.status_code == 401

    async def test_get_scan_wrong_owner_returns_404(self, client, viewer_token, host, db):
        from app.models import Scan
        from datetime import datetime, timezone
        # host is owned by admin; viewer does not own it — 404 to prevent ID enumeration
        scan = Scan(host_id=host.id, scan_type="project", project_path="/repo", received_at=datetime.now(timezone.utc))
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        r = await client.get(f"/api/scans/{scan.id}", headers=auth(viewer_token))
        assert r.status_code == 404


# ── /api/hosts ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestHostAuthGaps:
    async def test_get_host_non_owner_returns_404(self, client, operator_token, host):
        # host is owned by admin — operator should get 404 (not 403, to prevent enumeration)
        r = await client.get(f"/api/hosts/{host.id}", headers=auth(operator_token))
        assert r.status_code == 404

    async def test_patch_host_non_owner_returns_404(self, client, operator_token, host):
        # operator does not own this host — PATCH must return 404, not 200
        r = await client.patch(f"/api/hosts/{host.id}", json={"description": "pwned"}, headers=auth(operator_token))
        assert r.status_code == 404

    async def test_patch_host_unauthenticated_returns_401(self, client, host):
        r = await client.patch(f"/api/hosts/{host.id}", json={})
        assert r.status_code == 401

    async def test_patch_host_admin_can_update_any_host(self, client, admin_token, host):
        r = await client.patch(f"/api/hosts/{host.id}", json={"description": "updated"}, headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["description"] == "updated"


# ── /api/cooldown ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestCooldownDeleteAuthGaps:
    async def test_delete_requires_auth(self, client, operator_token):
        created = (await client.post("/api/cooldown", json={
            "package_name": "auth-gap-pkg", "ecosystem": "pypi",
        }, headers=auth(operator_token))).json()
        r = await client.delete(f"/api/cooldown/{created['id']}")
        assert r.status_code == 401

    async def test_delete_viewer_forbidden(self, client, operator_token, viewer_token):
        created = (await client.post("/api/cooldown", json={
            "package_name": "auth-gap-pkg2", "ecosystem": "pypi",
        }, headers=auth(operator_token))).json()
        r = await client.delete(f"/api/cooldown/{created['id']}", headers=auth(viewer_token))
        assert r.status_code == 403


# ── /api/config-templates ──────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestConfigTemplateAuthGaps:
    async def test_get_template_requires_auth(self, client, admin_token):
        created = (await client.post("/api/config-templates", json={
            "name": "auth-gap-tmpl", "toml_content": "[section]\nkey = 'value'",
        }, headers=auth(admin_token))).json()
        r = await client.get(f"/api/config-templates/{created['id']}")
        assert r.status_code == 401

    async def test_patch_template_requires_auth(self, client, admin_token):
        created = (await client.post("/api/config-templates", json={
            "name": "auth-gap-tmpl2", "toml_content": "[section]\nkey = 'value'",
        }, headers=auth(admin_token))).json()
        r = await client.patch(f"/api/config-templates/{created['id']}", json={"name": "renamed"})
        assert r.status_code == 401

    async def test_patch_template_viewer_forbidden(self, client, admin_token, viewer_token):
        created = (await client.post("/api/config-templates", json={
            "name": "auth-gap-tmpl3", "toml_content": "[section]\nkey = 'value'",
        }, headers=auth(admin_token))).json()
        r = await client.patch(f"/api/config-templates/{created['id']}", json={"name": "renamed"}, headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_assign_requires_auth(self, client, host, admin_token):
        created = (await client.post("/api/config-templates", json={
            "name": "auth-gap-tmpl4", "toml_content": "[section]\nkey = 'value'",
        }, headers=auth(admin_token))).json()
        r = await client.post(f"/api/config-templates/{created['id']}/assign/{host.id}")
        assert r.status_code == 401

    async def test_assign_viewer_forbidden(self, client, host, admin_token, viewer_token):
        created = (await client.post("/api/config-templates", json={
            "name": "auth-gap-tmpl5", "toml_content": "[section]\nkey = 'value'",
        }, headers=auth(admin_token))).json()
        r = await client.post(f"/api/config-templates/{created['id']}/assign/{host.id}", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_for_host_requires_auth(self, client, host):
        r = await client.get(f"/api/config-templates/for-host/{host.id}")
        assert r.status_code == 401


# ── /api/alerts ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestAlertAuthGaps:
    async def test_get_alert_requires_auth(self, client, admin_token, host, db):
        from app.models import Alert, AlertSeverity, AlertKind, Ecosystem
        alert = Alert(
            host_id=host.id, package_name="pkg", ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv, severity=AlertSeverity.high,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        r = await client.get(f"/api/alerts/{alert.id}")
        assert r.status_code == 401

    async def test_stream_requires_auth(self, client):
        r = await client.get("/api/alerts/stream")
        assert r.status_code == 401

    async def test_stream_invalid_token_returns_401(self, client):
        r = await client.get("/api/alerts/stream", headers={"Authorization": "Bearer not-a-valid-token"})
        assert r.status_code == 401

    async def test_stream_query_param_token_no_longer_accepted(self, client):
        r = await client.get("/api/alerts/stream?token=not-a-valid-token")
        assert r.status_code == 401

    async def test_stream_non_integer_sub_returns_401_not_500(self, client):
        """A validly-signed token with a non-integer sub must yield 401 on the SSE stream."""
        from app.core.security import create_access_token
        bad_token = create_access_token("not-an-integer")
        r = await client.get("/api/alerts/stream", headers={"Authorization": f"Bearer {bad_token}"})
        assert r.status_code == 401

    async def test_bulk_acknowledge_requires_auth(self, client, host, db):
        from app.models import Alert, AlertSeverity, AlertKind, Ecosystem
        alert = Alert(
            host_id=host.id, package_name="pkg", ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv, severity=AlertSeverity.high,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        r = await client.patch("/api/alerts/acknowledge-bulk", json={"alert_ids": [alert.id]})
        assert r.status_code == 401

    async def test_bulk_acknowledge_viewer_forbidden(self, client, viewer_token, host, db):
        from app.models import Alert, AlertSeverity, AlertKind, Ecosystem
        alert = Alert(
            host_id=host.id, package_name="pkg", ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv, severity=AlertSeverity.high,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        r = await client.patch("/api/alerts/acknowledge-bulk", json={"alert_ids": [alert.id]}, headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_bulk_acknowledge_operator_succeeds(self, client, operator_token, host, db):
        from app.models import Alert, AlertSeverity, AlertKind, Ecosystem
        a1 = Alert(host_id=host.id, package_name="pkg1", ecosystem=Ecosystem.pypi, kind=AlertKind.osv, severity=AlertSeverity.high)
        a2 = Alert(host_id=host.id, package_name="pkg2", ecosystem=Ecosystem.pypi, kind=AlertKind.osv, severity=AlertSeverity.medium)
        db.add_all([a1, a2])
        await db.commit()
        await db.refresh(a1)
        await db.refresh(a2)
        r = await client.patch("/api/alerts/acknowledge-bulk", json={"alert_ids": [a1.id, a2.id]}, headers=auth(operator_token))
        assert r.status_code == 204
        await db.refresh(a1)
        await db.refresh(a2)
        assert a1.acknowledged is True
        assert a2.acknowledged is True


# ── /api/ingest/repo-scan-result ───────────────────────────────────────────────

@pytest.mark.asyncio
class TestIngestRepoScanResultAuth:
    async def test_missing_key_returns_401(self, client):
        r = await client.post("/api/ingest/repo-scan-result", json={})
        assert r.status_code == 401

    async def test_wrong_key_returns_401(self, client):
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.fleet_system_api_key = "correct-key"
            r = await client.post(
                "/api/ingest/repo-scan-result",
                json={},
                headers={"X-API-Key": "wrong-key"},
            )
            assert r.status_code == 401

    async def test_user_jwt_cannot_use_system_endpoint(self, client, admin_token):
        r = await client.post(
            "/api/ingest/repo-scan-result",
            json={},
            headers=auth(admin_token),
        )
        assert r.status_code == 401


# ── /api/dashboard ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestDashboardScoping:
    async def test_requires_auth(self, client):
        r = await client.get("/api/dashboard")
        assert r.status_code == 401

    async def test_admin_sees_fleet_wide_stats(self, client, admin_token, host, db):
        from app.models import Alert, AlertSeverity, AlertKind, Ecosystem
        alert = Alert(
            host_id=host.id, package_name="pkg", ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv, severity=AlertSeverity.high,
        )
        db.add(alert)
        await db.commit()
        r = await client.get("/api/dashboard", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["total_hosts"] >= 1
        assert data["unacknowledged_alerts"] >= 1

    async def test_developer_sees_only_own_hosts(self, client, developer_token, developer_user, host, db):
        # host is owned by admin — developer should see zero hosts and zero alerts
        r = await client.get("/api/dashboard", headers=auth(developer_token))
        assert r.status_code == 200
        data = r.json()
        assert data["total_hosts"] == 0
        assert data["unacknowledged_alerts"] == 0

    async def test_developer_counts_own_host(self, client, developer_token, developer_user, db):
        from app.models import Host, Alert, AlertSeverity, AlertKind, Ecosystem
        own_host = Host(
            owner_user_id=developer_user.id,
            name="dev-host",
            hostname="dev-host.local",
        )
        db.add(own_host)
        await db.commit()
        await db.refresh(own_host)
        alert = Alert(
            host_id=own_host.id, package_name="pkg", ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv, severity=AlertSeverity.high,
        )
        db.add(alert)
        await db.commit()
        r = await client.get("/api/dashboard", headers=auth(developer_token))
        assert r.status_code == 200
        data = r.json()
        assert data["total_hosts"] == 1
        assert data["unacknowledged_alerts"] == 1

    async def test_viewer_sees_fleet_wide_stats(self, client, viewer_token, host, db):
        # viewer is not a developer — should see fleet-wide data
        from app.models import Alert, AlertSeverity, AlertKind, Ecosystem
        alert = Alert(
            host_id=host.id, package_name="pkg2", ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv, severity=AlertSeverity.medium,
        )
        db.add(alert)
        await db.commit()
        r = await client.get("/api/dashboard", headers=auth(viewer_token))
        assert r.status_code == 200
        assert r.json()["total_hosts"] >= 1


# ── JWT sub type safety ────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestJwtSubTypeSafety:
    async def test_non_integer_sub_returns_401_not_500(self, client):
        """A validly-signed token whose sub is not an integer must yield 401, not 500."""
        from app.core.security import create_access_token
        bad_token = create_access_token("not-an-integer")
        r = await client.get("/api/auth/me", headers=auth(bad_token))
        assert r.status_code == 401

    async def test_totp_session_token_cannot_be_used_as_access_token(self, client, admin_user):
        """A TOTP session token must not grant access to protected endpoints."""
        from app.core.security import create_totp_session_token
        totp_token = create_totp_session_token(admin_user.id)
        r = await client.get("/api/auth/me", headers=auth(totp_token))
        assert r.status_code == 401
