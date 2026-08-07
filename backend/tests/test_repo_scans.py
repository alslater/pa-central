"""Tests for /api/repo-scans CRUD."""
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models import AlertSeverity, FindingRecord
from tests.conftest import auth

REPO_PAYLOAD = {
    "name": "my-repo",
    "url": "https://github.com/example/repo.git",
    "branch": "main",
    "min_notify_severity": "high",
}


@pytest.mark.asyncio
class TestRepoScans:
    async def test_create_repo_scan(self, client, admin_token):
        r = await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "my-repo"

    async def test_list_repo_scans(self, client, admin_token):
        await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))
        r = await client.get("/api/repo-scans", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) >= 1

    async def test_get_repo_scan(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.get(f"/api/repo-scans/{created['id']}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["id"] == created["id"]

    async def test_patch_repo_scan(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.patch(
            f"/api/repo-scans/{created['id']}",
            json={"name": "renamed-repo"},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["name"] == "renamed-repo"

    async def test_delete_repo_scan(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.delete(f"/api/repo-scans/{created['id']}", headers=auth(admin_token))
        assert r.status_code == 204

    async def test_get_results_empty(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.get(f"/api/repo-scans/{created['id']}/results", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_requires_operator(self, client, viewer_token):
        r = await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(viewer_token))
        assert r.status_code == 403


@pytest.mark.asyncio
class TestRepoScanTrigger:
    async def _create_scan(self, client, token):
        r = await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(token))
        return r.json()

    async def test_trigger_creates_result_and_returns_202(self, client, admin_token):
        scan = await self._create_scan(client, admin_token)
        with patch("app.api.repo_scans.EcsClient") as MockECS, \
             patch("app.api.repo_scans._get_valkey") as MockValkey:
            MockECS.return_value.run_scan_task = AsyncMock(return_value="arn:aws:ecs:task/abc123")
            mock_ctx = MagicMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=None)
            mock_ctx.__aexit__ = AsyncMock(return_value=None)
            MockValkey.return_value = mock_ctx
            r = await client.post(f"/api/repo-scans/{scan['id']}/trigger", headers=auth(admin_token))
        assert r.status_code == 202, r.text
        assert r.json()["triggered_by"] == "manual"

    async def test_trigger_returns_400_when_disabled(self, client, admin_token):
        scan = await self._create_scan(client, admin_token)
        await client.patch(
            f"/api/repo-scans/{scan['id']}",
            json={"is_enabled": False},
            headers=auth(admin_token),
        )
        r = await client.post(f"/api/repo-scans/{scan['id']}/trigger", headers=auth(admin_token))
        assert r.status_code == 400


@pytest.mark.asyncio
class TestScanOptions:
    async def test_scan_options_returns_expected_shape(self, client, operator_token):
        r = await client.get("/api/repo-scans/scan-options", headers=auth(operator_token))
        assert r.status_code == 200
        data = r.json()
        assert "flags" in data
        assert "exclusions" in data
        assert isinstance(data["flags"], list)
        assert isinstance(data["exclusions"], list)

    async def test_scan_options_includes_known_flags(self, client, operator_token):
        r = await client.get("/api/repo-scans/scan-options", headers=auth(operator_token))
        assert r.status_code == 200
        names = {f["name"] for f in r.json()["flags"]}
        assert "scan_unpinned" in names
        assert "scan_installed" in names
        assert "requirements" in names

    async def test_scan_options_flag_shape(self, client, operator_token):
        r = await client.get("/api/repo-scans/scan-options", headers=auth(operator_token))
        flag = next(f for f in r.json()["flags"] if f["name"] == "scan_unpinned")
        assert flag["cli_flag"] == "--scan-unpinned"
        assert flag["type"] == "bool"
        assert isinstance(flag["help"], str)

    async def test_scan_options_exclusions_include_scan_installed_requirements(self, client, operator_token):
        r = await client.get("/api/repo-scans/scan-options", headers=auth(operator_token))
        assert ["scan_installed", "requirements"] in r.json()["exclusions"]


@pytest.mark.asyncio
class TestSubfolderValidation:
    """subfolder must be a relative path with no .. segments."""

    async def test_create_accepts_valid_subfolder(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "backend"},
            headers=auth(admin_token),
        )
        assert r.status_code == 201, r.text
        assert r.json()["subfolder"] == "backend"

    async def test_create_accepts_nested_subfolder(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "a/b/c"},
            headers=auth(admin_token),
        )
        assert r.status_code == 201, r.text

    async def test_create_rejects_absolute_path(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "/etc/passwd"},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    async def test_create_rejects_dotdot(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "../sibling"},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    async def test_create_rejects_embedded_dotdot(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "a/../../b"},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    async def test_patch_rejects_absolute_path(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.patch(
            f"/api/repo-scans/{created['id']}",
            json={"subfolder": "/tmp"},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    async def test_patch_rejects_dotdot(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.patch(
            f"/api/repo-scans/{created['id']}",
            json={"subfolder": ".."},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    async def test_patch_accepts_valid_subfolder(self, client, admin_token):
        created = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.patch(
            f"/api/repo-scans/{created['id']}",
            json={"subfolder": "src/app"},
            headers=auth(admin_token),
        )
        assert r.status_code == 200, r.text
        assert r.json()["subfolder"] == "src/app"

    async def test_create_normalizes_whitespace_only_to_none(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "   "},
            headers=auth(admin_token),
        )
        assert r.status_code == 201, r.text
        assert r.json()["subfolder"] is None

    async def test_create_normalizes_empty_string_to_none(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": ""},
            headers=auth(admin_token),
        )
        assert r.status_code == 201, r.text
        assert r.json()["subfolder"] is None

    async def test_create_normalizes_dot_to_none(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "."},
            headers=auth(admin_token),
        )
        assert r.status_code == 201, r.text
        assert r.json()["subfolder"] is None

    async def test_create_trims_whitespace_from_valid_subfolder(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "  backend  "},
            headers=auth(admin_token),
        )
        assert r.status_code == 201, r.text
        assert r.json()["subfolder"] == "backend"

    async def test_create_rejects_backslash(self, client, admin_token):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, "subfolder": "a\\b"},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    @pytest.mark.parametrize("field", ["sla_high_days", "sla_medium_days"])
    @pytest.mark.parametrize("value", [0, -1, -100])
    async def test_create_rejects_non_positive_sla(self, client, admin_token, field, value):
        r = await client.post(
            "/api/repo-scans",
            json={**REPO_PAYLOAD, field: value},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text

    @pytest.mark.parametrize("field", ["sla_high_days", "sla_medium_days"])
    @pytest.mark.parametrize("value", [0, -1])
    async def test_update_rejects_non_positive_sla(self, client, db, admin_user, admin_token, field, value):
        scan = (await client.post("/api/repo-scans", json=REPO_PAYLOAD, headers=auth(admin_token))).json()
        r = await client.patch(
            f"/api/repo-scans/{scan['id']}",
            json={field: value},
            headers=auth(admin_token),
        )
        assert r.status_code == 422, r.text


def _open_finding(repo_scan_id, days_old=5, severity="high", accepted=False):
    now = datetime.now(UTC)
    return FindingRecord(
        repo_scan_id=repo_scan_id,
        advisory_id="GHSA-t", package="pkg", ecosystem="pypi",
        severity=AlertSeverity(severity),
        first_found_at=now - timedelta(days=days_old),
        reopen_count=0,
        accepted_at=now if accepted else None,
        accepted_reason="ok" if accepted else None,
    )


@pytest.mark.asyncio
class TestRepoScanBreachField:
    async def test_breach_false_no_findings(self, client, db, admin_user, admin_token):
        scan = (await client.post("/api/repo-scans",
            json={"name": "b1", "url": "https://g.com/r.git", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        r = await client.get(f"/api/repo-scans/{scan['id']}", headers=auth(admin_token))
        assert r.json()["breach"] is False
        assert r.json()["breach_count"] == 0

    async def test_breach_false_within_sla(self, client, db, admin_user, admin_token):
        scan = (await client.post("/api/repo-scans",
            json={"name": "b2", "url": "https://g.com/r2.git", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        db.add(_open_finding(scan["id"], days_old=5, severity="high"))
        await db.commit()
        r = await client.get(f"/api/repo-scans/{scan['id']}", headers=auth(admin_token))
        assert r.json()["breach"] is False

    async def test_breach_true_past_sla(self, client, db, admin_user, admin_token):
        scan = (await client.post("/api/repo-scans",
            json={"name": "b3", "url": "https://g.com/r3.git", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        db.add(_open_finding(scan["id"], days_old=20, severity="high"))
        await db.commit()
        r = await client.get(f"/api/repo-scans/{scan['id']}", headers=auth(admin_token))
        assert r.json()["breach"] is True
        assert r.json()["breach_count"] == 1

    async def test_breach_false_when_accepted(self, client, db, admin_user, admin_token):
        scan = (await client.post("/api/repo-scans",
            json={"name": "b4", "url": "https://g.com/r4.git", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        db.add(_open_finding(scan["id"], days_old=20, severity="high", accepted=True))
        await db.commit()
        r = await client.get(f"/api/repo-scans/{scan['id']}", headers=auth(admin_token))
        assert r.json()["breach"] is False

    async def test_per_repo_findings_endpoint(self, client, db, admin_user, admin_token):
        scan = (await client.post("/api/repo-scans",
            json={"name": "b5", "url": "https://g.com/r5.git", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        db.add(_open_finding(scan["id"]))
        await db.commit()
        r = await client.get(f"/api/repo-scans/{scan['id']}/findings", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) == 1

    async def test_breach_true_lapsed_acceptance(self, client, db, admin_user, admin_token):
        """A finding with lapsed accepted_until is in breach."""
        from datetime import timedelta as td
        scan = (await client.post("/api/repo-scans",
            json={"name": "lapse-s", "url": "http://l", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        yesterday = datetime.now(UTC).date() - td(days=1)
        now = datetime.now(UTC)
        finding = FindingRecord(
            repo_scan_id=scan["id"],
            advisory_id="LAPSE-1", package="lapse-pkg", ecosystem="pypi",
            severity=AlertSeverity.high,
            first_found_at=now - timedelta(days=30),
            accepted_by_id=admin_user.id,
            accepted_at=now - timedelta(days=10),
            accepted_reason="temporary",
            accepted_until=yesterday,  # lapsed!
        )
        db.add(finding)
        await db.commit()
        r = await client.get("/api/repo-scans", headers=auth(admin_token))
        assert r.status_code == 200
        s = next(x for x in r.json() if x["id"] == scan["id"])
        assert s["breach"] is True
        assert s["breach_count"] == 1

    async def test_breach_true_with_stricter_per_scan_sla(self, client, db, admin_user, admin_token):
        """A finding within the global SLA but past a stricter per-scan override is in breach.

        Global default: high=14d. Scan override: sla_high_days=7.
        Finding age: 10d — not breaching globally, but breaching per-scan.
        """
        scan = (await client.post("/api/repo-scans",
            json={"name": "strict-sla", "url": "https://g.com/strict.git", "branch": "main",
                  "min_notify_severity": "high", "sla_high_days": 7},
            headers=auth(admin_token))).json()
        db.add(_open_finding(scan["id"], days_old=10, severity="high"))
        await db.commit()
        # Single-scan endpoint
        r = await client.get(f"/api/repo-scans/{scan['id']}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["breach"] is True
        assert r.json()["breach_count"] == 1
        # List endpoint
        r = await client.get("/api/repo-scans", headers=auth(admin_token))
        assert r.status_code == 200
        s = next(x for x in r.json() if x["id"] == scan["id"])
        assert s["breach"] is True
        assert s["breach_count"] == 1

    async def test_breach_count_multiple_findings(self, client, db, admin_user, admin_token):
        """breach_count reflects all breaching findings."""
        scan = (await client.post("/api/repo-scans",
            json={"name": "multi-s", "url": "http://m", "branch": "main", "min_notify_severity": "high"},
            headers=auth(admin_token))).json()
        old = datetime.now(UTC) - timedelta(days=30)
        for i in range(3):
            db.add(FindingRecord(
                repo_scan_id=scan["id"],
                advisory_id=f"MULTI-{i}", package=f"pkg-{i}", ecosystem="pypi",
                severity=AlertSeverity.high,
                first_found_at=old,
            ))
        await db.commit()
        r = await client.get("/api/repo-scans", headers=auth(admin_token))
        assert r.status_code == 200
        s = next(x for x in r.json() if x["id"] == scan["id"])
        assert s["breach"] is True
        assert s["breach_count"] == 3


@pytest.mark.asyncio
class TestScanConfigHash:
    async def test_hash_set_on_create(self, client, admin_token):
        resp = await client.post(
            "/api/repo-scans",
            json={"name": "hash-test", "url": "https://github.com/x/y", "branch": "main"},
            headers=auth(admin_token),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["scan_config_hash"] is not None
        assert len(data["scan_config_hash"]) == 64

    async def test_hash_changes_on_scan_flags_update(self, client, admin_token):
        resp = await client.post(
            "/api/repo-scans",
            json={"name": "hash-update-test", "url": "https://github.com/x/y", "branch": "main"},
            headers=auth(admin_token),
        )
        scan_id = resp.json()["id"]
        original_hash = resp.json()["scan_config_hash"]

        resp2 = await client.patch(
            f"/api/repo-scans/{scan_id}",
            json={"scan_flags": "--include-dev"},
            headers=auth(admin_token),
        )
        assert resp2.status_code == 200
        assert resp2.json()["scan_config_hash"] != original_hash

    async def test_hash_unchanged_on_non_config_update(self, client, admin_token):
        resp = await client.post(
            "/api/repo-scans",
            json={"name": "hash-stable-test", "url": "https://github.com/x/y", "branch": "main"},
            headers=auth(admin_token),
        )
        scan_id = resp.json()["id"]
        original_hash = resp.json()["scan_config_hash"]

        resp2 = await client.patch(
            f"/api/repo-scans/{scan_id}",
            json={"cron_schedule": "0 3 * * *"},
            headers=auth(admin_token),
        )
        assert resp2.status_code == 200
        assert resp2.json()["scan_config_hash"] == original_hash
