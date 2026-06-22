"""Tests for /api/repo-scans CRUD."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
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
