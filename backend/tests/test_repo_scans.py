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
