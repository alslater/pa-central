"""Tests for POST /api/ingest/repo-scan-result."""
import pytest
from app.models import RepoScan, RepoScanResult, RepoScanStatus, ScanTrigger, AlertSeverity
from app.core.config import settings as app_settings

TEST_SYSTEM_KEY = "test-fleet-system-key-for-tests"


def system_key_header() -> dict:
    return {"X-API-Key": TEST_SYSTEM_KEY}


@pytest.fixture(autouse=True)
def set_system_key(monkeypatch):
    monkeypatch.setattr(app_settings, "fleet_system_api_key", TEST_SYSTEM_KEY)


@pytest.fixture(autouse=True)
def suppress_email_background_task(monkeypatch):
    # _send_result_email opens its own DB engine which can't share the test's
    # in-process SAVEPOINT transaction. Suppress it — email sending is tested
    # separately; these tests only verify the ingest HTTP contract.
    monkeypatch.setattr("app.api.ingest._send_result_email", lambda *a, **kw: None)


@pytest.fixture
async def repo_scan(db, admin_user):
    scan = RepoScan(
        name="test-repo", url="https://github.com/test/repo",
        branch="main",
        min_notify_severity=AlertSeverity.medium,
        created_by_id=admin_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@pytest.fixture
async def pending_result(db, repo_scan):
    result = RepoScanResult(
        repo_scan_id=repo_scan.id,
        status=RepoScanStatus.running,
        triggered_by=ScanTrigger.manual,
    )
    db.add(result)
    await db.commit()
    await db.refresh(result)
    return result


@pytest.mark.asyncio
class TestIngestRepoScanResult:
    async def test_success_result_stored(self, client, pending_result):
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": pending_result.id,
            "status": "success",
            "pa_version": "1.2.3",
            "finding_count": 2,
            "findings": [{"package": "requests", "severity": "high"}],
        }, headers=system_key_header())
        assert r.status_code == 204, r.text

    async def test_failure_result_stored(self, client, pending_result):
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": pending_result.id,
            "status": "failed",
            "error_message": "Clone failed: authentication required",
        }, headers=system_key_header())
        assert r.status_code == 204

    async def test_unknown_result_id_returns_404(self, client):
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": 99999,
            "status": "success",
            "finding_count": 0,
        }, headers=system_key_header())
        assert r.status_code == 404

    async def test_requires_api_key(self, client, pending_result):
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": pending_result.id,
            "status": "success",
            "finding_count": 0,
        })
        assert r.status_code == 401
