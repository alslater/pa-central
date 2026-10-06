"""remediations (package-alert >= 0.9.0) on host-scan and repo-scan-result ingest."""
import pytest
from sqlalchemy import select

from app.core.config import settings as app_settings
from app.models import (
    AlertSeverity,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    Scan,
    ScanTrigger,
)
from tests.conftest import auth

TEST_SYSTEM_KEY = "test-fleet-system-key-for-tests"

REMEDIATION = {
    "package": "django", "ecosystem": "PyPI", "version": "5.2.15",
    "advisories": [{"id": "GHSA-aaaa", "aliases": ["PYSEC-2026-1"]}],
    "recommended_version": "5.2.17",
    "unfixed_advisory_ids": [],
    "major_upgrade": False,
    "verified": True,
    "recommended_age_days": 12.5,
    "in_cooldown": False,
}


@pytest.fixture(autouse=True)
def set_system_key(monkeypatch):
    monkeypatch.setattr(app_settings, "fleet_system_api_key", TEST_SYSTEM_KEY)


@pytest.fixture(autouse=True)
def suppress_email_background_task(monkeypatch):
    monkeypatch.setattr("app.api.ingest._send_result_email", lambda *a, **kw: None)


@pytest.fixture
async def running_result(db, admin_user):
    scan = RepoScan(
        name="rem-repo", url="https://github.com/test/rem", branch="main",
        min_notify_severity=AlertSeverity.medium, created_by_id=admin_user.id,
    )
    db.add(scan)
    await db.commit()
    result = RepoScanResult(
        repo_scan_id=scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual,
    )
    db.add(result)
    await db.commit()
    await db.refresh(result)
    return scan, result


async def _post_repo(client, result_id, **extra):
    return await client.post("/api/ingest/repo-scan-result", json={
        "repo_scan_result_id": result_id, "status": "success",
        "finding_count": 0, "findings": [], **extra,
    }, headers={"X-API-Key": TEST_SYSTEM_KEY})


async def _post_host(client, raw_key, **extra):
    return await client.post("/api/ingest/scans", json={
        "hostname": "rem-host", "project_path": "/app/rem", "scan_type": "project",
        "status": "findings", "finding_count": 1, **extra,
    }, headers={"X-API-Key": raw_key})


@pytest.mark.asyncio
class TestRepoScanResultRemediations:
    async def test_round_trips_through_results_endpoint(self, client, running_result, admin_token):
        scan, result = running_result
        r = await _post_repo(client, result.id, remediations=[REMEDIATION])
        assert r.status_code == 204, r.text
        r = await client.get(f"/api/repo-scans/{scan.id}/results", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()[0]["remediations"] == [REMEDIATION]

    async def test_all_results_endpoint_exposes_it(self, client, running_result, admin_token):
        _, result = running_result
        assert (await _post_repo(client, result.id, remediations=[REMEDIATION])).status_code == 204
        r = await client.get("/api/repo-scans/results", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()[0]["remediations"] == [REMEDIATION]

    async def test_absent_is_stored_as_null(self, client, running_result, db):
        _, result = running_result
        assert (await _post_repo(client, result.id)).status_code == 204
        await db.refresh(result)
        assert result.remediations is None

    async def test_unknown_keys_ignored_and_missing_fields_default(self, client, running_result, db):
        _, result = running_result
        r = await _post_repo(client, result.id, remediations=[{"package": "x", "future_key": 1}])
        assert r.status_code == 204, r.text
        await db.refresh(result)
        stored = result.remediations[0]
        assert "future_key" not in stored
        assert stored["advisories"] == []
        assert stored["recommended_version"] is None
        assert stored["major_upgrade"] is None

    async def test_malformed_entry_is_dropped_not_rejected(self, client, running_result, db):
        """A rejected ingest loses the whole scan result. Advice is not worth that."""
        _, result = running_result
        r = await _post_repo(client, result.id, remediations=[
            {"package": "bad", "advisories": "not-a-list"},
            "not-a-dict",
            REMEDIATION,
        ])
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert result.status == RepoScanStatus.success
        assert result.remediations == [REMEDIATION]

    async def test_non_list_value_is_stored_as_null(self, client, running_result, db):
        _, result = running_result
        r = await _post_repo(client, result.id, remediations={"package": "x"})
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert result.remediations is None


@pytest.mark.asyncio
class TestHostScanRemediations:
    async def test_round_trips_in_ingest_response(self, client, api_key, db):
        raw, _ = api_key
        r = await _post_host(client, raw, remediations=[REMEDIATION])
        assert r.status_code == 201, r.text
        assert r.json()["remediations"] == [REMEDIATION]
        scan = (await db.execute(select(Scan).where(Scan.project_path == "/app/rem"))).scalar_one()
        assert scan.remediations == [REMEDIATION]

    async def test_absent_is_null(self, client, api_key):
        raw, _ = api_key
        r = await _post_host(client, raw)
        assert r.status_code == 201
        assert r.json()["remediations"] is None

    async def test_malformed_entry_is_dropped_not_rejected(self, client, api_key):
        raw, _ = api_key
        r = await _post_host(client, raw, remediations=[{"advisories": [{"aliases": 5}]}, REMEDIATION])
        assert r.status_code == 201, r.text
        assert r.json()["remediations"] == [REMEDIATION]
