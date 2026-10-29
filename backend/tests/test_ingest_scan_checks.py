"""not_public and yank results (package-alert #121) on host-scan and repo-scan-result ingest.

package-alert sends `yank_checked` with null `yanked` / `yank_failures` when the yank check did
not run (scheduled daemon scans, --scan-installed, --no-yank). An empty list with 0 failures
would claim a check that never ran, so pa-central stores null whenever the check is not known
to have run, including for an older package-alert that sends no `yank_checked` at all.
"""
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

YANKED = {"ecosystem": "PyPI", "package": "requests", "version": "2.32.0", "reason": "broken wheel"}


@pytest.fixture(autouse=True)
def set_system_key(monkeypatch):
    monkeypatch.setattr(app_settings, "fleet_system_api_key", TEST_SYSTEM_KEY)


@pytest.fixture(autouse=True)
def suppress_email_background_task(monkeypatch):
    monkeypatch.setattr("app.api.ingest._send_result_email", lambda *a, **kw: None)


@pytest.fixture
async def running_result(db, admin_user):
    scan = RepoScan(
        name="checks-repo", url="https://github.com/test/checks", branch="main",
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
        "hostname": "checks-host", "project_path": "/app/checks", "scan_type": "project",
        "status": "clean", "finding_count": 0, **extra,
    }, headers={"X-API-Key": raw_key})


def _checks(row) -> tuple:
    return row.not_public, row.yank_checked, row.yanked, row.yank_failures


@pytest.mark.asyncio
class TestRepoScanResultChecks:
    async def test_checked_scan_round_trips(self, client, running_result, db, admin_token):
        scan, result = running_result
        r = await _post_repo(client, result.id, not_public=3, yank_checked=True,
                             yanked=[YANKED], yank_failures=1)
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert _checks(result) == (3, True, [YANKED], 1)
        body = (await client.get(f"/api/repo-scans/{scan.id}/results", headers=auth(admin_token))).json()[0]
        assert (body["not_public"], body["yank_checked"], body["yanked"], body["yank_failures"]) == \
            (3, True, [YANKED], 1)

    async def test_unchecked_scan_stores_null_whatever_was_sent(self, client, running_result, db):
        """A payload claiming no check but carrying results is normalised: no yank count is
        ever stored for a check that did not run."""
        _, result = running_result
        r = await _post_repo(client, result.id, yank_checked=False, yanked=[YANKED], yank_failures=0)
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert _checks(result) == (0, False, None, None)

    async def test_older_package_alert_without_the_fields_is_not_checked(self, client, running_result, db):
        """package-alert before #121 sends yanked=[] and yank_failures=0 from scan-project's JSON
        with no yank_checked, so whether the check ran is unknown."""
        _, result = running_result
        r = await _post_repo(client, result.id, yanked=[], yank_failures=0)
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert _checks(result) == (0, False, None, None)

    @pytest.mark.parametrize("field", ["not_public", "yank_failures"])
    async def test_negative_count_is_rejected(self, client, running_result, field):
        """Matches osv_failures / risk_failures: a negative count is not a value pa sends."""
        _, result = running_result
        r = await _post_repo(client, result.id, yank_checked=True, **{field: -1})
        assert r.status_code == 422

    async def test_malformed_yanked_entry_is_dropped_not_rejected(self, client, running_result, db):
        """A rejected ingest loses the whole scan result. A yank entry is not worth that."""
        _, result = running_result
        r = await _post_repo(client, result.id, yank_checked=True, yank_failures=0,
                             yanked=[{"package": ["not", "a", "string"]}, "not-a-dict", YANKED])
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert result.status == RepoScanStatus.success
        assert result.yanked == [YANKED]

    async def test_non_list_yanked_on_a_checked_scan_is_stored_as_null(self, client, running_result, db):
        _, result = running_result
        r = await _post_repo(client, result.id, yank_checked=True, yanked={"package": "x"}, yank_failures=0)
        assert r.status_code == 204, r.text
        await db.refresh(result)
        assert result.yanked is None


@pytest.mark.asyncio
class TestHostScanChecks:
    async def test_checked_scan_round_trips(self, client, api_key, db):
        raw, _ = api_key
        r = await _post_host(client, raw, not_public=2, yank_checked=True, yanked=[YANKED], yank_failures=0)
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["not_public"], body["yank_checked"], body["yanked"], body["yank_failures"]) == \
            (2, True, [YANKED], 0)
        scan = (await db.execute(select(Scan).where(Scan.project_path == "/app/checks"))).scalar_one()
        assert _checks(scan) == (2, True, [YANKED], 0)

    async def test_scheduled_scan_payload_is_not_checked(self, client, api_key):
        """The shape package-alert's central plugin sends for a scheduled daemon scan."""
        raw, _ = api_key
        r = await _post_host(client, raw, not_public=1, yank_checked=False, yanked=None, yank_failures=None)
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["not_public"], body["yank_checked"], body["yanked"], body["yank_failures"]) == \
            (1, False, None, None)

    async def test_older_plugin_without_the_fields_is_not_checked(self, client, api_key):
        raw, _ = api_key
        r = await _post_host(client, raw)
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["not_public"], body["yank_checked"], body["yanked"], body["yank_failures"]) == \
            (0, False, None, None)

    async def test_unchecked_scan_stores_null_whatever_was_sent(self, client, api_key):
        raw, _ = api_key
        r = await _post_host(client, raw, yanked=[YANKED], yank_failures=4)
        assert r.status_code == 201, r.text
        body = r.json()
        assert (body["yanked"], body["yank_failures"]) == (None, None)

    async def test_not_public_does_not_change_status(self, client, api_key):
        """package-alert keeps status 'clean' when only not_public is set; pa-central stores the
        status it is sent and never derives 'degraded' from not_public."""
        raw, _ = api_key
        r = await _post_host(client, raw, not_public=5)
        assert r.status_code == 201, r.text
        assert r.json()["status"] == "clean"

    async def test_get_scans_exposes_the_fields(self, client, api_key, admin_token):
        """GET /scans is what package-alert's retrieved-scan view reads; it reads these keys."""
        raw, _ = api_key
        assert (await _post_host(client, raw, not_public=2, yank_checked=True,
                                 yanked=[YANKED], yank_failures=0)).status_code == 201
        r = await client.get("/api/scans", headers={"X-API-Key": raw})
        assert r.status_code == 200, r.text
        row = r.json()[0]
        assert (row["not_public"], row["yank_checked"], row["yanked"], row["yank_failures"]) == \
            (2, True, [YANKED], 0)
