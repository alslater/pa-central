"""Tests for POST /api/ingest/repo-scan-result."""
import pytest
from sqlalchemy import select
from app.models import RepoScan, RepoScanResult, RepoScanStatus, ScanTrigger, AlertSeverity, FindingRecord
from app.core.config import settings as app_settings
from app.services.finding_lifecycle import compute_scan_config_hash


class TestComputeScanConfigHash:
    def test_none_values_produce_stable_hash(self):
        h = compute_scan_config_hash(None, None, None)
        assert len(h) == 64
        assert h == compute_scan_config_hash(None, None, None)

    def test_different_flags_produce_different_hash(self):
        a = compute_scan_config_hash("--include-dev", None, None)
        b = compute_scan_config_hash("--no-dev", None, None)
        assert a != b

    def test_different_subfolder_produces_different_hash(self):
        a = compute_scan_config_hash(None, "backend", None)
        b = compute_scan_config_hash(None, "frontend", None)
        assert a != b

    def test_different_template_produces_different_hash(self):
        a = compute_scan_config_hash(None, None, 1)
        b = compute_scan_config_hash(None, None, 2)
        assert a != b

    def test_none_and_empty_string_are_distinct(self):
        assert compute_scan_config_hash(None, None, None) != compute_scan_config_hash("", "", None)

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


def _finding(advisory_id="GHSA-x", package="requests", ecosystem="pypi", severity="high"):
    return {"advisory_id": advisory_id, "package": package, "ecosystem": ecosystem, "severity": severity}


async def _ingest(client, result_id, findings, headers):
    r = await client.post("/api/ingest/repo-scan-result", json={
        "repo_scan_result_id": result_id,
        "status": "success",
        "finding_count": len(findings),
        "findings": findings,
    }, headers=headers)
    assert r.status_code == 204
    return r


@pytest.mark.asyncio
class TestFindingLifecycleIngest:
    async def test_first_scan_opens_finding_records(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding()], headers)
        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].advisory_id == "GHSA-x"
        assert rows[0].closed_at is None
        assert rows[0].reopen_count == 0

    async def test_second_scan_same_findings_no_new_rows(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest(client, result2.id, [_finding()], headers)

        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is None

    async def test_finding_gone_closes_record(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest(client, result2.id, [], headers)  # clean scan

        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is not None

    async def test_finding_reappears_increments_reopen_count(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        # open
        await _ingest(client, pending_result.id, [_finding()], headers)
        # close
        r2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(r2)
        await db.commit()
        await db.refresh(r2)
        await _ingest(client, r2.id, [], headers)
        # reopen
        r3 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(r3)
        await db.commit()
        await db.refresh(r3)
        await _ingest(client, r3.id, [_finding()], headers)

        rows = (await db.execute(select(FindingRecord).where(FindingRecord.closed_at.is_(None)))).scalars().all()
        assert len(rows) == 1
        assert rows[0].reopen_count == 1

    async def test_clean_scan_closes_all_open_records(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        findings = [_finding("GHSA-a"), _finding("GHSA-b"), _finding("GHSA-c")]
        await _ingest(client, pending_result.id, findings, headers)

        r2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(r2)
        await db.commit()
        await db.refresh(r2)
        await _ingest(client, r2.id, [], headers)

        open_rows = (await db.execute(select(FindingRecord).where(FindingRecord.closed_at.is_(None)))).scalars().all()
        assert open_rows == []

    async def test_other_repos_records_unaffected(self, client, db, admin_user, pending_result):
        other = RepoScan(name="other", url="https://github.com/other/r", branch="main",
                         min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(other)
        await db.commit()
        await db.refresh(other)
        other_result = RepoScanResult(repo_scan_id=other.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(other_result)
        await db.commit()
        await db.refresh(other_result)

        headers = system_key_header()
        await _ingest(client, other_result.id, [_finding()], headers)
        # clean scan on original repo
        await _ingest(client, pending_result.id, [], headers)

        other_rows = (await db.execute(
            select(FindingRecord).where(FindingRecord.repo_scan_id == other.id)
        )).scalars().all()
        assert len(other_rows) == 1
        assert other_rows[0].closed_at is None

    async def test_missing_ecosystem_stored_as_empty_string(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        finding = {"advisory_id": "GHSA-y", "package": "flask", "severity": "medium"}  # no ecosystem
        await _ingest(client, pending_result.id, [finding], headers)
        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert rows[0].ecosystem == ""

    async def test_findings_missing_required_identity_fields_are_skipped(self, client, db, repo_scan, pending_result):
        """Entries without advisory_id or package must be dropped, not stored as bogus records."""
        headers = system_key_header()
        bad = [
            {"package": "pkg", "ecosystem": "pypi", "severity": "high"},           # no advisory_id
            {"advisory_id": "GHSA-x", "ecosystem": "pypi", "severity": "high"},    # no package
            {"advisory_id": "", "package": "pkg", "ecosystem": "pypi"},             # empty advisory_id
            {"advisory_id": "  ", "package": "pkg", "ecosystem": "pypi"},           # whitespace-only advisory_id
        ]
        await _ingest(client, pending_result.id, bad, headers)
        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert rows == []

    async def test_moderate_severity_alias_maps_to_medium(self, client, db, repo_scan, pending_result):
        """'moderate' from upstream scanners must be stored as 'medium', not coerced to 'info'."""
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding(severity="moderate")], headers)
        rows = (await db.execute(select(FindingRecord).where(FindingRecord.closed_at.is_(None)))).scalars().all()
        assert len(rows) == 1
        assert rows[0].severity.value == "medium"

    async def test_unknown_severity_falls_back_to_info(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding(severity="bogus")], headers)
        rows = (await db.execute(select(FindingRecord).where(FindingRecord.closed_at.is_(None)))).scalars().all()
        assert len(rows) == 1
        assert rows[0].severity.value == "info"

    async def test_severity_captured_at_first_appearance(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding(severity="high")], headers)

        r2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(r2)
        await db.commit()
        await db.refresh(r2)
        # severity changed to critical in subsequent scan — open record unchanged
        await _ingest(client, r2.id, [_finding(severity="critical")], headers)

        rows = (await db.execute(select(FindingRecord).where(FindingRecord.closed_at.is_(None)))).scalars().all()
        assert rows[0].severity.value == "high"

    async def test_duplicate_ingest_does_not_create_extra_open_record(self, client, db, repo_scan, pending_result):
        """Ingesting the same finding twice must not produce two open records.

        Simulates a repeated ingest (e.g. after a crash-and-retry) by calling
        update_finding_records twice with the same payload on the same scan.
        The partial unique index + savepoint guard should keep the count at 1.
        """
        from app.services.finding_lifecycle import update_finding_records

        # First ingest via HTTP (creates the open record and commits)
        headers = system_key_header()
        await _ingest(client, pending_result.id, [_finding()], headers)

        # Second ingest: build a new RepoScanResult for the same repo and call
        # update_finding_records directly to exercise the savepoint path.
        r2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running,
                            triggered_by=ScanTrigger.manual,
                            findings=[_finding()])
        db.add(r2)
        await db.flush()
        await update_finding_records(db, r2)
        await db.commit()

        open_rows = (await db.execute(
            select(FindingRecord)
            .where(FindingRecord.repo_scan_id == repo_scan.id)
            .where(FindingRecord.closed_at.is_(None))
        )).scalars().all()
        assert len(open_rows) == 1


class TestConfigChangeReset:
    async def test_config_change_closes_open_findings_with_reason(self, db, repo_scan):
        """When scan_config_hash changes between results, open findings are closed with closed_reason='config_change'."""
        from app.services.finding_lifecycle import update_finding_records, compute_scan_config_hash
        from app.models import FindingRecord, RepoScanResult, RepoScanStatus
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)

        r1 = RepoScanResult(
            repo_scan_id=repo_scan.id,
            status=RepoScanStatus.success,
            scan_config_hash=compute_scan_config_hash("--include-dev", None, None),
            finding_count=1,
            findings=[{"advisory_id": "GHSA-aaa", "package": "requests", "ecosystem": "pypi", "severity": "high"}],
            completed_at=now,
        )
        db.add(r1)
        await db.flush()
        await update_finding_records(db, r1)
        await db.flush()

        open_rows = (await db.execute(
            select(FindingRecord).where(FindingRecord.repo_scan_id == repo_scan.id).where(FindingRecord.closed_at.is_(None))
        )).scalars().all()
        assert len(open_rows) == 1

        r2 = RepoScanResult(
            repo_scan_id=repo_scan.id,
            status=RepoScanStatus.success,
            scan_config_hash=compute_scan_config_hash("--no-dev", None, None),
            finding_count=1,
            findings=[{"advisory_id": "GHSA-aaa", "package": "requests", "ecosystem": "pypi", "severity": "high"}],
            completed_at=now,
        )
        db.add(r2)
        await db.flush()
        await update_finding_records(db, r2)
        await db.flush()

        all_rows = (await db.execute(
            select(FindingRecord).where(FindingRecord.repo_scan_id == repo_scan.id)
        )).scalars().all()
        closed = [r for r in all_rows if r.closed_at is not None]
        assert len(closed) == 1
        assert closed[0].closed_reason == "config_change"

        open_after = [r for r in all_rows if r.closed_at is None]
        assert len(open_after) == 1
        assert open_after[0].reopen_count == 0  # config reset — not a true reopen

    async def test_same_config_hash_does_not_reset(self, db, repo_scan):
        """When scan_config_hash is unchanged, findings carry over normally."""
        from app.services.finding_lifecycle import update_finding_records, compute_scan_config_hash
        from app.models import FindingRecord, RepoScanResult, RepoScanStatus
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)
        h = compute_scan_config_hash(None, None, None)

        r1 = RepoScanResult(
            repo_scan_id=repo_scan.id,
            status=RepoScanStatus.success,
            scan_config_hash=h,
            finding_count=1,
            findings=[{"advisory_id": "GHSA-bbb", "package": "flask", "ecosystem": "pypi", "severity": "medium"}],
            completed_at=now,
        )
        db.add(r1)
        await db.flush()
        await update_finding_records(db, r1)
        await db.flush()

        r2 = RepoScanResult(
            repo_scan_id=repo_scan.id,
            status=RepoScanStatus.success,
            scan_config_hash=h,
            finding_count=1,
            findings=[{"advisory_id": "GHSA-bbb", "package": "flask", "ecosystem": "pypi", "severity": "medium"}],
            completed_at=now,
        )
        db.add(r2)
        await db.flush()
        await update_finding_records(db, r2)
        await db.flush()

        all_rows = (await db.execute(
            select(FindingRecord).where(FindingRecord.repo_scan_id == repo_scan.id)
        )).scalars().all()
        assert len(all_rows) == 1
        assert all_rows[0].closed_at is None
        assert all_rows[0].closed_reason is None

    async def test_null_hash_does_not_reset(self, db, repo_scan):
        """When scan_config_hash is NULL (pre-upgrade result), no reset occurs."""
        from app.services.finding_lifecycle import update_finding_records
        from app.models import FindingRecord, RepoScanResult, RepoScanStatus
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc)

        r1 = RepoScanResult(
            repo_scan_id=repo_scan.id,
            status=RepoScanStatus.success,
            scan_config_hash=None,
            finding_count=1,
            findings=[{"advisory_id": "GHSA-ccc", "package": "django", "ecosystem": "pypi", "severity": "high"}],
            completed_at=now,
        )
        db.add(r1)
        await db.flush()
        await update_finding_records(db, r1)
        await db.flush()

        r2 = RepoScanResult(
            repo_scan_id=repo_scan.id,
            status=RepoScanStatus.success,
            scan_config_hash=None,
            finding_count=1,
            findings=[{"advisory_id": "GHSA-ccc", "package": "django", "ecosystem": "pypi", "severity": "high"}],
            completed_at=now,
        )
        db.add(r2)
        await db.flush()
        await update_finding_records(db, r2)
        await db.flush()

        all_rows = (await db.execute(
            select(FindingRecord).where(FindingRecord.repo_scan_id == repo_scan.id)
        )).scalars().all()
        assert len(all_rows) == 1
        assert all_rows[0].closed_at is None
