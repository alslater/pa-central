"""Tests for POST /api/ingest/repo-scan-result."""
import pytest
from sqlalchemy import select

from app.core.config import settings as app_settings
from app.models import (
    AlertSeverity,
    FindingRecord,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    RiskRecord,
    ScanTrigger,
)
from app.services.finding_lifecycle import compute_scan_config_hash
from tests.conftest import auth


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


def _risk(package="reqeusts", ecosystem="pypi", version="1.0.0", score=46, level="warning"):
    return {
        "package": package, "ecosystem": ecosystem, "version": version,
        "score": score, "level": level,
        "signals": [{"name": "typosquat", "score": 15, "reason": "resembles 'requests'"}],
    }


async def _ingest_with_risks(client, result_id, risks, headers):
    r = await client.post("/api/ingest/repo-scan-result", json={
        "repo_scan_result_id": result_id,
        "status": "success",
        "finding_count": 0,
        "findings": [],
        "risks": risks,
    }, headers=headers)
    assert r.status_code == 204
    return r


async def _ingest_with_risk_failures(client, result_id, risks, risk_failures, headers):
    r = await client.post("/api/ingest/repo-scan-result", json={
        "repo_scan_result_id": result_id,
        "status": "success",
        "finding_count": 0,
        "findings": [],
        "risks": risks,
        "risk_failures": risk_failures,
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

    async def test_long_package_name_persists_across_scans(self, client, db, repo_scan, pending_result):
        """A package/ecosystem value longer than the column width must not be
        misread as a new finding on the next scan. If the identity key were
        built from the untruncated value, it would never match the open row's
        (already-truncated) package/ecosystem, closing and recreating the
        record every scan instead of recognizing it as persisting."""
        headers = system_key_header()
        long_package = "p" * 250  # exceeds FindingRecord.package's 200-char column
        finding = _finding(package=long_package)
        await _ingest(client, pending_result.id, [finding], headers)

        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert len(rows) == 1
        first_id = rows[0].id
        assert rows[0].reopen_count == 0

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest(client, result2.id, [finding], headers)

        rows = (await db.execute(select(FindingRecord))).scalars().all()
        assert len(rows) == 1, "long package name must not create a second row on the next scan"
        assert rows[0].id == first_id
        assert rows[0].closed_at is None
        assert rows[0].reopen_count == 0

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


@pytest.mark.asyncio
class TestRiskLifecycleIngest:
    async def test_first_scan_opens_risk_records(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].package == "reqeusts"
        assert rows[0].score == 46
        assert rows[0].closed_at is None
        assert rows[0].reopen_count == 0

    async def test_second_scan_same_risk_no_new_rows(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest_with_risks(client, result2.id, [_risk()], headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is None

    async def test_persisting_risk_updates_score_in_place(self, client, db, repo_scan, pending_result):
        """The one lifecycle divergence from findings: score/level/signals refresh
        on the open row every scan, rather than freezing at first appearance."""
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk(score=46, level="warning")], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest_with_risks(client, result2.id, [_risk(score=72, level="critical")], headers)

        rows = (await db.execute(select(RiskRecord).where(RiskRecord.closed_at.is_(None)))).scalars().all()
        assert len(rows) == 1
        assert rows[0].score == 72
        assert rows[0].level == "critical"

    async def test_risk_gone_closes_record(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest_with_risks(client, result2.id, [], headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is not None

    async def test_risk_reappears_increments_reopen_count(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)  # open
        r2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(r2)
        await db.commit()
        await db.refresh(r2)
        await _ingest_with_risks(client, r2.id, [], headers)  # close
        r3 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(r3)
        await db.commit()
        await db.refresh(r3)
        await _ingest_with_risks(client, r3.id, [_risk()], headers)  # reopen

        rows = (await db.execute(select(RiskRecord).where(RiskRecord.closed_at.is_(None)))).scalars().all()
        assert len(rows) == 1
        assert rows[0].reopen_count == 1

    async def test_missing_package_is_skipped(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        bad = [{"ecosystem": "pypi", "score": 20, "level": "info"}]  # no package
        await _ingest_with_risks(client, pending_result.id, bad, headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert rows == []

    async def test_non_numeric_score_is_skipped(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        bad = [{"package": "pkg", "ecosystem": "pypi", "score": "not-a-number", "level": "info"}]
        await _ingest_with_risks(client, pending_result.id, bad, headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert rows == []

    async def test_non_string_package_is_skipped_not_500(self, client, db, repo_scan, pending_result):
        """risks is only validated as list[dict] at the API boundary, so
        package/ecosystem can be any JSON type. A non-string value used to
        raise AttributeError on .strip(), turning an otherwise-successful
        ingest into a 500 instead of skipping the one malformed risk."""
        headers = system_key_header()
        bad = [
            {"package": 12345, "ecosystem": "pypi", "score": 20, "level": "info"},
            {"package": ["not", "a", "string"], "ecosystem": "pypi", "score": 20, "level": "info"},
            _risk(package="valid-pkg"),
        ]
        await _ingest_with_risks(client, pending_result.id, bad, headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].package == "valid-pkg"

    async def test_non_string_ecosystem_is_skipped_not_500(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        bad = [{"package": "pkg", "ecosystem": 42, "score": 20, "level": "info"}]
        await _ingest_with_risks(client, pending_result.id, bad, headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert rows == []

    async def test_missing_level_defaults_to_info(self, client, db, repo_scan, pending_result):
        headers = system_key_header()
        risk = {"package": "pkg", "ecosystem": "pypi", "score": 10}  # no level
        await _ingest_with_risks(client, pending_result.id, [risk], headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].level == "info"

    async def test_non_dict_signal_entries_are_filtered_before_persisting(
        self, client, db, repo_scan, pending_result, admin_token,
    ):
        """RiskRecordOut.signals is list[dict]. A non-dict entry (e.g.
        "signals": ["bad"]) would otherwise be stored as-is — the JSON column
        has no element-level constraint — and only fail later, when /api/risks
        or /api/repo-scans/{id}/risks tries to serialise it through that
        schema. Filtering at ingest keeps every persisted signal a dict."""
        headers = system_key_header()
        risk = {
            "package": "pkg", "ecosystem": "pypi", "score": 10, "level": "info",
            "signals": ["bad", 123, None, {"name": "typosquat", "score": 15, "reason": "ok"}],
        }
        await _ingest_with_risks(client, pending_result.id, [risk], headers)
        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].signals == [{"name": "typosquat", "score": 15, "reason": "ok"}]

        r = await client.get("/api/risks", headers=auth(admin_token))
        assert r.status_code == 200

    async def test_malformed_row_does_not_falsely_close_existing_risk(self, client, db, repo_scan, pending_result):
        """A row that fails our own parsing (bad type, blank package, or a
        non-numeric score) is dropped from `incoming` the same way a
        risk_failures-reported package is — but risk_failures itself stays 0
        in this case, since package-alert's own scoring pass succeeded; only
        our parsing choked. Without suppressing closure here too, the
        previously open risk for that same package would be misread as
        genuinely resolved and closed, even though it simply failed to parse
        on this scan."""
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        # risk_failures is 0 — package-alert's pass succeeded — but this row
        # is malformed on our side (non-string ecosystem) and gets skipped.
        bad = [{"package": "reqeusts", "ecosystem": 42, "score": 46, "level": "warning"}]
        await _ingest_with_risks(client, result2.id, bad, headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is None

    async def test_other_repos_records_unaffected(self, client, db, admin_user, pending_result):
        other = RepoScan(name="other-risk", url="https://github.com/other/r2", branch="main",
                         min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(other)
        await db.commit()
        await db.refresh(other)
        other_result = RepoScanResult(repo_scan_id=other.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(other_result)
        await db.commit()
        await db.refresh(other_result)

        headers = system_key_header()
        await _ingest_with_risks(client, other_result.id, [_risk()], headers)
        await _ingest_with_risks(client, pending_result.id, [], headers)  # clean scan on original repo

        other_rows = (await db.execute(
            select(RiskRecord).where(RiskRecord.repo_scan_id == other.id)
        )).scalars().all()
        assert len(other_rows) == 1
        assert other_rows[0].closed_at is None

    async def test_long_package_name_persists_across_scans(self, client, db, repo_scan, pending_result):
        """Same failure mode as findings: a package name exceeding
        RiskRecord.package's 200-char column must not be misread as a new
        risk on the next scan just because the identity key was built from
        the untruncated value."""
        headers = system_key_header()
        long_package = "p" * 250
        risk = _risk(package=long_package)
        await _ingest_with_risks(client, pending_result.id, [risk], headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        first_id = rows[0].id
        assert rows[0].reopen_count == 0

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest_with_risks(client, result2.id, [risk], headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1, "long package name must not create a second row on the next scan"
        assert rows[0].id == first_id
        assert rows[0].closed_at is None
        assert rows[0].reopen_count == 0

    async def test_risk_failures_prevents_closing_absent_records(self, client, db, repo_scan, pending_result):
        """A nonzero risk_failures means package-alert's risk pass only partially
        completed. An empty/short risks list in that scan must NOT be read as
        "these packages are no longer risky" — there is no way to tell a
        genuine resolution apart from a scoring failure, so closing is skipped
        entirely for a scan reporting failures."""
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        # Risk pass failed for every package this scan — risks list is empty,
        # but that must not be read as "nothing is risky anymore".
        await _ingest_with_risk_failures(client, result2.id, [], risk_failures=1, headers=headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is None

    async def test_risk_failures_does_not_block_upserting_successful_risks(self, client, db, repo_scan, pending_result):
        """Failures for some packages must not prevent packages that DID score
        successfully from being opened/refreshed normally."""
        headers = system_key_header()
        await _ingest_with_risk_failures(
            client, pending_result.id, [_risk(package="reqeusts", score=46)], risk_failures=1, headers=headers,
        )

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].package == "reqeusts"
        assert rows[0].score == 46
        assert rows[0].closed_at is None

    async def test_zero_risk_failures_still_closes_absent_records(self, client, db, repo_scan, pending_result):
        """Sanity check: the existing close-on-absence behavior is untouched
        when risk_failures is 0 (a genuinely clean scan)."""
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        await _ingest_with_risk_failures(client, result2.id, [], risk_failures=0, headers=headers)

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is not None

    async def test_risks_omitted_entirely_leaves_open_records_untouched(self, client, db, repo_scan, pending_result):
        """An older package-alert binary that predates risk scoring omits the
        `risks` field entirely rather than sending []. That must not be read
        as "risk pass ran, found nothing" — it means no risk pass was
        reported at all, so existing open records must be left exactly as
        they were: no closes, no opens, no refreshes."""
        headers = system_key_header()
        await _ingest_with_risks(client, pending_result.id, [_risk()], headers)

        result2 = RepoScanResult(repo_scan_id=repo_scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
        db.add(result2)
        await db.commit()
        await db.refresh(result2)
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": result2.id,
            "status": "success",
            "finding_count": 0,
            "findings": [],
        }, headers=headers)
        assert r.status_code == 204

        rows = (await db.execute(select(RiskRecord))).scalars().all()
        assert len(rows) == 1
        assert rows[0].closed_at is None
        assert rows[0].score == 46

    async def test_negative_risk_failures_is_rejected(self, client, db, repo_scan, pending_result):
        """A negative count is truthy in Python (`not -1` is False), so without
        this rejection update_risk_records would treat it as a partial-failure
        signal and skip closing absent risks — while the frontend's `> 0` check
        would simultaneously hide the warning explaining why. Malformed input
        must not be able to reach either code path."""
        headers = system_key_header()
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": pending_result.id,
            "status": "success",
            "finding_count": 0,
            "findings": [],
            "risks": [],
            "risk_failures": -1,
        }, headers=headers)
        assert r.status_code == 422


@pytest.mark.asyncio
class TestRisksDoNotTriggerEmail:
    async def test_risks_only_no_findings_does_not_send_email(self, client, db, repo_scan, pending_result, monkeypatch):
        """Risks are explicitly out of scope for email notifications (see spec
        Non-goals). A scan result with risks but zero findings must not queue
        _send_result_email — needs_email is keyed only on finding_count/status.

        This local monkeypatch overrides the autouse suppress_email_background_task
        stub (which silently discards calls) with one that records them, so an
        empty `sent` list here is real evidence add_task was never invoked —
        not an artifact of the background task not having run. ASGITransport
        (see conftest.py) runs BackgroundTasks synchronously as part of request
        completion, so if add_task had been called, _send_result_email would
        have executed before the response returned.
        """
        sent = []
        monkeypatch.setattr("app.api.ingest._send_result_email", lambda *a, **kw: sent.append(a))
        headers = system_key_header()
        r = await client.post("/api/ingest/repo-scan-result", json={
            "repo_scan_result_id": pending_result.id,
            "status": "success",
            "finding_count": 0,
            "findings": [],
            "risks": [_risk(level="critical", score=90)],
        }, headers=headers)
        assert r.status_code == 204
        assert sent == []


class TestConfigChangeReset:
    async def test_config_change_closes_open_findings_with_reason(self, db, repo_scan):
        """When scan_config_hash changes between results, open findings are closed with closed_reason='config_change'."""
        import datetime

        from app.models import FindingRecord, RepoScanResult, RepoScanStatus
        from app.services.finding_lifecycle import (
            compute_scan_config_hash,
            update_finding_records,
        )

        now = datetime.datetime.now(datetime.UTC)

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
        import datetime

        from app.models import FindingRecord, RepoScanResult, RepoScanStatus
        from app.services.finding_lifecycle import (
            compute_scan_config_hash,
            update_finding_records,
        )

        now = datetime.datetime.now(datetime.UTC)
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
        import datetime

        from app.models import FindingRecord, RepoScanResult, RepoScanStatus
        from app.services.finding_lifecycle import update_finding_records

        now = datetime.datetime.now(datetime.UTC)

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
