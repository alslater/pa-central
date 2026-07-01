"""Tests for finding_records model, lifecycle service, and findings API."""
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from app.models import AlertSeverity, FindingRecord
from app.services.finding_lifecycle import compute_sla_days, in_breach, is_accepted
from tests.conftest import auth


@pytest.mark.asyncio
class TestFindingRecordModel:
    async def test_finding_record_table_exists(self, db):
        """FindingRecord can be created and queried."""
        from sqlalchemy import select
        result = await db.execute(select(FindingRecord))
        assert result.scalars().all() == []


def _make_record(**kwargs) -> SimpleNamespace:
    defaults = dict(
        id=1, repo_scan_id=1,
        advisory_id="GHSA-x", package="requests", ecosystem="pypi",
        severity=AlertSeverity.high,
        first_found_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        closed_at=None, reopen_count=0,
        accepted_by_id=None, accepted_at=None,
        accepted_reason=None, accepted_until=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class TestComputeSlaDays:
    def test_critical_uses_high(self):
        assert compute_sla_days(AlertSeverity.critical, 14, 90) == 14

    def test_high_uses_high(self):
        assert compute_sla_days(AlertSeverity.high, 14, 90) == 14

    def test_medium_uses_medium(self):
        assert compute_sla_days(AlertSeverity.medium, 14, 90) == 90

    def test_warning_no_sla(self):
        assert compute_sla_days(AlertSeverity.warning, 14, 90) is None

    def test_low_no_sla(self):
        assert compute_sla_days(AlertSeverity.low, 14, 90) is None

    def test_info_no_sla(self):
        assert compute_sla_days(AlertSeverity.info, 14, 90) is None


class TestIsAccepted:
    def test_never_accepted(self):
        r = _make_record()
        assert is_accepted(r) is False

    def test_accepted_no_expiry(self):
        r = _make_record(accepted_at=datetime(2026, 1, 1, tzinfo=timezone.utc), accepted_reason="ok")
        assert is_accepted(r) is True

    def test_accepted_future_expiry(self):
        r = _make_record(
            accepted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            accepted_reason="ok",
            accepted_until=date(2099, 12, 31),
        )
        assert is_accepted(r) is True

    def test_accepted_past_expiry(self):
        r = _make_record(
            accepted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            accepted_reason="ok",
            accepted_until=date(2020, 1, 1),
        )
        assert is_accepted(r) is False

    def test_accepted_today_expiry_is_lapsed(self):
        today = date.today()
        r = _make_record(
            accepted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            accepted_reason="ok",
            accepted_until=today,
        )
        assert is_accepted(r) is False


class TestInBreach:
    def _now(self):
        return datetime(2026, 6, 22, tzinfo=timezone.utc)

    def test_no_sla_never_in_breach(self):
        r = _make_record(first_found_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
        assert in_breach(r, None, self._now()) is False

    def test_closed_never_in_breach(self):
        r = _make_record(
            first_found_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            closed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )
        assert in_breach(r, 14, self._now()) is False

    def test_accepted_never_in_breach(self):
        r = _make_record(
            first_found_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            accepted_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            accepted_reason="risk accepted",
        )
        assert in_breach(r, 14, self._now()) is False

    def test_within_sla_not_in_breach(self):
        r = _make_record(first_found_at=self._now() - timedelta(days=10))
        assert in_breach(r, 14, self._now()) is False

    def test_exactly_at_sla_not_in_breach(self):
        r = _make_record(first_found_at=self._now() - timedelta(days=14))
        assert in_breach(r, 14, self._now()) is False

    def test_past_sla_in_breach(self):
        r = _make_record(first_found_at=self._now() - timedelta(days=15))
        assert in_breach(r, 14, self._now()) is True

    def test_lapsed_acceptance_in_breach(self):
        r = _make_record(
            first_found_at=self._now() - timedelta(days=30),
            accepted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            accepted_reason="ok",
            accepted_until=date(2026, 1, 2),  # lapsed
        )
        assert in_breach(r, 14, self._now()) is True


class TestFindingSchemas:
    def test_finding_record_out_has_computed_fields(self):
        from app.schemas import FindingRecordOut
        # All fields present in schema
        fields = FindingRecordOut.model_fields
        for f in ("id", "repo_scan_id", "advisory_id", "package", "ecosystem",
                  "severity", "first_found_at", "closed_at", "reopen_count",
                  "accepted_by_id", "accepted_at", "accepted_reason", "accepted_until",
                  "is_accepted", "days_open", "sla_days", "in_breach"):
            assert f in fields, f"missing field: {f}"

    def test_finding_accept_body_requires_reason(self):
        from app.schemas import FindingAcceptBody
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            FindingAcceptBody()

    def test_finding_settings_has_three_fields(self):
        from app.schemas import FindingSettingsPut
        s = FindingSettingsPut(sla_high_days=14, sla_medium_days=90, finding_retention_days=365)
        assert s.sla_high_days == 14


async def _make_scan_and_finding(db, admin_user, days_old=20, severity="high",
                                 closed=False, accepted=False, accepted_until=None):
    """Helper: create a RepoScan + open FindingRecord, return (scan, record)."""
    from app.models import RepoScan, FindingRecord, AlertSeverity
    from datetime import datetime, timezone, timedelta
    scan = RepoScan(
        name="test", url="https://github.com/t/r", branch="main",
        min_notify_severity="medium", created_by_id=admin_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    now = datetime.now(timezone.utc)
    record = FindingRecord(
        repo_scan_id=scan.id,
        advisory_id="GHSA-z", package="flask", ecosystem="pypi",
        severity=AlertSeverity(severity),
        first_found_at=now - timedelta(days=days_old),
        closed_at=now if closed else None,
        reopen_count=0,
        accepted_by_id=admin_user.id if accepted else None,
        accepted_at=now if accepted else None,
        accepted_reason="ok" if accepted else None,
        accepted_until=accepted_until,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return scan, record


@pytest.mark.asyncio
class TestFindingsAPI:
    async def test_list_findings_returns_open_only(self, client, db, admin_user, admin_token):
        _, open_rec = await _make_scan_and_finding(db, admin_user, days_old=5)
        _, closed_rec = await _make_scan_and_finding(db, admin_user, days_old=20, closed=True)
        r = await client.get("/api/findings", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert open_rec.id in ids
        assert closed_rec.id not in ids

    async def test_list_findings_breach_filter(self, client, db, admin_user, admin_token):
        _, breaching = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        _, clean = await _make_scan_and_finding(db, admin_user, days_old=5, severity="high")
        r = await client.get("/api/findings?breach=true", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert breaching.id in ids
        assert clean.id not in ids

    async def test_breach_filter_includes_stricter_per_scan_sla(self, client, db, admin_user, admin_token):
        """breach=true must not drop findings that breach a stricter per-scan SLA.

        Global default: high=14d. Scan A override: sla_high_days=7.
        Finding age: 10d — safe under the global default but breaching the
        per-scan override. The aggregate cutoff must use min(7, 14)=7, not 14.
        """
        from app.models import RepoScan, FindingRecord, AlertSeverity
        from datetime import datetime, timezone, timedelta as td
        scan = RepoScan(
            name="strict", url="https://g.com/s.git", branch="main",
            min_notify_severity="medium", created_by_id=admin_user.id,
            sla_high_days=7,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        now = datetime.now(timezone.utc)
        record = FindingRecord(
            repo_scan_id=scan.id,
            advisory_id="GHSA-strict", package="pkg", ecosystem="pypi",
            severity=AlertSeverity.high,
            first_found_at=now - td(days=10),
            reopen_count=0,
        )
        db.add(record)
        await db.commit()
        r = await client.get("/api/findings?breach=true", headers=auth(admin_token))
        assert r.status_code == 200
        assert any(f["id"] == record.id for f in r.json())

    async def test_list_findings_severity_filter(self, client, db, admin_user, admin_token):
        _, high_rec = await _make_scan_and_finding(db, admin_user, severity="high")
        _, med_rec = await _make_scan_and_finding(db, admin_user, severity="medium")
        r = await client.get("/api/findings?severity=high", headers=auth(admin_token))
        ids = [f["id"] for f in r.json()]
        assert high_rec.id in ids
        assert med_rec.id not in ids

    async def test_list_findings_accepted_filter(self, client, db, admin_user, admin_token):
        _, accepted_rec = await _make_scan_and_finding(db, admin_user, accepted=True)
        _, open_rec = await _make_scan_and_finding(db, admin_user, accepted=False)
        r = await client.get("/api/findings?accepted=true", headers=auth(admin_token))
        ids = [f["id"] for f in r.json()]
        assert accepted_rec.id in ids
        assert open_rec.id not in ids

    async def test_accept_finding_sets_fields(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "known risk", "accepted_until": "2027-01-01"},
            headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["is_accepted"] is True
        assert data["accepted_reason"] == "known risk"
        assert data["accepted_until"] == "2027-01-01"

    async def test_accept_finding_missing_reason_422(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={}, headers=auth(admin_token))
        assert r.status_code == 422

    async def test_accept_finding_reason_too_long_422(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "x" * 1001}, headers=auth(admin_token))
        assert r.status_code == 422

    async def test_revoke_accept_clears_fields(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user, accepted=True)
        r = await client.delete(f"/api/findings/{record.id}/accept", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["is_accepted"] is False
        assert r.json()["accepted_reason"] is None

    async def test_revoke_non_accepted_is_idempotent(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user, accepted=False)
        r = await client.delete(f"/api/findings/{record.id}/accept", headers=auth(admin_token))
        assert r.status_code == 200

    async def test_accept_closed_finding_returns_409(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user, closed=True)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "too late"}, headers=auth(admin_token))
        assert r.status_code == 409

    async def test_revoke_closed_finding_returns_409(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user, closed=True, accepted=True)
        r = await client.delete(f"/api/findings/{record.id}/accept", headers=auth(admin_token))
        assert r.status_code == 409

    async def test_get_finding_settings_returns_defaults(self, client, admin_token):
        r = await client.get("/api/settings/findings", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["sla_high_days"] == 14
        assert data["sla_medium_days"] == 90
        assert data["finding_retention_days"] == 365

    async def test_put_finding_settings_persists(self, client, admin_token):
        r = await client.put("/api/settings/findings",
            json={"sla_high_days": 7, "sla_medium_days": 60, "finding_retention_days": 180},
            headers=auth(admin_token))
        assert r.status_code == 200
        r2 = await client.get("/api/settings/findings", headers=auth(admin_token))
        assert r2.json()["sla_high_days"] == 7

    async def test_put_finding_settings_rejects_zero(self, client, admin_token):
        r = await client.put("/api/settings/findings",
            json={"sla_high_days": 0, "sla_medium_days": 90, "finding_retention_days": 365},
            headers=auth(admin_token))
        assert r.status_code == 422

    async def test_lapsed_acceptance_not_shown_as_accepted(self, client, db, admin_user, admin_token):
        from datetime import date, timedelta
        yesterday = date.today() - timedelta(days=1)
        _, record = await _make_scan_and_finding(db, admin_user, accepted=True, accepted_until=yesterday)
        r = await client.get("/api/findings", headers=auth(admin_token))
        finding = next(f for f in r.json() if f["id"] == record.id)
        assert finding["is_accepted"] is False

    async def test_accepted_false_excludes_accepted_findings(self, client, db, admin_user, admin_token):
        _, accepted_rec = await _make_scan_and_finding(db, admin_user, accepted=True)
        _, open_rec = await _make_scan_and_finding(db, admin_user, accepted=False)
        r = await client.get("/api/findings?accepted=false", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert open_rec.id in ids
        assert accepted_rec.id not in ids

    async def test_breach_false_excludes_breaching_findings(self, client, db, admin_user, admin_token):
        _, breaching = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        _, clean = await _make_scan_and_finding(db, admin_user, days_old=5, severity="high")
        r = await client.get("/api/findings?breach=false", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert clean.id in ids
        assert breaching.id not in ids

    async def test_breach_true_with_repo_scan_id(self, client, db, admin_user, admin_token):
        """breach=true scoped to a single scan only returns breaching findings for that scan."""
        scan_a, breaching = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        _, other = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        r = await client.get(f"/api/findings?breach=true&repo_scan_id={scan_a.id}", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert breaching.id in ids
        assert other.id not in ids

    async def test_accepted_false_with_repo_scan_id(self, client, db, admin_user, admin_token):
        """accepted=false scoped to a scan excludes accepted findings from that scan."""
        scan, accepted_rec = await _make_scan_and_finding(db, admin_user, accepted=True)
        r = await client.get(f"/api/findings?accepted=false&repo_scan_id={scan.id}", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()]
        assert accepted_rec.id not in ids

    async def test_accept_with_past_accepted_until_returns_422(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "ok", "accepted_until": "2020-01-01"},
            headers=auth(admin_token))
        assert r.status_code == 422

    async def test_accept_with_today_accepted_until_returns_422(self, client, db, admin_user, admin_token):
        from datetime import date
        today = date.today().isoformat()
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "ok", "accepted_until": today},
            headers=auth(admin_token))
        assert r.status_code == 422

    async def test_limit_zero_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?limit=0", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_limit_above_max_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?limit=501", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_breach_true_and_accepted_true_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?breach=true&accepted=true", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_accept_finding_blank_reason_returns_422(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "   "}, headers=auth(admin_token))
        assert r.status_code == 422
        detail = r.json()["detail"]
        errors = detail if isinstance(detail, list) else [detail]
        assert any("reason must not be blank" in str(e) for e in errors)

    async def test_accept_finding_trims_reason(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "  known risk  "}, headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["accepted_reason"] == "known risk"


@pytest.mark.asyncio
class TestListRepoScanResults:
    """GET /api/repo-scans/results — verify scan_breach / scan_breach_count fields."""

    async def _make_scan_result(self, db, admin_user, findings=None):
        """Create a RepoScan + completed RepoScanResult with optional findings."""
        from app.models import RepoScan, RepoScanResult, RepoScanStatus, ScanTrigger
        scan = RepoScan(
            name="rs-result-test", url="https://github.com/t/r", branch="main",
            min_notify_severity="medium", created_by_id=admin_user.id,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        from datetime import datetime, timezone
        result = RepoScanResult(
            repo_scan_id=scan.id,
            status=RepoScanStatus.success,
            triggered_by=ScanTrigger.manual,
            finding_count=len(findings or []),
            findings=findings or [],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(result)
        await db.commit()
        await db.refresh(result)
        return scan, result

    async def test_results_include_scan_breach_fields(self, client, db, admin_user, admin_token):
        """Response items must carry scan_breach and scan_breach_count."""
        scan, _ = await self._make_scan_result(db, admin_user)
        r = await client.get("/api/repo-scans/results", headers=auth(admin_token))
        assert r.status_code == 200
        item = next((x for x in r.json() if x["repo_scan_id"] == scan.id), None)
        assert item is not None
        assert "scan_breach" in item
        assert "scan_breach_count" in item
        assert "scan_name" in item
        assert "scan_url" in item

    async def test_no_findings_no_breach(self, client, db, admin_user, admin_token):
        scan, _ = await self._make_scan_result(db, admin_user, findings=[])
        r = await client.get("/api/repo-scans/results", headers=auth(admin_token))
        assert r.status_code == 200
        item = next(x for x in r.json() if x["repo_scan_id"] == scan.id)
        assert item["scan_breach"] is False
        assert item["scan_breach_count"] == 0

    async def test_breaching_finding_sets_breach_true(self, client, db, admin_user, admin_token):
        """A high-severity finding older than the default 14-day SLA must flip scan_breach."""
        from app.models import RepoScan, RepoScanResult, RepoScanStatus, ScanTrigger, FindingRecord
        from datetime import datetime, timedelta, timezone
        scan = RepoScan(
            name="breach-scan", url="https://github.com/t/breach", branch="main",
            min_notify_severity="medium", created_by_id=admin_user.id,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        now = datetime.now(timezone.utc)
        record = FindingRecord(
            repo_scan_id=scan.id,
            advisory_id="GHSA-breach", package="old-pkg", ecosystem="pypi",
            severity=AlertSeverity.high,
            first_found_at=now - timedelta(days=20),
            reopen_count=0,
        )
        db.add(record)
        result = RepoScanResult(
            repo_scan_id=scan.id,
            status=RepoScanStatus.success,
            triggered_by=ScanTrigger.manual,
            finding_count=1,
            started_at=now,
            completed_at=now,
        )
        db.add(result)
        await db.commit()

        r = await client.get("/api/repo-scans/results", headers=auth(admin_token))
        assert r.status_code == 200
        item = next(x for x in r.json() if x["repo_scan_id"] == scan.id)
        assert item["scan_breach"] is True
        assert item["scan_breach_count"] >= 1
