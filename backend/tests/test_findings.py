"""Tests for finding_records model, lifecycle service, and findings API."""
from datetime import UTC, date, datetime, timedelta
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
    defaults = {
        "id": 1, "repo_scan_id": 1,
        "advisory_id": "GHSA-x", "package": "requests", "ecosystem": "pypi",
        "severity": AlertSeverity.high,
        "first_found_at": datetime(2026, 1, 1, tzinfo=UTC),
        "closed_at": None, "reopen_count": 0,
        "accepted_by_id": None, "accepted_at": None,
        "accepted_reason": None, "accepted_until": None,
        "sla_breach_cutoff_at": None,
    }
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
        r = _make_record(accepted_at=datetime(2026, 1, 1, tzinfo=UTC), accepted_reason="ok")
        assert is_accepted(r) is True

    def test_accepted_future_expiry(self):
        r = _make_record(
            accepted_at=datetime(2026, 1, 1, tzinfo=UTC),
            accepted_reason="ok",
            accepted_until=date(2099, 12, 31),
        )
        assert is_accepted(r) is True

    def test_accepted_past_expiry(self):
        r = _make_record(
            accepted_at=datetime(2026, 1, 1, tzinfo=UTC),
            accepted_reason="ok",
            accepted_until=date(2020, 1, 1),
        )
        assert is_accepted(r) is False

    def test_accepted_today_expiry_is_lapsed(self):
        today = datetime.now(UTC).date()
        r = _make_record(
            accepted_at=datetime(2026, 1, 1, tzinfo=UTC),
            accepted_reason="ok",
            accepted_until=today,
        )
        assert is_accepted(r) is False


def _cutoff(first_found_at: datetime, sla_days: int) -> datetime:
    """Compute sla_breach_cutoff_at as returned by UtcDateTime on read: aware UTC."""
    return (first_found_at + timedelta(days=sla_days + 1)).astimezone(UTC)


class TestInBreach:
    def _now(self):
        return datetime(2026, 6, 22, tzinfo=UTC)

    def test_null_cutoff_never_in_breach(self):
        # NULL sla_breach_cutoff_at (no SLA or pre-migration row) → not in breach
        r = _make_record(first_found_at=datetime(2020, 1, 1, tzinfo=UTC), sla_breach_cutoff_at=None)
        assert in_breach(r, self._now()) is False

    def test_closed_never_in_breach(self):
        first = datetime(2026, 1, 1, tzinfo=UTC)
        r = _make_record(
            first_found_at=first,
            closed_at=datetime(2026, 6, 1, tzinfo=UTC),
            sla_breach_cutoff_at=_cutoff(first, 14),
        )
        assert in_breach(r, self._now()) is False

    def test_accepted_never_in_breach(self):
        first = datetime(2026, 1, 1, tzinfo=UTC)
        r = _make_record(
            first_found_at=first,
            accepted_at=datetime(2026, 1, 2, tzinfo=UTC),
            accepted_reason="risk accepted",
            sla_breach_cutoff_at=_cutoff(first, 14),
        )
        assert in_breach(r, self._now()) is False

    def test_within_sla_not_in_breach(self):
        first = self._now() - timedelta(days=10)
        r = _make_record(first_found_at=first, sla_breach_cutoff_at=_cutoff(first, 14))
        assert in_breach(r, self._now()) is False

    def test_exactly_at_sla_not_in_breach(self):
        # (now - first).days == 14 → cutoff = first + 15d = now + 1d → not in breach
        first = self._now() - timedelta(days=14)
        r = _make_record(first_found_at=first, sla_breach_cutoff_at=_cutoff(first, 14))
        assert in_breach(r, self._now()) is False

    def test_past_sla_in_breach(self):
        # (now - first).days == 15 → cutoff = first + 15d = now → cutoff <= now → in breach
        first = self._now() - timedelta(days=15)
        r = _make_record(first_found_at=first, sla_breach_cutoff_at=_cutoff(first, 14))
        assert in_breach(r, self._now()) is True

    def test_lapsed_acceptance_in_breach(self):
        first = self._now() - timedelta(days=30)
        r = _make_record(
            first_found_at=first,
            accepted_at=datetime(2026, 1, 1, tzinfo=UTC),
            accepted_reason="ok",
            accepted_until=date(2026, 1, 2),  # lapsed
            sla_breach_cutoff_at=_cutoff(first, 14),
        )
        assert in_breach(r, self._now()) is True


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
        import pydantic

        from app.schemas import FindingAcceptBody
        with pytest.raises(pydantic.ValidationError):
            FindingAcceptBody()

    def test_finding_settings_has_three_fields(self):
        from app.schemas import FindingSettingsPut
        s = FindingSettingsPut(sla_high_days=14, sla_medium_days=90, finding_retention_days=365)
        assert s.sla_high_days == 14


async def _make_scan_and_finding(db, admin_user, days_old=20, severity="high",
                                 closed=False, accepted=False, accepted_until=None,
                                 scan_name="test", no_cutoff=False):
    """Helper: create a RepoScan + open FindingRecord, return (scan, record)."""
    from datetime import datetime, timedelta

    from app.models import AlertSeverity, FindingRecord, RepoScan
    scan = RepoScan(
        name=scan_name, url="https://github.com/t/r", branch="main",
        min_notify_severity="medium", created_by_id=admin_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    from app.services.finding_lifecycle import (
        DEFAULT_SLA_HIGH,
        DEFAULT_SLA_MEDIUM,
        _compute_breach_cutoff,
    )
    now = datetime.now(UTC)
    sev = AlertSeverity(severity)
    first_found = now - timedelta(days=days_old)
    record = FindingRecord(
        repo_scan_id=scan.id,
        advisory_id="GHSA-z", package="flask", ecosystem="pypi",
        severity=sev,
        first_found_at=first_found,
        closed_at=now if closed else None,
        reopen_count=0,
        accepted_by_id=admin_user.id if accepted else None,
        accepted_at=now if accepted else None,
        accepted_reason="ok" if accepted else None,
        accepted_until=accepted_until,
        sla_breach_cutoff_at=None if no_cutoff else _compute_breach_cutoff(sev, DEFAULT_SLA_HIGH, DEFAULT_SLA_MEDIUM, first_found),
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
        data = r.json()
        assert "items" in data and "total" in data
        ids = [f["id"] for f in data["items"]]
        assert open_rec.id in ids
        assert closed_rec.id not in ids

    async def test_list_findings_returns_pagination_envelope(self, client, db, admin_user, admin_token):
        r = await client.get("/api/findings", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert set(data.keys()) >= {"items", "total", "page", "page_size"}
        assert isinstance(data["items"], list)
        assert isinstance(data["total"], int)

    async def test_list_findings_breach_filter(self, client, db, admin_user, admin_token):
        _, breaching = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        _, clean = await _make_scan_and_finding(db, admin_user, days_old=5, severity="high")
        r = await client.get("/api/findings?breach=true", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert breaching.id in ids
        assert clean.id not in ids

    async def test_breach_filter_includes_stricter_per_scan_sla(self, client, db, admin_user, admin_token):
        """breach=true must not drop findings that breach a stricter per-scan SLA.

        Global default: high=14d. Scan A override: sla_high_days=7.
        Finding age: 10d — safe under the global default but breaching the
        per-scan override. The aggregate cutoff must use min(7, 14)=7, not 14.
        """
        from datetime import datetime
        from datetime import timedelta as td

        from app.models import AlertSeverity, FindingRecord, RepoScan
        scan = RepoScan(
            name="strict", url="https://g.com/s.git", branch="main",
            min_notify_severity="medium", created_by_id=admin_user.id,
            sla_high_days=7,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        now = datetime.now(UTC)
        # sla_breach_cutoff_at uses the per-scan override (7d) so breach SQL filter can evaluate it.
        first_found = now - td(days=10)
        record = FindingRecord(
            repo_scan_id=scan.id,
            advisory_id="GHSA-strict", package="pkg", ecosystem="pypi",
            severity=AlertSeverity.high,
            first_found_at=first_found,
            reopen_count=0,
            sla_breach_cutoff_at=first_found + td(days=7),
        )
        db.add(record)
        await db.commit()
        r = await client.get("/api/findings?breach=true", headers=auth(admin_token))
        assert r.status_code == 200
        assert any(f["id"] == record.id for f in r.json()["items"])

    async def test_list_findings_severity_filter(self, client, db, admin_user, admin_token):
        _, high_rec = await _make_scan_and_finding(db, admin_user, severity="high")
        _, med_rec = await _make_scan_and_finding(db, admin_user, severity="medium")
        r = await client.get("/api/findings?severity=high", headers=auth(admin_token))
        ids = [f["id"] for f in r.json()["items"]]
        assert high_rec.id in ids
        assert med_rec.id not in ids

    async def test_list_findings_accepted_filter(self, client, db, admin_user, admin_token):
        _, accepted_rec = await _make_scan_and_finding(db, admin_user, accepted=True)
        _, open_rec = await _make_scan_and_finding(db, admin_user, accepted=False)
        r = await client.get("/api/findings?accepted=true", headers=auth(admin_token))
        ids = [f["id"] for f in r.json()["items"]]
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
        from datetime import timedelta
        yesterday = datetime.now(UTC).date() - timedelta(days=1)
        _, record = await _make_scan_and_finding(db, admin_user, accepted=True, accepted_until=yesterday)
        r = await client.get("/api/findings", headers=auth(admin_token))
        finding = next(f for f in r.json()["items"] if f["id"] == record.id)
        assert finding["is_accepted"] is False

    async def test_accepted_false_excludes_accepted_findings(self, client, db, admin_user, admin_token):
        _, accepted_rec = await _make_scan_and_finding(db, admin_user, accepted=True)
        _, open_rec = await _make_scan_and_finding(db, admin_user, accepted=False)
        r = await client.get("/api/findings?accepted=false", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert open_rec.id in ids
        assert accepted_rec.id not in ids

    async def test_breach_false_excludes_breaching_findings(self, client, db, admin_user, admin_token):
        _, breaching = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        _, clean = await _make_scan_and_finding(db, admin_user, days_old=5, severity="high")
        r = await client.get("/api/findings?breach=false", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert clean.id in ids
        assert breaching.id not in ids

    async def test_breach_true_with_repo_scan_id(self, client, db, admin_user, admin_token):
        """breach=true scoped to a single scan only returns breaching findings for that scan."""
        scan_a, breaching = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        _, other = await _make_scan_and_finding(db, admin_user, days_old=20, severity="high")
        r = await client.get(f"/api/findings?breach=true&repo_scan_id={scan_a.id}", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert breaching.id in ids
        assert other.id not in ids

    async def test_accepted_false_with_repo_scan_id(self, client, db, admin_user, admin_token):
        """accepted=false scoped to a scan excludes accepted findings from that scan."""
        scan, accepted_rec = await _make_scan_and_finding(db, admin_user, accepted=True)
        r = await client.get(f"/api/findings?accepted=false&repo_scan_id={scan.id}", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert accepted_rec.id not in ids

    async def test_accept_with_past_accepted_until_returns_422(self, client, db, admin_user, admin_token):
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "ok", "accepted_until": "2020-01-01"},
            headers=auth(admin_token))
        assert r.status_code == 422

    async def test_accept_with_today_accepted_until_returns_422(self, client, db, admin_user, admin_token):
        today = datetime.now(UTC).date().isoformat()
        _, record = await _make_scan_and_finding(db, admin_user)
        r = await client.post(f"/api/findings/{record.id}/accept",
            json={"reason": "ok", "accepted_until": today},
            headers=auth(admin_token))
        assert r.status_code == 422

    async def test_page_size_zero_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?page_size=0", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_page_size_above_max_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?page_size=201", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_invalid_sort_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?sort=unknown", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_invalid_sort_dir_returns_422(self, client, admin_token):
        r = await client.get("/api/findings?sort_dir=sideways", headers=auth(admin_token))
        assert r.status_code == 422

    async def test_pagination_page_and_total(self, client, db, admin_user, admin_token):
        """page=0 and page=1 with page_size=1 should return different findings; total reflects all."""
        _, _rec1 = await _make_scan_and_finding(db, admin_user, days_old=5, severity="medium")
        _, _rec2 = await _make_scan_and_finding(db, admin_user, days_old=10, severity="medium")
        r = await client.get("/api/findings?page_size=1&page=0", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["total"] >= 2
        assert len(data["items"]) == 1
        r2 = await client.get("/api/findings?page_size=1&page=1", headers=auth(admin_token))
        assert r2.status_code == 200
        data2 = r2.json()
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] != data["items"][0]["id"]

    async def test_sort_severity_orders_critical_before_high(self, client, db, admin_user, admin_token):
        _, _high_rec = await _make_scan_and_finding(db, admin_user, severity="high", days_old=5)
        _, _crit_rec = await _make_scan_and_finding(db, admin_user, severity="critical", days_old=5)
        r = await client.get("/api/findings?sort=severity&sort_dir=asc", headers=auth(admin_token))
        assert r.status_code == 200
        items = r.json()["items"]
        sevs = [f["severity"] for f in items]
        assert sevs.index("critical") < sevs.index("high")

    async def test_sort_severity_desc_orders_low_before_critical(self, client, db, admin_user, admin_token):
        _, _low_rec = await _make_scan_and_finding(db, admin_user, severity="low", days_old=5)
        _, _crit_rec = await _make_scan_and_finding(db, admin_user, severity="critical", days_old=5)
        r = await client.get("/api/findings?sort=severity&sort_dir=desc", headers=auth(admin_token))
        assert r.status_code == 200
        items = r.json()["items"]
        sevs = [f["severity"] for f in items]
        assert sevs.index("low") < sevs.index("critical")

    async def test_sort_days_open_asc_orders_newer_before_older(self, client, db, admin_user, admin_token):
        # days_open asc → fewest days first → newer finding (days_old=2) before older (days_old=30)
        _, newer = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=2)
        _, older = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=30)
        r = await client.get("/api/findings?sort=days_open&sort_dir=asc", headers=auth(admin_token))
        assert r.status_code == 200
        items = r.json()["items"]
        ids = [f["id"] for f in items]
        assert ids.index(newer.id) < ids.index(older.id)

    async def test_sort_days_open_desc_orders_older_before_newer(self, client, db, admin_user, admin_token):
        # days_open desc → most days first → older finding (days_old=30) before newer (days_old=2)
        _, newer = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=2)
        _, older = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=30)
        r = await client.get("/api/findings?sort=days_open&sort_dir=desc", headers=auth(admin_token))
        assert r.status_code == 200
        items = r.json()["items"]
        ids = [f["id"] for f in items]
        assert ids.index(older.id) < ids.index(newer.id)

    async def test_sort_repo_asc_orders_alphabetically(self, client, db, admin_user, admin_token):
        _, rec_b = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=5, scan_name="repo-b")
        _, rec_a = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=5, scan_name="repo-a")
        r = await client.get("/api/findings?sort=repo&sort_dir=asc", headers=auth(admin_token))
        assert r.status_code == 200
        items = r.json()["items"]
        ids = [f["id"] for f in items]
        assert ids.index(rec_a.id) < ids.index(rec_b.id)

    async def test_sort_repo_tiebreak_by_id(self, client, db, admin_user, admin_token):
        # Two findings on the same repo: lower id must come first (secondary tiebreaker).
        _, rec1 = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=5, scan_name="same-repo")
        _, rec2 = await _make_scan_and_finding(db, admin_user, severity="medium", days_old=5, scan_name="same-repo")
        r = await client.get("/api/findings?sort=repo&sort_dir=asc", headers=auth(admin_token))
        assert r.status_code == 200
        items = r.json()["items"]
        ids = [f["id"] for f in items]
        assert ids.index(rec1.id) < ids.index(rec2.id)

    async def test_breach_boundary_sql_matches_python(self, client, db, admin_user, admin_token):
        """SQL breach filter and Python in_breach() must agree at the SLA boundary.

        A finding at exactly sla_days elapsed is NOT yet in breach (integer-day
        truncation: .days == sla_days, not > sla_days). One at sla_days+1 is.
        Both the breach=true filter and the in_breach field in the response must
        reflect the same threshold.
        """
        from datetime import datetime, timedelta

        from app.models import AlertSeverity, FindingRecord, RepoScan
        from app.services.finding_lifecycle import (
            DEFAULT_SLA_HIGH,
            _compute_breach_cutoff,
        )

        now = datetime.now(UTC)
        sla = DEFAULT_SLA_HIGH  # 14 days for "high"

        scan = RepoScan(name="boundary-test", url="https://github.com/t/r", branch="main",
                        min_notify_severity="medium", created_by_id=admin_user.id)
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        sev = AlertSeverity.high

        # Exactly sla_days elapsed — NOT in breach (.days == sla, not > sla)
        at_boundary = now - timedelta(days=sla)
        rec_boundary = FindingRecord(
            repo_scan_id=scan.id, advisory_id="GHSA-boundary", package="pkg-a",
            ecosystem="pypi", severity=sev, first_found_at=at_boundary,
            reopen_count=0,
            sla_breach_cutoff_at=_compute_breach_cutoff(sev, sla, 90, at_boundary),
        )
        # One day past sla_days — IS in breach
        past_boundary = now - timedelta(days=sla + 1)
        rec_past = FindingRecord(
            repo_scan_id=scan.id, advisory_id="GHSA-past", package="pkg-b",
            ecosystem="pypi", severity=sev, first_found_at=past_boundary,
            reopen_count=0,
            sla_breach_cutoff_at=_compute_breach_cutoff(sev, sla, 90, past_boundary),
        )
        db.add(rec_boundary)
        db.add(rec_past)
        await db.commit()
        await db.refresh(rec_boundary)
        await db.refresh(rec_past)

        r = await client.get("/api/findings?breach=true", headers=auth(admin_token))
        assert r.status_code == 200
        breach_ids = {f["id"] for f in r.json()["items"]}
        assert rec_boundary.id not in breach_ids, "finding at exactly sla_days should not be in breach"
        assert rec_past.id in breach_ids, "finding at sla_days+1 should be in breach"

        # Verify in_breach field on each item matches the filter
        r_all = await client.get("/api/findings", headers=auth(admin_token))
        all_items = {f["id"]: f for f in r_all.json()["items"]}
        if rec_boundary.id in all_items:
            assert all_items[rec_boundary.id]["in_breach"] is False
        if rec_past.id in all_items:
            assert all_items[rec_past.id]["in_breach"] is True

    async def test_null_cutoff_excluded_from_breach_true(self, client, db, admin_user, admin_token):
        """Pre-migration findings (sla_breach_cutoff_at=NULL) must not appear in breach=true results."""
        _, rec = await _make_scan_and_finding(db, admin_user, severity="high", days_old=30, no_cutoff=True)
        r = await client.get("/api/findings?breach=true", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert rec.id not in ids

    async def test_null_cutoff_included_in_breach_false(self, client, db, admin_user, admin_token):
        """Pre-migration findings (sla_breach_cutoff_at=NULL) must appear in breach=false results."""
        _, rec = await _make_scan_and_finding(db, admin_user, severity="high", days_old=30, no_cutoff=True)
        r = await client.get("/api/findings?breach=false", headers=auth(admin_token))
        assert r.status_code == 200
        ids = [f["id"] for f in r.json()["items"]]
        assert rec.id in ids

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

        from datetime import datetime
        result = RepoScanResult(
            repo_scan_id=scan.id,
            status=RepoScanStatus.success,
            triggered_by=ScanTrigger.manual,
            finding_count=len(findings or []),
            findings=findings or [],
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
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
        from datetime import datetime, timedelta

        from app.models import (
            FindingRecord,
            RepoScan,
            RepoScanResult,
            RepoScanStatus,
            ScanTrigger,
        )
        scan = RepoScan(
            name="breach-scan", url="https://github.com/t/breach", branch="main",
            min_notify_severity="medium", created_by_id=admin_user.id,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        now = datetime.now(UTC)
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
