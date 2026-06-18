"""
Tests verifying that pa-central's ingest schema correctly accepts the exact
data formats produced by package-alert.
"""
import pytest


def api_key_header(raw: str) -> dict:
    return {"X-API-Key": raw}


@pytest.mark.asyncio
class TestSeverityNormalisation:
    """package-alert emits OSV severity in uppercase; we must accept it."""

    async def test_uppercase_critical_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1",
            "package_name": "requests",
            "severity": "CRITICAL",
            "kind": "osv",
        }, headers=api_key_header(raw))
        assert r.status_code == 201, r.text
        assert r.json()["severity"] == "critical"

    async def test_uppercase_high_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1", "package_name": "pkg", "severity": "HIGH", "kind": "osv",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["severity"] == "high"

    async def test_uppercase_medium_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1", "package_name": "pkg", "severity": "MEDIUM", "kind": "osv",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["severity"] == "medium"

    async def test_uppercase_low_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1", "package_name": "pkg", "severity": "LOW", "kind": "osv",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["severity"] == "low"

    async def test_heuristic_warning_level_accepted(self, client, api_key):
        """package-alert heuristic engine uses 'warning' as an intermediate level."""
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1", "package_name": "pkg",
            "severity": "warning", "kind": "heuristic",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["severity"] == "warning"

    async def test_lowercase_severity_still_works(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1", "package_name": "pkg", "severity": "high", "kind": "osv",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["severity"] == "high"


@pytest.mark.asyncio
class TestHeuristicAlertFields:
    """Heuristic alerts carry risk_score and signals, not advisory_id."""

    async def test_risk_score_and_signals_stored(self, client, api_key):
        raw, _ = api_key
        signals = [
            {"name": "typosquat", "score": 45, "reason": "Similar to 'requests'"},
            {"name": "low_popularity", "score": 30, "reason": "Few dependents"},
        ]
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1",
            "package_name": "requsts",
            "severity": "warning",
            "kind": "heuristic",
            "risk_score": 75,
            "signals": signals,
        }, headers=api_key_header(raw))
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["risk_score"] == 75
        assert len(data["signals"]) == 2
        assert data["signals"][0]["name"] == "typosquat"

    async def test_osv_alert_without_risk_score(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "host-1",
            "package_name": "requests",
            "severity": "HIGH",
            "kind": "osv",
            "advisory_id": "GHSA-1234-5678-abcd",
            "summary": "Remote code execution in requests",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        data = r.json()
        assert data["advisory_id"] == "GHSA-1234-5678-abcd"
        assert data["risk_score"] is None
        assert data["signals"] is None


@pytest.mark.asyncio
class TestScanRootAlias:
    """package-alert's scan JSON uses 'root' instead of 'project_path'."""

    async def test_root_field_accepted_as_project_path(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "scan-host",
            "root": "/home/user/myproject",
            "scan_type": "project",
            "status": "findings",
            "finding_count": 2,
            "findings": [{"package": "requests", "advisory_id": "GHSA-x"}],
        }, headers=api_key_header(raw))
        assert r.status_code == 201, r.text
        assert r.json()["project_path"] == "/home/user/myproject"

    async def test_project_path_field_still_works(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "scan-host",
            "project_path": "/home/user/other",
            "scan_type": "project",
            "status": "clean",
            "finding_count": 0,
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["project_path"] == "/home/user/other"

    async def test_unpinned_field_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "scan-host",
            "root": "/app",
            "scan_type": "project",
            "status": "clean",
            "finding_count": 0,
            "unpinned": [{"name": "flask", "ecosystem": "pypi"}],
        }, headers=api_key_header(raw))
        assert r.status_code == 201


@pytest.mark.asyncio
class TestAlertKindValidation:
    """Only 'osv' and 'heuristic' are valid kinds (cooldown removed)."""

    async def test_osv_kind_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "h", "package_name": "pkg", "kind": "osv",
        }, headers=api_key_header(raw))
        assert r.status_code == 201

    async def test_heuristic_kind_accepted(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "h", "package_name": "pkg", "kind": "heuristic",
        }, headers=api_key_header(raw))
        assert r.status_code == 201

    async def test_cooldown_kind_rejected(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "h", "package_name": "pkg", "kind": "cooldown",
        }, headers=api_key_header(raw))
        assert r.status_code == 422
