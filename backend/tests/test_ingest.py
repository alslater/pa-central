"""Tests for /api/ingest endpoints — agent self-registration and data upload."""
import pytest
from sqlalchemy import select

from app.models import Alert, Host, Scan


def api_key_header(raw: str) -> dict:
    return {"X-API-Key": raw}


@pytest.mark.asyncio
class TestHeartbeat:
    async def test_heartbeat_creates_host_on_first_call(self, client, api_key, db):
        raw, _ = api_key
        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "server-01",
            "daemon_status": "running",
            "pa_version": "1.2.3",
        }, headers=api_key_header(raw))
        assert r.status_code == 204

        result = await db.execute(select(Host).where(Host.hostname == "server-01"))
        host = result.scalar_one_or_none()
        assert host is not None
        assert host.pa_version == "1.2.3"
        assert host.daemon_status.value == "running"

    async def test_heartbeat_updates_existing_host(self, client, api_key, db):
        raw, _ = api_key
        await client.post("/api/ingest/heartbeat", json={
            "hostname": "server-02", "daemon_status": "running",
        }, headers=api_key_header(raw))
        await client.post("/api/ingest/heartbeat", json={
            "hostname": "server-02", "daemon_status": "stopped", "pa_version": "2.0.0",
        }, headers=api_key_header(raw))

        result = await db.execute(select(Host).where(Host.hostname == "server-02"))
        host = result.scalar_one_or_none()
        assert host.daemon_status.value == "stopped"
        assert host.pa_version == "2.0.0"

    async def test_same_hostname_via_different_keys_creates_separate_hosts(
        self, client, db, admin_user, operator_user
    ):
        from app.core.security import generate_api_key
        from app.models import ApiKey

        raw1, h1 = generate_api_key()
        key1 = ApiKey(name="k1", key_hash=h1, user_id=admin_user.id, is_active=True)
        raw2, h2 = generate_api_key()
        key2 = ApiKey(name="k2", key_hash=h2, user_id=operator_user.id, is_active=True)
        db.add(key1)
        db.add(key2)
        await db.commit()

        await client.post("/api/ingest/heartbeat", json={
            "hostname": "shared-name", "daemon_status": "running",
        }, headers=api_key_header(raw1))
        await client.post("/api/ingest/heartbeat", json={
            "hostname": "shared-name", "daemon_status": "running",
        }, headers=api_key_header(raw2))

        result = await db.execute(select(Host).where(Host.hostname == "shared-name"))
        hosts = result.scalars().all()
        assert len(hosts) == 2
        owner_ids = {h.owner_user_id for h in hosts}
        assert admin_user.id in owner_ids
        assert operator_user.id in owner_ids

    async def test_heartbeat_requires_valid_api_key(self, client):
        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "x", "daemon_status": "running",
        }, headers=api_key_header("invalid_key"))
        assert r.status_code == 401

    async def test_heartbeat_requires_api_key(self, client):
        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "x", "daemon_status": "running",
        })
        assert r.status_code == 401

    async def test_heartbeat_updates_last_seen_at(self, client, api_key, db):
        raw, _ = api_key
        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "ts-host", "daemon_status": "running",
        }, headers=api_key_header(raw))
        assert r.status_code == 204

        result = await db.execute(select(Host).where(Host.hostname == "ts-host"))
        host = result.scalar_one_or_none()
        assert host.last_seen_at is not None


@pytest.mark.asyncio
class TestIngestAlert:
    async def test_alert_is_saved_and_creates_host(self, client, api_key, db):
        raw, _ = api_key
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "alert-host",
            "package_name": "requests",
            "package_version": "2.28.0",
            "ecosystem": "pypi",
            "kind": "osv",
            "severity": "high",
            "advisory_id": "GHSA-1234-5678",
            "summary": "test vuln",
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        data = r.json()
        assert data["package_name"] == "requests"
        assert data["severity"] == "high"
        assert data["acknowledged"] is False

        result = await db.execute(select(Alert).where(Alert.advisory_id == "GHSA-1234-5678"))
        alert = result.scalar_one_or_none()
        assert alert is not None

    async def test_alert_requires_valid_api_key(self, client):
        r = await client.post("/api/ingest/alerts", json={
            "hostname": "x", "package_name": "pkg",
        }, headers=api_key_header("bad"))
        assert r.status_code == 401

    async def test_revoked_key_is_rejected(self, client, db, admin_user):
        from app.core.security import generate_api_key
        from app.models import ApiKey
        raw, hashed = generate_api_key()
        key = ApiKey(name="revoked", key_hash=hashed, user_id=admin_user.id, is_active=False)
        db.add(key)
        await db.commit()

        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "x", "daemon_status": "running",
        }, headers=api_key_header(raw))
        assert r.status_code == 401


@pytest.mark.asyncio
class TestIngestScan:
    async def test_scan_is_saved(self, client, api_key, db):
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "scan-host",
            "project_path": "/app/myproject",
            "scan_type": "project",
            "status": "findings",
            "finding_count": 3,
            "findings": [{"id": "GHSA-abc", "pkg": "foo"}],
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        data = r.json()
        assert data["finding_count"] == 3
        assert data["project_path"] == "/app/myproject"

        result = await db.execute(select(Scan).where(Scan.project_path == "/app/myproject"))
        scan = result.scalar_one_or_none()
        assert scan is not None
        assert scan.status.value == "findings"

    async def test_clean_scan_is_saved(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "clean-host",
            "project_path": "/app/clean",
            "scan_type": "project",
            "status": "clean",
            "finding_count": 0,
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        assert r.json()["status"] == "clean"

    async def test_scan_risks_are_saved(self, client, api_key, db):
        raw, _ = api_key
        risks = [{"kind": "maintainer_change", "package": "left-pad", "severity": "medium"}]
        r = await client.post("/api/ingest/scans", json={
            "hostname": "risk-host",
            "project_path": "/app/riskyproject",
            "scan_type": "project",
            "status": "findings",
            "finding_count": 0,
            "risks": risks,
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        data = r.json()
        assert data["risks"] == risks

        result = await db.execute(select(Scan).where(Scan.project_path == "/app/riskyproject"))
        scan = result.scalar_one_or_none()
        assert scan is not None
        assert scan.risks == risks

    async def test_scan_risk_failures_are_saved(self, client, api_key, db):
        """Host scans must carry risk_failures through like repo scans do —
        otherwise a scan with scoring failures is stored and displayed as
        zero-risk/clean, since extra Pydantic fields are silently dropped."""
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "risk-failure-host",
            "project_path": "/app/partialscan",
            "scan_type": "project",
            "status": "findings",
            "finding_count": 0,
            "risks": [],
            "risk_failures": 2,
        }, headers=api_key_header(raw))
        assert r.status_code == 201
        data = r.json()
        assert data["risk_failures"] == 2

        result = await db.execute(select(Scan).where(Scan.project_path == "/app/partialscan"))
        scan = result.scalar_one_or_none()
        assert scan is not None
        assert scan.risk_failures == 2

    async def test_scan_negative_risk_failures_is_rejected(self, client, api_key):
        raw, _ = api_key
        r = await client.post("/api/ingest/scans", json={
            "hostname": "bad-risk-failure-host",
            "project_path": "/app/badscan",
            "scan_type": "project",
            "status": "findings",
            "finding_count": 0,
            "risk_failures": -1,
        }, headers=api_key_header(raw))
        assert r.status_code == 422


@pytest.mark.asyncio
class TestIngestConfig:
    async def test_returns_204_when_no_config_assigned(self, client, api_key):
        raw, _ = api_key
        r = await client.get(
            "/api/ingest/config",
            params={"hostname": "cfg-host"},
            headers=api_key_header(raw),
        )
        assert r.status_code == 204

    async def test_returns_toml_when_config_assigned(self, client, api_key, db, admin_user):
        from app.models import ConfigAssignment, ConfigTemplate, Host

        raw, _key_obj = api_key

        # First register the host via heartbeat
        await client.post("/api/ingest/heartbeat", json={
            "hostname": "cfg-host-2", "daemon_status": "running",
        }, headers=api_key_header(raw))

        result = await db.execute(select(Host).where(Host.hostname == "cfg-host-2"))
        host = result.scalar_one()

        toml = "[package_alert]\nfleet = true\n"
        tmpl = ConfigTemplate(name="fleet-cfg", toml_content=toml, created_by_id=admin_user.id)
        db.add(tmpl)
        await db.flush()
        assignment = ConfigAssignment(host_id=host.id, template_id=tmpl.id, assigned_by_id=admin_user.id)
        db.add(assignment)
        await db.commit()

        r = await client.get(
            "/api/ingest/config",
            params={"hostname": "cfg-host-2"},
            headers=api_key_header(raw),
        )
        assert r.status_code == 200
        assert "fleet = true" in r.text


@pytest.mark.asyncio
class TestDefaultConfigAutoAssign:
    async def test_new_host_gets_default_config(self, client, api_key, admin_user, db):
        from sqlalchemy import select

        from app.models import ConfigAssignment, ConfigTemplate, Host

        tmpl = ConfigTemplate(
            name="auto-default",
            toml_content="[osv]\ncache_ttl_hours=24",
            created_by_id=admin_user.id,
            is_default=True,
        )
        db.add(tmpl)
        await db.commit()
        await db.refresh(tmpl)

        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "auto-test-host",
            "daemon_status": "running",
        }, headers={"X-API-Key": api_key[0]})
        assert r.status_code == 204

        host = (await db.execute(
            select(Host).where(Host.hostname == "auto-test-host")
        )).scalar_one()
        assignment = (await db.execute(
            select(ConfigAssignment).where(ConfigAssignment.host_id == host.id)
        )).scalar_one_or_none()
        assert assignment is not None
        assert assignment.template_id == tmpl.id

    async def test_new_host_without_default_gets_no_assignment(self, client, api_key, db):
        from sqlalchemy import select

        from app.models import ConfigAssignment, Host

        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "no-default-host",
            "daemon_status": "running",
        }, headers={"X-API-Key": api_key[0]})
        assert r.status_code == 204

        host = (await db.execute(
            select(Host).where(Host.hostname == "no-default-host")
        )).scalar_one()
        assignment = (await db.execute(
            select(ConfigAssignment).where(ConfigAssignment.host_id == host.id)
        )).scalar_one_or_none()
        assert assignment is None

    async def test_existing_host_reconnect_does_not_duplicate_assignment(self, client, api_key, admin_user, db):
        from sqlalchemy import func, select

        from app.models import ConfigAssignment, ConfigTemplate, Host

        tmpl = ConfigTemplate(
            name="auto-default-2",
            toml_content="[osv]",
            created_by_id=admin_user.id,
            is_default=True,
        )
        db.add(tmpl)
        await db.commit()

        await client.post("/api/ingest/heartbeat", json={
            "hostname": "reconnect-host",
            "daemon_status": "running",
        }, headers={"X-API-Key": api_key[0]})

        await client.post("/api/ingest/heartbeat", json={
            "hostname": "reconnect-host",
            "daemon_status": "running",
        }, headers={"X-API-Key": api_key[0]})

        host = (await db.execute(
            select(Host).where(Host.hostname == "reconnect-host")
        )).scalar_one()
        count = (await db.execute(
            select(func.count()).select_from(ConfigAssignment)
            .where(ConfigAssignment.host_id == host.id)
        )).scalar()
        assert count == 1
