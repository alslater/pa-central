"""Tests for /api/scans endpoints."""
import pytest

from app.models import Scan, ScanStatus
from tests.conftest import auth


async def _seed_scan(db, host, **kwargs):
    defaults = {
        "host_id": host.id,
        "project_path": "/app/project",
        "scan_type": "project",
        "status": ScanStatus.clean,
        "finding_count": 0,
    }
    defaults.update(kwargs)
    scan = Scan(**defaults)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@pytest.mark.asyncio
class TestListScans:
    async def test_returns_empty_list(self, client, admin_token):
        r = await client.get("/api/scans", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_returns_scans(self, client, admin_token, host, db):
        await _seed_scan(db, host)
        r = await client.get("/api/scans", headers=auth(admin_token))
        assert len(r.json()) == 1

    async def test_filter_by_host_id(self, client, admin_token, host, db):
        await _seed_scan(db, host)
        r = await client.get(f"/api/scans?host_id={host.id}", headers=auth(admin_token))
        assert len(r.json()) == 1
        r2 = await client.get("/api/scans?host_id=999999", headers=auth(admin_token))
        assert r2.json() == []

    async def test_requires_auth(self, client):
        r = await client.get("/api/scans")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestGetScan:
    async def test_returns_scan_by_id(self, client, admin_token, host, db):
        scan = await _seed_scan(db, host, finding_count=2, status=ScanStatus.findings)
        r = await client.get(f"/api/scans/{scan.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["finding_count"] == 2

    async def test_returns_404_for_unknown(self, client, admin_token):
        r = await client.get("/api/scans/999999", headers=auth(admin_token))
        assert r.status_code == 404
