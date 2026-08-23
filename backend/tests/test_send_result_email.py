"""Integration tests for _send_result_email's recipient resolution.

_send_result_email opens its own DB engine (see the comment in
test_ingest_repo_scan.py), so it can't share the SAVEPOINT-based `db`
fixture used elsewhere. These tests point it at a real throwaway SQLite
file instead and capture what EmailService.send is called with.
"""
import os
import tempfile

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings as app_settings
from app.core.database import Base
from app.core.security import hash_password
from app.models import (
    AlertSeverity,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    SettingValueType,
    SystemSetting,
    User,
    UserRole,
)


@pytest.fixture
async def temp_db_url(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)  # let create_all start from a clean file
    monkeypatch.setattr(app_settings, "database_type", "sqlite")
    monkeypatch.setattr(app_settings, "database_name", path)

    from app.core.db_config import async_url

    url = async_url()
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()

    yield url

    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
async def seeded_scan(temp_db_url):
    """Create an admin (undeliverable address) + a scan with valid notify_recipients."""
    engine = create_async_engine(temp_db_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        admin = User(
            email="admin@localhost",
            display_name="Bootstrap Admin",
            hashed_password=hash_password("x"),
            role=UserRole.admin,
            is_active=True,
        )
        session.add(admin)
        await session.flush()

        session.add(SystemSetting(key="smtp_host", value="localhost", value_type=SettingValueType.string))
        session.add(SystemSetting(key="smtp_port", value="9025", value_type=SettingValueType.string))

        scan = RepoScan(
            name="test-repo",
            url="https://github.com/test/repo",
            branch="main",
            min_notify_severity=AlertSeverity.medium,
            notify_recipients=["team@example.com"],
            created_by_id=admin.id,
        )
        session.add(scan)
        await session.flush()

        result = RepoScanResult(
            repo_scan_id=scan.id,
            status=RepoScanStatus.success,
            finding_count=1,
            findings=[{
                "package": "requests", "severity": "high",
                "advisory_id": "GHSA-x", "summary": "vuln",
            }],
        )
        session.add(result)
        await session.commit()
        result_id = result.id

    await engine.dispose()
    return result_id


async def test_valid_notify_recipients_still_emailed_when_all_admins_undeliverable(
    seeded_scan, monkeypatch
):
    """Regression: a scan with a valid notify_recipients address must still get
    an email even though the only admin (admin@localhost) is filtered out as
    undeliverable — the recipient merge must happen before any early return."""
    from app.api.ingest import _send_result_email
    from app.core.email import EmailService

    captured = []

    async def fake_send(self, msg, recipients):
        captured.append(recipients)

    monkeypatch.setattr(EmailService, "send", fake_send)

    await _send_result_email(seeded_scan)

    assert len(captured) == 1
    assert captured[0] == ["team@example.com"]


async def test_no_email_sent_when_every_recipient_is_undeliverable(temp_db_url, monkeypatch):
    engine = create_async_engine(temp_db_url)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        admin = User(
            email="admin@localhost",
            display_name="Bootstrap Admin",
            hashed_password=hash_password("x"),
            role=UserRole.admin,
            is_active=True,
        )
        session.add(admin)
        await session.flush()

        session.add(SystemSetting(key="smtp_host", value="localhost", value_type=SettingValueType.string))
        session.add(SystemSetting(key="smtp_port", value="9025", value_type=SettingValueType.string))

        scan = RepoScan(
            name="test-repo", url="https://github.com/test/repo", branch="main",
            min_notify_severity=AlertSeverity.medium,
            created_by_id=admin.id,
        )
        session.add(scan)
        await session.flush()

        result = RepoScanResult(
            repo_scan_id=scan.id,
            status=RepoScanStatus.success,
            finding_count=1,
            findings=[{
                "package": "requests", "severity": "high",
                "advisory_id": "GHSA-x", "summary": "vuln",
            }],
        )
        session.add(result)
        await session.commit()
        result_id = result.id

    await engine.dispose()

    from app.api.ingest import _send_result_email
    from app.core.email import EmailService

    captured = []

    async def fake_send(self, msg, recipients):
        captured.append(recipients)

    monkeypatch.setattr(EmailService, "send", fake_send)

    await _send_result_email(result_id)  # must not raise

    assert captured == []

    engine2 = create_async_engine(temp_db_url)
    factory2 = async_sessionmaker(engine2, class_=AsyncSession, expire_on_commit=False)
    async with factory2() as session:
        r = (await session.execute(select(RepoScanResult).where(RepoScanResult.id == result_id))).scalar_one()
        assert r.notified is False
    await engine2.dispose()
