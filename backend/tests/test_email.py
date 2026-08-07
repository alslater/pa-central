"""Tests for email notification service."""
import socket

import pytest

from app.core.email import (
    EmailService,
    SmtpConfig,
    build_failure_email,
    build_findings_email,
    filter_findings_by_severity,
)
from app.models import AlertSeverity


def _valkey_available() -> bool:
    try:
        with socket.create_connection(("localhost", 6379), timeout=1):
            return True
    except OSError:
        return False


valkey_required = pytest.mark.skipif(
    not _valkey_available(),
    reason="Redis/Valkey not available on localhost:6379",
)


# ── SMTP config helper ────────────────────────────────────────────────────────

def smtp_cfg(host="localhost", port=9025, tls_mode="none"):
    return SmtpConfig(
        host=host, port=port, username=None, password=None,
        from_addr="fleet@example.com", tls_mode=tls_mode
    )


# ── Unit: email builders ──────────────────────────────────────────────────────

def test_build_findings_email_subject():
    msg = build_findings_email(
        repo_name="my-repo", branch="main", pa_version="1.2.3",
        findings=[{"package": "requests", "severity": "high", "advisory_id": "GHSA-x", "summary": "RCE"}],
        min_severity=AlertSeverity.medium,
        recipients=["admin@example.com"],
        from_addr="fleet@example.com",
    )
    assert "my-repo" in msg["Subject"]
    assert "1" in msg["Subject"]


def test_build_failure_email_subject():
    msg = build_failure_email(
        repo_name="bad-repo", repo_url="https://github.com/x/y",
        branch="main", pa_version="1.2.3",
        error_message="git clone failed: auth",
        ecs_task_arn="arn:aws:ecs:task/abc",
        recipients=["admin@example.com"],
        from_addr="fleet@example.com",
    )
    assert "bad-repo" in msg["Subject"]
    assert "failed" in msg["Subject"].lower()


def test_filter_findings_by_severity():
    findings = [
        {"severity": "critical"}, {"severity": "high"}, {"severity": "medium"},
        {"severity": "low"}, {"severity": "info"},
    ]
    result = filter_findings_by_severity(findings, AlertSeverity.high)
    assert len(result) == 2
    assert all(f["severity"] in ("critical", "high") for f in result)


def test_filter_findings_warning_included_above_low():
    findings = [{"severity": "warning"}, {"severity": "low"}]
    result = filter_findings_by_severity(findings, AlertSeverity.warning)
    assert len(result) == 1
    assert result[0]["severity"] == "warning"


def test_findings_email_body_contains_package_names():
    msg = build_findings_email(
        repo_name="repo", branch="main", pa_version="1.0.0",
        findings=[{"package": "flask", "severity": "high", "advisory_id": "X", "summary": "vuln"}],
        min_severity=AlertSeverity.medium,
        recipients=["a@example.com"],
        from_addr="fleet@example.com",
    )
    body = msg.get_payload()
    assert "flask" in body


# ── Integration: SMTP send ────────────────────────────────────────────────────

class CapturingSMTPHandler:
    """Simple in-process SMTP handler that captures messages."""
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(envelope)
        return "250 OK"


@pytest.fixture
def smtp_server():
    """Start an in-process SMTP server on port 9025."""
    from aiosmtpd.controller import Controller
    handler = CapturingSMTPHandler()
    controller = Controller(handler, hostname="localhost", port=9025)
    controller.start()
    yield handler
    controller.stop()


async def test_send_email_reaches_smtp_server(smtp_server):
    svc = EmailService(smtp_cfg())
    msg = build_findings_email(
        repo_name="repo", branch="main", pa_version="1.0",
        findings=[{"package": "requests", "severity": "high", "advisory_id": "X", "summary": "s"}],
        min_severity=AlertSeverity.medium,
        recipients=["admin@example.com"],
        from_addr="fleet@example.com",
    )
    await svc.send(msg, ["admin@example.com"])
    assert len(smtp_server.messages) == 1


async def test_send_failure_email_reaches_smtp_server(smtp_server):
    svc = EmailService(smtp_cfg())
    msg = build_failure_email(
        repo_name="repo", repo_url="https://github.com/x/y",
        branch="main", pa_version="1.0",
        error_message="clone failed",
        ecs_task_arn="arn:test",
        recipients=["admin@example.com"],
        from_addr="fleet@example.com",
    )
    await svc.send(msg, ["admin@example.com"])
    assert len(smtp_server.messages) == 1


async def test_send_skipped_when_smtp_not_configured():
    svc = EmailService(None)
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = "test"
    await svc.send(msg, ["admin@example.com"])  # should not raise


@valkey_required
async def test_dedup_lock_prevents_double_send(smtp_server):
    """Second send with same lock key is skipped."""
    import redis.asyncio as aioredis
    r = aioredis.Redis.from_url("redis://localhost:6379", decode_responses=True)
    lock_key = "test:email:dedup:999"
    await r.delete(lock_key)

    svc = EmailService(smtp_cfg())
    msg = build_findings_email(
        repo_name="repo", branch="main", pa_version="1.0",
        findings=[{"package": "x", "severity": "high", "advisory_id": "X", "summary": "s"}],
        min_severity=AlertSeverity.medium,
        recipients=["admin@example.com"],
        from_addr="fleet@example.com",
    )

    from app.core.valkey import get_valkey
    valkey = get_valkey("redis://localhost:6379")
    await svc.send_with_dedup(msg, ["admin@example.com"], valkey, lock_key)
    await svc.send_with_dedup(msg, ["admin@example.com"], valkey, lock_key)
    await valkey.aclose()

    assert len(smtp_server.messages) == 1  # only sent once
    await r.delete(lock_key)
    await r.aclose()
