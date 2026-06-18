"""Email notification service for repo scan results."""
import asyncio
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from app.models import AlertSeverity

# Severity ordering for threshold filtering
_SEVERITY_ORDER = [
    AlertSeverity.info,
    AlertSeverity.low,
    AlertSeverity.warning,
    AlertSeverity.medium,
    AlertSeverity.high,
    AlertSeverity.critical,
]


def filter_findings_by_severity(
    findings: list[dict], min_severity: AlertSeverity
) -> list[dict]:
    """Return findings at or above min_severity."""
    try:
        threshold = _SEVERITY_ORDER.index(min_severity)
    except ValueError:
        threshold = 0
    def _rank(f: dict) -> int:
        try:
            sev = AlertSeverity(str(f.get("severity", "info")).lower())
        except ValueError:
            sev = AlertSeverity.info
        try:
            return _SEVERITY_ORDER.index(sev)
        except ValueError:
            return 0

    return [f for f in findings if _rank(f) >= threshold]


def build_findings_email(
    repo_name: str,
    branch: str,
    pa_version: str,
    findings: list[dict],
    min_severity: AlertSeverity,
    recipients: list[str],
    from_addr: str,
) -> EmailMessage:
    filtered = filter_findings_by_severity(findings, min_severity)
    msg = EmailMessage()
    msg["Subject"] = f"[PA Central] {len(filtered)} vulnerabilities found in {repo_name} ({min_severity.value}+)"
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)

    rows = "\n".join(
        f"  {f.get('package','?'):<30} {f.get('severity','?'):<10} {f.get('advisory_id','N/A'):<20} {f.get('summary','')}"
        for f in filtered
    )
    msg.set_payload(
        f"Repository: {repo_name} (branch: {branch})\n"
        f"PA version: {pa_version}\n"
        f"Findings ({len(filtered)}):\n\n"
        f"{'Package':<30} {'Severity':<10} {'Advisory':<20} Summary\n"
        f"{'-'*80}\n"
        f"{rows}\n"
    )
    return msg


def build_failure_email(
    repo_name: str,
    repo_url: str,
    branch: str,
    pa_version: str | None,
    error_message: str,
    ecs_task_arn: str | None,
    recipients: list[str],
    from_addr: str,
) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"[PA Central] Scan failed: {repo_name}"
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_payload(
        f"Scan failed for repository: {repo_name}\n"
        f"URL: {repo_url}\n"
        f"Branch: {branch}\n"
        f"PA version attempted: {pa_version or 'unknown'}\n"
        f"ECS task ARN: {ecs_task_arn or 'N/A'}\n\n"
        f"Error:\n{error_message}\n"
    )
    return msg


@dataclass
class SmtpConfig:
    host: str
    port: int
    username: str | None
    password: str | None
    from_addr: str
    tls_mode: str  # "none", "ssl", "starttls"


class EmailService:
    def __init__(self, config: SmtpConfig | None):
        self._config = config

    async def send(self, msg: EmailMessage, recipients: list[str]) -> None:
        """Send email. No-op if config is None."""
        if not self._config:
            return
        cfg = self._config
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._send_sync, msg, recipients, cfg)

    @staticmethod
    def _send_sync(msg: EmailMessage, recipients: list[str], cfg: SmtpConfig) -> None:
        if cfg.tls_mode == "ssl":
            smtp_cls = smtplib.SMTP_SSL
        else:
            smtp_cls = smtplib.SMTP
        with smtp_cls(cfg.host, cfg.port) as smtp:
            if cfg.tls_mode == "starttls":
                smtp.starttls()
            if cfg.username:
                smtp.login(cfg.username, cfg.password or "")
            smtp.send_message(msg, to_addrs=recipients)

    async def send_with_dedup(
        self,
        msg: EmailMessage,
        recipients: list[str],
        valkey: Any,
        lock_key: str,
        ttl_seconds: int = 300,
    ) -> bool:
        """Send email guarded by a Valkey SET NX lock. Returns True if sent."""
        if valkey is not None:
            from app.core.valkey import acquire_lock, release_lock
            acquired = await acquire_lock(valkey, lock_key, ttl_seconds)
            if not acquired:
                return False
            try:
                await self.send(msg, recipients)
            except Exception:
                await release_lock(valkey, lock_key)
                raise
        else:
            await self.send(msg, recipients)
        return True
