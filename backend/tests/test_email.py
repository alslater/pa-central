"""Tests for email notification service."""
import asyncio
import socket
import threading
import time
from email.message import EmailMessage

import pytest

import app.core.email as email_module
from app.core.email import (
    DEFAULT_SMTP_TIMEOUT_SECONDS,
    INTERACTIVE_SEND_DEADLINE_SECONDS,
    MAX_SMTP_TIMEOUT_SECONDS,
    EmailService,
    SmtpConfig,
    build_failure_email,
    build_findings_email,
    filter_deliverable_recipients,
    filter_findings_by_severity,
)
from app.core.smtp_settings import (
    build_smtp_config,
    looks_like_smtp_host,
    parse_smtp_from_addr,
    self_service_reset_enabled,
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


def test_filter_deliverable_recipients_drops_localhost():
    result = filter_deliverable_recipients(["admin@localhost", "real@example.com"])
    assert result == ["real@example.com"]


def test_filter_deliverable_recipients_drops_bare_hostname_and_no_at():
    result = filter_deliverable_recipients(["user@intranet", "not-an-email", "ok@example.com"])
    assert result == ["ok@example.com"]


def test_filter_deliverable_recipients_keeps_all_valid():
    addrs = ["a@example.com", "b@sub.example.co.uk"]
    assert filter_deliverable_recipients(addrs) == addrs


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


async def test_send_findings_email_with_non_ascii_summary(smtp_server):
    """Non-ASCII characters (e.g. an em dash) in a finding summary must not
    crash SMTP serialization — set_content() picks an encoding that can
    represent them; set_payload() assumes ASCII and raises UnicodeEncodeError."""
    svc = EmailService(smtp_cfg())
    msg = build_findings_email(
        repo_name="repo", branch="main", pa_version="1.0",
        findings=[{
            "package": "requests", "severity": "high", "advisory_id": "X",
            "summary": "Regular expression denial of service — backtracking",
        }],
        min_severity=AlertSeverity.medium,
        recipients=["admin@example.com"],
        from_addr="fleet@example.com",
    )
    await svc.send(msg, ["admin@example.com"])
    assert len(smtp_server.messages) == 1


async def test_send_failure_email_with_non_ascii_error_message(smtp_server):
    """Same non-ASCII regression as above, but for build_failure_email — it
    was switched to set_content() too, and error_message (often copied
    verbatim from a subprocess/git error) can just as easily contain
    non-ASCII characters."""
    svc = EmailService(smtp_cfg())
    msg = build_failure_email(
        repo_name="repo", repo_url="https://github.com/x/y",
        branch="main", pa_version="1.0",
        error_message="clone failed: authentication error — bad credentials",
        ecs_task_arn="arn:test",
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


# ── SMTP timeouts ─────────────────────────────────────────────────────────────

class TestSmtpTimeout:
    """Every SMTP operation must be bounded.

    smtplib defaults to no timeout, so a host that accepts the connection and
    then never speaks blocks its thread forever. Sends run in the default
    executor and forgot-password detaches them, so each hung send permanently
    consumes an executor thread and a _pending_sends slot — a burst against an
    unreachable relay exhausts the pool and never recovers. Verified against a
    deliberately silent server: no timeout blocked indefinitely, 2s failed
    cleanly.
    """

    def test_config_carries_a_finite_timeout_by_default(self):
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa@example.com", tls_mode="starttls",
        )
        assert cfg.timeout == DEFAULT_SMTP_TIMEOUT_SECONDS
        assert cfg.timeout > 0

    def test_the_timeout_is_passed_to_smtplib(self, monkeypatch):
        """The value has to reach the constructor — carrying it on the config
        and never using it would look identical in every other test."""
        seen: dict[str, object] = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                seen["timeout"] = timeout

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def starttls(self):
                pass

            def send_message(self, msg, to_addrs=None):
                pass

        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa@example.com", tls_mode="starttls", timeout=12.5,
        )
        EmailService._send_sync(EmailMessage(), ["a@example.com"], cfg, cfg.timeout)
        assert seen["timeout"] == 12.5

    def test_an_unreachable_server_fails_rather_than_hanging(self):
        """End to end against a socket that accepts and stays silent — the
        shape of a broken relay, and what smtplib waits on forever without a
        timeout."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]

        accepted: list[socket.socket] = []

        def hold() -> None:
            while True:
                try:
                    accepted.append(server.accept()[0])
                except OSError:
                    return

        threading.Thread(target=hold, daemon=True).start()
        try:
            cfg = SmtpConfig(
                host="127.0.0.1", port=port, username=None, password=None,
                from_addr="pa@example.com", tls_mode="none", timeout=1.0,
            )
            started = time.perf_counter()
            with pytest.raises(OSError):
                EmailService._send_sync(EmailMessage(), ["a@example.com"], cfg, cfg.timeout)
            elapsed = time.perf_counter() - started
            assert elapsed < 5.0, (
                f"send took {elapsed:.1f}s against a silent server — the "
                "timeout is not being applied"
            )
        finally:
            server.close()
            for conn in accepted:
                conn.close()


class TestInteractiveSendHasAnOverallDeadline:
    """cfg.timeout bounds each individual blocking smtplib call separately
    (connect, starttls, login, send_message) — a server that stalls on each
    subsequent step in turn re-arms that same budget every time, so the
    whole call can run to a small multiple of cfg.timeout, not just once.
    Reproduced directly: a fake server stalling 90% of a 2.0s cfg.timeout on
    each of starttls/login/send_message made a single interactive send take
    5.4s wall-clock, not 2.0s.

    That stacking matters specifically for the interactive path: it is used
    by the admin-initiated reset, and by the time it runs the target's
    password has already been invalidated and committed — every extra
    second here is a live lockout the admin is blocked on, not a slow
    background job. INTERACTIVE_SEND_DEADLINE_SECONDS bounds the *whole*
    send regardless of how many steps stall.
    """

    class _StallsOnEveryStep:
        """Mimics a server that accepts the connection immediately but
        stalls on each subsequent blocking call for a large fraction of the
        configured per-step timeout — the shape that lets three separate
        steps each burn nearly a full cfg.timeout in turn."""

        def __init__(self, host, port, timeout=None):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            time.sleep(self.timeout * 0.9)

        def login(self, username, password):
            time.sleep(self.timeout * 0.9)

        def send_message(self, msg, to_addrs=None):
            time.sleep(self.timeout * 0.9)

    async def test_stacked_per_step_timeouts_exceed_a_single_cfg_timeout(
        self, monkeypatch
    ):
        """Establishes the premise the rest of this class fixes: without any
        overall deadline, three stalling steps sum to noticeably more than
        one cfg.timeout."""
        monkeypatch.setattr("app.core.email.smtplib.SMTP", self._StallsOnEveryStep)
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username="u", password="p",
            from_addr="pa@example.com", tls_mode="starttls", timeout=1.0,
        )
        started = time.perf_counter()
        EmailService._send_sync(EmailMessage(), ["a@example.com"], cfg, cfg.timeout)
        elapsed = time.perf_counter() - started
        assert elapsed > 2.0, (
            f"three stalling steps against a 1.0s cfg.timeout took only "
            f"{elapsed:.2f}s — the premise this class exercises (per-step "
            "timeouts stacking past a single cfg.timeout) no longer holds"
        )

    async def test_an_interactive_send_is_bounded_by_the_overall_deadline(
        self, monkeypatch
    ):
        monkeypatch.setattr(email_module, "INTERACTIVE_SEND_DEADLINE_SECONDS", 1.0)
        monkeypatch.setattr("app.core.email.smtplib.SMTP", self._StallsOnEveryStep)
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username="u", password="p",
            from_addr="pa@example.com", tls_mode="starttls", timeout=2.0,
        )
        started = time.perf_counter()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(
                EmailService(cfg).send(
                    EmailMessage(), ["a@example.com"], interactive=True
                ),
                timeout=5.0,
            )
        elapsed = time.perf_counter() - started
        assert elapsed < 2.0, (
            f"an interactive send took {elapsed:.2f}s despite a 1.0s "
            "overall deadline — cfg.timeout's per-step bound is being "
            "relied on instead of the request-level one"
        )

    async def test_a_non_interactive_send_is_not_bound_by_the_interactive_deadline(
        self, monkeypatch
    ):
        """The deadline is specific to the synchronous, HTTP-request-facing
        path. Detached forgot-password dispatch and scan-result
        notifications have no caller waiting on them, so applying the same
        short deadline there would only turn a slow-but-eventually-
        successful send into a spurious failure."""
        monkeypatch.setattr(email_module, "INTERACTIVE_SEND_DEADLINE_SECONDS", 0.05)

        def slow_but_finite(msg, recipients, cfg, socket_timeout):
            time.sleep(0.3)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(slow_but_finite)
        )
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa@example.com", tls_mode="none", timeout=5.0,
        )
        started = time.perf_counter()
        await EmailService(cfg).send(EmailMessage(), ["a@example.com"], interactive=False)
        elapsed = time.perf_counter() - started
        assert elapsed >= 0.3, (
            "a non-interactive send returned before its own _send_sync "
            "finished — the interactive deadline is being applied to the "
            "detached path too"
        )

    def test_the_deadline_is_below_the_default_cfg_timeout(self):
        """A sanity bound on the constant itself: the whole point is that a
        single interactive send should not be allowed to run past roughly
        one ordinary send's worth of time, whatever the configured
        per-step timeout is set to."""
        assert INTERACTIVE_SEND_DEADLINE_SECONDS <= DEFAULT_SMTP_TIMEOUT_SECONDS

    async def test_an_abandoned_interactive_send_does_not_leak_its_worker_thread_for_cfg_timeout(
        self, monkeypatch
    ):
        """asyncio.wait_for timing out on the interactive deadline abandons
        the coroutine, but the worker thread underneath keeps running
        smtplib until *its own* socket timeout elapses — cfg.timeout,
        admin-configurable up to MAX_SMTP_TIMEOUT_SECONDS. Only
        MAX_CONCURRENT_INTERACTIVE_SENDS=2 threads exist for this pool, so
        two sends against a large cfg.timeout (or one stalling under
        DEFAULT_SMTP_TIMEOUT_SECONDS's own stacking, per the class above)
        can occupy the entire interactive pool for far longer than any
        individual send's own 20s deadline — every later admin-initiated
        reset then queues behind them and times out without its email ever
        starting, after that admin's target password has already been
        invalidated. Reproduced directly before this fix: an interactive
        send with cfg.timeout=86400.0 passed that literal value straight to
        smtplib.SMTP's own timeout parameter.

        Fixed by capping the *socket* timeout passed to smtplib to
        INTERACTIVE_SEND_DEADLINE_SECONDS for the interactive path
        specifically, regardless of cfg.timeout — so the thread itself can
        never be held open longer than the deadline already bounding the
        coroutine waiting on it.
        """
        seen: dict[str, object] = {}

        class RecordingSMTP:
            def __init__(self, host, port, timeout=None):
                seen["timeout"] = timeout

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def send_message(self, msg, to_addrs=None):
                pass

        monkeypatch.setattr("app.core.email.smtplib.SMTP", RecordingSMTP)
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa@example.com", tls_mode="none",
            timeout=MAX_SMTP_TIMEOUT_SECONDS,
        )
        await EmailService(cfg).send(EmailMessage(), ["a@example.com"], interactive=True)
        assert seen["timeout"] <= INTERACTIVE_SEND_DEADLINE_SECONDS, (
            f"the interactive send's socket timeout was {seen['timeout']}s — "
            f"unbounded by cfg.timeout instead of capped to "
            f"INTERACTIVE_SEND_DEADLINE_SECONDS "
            f"({INTERACTIVE_SEND_DEADLINE_SECONDS}s), so a large configured "
            "timeout can hold an interactive worker thread open far past "
            "this send's own overall deadline"
        )

    async def test_a_non_interactive_send_still_uses_cfg_timeout_uncapped(
        self, monkeypatch
    ):
        """The cap above is specific to the interactive path — the detached
        path has no request-level deadline to agree with, and capping it
        the same way would silently shrink whatever timeout an admin
        configured for a deliberately slow relay with nothing waiting on
        it."""
        seen: dict[str, object] = {}

        class RecordingSMTP:
            def __init__(self, host, port, timeout=None):
                seen["timeout"] = timeout

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def send_message(self, msg, to_addrs=None):
                pass

        monkeypatch.setattr("app.core.email.smtplib.SMTP", RecordingSMTP)
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa@example.com", tls_mode="none", timeout=3600.0,
        )
        await EmailService(cfg).send(EmailMessage(), ["a@example.com"], interactive=False)
        assert seen["timeout"] == 3600.0, (
            "the detached path's socket timeout was capped or otherwise "
            "altered — it must pass cfg.timeout through unchanged"
        )


class TestSmtpTimeoutSetting:
    """smtp_timeout_seconds, and the values that must not disable it."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("10", 10.0),
            ("2.5", 2.5),
            # None of these may yield 0 or None: without a timeout smtplib
            # blocks forever, so an unparseable or non-positive setting has to
            # fall back rather than switch the bound off.
            ("0", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("-5", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("abc", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("", DEFAULT_SMTP_TIMEOUT_SECONDS),
            # Non-finite: float("inf") > 0 is True, so a bare positivity
            # check accepted all of these. Worse than losing the bound —
            # smtplib raises OverflowError on every send, and send_reset_email
            # swallows exceptions, so the deployment would silently deliver no
            # reset emails at all.
            ("inf", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("Infinity", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("1e309", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("-inf", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("nan", DEFAULT_SMTP_TIMEOUT_SECONDS),
            # Huge but finite: passes math.isfinite(v) and v > 0 cleanly, but
            # socket.settimeout() still raises OverflowError once the value
            # exceeds what the platform's timeout conversion supports —
            # verified directly, 1e10 already overflows. Same silent-outage
            # consequence as the non-finite case, from a value that looks
            # perfectly reasonable to a bare finiteness/positivity check.
            ("1e10", DEFAULT_SMTP_TIMEOUT_SECONDS),
            ("1e8", DEFAULT_SMTP_TIMEOUT_SECONDS),
            (str(MAX_SMTP_TIMEOUT_SECONDS + 1), DEFAULT_SMTP_TIMEOUT_SECONDS),
            # Right at the boundary: must still be honoured, not treated as
            # "too large" by an off-by-one in the comparison.
            (str(MAX_SMTP_TIMEOUT_SECONDS), MAX_SMTP_TIMEOUT_SECONDS),
        ],
    )
    def test_parsing(self, raw, expected):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com",
                                 "smtp_timeout_seconds": raw})
        assert cfg is not None
        assert cfg.timeout == expected

    def test_every_accepted_value_is_finite_and_positive(self):
        """The property the parametrised cases sample: whatever is stored,
        the resulting timeout is usable by smtplib. A value that is merely
        `> 0` is not enough — infinity satisfies that and crashes the send.
        Being finite is not enough either — 1e10 is finite and positive and
        still crashes the send, so every accepted value must additionally
        be checked against the actual settimeout() boundary below."""
        import math

        for raw in ["inf", "Infinity", "1e309", "-inf", "nan", "0", "-5",
                    "abc", "", "30", "2.5", "0.001", "1e10", "1e8"]:
            cfg = build_smtp_config({"smtp_host": "smtp.example.com",
                                     "smtp_timeout_seconds": raw})
            assert cfg is not None
            assert math.isfinite(cfg.timeout), f"{raw!r} yielded {cfg.timeout!r}"
            assert cfg.timeout > 0, f"{raw!r} yielded {cfg.timeout!r}"
            self._assert_settimeout_accepts(cfg.timeout, raw)

    @staticmethod
    def _assert_settimeout_accepts(timeout: float, raw: str) -> None:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
        except OverflowError:
            pytest.fail(
                f"{raw!r} parsed to {timeout!r}, which socket.settimeout() "
                "itself rejects — the same failure this parser exists to "
                "prevent for non-finite values"
            )
        finally:
            s.close()

    def test_an_infinite_timeout_would_break_smtplib(self):
        """Why non-finite is rejected rather than passed through: this is the
        failure it would cause on every send."""
        import smtplib

        with pytest.raises(OverflowError):
            smtplib.SMTP("127.0.0.1", 1, timeout=float("inf"))

    def test_a_huge_finite_timeout_would_also_break_smtplib(self):
        """The case this fix specifically closes: 1e10 is not `inf`, so it
        needs its own demonstration that it breaks the exact same way. If
        this test ever stops raising, MAX_SMTP_TIMEOUT_SECONDS may need
        lowering — it would mean the platform's actual overflow boundary
        moved below what this test probes."""
        import smtplib

        with pytest.raises(OverflowError):
            smtplib.SMTP("127.0.0.1", 1, timeout=1e10)

    def test_max_timeout_constant_is_below_the_actual_overflow_boundary(self):
        """MAX_SMTP_TIMEOUT_SECONDS is a chosen safety margin, not a
        precisely-measured platform limit — this asserts it actually sits
        below where settimeout() fails, so the constant cannot silently drift
        past the boundary it exists to stay clear of."""
        self._assert_settimeout_accepts(
            MAX_SMTP_TIMEOUT_SECONDS, "MAX_SMTP_TIMEOUT_SECONDS"
        )

    def test_absent_setting_uses_the_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com"})
        assert cfg is not None
        assert cfg.timeout == DEFAULT_SMTP_TIMEOUT_SECONDS


class TestSmtpHostIsTrimmed:
    """The availability checks (self_service_reset_enabled, and
    api/system_settings.py's write-time gate) both strip smtp_host before
    deciding it is present. build_smtp_config previously did not — a value
    with leading/trailing whitespace (pasted from a UI field, say) passed
    every presence check as configured, then failed DNS resolution when
    actually handed to smtplib, since `socket.getaddrinfo(" host ", ...)`
    does not resolve a padded hostname. On the admin-reset path, that
    failure surfaces only after the target's password has already been
    invalidated.
    """

    def test_a_padded_host_is_trimmed_before_reaching_smtpconfig(self):
        cfg = build_smtp_config({"smtp_host": " smtp.example.com "})
        assert cfg is not None
        assert cfg.host == "smtp.example.com", (
            f"expected the trimmed hostname, got {cfg.host!r} — this is "
            "the exact value that reaches socket.getaddrinfo()"
        )

    def test_a_whitespace_only_host_is_treated_as_absent(self):
        assert build_smtp_config({"smtp_host": "   "}) is None

    def test_a_padded_host_would_fail_dns_resolution_untrimmed(self):
        """Why trimming matters: this is the failure it prevents."""
        import socket

        with pytest.raises(socket.gaierror):
            socket.getaddrinfo(" smtp.example.invalid ", 587)

    def test_build_smtp_config_agrees_with_self_service_reset_enabled(self):
        """The actual bug: two functions checking the same setting
        disagreed about what "present" means for the same padded value —
        one said usable, the other produced something unusable. This
        asserts they now agree on the *value*, not just both saying
        "present"."""
        settings_map = {
            "smtp_host": " smtp.example.com ",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        assert self_service_reset_enabled(settings_map) is True

        cfg = build_smtp_config(settings_map)
        assert cfg is not None
        assert cfg.host == "smtp.example.com", (
            "self_service_reset_enabled() reported the feature usable, but "
            "build_smtp_config() produced a host that would fail DNS "
            "resolution — the two consumers of smtp_host disagree about "
            "what value it actually holds"
        )


class TestSmtpHostIsValidated:
    """build_smtp_config and self_service_reset_enabled previously accepted
    any non-empty smtp_host, including a value socket.getaddrinfo can never
    resolve on any network. Both now reject via the shared
    looks_like_smtp_host(), the same pattern already used for smtp_port,
    smtp_tls_mode, smtp_from, and app_base_url.
    """

    @pytest.mark.parametrize(
        "bad_host",
        [
            "not a host",
            "bad\x01host",
            "trailing\tws",
            "line\nbreak",
            "carriage\rreturn",
            "\x7fdel",
            " ",
            "",
        ],
    )
    def test_rejects_a_syntactically_impossible_host(self, bad_host):
        assert looks_like_smtp_host(bad_host) is False

    @pytest.mark.parametrize(
        "good_host",
        [
            "smtp.example.com",
            "mail-server01.internal",
            "localhost",
            "192.168.1.50",
            "::1",
            "a" * 250 + ".com",
        ],
    )
    def test_accepts_an_ordinary_host_or_ip_literal(self, good_host):
        assert looks_like_smtp_host(good_host) is True

    def test_rejects_an_absurdly_long_host(self):
        """RFC 1035 caps a full domain name at 255 octets; smtplib itself
        enforces nothing, so an unbounded value would otherwise reach
        socket.getaddrinfo() untouched."""
        assert looks_like_smtp_host("a" * 300 + ".com") is False

    def test_build_smtp_config_rejects_a_syntactically_impossible_host(self):
        assert build_smtp_config({"smtp_host": "not a host"}) is None

    def test_self_service_reset_enabled_rejects_a_syntactically_impossible_host(self):
        settings_map = {
            "smtp_host": "not a host",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        assert self_service_reset_enabled(settings_map) is False

    def test_a_syntactically_impossible_host_would_fail_dns_resolution(self):
        """Why this is rejected rather than passed through: this is the
        predictable failure it prevents from being discovered only at send
        time, after the reset token has already been committed (and, on
        the admin-reset path, after the target's password has already been
        invalidated)."""
        with pytest.raises(socket.gaierror):
            socket.getaddrinfo("not a host", 587)


class TestSmtpPortIsValidated:
    """A bare `int(raw or "587")` raised ValueError uncaught on a
    non-numeric smtp_port — a legacy row, one restored from a backup, or
    written directly to the database, all of which bypass PATCH's own
    int-and-range validation. forgot_password only reaches
    build_smtp_config (via prepare_reset_email) for a real, active
    account — an unknown address returns the padded 202 without ever
    calling it — so an uncaught raise here restored account enumeration by
    status code: the exact class of bug prepare_reset_email's own
    docstring says it exists to prevent, just via ValueError instead of
    the DBAPIError it already catches. On the admin-reset path
    (api/users.py's reset_password), the same raise surfaced only after
    the account's password had already been invalidated, instead of the
    designed 502 "the email could not be sent" response.
    """

    def test_a_nonnumeric_port_is_treated_as_unconfigured(self):
        assert build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_port": "not-a-port",
        }) is None

    def test_an_empty_port_falls_back_to_the_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com", "smtp_port": ""})
        assert cfg is not None
        assert cfg.port == 587

    def test_an_absent_port_falls_back_to_the_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com"})
        assert cfg is not None
        assert cfg.port == 587

    @pytest.mark.parametrize("raw", ["0", "-1", "65536", "999999"])
    def test_an_out_of_range_port_is_treated_as_unconfigured(self, raw):
        assert build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_port": raw,
        }) is None

    def test_a_valid_port_is_used_as_an_int(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com", "smtp_port": "2525"})
        assert cfg is not None
        assert cfg.port == 2525

    def test_self_service_reset_enabled_agrees_with_build_smtp_config_on_a_bad_port(self):
        """The actual bug: build_smtp_config would refuse this
        configuration (returning None, once fixed to not raise), but
        self_service_reset_enabled never looked at smtp_port at all and
        reported the feature enabled anyway — the exact disagreement
        pattern already fixed once for smtp_host and app_base_url."""
        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_port": "not-a-port",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        assert build_smtp_config(settings_map) is None
        assert self_service_reset_enabled(settings_map) is False, (
            "self_service_reset_enabled() reported the feature usable with "
            "an smtp_port build_smtp_config refuses to use — forgot_password "
            "would reach prepare_reset_email only for a real account, and "
            "the admin-reset path would invalidate the password before "
            "discovering delivery is impossible"
        )


class TestSmtpTlsModeIsValidated:
    """EmailService._send_sync only recognises the exact strings "ssl" and
    "starttls" — anything else, including the deliberate "none" opt-out
    *and* an unrecognised value such as a typo, falls through identically
    to plain, unencrypted smtplib.SMTP with no starttls() upgrade at all.
    smtp_tls_mode is a plain string with no PATCH-side shape validation,
    so a typo like "start-tls" previously saved successfully and silently
    sent password reset links — containing the raw credential — over an
    unencrypted connection, with nothing anywhere indicating the admin's
    intended setting was never honoured. Reproduced directly:
    EmailService._send_sync with tls_mode="start-tls" used plain
    smtplib.SMTP and never called .starttls(), identically to an explicit
    "none".
    """

    def test_an_unrecognised_value_is_treated_as_unconfigured(self):
        assert build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_tls_mode": "start-tls",
        }) is None

    @pytest.mark.parametrize("raw", ["STARTTLS", "SSL", "tls"])
    def test_case_variants_are_also_unconfigured(self, raw):
        """Case variants of a valid mode are not auto-corrected — a typo
        that happens to look close to a valid value must fail exactly
        like one that doesn't, not be silently normalised into behaving
        correctly by accident."""
        assert build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_tls_mode": raw,
        }) is None

    @pytest.mark.parametrize("raw", [" ssl", "ssl ", " starttls ", "\tstarttls\n"])
    def test_surrounding_whitespace_is_stripped_before_comparison(self, raw):
        """Unlike case, surrounding whitespace IS normalised away — the
        PATCH-time effective-state gate in system_settings.py already
        strips both submitted and stored values before calling this same
        parse function (_effective()), so a stored " starttls " (a legacy
        row, a direct edit, or a client that didn't trim) passed that gate
        while this function — called unstripped everywhere else
        (build_smtp_config, self_service_reset_enabled) — rejected the
        identical value, letting PATCH report 200 while the very next read
        reported the feature unavailable. Stripping here, once, keeps
        every caller agreeing without each needing its own normalisation."""
        cfg = build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_tls_mode": raw,
        })
        assert cfg is not None
        assert cfg.tls_mode == raw.strip()

    def test_an_empty_value_falls_back_to_the_starttls_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com", "smtp_tls_mode": ""})
        assert cfg is not None
        assert cfg.tls_mode == "starttls"

    def test_an_absent_value_falls_back_to_the_starttls_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com"})
        assert cfg is not None
        assert cfg.tls_mode == "starttls"

    @pytest.mark.parametrize("valid", ["none", "ssl", "starttls"])
    def test_every_valid_value_is_used_as_is(self, valid):
        cfg = build_smtp_config({
            "smtp_host": "smtp.example.com", "smtp_tls_mode": valid,
        })
        assert cfg is not None
        assert cfg.tls_mode == valid

    def test_self_service_reset_enabled_agrees_with_build_smtp_config_on_a_bad_tls_mode(self):
        """The actual bug: build_smtp_config refuses this configuration,
        but self_service_reset_enabled never looked at smtp_tls_mode at
        all and reported the feature enabled anyway — the same
        disagreement pattern already fixed for smtp_host, app_base_url,
        and smtp_port."""
        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_tls_mode": "start-tls",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        assert build_smtp_config(settings_map) is None
        assert self_service_reset_enabled(settings_map) is False, (
            "self_service_reset_enabled() reported the feature usable with "
            "an smtp_tls_mode build_smtp_config refuses to use — the actual "
            "send would silently downgrade to an unencrypted connection "
            "while this gate advertised the feature as available"
        )

    def test_a_typo_actually_sends_plaintext_not_merely_fails_validation(self):
        """Confirms the real-world consequence the finding is about, not
        just that parse_smtp_tls_mode rejects the value: even bypassing
        this fix entirely (calling _send_sync directly with the raw,
        unvalidated string, as would happen if some other code path ever
        constructed an SmtpConfig without going through build_smtp_config),
        an unrecognised tls_mode still silently means plaintext — this is
        why treating it as "unconfigured" up front, rather than trusting
        _send_sync to reject it, is the only safe fix."""
        cfg = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa-central@localhost", tls_mode="start-tls", timeout=5.0,
        )
        assert cfg.tls_mode != "ssl"
        assert cfg.tls_mode != "starttls"
        # i.e. EmailService._send_sync's own `if/elif` chain falls through
        # both branches for this value: smtp_cls stays plain smtplib.SMTP,
        # and .starttls() is never called — the exact plaintext consequence.


class TestSmtpFromAddrIsValidated:
    """build_password_reset_email (core/email.py) assigns smtp_from
    straight to `EmailMessage()["From"]` — Python's own email module
    raises ValueError for a value containing a carriage return or line
    feed (a header-injection vector), and that assignment happens *after*
    the reset token has already been committed, or after set_password has
    already invalidated the admin-reset target's password. This key had
    no shape validation at all, so a stored value with an embedded CR/LF
    reached that assignment only once a real account actually triggered
    issuance. Reproduced directly across all three callers before this
    fix: forgot_password raised an uncaught ValueError only for a real,
    active account (an unknown address never reaches build_smtp_config at
    all, so it kept returning the padded 202 — an account-existence oracle
    by status code); register() left an already-committed new user row
    behind an unhandled 500 instead of the designed rollback-and-502;
    reset_password raised after set_password had already invalidated the
    target's password, with no link ever built to relay instead of the
    designed 502.
    """

    def test_a_value_with_a_carriage_return_is_treated_as_unconfigured(self):
        assert build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa\r\nBcc: evil@example.com",
        }) is None

    def test_a_value_with_a_bare_line_feed_is_treated_as_unconfigured(self):
        assert build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa\nBcc: evil@example.com",
        }) is None

    def test_an_empty_value_falls_back_to_the_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com", "smtp_from": ""})
        assert cfg is not None
        assert cfg.from_addr == "pa-central@localhost"

    def test_an_absent_value_falls_back_to_the_default(self):
        cfg = build_smtp_config({"smtp_host": "smtp.example.com"})
        assert cfg is not None
        assert cfg.from_addr == "pa-central@localhost"

    def test_a_valid_value_is_used_and_trimmed(self):
        cfg = build_smtp_config({
            "smtp_host": "smtp.example.com",
            "smtp_from": "  pa-central@example.com  ",
        })
        assert cfg is not None
        assert cfg.from_addr == "pa-central@example.com"

    def test_self_service_reset_enabled_agrees_with_build_smtp_config_on_a_bad_from_addr(self):
        """The actual bug: build_smtp_config refuses this configuration,
        but self_service_reset_enabled never looked at smtp_from at all
        and reported the feature enabled anyway — the same disagreement
        pattern already fixed for smtp_host, app_base_url, smtp_port, and
        smtp_tls_mode."""
        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa\r\nBcc: evil@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        assert build_smtp_config(settings_map) is None
        assert self_service_reset_enabled(settings_map) is False, (
            "self_service_reset_enabled() reported the feature usable with "
            "an smtp_from build_smtp_config refuses to use — issuance "
            "would raise an uncaught ValueError only for a real account, "
            "after set_password/the account row had already committed"
        )

    def test_a_bad_from_addr_actually_raises_in_build_password_reset_email(self):
        """Confirms the real-world consequence directly, not just that
        parse_smtp_from_addr rejects the value: EmailMessage() itself
        raises ValueError for this string, which is the exact exception
        that reached forgot_password/register()/reset_password as an
        unhandled 500 before this fix — this is why treating it as
        "unconfigured" up front, before any commit, is the only safe fix."""
        from app.core.email import build_password_reset_email

        with pytest.raises(ValueError, match="linefeed or carriage return"):
            build_password_reset_email(
                reset_url="https://pa.example.com/reset-password#token=abc",
                display_name="Someone",
                recipient="someone@example.com",
                from_addr="pa\r\nBcc: evil@example.com",
                expires_minutes=60,
            )

    def test_parse_smtp_from_addr_directly(self):
        assert parse_smtp_from_addr(None) == "pa-central@localhost"
        assert parse_smtp_from_addr("") == "pa-central@localhost"
        assert parse_smtp_from_addr("a@b.com") == "a@b.com"
        assert parse_smtp_from_addr("  a@b.com  ") == "a@b.com"
        assert parse_smtp_from_addr("a\r\nb@c.com") is None
        assert parse_smtp_from_addr("a\nb@c.com") is None
        assert parse_smtp_from_addr("a\rb@c.com") is None

