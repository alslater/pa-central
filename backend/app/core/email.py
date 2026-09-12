"""Email notification service for repo scan results."""
import asyncio
import logging
import smtplib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from app.models import AlertSeverity

logger = logging.getLogger(__name__)

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


def filter_deliverable_recipients(recipients: list[str]) -> list[str]:
    """Drop addresses whose domain isn't fully-qualified (e.g. admin@localhost).

    Real SMTP servers reject these with 'Recipient address rejected: need
    fully-qualified address'. smtplib only raises when *every* recipient is
    refused — a partial refusal is returned as a dict instead, which
    EmailService._send_sync discards — so a single bad address otherwise
    fails silently whenever at least one other recipient is valid.
    """
    result = []
    for addr in recipients:
        domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
        if "." in domain:
            result.append(addr)
    return result


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
    msg.set_content(
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
    msg.set_content(
        f"Scan failed for repository: {repo_name}\n"
        f"URL: {repo_url}\n"
        f"Branch: {branch}\n"
        f"PA version attempted: {pa_version or 'unknown'}\n"
        f"ECS task ARN: {ecs_task_arn or 'N/A'}\n\n"
        f"Error:\n{error_message}\n"
    )
    return msg


def build_password_reset_email(
    reset_url: str,
    display_name: str,
    recipient: str,
    from_addr: str,
    expires_minutes: int,
    admin_initiated: bool = False,
    welcome: bool = False,
) -> EmailMessage:
    """Password reset link email.

    Deliberately contains no information about the account beyond the display
    name the recipient already supplied — the link itself is the only secret,
    and it is single-use and short-lived.

    Three variants, because the same link means three different things:

    * self-service — the recipient asked for this, and nothing has changed
      unless they act, so "ignore this if it wasn't you" is correct.
    * admin-initiated — they did not ask, and their password has *already*
      been invalidated, so the mail must explain they are locked out and the
      link is how they get back in. "Ignore this" would be actively
      misleading.
    * welcome — a brand-new account. There is no previous password to
      mention, and the link is how they set their first one; the mail has to
      introduce the account rather than report a change to it.
    """
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = recipient

    if expires_minutes % (24 * 60) == 0:
        days = expires_minutes // (24 * 60)
        validity = "24 hours" if days == 1 else f"{days} days"
    elif expires_minutes % 60 == 0:
        hours = expires_minutes // 60
        validity = "1 hour" if hours == 1 else f"{hours} hours"
    else:
        validity = f"{expires_minutes} minutes"

    if welcome:
        msg["Subject"] = "[PA Central] Welcome — set your password"
        msg.set_content(
            f"Hello {display_name},\n\n"
            f"An administrator has created a PA Central account for you, "
            f"using this email address.\n\n"
            f"Use the link below to choose a password and sign in for the "
            f"first time. It can be used once and expires in {validity}.\n\n"
            f"{reset_url}\n\n"
            f"If the link expires before you use it, ask your administrator "
            f"to send a new one.\n"
        )
    elif admin_initiated:
        msg["Subject"] = "[PA Central] Your password has been reset"
        msg.set_content(
            f"Hello {display_name},\n\n"
            f"An administrator has reset the password on your PA Central "
            f"account. Your previous password no longer works.\n\n"
            f"Use the link below to choose a new one. It can be used once and "
            f"expires in {validity}.\n\n"
            f"{reset_url}\n\n"
            f"If you were not expecting this, contact your administrator — "
            f"it may have been done in response to a suspected compromise of "
            f"your account.\n"
        )
    else:
        msg["Subject"] = "[PA Central] Password reset"
        msg.set_content(
            f"Hello {display_name},\n\n"
            f"A password reset was requested for your PA Central account.\n"
            f"Use the link below to choose a new password. It can be used "
            f"once and expires in {validity}.\n\n"
            f"{reset_url}\n\n"
            f"If you did not request this, you can ignore this email — your "
            f"password has not been changed.\n"
        )
    return msg


# Ceiling on any single SMTP operation (connect, and each subsequent socket
# read/write). smtplib defaults to no timeout at all, which means a host that
# accepts the connection and then never speaks blocks the calling thread
# forever — verified directly: a silent server left a no-timeout connect
# blocked indefinitely, while a 2s timeout failed cleanly.
#
# That matters because sends run in the default executor and are started
# detached by forgot-password: every hung send permanently consumes an
# executor thread and a _pending_sends entry, so a burst against an
# unreachable relay exhausts the pool and never recovers. 30s is generous for
# a working relay and finite for a broken one.
DEFAULT_SMTP_TIMEOUT_SECONDS = 30.0

# Ceiling on a configured smtp_timeout_seconds value.
#
# An *operational* ceiling, not merely one short of where the platform
# overflows: socket.settimeout() (reached via smtplib.SMTP(...,
# timeout=cfg.timeout)) raises OverflowError for a value beyond what the
# platform's timeout conversion supports — verified directly: 1e10 already
# overflows on this platform, despite being finite and positive, well within
# what a bare `math.isfinite(v) and v > 0` check accepts — but an earlier
# version of this constant (86400.0, one day) picked a value merely below
# that overflow boundary rather than one that is actually sane to run with.
# Every one of MAX_CONCURRENT_SENDS/MAX_CONCURRENT_INTERACTIVE_SENDS worker
# threads is uncancellable once smtplib is holding it (see EmailService.send
# and shutdown_send_executor's own docstring), so a stalling relay under a
# day-long configured timeout — or an admin genuinely setting one, thinking
# they are being generous with a flaky server — can occupy a worker for
# nearly that entire day. For the interactive pool specifically
# (MAX_CONCURRENT_INTERACTIVE_SENDS=2), two such stalls exhaust it entirely:
# every later admin-initiated reset then queues behind them and hits its own
# INTERACTIVE_SEND_DEADLINE_SECONDS without its email ever starting, after
# that admin's target password has already been invalidated — the
# interactive path's own socket timeout is separately capped to that
# deadline regardless of cfg.timeout (see EmailService.send), but the
# detached path has no such per-call cap, so this ceiling is what actually
# bounds its worst case.
#
# Five minutes is well past what any real, currently-reachable SMTP relay
# should ever need for one connect/TLS/login/send operation — the default is
# 30s — while still leaving generous headroom for a deliberately slow or
# heavily loaded server, and unlike the previous value it makes the
# detached pool's worst-case stall something an operator can wait out
# rather than something that persists for most of a day.
MAX_SMTP_TIMEOUT_SECONDS = 300.0


# Ceiling on SMTP worker threads, process-wide.
#
# Enforced by the executor's own size rather than a semaphore, so a send whose
# coroutine is cancelled cannot leak a thread past the cap (see
# EmailService.send). Sized to keep a backlog from being slow while staying
# far below the default executor's 20 workers.
MAX_CONCURRENT_SENDS = 4

# Ceiling on the *separate* executor reserved for interactive sends — see
# _interactive_send_executor below.
MAX_CONCURRENT_INTERACTIVE_SENDS = 2

# Overall wall-clock deadline for an interactive send, independent of
# cfg.timeout. cfg.timeout bounds each individual blocking smtplib call
# (connect, starttls, login, send_message) separately — a server that
# accepts the connection and then stalls on each subsequent step in turn
# re-arms that same budget every time, so the *call* can run to a small
# multiple of cfg.timeout, not just once. Reproduced directly: a fake
# server stalling 90% of a 2.0s cfg.timeout on each of starttls/login/
# send_message made a single send take 5.4s, not 2.0s.
#
# That stacking matters far more here than for a detached send: the
# interactive path is used by the admin-initiated reset, and by the time
# this call happens the target's password has already been invalidated and
# committed (see api/users.py's reset_password) — so every extra second
# spent here is a live lockout the admin is blocked on, not merely a slow
# background job. Set below cfg.timeout's own default so a single stalled
# step still cannot make the caller wait longer than roughly one ordinary
# send would have taken, whatever the configured per-step timeout is.
INTERACTIVE_SEND_DEADLINE_SECONDS = 20.0

_executor: ThreadPoolExecutor | None = None
_interactive_executor: ThreadPoolExecutor | None = None


def _send_executor() -> ThreadPoolExecutor:
    """The shared SMTP executor, created on first use.

    Lazy so importing this module does not spawn threads in processes that
    never send mail — the scheduler and the CLI both import it.

    Used by detached, fire-and-forget sends: the public forgot-password
    endpoint's own dispatch, and scan-result notifications. Not used by a
    caller that is itself awaited inline by an HTTP handler — see
    _interactive_send_executor.
    """
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(
            max_workers=MAX_CONCURRENT_SENDS, thread_name_prefix="smtp"
        )
    return _executor


def _interactive_send_executor() -> ThreadPoolExecutor:
    """A small executor reserved for sends an HTTP request is waiting on
    synchronously — currently the admin-initiated reset and the welcome
    email on registration (see password_reset.send_reset_email).

    Those calls share `EmailService.send`'s implementation with every
    detached forgot-password send, and all of it used to funnel through the
    one shared executor above. A public request queues up to
    MAX_PENDING_SENDS (1000) sends ahead of it there — each potentially
    taking the full SmtpConfig.timeout before failing — so a synchronous
    admin-reset call could be left waiting behind an entirely unrelated
    public backlog for far longer than any SMTP timeout would suggest.
    Reproduced directly: an inline send waited 5.45s behind just 40 queued
    0.5s jobs on the shared 4-worker pool, scaling linearly with backlog
    depth; at the real MAX_PENDING_SENDS ceiling against a broken relay this
    is unbounded in practice. Worse, by the time this call runs, the admin
    path has already invalidated the target's password (see
    api/users.py's reset_password) — the exact scenario the containment
    design assumed would resolve within one SmtpConfig.timeout, not queue
    behind a thousand unrelated jobs first.

    A separate pool removes the contention structurally rather than merely
    bounding the wait: kept small (2, not 4) because interactive callers are
    inherently low-volume — one admin action or one registration at a
    time — so a large pool here would just be idle capacity taken away from
    the public path's own worst case.
    """
    global _interactive_executor
    if _interactive_executor is None:
        _interactive_executor = ThreadPoolExecutor(
            max_workers=MAX_CONCURRENT_INTERACTIVE_SENDS,
            thread_name_prefix="smtp-interactive",
        )
    return _interactive_executor


# How long shutdown will actually wait for SMTP worker threads to finish
# before giving up on them. Independent of DRAIN_TIMEOUT_SECONDS in
# password_reset.py, which bounds the *coroutines* awaiting these threads —
# a coroutine abandoned there does not stop the thread it was waiting on.
EXECUTOR_SHUTDOWN_TIMEOUT_SECONDS = 5.0


async def shutdown_send_executor(
    timeout: float = EXECUTOR_SHUTDOWN_TIMEOUT_SECONDS,
) -> None:
    """Wait up to `timeout` for in-flight SMTP sends to finish, then let go.

    `ThreadPoolExecutor.shutdown(wait=False, cancel_futures=True)` looks like
    it stops things but does neither for work already running: cancelling
    futures only drops queued-but-unstarted work, and a thread blocked in a
    synchronous smtplib call has no cooperative cancellation point — nothing
    inside it ever checks for cancellation. Verified directly: `shutdown`
    returned immediately while its one running thread kept executing, and a
    bare Python process with a non-daemon ThreadPoolExecutor thread did not
    exit until that thread finished, regardless of what the calling code had
    already decided to do.

    So this can only ever be a *best-effort* bound, never a guarantee: each
    thread is itself bounded by SmtpConfig.timeout (30s default) socket
    operations, but a transport that keeps trickling bytes just under that
    timeout, or a DNS resolution that hangs before any socket exists
    (`socket.create_connection`'s timeout does not reach `getaddrinfo`), can
    still run past this function's own budget or `SmtpConfig.timeout`
    entirely. `shutdown(wait=True)` has no timeout parameter of its own, so
    it is run on a helper thread and *that* thread is joined with a bound —
    the only way to observe "gave up waiting" with the public API rather
    than reaching into ThreadPoolExecutor internals.

    A restart that forcibly kills the process (SIGKILL, or a container
    runtime's kill-after-grace-period) is unaffected by any of this — those
    do not wait for Python to exit cleanly at all. This function only
    matters for a restart that *does* wait for the process, where it decides
    how much of that wait is spent on emails already in flight versus given
    up on cleanly.
    """
    global _executor, _interactive_executor
    pools = [
        ("SMTP executor", _executor, MAX_CONCURRENT_SENDS),
        ("interactive SMTP executor", _interactive_executor, MAX_CONCURRENT_INTERACTIVE_SENDS),
    ]
    _executor = None
    _interactive_executor = None
    pools = [(name, ex, cap) for name, ex, cap in pools if ex is not None]
    if not pools:
        return

    async def _shutdown_one(name: str, executor: ThreadPoolExecutor, cap: int, deadline: float) -> None:
        done = threading.Event()

        def _wait() -> None:
            # cancel_futures drops only queued-but-not-yet-started work — it
            # has no effect on jobs already running, which still finish or
            # hang under the bounded wait/warning below. Without it, a large
            # backlog kept every worker pulling the next queued send after
            # this function had already logged that it gave up: reproduced
            # with 20 queued 0.3s jobs on 2 workers — the wait gave up at
            # 1.0s, but the executor's own non-daemon threads did not finish
            # draining the queue until 3.0s, continuing to block process
            # exit the whole time.
            executor.shutdown(wait=True, cancel_futures=True)
            done.set()

        # Not the caller's job to keep a leaked thread alive: this helper
        # thread is itself daemonic, so if the join below times out, giving
        # up here does not add another non-daemon thread to whatever already
        # keeps the process alive.
        waiter = threading.Thread(
            target=_wait, daemon=True, name=f"{name.replace(' ', '-')}-shutdown-wait"
        )
        waiter.start()
        remaining = max(0.0, deadline - asyncio.get_running_loop().time())
        await asyncio.get_running_loop().run_in_executor(None, done.wait, remaining)
        if not done.is_set():
            logger.warning(
                "%s did not shut down within its share of %.1fs; up to %d "
                "worker thread(s) may still be sending mail and can keep a "
                "graceful shutdown alive past this bound",
                name, timeout, cap,
            )

    # Both pools share one overall deadline rather than each getting the
    # full `timeout` — shutting down sequentially with a fresh budget each
    # would let two stuck pools double the advertised bound.
    deadline = asyncio.get_running_loop().time() + timeout
    for name, executor, cap in pools:
        await _shutdown_one(name, executor, cap, deadline)


@dataclass
class SmtpConfig:
    host: str
    port: int
    username: str | None
    password: str | None
    from_addr: str
    tls_mode: str  # "none", "ssl", "starttls"
    timeout: float = DEFAULT_SMTP_TIMEOUT_SECONDS


class EmailService:
    def __init__(self, config: SmtpConfig | None):
        self._config = config

    async def send(
        self, msg: EmailMessage, recipients: list[str], *, interactive: bool = False
    ) -> None:
        """Send email. No-op if config is None.

        Runs on a dedicated bounded executor rather than asyncio's default
        one. Two reasons, both load-bearing:

        * a blocking smtplib call must not occupy a shared worker that
          unrelated features need — with an unreachable relay it holds one for
          the whole SMTP timeout;
        * the thread count is then bounded *structurally*. A semaphore around
          the await cannot do that: `asyncio.wait_for` cancels the coroutine
          and releases the semaphore, but `run_in_executor` cannot cancel the
          worker, so the thread keeps running unaccounted. Measured: 20
          concurrent threads against a cap of 4, saturating the default pool —
          the exact exhaustion the cap existed to prevent.

        `interactive=True` routes to a smaller, separate executor
        (`_interactive_send_executor`) reserved for a caller an HTTP request
        is waiting on synchronously — pass it when the caller of `send`
        cannot return a response until this completes. Everything else
        (detached forgot-password dispatch, scan-result notifications)
        shares the pool above. Without the split, a public backlog of up to
        MAX_PENDING_SENDS queued sends could leave a synchronous caller
        waiting behind all of it — reproduced at 5.45s behind just 40 queued
        jobs, unbounded in practice at the real backlog ceiling.

        `interactive=True` also applies INTERACTIVE_SEND_DEADLINE_SECONDS as
        an overall deadline on top of cfg.timeout — see that constant for
        why per-step socket timeouts alone are not a request-level bound.
        `run_in_executor`'s worker thread cannot be cancelled (smtplib has no
        cooperative cancellation point; see shutdown_send_executor), so
        `asyncio.wait_for` timing out here abandons the thread rather than
        stopping it: **the send may still complete and actually deliver the
        message after this coroutine has already raised.** It raises
        `asyncio.TimeoutError` (a plain `TimeoutError` since Python 3.11) —
        deliberately left distinguishable from every other exception this
        method can raise, rather than caught and re-raised as something
        generic, precisely so a caller with a destructive fallback (see
        send_reset_email) can tell "confirmed failed" apart from "unknown
        outcome, do not assume failure" instead of treating a timeout as
        proof no email will ever arrive.

        Abandoning the coroutine does not free the thread, though — the
        underlying smtplib call keeps running in the worker until its own
        *socket* timeout (`cfg.timeout`, admin-configurable up to
        MAX_SMTP_TIMEOUT_SECONDS) elapses, on each of connect/starttls/
        login/send_message in turn. cfg.timeout is passed straight through
        for the detached path, but here it is capped to
        INTERACTIVE_SEND_DEADLINE_SECONDS before reaching smtplib: without
        the cap, a large configured timeout (or a stalling relay under the
        30s default, per the stacking documented above) could occupy one of
        only MAX_CONCURRENT_INTERACTIVE_SENDS=2 worker threads for far
        longer than this coroutine's own deadline — two such sends exhaust
        the entire interactive pool, and every subsequent admin-initiated
        reset then queues behind them and hits its own 20s deadline without
        its email ever starting, after that admin's target password has
        already been invalidated. The deadline this coroutine waits on and
        the socket timeout the thread itself is bounded by must agree, or
        capping one leaves the other free to leak the thread regardless.
        """
        if not self._config:
            return
        cfg = self._config
        loop = asyncio.get_running_loop()
        if interactive:
            socket_timeout = min(cfg.timeout, INTERACTIVE_SEND_DEADLINE_SECONDS)
            await asyncio.wait_for(
                loop.run_in_executor(
                    _interactive_send_executor(),
                    self._send_sync, msg, recipients, cfg, socket_timeout,
                ),
                timeout=INTERACTIVE_SEND_DEADLINE_SECONDS,
            )
        else:
            await loop.run_in_executor(
                _send_executor(), self._send_sync, msg, recipients, cfg, cfg.timeout
            )

    @staticmethod
    def _send_sync(
        msg: EmailMessage, recipients: list[str], cfg: SmtpConfig, socket_timeout: float,
    ) -> None:
        if cfg.tls_mode == "ssl":
            smtp_cls = smtplib.SMTP_SSL
        else:
            smtp_cls = smtplib.SMTP
        # socket_timeout, not cfg.timeout directly: applies to the connect
        # *and* to every subsequent socket operation, so a server that
        # accepts and then stalls mid-exchange is bounded too, not just an
        # unreachable one. The interactive caller passes a value already
        # capped to its own overall deadline (see send's own docstring);
        # the detached caller passes cfg.timeout unchanged.
        with smtp_cls(cfg.host, cfg.port, timeout=socket_timeout) as smtp:
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
