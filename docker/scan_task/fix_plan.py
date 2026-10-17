"""The scan task's fix step: run `pa fix` isolated from the task's own secrets.

Runs as root up to the point of launching anything that executes repository code; every
such process runs as TRIAL_UID with a scrubbed environment, in a copy of the scanned
directory without .git, under package-alert's container isolation
(PA_SANDBOX_ISOLATION=container). See docs/fix-plans-deployment.md (requirements R1-R4).
Nothing here raises: every failure becomes a fix_plan entry, so the scan result is never lost.
"""
from __future__ import annotations

import json
import math
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import tomli_w

TRIAL_UID = 10001
TRIAL_HOME = Path("/home/pa-trial")
ERROR_LIMIT = 2048
_PASSTHROUGH = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
                "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE")
_CONFIG_DROP = ("plugins", "api_key", "server_url")


def credential_free_url(url: str) -> tuple[str, list[str]]:
    """*url* without credentials, and the values removed.

    The configured repo URL is a plain string (no user-info validation in RepoScanCreate), so it
    can carry a password or token itself. http(s): drop all user-info. The secret is the password,
    or the username when there is no password (https://TOKEN@host/...); a username next to a
    password (oauth2, x-access-token) is not secret and is not searched for, since short common
    words would match unrelated config text. ssh://: keep the user, drop a password. scp-style
    git@host:org/repo has no password syntax and is returned unchanged. Each secret is returned
    both percent-encoded (as git writes it) and decoded.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https", "ssh") or "@" not in parts.netloc:
        return url, []
    userinfo, _, hostport = parts.netloc.rpartition("@")
    user, _, password = userinfo.partition(":")
    if parts.scheme == "ssh":
        secret_parts, netloc = [password], (f"{user}@{hostport}" if user else hostport)
    else:
        secret_parts, netloc = ([password] if password else [user]), hostport
    removed: list[str] = []
    for raw in secret_parts:
        for value in (raw, unquote(raw)):
            if value and value not in removed:
                removed.append(value)
    return urlunsplit(parts._replace(netloc=netloc)), removed


def strip_remote_credentials(repo_path: Path, url: str, secrets: Sequence[str] = ()) -> bool:
    """Point origin at the credential-free form of *url*; True only if that verifiably worked.

    Checked, not assumed: the remote must read back as the clean URL, and .git/config must contain
    neither the values removed from *url* nor any of *secrets* (the separately supplied credential).
    The caller runs no fix step unless this is True.
    """
    clean, removed = credential_free_url(url)
    git = ["git", "-C", str(repo_path)]
    if subprocess.run([*git, "remote", "set-url", "origin", clean], capture_output=True, text=True,
                      check=False).returncode != 0:
        return False
    got = subprocess.run([*git, "remote", "get-url", "origin"], capture_output=True, text=True, check=False)
    if got.returncode != 0 or got.stdout.strip() != clean:
        return False
    if credential_free_url(clean)[1]:
        return False
    try:
        config = (repo_path / ".git" / "config").read_text(errors="replace")
    except OSError:
        return False
    return not any(v and v in config for v in (*removed, *secrets))


def _give(path: Path) -> None:
    """Hand one file or directory to the trial user (the task runs as root)."""
    os.lchown(path, TRIAL_UID, TRIAL_UID)


def _chown_tree(path: Path, uid: int) -> None:
    for root, dirs, files in os.walk(path):
        os.lchown(root, uid, uid)
        for name in (*dirs, *files):
            os.lchown(os.path.join(root, name), uid, uid)


def copy_project(src: Path, dest: Path) -> None:
    """Copy *src* to *dest* without any .git; links stay links (never followed out of the repo)."""
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    _chown_tree(dest, TRIAL_UID)


def strip_config(toml_text: str) -> str:
    """The config without anything pa fix does not need that could carry a secret."""
    data = tomllib.loads(toml_text)
    for key in _CONFIG_DROP:
        data.pop(key, None)
    return tomli_w.dumps(data)


def redact(text: str, secrets: list[str]) -> str:
    # Longest first, so a secret that is a prefix of another cannot leave a fragment of it.
    for s in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(s, "***")
    return text


def _trim(text: str) -> str:
    return text if len(text) <= ERROR_LIMIT else text[: ERROR_LIMIT - 1] + "…"


def _redact_tree(value: Any, secrets: list[str]) -> Any:
    """*value* with every string in it redacted: pa fix output (trial details, commands) can echo a secret."""
    if isinstance(value, str):
        return redact(value, secrets)
    if isinstance(value, list):
        return [_redact_tree(v, secrets) for v in value]
    if isinstance(value, dict):
        return {k: _redact_tree(v, secrets) for k, v in value.items()}
    return value


def _now() -> float:
    return time.monotonic()


class _Deadline:
    """The whole fix step's budget: every stage takes its timeout from what is left, with no grace."""

    def __init__(self, timeout: int) -> None:
        self.timeout = timeout
        self.start = _now()

    def elapsed(self) -> float:
        return _now() - self.start

    def stage(self, cap: float | None = None) -> float:
        """Seconds the next stage may take; TimeoutExpired once the budget is spent."""
        left = self.timeout - self.elapsed()
        if left <= 0:
            raise subprocess.TimeoutExpired("fix step", self.timeout)
        return min(cap, left) if cap is not None else left


def _finish(fields: dict, *, deadline: _Deadline, secrets: list[str]) -> dict:
    # Only the free-text parts are redacted; status, exit_code and the timings are ours, and a short
    # secret must not corrupt them.
    out = dict(fields)
    for key in ("error", "lockfile", "plan"):
        if key in out:
            out[key] = _redact_tree(out[key], secrets)
    if out.get("error") is not None:
        out["error"] = _trim(str(out["error"]))
    out.update(duration_seconds=round(deadline.elapsed(), 1), timeout_seconds=deadline.timeout)
    return out


def failed(error: str, *, timeout: int) -> dict:
    """An error before the fix step started, with the timing fields every fix_plan carries."""
    return {"status": "error", "error": _trim(error), "duration_seconds": 0.0, "timeout_seconds": timeout}


def _without_userinfo(value: str) -> str | None:
    """A proxy URL with any user:password@ removed; None when it cannot be parsed (then it is not forwarded).

    Proxy credentials are not a secret fix plans are granted: trials behind an authenticating
    proxy fail visibly (407) rather than receive them. Any scheme (http, https, socks5) and the
    scheme-less host:port form are handled.
    """
    if "@" not in value:
        return value
    has_scheme = "://" in value
    try:
        parts = urlsplit(value if has_scheme else f"http://{value}")
        clean = urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))
    except ValueError:
        return None
    return clean if has_scheme else clean.split("://", 1)[1]


def trial_env(*, uv_auth: bool) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(TRIAL_HOME),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PA_SANDBOX_ISOLATION": "container",
    }
    for key in _PASSTHROUGH:
        if key not in os.environ:
            continue
        value = _without_userinfo(os.environ[key]) if "proxy" in key.lower() else os.environ[key]
        if value is not None:
            env[key] = value
    if uv_auth:
        env["PA_RUN_OPTS"] = "--flags python:uv-auth"
    return env


def _no_constant(_name: str) -> None:
    """json.loads' parse_constant: NaN and ±Infinity become null (httpx refuses to send them)."""
    return None


def _finite_float(text: str) -> float | None:
    """json.loads' parse_float: a number that overflows to ±inf (1e999) becomes null too."""
    value = float(text)
    return value if math.isfinite(value) else None


def parse_indexes(raw: str) -> list[dict]:
    if not raw.strip():
        return []
    data = json.loads(raw)
    if not isinstance(data, list) or not all(isinstance(i, dict) and i.get("url") for i in data):
        raise ValueError("PACKAGE_INDEXES must be a JSON list of objects with a url")
    return data


def _run(argv: list[str], *, timeout: float, **kw: Any) -> subprocess.CompletedProcess:
    """subprocess.run in its own session; the whole process group is killed on timeout."""
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True, **kw)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        for s in (proc.stdout, proc.stderr):
            if s is not None:
                s.close()
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


def _bounded(fn: Callable[..., str], timeout: float, *args: Any) -> str:
    """fn(*args), waited on for at most *timeout*; TimeoutExpired past it (the deadline covers secret fetches too).

    The SDK call cannot be cancelled. It runs in a daemon thread, so a stuck call can never keep
    the scan task alive past the fix step (a ThreadPoolExecutor worker would be joined at
    interpreter exit), and scan_task.fetch_secret bounds the call itself to *timeout* in total.
    """
    box: dict[str, Any] = {}

    def work() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=work, name="pa-fetch-secret", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise subprocess.TimeoutExpired("fetch registry secret", timeout)
    if "error" in box:
        raise box["error"]
    return box["value"]


def _stage_name(cmd: Any) -> str:
    """A timed-out stage, named by its program and first two arguments (never a later one: uv auth
    login's credentials follow its URL); a non-command stage is named by its label."""
    if isinstance(cmd, (list, tuple)) and cmd:
        return " ".join([Path(str(cmd[0])).name, *(str(a) for a in cmd[1:3])])
    return str(cmd)


def _as_trial(env: dict[str, str]) -> dict[str, Any]:
    return {"env": env, "user": TRIAL_UID, "group": TRIAL_UID, "extra_groups": []}


def run_fix(repo_path: Path, scan_dir: Path, *, config_toml: str, indexes: list[dict], timeout: int,
            fetch_secret: Callable[[str, float], str]) -> dict:
    deadline = _Deadline(timeout)
    secrets: list[str] = []

    def done(**fields: Any) -> dict:
        return _finish(fields, deadline=deadline, secrets=secrets)

    pa = str(Path(sys.executable).parent / "pa")
    try:
        # Every pa process, the capability probe included, runs as the trial user with the scrubbed
        # environment: none ever sees the scan task's own credentials.
        env = trial_env(uv_auth=bool(indexes))
        probe = _run([pa, "fix", "--help"], timeout=deadline.stage(60), cwd=TRIAL_HOME, **_as_trial(env))
        if probe.returncode != 0:
            return done(status="skipped", error="the installed package-alert has no pa fix")
        # The whole repository is copied, so a path dependency outside the scanned subfolder (a uv
        # source at ../shared) is where the project expects it; pa fix runs in that subfolder.
        copy_project(repo_path, TRIAL_HOME / "work")
        work = TRIAL_HOME / "work" / scan_dir.relative_to(repo_path)
        deadline.stage()  # copying cannot be interrupted, but a budget it used up is still a timeout
        cmd = [pa, "fix", ".", "--format", "json"]
        if config_toml:
            cfg = TRIAL_HOME / "pa-config.toml"
            cfg.write_text(strip_config(config_toml))
            _give(cfg)
            cmd = [pa, "fix", "--config", str(cfg), ".", "--format", "json"]
        uv = shutil.which("uv") or "uv"
        for idx in indexes:
            if idx.get("value"):
                secret = idx["value"]
            else:
                limit = deadline.stage(60)
                secret = _bounded(fetch_secret, limit, idx.get("secret_arn") or "", limit)
            secrets.extend(dict.fromkeys([secret, quote(secret, safe="")]))
            creds = ["--username", idx["username"], "--password", secret] if idx.get("username") \
                else ["--token", secret]
            login = _run([uv, "auth", "login", idx["url"], *creds], timeout=deadline.stage(60),
                         cwd=TRIAL_HOME, **_as_trial(env))
            if login.returncode != 0:
                return done(status="error", error=f"registry login failed for {idx['url']}")
        r = _run(cmd, timeout=deadline.stage(), cwd=work, **_as_trial(env))
        if r.returncode == 2:
            status = "unsupported" if "No supported lock file" in r.stderr else "error"
            return done(status=status, exit_code=2, error=r.stderr.strip() or "pa fix exited 2")
        if r.returncode not in (0, 1):
            return done(status="error", exit_code=r.returncode, error=r.stderr.strip() or "pa fix failed")
        try:
            plan = json.loads(r.stdout, parse_constant=_no_constant, parse_float=_finite_float)
        except json.JSONDecodeError as exc:
            return done(status="error", exit_code=r.returncode, error=f"pa fix output was not JSON: {exc}")
        rel_scan = scan_dir.relative_to(repo_path)
        try:
            rel_lock = (rel_scan / Path(plan.get("lockfile", "")).relative_to(work)).as_posix()
        except ValueError:
            rel_lock = (rel_scan / Path(plan.get("lockfile", "")).name).as_posix()
        plan["lockfile"] = rel_lock
        return done(status="planned", lockfile=rel_lock, exit_code=r.returncode, plan=plan)
    except subprocess.TimeoutExpired as exc:
        # "timeout" means the budget ran out, which raising it would fix. A stage that hit its own cap
        # (the probe, a secret fetch or a registry login get 60 s) with budget left is an error naming
        # it: a bigger budget would not have helped.
        if deadline.timeout - deadline.elapsed() < 1:
            return done(status="timeout", error=f"the fix step did not finish within {timeout} s")
        return done(status="error", error=f"{_stage_name(exc.cmd)} timed out after {exc.timeout:g} s")
    except Exception as exc:  # noqa: BLE001 - the fix step must never cost the scan its result
        return done(status="error", error=f"fix step failed: {exc}")
