"""The scan task's fix step: isolation of secrets, normalisation, and never failing the scan."""
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import fix_plan


@pytest.fixture(autouse=True)
def no_chown(monkeypatch):
    # The task runs as root in the container; tests do not, so ownership changes are stubbed.
    monkeypatch.setattr(fix_plan, "_chown_tree", lambda *a: None)
    monkeypatch.setattr(fix_plan, "_give", lambda *a: None)


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "pa-trial"
    h.mkdir()
    monkeypatch.setattr(fix_plan, "TRIAL_HOME", h)
    return h


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / ".git").mkdir(parents=True)
    (r / ".git" / "config").write_text('[remote "origin"]\n\turl = https://oauth2:TOKEN@h/x\n')
    (r / "backend").mkdir()
    (r / "backend" / "uv.lock").write_text("version = 1\n")
    (r / "backend" / "pyproject.toml").write_text("[project]\nname='x'\n")
    return r


def test_trial_env_has_only_the_allowlist(monkeypatch):
    for k in ("FLEET_SYSTEM_API_KEY", "CREDENTIAL_VALUE", "AWS_SECRET_ACCESS_KEY", "ECS_CONTAINER_METADATA_URI_V4",
              "PACKAGE_INDEXES", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        monkeypatch.setenv(k, "secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
    env = fix_plan.trial_env(uv_auth=False)
    assert set(env) <= {"PATH", "HOME", "LANG", "PA_SANDBOX_ISOLATION", "PA_RUN_OPTS", "HTTPS_PROXY"}
    assert env["PA_SANDBOX_ISOLATION"] == "container"
    assert env["HTTPS_PROXY"] == "http://proxy:3128"
    assert "PA_RUN_OPTS" not in env
    assert fix_plan.trial_env(uv_auth=True)["PA_RUN_OPTS"] == "--flags python:uv-auth"


@pytest.mark.parametrize("raw, forwarded", [
    ("http://proxy:3128", "http://proxy:3128"),
    ("http://user:s3cret@proxy:3128", "http://proxy:3128"),
    ("https://s3cret@proxy.example:8443/", "https://proxy.example:8443/"),
    ("socks5://user:s3cret@proxy:1080", "socks5://proxy:1080"),
    ("user:s3cret@proxy:3128", "proxy:3128"),
    ("http://user:s3cret@[::1", None),
])
@pytest.mark.parametrize("var", ["HTTP_PROXY", "HTTPS_PROXY", "https_proxy", "http_proxy"])
def test_proxy_credentials_are_never_forwarded(monkeypatch, var, raw, forwarded):
    monkeypatch.setenv(var, raw)
    env = fix_plan.trial_env(uv_auth=False)
    assert env.get(var) == forwarded
    assert "s3cret" not in json.dumps(env)


def test_copy_excludes_git_everywhere(repo, tmp_path):
    (repo / "backend" / "sub").mkdir()
    (repo / "backend" / "sub" / ".git").write_text("gitdir: ../.git/modules/sub")
    dest = tmp_path / "work"
    fix_plan.copy_project(repo / "backend", dest)
    assert (dest / "uv.lock").exists()
    assert not (dest / "sub" / ".git").exists()
    fix_plan.copy_project(repo, tmp_path / "work2")
    assert not (tmp_path / "work2" / ".git").exists()


def test_copy_keeps_symlinks_as_links(repo, tmp_path):
    secret = tmp_path / "root-only"
    secret.write_text("AWS")
    (repo / "backend" / "creds").symlink_to(secret)
    dest = tmp_path / "work"
    fix_plan.copy_project(repo / "backend", dest)
    assert (dest / "creds").is_symlink()


def test_strip_remote_credentials(tmp_path):
    clone = tmp_path / "clone"
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "remote", "add", "origin", "https://oauth2:TOKEN@h/x"], check=True)
    assert fix_plan.strip_remote_credentials(clone, "https://h/x") is True
    url = subprocess.run(["git", "-C", str(clone), "remote", "get-url", "origin"], capture_output=True,
                         text=True, check=True).stdout.strip()
    assert "TOKEN" not in (clone / ".git" / "config").read_text()
    assert url == "https://h/x"


def test_strip_remote_credentials_reports_success(tmp_path):
    clone = tmp_path / "clone"
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "remote", "add", "origin", "https://oauth2:TOKEN@h/x"], check=True)
    assert fix_plan.strip_remote_credentials(clone, "https://h/x", ["TOKEN"]) is True


def test_strip_remote_credentials_fails_when_git_fails(tmp_path):
    assert fix_plan.strip_remote_credentials(tmp_path / "not-a-repo", "https://h/x", ["TOKEN"]) is False


def test_strip_remote_credentials_fails_when_the_token_remains(tmp_path):
    # set-url fixes origin, but another remote still carries the token.
    clone = tmp_path / "clone"
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "remote", "add", "origin", "https://oauth2:TOKEN@h/x"], check=True)
    subprocess.run(["git", "-C", str(clone), "remote", "add", "mirror", "https://oauth2:TOKEN@h/y"], check=True)
    assert fix_plan.strip_remote_credentials(clone, "https://h/x", ["TOKEN"]) is False


@pytest.mark.parametrize("url, clean, removed", [
    ("https://h/x", "https://h/x", []),
    ("https://oauth2:p%40ss@h/x", "https://h/x", ["p%40ss", "p@ss"]),
    ("https://ghp_TOKEN@github.com/o/r.git", "https://github.com/o/r.git", ["ghp_TOKEN"]),
    ("ssh://git@h/o/r.git", "ssh://git@h/o/r.git", []),
    ("ssh://git:pw@h/o/r.git", "ssh://git@h/o/r.git", ["pw"]),
    ("git@github.com:o/r.git", "git@github.com:o/r.git", []),
])
def test_credential_free_url(url, clean, removed):
    got_clean, got_removed = fix_plan.credential_free_url(url)
    assert got_clean == clean
    assert sorted(got_removed) == sorted(removed)


def test_a_credential_in_the_configured_url_is_removed(tmp_path):
    # The repo URL itself carries the token (no separate credential): cleanup must still remove it.
    clone = tmp_path / "clone"
    subprocess.run(["git", "init", "-q", str(clone)], check=True)
    subprocess.run(["git", "-C", str(clone), "remote", "add", "origin", "https://ghp_EMBEDDED@h/x"], check=True)
    assert fix_plan.strip_remote_credentials(clone, "https://ghp_EMBEDDED@h/x") is True
    assert "ghp_EMBEDDED" not in (clone / ".git" / "config").read_text()
    url = subprocess.run(["git", "-C", str(clone), "remote", "get-url", "origin"], capture_output=True,
                         text=True, check=True).stdout.strip()
    assert url == "https://h/x"


def test_strip_config_removes_central_secrets():
    out = fix_plan.strip_config('api_key = "k"\nserver_url = "u"\n[osv]\ncache_ttl_hours = 2\n'
                                '[plugins.pa-central]\napi_key = "k2"\n[fix]\nallow_major = ["django"]\n')
    assert "api_key" not in out and "server_url" not in out and "plugins" not in out
    assert "cache_ttl_hours = 2" in out and "allow_major" in out


def test_redact():
    assert fix_plan.redact("token s3cret failed s3cret", ["s3cret", ""]) == "token *** failed ***"


@pytest.mark.parametrize("raw, ok", [
    ("", True), ('[{"url":"https://a","username":null,"value":"t"}]', True),
    ("not json", False), ('{"url":"x"}', False), ('[{"username":"u"}]', False),
])
def test_parse_indexes(raw, ok):
    if ok:
        fix_plan.parse_indexes(raw)
    else:
        with pytest.raises(ValueError):
            fix_plan.parse_indexes(raw)


# --- run_fix with a fake pa ---

class FakeRun:
    """Stands in for subprocess: answers the probe, uv auth login and pa fix."""

    def __init__(self, *, probe_rc=0, fix_rc=1, fix_out=None, fix_err="", login_rc=0, login_err="",
                 timeout=False, login_timeout=False, clock=None):
        # *clock*: a patched fix_plan._now's list; a timeout first uses up the stage's whole limit.
        self.clock = clock
        self.calls = []
        self.probe_rc, self.fix_rc, self.fix_err = probe_rc, fix_rc, fix_err
        self.login_rc, self.login_err, self.timeout = login_rc, login_err, timeout
        self.login_timeout = login_timeout
        self.fix_out = fix_out if fix_out is not None else json.dumps(
            {"lockfile": "/home/pa-trial/work/uv.lock", "planned": [], "held": [], "commands": [],
             "verified": True, "unverified_reason": None})

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if argv[1:3] == ["fix", "--help"]:
            return subprocess.CompletedProcess(argv, self.probe_rc, "", "")
        if argv[1:3] == ["auth", "login"]:
            if self.login_timeout:
                self._spend(kw)
                raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))
            return subprocess.CompletedProcess(argv, self.login_rc, "", self.login_err)
        if self.timeout:
            self._spend(kw)
            raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))
        return subprocess.CompletedProcess(argv, self.fix_rc, self.fix_out, self.fix_err)

    def _spend(self, kw):
        if self.clock is not None:
            self.clock[0] += kw.get("timeout", 0)

    def fix_call(self):
        return next((a, k) for a, k in self.calls if "fix" in a and "--help" not in a)


def _run(repo, fake, **kw):
    args = {"config_toml": "", "indexes": [], "timeout": 900, "fetch_secret": lambda arn, timeout: "from-sm"}
    args.update(kw)
    with patch.object(fix_plan, "_run", fake):
        return fix_plan.run_fix(repo, repo / "backend", **args)


def test_planned_result_is_normalised(repo, home):
    fake = FakeRun(fix_out=json.dumps({"lockfile": str(home / "work" / "backend" / "uv.lock"), "planned": [],
                                       "held": [], "verified": True}))
    out = _run(repo, fake)
    assert out["status"] == "planned" and out["exit_code"] == 1
    assert out["lockfile"] == "backend/uv.lock" and out["plan"]["lockfile"] == "backend/uv.lock"
    assert out["timeout_seconds"] == 900 and isinstance(out["duration_seconds"], float)
    argv, kw = fake.fix_call()
    assert argv[-3:] == [".", "--format", "json"]
    assert kw["cwd"] == home / "work" / "backend"
    assert kw["user"] == fix_plan.TRIAL_UID and kw["extra_groups"] == []
    assert "FLEET_SYSTEM_API_KEY" not in kw["env"]


def test_every_pa_process_runs_as_the_trial_user_with_a_scrubbed_env(repo, home, monkeypatch):
    monkeypatch.setenv("FLEET_SYSTEM_API_KEY", "fleet-secret")
    monkeypatch.setenv("CREDENTIAL_VALUE", "git-secret")
    fake = FakeRun()
    _run(repo, fake, indexes=[{"url": "https://a/simple", "username": None, "value": "t"}])
    pa_calls = [(a, k) for a, k in fake.calls if Path(a[0]).name == "pa"]
    assert len(pa_calls) == 2  # the probe and pa fix
    for _argv, kw in pa_calls:
        assert kw["user"] == fix_plan.TRIAL_UID and kw["extra_groups"] == []
        assert "fleet-secret" not in json.dumps(kw["env"]) and "git-secret" not in json.dumps(kw["env"])


def test_no_pa_fix_is_skipped(repo, home):
    out = _run(repo, FakeRun(probe_rc=2))
    assert out["status"] == "skipped" and "no pa fix" in out["error"]


@pytest.mark.parametrize("stderr, status", [
    ("No supported lock file in /home/pa-trial/work: pa fix supports uv.lock", "unsupported"),
    ("Several lock files in /home/pa-trial/work (uv.lock, package-lock.json)", "error"),
])
def test_exit_2(repo, home, stderr, status):
    out = _run(repo, FakeRun(fix_rc=2, fix_out="", fix_err=stderr))
    assert out["status"] == status and out["exit_code"] == 2 and out["error"]


def _clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(fix_plan, "_now", lambda: now[0])
    return now


def test_timeout(repo, home, monkeypatch):
    out = _run(repo, FakeRun(timeout=True, clock=_clock(monkeypatch)), timeout=120)
    assert out["status"] == "timeout" and out["timeout_seconds"] == 120
    assert out["error"] == "the fix step did not finish within 120 s"


def test_a_path_dependency_outside_the_subfolder_is_in_the_copy(repo, home):
    # backend/pyproject.toml has a uv source at ../shared: the trial copy must hold it beside backend.
    (repo / "shared").mkdir()
    (repo / "shared" / "pyproject.toml").write_text("[project]\nname='shared'\n")
    (repo / "backend" / "pyproject.toml").write_text(
        "[project]\nname='x'\ndependencies=['shared']\n[tool.uv.sources]\nshared={path='../shared'}\n")
    seen = {}
    fake = FakeRun()
    real_call = fake.__call__

    def spy(argv, **kw):
        if Path(argv[0]).name == "pa" and argv[1:2] == ["fix"] and "--help" not in argv:
            cwd = Path(kw["cwd"])
            seen["cwd"] = cwd
            seen["sibling"] = (cwd / "../shared/pyproject.toml").resolve().read_text()
            seen["git"] = any(p.name == ".git" for p in (home / "work").rglob("*"))
        return real_call(argv, **kw)

    out = _run(repo, spy)
    assert out["status"] == "planned"
    assert seen["cwd"] == home / "work" / "backend"
    assert seen["sibling"] == "[project]\nname='shared'\n"
    assert seen["git"] is False  # still no .git (it holds the clone's remote)
    assert out["lockfile"] == "backend/uv.lock"


def test_non_json_is_an_error(repo, home):
    out = _run(repo, FakeRun(fix_out="Traceback ..."))
    assert out["status"] == "error"


def test_non_finite_numbers_in_the_plan_become_null(repo, home):
    # httpx refuses NaN/Infinity when encoding the post, so they must not survive parsing.
    raw = ('{"lockfile": "uv.lock", "planned": [], "held": [], "commands": [], '
           '"a": NaN, "b": Infinity, "c": -Infinity, "d": 1e999, "e": 1.5, "nested": [{"x": NaN}]}')
    out = _run(repo, FakeRun(fix_out=raw))
    assert out["status"] == "planned"
    plan = out["plan"]
    assert (plan["a"], plan["b"], plan["c"], plan["d"], plan["e"]) == (None, None, None, None, 1.5)
    assert plan["nested"] == [{"x": None}]
    json.dumps(out, allow_nan=False)  # what httpx does: must not raise


def test_an_unexpected_exception_is_an_error_not_a_crash(repo, home):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    with patch.object(fix_plan, "copy_project", boom):
        out = _run(repo, FakeRun())
    assert out["status"] == "error" and "disk full" in out["error"]


def test_config_is_stripped_and_passed(repo, home):
    fake = FakeRun()
    _run(repo, fake, config_toml='api_key = "k"\n[osv]\ncache_ttl_hours = 2\n')
    argv, _ = fake.fix_call()
    cfg = Path(argv[argv.index("--config") + 1])
    assert cfg.parent == home and "api_key" not in cfg.read_text()


def test_registry_login_runs_as_the_trial_user_before_fix(repo, home):
    fake = FakeRun()
    _run(repo, fake, indexes=[{"url": "https://a/simple", "username": "u", "value": "pw"},
                              {"url": "https://b/simple", "username": None, "secret_arn": "arn:x"}])
    logins = [(a, k) for a, k in fake.calls if a[1:3] == ["auth", "login"]]
    assert logins[0][0][3:] == ["https://a/simple", "--username", "u", "--password", "pw"]
    assert logins[1][0][3:] == ["https://b/simple", "--token", "from-sm"]
    assert all(k["user"] == fix_plan.TRIAL_UID and k["env"]["HOME"] == str(home) for _, k in logins)
    order = [a[1:3] for a, _ in fake.calls]
    assert order.index(["auth", "login"]) < len(order) - 1
    _, kw = fake.fix_call()
    assert kw["env"]["PA_RUN_OPTS"] == "--flags python:uv-auth"
    assert "pw" not in json.dumps(kw["env"]) and "from-sm" not in json.dumps(kw["env"])


def test_login_failure_never_posts_the_secret(repo, home):
    fake = FakeRun(login_rc=1, login_err="error: bad credentials pw for u@https://a")
    out = _run(repo, fake, indexes=[{"url": "https://a/simple", "username": "u", "value": "pw"}])
    assert out["status"] == "error"
    assert "registry login failed for https://a/simple" in out["error"]
    assert "pw" not in json.dumps(out)
    assert not any("fix" in a and "--help" not in a for a, _ in fake.calls)


def test_a_planned_result_is_redacted_throughout(repo, home):
    out_json = json.dumps({"lockfile": str(home / "work" / "uv.lock"), "planned": [],
                           "held": [{"package": "x", "reason": "could not verify",
                                     "detail": "401 for https://u:pw@a/simple"}],
                           "trial_failure": "auth pw rejected", "commands": [["uv", "lock", "pw"]],
                           "verified": True})
    out = _run(repo, FakeRun(fix_out=out_json),
               indexes=[{"url": "https://a/simple", "username": "u", "value": "pw"}])
    assert out["status"] == "planned"
    assert "pw" not in json.dumps(out)
    assert out["plan"]["held"][0]["detail"] == "401 for https://u:***@a/simple"


def test_a_registry_login_hitting_its_own_cap_is_a_named_error(repo, home, monkeypatch):
    # 60 s cap, 240 s of a 300 s budget left: raising the budget would not help, so not "timeout".
    fake = FakeRun(login_timeout=True, clock=_clock(monkeypatch))
    out = _run(repo, fake, indexes=[{"url": "https://a/simple", "username": None, "value": "tok-123"}], timeout=300)
    assert out["status"] == "error" and out["timeout_seconds"] == 300
    assert out["error"] == "uv auth login timed out after 60 s"
    assert not any("fix" in a and "--help" not in a for a, _ in fake.calls)


def test_a_registry_login_that_runs_out_the_budget_is_a_timeout(repo, home, monkeypatch):
    fake = FakeRun(login_timeout=True, clock=_clock(monkeypatch))
    out = _run(repo, fake, indexes=[{"url": "https://a/simple", "username": None, "value": "tok-123"}], timeout=45)
    assert out["status"] == "timeout" and out["error"] == "the fix step did not finish within 45 s"


def test_a_probe_hitting_its_cap_is_a_named_error(repo, home, monkeypatch):
    now = _clock(monkeypatch)

    def slow_probe(argv, **kw):
        if argv[1:3] == ["fix", "--help"]:
            now[0] += kw["timeout"]
            raise subprocess.TimeoutExpired(argv, kw["timeout"])
        return FakeRun()(argv, **kw)

    out = _run(repo, slow_probe)
    assert out["status"] == "error" and out["error"] == "pa fix --help timed out after 60 s"


def test_a_stage_name_never_includes_the_login_credentials():
    argv = ["/usr/bin/uv", "auth", "login", "https://a/simple", "--token", "tok-123"]
    assert fix_plan._stage_name(argv) == "uv auth login"
    assert fix_plan._stage_name("fetch registry secret") == "fetch registry secret"


def test_a_budget_spent_while_copying_is_a_timeout(repo, home, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(fix_plan, "_now", lambda: now[0])
    real_copy = fix_plan.copy_project

    def slow_copy(src, dst):
        real_copy(src, dst)
        now[0] = 1000.0

    monkeypatch.setattr(fix_plan, "copy_project", slow_copy)
    fake = FakeRun()
    out = _run(repo, fake, timeout=120)
    assert out["status"] == "timeout" and out["duration_seconds"] == 1000.0
    assert not any("fix" in a and "--help" not in a for a, _ in fake.calls)


def test_stages_never_get_more_than_the_budget_left(repo, home, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(fix_plan, "_now", lambda: now[0])
    seen = []

    def record(argv, **kw):
        seen.append(kw["timeout"])
        now[0] += 50
        return FakeRun()(argv, **kw)

    with patch.object(fix_plan, "_run", record):
        fix_plan.run_fix(repo, repo / "backend", config_toml="", indexes=[], timeout=120,
                         fetch_secret=lambda a, t: "")
    assert seen == [60, 70]  # probe capped at 60; pa fix gets exactly the 70 s left, no grace


def test_a_slow_secret_fetch_is_a_timeout(repo, home):
    import time as real_time

    def slow(arn, timeout):
        real_time.sleep(5)
        return "late"

    fake = FakeRun()
    started = real_time.monotonic()
    out = _run(repo, fake, indexes=[{"url": "https://a/simple", "username": None, "secret_arn": "arn:x"}],
               timeout=1, fetch_secret=slow)
    assert real_time.monotonic() - started < 4
    assert out["status"] == "timeout"
    assert not any(a[1:3] == ["auth", "login"] for a, _ in fake.calls)
    import threading
    stuck = [t for t in threading.enumerate() if t.name == "pa-fetch-secret"]
    assert stuck and all(t.daemon for t in stuck)  # cannot keep the scan task alive at exit


def test_the_secret_fetch_gets_the_remaining_budget(repo, home, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(fix_plan, "_now", lambda: now[0])
    seen = []

    def record(argv, **kw):
        now[0] += 100
        return FakeRun()(argv, **kw)

    with patch.object(fix_plan, "_run", record):
        fix_plan.run_fix(repo, repo / "backend", config_toml="", indexes=[
            {"url": "https://a/simple", "username": None, "secret_arn": "arn:x"}], timeout=150,
            fetch_secret=lambda arn, timeout: seen.append(timeout) or "s")
    assert seen == [50]  # 150 s budget, 100 s used by the probe: the fetch may take only 50


def test_failed_carries_the_timing_fields():
    out = fix_plan.failed("x" * 5000, timeout=600)
    assert out["status"] == "error" and out["timeout_seconds"] == 600 and out["duration_seconds"] == 0.0
    assert len(out["error"]) <= fix_plan.ERROR_LIMIT


def test_fix_stderr_is_redacted_and_truncated(repo, home):
    long_err = "pw " + "x" * 5000
    out = _run(repo, FakeRun(fix_rc=2, fix_out="", fix_err=long_err),
               indexes=[{"url": "https://a/simple", "username": "u", "value": "pw"}])
    assert "pw" not in out["error"] and len(out["error"]) <= fix_plan.ERROR_LIMIT


def test_a_short_secret_never_corrupts_controlled_fields(repo, home):
    fake = FakeRun(login_timeout=True)
    out = _run(repo, fake, indexes=[{"url": "https://a/simple", "username": None, "value": "t"}], timeout=300)
    assert out["status"] == "error" and out["timeout_seconds"] == 300
    out = _run(repo, FakeRun(fix_rc=2, fix_out="", fix_err="bad t token"),
               indexes=[{"url": "https://a/simple", "username": None, "value": "t"}])
    assert out["status"] == "error" and out["error"] == "bad *** ***oken"



def test_overlapping_secrets_are_redacted_longest_first():
    assert fix_plan.redact("x abcdef y", ["abc", "abcdef"]) == "x *** y"


def test_a_percent_encoded_secret_is_redacted(repo, home):
    out = _run(repo, FakeRun(fix_rc=2, fix_out="", fix_err="401 for https://u:p%40ss%2Fx@a/simple"),
               indexes=[{"url": "https://a/simple", "username": "u", "value": "p@ss/x"}])
    assert "p%40ss%2Fx" not in out["error"] and "p@ss/x" not in out["error"]


def test_the_top_level_lockfile_is_redacted(repo, home):
    out_json = json.dumps({"lockfile": str(home / "work" / "backend" / "s3cr3t" / "uv.lock"), "planned": [],
                           "held": [], "verified": True})
    out = _run(repo, FakeRun(fix_out=out_json),
               indexes=[{"url": "https://a/simple", "username": "u", "value": "s3cr3t"}])
    assert out["status"] == "planned"
    assert out["lockfile"] == "backend/***/uv.lock"
    assert "s3cr3t" not in json.dumps(out)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A zombie still answers kill(0); it has been killed, it is only waiting to be reaped.
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def test_a_timeout_kills_the_whole_process_group(tmp_path):
    """Spec: timeout -> whole process group killed (a sleeping grandchild is gone afterwards).

    Runs the real _run with no user switch. _run is called on a worker thread so a mutant that
    no longer kills the group (and so waits on the shell forever) fails the test instead of hanging
    it; the finally kills the whole group whatever happens, leaving no stray processes.
    """
    pid_file = tmp_path / "pid"
    outcome: dict = {}

    def call() -> None:
        try:
            fix_plan._run(["sh", "-c", f"sleep 300 & echo $$ $! > {pid_file}; sleep 300"], timeout=1)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion below
            outcome["exc"] = exc

    def pids() -> tuple[int, int] | None:
        try:
            pgid, child = pid_file.read_text().split()
            return int(pgid), int(child)
        except (OSError, ValueError):
            return None

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    try:
        worker.join(15)
        assert not worker.is_alive(), "_run did not return after its timeout"
        assert isinstance(outcome.get("exc"), subprocess.TimeoutExpired)
        found = pids()
        assert found is not None
        end = time.monotonic() + 5
        while _alive(found[1]) and time.monotonic() < end:
            time.sleep(0.05)
        assert not _alive(found[1]), "the sleeping grandchild survived the timeout"
    finally:
        found = pids()
        if found is not None:
            try:
                os.killpg(found[0], signal.SIGKILL)
            except ProcessLookupError:
                pass
        worker.join(5)
