"""Unit tests for scan_task.py — all AWS/subprocess calls are mocked."""
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add parent dir so we can import scan_task
sys.path.insert(0, str(Path(__file__).parent.parent))
import scan_task

BASE_ENV = {
    "PA_VERSION": "1.2.3",
    "REPO_SCAN_RESULT_ID": "42",
    "REPO_URL": "https://github.com/example/repo.git",
    "BRANCH": "main",
    "CREDENTIAL_TYPE": "https_token",
    "CREDENTIAL_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:000:secret:test",
    "FLEET_API_URL": "http://fleet.internal",
    "FLEET_SYSTEM_API_KEY": "pa_testkey",
    "PA_CONFIG_TOML": "",
}


def test_require_env_raises_when_missing():
    with pytest.raises(RuntimeError, match="PA_VERSION"):
        with patch.dict(os.environ, {}, clear=True):
            scan_task.require_env("PA_VERSION")


def test_require_env_returns_value():
    with patch.dict(os.environ, {"MY_VAR": "hello"}):
        assert scan_task.require_env("MY_VAR") == "hello"



def test_install_pa_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        scan_task.install_pa("1.2.3")
        assert "package-alert==1.2.3" in " ".join(mock_run.call_args[0][0])


def test_install_pa_latest_when_no_version():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        scan_task.install_pa("")
        cmd = " ".join(mock_run.call_args[0][0])
        assert "package-alert" in cmd
        assert "==" not in cmd


def test_install_pa_failure_raises():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="No matching distribution")
        with pytest.raises(RuntimeError, match="pip install failed"):
            scan_task.install_pa("9.9.9")


def test_clone_repo_none_rejects_ssh_url():
    with pytest.raises(RuntimeError, match="credential_type is 'none'"):
        scan_task.clone_repo(
            "git@github.com:example/repo.git", "main",
            Path("/tmp/test/repo"), "none", ""
        )


def test_clone_repo_none_clones_without_auth():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        scan_task.clone_repo(
            "https://github.com/example/public-repo.git", "main",
            Path("/tmp/test/repo"), "none", ""
        )
        cmd = " ".join(mock_run.call_args[0][0])
        assert "git clone" in cmd
        assert "oauth2" not in cmd
        assert "GIT_SSH_COMMAND" not in mock_run.call_args[1].get("env", {})


def test_clone_repo_https_injects_token():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        scan_task.clone_repo(
            "https://github.com/example/repo.git", "main",
            Path("/tmp/test/repo"), "https_token", "ghp_token123"
        )
        cmd = " ".join(mock_run.call_args[0][0])
        assert "ghp_token123" in cmd
        assert "git clone" in cmd


def test_clone_repo_ssh_sets_git_ssh_command(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        dest = tmp_path / "repo"
        scan_task.clone_repo(
            "git@github.com:example/repo.git", "main",
            dest, "ssh_key", "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        )
        env = mock_run.call_args[1]["env"]
        assert "GIT_SSH_COMMAND" in env
        assert "StrictHostKeyChecking=no" in env["GIT_SSH_COMMAND"]
        # SSH key file should be cleaned up
        assert not (tmp_path / "id_rsa").exists()


def test_clone_repo_ssh_with_passphrase_strips_it(tmp_path):
    import json as _json
    secret = _json.dumps({"key": "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----", "passphrase": "hunter2"})
    dest = tmp_path / "repo"

    def fake_run(cmd, **kwargs):
        m = MagicMock()
        if "ssh-keygen" in cmd:
            m.returncode = 0
            m.stderr = ""
        else:
            m.returncode = 0
            m.stderr = ""
        return m

    with patch("subprocess.run", side_effect=fake_run) as mock_run:
        scan_task.clone_repo("git@github.com:example/repo.git", "main", dest, "ssh_key", secret)

    calls = mock_run.call_args_list
    keygen_call = next(c for c in calls if "ssh-keygen" in c[0][0])
    assert "-P" in keygen_call[0][0]
    assert "hunter2" in keygen_call[0][0]


def test_clone_repo_ssh_passphrase_strip_failure_raises(tmp_path):
    import json as _json
    secret = _json.dumps({"key": "-----BEGIN RSA PRIVATE KEY-----\ntest", "passphrase": "wrong"})
    dest = tmp_path / "repo"

    def fake_run(cmd, **kwargs):
        m = MagicMock()
        if "ssh-keygen" in cmd:
            m.returncode = 1
            m.stderr = "incorrect passphrase"
        else:
            m.returncode = 0
            m.stderr = ""
        return m

    with patch("subprocess.run", side_effect=fake_run):
        with pytest.raises(RuntimeError, match="SSH key passphrase is incorrect"):
            scan_task.clone_repo("git@github.com:example/repo.git", "main", dest, "ssh_key", secret)


def test_clone_repo_failure_raises():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=128, stderr="Authentication failed")
        with pytest.raises(RuntimeError, match="git clone failed"):
            scan_task.clone_repo(
                "https://github.com/example/repo.git", "main",
                Path("/tmp/repo"), "https_token", "bad_token"
            )


def _fake_run(output='{"findings": [], "sources": []}', returncode=0):
    return MagicMock(returncode=returncode, stdout=output, stderr="")


def test_run_pa_scan_parses_json_output(tmp_path):
    findings = [{"package": "requests", "severity": "high", "advisory_id": "GHSA-x"}]
    output = json.dumps({"findings": findings, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=output, stderr="")
        count, result, risks, risk_failures, _, sources, _ = scan_task.run_pa_scan(tmp_path, "")
    assert count == 1
    assert result[0]["package"] == "requests"
    assert risks is None
    assert risk_failures == 0
    assert sources == []


def test_run_pa_scan_subprocess_gets_only_an_allow_listed_environment(tmp_path):
    """pa scan-project must not inherit the task's secrets (least privilege), but keeps proxy/TLS vars."""
    secrets = {
        "FLEET_SYSTEM_API_KEY": "k", "CREDENTIAL_VALUE": "c", "AWS_SECRET_ACCESS_KEY": "s",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/x",
        "ECS_CONTAINER_METADATA_URI_V4": "http://169.254.170.2/v4/x", "PACKAGE_INDEXES": "[]",
        "CREDENTIAL_SECRET_ARN": "arn", "FIX_PLAN": "1",
    }
    env = {"PATH": "/usr/bin", "HOME": "/root", "HTTPS_PROXY": "http://user:pw@proxy:3128",
           "SSL_CERT_FILE": "/etc/ca.pem", **secrets}
    with patch.dict(os.environ, env, clear=True), patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(tmp_path, "")
    passed = mock_run.call_args.kwargs["env"]
    assert not set(secrets) & set(passed)
    assert passed["PATH"] == "/usr/bin" and passed["HOME"] == "/root"
    assert passed["HTTPS_PROXY"] == "http://user:pw@proxy:3128"
    assert passed["SSL_CERT_FILE"] == "/etc/ca.pem"


def test_run_pa_scan_missing_risks_key_is_none_not_empty_list(tmp_path):
    """An older package-alert binary that predates risk scoring omits "risks"
    entirely from its JSON output. That must surface as None, not [], so
    update_risk_records can tell "no risk pass was reported" apart from
    "risk pass ran and found nothing" and skip closing open risk records.
    """
    output = json.dumps({"findings": [], "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        _, _, risks, _, _, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert risks is None


def test_run_pa_scan_parses_risks(tmp_path):
    risks = [{"kind": "maintainer_change", "package": "left-pad", "severity": "medium"}]
    output = json.dumps({"findings": [], "risks": risks, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        count, result, result_risks, risk_failures, _, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert count == 0
    assert result == []
    assert result_risks == risks
    assert risk_failures == 0


def test_run_pa_scan_parses_risk_failures(tmp_path):
    output = json.dumps({"findings": [], "risks": [], "risk_failures": 3, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        _, _, risks, risk_failures, _, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert risks == []
    assert risk_failures == 3


def test_run_pa_scan_parses_osv_failures(tmp_path):
    output = json.dumps({"findings": [], "osv_failures": 5, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        _, _, _, _, osv_failures, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert osv_failures == 5


def test_run_pa_scan_missing_osv_failures_defaults_to_zero(tmp_path):
    output = json.dumps({"findings": [], "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        _, _, _, _, osv_failures, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert osv_failures == 0


def test_run_pa_scan_empty_findings(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        count, result, risks, risk_failures, _, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert count == 0
    assert result == []
    assert risks is None
    assert risk_failures == 0


def test_run_pa_scan_passes_config_flag(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(tmp_path, "[osv]\ncache_ttl_hours = 12")
        cmd = " ".join(mock_run.call_args[0][0])
        assert "--config" in cmd


def test_run_pa_scan_no_config_flag_when_empty(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(tmp_path, "")
        cmd = " ".join(mock_run.call_args[0][0])
        assert "--config" not in cmd


# ── subfolder path handling ────────────────────────────────────────────────────

def test_run_pa_scan_no_subfolder_uses_repo_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(repo, "")
    cmd = mock_run.call_args[0][0]
    assert cmd[-1] == str(repo.resolve())


def test_run_pa_scan_subfolder_appended_as_path(tmp_path):
    repo = tmp_path / "repo"
    sub = repo / "backend"
    sub.mkdir(parents=True)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(repo, "", subfolder="backend")
    cmd = mock_run.call_args[0][0]
    assert cmd[-1] == str(sub.resolve())


def test_run_pa_scan_nested_subfolder(tmp_path):
    repo = tmp_path / "repo"
    sub = repo / "a" / "b"
    sub.mkdir(parents=True)
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(repo, "", subfolder="a/b")
    cmd = mock_run.call_args[0][0]
    assert cmd[-1] == str(sub.resolve())


def test_run_pa_scan_dotdot_subfolder_raises(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(RuntimeError, match="escapes the repository"):
        scan_task.run_pa_scan(repo, "", subfolder="..")


def test_run_pa_scan_symlink_escaping_repo_raises(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = repo / "escape"
    link.symlink_to(outside)
    with pytest.raises(RuntimeError, match="escapes the repository"):
        scan_task.run_pa_scan(repo, "", subfolder="escape")


# ── scan_flags passthrough ─────────────────────────────────────────────────────

def test_run_pa_scan_flags_appended_before_path(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(repo, "", scan_flags="--scan-unpinned")
    cmd = mock_run.call_args[0][0]
    unpinned_idx = cmd.index("--scan-unpinned")
    path_idx = cmd.index(str(repo.resolve()))
    assert unpinned_idx < path_idx


def test_run_pa_scan_non_json_output_raises_runtime_error(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run(output="Traceback (most recent call last):\n  crash")
        with pytest.raises(RuntimeError, match="not valid JSON"):
            scan_task.run_pa_scan(repo, "")


def test_run_pa_scan_invalid_scan_flags_raises_runtime_error(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(RuntimeError, match="invalid scan_flags quoting"):
        scan_task.run_pa_scan(repo, "", scan_flags="--requirements='unterminated")


def test_run_pa_scan_format_json_always_present(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        scan_task.run_pa_scan(repo, "", scan_flags="--scan-unpinned")
    cmd = mock_run.call_args[0][0]
    assert "--format" in cmd
    assert "json" in cmd


def test_main_pip_failure_posts_failed_result():
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa", side_effect=RuntimeError("pip install failed: no dist")), \
         patch("scan_task.post_result") as mock_post:
        scan_task.main()
    mock_post.assert_called_once()
    call_args = mock_post.call_args
    assert call_args[0][3] == "failed"
    assert "pip install failed" in call_args[1]["error_message"]


def test_main_clone_failure_posts_failed_result():
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo", side_effect=RuntimeError("git clone failed: auth")), \
         patch("scan_task.post_result") as mock_post:
        scan_task.main()
    assert mock_post.call_args[0][3] == "failed"
    assert "git clone failed" in mock_post.call_args[1]["error_message"]


def test_main_scan_failure_posts_failed_result(tmp_path):
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", side_effect=RuntimeError("scan error")), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    assert mock_post.call_args[0][3] == "failed"


def test_main_success_posts_success_result(tmp_path):
    findings = [{"package": "flask", "severity": "medium"}]
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(1, findings, [], 0, 0, [], None)), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_post.assert_called_once()
    assert mock_post.call_args[0][3] == "success"
    assert mock_post.call_args[1]["finding_count"] == 1
    assert mock_post.call_args[1]["findings"] == findings


def test_main_success_forwards_risks(tmp_path):
    risks = [{"kind": "maintainer_change", "package": "left-pad", "severity": "medium"}]
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(0, [], risks, 0, 0, [], None)), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_post.assert_called_once()
    assert mock_post.call_args[1]["risks"] == risks


def test_main_success_forwards_risk_failures(tmp_path):
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(0, [], [], 2, 0, [], None)), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_post.assert_called_once()
    assert mock_post.call_args[1]["risk_failures"] == 2


def test_main_success_forwards_osv_failures(tmp_path):
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(0, [], [], 0, 5, [], None)), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_post.assert_called_once()
    assert mock_post.call_args[1]["osv_failures"] == 5


def test_main_cleans_up_tempdir_on_success(tmp_path):
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(0, [], [], 0, 0, [], None)), \
         patch("scan_task.post_result"), \
         patch("shutil.rmtree") as mock_rm, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    # workdir is constructed as Path(mkdtemp(...)) so compare as Path
    mock_rm.assert_called_once_with(Path(str(tmp_path)), ignore_errors=True)


def test_main_cleans_up_tempdir_on_failure(tmp_path):
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa", side_effect=RuntimeError("fail")), \
         patch("scan_task.post_result"), \
         patch("shutil.rmtree") as mock_rm, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_rm.assert_called_once_with(Path(str(tmp_path)), ignore_errors=True)


def test_run_pa_scan_parses_remediations(tmp_path):
    remediations = [{
        "package": "django", "ecosystem": "PyPI", "version": "5.2.15",
        "advisories": [{"id": "GHSA-a", "aliases": ["PYSEC-1"]}],
        "recommended_version": "5.2.17", "unfixed_advisory_ids": [],
        "major_upgrade": False, "verified": True,
        "recommended_age_days": None, "in_cooldown": None,
    }]
    output = json.dumps({"findings": [], "remediations": remediations, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout=output, stderr="")
        *_, result_remediations = scan_task.run_pa_scan(tmp_path, "")
    assert result_remediations == remediations


def test_run_pa_scan_missing_remediations_is_none(tmp_path):
    """package-alert < 0.9.0 has no "remediations" key. That must stay None
    (not []) so post_result omits it and the server stores NULL, which the UI
    reads as "no advice available" rather than "no vulnerable packages"."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        *_, remediations = scan_task.run_pa_scan(tmp_path, "")
    assert remediations is None


def test_run_pa_scan_non_list_remediations_is_none(tmp_path):
    output = json.dumps({"findings": [], "remediations": {"oops": 1}, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        *_, remediations = scan_task.run_pa_scan(tmp_path, "")
    assert remediations is None


def test_main_success_forwards_remediations(tmp_path):
    remediations = [{"package": "flask", "recommended_version": "3.0.1"}]
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(0, [], [], 0, 0, [], remediations)), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_post.assert_called_once()
    assert mock_post.call_args[1]["remediations"] == remediations


def test_post_result_includes_remediations_when_given():
    with patch("httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=204, raise_for_status=lambda: None)
        scan_task.post_result("http://f", "k", 1, "success", remediations=[{"package": "a"}])
    assert mock_post.call_args[1]["json"]["remediations"] == [{"package": "a"}]


def test_post_result_omits_remediations_when_none():
    with patch("httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=204, raise_for_status=lambda: None)
        scan_task.post_result("http://f", "k", 1, "success")
    assert "remediations" not in mock_post.call_args[1]["json"]


# --- fix plans wiring ---

def _main_with(monkeypatch, *, fix_plans, finding_count, fix_result=None, remote_clean=True):
    monkeypatch.setenv("FIX_PLANS", fix_plans)
    monkeypatch.setenv("FIX_PLAN_TIMEOUT", "600")
    posted = {}
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: remote_clean)
    monkeypatch.setattr(scan_task, "run_pa_scan",
                        lambda *a, **k: (finding_count, [], [], 0, 0, [], None))
    result = fix_result or {"status": "planned"}
    monkeypatch.setattr(scan_task.fix_plan, "run_fix", lambda *a, **k: result)
    monkeypatch.setattr(scan_task, "post_result", lambda *a, **k: posted.update(k, status=a[3]))
    scan_task.main()
    return posted


def test_fix_runs_only_when_enabled_and_findings(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    assert _main_with(monkeypatch, fix_plans="1", finding_count=2)["fix_plan"] == {"status": "planned"}
    assert _main_with(monkeypatch, fix_plans="1", finding_count=0).get("fix_plan") is None
    assert _main_with(monkeypatch, fix_plans="", finding_count=2).get("fix_plan") is None


def test_fix_error_still_posts_success(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    posted = _main_with(monkeypatch, fix_plans="1", finding_count=1,
                        fix_result={"status": "error", "error": "x"})
    assert posted["status"] == "success" and posted["fix_plan"]["status"] == "error"


def test_an_unclean_remote_skips_the_fix_step(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    ran = []
    monkeypatch.setattr(scan_task.fix_plan, "run_fix", lambda *a, **k: ran.append(1))
    posted = _main_with(monkeypatch, fix_plans="1", finding_count=1, remote_clean=False)
    assert posted["status"] == "success"
    assert posted["fix_plan"]["status"] == "error" and "remote URL" in posted["fix_plan"]["error"]
    assert posted["fix_plan"]["timeout_seconds"] == 600 and "duration_seconds" in posted["fix_plan"]


def test_a_malformed_package_indexes_error_carries_timing_fields(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PACKAGE_INDEXES", "not json")
    monkeypatch.setenv("FIX_PLANS", "1")
    monkeypatch.setenv("FIX_PLAN_TIMEOUT", "600")
    posted = {}
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: True)
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, [], [], 0, 0, [], None))
    monkeypatch.setattr(scan_task, "post_result", lambda *a, **k: posted.update(k, status=a[3]))
    scan_task.main()
    fp = posted["fix_plan"]
    assert fp["status"] == "error" and fp["timeout_seconds"] == 600 and fp["duration_seconds"] == 0.0


def test_fetch_secret_bounds_the_sdk_call_when_given_a_timeout():
    with patch("boto3.client") as client:
        client.return_value.get_secret_value.return_value = {"SecretString": "s"}
        assert scan_task.fetch_secret("arn:x", timeout=12.0) == "s"
        cfg = client.call_args.kwargs["config"]
        assert cfg.read_timeout + cfg.connect_timeout <= 12.0
        assert cfg.retries == {"total_max_attempts": 1}
        scan_task.fetch_secret("arn:y")
        assert client.call_args.kwargs.get("config") is None


def test_post_result_includes_or_omits_fix_plan():
    with patch("httpx.post") as post:
        post.return_value.raise_for_status = lambda: None
        scan_task.post_result("u", "k", 1, "success", fix_plan={"status": "planned"})
        assert post.call_args.kwargs["json"]["fix_plan"] == {"status": "planned"}
        scan_task.post_result("u", "k", 1, "success")
        assert "fix_plan" not in post.call_args.kwargs["json"]


def test_a_non_numeric_fix_plan_timeout_falls_back_to_900(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("FIX_PLAN_TIMEOUT", "abc")
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: False)
    posted = {}
    monkeypatch.setattr(scan_task, "post_result", lambda *a, **k: posted.update(k))
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, [], [], 0, 0, [], None))
    monkeypatch.setenv("FIX_PLANS", "1")
    scan_task.main()
    assert posted["fix_plan"]["timeout_seconds"] == 900


def test_subfolder_reaches_run_fix_as_scan_dir(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PA_SUBFOLDER", "backend")
    got = {}
    monkeypatch.setattr(scan_task.fix_plan, "run_fix",
                        lambda repo, scan_dir, **k: got.update(repo=repo, scan_dir=scan_dir) or {"status": "planned"})
    monkeypatch.setenv("FIX_PLANS", "1")
    posted = {}
    monkeypatch.setattr(scan_task, "post_result", lambda *a, **k: posted.update(k))
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: True)
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, [], [], 0, 0, [], None))
    scan_task.main()
    assert got["scan_dir"].name == "backend"
    assert got["scan_dir"].parent.resolve() == got["repo"].resolve()


def test_an_unexpected_run_fix_exception_still_posts_success(monkeypatch):
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(scan_task.fix_plan, "run_fix", boom)
    posted = {}
    monkeypatch.setenv("FIX_PLANS", "1")
    monkeypatch.setattr(scan_task, "post_result", lambda *a, **k: posted.update(k, status=a[3]))
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: True)
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, [], [], 0, 0, [], None))
    scan_task.main()
    assert posted["status"] == "success" and posted["fix_plan"]["status"] == "error"
    assert "kaboom" in posted["fix_plan"]["error"]


@pytest.mark.parametrize("subfolder", ["", "backend"])
def test_run_fix_gets_resolved_paths_when_the_workdir_is_behind_a_symlink(monkeypatch, tmp_path, subfolder):
    # On hosts where /tmp is a symlink, an unresolved scan_dir against a resolved repo_path makes
    # run_fix's scan_dir.relative_to(repo_path) fail; both must be resolved.
    real = tmp_path / "real"
    (real / "repo" / "backend").mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PA_SUBFOLDER", subfolder)
    got = {}
    monkeypatch.setattr(scan_task.fix_plan, "run_fix",
                        lambda repo, scan_dir, **k: got.update(repo=repo, scan_dir=scan_dir) or {"status": "planned"})
    monkeypatch.setenv("FIX_PLANS", "1")
    monkeypatch.setattr(scan_task, "post_result", lambda *a, **k: None)
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: True)
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, [], [], 0, 0, [], None))
    with patch("tempfile.mkdtemp", return_value=str(link)):
        scan_task.main()
    assert got["repo"] == (real / "repo").resolve()
    assert got["scan_dir"].relative_to(got["repo"]) == Path(subfolder)


# --- a fix plan pa-central rejects must not cost the scan its result ---

def _http_error(status):
    import httpx

    req = httpx.Request("POST", "http://f/api/ingest/repo-scan-result")
    return httpx.HTTPStatusError("boom", request=req, response=httpx.Response(status, request=req, text="SECRET-BODY"))


def _run_main_posting(monkeypatch, responses, *, fix_plans="1"):
    """main() with httpx.post patched: each entry of *responses* is an HTTP status for one post (204 = ok)."""
    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("FIX_PLANS", fix_plans)
    monkeypatch.setenv("FIX_PLAN_TIMEOUT", "600")
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: True)
    findings = [{"package": "flask"}]
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, findings, [], 0, 0, [], None))
    monkeypatch.setattr(scan_task.fix_plan, "run_fix", lambda *a, **k: {"status": "planned", "plan": {"x": 1}})
    statuses = iter(responses)

    def fake_post(url, **kw):
        status = next(statuses)

        def raise_for_status():
            if status >= 400:
                raise _http_error(status)
        return MagicMock(status_code=status, raise_for_status=raise_for_status)

    with patch("httpx.post", side_effect=fake_post) as mock_post:
        try:
            scan_task.main()
        except Exception as exc:  # noqa: BLE001
            return mock_post, exc
    return mock_post, None


@pytest.mark.parametrize("status", [400, 413, 422])
def test_rejected_fix_plan_is_replaced_by_an_error_and_reposted(monkeypatch, status):
    mock_post, exc = _run_main_posting(monkeypatch, [status, 204])
    assert exc is None
    assert mock_post.call_count == 2
    first, second = (c.kwargs["json"] for c in mock_post.call_args_list)
    assert first["fix_plan"]["status"] == "planned"
    assert second["status"] == "success" and second["findings"] == first["findings"] == [{"package": "flask"}]
    assert second["finding_count"] == first["finding_count"]
    assert second["fix_plan"]["status"] == "error"
    assert f"HTTP {status}" in second["fix_plan"]["error"]
    assert second["fix_plan"]["timeout_seconds"] == 600
    assert "SECRET-BODY" not in second["fix_plan"]["error"]


def test_a_plan_httpx_cannot_encode_is_replaced_by_an_error_and_posted(monkeypatch):
    # Real httpx encoding (only the transport is stubbed): a non-finite number is refused locally,
    # before anything is sent, so the HTTP-status fallback alone would have lost the scan result.
    import httpx

    for k, v in BASE_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("FIX_PLANS", "1")
    monkeypatch.setenv("FIX_PLAN_TIMEOUT", "600")
    monkeypatch.setattr(scan_task, "fetch_secret", lambda *a, **k: "token")  # never real AWS
    monkeypatch.setattr(scan_task, "install_pa", lambda v: None)
    monkeypatch.setattr(scan_task, "clone_repo", lambda *a, **k: None)
    monkeypatch.setattr(scan_task.fix_plan, "strip_remote_credentials", lambda *a: True)
    monkeypatch.setattr(scan_task, "run_pa_scan", lambda *a, **k: (1, [{"package": "flask"}], [], 0, 0, [], None))
    monkeypatch.setattr(scan_task.fix_plan, "run_fix",
                        lambda *a, **k: {"status": "planned", "plan": {"duration": float("nan")}})
    sent = []

    def handle(self, request):
        sent.append(json.loads(request.content))
        return httpx.Response(204, request=request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)
    scan_task.main()
    assert len(sent) == 1, sent  # the first post never left the process
    assert sent[0]["status"] == "success", sent[0].get("error_message")
    assert sent[0]["status"] == "success" and sent[0]["findings"] == [{"package": "flask"}]
    assert sent[0]["fix_plan"]["status"] == "error"
    assert sent[0]["fix_plan"]["error"] == "the fix plan could not be encoded as JSON"


def test_a_5xx_is_not_retried(monkeypatch):
    mock_post, exc = _run_main_posting(monkeypatch, [500, 204])
    assert mock_post.call_count == 1 and exc is not None


def test_a_4xx_without_a_fix_plan_is_not_retried(monkeypatch):
    mock_post, exc = _run_main_posting(monkeypatch, [400, 204], fix_plans="")
    assert mock_post.call_count == 1 and exc is not None


def test_the_retry_happens_only_once(monkeypatch):
    mock_post, exc = _run_main_posting(monkeypatch, [400, 400, 204])
    assert mock_post.call_count == 2 and exc is not None
