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
        count, result, risks, risk_failures, sources = scan_task.run_pa_scan(tmp_path, "")
    assert count == 1
    assert result[0]["package"] == "requests"
    assert risks is None
    assert risk_failures == 0
    assert sources == []


def test_run_pa_scan_missing_risks_key_is_none_not_empty_list(tmp_path):
    """An older package-alert binary that predates risk scoring omits "risks"
    entirely from its JSON output. That must surface as None, not [], so
    update_risk_records can tell "no risk pass was reported" apart from
    "risk pass ran and found nothing" and skip closing open risk records.
    """
    output = json.dumps({"findings": [], "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        _, _, risks, _, _ = scan_task.run_pa_scan(tmp_path, "")
    assert risks is None


def test_run_pa_scan_parses_risks(tmp_path):
    risks = [{"kind": "maintainer_change", "package": "left-pad", "severity": "medium"}]
    output = json.dumps({"findings": [], "risks": risks, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        count, result, result_risks, risk_failures, sources = scan_task.run_pa_scan(tmp_path, "")
    assert count == 0
    assert result == []
    assert result_risks == risks
    assert risk_failures == 0


def test_run_pa_scan_parses_risk_failures(tmp_path):
    output = json.dumps({"findings": [], "risks": [], "risk_failures": 3, "sources": []})
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout=output, stderr="")
        count, result, risks, risk_failures, sources = scan_task.run_pa_scan(tmp_path, "")
    assert risks == []
    assert risk_failures == 3


def test_run_pa_scan_empty_findings(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = _fake_run()
        count, result, risks, risk_failures, sources = scan_task.run_pa_scan(tmp_path, "")
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
         patch("scan_task.run_pa_scan", return_value=(1, findings, [], 0, [])), \
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
         patch("scan_task.run_pa_scan", return_value=(0, [], risks, 0, [])), \
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
         patch("scan_task.run_pa_scan", return_value=(0, [], [], 2, [])), \
         patch("scan_task.post_result") as mock_post, \
         patch("tempfile.mkdtemp", return_value=str(tmp_path)):
        scan_task.main()
    mock_post.assert_called_once()
    assert mock_post.call_args[1]["risk_failures"] == 2


def test_main_cleans_up_tempdir_on_success(tmp_path):
    with patch.dict(os.environ, BASE_ENV), \
         patch("scan_task.install_pa"), \
         patch("scan_task.fetch_secret", return_value="token"), \
         patch("scan_task.clone_repo"), \
         patch("scan_task.run_pa_scan", return_value=(0, [], [], 0, [])), \
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
