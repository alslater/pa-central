#!/usr/bin/env python3
"""
PA Central scan task — runs inside an ephemeral ECS Fargate container.

Reads configuration from environment variables, installs package-alert,
clones the target repository, runs pa scan-project, and POSTs the result
back to the fleet API.

Environment variables (all required unless noted):
  PA_VERSION              — PyPI version of package-alert to install
  REPO_SCAN_RESULT_ID     — PK of the RepoScanResult row to update
  REPO_URL                — git clone URL (https or ssh)
  BRANCH                  — branch to clone
  CREDENTIAL_TYPE         — "https_token", "ssh_key", or "none"
  CREDENTIAL_SECRET_ARN   — Secrets Manager ARN for the credential (mutually exclusive with CREDENTIAL_VALUE)
  CREDENTIAL_VALUE        — Raw credential value (used in local Docker mode instead of Secrets Manager)
  FLEET_API_URL           — base URL of the fleet app
  FLEET_SYSTEM_API_KEY    — API key for fleet app authentication
  PA_CONFIG_TOML          — (optional) TOML config content for pa scan-project
  PA_SCAN_FLAGS           — (optional) shell-quoted CLI args for pa scan-project (--flag=value form, split via shlex)
  PA_SUBFOLDER            — (optional) repo subdirectory to scan (relative path; defaults to repo root)
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# ── Environment ───────────────────────────────────────────────────────────────

def require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise RuntimeError(f"Required env var {name} is not set")
    return val


def get_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


# ── Secrets Manager ───────────────────────────────────────────────────────────

def fetch_secret(arn: str) -> str:
    import boto3
    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=arn)
    return resp["SecretString"]


# ── Fleet API ─────────────────────────────────────────────────────────────────

def post_result(
    fleet_url: str,
    api_key: str,
    result_id: int,
    status: str,
    pa_version: str | None = None,
    finding_count: int = 0,
    findings: list[dict] | None = None,
    sources: list[str] | None = None,
    error_message: str | None = None,
) -> None:
    import httpx
    payload: dict[str, Any] = {
        "repo_scan_result_id": result_id,
        "status": status,
        "finding_count": finding_count,
    }
    if pa_version:
        payload["pa_version"] = pa_version
    if findings is not None:
        payload["findings"] = findings
    if sources is not None:
        payload["sources"] = sources
    if error_message:
        payload["error_message"] = error_message

    r = httpx.post(
        f"{fleet_url}/api/ingest/repo-scan-result",
        json=payload,
        headers={"X-API-Key": api_key},
        timeout=30,
    )
    r.raise_for_status()


# ── Package-Alert installation ─────────────────────────────────────────────────

def install_pa(version: str) -> None:
    pkg = f"package-alert=={version}" if version else "package-alert"
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pip install failed: {result.stderr}")


# ── Git clone ──────────────────────────────────────────────────────────────────

def clone_repo(
    url: str,
    branch: str,
    dest: Path,
    credential_type: str,
    credential: str,
) -> None:
    env = os.environ.copy()

    if credential_type == "https_token":
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        authed_url = urlunparse(parsed._replace(
            netloc=f"oauth2:{credential}@{parsed.netloc}"
        ))
        clone_url = authed_url
    elif credential_type == "ssh_key":
        # Secret may be a bare PEM string or JSON {"key": ..., "passphrase": ...}
        passphrase: str | None = None
        try:
            parsed = json.loads(credential)
            raw_key = parsed["key"]
            passphrase = parsed.get("passphrase") or None
        except (json.JSONDecodeError, KeyError):
            raw_key = credential

        key_file = dest.parent / "id_rsa"
        key_file.write_text(raw_key if raw_key.endswith("\n") else raw_key + "\n")
        key_file.chmod(0o600)

        if passphrase:
            # Strip the passphrase so git/ssh can use the key without interaction
            strip = subprocess.run(
                ["ssh-keygen", "-p", "-P", passphrase, "-N", "", "-f", str(key_file)],
                capture_output=True, text=True,
            )
            if strip.returncode != 0:
                key_file.unlink(missing_ok=True)
                raise RuntimeError(
                    "SSH key passphrase is incorrect or the key is unsupported. "
                    f"ssh-keygen: {strip.stderr.strip()}"
                )

        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        )
        clone_url = url
    elif credential_type == "none":
        if url.startswith("git@") or url.startswith("ssh://"):
            raise RuntimeError(
                f"credential_type is 'none' but URL requires SSH: {url!r}. "
                "Use an HTTPS URL for public repos, or set a credential."
            )
        clone_url = url
    else:
        raise RuntimeError(f"Unknown credential_type: {credential_type}")

    result = subprocess.run(
        ["git", "clone", "--branch", branch, "--depth", "1", clone_url, str(dest)],
        capture_output=True, text=True, env=env,
    )
    # Wipe SSH key from disk immediately after clone attempt
    if credential_type == "ssh_key":
        key_file = dest.parent / "id_rsa"
        if key_file.exists():
            key_file.unlink()

    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")


# ── pa scan-project ────────────────────────────────────────────────────────────

def run_pa_scan(
    repo_path: Path,
    config_toml: str,
    scan_flags: str = "",
    subfolder: str = "",
) -> tuple[int, list[dict], list[str]]:
    """Run pa scan-project. Returns (finding_count, findings, sources)."""
    import shlex
    cmd = [str(Path(sys.executable).parent / "pa"), "scan-project", "--format", "json"]
    config_tmp = None
    if config_toml:
        with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
            f.write(config_toml)
            config_tmp = f.name
        cmd += ["--config", config_tmp]

    if scan_flags:
        # scan_flags cannot contain --format, --config, --details, --fmt, or a PATH
        # argument because the value is a closed system:
        #   1. The only write path is the frontend ScanArgsField, which assembles flags
        #      solely from the list returned by the /repo-scans/scan-options API.
        #   2. That API calls get_scan_options() (backend/app/services/scan_options.py),
        #      which filters every param through _EXCLUDED_PARAMS before returning it.
        #   3. _EXCLUDED_PARAMS = {"path", "format", "fmt", "details", "config"} — all
        #      of the flags that could override the safe defaults above.
        # The DB field is operator-only (requires the "operator" role to write) and is
        # never accepted as raw user freetext; ScanArgsField is the only UI surface.
        # Runtime validation is intentionally minimal because scan_flags is expected to
        # come from the backend-filtered scan-options list.
        try:
            cmd += shlex.split(scan_flags)
        except ValueError as exc:
            raise RuntimeError(f"invalid scan_flags quoting: {exc}") from exc

    # PATH argument: subdirectory within the cloned repo, or repo root.
    # subfolder is validated at the API layer (no absolute paths, no .. segments),
    # but we resolve both paths and assert containment here as defence-in-depth.
    scan_path = (repo_path / subfolder).resolve() if subfolder else repo_path.resolve()
    repo_root = repo_path.resolve()
    if repo_root != scan_path and repo_root not in scan_path.parents:
        raise RuntimeError(f"subfolder '{subfolder}' escapes the repository directory")
    cmd.append(str(scan_path))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    finally:
        if config_tmp:
            Path(config_tmp).unlink(missing_ok=True)

    if result.returncode not in (0, 1):  # pa exits 1 when findings found
        raise RuntimeError(f"pa scan-project failed: {result.stderr}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        snippet = result.stdout[:200].replace("\n", " ")
        raise RuntimeError(
            f"pa scan-project output was not valid JSON: {exc}. Output: {snippet!r}"
        ) from exc
    findings = data.get("findings", [])
    sources = data.get("sources", [])
    return len(findings), findings, sources


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    pa_version = get_env("PA_VERSION")
    result_id = int(require_env("REPO_SCAN_RESULT_ID"))
    repo_url = require_env("REPO_URL")
    branch = require_env("BRANCH")
    credential_type = require_env("CREDENTIAL_TYPE")
    credential_arn = get_env("CREDENTIAL_SECRET_ARN")
    fleet_url = require_env("FLEET_API_URL")
    fleet_key = require_env("FLEET_SYSTEM_API_KEY")
    config_toml = get_env("PA_CONFIG_TOML", "")

    workdir = Path(tempfile.mkdtemp(prefix="pa-scan-"))
    repo_path = workdir / "repo"

    try:
        # 1. Install package-alert
        try:
            install_pa(pa_version)
        except RuntimeError as exc:
            post_result(fleet_url, fleet_key, result_id, "failed",
                        error_message=str(exc))
            return

        # 2. Fetch credential (direct env var takes priority over Secrets Manager)
        try:
            # Don't strip CREDENTIAL_VALUE — PEM keys require a trailing newline
            # and stripping it causes OpenSSH to silently reject the key file.
            direct_value = os.environ.get("CREDENTIAL_VALUE", "")
            if direct_value:
                credential = direct_value
            elif credential_arn:
                credential = fetch_secret(credential_arn)
            else:
                credential = ""
        except Exception as exc:
            post_result(fleet_url, fleet_key, result_id, "failed",
                        error_message=f"Secrets Manager fetch failed: {exc}")
            return

        # 3. Clone repo
        try:
            clone_repo(repo_url, branch, repo_path, credential_type, credential)
        except RuntimeError as exc:
            post_result(fleet_url, fleet_key, result_id, "failed",
                        pa_version=pa_version, error_message=str(exc))
            return

        # 4. Run scan
        try:
            scan_flags = get_env("PA_SCAN_FLAGS", "")
            subfolder = get_env("PA_SUBFOLDER", "")
            finding_count, findings, sources = run_pa_scan(repo_path, config_toml, scan_flags, subfolder)
        except RuntimeError as exc:
            post_result(fleet_url, fleet_key, result_id, "failed",
                        pa_version=pa_version, error_message=str(exc))
            return

        # 5. Report success
        post_result(
            fleet_url, fleet_key, result_id, "success",
            pa_version=pa_version,
            finding_count=finding_count,
            findings=findings,
            sources=sources or None,
        )

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
