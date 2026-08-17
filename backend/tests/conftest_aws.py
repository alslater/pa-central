"""AWS/LocalStack fixtures for integration tests."""
import subprocess
import time

import boto3
import httpx
import pytest

LOCALSTACK_URL = "http://localhost:4566"
AWS_DUMMY = {
    "aws_access_key_id": "test",
    "aws_secret_access_key": "test",
    "region_name": "us-east-1",
}


def _localstack_running() -> bool:
    try:
        r = httpx.get(f"{LOCALSTACK_URL}/_localstack/health", timeout=2)
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def _startup_problem() -> str | None:
    """Why `localstack start` cannot run here, or None if it can.

    Returns the reason rather than a bool: the CLI and the Docker daemon are
    separate prerequisites, and a single "not installed" message sends someone
    to reinstall a CLI that is already there when the real problem is a stopped
    daemon.
    """
    try:
        subprocess.run(["localstack", "--version"], check=True, capture_output=True)
    except FileNotFoundError:
        return "the LocalStack CLI is not installed (pip install localstack)"
    except subprocess.CalledProcessError as exc:
        return (
            "`localstack --version` failed: "
            f"{_stderr(exc) or f'exit {exc.returncode}'}"
        )

    # The CLI alone isn't enough: `localstack start` needs a working Docker
    # daemon. Without this check the fixture errors out instead of skipping.
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
    except FileNotFoundError:
        return "the LocalStack CLI is installed but the `docker` CLI is not"
    except subprocess.CalledProcessError as exc:
        return (
            "the LocalStack CLI is installed but the Docker daemon is not "
            f"reachable — `docker info` failed: "
            f"{_stderr(exc) or f'exit {exc.returncode}'}"
        )
    return None


def _stderr(exc: subprocess.CalledProcessError) -> str:
    """The last meaningful stderr line, for a one-line skip message."""
    raw = (exc.stderr or b"").decode(errors="replace").strip()
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


@pytest.fixture(scope="session")
def localstack():
    """Start LocalStack if not already running; skip if it cannot be started."""
    already_running = _localstack_running()
    if not already_running:
        if problem := _startup_problem():
            pytest.skip(f"skipping AWS integration tests: {problem}")
        subprocess.run(["localstack", "start", "-d"], check=True)
        for _ in range(30):
            if _localstack_running():
                break
            time.sleep(1)
        else:
            pytest.fail("LocalStack did not start in time")
    yield LOCALSTACK_URL
    if not already_running:
        subprocess.run(["localstack", "stop"], check=True)


@pytest.fixture
def secretsmanager(localstack):
    """Boto3 Secrets Manager client pointed at LocalStack."""
    return boto3.client("secretsmanager", endpoint_url=localstack, **AWS_DUMMY)


@pytest.fixture
def ecs_client(localstack):
    """Boto3 ECS client pointed at LocalStack."""
    return boto3.client("ecs", endpoint_url=localstack, **AWS_DUMMY)
