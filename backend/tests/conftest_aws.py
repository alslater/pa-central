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


def _localstack_cli_available() -> bool:
    try:
        subprocess.run(["localstack", "--version"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


@pytest.fixture(scope="session")
def localstack():
    """Start LocalStack if not already running; skip if the CLI isn't installed."""
    already_running = _localstack_running()
    if not already_running:
        if not _localstack_cli_available():
            pytest.skip("LocalStack CLI not installed — skipping AWS integration tests")
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
