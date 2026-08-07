"""Tests for local Docker scan runner."""
from unittest.mock import MagicMock, patch

import pytest

ENV = {
    "PA_VERSION": "1.0.0",
    "REPO_SCAN_RESULT_ID": "7",
    "REPO_URL": "https://github.com/example/repo",
    "BRANCH": "main",
    "CREDENTIAL_TYPE": "none",
    "CREDENTIAL_SECRET_ARN": "",
    "FLEET_SYSTEM_API_KEY": "test-key",
    "PA_CONFIG_TOML": "",
}


@pytest.mark.asyncio
async def test_run_local_scan_returns_pseudo_arn():
    container = MagicMock()
    container.id = "abc123def456" * 2  # 24-char id
    container.short_id = "abc123"

    mock_client = MagicMock()
    mock_client.containers.run.return_value = container

    with patch("docker.from_env", return_value=mock_client):
        from app.core.docker_runner import run_local_scan
        arn = await run_local_scan("pa-central-scan-task:latest", ENV, "http://host.docker.internal:8000")

    assert arn.startswith("local-docker://")
    assert container.id in arn


@pytest.mark.asyncio
async def test_run_local_scan_passes_fleet_url():
    container = MagicMock()
    container.id = "xyz"
    container.short_id = "xyz"

    mock_client = MagicMock()
    mock_client.containers.run.return_value = container

    with patch("docker.from_env", return_value=mock_client):
        from app.core.docker_runner import run_local_scan
        await run_local_scan("my-image:dev", ENV, "http://host.docker.internal:8000")

    call_kwargs = mock_client.containers.run.call_args
    env_passed = call_kwargs[1]["environment"]
    assert env_passed["FLEET_API_URL"] == "http://host.docker.internal:8000"


@pytest.mark.asyncio
async def test_run_local_scan_runs_detached():
    container = MagicMock()
    container.id = "ccc"
    container.short_id = "ccc"

    mock_client = MagicMock()
    mock_client.containers.run.return_value = container

    with patch("docker.from_env", return_value=mock_client):
        from app.core.docker_runner import run_local_scan
        await run_local_scan("img", ENV, "http://localhost:8000")

    call_kwargs = mock_client.containers.run.call_args
    assert call_kwargs[1]["detach"] is True
    assert call_kwargs[1]["remove"] is True


@pytest.mark.asyncio
async def test_run_local_scan_propagates_docker_error():
    mock_client = MagicMock()
    mock_client.containers.run.side_effect = RuntimeError("image not found: img:latest")

    with patch("docker.from_env", return_value=mock_client):
        from app.core.docker_runner import run_local_scan
        with pytest.raises(RuntimeError, match="image not found"):
            await run_local_scan("img:latest", ENV, "http://localhost:8000")


def test_is_local_task_arn_true():
    from app.core.docker_runner import is_local_task_arn
    assert is_local_task_arn("local-docker://abc123") is True


def test_is_local_task_arn_false_for_ecs():
    from app.core.docker_runner import is_local_task_arn
    assert is_local_task_arn("arn:aws:ecs:us-east-1:123:task/abc") is False


def test_is_local_task_arn_false_for_none():
    from app.core.docker_runner import is_local_task_arn
    assert is_local_task_arn(None) is False
