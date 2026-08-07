"""Smoke test: LocalStack fixture starts and Secrets Manager is reachable."""
import pytest


def test_secretsmanager_reachable(secretsmanager):
    response = secretsmanager.list_secrets()
    assert "SecretList" in response


def test_ecs_reachable(ecs_client):
    """ECS requires LocalStack Pro. Skip gracefully if not licensed."""
    try:
        response = ecs_client.list_clusters()
        assert "clusterArns" in response
    except Exception as e:
        if "not included within your LocalStack license" in str(e):
            pytest.skip("ECS requires LocalStack Pro license")
        raise
