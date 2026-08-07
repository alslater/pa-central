"""Tests for AWS client wrapper using LocalStack."""
import pytest

from app.core.aws import EcsClient, SecretsManagerClient

LOCALSTACK = "http://localhost:4566"
AWS_CREDS = {"aws_access_key_id": "test", "aws_secret_access_key": "test", "region_name": "us-east-1"}


@pytest.fixture
def sm(localstack):
    return SecretsManagerClient(endpoint_url=localstack, **AWS_CREDS)


@pytest.fixture
def ecs(localstack):
    return EcsClient(endpoint_url=localstack, **AWS_CREDS)


async def test_create_and_get_secret(sm):
    arn = await sm.create_secret("pa-central/repo-creds/test-1", "my-token")
    assert "pa-central/repo-creds/test-1" in arn
    value = await sm.get_secret(arn)
    assert value == "my-token"
    await sm.delete_secret(arn)


async def test_update_secret(sm):
    arn = await sm.create_secret("pa-central/repo-creds/test-2", "original")
    await sm.update_secret(arn, "updated")
    value = await sm.get_secret(arn)
    assert value == "updated"
    await sm.delete_secret(arn)


async def test_delete_secret(sm):
    arn = await sm.create_secret("pa-central/repo-creds/test-3", "value")
    await sm.delete_secret(arn)
    with pytest.raises(Exception):  # noqa: B017
        await sm.get_secret(arn)


async def test_run_task_requires_pro(ecs, localstack):
    """ECS RunTask requires LocalStack Pro — skip gracefully."""
    import boto3
    b = boto3.client("ecs", endpoint_url=localstack, **AWS_CREDS)
    try:
        b.create_cluster(clusterName="test-cluster")
        b.register_task_definition(
            family="pa-central-scan-task",
            networkMode="awsvpc",
            containerDefinitions=[{
                "name": "scan", "image": "python:3.12-slim",
                "memory": 512, "cpu": 256,
                "essential": True,
            }],
            requiresCompatibilities=["FARGATE"],
            cpu="256", memory="512",
        )
        arn = await ecs.run_scan_task(
            cluster_arn="test-cluster",
            task_definition_arn="pa-central-scan-task",
            subnet_ids=["subnet-12345678"],
            security_group_ids=["sg-12345678"],
            environment={"PA_VERSION": "1.0.0"},
        )
        assert arn is not None
    except Exception as e:
        if "not included within your LocalStack license" in str(e):
            pytest.skip("ECS requires LocalStack Pro license")
        raise
