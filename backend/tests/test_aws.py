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


async def test_run_scan_task_launches_a_fargate_task(ecs, localstack):
    """ECS RunTask is a LocalStack Pro feature — skip gracefully without a
    Pro/Ultimate license. With one, this exercises run_scan_task end to end
    against real (LocalStack-emulated) networking, since RunTask validates
    the subnet/security-group ids for real rather than accepting placeholder
    values."""
    import boto3
    ecs_b = boto3.client("ecs", endpoint_url=localstack, **AWS_CREDS)
    ec2_b = boto3.client("ec2", endpoint_url=localstack, **AWS_CREDS)

    vpc = None
    subnet = None
    security_group = None
    cluster_created = False
    task_def_arn = None
    task_arn = None

    def _cleanup() -> None:
        """Each teardown step runs independently of the others, and only
        for a resource that was actually created — a failure creating (or
        cleaning up) one resource must not skip cleanup of the rest, and
        must not leak a resource created before the failing step. E.g. a
        failed create_cluster leaving cluster_created False must still let
        EC2 cleanup run; a failed create_subnet after create_vpc succeeded
        must still let the VPC be deleted; a security-group deletion
        blocked by a lingering ENI must not skip subnet/VPC cleanup. This
        matters because localstack is a session-scoped, already-running
        instance — anything left uncleaned here persists across tests."""
        if task_arn is not None:
            try:
                ecs_b.stop_task(cluster="test-cluster", task=task_arn)
                ecs_b.get_waiter("tasks_stopped").wait(cluster="test-cluster", tasks=[task_arn])
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: failed to stop task {task_arn}: {exc}")
        if task_def_arn is not None:
            try:
                ecs_b.deregister_task_definition(taskDefinition=task_def_arn)
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: failed to deregister {task_def_arn}: {exc}")
        if cluster_created:
            try:
                ecs_b.delete_cluster(cluster="test-cluster")
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: failed to delete cluster: {exc}")
        if security_group is not None:
            try:
                ec2_b.delete_security_group(GroupId=security_group)
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: failed to delete security group {security_group}: {exc}")
        if subnet is not None:
            try:
                ec2_b.delete_subnet(SubnetId=subnet)
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: failed to delete subnet {subnet}: {exc}")
        if vpc is not None:
            try:
                ec2_b.delete_vpc(VpcId=vpc)
            except Exception as exc:  # noqa: BLE001
                print(f"cleanup: failed to delete vpc {vpc}: {exc}")

    try:
        vpc = ec2_b.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2_b.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        security_group = ec2_b.create_security_group(
            GroupName="pa-central-scan-test", Description="test", VpcId=vpc
        )["GroupId"]
        ecs_b.create_cluster(clusterName="test-cluster")
        cluster_created = True
        task_def_arn = ecs_b.register_task_definition(
            family="pa-central-scan-task",
            networkMode="awsvpc",
            containerDefinitions=[{
                "name": "scan", "image": "python:3.12-slim",
                "memory": 512, "cpu": 256,
                "essential": True,
            }],
            requiresCompatibilities=["FARGATE"],
            cpu="256", memory="512",
        )["taskDefinition"]["taskDefinitionArn"]
        try:
            task_arn = await ecs.run_scan_task(
                cluster_arn="test-cluster",
                task_definition_arn="pa-central-scan-task",
                subnet_ids=[subnet],
                security_group_ids=[security_group],
                environment={"PA_VERSION": "1.0.0"},
            )
            assert task_arn is not None
        except Exception as e:
            if "not included within your LocalStack license" in str(e):
                pytest.skip("ECS requires LocalStack Pro license")
            raise
    finally:
        _cleanup()
