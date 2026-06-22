"""Thin async wrappers around boto3 for Secrets Manager and ECS.

All clients accept an optional endpoint_url for LocalStack testing.
In production endpoint_url is None (boto3 uses the real AWS endpoints).
"""
import asyncio
from functools import partial
from typing import Any
import boto3


def _boto(service: str, endpoint_url: str | None, **kwargs) -> Any:
    return boto3.client(service, endpoint_url=endpoint_url, **kwargs)


async def _run(fn, *args, **kwargs):
    """Run a blocking boto3 call in a thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(fn, *args, **kwargs))


class SecretsManagerClient:
    def __init__(self, endpoint_url: str | None = None, **kwargs):
        self._client = _boto("secretsmanager", endpoint_url, **kwargs)

    async def create_secret(self, name: str, value: str) -> str:
        """Create a secret. Returns the ARN."""
        resp = await _run(self._client.create_secret, Name=name, SecretString=value)
        return resp["ARN"]

    async def update_secret(self, arn: str, value: str) -> None:
        await _run(self._client.put_secret_value, SecretId=arn, SecretString=value)

    async def get_secret(self, arn: str) -> str:
        resp = await _run(self._client.get_secret_value, SecretId=arn)
        return resp["SecretString"]

    async def delete_secret(self, arn: str) -> None:
        await _run(
            self._client.delete_secret,
            SecretId=arn,
            ForceDeleteWithoutRecovery=True,
        )


class EcsClient:
    def __init__(self, endpoint_url: str | None = None, **kwargs):
        self._client = _boto("ecs", endpoint_url, **kwargs)

    async def run_scan_task(
        self,
        cluster_arn: str,
        task_definition_arn: str,
        subnet_ids: list[str],
        security_group_ids: list[str],
        environment: dict[str, str],
    ) -> str:
        """Launch a Fargate scan task. Returns the task ARN."""
        env = [{"name": k, "value": v} for k, v in environment.items()]
        resp = await _run(
            self._client.run_task,
            cluster=cluster_arn,
            taskDefinition=task_definition_arn,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": subnet_ids,
                    "securityGroups": security_group_ids,
                    "assignPublicIp": "DISABLED",
                }
            },
            overrides={"containerOverrides": [{"name": "scan", "environment": env}]},
        )
        tasks = resp.get("tasks", [])
        if not tasks:
            failures = resp.get("failures", [])
            raise RuntimeError(f"ECS RunTask returned no tasks: {failures}")
        return tasks[0]["taskArn"]


async def build_scan_task_env(scan: Any, result_id: int, credential: Any = None) -> dict[str, str]:
    """Build environment variable dict for a scan task."""
    from app.core.config import settings as app_settings
    from app.models import CredentialType
    cred_type = credential.credential_type if credential else CredentialType.none
    cred_arn = credential.credential_secret_arn if credential else None
    local_arn = (cred_arn or "").startswith("local://")
    return {
        "PA_VERSION": scan.pa_version or "",
        "REPO_SCAN_RESULT_ID": str(result_id),
        "REPO_URL": scan.url,
        "BRANCH": scan.branch,
        "CREDENTIAL_TYPE": cred_type.value,
        "CREDENTIAL_SECRET_ARN": "" if local_arn else (cred_arn or ""),
        "CREDENTIAL_VALUE": cred_arn[len("local://"):] if local_arn else "",
        "FLEET_API_URL": app_settings.fleet_base_url,
        "FLEET_SYSTEM_API_KEY": app_settings.fleet_system_api_key or "",
        "PA_CONFIG_TOML": "",  # filled by caller if config template assigned
        "PA_SCAN_FLAGS": getattr(scan, 'scan_flags', None) or "",
        "PA_SUBFOLDER": getattr(scan, 'subfolder', None) or "",
    }
