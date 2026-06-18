"""Local Docker runner — launches scan_task container via the Docker socket.

Used in development when LOCAL_DOCKER_SCAN=true so ECS / AWS are not needed.
The container runs detached; the scan task itself POSTs results back to the
fleet API, so the lifecycle is identical to the ECS path.
"""
import asyncio
import logging
from functools import partial

logger = logging.getLogger(__name__)

# Prefix we embed in the "task ARN" so the rest of the code can identify origin
_LOCAL_PREFIX = "local-docker://"


def _host_gateway() -> dict[str, str]:
    """Return the extra_hosts mapping so containers can reach the Docker host.

    On Linux, host.docker.internal is not injected automatically; we add it
    ourselves pointing at the special host-gateway sentinel.
    On Mac/Windows, Docker Desktop injects host.docker.internal already, so no
    extra_hosts entry is needed — we return an empty dict.
    """
    import platform
    if platform.system() == "Linux":
        return {"host.docker.internal": "host-gateway"}
    return {}


def _run_container_sync(image: str, environment: dict[str, str], fleet_url: str) -> str:
    """Blocking call — run inside a thread pool executor."""
    import docker  # type: ignore[import]

    env = dict(environment)
    env["FLEET_API_URL"] = fleet_url

    client = docker.from_env()
    container = client.containers.run(
        image,
        detach=True,
        remove=True,
        environment=env,
        extra_hosts=_host_gateway(),
        network_mode="bridge",
    )
    logger.info("started local scan container %s from image %s", container.short_id, image)
    return f"{_LOCAL_PREFIX}{container.id}"


async def run_local_scan(
    image: str,
    environment: dict[str, str],
    fleet_url: str,
) -> str:
    """Async wrapper: launch a detached scan container. Returns a pseudo-ARN."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        partial(_run_container_sync, image, environment, fleet_url),
    )


def is_local_task_arn(arn: str | None) -> bool:
    return bool(arn and arn.startswith(_LOCAL_PREFIX))
