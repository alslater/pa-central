import os

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    app_title: str = "PA Central"
    secret_key: str = "changeme-use-a-long-random-string-in-production"
    debug: bool = False

    # Database — swap to postgresql+asyncpg://... for production
    # Absolute path so the DB is always next to this file regardless of cwd.
    database_url: str = f"sqlite+aiosqlite:///{os.path.join(os.path.dirname(__file__), '..', '..', 'pa_central.db')}"

    # Auth
    access_token_expire_minutes: int = 60 * 8  # 8 hours
    algorithm: str = "HS256"

    # First-run admin bootstrap (set via env, cleared after first use)
    bootstrap_admin_password: str | None = None

    # A host is considered online if it sent a heartbeat within this window.
    # package-alert agents should heartbeat more frequently than this value.
    host_online_threshold_minutes: int = 15

    # Valkey/Redis URL for distributed locks (optional — locks skipped if unset)
    valkey_url: str | None = None

    # Encryption key for secret system settings (must be set in production)
    settings_encryption_key: str = "changeme-set-in-production-32chars"

    # AWS / ECS settings for repo scanning
    aws_endpoint_url: str | None = None  # override for LocalStack in tests/dev
    aws_region: str = "us-east-1"
    ecs_cluster_arn: str | None = None
    scan_task_definition_arn: str | None = None
    scan_task_subnet_ids: str = ""   # comma-separated
    scan_task_security_group_ids: str = ""  # comma-separated

    # URL this fleet app is reachable at (used by scan tasks to POST results back)
    fleet_base_url: str = "http://localhost:8000"

    # System API key for scan tasks and scheduler auth
    fleet_system_api_key: str | None = None

    # Local Docker scan mode — skips ECS, runs scan_task image via local Docker
    local_docker_scan: bool = False
    # Image name built from docker/scan_task/
    scan_task_image: str = "pa-central-scan-task:latest"
    # Override fleet URL for containers (defaults to host.docker.internal when unset)
    scan_task_fleet_url: str | None = None


settings = Settings()

_INSECURE_DEFAULTS = {
    "secret_key": "changeme-use-a-long-random-string-in-production",
    "settings_encryption_key": "changeme-set-in-production-32chars",
}

if not settings.debug:
    _problems = [name for name, default in _INSECURE_DEFAULTS.items() if getattr(settings, name) == default]
    if _problems:
        raise RuntimeError(
            f"Insecure default value detected for: {', '.join(_problems)}. "
            "Set these environment variables before starting in production. "
            "To suppress this check during development, set DEBUG=true."
        )
