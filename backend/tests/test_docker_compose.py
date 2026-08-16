"""docker-compose.yml must forward every DATABASE_* setting it advertises.

compose's `environment:` block is an explicit allowlist, not a passthrough —
a variable set in the host's .env has no effect on the container unless it is
named here. Skips automatically if the Docker CLI or compose plugin is
unavailable, matching the convention used by the Postgres/LocalStack fixtures.
"""
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

ALL_DATABASE_FIELDS = (
    "DATABASE_TYPE",
    "DATABASE_NAME",
    "DATABASE_HOST",
    "DATABASE_PORT",
    "DATABASE_USER",
    "DATABASE_PASSWORD",
    "DATABASE_PASSWORD_FILE",
    "DATABASE_SCHEMA",
    "DATABASE_SSLMODE",
    "DATABASE_SSLROOTCERT",
    "DATABASE_SSLCERT",
    "DATABASE_SSLKEY",
)


def _compose_available() -> bool:
    if not shutil.which("docker"):
        return False
    result = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, check=False
    )
    return result.returncode == 0


pytestmark = pytest.mark.skipif(
    not _compose_available(), reason="Docker Compose CLI not available"
)


def _rendered_environment(monkeypatch) -> dict:
    """The pa-central service's environment as compose would actually set it."""
    monkeypatch.setenv("SECRET_KEY", "x")
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "x")
    result = subprocess.run(
        ["docker", "compose", "config", "pa-central"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    rendered = yaml.safe_load(result.stdout)
    return rendered["services"]["pa-central"]["environment"]


class TestAllDatabaseFieldsAreForwarded:
    def test_every_database_field_is_in_the_environment_block(self, monkeypatch):
        """Every field the app understands must be settable via docker compose,
        not just the 7 that happened to be listed when this block was last
        written. DATABASE_SCHEMA is the sharpest case: silently omitting it
        does not fail — it runs migrations against the default schema instead
        of the one the operator configured."""
        env = _rendered_environment(monkeypatch)
        missing = [name for name in ALL_DATABASE_FIELDS if name not in env]
        assert not missing, f"docker-compose.yml does not forward: {missing}"

    def test_database_schema_set_in_env_reaches_the_container(self, monkeypatch):
        monkeypatch.setenv("DATABASE_SCHEMA", "my_schema")
        env = _rendered_environment(monkeypatch)
        assert env.get("DATABASE_SCHEMA") == "my_schema"


class TestLegacyDatabaseUrlIsForwarded:
    def test_database_url_set_on_the_host_reaches_the_container(self, monkeypatch):
        """DATABASE_URL must be forwarded even though the app no longer reads
        it for connection info — forwarding it is solely so the container's
        own validate_database_settings() can see it and reject it loudly.

        An operator migrating an existing deployment has DATABASE_URL set in
        their shell/CI environment, not necessarily in a .env file the
        container ships with. compose reads that value for variable
        substitution in this file, but never passes it to the container
        unless it is named in the environment: block — so without this
        entry, the value crosses the host boundary into nothing: the
        container starts with DATABASE_TYPE defaulting to sqlite and no
        error at all, silently discarding whatever database the operator
        thought they were connecting to. Rendered directly: with
        DATABASE_URL=postgresql://user:pass@host/db set on the host, the
        container's environment came back with DATABASE_TYPE: sqlite and no
        DATABASE_URL key present at all before this fix."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@host/db")
        env = _rendered_environment(monkeypatch)
        assert env.get("DATABASE_URL") == "postgresql://user:pass@host/db"
