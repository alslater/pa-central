import math
import os

from dotenv import dotenv_values
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Absolute so the database file sits beside the source regardless of cwd.
_SQLITE_DEFAULT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "pa_central.db"
)

# docker-compose.yml's own DATABASE_NAME fallback (`${DATABASE_NAME:-...}`),
# pointing at the pa_central_data volume mount. Compose's environment: block
# cannot vary a default based on another variable's value, so this is
# forwarded into the container even when DATABASE_TYPE=postgresql is set
# without an explicit DATABASE_NAME — must be treated as "unset" the same way
# as _SQLITE_DEFAULT_PATH below, or startup validation passes and the failure
# only surfaces later, misleadingly, at connection time.
_COMPOSE_SQLITE_DEFAULT_PATH = "./data/pa_central.db"

# Absolute for the same reason: a relative ".env" resolves against whatever
# the current process's cwd happens to be, not this file's location. A test
# runner or IDE that launches Python from the repo root instead of backend/
# would otherwise silently pick up a different, unrelated .env file one
# directory up.
_ENV_FILE_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", ".env")
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE_PATH, env_file_encoding="utf-8", extra="ignore"
    )

    # App
    app_title: str = "PA Central"
    secret_key: str = "changeme-use-a-long-random-string-in-production"
    debug: bool = False

    # Database — structured rather than a URI. See README.md.
    database_type: str = "sqlite"
    # sqlite: a file path. postgresql: the database name.
    database_name: str | None = _SQLITE_DEFAULT_PATH
    database_host: str | None = None
    database_port: int = 5432
    database_user: str | None = None
    database_password: str | None = None
    database_password_file: str | None = None
    database_schema: str | None = None
    database_sslmode: str = "prefer"
    database_sslrootcert: str | None = None
    database_sslcert: str | None = None
    database_sslkey: str | None = None

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

    # Ceiling on how long startup waits to acquire the PostgreSQL migration
    # advisory lock before failing (seconds; unused on SQLite). Generous
    # enough for a genuinely long migration on a peer instance, short enough
    # that a stuck lock surfaces as a failed start rather than an indefinite
    # hang.
    migration_lock_timeout: float = 300.0

    @field_validator("migration_lock_timeout", mode="before")
    @classmethod
    def _finite_non_negative_timeout(cls, v: object) -> object:
        # Plain float coercion accepts "nan" and "inf" as valid floats —
        # confirmed live: Settings(migration_lock_timeout="nan") assigns
        # float("nan") with no error. Both defeat the deadline check in
        # app.main._run_migrations (`time.monotonic() >= deadline`): nan
        # compares False against everything, and monotonic time never
        # reaches +inf. Either would silently recreate the indefinite hang
        # this timeout exists to prevent, so both are rejected here alongside
        # ordinary malformed input — before pydantic's own float coercion
        # gets a chance to accept them.
        try:
            value = float(v)
        except (TypeError, ValueError):
            raise ValueError(
                f"MIGRATION_LOCK_TIMEOUT={v!r} is not a valid number"
            ) from None
        if not math.isfinite(value) or value < 0:
            raise ValueError(
                f"MIGRATION_LOCK_TIMEOUT={v!r} must be a finite, non-negative "
                "number of seconds"
            )
        return value

    @field_validator(
        "database_name",
        "database_host",
        "database_user",
        "database_password",
        "database_password_file",
        "database_schema",
        "database_sslrootcert",
        "database_sslcert",
        "database_sslkey",
        mode="before",
    )
    @classmethod
    def _blank_to_none(cls, v: str | None) -> str | None:
        """An empty string must mean the same thing as "unset" for these
        fields — not just here, but to every downstream consumer.

        This class's own validation only ever checks truthiness
        (`if cfg.database_schema:`), so "" and None look identical here. But
        migrations/env.py passes settings.database_schema straight through as
        Alembic's version_table_schema with no guard, and SQLAlchemy/Alembic
        treat schema="" as a real (if odd) schema name distinct from
        schema=None — confirmed live: a subprocess started with
        DATABASE_SCHEMA="" in its environment resolved database_schema to the
        literal string "" (pydantic does not coerce it), and version-table
        existence checks against that literal empty schema stopped matching
        tables created under the default schema, corrupting a previously
        passing concurrent-migration test. app.main._alembic_upgrade
        deliberately sets every optional DATABASE_* variable to an explicit
        empty string (never omits the key) so the migration subprocess's own
        Settings() cannot fall back to a stale value in backend/.env — that
        technique only works precedence-wise (env source beats dotenv when
        the key is merely present) if the resulting value still collapses to
        None afterwards.
        """
        return v or None


_ACCEPTED_SSLMODES = ("disable", "prefer", "require", "verify-ca", "verify-full")

# Fields that only mean anything for PostgreSQL. Setting one under SQLite is an
# error rather than a silent no-op: the alternative is someone setting
# DATABASE_HOST, seeing SQLite still in use, and having nothing to go on.
_POSTGRES_ONLY_FIELDS = (
    ("database_host", "DATABASE_HOST"),
    ("database_user", "DATABASE_USER"),
    ("database_password", "DATABASE_PASSWORD"),
    ("database_password_file", "DATABASE_PASSWORD_FILE"),
    ("database_schema", "DATABASE_SCHEMA"),
    ("database_sslrootcert", "DATABASE_SSLROOTCERT"),
    ("database_sslcert", "DATABASE_SSLCERT"),
    ("database_sslkey", "DATABASE_SSLKEY"),
)

_CERT_FIELDS = (
    ("database_sslrootcert", "DATABASE_SSLROOTCERT"),
    ("database_sslcert", "DATABASE_SSLCERT"),
    ("database_sslkey", "DATABASE_SSLKEY"),
)


def _legacy_database_url_is_set() -> bool:
    """True if DATABASE_URL is set in the real environment or in .env.

    pydantic-settings loads env_file values through its own dotenv source
    without ever writing them into os.environ, so an old .env carrying only
    DATABASE_URL — the exact case this check exists to catch — would
    otherwise pass silently: os.environ.get("DATABASE_URL") sees nothing,
    there is no database_url field left to populate, and extra="ignore"
    drops the unrecognised key without complaint.

    Both lookups are case-insensitive: pydantic-settings' case_sensitive
    defaults to False and is never overridden here, so the old
    Settings.database_url field this guard replaces matched
    database_url/Database_Url/DATABASE_URL alike. A deployment that had
    been running for months with a lowercase database_url in its real
    environment or .env would otherwise have that value silently ignored by
    a literal-string-only check, falling back to SQLite with no warning.
    """
    if any(k.upper() == "DATABASE_URL" and v for k, v in os.environ.items()):
        return True
    env_file = Settings.model_config.get("env_file")
    if not env_file or not os.path.isfile(env_file):
        return False
    encoding = Settings.model_config.get("env_file_encoding")
    values = dotenv_values(env_file, encoding=encoding)
    return any(k.upper() == "DATABASE_URL" and v for k, v in values.items())


def validate_database_settings(cfg: "Settings") -> None:
    """Raise RuntimeError for any unusable DATABASE_* combination.

    Everything is checked at startup rather than at first connection, so a
    misconfiguration fails immediately and names the field responsible. No
    message includes a credential.
    """
    if _legacy_database_url_is_set():
        raise RuntimeError(
            "DATABASE_URL is no longer used. Set the structured variables "
            "instead: DATABASE_TYPE, and for PostgreSQL also DATABASE_HOST, "
            "DATABASE_PORT, DATABASE_NAME, and DATABASE_USER. Set "
            "DATABASE_PASSWORD or DATABASE_PASSWORD_FILE if your server "
            "requires a password -- peer, trust, and IAM authentication do "
            "not. See README.md."
        )

    if cfg.database_type not in ("sqlite", "postgresql"):
        raise RuntimeError(
            f"DATABASE_TYPE must be 'sqlite' or 'postgresql', "
            f"got {cfg.database_type!r}"
        )

    if cfg.database_type == "sqlite":
        offenders = [
            label for attr, label in _POSTGRES_ONLY_FIELDS if getattr(cfg, attr)
        ]
        if offenders:
            raise RuntimeError(
                f"{', '.join(offenders)} only apply when "
                f"DATABASE_TYPE=postgresql, but DATABASE_TYPE=sqlite. Remove "
                "them, or set DATABASE_TYPE=postgresql."
            )
        if not cfg.database_name:
            # "" and None both pass str|None typing and both build
            # sqlite:/// or sqlite:// — an in-memory database with no error
            # anywhere. SQLAlchemy's default pool opens a fresh :memory: per
            # connection, so this is not just "loses data at restart" but
            # "a different empty database on every pooled connection."
            raise RuntimeError(
                "DATABASE_NAME must be a non-empty file path for "
                "DATABASE_TYPE=sqlite. An empty or unset value would "
                "silently create an in-memory database."
            )
        return

    # database_name carries a SQLite default path unless overridden — either
    # this process's own _SQLITE_DEFAULT_PATH, or docker-compose.yml's
    # _COMPOSE_SQLITE_DEFAULT_PATH — so for PostgreSQL both count as unset.
    # Otherwise a user who sets DATABASE_TYPE=postgresql and forgets
    # DATABASE_NAME would silently try to open a database named after a
    # filesystem path.
    name_is_set = bool(cfg.database_name) and cfg.database_name not in (
        _SQLITE_DEFAULT_PATH,
        _COMPOSE_SQLITE_DEFAULT_PATH,
    )
    missing = [
        label
        for label, present in (
            ("DATABASE_HOST", bool(cfg.database_host)),
            ("DATABASE_NAME", name_is_set),
            ("DATABASE_USER", bool(cfg.database_user)),
        )
        if not present
    ]
    if missing:
        raise RuntimeError(
            f"DATABASE_TYPE=postgresql requires {', '.join(missing)}"
        )

    if not 1 <= cfg.database_port <= 65535:
        # database_port is a plain int with no range constraint, so 0, a
        # negative number, or anything above the actual TCP port ceiling all
        # pass Pydantic's typing and URL.create() builds a syntactically
        # valid URL string regardless — confirmed directly. Without this,
        # the only failure was ever a confusing connection-time error
        # instead of a startup message naming the field responsible.
        raise RuntimeError(
            f"DATABASE_PORT must be between 1 and 65535, got {cfg.database_port}"
        )

    if cfg.database_password and cfg.database_password_file:
        raise RuntimeError(
            "Set DATABASE_PASSWORD or DATABASE_PASSWORD_FILE, not both"
        )

    if cfg.database_password_file:
        try:
            with open(cfg.database_password_file, encoding="utf-8") as handle:
                handle.read()
        except OSError as exc:
            raise RuntimeError(
                f"DATABASE_PASSWORD_FILE cannot be read: "
                f"{cfg.database_password_file} ({exc.strerror})"
            ) from None

    if cfg.database_sslmode not in _ACCEPTED_SSLMODES:
        raise RuntimeError(
            f"DATABASE_SSLMODE must be one of {', '.join(_ACCEPTED_SSLMODES)}, "
            f"got {cfg.database_sslmode!r}. libpq's 'allow' is not supported: "
            "it prefers plaintext and has no SSLContext equivalent."
        )

    if cfg.database_sslmode == "verify-ca" and not cfg.database_sslrootcert:
        # sync_connect_args() defaults to sslrootcert="system" for verify-ca
        # and verify-full alike when unset, but libpq rejects that specific
        # combination outright — confirmed live: `psql "sslmode=verify-ca
        # sslrootcert=system"` fails immediately with 'weak sslmode
        # "verify-ca" may not be used with sslrootcert=system (use
        # "verify-full")', before any network attempt. System roots are too
        # broad a trust store for chain-only (no hostname check) validation
        # in libpq's view. asyncpg has no equivalent restriction, so without
        # this, verify-ca with no root would work on the async driver and be
        # permanently unusable on the sync driver (Alembic).
        raise RuntimeError(
            "DATABASE_SSLMODE=verify-ca requires DATABASE_SSLROOTCERT to be "
            "set. Without an explicit CA, libpq refuses to combine verify-ca "
            "with the system trust store — use verify-full instead, or "
            "provide a CA file for verify-ca."
        )

    if bool(cfg.database_sslcert) != bool(cfg.database_sslkey):
        missing_label = (
            "DATABASE_SSLKEY" if cfg.database_sslcert else "DATABASE_SSLCERT"
        )
        raise RuntimeError(
            f"client certificate authentication needs both DATABASE_SSLCERT "
            f"and DATABASE_SSLKEY; {missing_label} is not set"
        )

    if cfg.database_sslcert and cfg.database_sslmode in ("disable", "prefer"):
        # asyncpg only ever reads sslcert/sslkey from a DSN query string or
        # PGSSLCERT/PGSSLKEY — never as connect() keyword arguments — and this
        # module deliberately builds no query string and reads no such env
        # var (see db_config.py's module docstring). `prefer`'s plaintext
        # fallback also requires passing ssl="prefer" as a bare string rather
        # than an SSLContext, which has no way to carry a cert chain either.
        # psycopg2 (Alembic) would still present the certificate; asyncpg (the
        # running application) silently would not — an asymmetry that would
        # only surface as an unexplained auth failure in production.
        raise RuntimeError(
            f"DATABASE_SSLCERT/DATABASE_SSLKEY are configured, but "
            f"DATABASE_SSLMODE={cfg.database_sslmode!r} cannot present them "
            "on the async driver the application actually connects with. Use "
            "require, verify-ca, or verify-full instead."
        )

    if cfg.database_sslrootcert and cfg.database_sslmode in ("disable", "prefer"):
        # Neither mode ever verifies the server certificate. `disable` has no
        # TLS session at all; `prefer` must reach asyncpg as the bare string
        # "prefer" to keep its plaintext fallback (an SSLContext would force
        # full verification — see _ssl_context's docstring in db_config.py),
        # and a bare string cannot carry a trust store. libpq behaves the
        # same way. An operator who supplies a CA under these modes gets no
        # verification while the trust root's presence suggests otherwise —
        # reject at startup rather than silently ignore it, mirroring the
        # client-certificate rule above.
        raise RuntimeError(
            f"DATABASE_SSLROOTCERT is configured, but "
            f"DATABASE_SSLMODE={cfg.database_sslmode!r} never verifies the "
            "server certificate, so the CA would be silently ignored. Use "
            "require, verify-ca, or verify-full instead."
        )

    for attr, label in _CERT_FIELDS:
        path = getattr(cfg, attr)
        if path and not os.path.isfile(path):
            raise RuntimeError(f"{label} file does not exist: {path}")


settings = Settings()
validate_database_settings(settings)

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
