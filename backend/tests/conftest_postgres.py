"""PostgreSQL fixtures for migration and FK-behaviour integration tests.

The suite runs on SQLite, which cannot catch dialect-specific defects: batch
migrations rebuild the table on SQLite but emit ALTER TABLE on PostgreSQL, and
SQLite ignores FK actions entirely unless a PRAGMA is set per connection. These
fixtures spin up a throwaway PostgreSQL container so those paths are exercised.

Follows the same shape as conftest_aws.py: reuse an already-running instance,
start one if the tooling exists, skip otherwise, and only tear down what this
fixture started.
"""
import os
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest
import sqlalchemy as sa
from sqlalchemy.engine import URL, make_url

from app.core.db_config import mask

PG_CONTAINER = "pa-central-test-postgres"
PG_IMAGE = "postgres:16-alpine"
PG_PORT = 55432
PG_PASSWORD = "test"
PG_ADMIN_DB = "postgres"

# Set PA_TEST_POSTGRES_URL to point at an existing server instead of Docker.
PG_URL_ENV = "PA_TEST_POSTGRES_URL"


def _admin_url(host_url: str, database: str) -> str:
    """Swap the database name on a URL, preserving everything else.

    Uses make_url rather than string surgery so query parameters survive —
    ``?sslmode=require`` on an external PA_TEST_POSTGRES_URL would otherwise be
    dropped, and every per-test database connection would fail against a server
    that requires SSL. Also safe for passwords containing '/'.
    """
    return (
        make_url(host_url)
        .set(database=database)
        .render_as_string(hide_password=False)
    )


def _safe_url(url: str) -> str:
    """Password-masked rendering for error messages — see app.core.db_config.mask."""
    return mask(url)


def _url_problem(url: str) -> str | None:
    """Describe why *url* is unusable, or None if it is fine.

    Returns a message rather than raising: an exception propagating out of a
    fixture makes pytest render the traceback, and it prints every frame's
    locals — so the raw URL, password included, lands in the output regardless
    of how carefully the error message itself is masked.
    """
    try:
        backend = make_url(url).get_backend_name()
    except Exception:  # noqa: BLE001 — any parse failure is equally unusable
        return "could not be parsed as a database URL: <unparseable URL>"
    if backend != "postgresql":
        return (
            f"must be a PostgreSQL URL, got backend {backend!r}: {mask(url)}"
        )
    return None


def _require_postgres(url: str) -> None:
    """Reject anything that is not PostgreSQL.

    Production's structured config also accepts SQLite, which is correct for
    the application but wrong for these fixtures: they provision databases and
    inspect pg_catalog. Checking here keeps the failure at the point the URL
    is supplied rather than at some later CREATE DATABASE.
    """
    backend = make_url(url).get_backend_name()
    if backend != "postgresql":
        raise ValueError(
            f"{PG_URL_ENV} must be a PostgreSQL URL, got backend "
            f"{backend!r}: {mask(url)}"
        )


# libpq and asyncpg spell the same setting differently. Production code never
# needs this — app.core.db_config builds each driver's connect_args directly
# from structured settings, with no query string to translate. But these two
# helpers convert an *externally supplied* URL (PA_TEST_POSTGRES_URL, which
# README.md documents as accepting `?sslmode=require`), so a caller's query
# survives the driver swap unmodified unless renamed here — and psycopg2
# rejects `ssl=`, asyncpg.connect() rejects `sslmode=`, with no fallback.
_TO_ASYNCPG_QUERY_ALIAS = {"sslmode": "ssl"}
_TO_PSYCOPG2_QUERY_ALIAS = {"ssl": "sslmode"}


def _rename_query_keys(url: URL, alias: dict[str, str]) -> URL:
    if not (alias.keys() & url.query.keys()):
        return url
    query = dict(url.query)
    for old, new in alias.items():
        if old not in query:
            continue
        if new in query and query[new] != query[old]:
            # e.g. ?sslmode=require&ssl=disable: both spellings present with
            # different values. Silently keeping either would discard the
            # other's meaning; there is no correct answer, so refuse rather
            # than guess which one the caller meant.
            raise ValueError(
                f"conflicting query parameters {old!r}={query[old]!r} and "
                f"{new!r}={query[new]!r} on {mask(url.render_as_string(hide_password=False))} "
                "— these are the same setting under two spellings; remove one"
            )
        query[new] = query.pop(old)
    return url.set(query=query)


def _as_sync_url(url: str) -> str:
    """Normalise a PostgreSQL URL to the sync psycopg2 driver.

    These fixtures use synchronous engines, so an async URL would raise
    MissingGreenlet on connect — and because `_server_ready` swallows every
    exception, that surfaces as a misleading "server is unreachable". Callers
    naturally have the asyncpg form to hand (it is what PA_TEST_POSTGRES_URL
    commonly uses), so accept it and convert rather than rejecting it.
    """
    _require_postgres(url)
    parsed = _rename_query_keys(make_url(url), _TO_PSYCOPG2_QUERY_ALIAS)
    return parsed.set(drivername="postgresql+psycopg2").render_as_string(
        hide_password=False
    )


def as_async_url(url: str) -> str:
    """Swap a test URL's driver to asyncpg.

    Test-only: the fixtures produce psycopg2 URLs and the async engines need
    asyncpg. Production code builds both forms from structured settings and
    never converts between them — but this helper also accepts an externally
    supplied URL (PA_TEST_POSTGRES_URL), so `?sslmode=` is renamed to `?ssl=`
    the way asyncpg.connect() expects it; left unrenamed, it raises
    `TypeError: connect() got an unexpected keyword argument 'sslmode'`.

    Client certificates are handled correctly on both drivers by
    app.core.db_config (async_connect_args() builds a real ssl.SSLContext from
    DATABASE_SSLCERT/DATABASE_SSLKEY/DATABASE_SSLROOTCERT); this conversion
    helper does not need to carry that limitation forward.
    """
    _require_postgres(url)
    parsed = _rename_query_keys(make_url(url), _TO_ASYNCPG_QUERY_ALIAS)
    return parsed.set(drivername="postgresql+asyncpg").render_as_string(
        hide_password=False
    )


def _server_ready(url: str) -> bool:
    # Disposed in `finally`: this is called in a polling loop while the
    # container starts, so an engine leaked per failed attempt would accumulate
    # pooled sockets across up to 60 retries.
    engine = sa.create_engine(url, connect_args={"connect_timeout": 2})
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 — any connection failure means "not ready"
        return False
    finally:
        engine.dispose()


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _container_running() -> bool:
    try:
        r = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{PG_CONTAINER}$", "--format", "{{.Names}}"],
            check=True, capture_output=True, text=True,
        )
        return PG_CONTAINER in r.stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


@pytest.fixture(scope="session")
def postgres_server() -> Iterator[str]:
    """Base URL of a running PostgreSQL server, or skip.

    Always yields a `postgresql+psycopg2` URL pointing at the default `postgres`
    database — an async URL supplied via PA_TEST_POSTGRES_URL is normalised, not
    rejected. Use the `postgres_url` fixture for a per-test throwaway database.
    """
    external = os.environ.get(PG_URL_ENV)
    if external:
        # Validated without raising: an exception escaping here would be
        # rendered by pytest as a traceback, and pytest prints each frame's
        # local variables — including the raw, unmasked URL. pytest.fail
        # raises no such frame, so this is the only leak-free shape.
        if problem := _url_problem(external):
            pytest.fail(f"{PG_URL_ENV} {problem}")
        external = _as_sync_url(external)
        if not _server_ready(external):
            pytest.fail(
                f"{PG_URL_ENV} is set but the server is unreachable: "
                f"{_safe_url(external)}"
            )
        yield external
        return

    base = f"postgresql+psycopg2://postgres:{PG_PASSWORD}@localhost:{PG_PORT}/{PG_ADMIN_DB}"

    if _server_ready(base):
        # Something is already listening (a previous run, or a dev container).
        yield base
        return

    if not _docker_available():
        pytest.skip(
            "Docker not available and PA_TEST_POSTGRES_URL unset — "
            "skipping PostgreSQL integration tests"
        )

    started_here = not _container_running()
    if started_here:
        subprocess.run(
            [
                "docker", "run", "-d", "--rm", "--name", PG_CONTAINER,
                "-e", f"POSTGRES_PASSWORD={PG_PASSWORD}",
                "-p", f"{PG_PORT}:5432",
                PG_IMAGE,
            ],
            check=True, capture_output=True,
        )

    for _ in range(60):
        if _server_ready(base):
            break
        time.sleep(1)
    else:
        if started_here:
            # Best-effort cleanup; check=False so a failure here doesn't mask
            # the pytest.fail below, which is the useful diagnostic.
            subprocess.run(
                ["docker", "rm", "-f", PG_CONTAINER], capture_output=True, check=False
            )
        pytest.fail("PostgreSQL container did not become ready in time")

    yield base

    if started_here:
        # check=False: teardown is best-effort — a failure here must not mask
        # the test result or the pytest.fail below.
        subprocess.run(["docker", "rm", "-f", PG_CONTAINER], capture_output=True, check=False)


@pytest.fixture
def postgres_url(postgres_server: str) -> Iterator[str]:
    """A freshly created, empty database; dropped afterwards.

    Each test gets its own database so migration state cannot leak between
    tests, and so tests remain order-independent.
    """
    db_name = f"pa_test_{uuid.uuid4().hex[:12]}"
    admin = sa.create_engine(postgres_server, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(sa.text(f'CREATE DATABASE "{db_name}"'))
    finally:
        admin.dispose()

    try:
        yield _admin_url(postgres_server, db_name)
    finally:
        _drop_database(postgres_server, db_name)


def _drop_database(server_url: str, db_name: str) -> None:
    """Drop *db_name*, terminating any lingering sessions first."""
    admin = sa.create_engine(server_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            # Terminate stragglers so DROP isn't blocked by a lingering
            # connection (e.g. a test that left an engine undisposed).
            conn.execute(
                sa.text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :db AND pid <> pg_backend_pid()"
                ),
                {"db": db_name},
            )
            conn.execute(sa.text(f'DROP DATABASE IF EXISTS "{db_name}"'))
    finally:
        admin.dispose()


def apply_postgres_settings(monkeypatch, url: str) -> None:
    """Point settings and the environment at *url*.

    The fixtures still yield a URL because 60 test call sites take one, and
    decomposing it here keeps that churn out of the tests. This is the only
    place a URL is parsed — production code builds them and never parses.
    """
    import sqlalchemy as sa

    from app.core.config import settings as app_settings

    parsed = sa.engine.make_url(url)
    values = {
        "database_type": "postgresql",
        "database_host": parsed.host,
        "database_port": parsed.port or 5432,
        "database_name": parsed.database,
        "database_user": parsed.username,
        "database_password": parsed.password,
        "database_password_file": None,
        "database_schema": None,
        "database_sslmode": "prefer",
        "database_sslrootcert": None,
        "database_sslcert": None,
        "database_sslkey": None,
    }
    for attr, value in values.items():
        monkeypatch.setattr(app_settings, attr, value)

    # The Alembic subprocess reads the environment, not this Settings object.
    monkeypatch.setenv("DATABASE_TYPE", "postgresql")
    monkeypatch.setenv("DATABASE_HOST", str(parsed.host))
    monkeypatch.setenv("DATABASE_PORT", str(parsed.port or 5432))
    monkeypatch.setenv("DATABASE_NAME", str(parsed.database))
    monkeypatch.setenv("DATABASE_USER", str(parsed.username))
    if parsed.password:
        monkeypatch.setenv("DATABASE_PASSWORD", parsed.password)
    else:
        monkeypatch.delenv("DATABASE_PASSWORD", raising=False)
    monkeypatch.delenv("DATABASE_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("DATABASE_SCHEMA", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
