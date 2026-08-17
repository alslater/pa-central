import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make app importable
sys.path.insert(0, str(Path(__file__).parents[1]))

import app.models  # noqa: F401 — registers all ORM models with Base.metadata
from app.core.config import settings
from app.core.database import Base
from app.core.db_config import (
    _quoted_search_path,
    ensure_schema_sync,
    sync_connect_args,
    sync_url,
)

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# Alembic has no async support, so it runs against the sync driver. Both the URL
# and the connection arguments come from the same structured settings the
# application uses, so the migration and the advisory lock cannot target
# different databases.
def get_sync_url() -> str:
    return sync_url()


def run_migrations_offline() -> None:
    context.configure(
        url=get_sync_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,
        version_table_schema=settings.database_schema,
    )
    with context.begin_transaction():
        if settings.database_schema:
            _emit_offline_schema_preamble(settings.database_schema)
        context.run_migrations()


def _dollar_quoted(body: str) -> str:
    """Wrap *body* in a dollar-quoted string using a tag guaranteed absent
    from *body* itself.

    Postgres dollar-quoting has no escape mechanism: it closes on the first
    literal occurrence of the tag, regardless of surrounding quote context.
    A fixed "$$" tag is unsafe here because *body* embeds a DATABASE_SCHEMA
    value with no character restriction — a schema name containing "$$"
    (valid once double-quoted, e.g. "a$$b") would close the block early and
    leave a dangling SQL fragment, reproduced live: `DO $$ ... schema_name =
    'a$$b') ... $$` raised `syntax error at or near "b') THEN EXECUTE '"`.
    """
    tag = ""
    suffix = 0
    while f"${tag}$" in body:
        suffix += 1
        tag = f"pa{suffix}"
    delim = f"${tag}$"
    return f"{delim}{body}{delim}"


def _emit_offline_schema_preamble(schema: str) -> None:
    """Write schema-creation and search_path statements into the generated
    --sql script.

    Offline mode never opens a connection, so unlike run_migrations_online()
    it can neither call ensure_schema_sync() to create *schema* nor rely on
    sync_connect_args()'s connection-level search_path — and the migration
    operations that follow use unqualified table names throughout. Without
    this, the generated script creates every application table in whatever
    the executor's default schema happens to be (usually public), not
    *schema*, and the schema-qualified `CREATE TABLE <schema>.alembic_version`
    statement immediately below fails outright if *schema* was never created
    at all — reproduced live via `alembic upgrade head --sql` with
    DATABASE_SCHEMA set before this fix existed.

    Checked-then-create (rather than a bare `CREATE SCHEMA IF NOT EXISTS`)
    mirrors ensure_schema_sync(): unconditionally attempting creation raises
    InsufficientPrivilege even when the schema already exists, which would
    break the common case this script is handed to — a DBA who provisions
    the schema ahead of time and grants the executing role only USAGE.
    """
    literal = schema.replace("'", "''")
    body = (
        " BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM information_schema.schemata "
        f"WHERE schema_name = '{literal}') THEN "
        f"EXECUTE 'CREATE SCHEMA ' || quote_ident('{literal}'); "
        "END IF; END "
    )
    context.execute(f"DO {_dollar_quoted(body)}")
    context.execute(f"SET search_path TO {_quoted_search_path(schema)}")


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = get_sync_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        connect_args=sync_connect_args(),
    )
    with connectable.connect() as connection:
        # version_table_schema below assumes the schema exists — true when the
        # app itself starts up (app.main._ensure_schema runs first), but a
        # CLI-invoked `alembic upgrade head` or a CI pipeline never goes
        # through app startup at all.
        if settings.database_schema:
            ensure_schema_sync(connection, settings.database_schema)

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,
            version_table_schema=settings.database_schema,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
