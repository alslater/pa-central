"""Build database connection parameters from structured settings.

URLs are *built*, never parsed, and carry no query string. Everything a driver
needs beyond host/port/database/credentials travels as ``connect_args`` — typed
Python values that never make a lossy round trip through a string.

That is the whole design. A URI can spell one target several ways and libpq's
precedence rules between the authority and the query string are not obvious;
building removes the ambiguity rather than defending against it.
"""
import ssl

from sqlalchemy import text
from sqlalchemy.engine import URL, Connection, make_url

from app.core.config import Settings, settings


def _cfg(cfg: Settings | None) -> Settings:
    return settings if cfg is None else cfg


def resolved_password(cfg: Settings | None = None) -> str | None:
    """The password, from the literal setting or the secret file.

    The file's trailing newline is stripped: `echo secret > file` is the usual
    way to write one, and libpq would otherwise send the newline as part of the
    credential.
    """
    conf = _cfg(cfg)
    if conf.database_password:
        return conf.database_password
    if conf.database_password_file:
        with open(conf.database_password_file, encoding="utf-8") as handle:
            return handle.read().rstrip("\r\n")
    return None


def _build(cfg: Settings | None, drivername: str) -> str:
    conf = _cfg(cfg)
    if conf.database_type == "sqlite":
        return URL.create(
            drivername=drivername, database=conf.database_name
        ).render_as_string(hide_password=False)
    return URL.create(
        drivername=drivername,
        host=conf.database_host,
        port=conf.database_port,
        database=conf.database_name,
        username=conf.database_user,
        password=resolved_password(conf),
    ).render_as_string(hide_password=False)


def sync_url(cfg: Settings | None = None) -> str:
    """The synchronous URL, used by Alembic and the sync test engines."""
    conf = _cfg(cfg)
    driver = "sqlite" if conf.database_type == "sqlite" else "postgresql+psycopg2"
    return _build(conf, driver)


def async_url(cfg: Settings | None = None) -> str:
    """The asynchronous URL, used by the application engines."""
    conf = _cfg(cfg)
    driver = (
        "sqlite+aiosqlite" if conf.database_type == "sqlite" else "postgresql+asyncpg"
    )
    return _build(conf, driver)


def _quoted_search_path(schema: str) -> str:
    """A schema name as a single, unambiguous search_path list entry.

    search_path's own grammar splits on unquoted commas no matter what the
    caller meant — DATABASE_SCHEMA=a,b must select the one schema literally
    named "a,b", not the two schemas a and b. Double-quoting (with embedded
    double-quotes doubled, the standard SQL identifier escape) is the same
    rule Postgres uses for any search_path entry containing a comma, space,
    or other special character, verified directly against a live server:
    `SET search_path = "a,b"` reports search_path as "a,b" (one schema);
    `SET search_path = a,b` reports `a, b` (two schemas).
    """
    return '"' + schema.replace('"', '""') + '"'


def _libpq_options_escape(value: str) -> str:
    """Escape a value for embedding in libpq's `options` connection parameter.

    `options` is itself parsed shell-style by libpq, splitting on unescaped
    whitespace before the value ever reaches the server — so the double
    quotes _quoted_search_path just added, and any whitespace in the schema
    name, must be backslash-escaped or the server never sees a valid
    parameter at all. Verified directly against a live server: not just a
    literal space but tab, newline, carriage return, vertical tab, and form
    feed each independently produce the identical "invalid value for
    parameter search_path" failure when unescaped, and each round-trips
    correctly once backslash-escaped — matching Python's own str.isspace(),
    not just the space character.
    """
    escaped = value.replace("\\", "\\\\")
    return "".join("\\" + c if c == '"' or c.isspace() else c for c in escaped)


def sync_connect_args(cfg: Settings | None = None) -> dict:
    """psycopg2 connect kwargs: libpq TLS parameters and search_path."""
    conf = _cfg(cfg)
    if conf.database_type == "sqlite":
        return {"check_same_thread": False}

    args: dict = {"sslmode": conf.database_sslmode}
    for attr, key in (
        ("database_sslrootcert", "sslrootcert"),
        ("database_sslcert", "sslcert"),
        ("database_sslkey", "sslkey"),
    ):
        value = getattr(conf, attr)
        if value:
            args[key] = value

    if (
        conf.database_sslmode in ("verify-ca", "verify-full")
        and "sslrootcert" not in args
    ):
        # libpq's own default here is ~/.postgresql/root.crt — a per-user
        # dotfile unrelated to any system trust store — and the connection
        # fails outright if that file happens not to exist (verified live:
        # "root certificate file ... does not exist ... use the system's
        # trusted roots with sslrootcert=system"). asyncpg's
        # ssl.create_default_context() already falls back to the OS trust
        # store with no configuration at all, so without this, the identical
        # DATABASE_SSLROOTCERT-unset configuration would validate against
        # system roots on one driver and fail to even connect on the other.
        # sslrootcert=system is a real libpq 16+ feature (confirmed against
        # libpq 17.9 here via psycopg2.__libpq_version__), so this makes both
        # drivers agree on the default trust source instead.
        args["sslrootcert"] = "system"

    if conf.database_schema:
        search_path = _quoted_search_path(conf.database_schema)
        args["options"] = f"-csearch_path={_libpq_options_escape(search_path)}"
    return args


def _ssl_context(conf: Settings) -> ssl.SSLContext | bool | str:
    """Translate the libpq sslmode vocabulary into asyncpg's ssl= argument.

    asyncpg takes TLS material as an SSLContext object rather than as file
    paths, which is exactly what a URL could not express — and why client
    certificates previously worked only for the Alembic subprocess.

    `prefer` is deliberately NOT built as an SSLContext, unlike every other
    mode. asyncpg special-cases the *string* forms of sslmode
    (asyncpg.connect_utils.SSLMode): passing an SSLContext object at all makes
    it force sslmode to verify-full internally, which is mandatory TLS with no
    plaintext fallback — the opposite of what `prefer` means. Proven against a
    live non-TLS server: an SSLContext for `prefer` gets
    `ConnectionError: ... rejected SSL upgrade`, while the string `"prefer"`
    connects. Only the string form gets asyncpg's `ssl_is_advisory` retry path
    that actually implements "encrypt if possible, fall back to plaintext".
    """
    if conf.database_sslmode == "disable":
        return False
    if conf.database_sslmode == "prefer":
        return "prefer"

    context = ssl.create_default_context(cafile=conf.database_sslrootcert or None)
    if conf.database_sslmode == "require":
        # libpq's `require` behaves in two completely different ways
        # depending on whether sslrootcert is set — verified live: with none,
        # an unrelated/wrong CA still connects (no validation at all); the
        # moment sslrootcert points at a file, libpq silently upgrades to the
        # same validation verify-ca performs, and a wrong CA is rejected.
        # check_hostname must be cleared first in the no-rootcert branch —
        # CPython forbids CERT_NONE while it is set.
        if conf.database_sslrootcert:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    elif conf.database_sslmode == "verify-ca":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    else:  # verify-full
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

    if conf.database_sslcert and conf.database_sslkey:
        context.load_cert_chain(conf.database_sslcert, conf.database_sslkey)
    return context


def async_connect_args(cfg: Settings | None = None) -> dict:
    """asyncpg connect kwargs: an SSLContext and server_settings."""
    conf = _cfg(cfg)
    if conf.database_type == "sqlite":
        return {}

    args: dict = {"ssl": _ssl_context(conf)}
    if conf.database_schema:
        args["server_settings"] = {
            "search_path": _quoted_search_path(conf.database_schema)
        }
    return args


def ensure_schema_sync(connection: Connection, schema: str) -> None:
    """Create *schema* if it is absent — the sync-driver twin of
    app.main._ensure_schema, for Alembic.

    version_table_schema=settings.database_schema is passed to
    context.configure() in migrations/env.py regardless of whether the
    schema exists yet. app startup creates it beforehand
    (app.main._ensure_schema, inside the migration advisory-lock window),
    but a CLI-invoked `alembic upgrade head` — or a CI pipeline that runs
    migrations independently of the app — never goes through app startup at
    all. Without this, a missing schema surfaces as a raw
    ProgrammingError several frames deep in SQLAlchemy internals, naming
    neither DATABASE_SCHEMA nor how to fix it, reproduced live before this
    function existed.

    Check first, then create: `CREATE SCHEMA IF NOT EXISTS` raises
    InsufficientPrivilege even when the schema already exists — it is a
    permission check on the statement, not a guard — so always attempting it
    would break the normal production case, where a DBA provisions the
    schema and the application user holds only USAGE.
    """
    exists = connection.execute(
        text(
            "SELECT 1 FROM information_schema.schemata "
            "WHERE schema_name = :name"
        ),
        {"name": schema},
    ).scalar()
    if exists:
        # The SELECT above autobegins a transaction on this connection (a
        # SQLAlchemy Connection always does, whether or not the caller ever
        # calls begin() explicitly). Returning here without ending it left
        # that transaction open and handed straight to
        # migrations/env.py's context.configure(connection=connection, ...),
        # which inspects the connection at configure time and — finding it
        # already "in a transaction" — treats it as externally managed:
        # context.begin_transaction() then becomes a no-op that neither
        # Alembic nor this function ever commits. The migration DDL still
        # runs and `alembic upgrade head` still exits 0, but the connection
        # is closed uncommitted at the end of run_migrations_online()'s
        # `with connectable.connect() as connection:` block, and closing an
        # uncommitted connection rolls it back — silently discarding an
        # apparently successful migration. Reproduced live: upgrading
        # against a pre-existing schema left `alembic_version` missing
        # afterwards despite a clean exit code. Rolling back (rather than
        # committing) is correct here regardless: this branch only ever ran
        # a SELECT, so there is nothing to persist — the point is solely to
        # end the transaction before returning.
        connection.rollback()
        return

    try:
        # Not an f-string interpolation: a schema name cannot be bound as a
        # SQL parameter in DDL, and naively quoting it (f'"{schema}"') would
        # let an embedded `"` break out of the identifier —
        # IdentifierPreparer quotes it the way the dialect actually
        # requires, doubling any embedded quote.
        quoted = connection.dialect.identifier_preparer.quote(schema)
        connection.execute(text(f"CREATE SCHEMA {quoted}"))
        connection.commit()
    except Exception as exc:  # noqa: BLE001 — any DB error here becomes a clear startup failure
        raise RuntimeError(
            f"database schema {schema!r} does not exist and could not be "
            f"created: {exc}. Create it manually, or grant CREATE on the "
            "database."
        ) from None


def mask(value: str) -> str:
    """Render a URL with its password hidden, for logs and error messages."""
    try:
        return make_url(value).render_as_string(hide_password=True)
    except Exception:  # noqa: BLE001 — unparseable input must not be echoed back
        return "<unparseable URL>"
