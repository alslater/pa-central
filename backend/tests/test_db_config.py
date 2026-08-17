"""Unit tests for structured database configuration.

No database required: these cover field declaration, validation, and the
URL/connect_args builders. Integration behaviour lives in
test_postgres_behaviour.py.
"""
import os
import shutil

import pytest

from app.core.config import Settings, validate_database_settings


def _settings(**overrides) -> Settings:
    """A Settings instance with the given DATABASE_* overrides.

    _env_file=None so a developer's .env cannot change the outcome.
    """
    base = {"debug": True, "_env_file": None}
    return Settings(**{**base, **overrides})


class TestAmbientDebugEnvIsSanitized:
    """conftest.py's _ensure_debug_env_is_a_valid_bool(), exercised directly.

    A known bug in the OpenAI Codex VS Code extension
    (github.com/openai/codex/issues/13694) leaks DEBUG=release into every
    other extension's spawned subprocesses, including the Python extension's
    pytest-discovery subprocess — breaking test discovery entirely with a
    pydantic ValidationError, since "release" is not a valid bool. Confirmed
    live via a direct os.environ dump inside conftest.py during a real IDE
    discovery failure before this fix existed.
    """

    def test_unparseable_ambient_value_is_replaced(self, monkeypatch):
        from tests.conftest import _ensure_debug_env_is_a_valid_bool

        monkeypatch.setenv("DEBUG", "release")
        _ensure_debug_env_is_a_valid_bool()
        assert os.environ["DEBUG"] == "true"

    def test_real_false_override_is_preserved(self, monkeypatch):
        from tests.conftest import _ensure_debug_env_is_a_valid_bool

        monkeypatch.setenv("DEBUG", "false")
        _ensure_debug_env_is_a_valid_bool()
        assert os.environ["DEBUG"] == "false"

    def test_unset_gets_the_true_default(self, monkeypatch):
        from tests.conftest import _ensure_debug_env_is_a_valid_bool

        monkeypatch.delenv("DEBUG", raising=False)
        _ensure_debug_env_is_a_valid_bool()
        assert os.environ["DEBUG"] == "true"

    def test_pydantic_short_boolean_forms_are_preserved(self, monkeypatch):
        """Pydantic accepts 'f', 'n', 't', 'y' as boolean strings (in addition
        to the common full forms). A real override using these valid short forms
        must be preserved, not rewritten to 'true'."""
        from tests.conftest import _ensure_debug_env_is_a_valid_bool

        for short_form in ("f", "n", "t", "y"):
            monkeypatch.setenv("DEBUG", short_form)
            _ensure_debug_env_is_a_valid_bool()
            assert (
                os.environ["DEBUG"] == short_form
            ), f"DEBUG={short_form} was incorrectly rewritten"


class TestEnvFileIsIndependentOfCwd:
    def test_env_file_path_does_not_depend_on_cwd(self):
        """A relative "env_file" resolves against whatever the current
        process's cwd happens to be, not this module's location — an IDE
        test runner or any launcher invoking Python from the repo root
        instead of backend/ would otherwise silently pick up a different,
        unrelated .env file one directory up. Confirmed live: a repo-root
        .env in this project genuinely exists with a stale DATABASE_URL left
        over from before the PA Fleet -> PA Central rename, and an IDE whose
        pytest cwd landed on the repo root picked it up and failed with
        "DATABASE_URL is no longer used" even though backend/.env (the
        correct file) has no such key."""
        from app.core.config import Settings

        env_file = Settings.model_config.get("env_file")
        assert os.path.isabs(env_file), (
            f"env_file is {env_file!r}, not absolute — resolution would "
            "depend on the caller's cwd"
        )
        assert os.path.basename(env_file) == ".env"
        # __file__ is backend/tests/test_db_config.py; two dirnames up is
        # backend/, which is where env_file must also resolve to.
        assert os.path.dirname(env_file) == os.path.dirname(
            os.path.dirname(__file__)
        )

    def test_legacy_detection_ignores_an_unrelated_cwd_dotenv(
        self, monkeypatch, tmp_path
    ):
        """A .env file that happens to sit in whatever directory a test
        runner launched Python from — but is not backend/.env — must not be
        read at all, even if it contains a legacy DATABASE_URL."""
        from app.core.config import _legacy_database_url_is_set

        other_dir = tmp_path / "unrelated_cwd"
        other_dir.mkdir()
        (other_dir / ".env").write_text(
            "DATABASE_URL=postgresql+asyncpg://u@h/db\n"
        )
        monkeypatch.chdir(other_dir)
        assert "DATABASE_URL" not in os.environ

        assert _legacy_database_url_is_set() is False


class TestDatabaseUrlIsRejected:
    def test_database_url_env_var_is_rejected(self, monkeypatch):
        """An old .env must fail loudly, not fall back to the SQLite default."""
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u@h/db")
        with pytest.raises(RuntimeError, match="DATABASE_URL is no longer used"):
            validate_database_settings(_settings())

    def test_error_names_the_replacement_variables(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u@h/db")
        with pytest.raises(RuntimeError) as exc:
            validate_database_settings(_settings())
        for name in ("DATABASE_TYPE", "DATABASE_HOST", "DATABASE_NAME"):
            assert name in str(exc.value)

    def test_error_does_not_echo_the_url(self, monkeypatch):
        """The old URL may carry a password."""
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:hunter2@h/db")
        with pytest.raises(RuntimeError) as exc:
            validate_database_settings(_settings())
        assert "hunter2" not in str(exc.value)

    def test_error_does_not_claim_a_password_is_required(self, monkeypatch):
        """validate_database_settings() itself accepts neither password form
        for peer, trust, or IAM authentication
        (TestPasswordSources.test_neither_password_form_is_valid) -- this
        message must not tell an operator using passwordless auth that they
        need to add credentials."""
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u@h/db")
        with pytest.raises(RuntimeError) as exc:
            validate_database_settings(_settings())
        message = str(exc.value)
        assert "one of DATABASE_PASSWORD" not in message
        assert "and DATABASE_USER" in message

    def test_database_url_in_dotenv_only_is_rejected(self, monkeypatch, tmp_path):
        """A DATABASE_URL sitting only in .env (not the real environment) is
        the exact old-.env upgrade case this check exists for. pydantic-settings
        loads env_file values through its own dotenv source without ever
        writing them into os.environ, so a naive os.environ.get("DATABASE_URL")
        check misses this case entirely and falls back to SQLite in silence."""
        from app.core import config as config_module

        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_URL=postgresql+asyncpg://u@h/db\n")
        monkeypatch.setitem(config_module.Settings.model_config, "env_file", str(env_file))
        assert "DATABASE_URL" not in os.environ

        with pytest.raises(RuntimeError, match="DATABASE_URL is no longer used"):
            validate_database_settings(_settings())

    def test_no_dotenv_file_does_not_false_positive(self, monkeypatch, tmp_path):
        """A missing .env file must not itself be mistaken for a legacy URL."""
        from app.core import config as config_module

        monkeypatch.setitem(
            config_module.Settings.model_config, "env_file", str(tmp_path / "does-not-exist.env")
        )
        validate_database_settings(_settings())

    @pytest.mark.parametrize("key", ["database_url", "Database_Url", "DATABASE_url"])
    def test_lowercase_or_mixed_case_env_var_is_rejected(self, monkeypatch, key):
        """pydantic-settings itself reads env vars case-insensitively by
        default (case_sensitive defaults to False, never overridden here) —
        the old Settings.database_url field this guard replaces was matched
        the same way, so a deployment running for months with a lowercase
        database_url in its real environment would have had it silently
        respected. Checking only the literal string "DATABASE_URL" via
        os.environ.get is case-sensitive regardless of pydantic's own
        matching, so that exact deployment's URL would now be silently
        ignored — a config that worked before this migration and used to
        connect to PostgreSQL would silently start using SQLite instead."""
        monkeypatch.setenv(key, "postgresql+asyncpg://u@h/db")
        with pytest.raises(RuntimeError, match="DATABASE_URL is no longer used"):
            validate_database_settings(_settings())

    @pytest.mark.parametrize("key", ["database_url", "Database_Url", "DATABASE_url"])
    def test_lowercase_or_mixed_case_dotenv_key_is_rejected(
        self, monkeypatch, tmp_path, key
    ):
        """Same case-insensitivity gap, but for the .env file rather than the
        real environment — dotenv_values() returns a plain dict keyed
        exactly as written in the file, so a naive values.get("DATABASE_URL")
        also misses a lowercase key."""
        from app.core import config as config_module

        env_file = tmp_path / ".env"
        env_file.write_text(f"{key}=postgresql+asyncpg://u@h/db\n")
        monkeypatch.setitem(config_module.Settings.model_config, "env_file", str(env_file))
        assert "DATABASE_URL" not in os.environ

        with pytest.raises(RuntimeError, match="DATABASE_URL is no longer used"):
            validate_database_settings(_settings())


class TestSqliteRejectsPostgresFields:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("database_host", "db.example.com"),
            ("database_user", "pa"),
            ("database_password", "pw"),
            ("database_password_file", "/run/secrets/pw"),
            ("database_schema", "app"),
            ("database_sslrootcert", "/ca.pem"),
            ("database_sslcert", "/c.pem"),
            ("database_sslkey", "/k.pem"),
        ],
    )
    def test_postgres_only_field_under_sqlite_is_rejected(self, field, value):
        """Silently ignoring these produces 'I set DATABASE_HOST and nothing happened'."""
        with pytest.raises(RuntimeError, match="only apply when DATABASE_TYPE=postgresql"):
            validate_database_settings(_settings(database_type="sqlite", **{field: value}))

    def test_the_offending_field_is_named(self):
        with pytest.raises(RuntimeError) as exc:
            validate_database_settings(
                _settings(database_type="sqlite", database_host="db.example.com")
            )
        assert "DATABASE_HOST" in str(exc.value)

    def test_sqlite_with_only_a_name_is_valid(self):
        validate_database_settings(_settings(database_type="sqlite", database_name="/tmp/x.db"))

    def test_sqlite_defaults_to_a_file_beside_the_source(self):
        """Zero-config `git clone && pytest` must keep working. A None default
        would build `sqlite+aiosqlite://` — an in-memory database that silently
        discards everything written to it."""
        cfg = _settings()
        assert cfg.database_type == "sqlite"
        assert cfg.database_name is not None
        assert cfg.database_name.endswith("pa_central.db")

    def test_empty_sqlite_name_is_rejected(self):
        """DATABASE_NAME= (empty string) is a valid str, so pydantic accepts
        it and overrides the file-path default with "" — which URL.create()
        happily turns into sqlite:/// (in-memory), with no error anywhere.
        Confirmed live: SQLAlchemy's default pool opens a fresh :memory:
        database per connection, so even a single running process would see
        a different empty database on every pooled connection, on top of
        losing everything at restart."""
        with pytest.raises(RuntimeError, match="DATABASE_NAME"):
            validate_database_settings(
                _settings(database_type="sqlite", database_name="")
            )

    def test_explicit_none_sqlite_name_is_rejected(self):
        """DATABASE_NAME unset falls back to the file-path default (see the
        zero-config test above) — but a caller can still pass database_name=
        None directly, which must be rejected the same way as the empty
        string rather than silently building sqlite:// (in-memory)."""
        with pytest.raises(RuntimeError, match="DATABASE_NAME"):
            validate_database_settings(
                _settings(database_type="sqlite", database_name=None)
            )


class TestPostgresRequiredFields:
    def test_missing_fields_are_all_reported(self):
        """One startup, one list — not one error per run."""
        with pytest.raises(RuntimeError) as exc:
            validate_database_settings(_settings(database_type="postgresql"))
        message = str(exc.value)
        for name in ("DATABASE_HOST", "DATABASE_NAME", "DATABASE_USER"):
            assert name in message

    def test_complete_postgres_config_is_valid(self):
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h",
            database_name="pa", database_user="u", database_password="pw",
        ))

    def test_compose_sqlite_default_does_not_mask_missing_name(self):
        """docker-compose.yml's own DATABASE_NAME fallback
        (`${DATABASE_NAME:-./data/pa_central.db}`) is applied unconditionally —
        Compose's environment: block cannot vary a default based on another
        variable's value, so it is forwarded into the container even when
        DATABASE_TYPE=postgresql is set without an explicit DATABASE_NAME.
        Without this check, that non-empty string satisfies the bare
        `bool(cfg.database_name)` test below and startup proceeds, only to
        fail much later at connection time against a PostgreSQL server with a
        misleading "database does not exist" error naming a path-shaped
        string instead of a startup error naming DATABASE_NAME as missing."""
        with pytest.raises(RuntimeError, match="DATABASE_NAME"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h",
                database_name="./data/pa_central.db", database_user="u",
            ))


class TestPortValidation:
    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_out_of_range_port_is_rejected(self, port):
        """database_port is a plain int with no range constraint, so 0, a
        negative number, or anything above 65535 all pass Pydantic's typing
        and sailed through validate_database_settings() entirely — confirmed
        directly: URL.create() builds a syntactically valid URL string for
        every one of these (e.g. postgresql+asyncpg://u:p@h:99999/d), so the
        only failure was ever going to be a confusing connection-time error,
        not a startup message naming DATABASE_PORT as the problem."""
        with pytest.raises(RuntimeError, match="DATABASE_PORT"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h",
                database_name="pa", database_user="u",
                database_password="pw", database_port=port,
            ))

    @pytest.mark.parametrize("port", [1, 5432, 65535])
    def test_boundary_and_typical_ports_are_valid(self, port):
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h",
            database_name="pa", database_user="u",
            database_password="pw", database_port=port,
        ))


class TestPasswordSources:
    def test_both_password_forms_is_rejected(self, tmp_path):
        pw_file = tmp_path / "pw"
        pw_file.write_text("filepw", encoding="utf-8")
        with pytest.raises(RuntimeError, match="not both"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_password="pw",
                database_password_file=str(pw_file),
            ))

    def test_unreadable_password_file_is_rejected(self, tmp_path):
        with pytest.raises(RuntimeError, match="DATABASE_PASSWORD_FILE"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_password_file=str(tmp_path / "missing"),
            ))

    def test_neither_password_form_is_valid(self):
        """Peer/trust auth and IAM-injected passwords are legitimate."""
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h",
            database_name="pa", database_user="u",
        ))


class TestTlsValidation:
    def test_invalid_sslmode_is_rejected(self):
        with pytest.raises(RuntimeError, match="DATABASE_SSLMODE"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslmode="bogus",
            ))

    def test_libpq_allow_is_rejected(self):
        """`allow` prefers plaintext and has no SSLContext equivalent."""
        with pytest.raises(RuntimeError, match="DATABASE_SSLMODE"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslmode="allow",
            ))

    @pytest.mark.parametrize(
        "mode", ["disable", "prefer", "require", "verify-full"]
    )
    def test_accepted_sslmodes(self, mode):
        """verify-ca is deliberately excluded here: with no explicit
        DATABASE_SSLROOTCERT, verify-ca now requires one — see
        TestVerifyCaRequiresAnExplicitRoot."""
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode=mode,
        ))

    def test_sslcert_without_sslkey_is_rejected(self, tmp_path):
        cert = tmp_path / "c.pem"
        cert.write_text("x", encoding="utf-8")
        with pytest.raises(RuntimeError, match="DATABASE_SSLKEY"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslcert=str(cert),
            ))

    def test_sslkey_without_sslcert_is_rejected(self, tmp_path):
        key = tmp_path / "k.pem"
        key.write_text("x", encoding="utf-8")
        with pytest.raises(RuntimeError, match="DATABASE_SSLCERT"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslkey=str(key),
            ))

    def test_missing_cert_file_is_rejected_at_startup(self, tmp_path):
        """Better than failing at the first connection attempt."""
        with pytest.raises(RuntimeError, match="DATABASE_SSLROOTCERT"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslrootcert=str(tmp_path / "missing.pem"),
            ))

    @pytest.mark.parametrize("mode", ["disable", "prefer"])
    def test_client_certs_with_disable_or_prefer_is_rejected(self, mode, tmp_path):
        """asyncpg only accepts sslcert/sslkey through a DSN query string or
        PGSSLCERT/PGSSLKEY — never as connect() keyword arguments — and this
        module deliberately builds no query string and reads no such env vars.
        `prefer`'s plaintext-fallback also requires passing ssl="prefer" as a
        bare string rather than an SSLContext (see _ssl_context's docstring),
        and there is no way to attach a cert chain to that string. So a client
        certificate configured under `disable` or `prefer` can authenticate on
        the sync/psycopg2 side (Alembic) but is silently never presented on
        the async/asyncpg side (the running application) — an asymmetry that
        would only surface as an unexplained auth failure in production.
        Rejecting at startup makes the operator pick a mode that actually
        sends the certificate on both drivers."""
        cert, key = (tmp_path / n for n in ("c.pem", "k.pem"))
        cert.write_text("x", encoding="utf-8")
        key.write_text("x", encoding="utf-8")
        with pytest.raises(RuntimeError, match="DATABASE_SSLMODE"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslmode=mode,
                database_sslcert=str(cert), database_sslkey=str(key),
            ))

    def test_accepted_sslmodes_without_certs_still_pass(self):
        """The reject-with-certs rule must not regress the plain no-cert case
        that test_accepted_sslmodes already covers for every mode."""
        for mode in ("disable", "prefer"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslmode=mode,
            ))

    @pytest.mark.parametrize("mode", ["disable", "prefer"])
    def test_rootcert_with_disable_or_prefer_is_rejected(self, mode, tmp_path):
        """_ssl_context() returns before ever loading the CA under `disable`
        (no TLS session at all) and `prefer` (passed to asyncpg as the bare
        string "prefer", which cannot carry a trust store — an SSLContext
        would force full verification and break the plaintext fallback, see
        _ssl_context's docstring). libpq behaves the same way: neither mode
        verifies the server certificate regardless of sslrootcert. So an
        operator who supplies DATABASE_SSLROOTCERT under these modes gets no
        certificate verification while the presence of a trust root suggests
        otherwise. Rejecting at startup forces a mode that actually uses the
        CA, mirroring the client-cert rule above."""
        ca = tmp_path / "ca.pem"
        ca.write_text("x", encoding="utf-8")
        with pytest.raises(
            RuntimeError, match="DATABASE_SSLROOTCERT is configured"
        ):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslmode=mode,
                database_sslrootcert=str(ca),
            ))

    def test_rootcert_with_require_is_still_accepted(self, tmp_path):
        """`require` + rootcert must not be swept into the rejection: it is
        the one mode where a supplied CA upgrades behaviour (chain
        verification) on both drivers — _ssl_context() sets CERT_REQUIRED,
        and libpq documents the same root-CA backward-compatibility
        promotion for `require`."""
        ca = tmp_path / "ca.pem"
        ca.write_text("x", encoding="utf-8")
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="require",
            database_sslrootcert=str(ca),
        ))


class TestVerifyCaRequiresAnExplicitRoot:
    def test_verify_ca_without_a_rootcert_is_rejected(self):
        """sync_connect_args() defaults to sslrootcert="system" for both
        verify-ca and verify-full when DATABASE_SSLROOTCERT is unset — but
        libpq itself refuses that specific combination outright, confirmed
        live: `psql "sslmode=verify-ca sslrootcert=system"` fails immediately
        with 'weak sslmode "verify-ca" may not be used with sslrootcert=system
        (use "verify-full")', before any network attempt at all. System roots
        are broad public CAs meant for verifying arbitrary named hosts;
        libpq considers chain-only trust (verify-ca has no hostname check)
        against that broad a trust store too weak to allow, and requires
        either an explicit (presumably private) CA or a hostname-checked
        verify-full. asyncpg has no equivalent restriction, so leaving this
        unrejected would mean DATABASE_SSLMODE=verify-ca with no
        DATABASE_SSLROOTCERT works on the async driver but can never
        connect at all on the sync driver (Alembic)."""
        with pytest.raises(RuntimeError, match="DATABASE_SSLROOTCERT"):
            validate_database_settings(_settings(
                database_type="postgresql", database_host="h", database_name="pa",
                database_user="u", database_sslmode="verify-ca",
            ))

    def test_verify_ca_with_a_rootcert_is_accepted(self, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("x", encoding="utf-8")
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="verify-ca",
            database_sslrootcert=str(ca),
        ))

    def test_verify_full_without_a_rootcert_is_still_accepted(self):
        """Only verify-ca is restricted — verify-full + sslrootcert=system is
        a combination libpq accepts (confirmed live: it fails only at the
        actual connection attempt, never at parameter validation), so
        verify-full must not be swept into this rejection."""
        validate_database_settings(_settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="verify-full",
        ))


class TestUrlBuilders:
    def test_sqlite_async_url(self):
        from app.core.db_config import async_url

        cfg = _settings(database_type="sqlite", database_name="/tmp/x.db")
        assert async_url(cfg) == "sqlite+aiosqlite:////tmp/x.db"

    def test_sqlite_sync_url(self):
        from app.core.db_config import sync_url

        cfg = _settings(database_type="sqlite", database_name="/tmp/x.db")
        assert sync_url(cfg) == "sqlite:////tmp/x.db"

    def test_postgres_async_url(self):
        from app.core.db_config import async_url

        cfg = _settings(
            database_type="postgresql", database_host="db.example.com",
            database_port=5433, database_name="pa", database_user="u",
            database_password="pw",
        )
        assert async_url(cfg) == "postgresql+asyncpg://u:pw@db.example.com:5433/pa"

    def test_postgres_sync_url(self):
        from app.core.db_config import sync_url

        cfg = _settings(
            database_type="postgresql", database_host="db.example.com",
            database_port=5433, database_name="pa", database_user="u",
            database_password="pw",
        )
        assert sync_url(cfg) == "postgresql+psycopg2://u:pw@db.example.com:5433/pa"

    def test_urls_carry_no_query_string(self):
        """The whole point: nothing rides in the query, so nothing can be
        misparsed, aliased, or given the wrong precedence."""
        import sqlalchemy as sa

        from app.core.db_config import async_url, sync_url

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_password="pw", database_sslmode="verify-full",
            database_schema="app",
        )
        for built in (sync_url(cfg), async_url(cfg)):
            assert sa.engine.make_url(built).query == {}

    def test_password_special_characters_survive(self):
        """URL.create escapes on render; a naive f-string would corrupt this."""
        import sqlalchemy as sa

        from app.core.db_config import sync_url

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_password="p@ss:w/rd?#",
        )
        assert sa.engine.make_url(sync_url(cfg)).password == "p@ss:w/rd?#"


class TestResolvedPassword:
    def test_literal_password(self):
        from app.core.db_config import resolved_password

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_password="literal",
        )
        assert resolved_password(cfg) == "literal"

    def test_password_from_file(self, tmp_path):
        from app.core.db_config import resolved_password

        pw_file = tmp_path / "pw"
        pw_file.write_text("frimfile\n", encoding="utf-8")
        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_password_file=str(pw_file),
        )
        # Trailing newline stripped: `echo secret > file` is the common way to
        # write one, and libpq would otherwise send the newline as part of it.
        assert resolved_password(cfg) == "frimfile"

    def test_leading_newline_in_password_is_preserved(self, tmp_path):
        """Only the trailing newline added by tools like `echo` is part of
        the contract — a password that itself starts with CR/LF must survive
        untouched, not be silently truncated."""
        from app.core.db_config import resolved_password

        pw_file = tmp_path / "pw"
        # `open(..., encoding="utf-8")` performs universal-newline translation
        # on read, so a leading "\r\n" on disk would arrive as "\n" regardless
        # of this fix — write a bare "\n" so the test isolates strip direction.
        pw_file.write_text("\nfrimfile\n", encoding="utf-8")
        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_password_file=str(pw_file),
        )
        assert resolved_password(cfg) == "\nfrimfile"

    def test_no_password(self):
        from app.core.db_config import resolved_password

        cfg = _settings(
            database_type="postgresql", database_host="h",
            database_name="pa", database_user="u",
        )
        assert resolved_password(cfg) is None


class TestSyncConnectArgs:
    def test_sqlite_gets_check_same_thread(self):
        from app.core.db_config import sync_connect_args

        cfg = _settings(database_type="sqlite", database_name="/tmp/x.db")
        assert sync_connect_args(cfg) == {"check_same_thread": False}

    def test_sslmode_is_passed_through(self):
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="verify-full",
        )
        assert sync_connect_args(cfg)["sslmode"] == "verify-full"

    def test_cert_paths_are_passed_through(self, tmp_path):
        from app.core.db_config import sync_connect_args

        ca, cert, key = (tmp_path / n for n in ("ca.pem", "c.pem", "k.pem"))
        for path in (ca, cert, key):
            path.write_text("x", encoding="utf-8")
        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="verify-full",
            database_sslrootcert=str(ca), database_sslcert=str(cert),
            database_sslkey=str(key),
        )
        args = sync_connect_args(cfg)
        assert args["sslrootcert"] == str(ca)
        assert args["sslcert"] == str(cert)
        assert args["sslkey"] == str(key)

    @pytest.mark.parametrize("mode", ["verify-ca", "verify-full"])
    def test_no_rootcert_falls_back_to_system_roots(self, mode):
        """Without this, libpq's own default for verify-ca/verify-full is
        `~/.postgresql/root.crt` — a per-user dotfile unrelated to any system
        trust store — and the connection fails outright if that file happens
        not to exist, verified live against a real server: "root certificate
        file ... does not exist ... use the system's trusted roots with
        sslrootcert=system". Meanwhile asyncpg's ssl.create_default_context()
        already falls back to the OS trust store with no configuration at
        all. Passing sslrootcert="system" explicitly (a libpq 16+ feature —
        see TestPsycopg2VersionFloor for the pyproject.toml floor this
        depends on) makes both drivers validate against the same system
        trust store by default instead of one requiring a file the other
        doesn't need."""
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode=mode,
        )
        assert sync_connect_args(cfg)["sslrootcert"] == "system"

    def test_explicit_rootcert_is_not_overridden(self, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("x", encoding="utf-8")
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="verify-full",
            database_sslrootcert=str(ca),
        )
        assert sync_connect_args(cfg)["sslrootcert"] == str(ca)

    def test_require_gets_no_default_rootcert(self):
        """Only verify-ca/verify-full get the system-roots default: require
        with no rootcert must stay encrypt-only, matching libpq exactly."""
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="require",
        )
        assert "sslrootcert" not in sync_connect_args(cfg)

    def test_schema_becomes_a_search_path_option(self):
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema="app",
        )
        assert sync_connect_args(cfg)["options"] == r'-csearch_path=\"app\"'

    def test_no_schema_means_no_options_key(self):
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h",
            database_name="pa", database_user="u",
        )
        assert "options" not in sync_connect_args(cfg)

    def test_schema_with_a_comma_is_not_interpreted_as_a_list(self):
        """DATABASE_SCHEMA=a,b must select the single schema literally named
        "a,b" — not the two schemas a and b. search_path's own grammar treats
        an unquoted comma as a list separator regardless of the caller's
        intent, so the value must be double-quoted the way Postgres requires
        for any search_path entry containing one.

        The options string adds a second layer: libpq parses -c values
        shell-style, splitting on unescaped whitespace, so the quotes and any
        space in the schema name must themselves be backslash-escaped or the
        server never sees a valid parameter at all."""
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema="a,b",
        )
        assert sync_connect_args(cfg)["options"] == r'-csearch_path=\"a,b\"'

    def test_schema_with_a_space_does_not_break_the_options_string(self):
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema="has space",
        )
        assert sync_connect_args(cfg)["options"] == r'-csearch_path=\"has\ space\"'

    def test_schema_with_an_embedded_quote_is_escaped(self):
        """Worst case: comma, space, and an embedded double-quote together —
        every layer of escaping (search_path quoting, quote-doubling, and
        options backslash-escaping) has to compose correctly at once."""
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema='a,b "c',
        )
        assert (
            sync_connect_args(cfg)["options"]
            == r'-csearch_path=\"a,b\ \"\"c\"'
        )

    @pytest.mark.parametrize(
        ("name", "char"),
        [
            ("tab", "\t"),
            ("newline", "\n"),
            ("carriage_return", "\r"),
            ("vertical_tab", "\v"),
            ("form_feed", "\f"),
        ],
    )
    def test_schema_with_other_whitespace_is_escaped(self, name, char):
        """Only the literal space character was ever backslash-escaped, but
        libpq's options tokenizer splits on ALL whitespace it treats as a
        separator — verified live against a real server: an unescaped tab,
        newline, carriage return, vertical tab, or form feed in the options
        value all produce the identical "invalid value for parameter
        search_path" failure that an unescaped space does, and backslash-
        escaping each of them (exactly like space) round-trips the literal
        character through search_path correctly. Before this fix, a schema
        name containing a tab would build a value that *creates* successfully
        (CREATE SCHEMA takes the name as a bound parameter, unaffected by any
        of this) but silently corrupts or breaks the sync driver's actual
        search_path — a schema that exists and works over asyncpg would be
        unreachable over psycopg2/Alembic."""
        from app.core.db_config import sync_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema=f"has{char}char",
        )
        options = sync_connect_args(cfg)["options"]
        assert options == f'-csearch_path=\\"has\\{char}char\\"'


class TestAsyncConnectArgs:
    def test_sqlite_has_no_connect_args(self):
        from app.core.db_config import async_connect_args

        cfg = _settings(database_type="sqlite", database_name="/tmp/x.db")
        assert async_connect_args(cfg) == {}

    def test_disable_yields_ssl_false(self):
        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="disable",
        )
        assert async_connect_args(cfg)["ssl"] is False

    def test_prefer_yields_the_string_not_a_context(self):
        """`prefer` must not be built as an SSLContext, unlike every other mode.

        asyncpg forces sslmode to verify-full internally whenever `ssl` is an
        SSLContext object at all (asyncpg.connect_utils), which is mandatory TLS
        with no plaintext fallback — the opposite of what `prefer` means. Only
        the string form gets asyncpg's ssl_is_advisory retry path that actually
        implements "encrypt if possible, fall back to plaintext". Verified
        against a live non-TLS server: an SSLContext for `prefer` raised
        `ConnectionError: ... rejected SSL upgrade`; the string connected.
        """
        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="prefer",
        )
        assert async_connect_args(cfg)["ssl"] == "prefer"

    @pytest.mark.parametrize(
        ("mode", "check_hostname", "verify_mode_name"),
        [
            ("require", False, "CERT_NONE"),
            ("verify-ca", False, "CERT_REQUIRED"),
            ("verify-full", True, "CERT_REQUIRED"),
        ],
    )
    def test_ssl_context_matches_the_mode(self, mode, check_hostname, verify_mode_name):
        """asyncpg takes an SSLContext, not libpq's file paths — this mapping is
        what makes client certificates work on the async driver at all."""
        import ssl

        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode=mode,
        )
        ctx = async_connect_args(cfg)["ssl"]
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is check_hostname
        assert ctx.verify_mode is getattr(ssl, verify_mode_name)

    @pytest.mark.skipif(
        shutil.which("openssl") is None,
        reason="openssl binary not available",
    )
    def test_require_with_a_rootcert_validates_like_libpq(self, tmp_path):
        """libpq's `require` behaves completely differently depending on
        whether sslrootcert is set: with none, it encrypts without validating
        anything (verified live: a connection with an unrelated CA still
        succeeds); but the moment sslrootcert points at a file, libpq silently
        upgrades to the same validation verify-ca performs (verified live:
        the identical connection then fails with "certificate verify
        failed" against a CA that did not sign the server certificate). Before
        this fix, our asyncpg path ignored sslrootcert entirely under
        `require` and always used CERT_NONE, so the same DATABASE_SSLROOTCERT
        setting validated on the sync driver but not the async one — the
        actual application connection had no certificate protection at all
        while an operator believed it did.
        """
        import ssl
        import subprocess

        from app.core.db_config import async_connect_args

        ca = tmp_path / "ca.pem"
        key = tmp_path / "ca-key.pem"
        subprocess.run(
            ["openssl", "req", "-new", "-x509", "-nodes", "-days", "1",
             "-subj", "/CN=test-ca", "-keyout", str(key), "-out", str(ca)],
            capture_output=True, check=True,
        )
        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="require",
            database_sslrootcert=str(ca),
        )
        ctx = async_connect_args(cfg)["ssl"]
        assert ctx.verify_mode is ssl.CERT_REQUIRED

    def test_require_without_a_rootcert_still_does_not_validate(self):
        """The no-rootcert case must be unchanged: libpq's `require` with no
        root file encrypts only, so ours must keep matching that."""
        import ssl

        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_sslmode="require",
        )
        ctx = async_connect_args(cfg)["ssl"]
        assert ctx.verify_mode is ssl.CERT_NONE

    def test_schema_becomes_server_settings(self):
        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema="app",
        )
        assert async_connect_args(cfg)["server_settings"] == {"search_path": '"app"'}

    def test_schema_with_a_comma_is_not_interpreted_as_a_list(self):
        """search_path treats an unquoted comma as a list separator no matter
        what the caller meant, so DATABASE_SCHEMA=a,b must be sent as the
        quoted single entry "a,b", not the bare two-element list a,b."""
        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema="a,b",
        )
        assert async_connect_args(cfg)["server_settings"] == {"search_path": '"a,b"'}

    def test_schema_with_an_embedded_quote_is_escaped(self):
        from app.core.db_config import async_connect_args

        cfg = _settings(
            database_type="postgresql", database_host="h", database_name="pa",
            database_user="u", database_schema='a"b',
        )
        assert async_connect_args(cfg)["server_settings"] == {
            "search_path": '"a""b"'
        }


class TestMask:
    def test_password_is_hidden(self):
        from app.core.db_config import mask

        out = mask("postgresql+psycopg2://u:hunter2@h:5432/pa")
        assert "hunter2" not in out
        assert "h:5432" in out

    def test_unparseable_input_is_not_echoed(self):
        from app.core.db_config import mask

        assert mask("not a url") == "<unparseable URL>"


class TestEngineConstruction:
    def test_engine_is_built_from_structured_config(self):
        """The app engine must not read settings.database_url."""
        import inspect

        from app.core import database

        source = inspect.getsource(database)
        assert "database_url" not in source, (
            "database.py still references the removed database_url setting"
        )
        assert "async_url" in source

    def test_sqlite_pragma_is_keyed_off_database_type(self):
        """The old code tested `"sqlite" in settings.database_url`, which would
        also match a PostgreSQL database literally named 'sqlite'."""
        import inspect

        from app.core import database

        source = inspect.getsource(database)
        assert 'database_type == "sqlite"' in source


class TestAlembicEnv:
    def test_env_does_not_read_an_override_variable(self):
        """ALEMBIC_DATABASE_URL existed only because a URL could not carry
        client certificates to asyncpg. Structured config renders each driver's
        TLS form directly, so the override — and the whole class of
        migrate-a-different-database bugs it enabled — is gone."""
        from pathlib import Path

        env_py = Path(__file__).resolve().parents[1] / "migrations" / "env.py"
        source = env_py.read_text(encoding="utf-8")
        assert "ALEMBIC_DATABASE_URL" not in source
        assert "assert_same_target" not in source
        assert "sync_url" in source


class TestAlembicSubprocessEnv:
    def test_structured_vars_are_passed_explicitly(self):
        """The subprocess must migrate the database this process locked, not
        whatever the ambient environment happens to hold."""
        import inspect

        from app import main

        source = inspect.getsource(main._alembic_upgrade)
        assert "DATABASE_URL" not in source
        assert "assert_same_target" not in source
        for name in ("DATABASE_TYPE", "DATABASE_HOST", "DATABASE_NAME"):
            assert name in source

    def test_stale_ambient_vars_are_cleared_not_inherited(self, monkeypatch):
        """A DATABASE_* var left over from an unrelated ambient environment
        (e.g. a shell that once exported DATABASE_HOST for a different
        database) must not leak into the migration subprocess just because
        this process's own settings leave that field unset. Each field is set
        to an explicit empty string rather than left absent — a merely-popped
        key would let the subprocess's own Settings() construction fall back
        to a same-named value in backend/.env instead (see
        TestAlembicSubprocessEnvDoesNotFallBackToDotenv)."""
        import subprocess

        from app import main

        for name, stale in (
            ("DATABASE_HOST", "stale-host.invalid"),
            ("DATABASE_USER", "stale-user"),
            ("DATABASE_SCHEMA", "stale_schema"),
            ("DATABASE_SSLROOTCERT", "/stale/ca.pem"),
            ("DATABASE_SSLCERT", "/stale/cert.pem"),
            ("DATABASE_SSLKEY", "/stale/key.pem"),
            ("DATABASE_PASSWORD", "stale-password"),
        ):
            monkeypatch.setenv(name, stale)

        monkeypatch.setattr(main.settings, "database_host", None)
        monkeypatch.setattr(main.settings, "database_user", None)
        monkeypatch.setattr(main.settings, "database_schema", None)
        monkeypatch.setattr(main.settings, "database_sslrootcert", None)
        monkeypatch.setattr(main.settings, "database_sslcert", None)
        monkeypatch.setattr(main.settings, "database_sslkey", None)
        monkeypatch.setattr(main.settings, "database_password", None)
        monkeypatch.setattr(main.settings, "database_password_file", None)

        captured = {}

        def fake_run(*args, **kwargs):
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        main._alembic_upgrade(backend_dir=".")

        env = captured["env"]
        for name in (
            "DATABASE_HOST",
            "DATABASE_USER",
            "DATABASE_SCHEMA",
            "DATABASE_SSLROOTCERT",
            "DATABASE_SSLCERT",
            "DATABASE_SSLKEY",
            "DATABASE_PASSWORD",
        ):
            assert env[name] == "", f"{name} leaked a stale ambient value: {env[name]!r}"

    def test_stale_ambient_vars_are_cleared_regardless_of_case(self, monkeypatch):
        """Settings are read case-insensitively (pydantic-settings never sets
        case_sensitive=True), so a lowercase or mixed-case ambient
        database_password_file is exactly as live a threat as the uppercase
        form — e.g. it would reach the subprocess alongside the freshly
        resolved DATABASE_PASSWORD and trip Settings' own
        'Set DATABASE_PASSWORD or DATABASE_PASSWORD_FILE, not both' check."""
        import subprocess

        from app import main

        monkeypatch.setenv("database_password_file", "/stale/lower/pw")
        monkeypatch.setenv("Database_Sslmode", "verify-full")

        monkeypatch.setattr(main.settings, "database_password", "literal-pw")
        monkeypatch.setattr(main.settings, "database_password_file", None)

        captured = {}

        def fake_run(*args, **kwargs):
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        main._alembic_upgrade(backend_dir=".")

        env = captured["env"]
        assert "database_password_file" not in env, (
            "a lowercase ambient database_password_file leaked into the "
            "subprocess env alongside the real DATABASE_PASSWORD"
        )
        assert "Database_Sslmode" not in env, "Database_Sslmode leaked"
        assert env["DATABASE_PASSWORD"] == "literal-pw"
        assert env["DATABASE_PASSWORD_FILE"] == ""


class TestAlembicSubprocessEnvDoesNotFallBackToDotenv:
    """Removing a key from the child's os.environ dict does not hide a value
    from backend/.env, because the subprocess's own Settings() construction
    (triggered when Alembic's env.py imports app.core.config) reloads that
    same file. pydantic-settings' env-var source only outranks its dotenv
    source when the key is actually present in os.environ -- even as an
    empty string -- confirmed live: a *missing* key falls through to
    whatever the configured env_file defines. In a documented direct-run
    setup using DATABASE_PASSWORD_FILE, the parent would resolve the secret
    into DATABASE_PASSWORD, then the child would reload DATABASE_PASSWORD_FILE
    from .env, tripping the 'not both' validation."""

    @staticmethod
    def _settings_read_back_through(monkeypatch, env: dict, env_file) -> "Settings":
        """Reconstruct Settings the way the Alembic subprocess would: fresh
        process, same os.environ, same env_file on disk."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class _ChildSettings(BaseSettings):
            model_config = SettingsConfigDict(env_file=str(env_file), extra="ignore")

            database_password: str | None = None
            database_password_file: str | None = None
            database_host: str | None = None

        monkeypatch.setattr(os, "environ", env)
        return _ChildSettings()

    def test_password_file_does_not_leak_back_from_dotenv(self, monkeypatch, tmp_path):
        import subprocess

        from app import main

        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_PASSWORD_FILE=/from/dotenv\n")

        monkeypatch.setattr(main.settings, "database_password_file", None)
        monkeypatch.setattr(main, "resolved_password", lambda: "resolved-pw")

        captured = {}

        def fake_run(*args, **kwargs):
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        main._alembic_upgrade(backend_dir=".")

        child = self._settings_read_back_through(monkeypatch, captured["env"], env_file)
        assert not child.database_password_file, (
            "the subprocess's own Settings() fell back to backend/.env's "
            "DATABASE_PASSWORD_FILE despite the parent already resolving "
            f"the password: {child.database_password_file!r}"
        )
        assert child.database_password == "resolved-pw"

    def test_host_does_not_leak_back_from_dotenv(self, monkeypatch, tmp_path):
        """Not just DATABASE_PASSWORD_FILE -- every DATABASE_* field this
        function clears when unset shares the identical pop()-does-not-shadow-
        dotenv structure. A stray DATABASE_HOST left in backend/.env from a
        prior configuration would otherwise resurface in the subprocess even
        though this process's own settings have no host at all (e.g. SQLite)."""
        import subprocess

        from app import main

        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_HOST=stale-dotenv-host.invalid\n")

        monkeypatch.setattr(main.settings, "database_host", None)
        monkeypatch.setattr(main, "resolved_password", lambda: None)

        captured = {}

        def fake_run(*args, **kwargs):
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        main._alembic_upgrade(backend_dir=".")

        child = self._settings_read_back_through(monkeypatch, captured["env"], env_file)
        assert not child.database_host, (
            "the subprocess's own Settings() fell back to backend/.env's "
            f"stale DATABASE_HOST despite the parent's settings having none: {child.database_host!r}"
        )


class TestOptionalDatabaseFieldsNormalizeBlankToNone:
    """app.main._alembic_upgrade shadows every optional DATABASE_* field with
    an explicit empty string rather than omitting the key (see
    TestAlembicSubprocessEnvDoesNotFallBackToDotenv) -- but pydantic-settings
    does not coerce an empty-string value to None on its own for a
    ``str | None`` field, confirmed live. Left unnormalized, the subprocess's
    own Settings() would resolve e.g. database_schema to the literal string
    "" rather than None, and migrations/env.py passes it straight through as
    Alembic's version_table_schema with no truthy guard -- SQLAlchemy/Alembic
    treat schema="" as a real (if odd) schema name distinct from schema=None,
    which broke a previously-passing concurrent-migration integration test by
    corrupting the version-table existence check."""

    @pytest.mark.parametrize(
        "field",
        [
            "database_name",
            "database_host",
            "database_user",
            "database_password",
            "database_password_file",
            "database_schema",
            "database_sslrootcert",
            "database_sslcert",
            "database_sslkey",
        ],
    )
    def test_blank_value_resolves_to_none(self, field):
        cfg = _settings(**{field: ""})
        assert getattr(cfg, field) is None, (
            f"{field}='' resolved to {getattr(cfg, field)!r}, not None -- "
            "downstream code that passes this field straight through with no "
            "truthy guard (e.g. migrations/env.py's version_table_schema) "
            "will see a real, if odd, empty-string value instead of 'unset'"
        )


class TestMigrationLockTimeoutParsing:
    """MIGRATION_LOCK_TIMEOUT gates the deadline check in _run_migrations:
    `time.monotonic() >= deadline`. Plain float coercion happily accepts
    "nan" and "inf" — both defeat that comparison forever (nan compares
    False against everything; monotonic time never reaches +inf), silently
    recreating the indefinite hang this timeout exists to prevent.

    A Settings field (not a bare os.getenv() in app.main) so a value placed
    in backend/.env — the documented direct-run configuration file — is
    actually honored: pydantic-settings' dotenv source never touches
    os.environ, so os.getenv() alone cannot see it."""

    def test_rejects_nan(self):
        with pytest.raises(ValueError, match="MIGRATION_LOCK_TIMEOUT"):
            _settings(migration_lock_timeout="nan")

    def test_rejects_positive_infinity(self):
        with pytest.raises(ValueError, match="MIGRATION_LOCK_TIMEOUT"):
            _settings(migration_lock_timeout="inf")

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="MIGRATION_LOCK_TIMEOUT"):
            _settings(migration_lock_timeout="-1")

    def test_rejects_malformed_value_with_a_clear_message(self):
        with pytest.raises(ValueError, match="MIGRATION_LOCK_TIMEOUT"):
            _settings(migration_lock_timeout="notanumber")

    def test_accepts_a_finite_non_negative_value(self):
        assert _settings(migration_lock_timeout="300").migration_lock_timeout == 300.0
        assert _settings(migration_lock_timeout="0").migration_lock_timeout == 0.0

    def test_default_is_300(self):
        assert _settings().migration_lock_timeout == 300.0

    def test_value_from_env_file_is_honored(self, tmp_path, monkeypatch):
        """The bug this field replaces: app.main previously read
        MIGRATION_LOCK_TIMEOUT via a bare os.getenv(), which only ever sees
        the real process environment. A value placed solely in backend/.env
        — the documented direct-run configuration file — never reached it,
        and the timeout silently stayed at its 300s default. Settings loads
        this env file itself, so the field must pick up a .env-only value
        with nothing set in the real environment."""
        monkeypatch.delenv("MIGRATION_LOCK_TIMEOUT", raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text("MIGRATION_LOCK_TIMEOUT=42\n", encoding="utf-8")
        cfg = Settings(debug=True, _env_file=str(env_file))
        assert cfg.migration_lock_timeout == 42.0


class TestPsycopg2VersionFloor:
    """db_config.py passes sslrootcert="system" for verify-ca/verify-full by
    default — a libpq 16+ feature. psycopg2-binary bundles its own libpq
    rather than using the OS one, and the version bundled has changed
    release to release: 2.9.0 bundled libpq 13.3, and libpq wasn't bumped to
    16 until 2.9.8 (confirmed against the psycopg2 NEWS file) — so the
    previously-declared floor of psycopg2-binary>=2.9.0 permitted installing
    a wheel where sslrootcert="system" would be rejected as an unrecognized
    connection parameter, breaking every verify-ca/verify-full connection
    with no explicit DATABASE_SSLROOTCERT.
    """

    def test_declared_floor_admits_only_versions_bundling_libpq_16_plus(self):
        """Asks the specifier what it *admits* rather than reverse-engineering
        a floor from operators — the same approach test_db_url.py used for
        asyncpg's `service`/`servicefile` floor before it was deleted in the
        db_url.py removal. Extracting `.version` from the requirement would
        have to special-case every operator that implies a lower bound and
        mishandle multi-specifier sets; `specifier.contains()` answers the
        question this test actually poses: can the declared constraint
        resolve to a psycopg2-binary whose bundled libpq predates 16?

        Not a hand-rolled tuple/split(\".\") comparison: a pre-release or
        post-release suffix (2.9.8rc1) puts a non-numeric segment where
        int() would break, and packaging also gets PEP 440 ordering right in
        ways naive string/tuple comparison does not.
        """
        import tomllib
        from pathlib import Path

        from packaging.requirements import Requirement

        # encoding is explicit: pyproject.toml is UTF-8 by PEP 621, but
        # read_text() would otherwise use locale.getpreferredencoding().
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        deps = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"][
            "dependencies"
        ]
        requirement = next(
            Requirement(d) for d in deps if Requirement(d).name == "psycopg2-binary"
        )

        # 2.9.7 is the last release to bundle a pre-16 libpq; 2.9.8 is the
        # first to bundle 16 (confirmed against the psycopg2 NEWS file).
        too_old = [
            v for v in ("2.9.0", "2.9.5", "2.9.7")
            if requirement.specifier.contains(v, prereleases=True)
        ]
        assert not too_old, (
            f"psycopg2-binary is declared as `{requirement}`, which still "
            f"admits {too_old} — sslrootcert=\"system\" needs libpq 16+, "
            "first bundled in the 2.9.8 wheel"
        )

    def test_installed_psycopg2_satisfies_the_declared_floor(self):
        """The suite runs on whatever is installed, which can silently be
        newer than the declared floor — so also assert the installed version
        actually satisfies the declaration, not just that the declaration
        itself is sound."""
        import tomllib
        from pathlib import Path

        import psycopg2
        from packaging.requirements import Requirement
        from packaging.version import Version

        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        deps = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"][
            "dependencies"
        ]
        requirement = next(
            Requirement(d) for d in deps if Requirement(d).name == "psycopg2-binary"
        )

        # __version__ is e.g. "2.9.12 (dt dec pq3 ext lo64)" — only the
        # leading dotted-number part is a PEP 440 version.
        installed = Version(psycopg2.__version__.split()[0])
        assert requirement.specifier.contains(installed, prereleases=True), (
            f"installed psycopg2-binary {installed} does not satisfy "
            f"`{requirement}`"
        )

    def test_installed_libpq_supports_sslrootcert_system(self):
        """Defense in depth, independent of the psycopg2-binary version
        entirely: confirm the libpq actually linked into this environment's
        psycopg2 supports the feature. __libpq_version__ is an integer in
        MMmmpp00 form (e.g. 170009 for 17.9), so >= 160000 means libpq 16 or
        newer — this is the real thing that matters, and version-floor
        reasoning about psycopg2-binary releases is only a proxy for it."""
        import psycopg2

        assert psycopg2.__libpq_version__ >= 160000
