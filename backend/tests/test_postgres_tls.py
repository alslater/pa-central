"""TLS connections on both drivers, against a real certificate chain.

asyncpg takes TLS material as an SSLContext rather than libpq's file paths.
That difference is why client certificates could not previously reach the async
driver at all, so it needs testing against a live server rather than by
asserting on the shape of a dict.
"""
import subprocess

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.config import Settings
from app.core.db_config import (
    async_connect_args,
    async_url,
    sync_connect_args,
    sync_url,
)
from tests import conftest_postgres_tls

# A loopback address that reaches the same published container port but is not
# named by the server certificate (which covers DNS:localhost and IP:127.0.0.1).
# verify-full must reject it and verify-ca must accept it.
MISMATCHED_HOST = "127.0.0.2"

SSL_ACTIVE = "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
CLIENT_DN = "SELECT client_dn FROM pg_stat_ssl WHERE pid = pg_backend_pid()"


def _tls_settings(url: str, **overrides) -> Settings:
    """Settings pointed at the fixture's server, with *overrides* winning.

    The connection details come from the fixture URL, but the certificate tests
    need to replace the credentials — so overrides are merged over the defaults
    rather than passed alongside them, which would be a duplicate keyword.
    """
    parsed = sa.engine.make_url(url)
    values = {
        "database_type": "postgresql",
        "database_host": parsed.host,
        "database_port": parsed.port,
        "database_name": parsed.database,
        "database_user": parsed.username,
        "database_password": parsed.password,
    }
    values.update(overrides)
    return Settings(_env_file=None, debug=True, **values)


def _unrelated_ca(directory) -> str:
    """A self-signed CA that signed nothing on the fixture's server."""
    ca = directory / "other-ca.pem"
    subprocess.run(
        [
            "openssl", "req", "-new", "-x509", "-nodes", "-days", "1",
            "-subj", "/CN=unrelated-ca",
            "-keyout", str(directory / "other-ca-key.pem"),
            "-out", str(ca),
        ],
        capture_output=True, check=True,
    )
    return str(ca)


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_sync_driver_connects_over_tls(postgres_tls, mode):
    url, ca, _cert, _key = postgres_tls
    cfg = _tls_settings(url, database_sslmode=mode, database_sslrootcert=ca)
    engine = sa.create_engine(sync_url(cfg), connect_args=sync_connect_args(cfg))
    try:
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT 1")).scalar() == 1
            assert conn.execute(sa.text(SSL_ACTIVE)).scalar()
    finally:
        engine.dispose()


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
async def test_async_driver_connects_over_tls(postgres_tls, mode):
    url, ca, _cert, _key = postgres_tls
    cfg = _tls_settings(url, database_sslmode=mode, database_sslrootcert=ca)
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        async with engine.connect() as conn:
            assert (await conn.execute(sa.text("SELECT 1"))).scalar() == 1
            assert (await conn.execute(sa.text(SSL_ACTIVE))).scalar()
    finally:
        await engine.dispose()


def test_sync_driver_sends_a_client_certificate(postgres_tls):
    """psycopg2 authenticates as the certificate role via libpq file paths."""
    url, ca, cert, key = postgres_tls
    cfg = _tls_settings(
        url,
        database_user="certuser",
        database_password=None,
        database_sslmode="verify-ca",
        database_sslrootcert=ca,
        database_sslcert=cert,
        database_sslkey=key,
    )
    engine = sa.create_engine(sync_url(cfg), connect_args=sync_connect_args(cfg))
    try:
        with engine.connect() as conn:
            assert conn.execute(sa.text("SELECT current_user")).scalar() == "certuser"
            assert conn.execute(sa.text(CLIENT_DN)).scalar() is not None
    finally:
        engine.dispose()


async def test_async_driver_sends_a_client_certificate(postgres_tls):
    """The case a URL could never express: asyncpg needs load_cert_chain.

    The server's pg_hba.conf authenticates `certuser` by certificate alone, so
    connecting with no password at all only succeeds if the client certificate
    actually reached the server.
    """
    url, ca, cert, key = postgres_tls
    cfg = _tls_settings(
        url,
        database_user="certuser",
        database_password=None,
        database_sslmode="verify-ca",
        database_sslrootcert=ca,
        database_sslcert=cert,
        database_sslkey=key,
    )
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        async with engine.connect() as conn:
            assert (
                await conn.execute(sa.text("SELECT current_user"))
            ).scalar() == "certuser"
            assert (await conn.execute(sa.text(CLIENT_DN))).scalar() is not None
    finally:
        await engine.dispose()


async def test_make_async_engine_carries_certificates_from_a_query_url(postgres_tls):
    """The documented PA_TEST_POSTGRES_URL shape — certificate paths as URL
    query options — must reach asyncpg through the fixture helper.

    The postgres_url fixture propagates an external URL's query options
    verbatim, but as_async_url() rejects sslrootcert/sslcert/sslkey outright
    (asyncpg has no keyword argument for them), so integration tests that
    built engines straight from the URL failed against a cert-authenticated
    external server before attempting a single connection. make_async_engine()
    is the fix: it moves the TLS options into an SSLContext via the production
    connect-args path. Authenticating as the certificate-only role proves the
    material genuinely reached the server, not merely that a URL parsed.
    """
    from tests.conftest_postgres import make_async_engine

    url, ca, cert, key = postgres_tls
    base = sa.engine.make_url(url)
    external = sa.engine.URL.create(
        "postgresql+psycopg2",
        username=conftest_postgres_tls.TLS_CERT_USER,
        host=base.host,
        port=base.port,
        database=base.database,
        query={
            "sslmode": "verify-full",
            "sslrootcert": ca,
            "sslcert": cert,
            "sslkey": key,
        },
    ).render_as_string(hide_password=False)

    engine = make_async_engine(external)
    try:
        async with engine.connect() as conn:
            assert (
                await conn.execute(sa.text("SELECT current_user"))
            ).scalar() == conftest_postgres_tls.TLS_CERT_USER
            assert (await conn.execute(sa.text(CLIENT_DN))).scalar() is not None
    finally:
        await engine.dispose()


async def test_async_driver_without_a_client_certificate_is_rejected(postgres_tls):
    """Counterpart to the test above: it must be the certificate doing the work.

    Without one, the same role over the same TLS connection has no credential
    the server will accept — so the passing case above cannot be an artefact of
    permissive authentication.
    """
    url, ca, _cert, _key = postgres_tls
    cfg = _tls_settings(
        url,
        database_user="certuser",
        database_password=None,
        database_sslmode="verify-ca",
        database_sslrootcert=ca,
    )
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        with pytest.raises(Exception, match="(?i)certificate|authentication|password"):
            async with engine.connect() as conn:
                await conn.execute(sa.text("SELECT 1"))
    finally:
        await engine.dispose()


async def test_verify_full_rejects_a_hostname_mismatch(postgres_tls):
    """verify-full must actually verify.

    The server certificate names 'localhost' only, so reaching the very same
    server through a name it does not cover has to fail.
    """
    url, ca, _cert, _key = postgres_tls
    cfg = _tls_settings(url, database_sslmode="verify-full", database_sslrootcert=ca)
    cfg = cfg.model_copy(update={"database_host": MISMATCHED_HOST})
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        with pytest.raises(Exception, match="(?i)certificate|hostname|match"):
            async with engine.connect() as conn:
                await conn.execute(sa.text("SELECT 1"))
    finally:
        await engine.dispose()


async def test_verify_ca_accepts_a_hostname_mismatch(postgres_tls):
    """verify-ca checks the chain but not the name — the libpq distinction.

    Reaching the server by an address the certificate does not name must still
    succeed, or verify-ca has been silently upgraded to verify-full. The address
    is the same one the verify-full test is rejected by, which is what makes the
    pair meaningful: only the mode differs.
    """
    url, ca, _cert, _key = postgres_tls
    cfg = _tls_settings(url, database_sslmode="verify-ca", database_sslrootcert=ca)
    cfg = cfg.model_copy(update={"database_host": MISMATCHED_HOST})
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        async with engine.connect() as conn:
            assert (await conn.execute(sa.text(SSL_ACTIVE))).scalar()
    finally:
        await engine.dispose()


async def test_verify_ca_rejects_an_untrusted_chain(postgres_tls, tmp_path):
    """A CA that did not sign the server certificate must fail verification.

    Without this, `verify-ca` passing proves only that a TLS handshake happened,
    not that the CA file was consulted at all.
    """
    url, _ca, _cert, _key = postgres_tls
    cfg = _tls_settings(
        url,
        database_sslmode="verify-ca",
        database_sslrootcert=_unrelated_ca(tmp_path),
    )
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        with pytest.raises(Exception, match="(?i)certificate|verify|unknown"):
            async with engine.connect() as conn:
                await conn.execute(sa.text("SELECT 1"))
    finally:
        await engine.dispose()


async def test_require_with_a_rootcert_rejects_an_untrusted_chain(
    postgres_tls, tmp_path
):
    """`require` with sslrootcert set must validate exactly like verify-ca —
    matching libpq, which silently upgrades `require`'s validation the moment
    a root cert is configured (confirmed live against a real server: an
    unrelated CA connects fine under plain `require`, but is rejected once
    sslrootcert points anywhere). Without this, the async driver's `require`
    ignored sslrootcert entirely and always used CERT_NONE — the identical
    DATABASE_SSLROOTCERT setting validated the certificate on the sync driver
    (Alembic) while providing no protection at all on the async driver (the
    running application)."""
    url, _ca, _cert, _key = postgres_tls
    cfg = _tls_settings(
        url,
        database_sslmode="require",
        database_sslrootcert=_unrelated_ca(tmp_path),
    )
    engine = create_async_engine(async_url(cfg), connect_args=async_connect_args(cfg))
    try:
        with pytest.raises(Exception, match="(?i)certificate|verify|unknown"):
            async with engine.connect() as conn:
                await conn.execute(sa.text("SELECT 1"))
    finally:
        await engine.dispose()


def test_sync_driver_falls_back_to_system_roots_without_a_rootcert(postgres_tls):
    """verify-full with no DATABASE_SSLROOTCERT must validate against the
    system trust store on the sync driver too, not fail on libpq's own
    ~/.postgresql/root.crt default (confirmed live: that failure names the
    exact dotfile path and suggests sslrootcert=system as the fix). The
    fixture's self-signed CA is not in the system trust store, so this must
    still fail — proving the system-roots fallback actually engaged, rather
    than silently succeeding for an unrelated reason (e.g. sslmode being
    ignored) or raising the old missing-file error instead."""
    url, _ca, _cert, _key = postgres_tls
    cfg = _tls_settings(url, database_sslmode="verify-full")
    engine = sa.create_engine(sync_url(cfg), connect_args=sync_connect_args(cfg))
    try:
        with (
            pytest.raises(Exception, match="(?i)certificate|verify|ssl") as exc,
            engine.connect() as conn,
        ):
            conn.execute(sa.text("SELECT 1"))
        assert "root.crt" not in str(exc.value)
    finally:
        engine.dispose()


class TestPostgresTlsFixtureSkipsWithoutOpenssl:
    """The postgres_tls fixture must skip, not error, when a prerequisite it
    needs beyond Docker is missing.

    Only _docker_available() was ever checked before _make_certificates()
    shells out to the host `openssl` binary — a Docker-capable machine
    without OpenSSL got an uncaught FileNotFoundError from deep inside
    certificate generation instead of the documented automatic skip.
    """

    def test_openssl_unavailable_is_detected(self, monkeypatch):
        monkeypatch.setattr(
            conftest_postgres_tls.shutil, "which", lambda _name: None
        )
        assert conftest_postgres_tls._openssl_available() is False

    def test_openssl_available_is_detected(self, monkeypatch):
        monkeypatch.setattr(
            conftest_postgres_tls.shutil, "which", lambda _name: "/usr/bin/openssl"
        )
        assert conftest_postgres_tls._openssl_available() is True

    def test_fixture_skips_rather_than_erroring_without_openssl(
        self, monkeypatch, tmp_path_factory
    ):
        monkeypatch.setattr(conftest_postgres_tls, "_docker_available", lambda: True)
        monkeypatch.setattr(
            conftest_postgres_tls, "_openssl_available", lambda: False
        )

        with pytest.raises(pytest.skip.Exception, match="openssl"):
            next(conftest_postgres_tls.postgres_tls.__wrapped__(tmp_path_factory))
