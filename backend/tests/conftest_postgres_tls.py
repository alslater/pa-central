"""A PostgreSQL container configured for TLS, with generated certificates.

Certificate support exists for other people's deployments — it is never
exercised in normal development, so without integration coverage it is untested
plumbing that fails for the first person who needs it. These fixtures stand up a
throwaway TLS-terminated server with a real chain so both drivers can be checked
against it.

Skips when Docker or openssl is unavailable, matching conftest_postgres.py.
"""
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa

TLS_CONTAINER = "pa-central-test-postgres-tls"
TLS_IMAGE = "postgres:16-alpine"
TLS_PORT = 55434
TLS_PASSWORD = "test"
TLS_CERT_USER = "certuser"

# The postgres user inside the alpine image. The server refuses to start if the
# private key is group/world readable *or* not owned by the running user, so the
# key is copied in and chowned rather than bind-mounted from the host.
PG_UID = 70
PG_GID = 70

# `cert` authentication for the certificate role, password auth for everyone
# else. Both lines are hostssl, so a non-TLS connection is refused outright —
# which is what makes the TLS assertions meaningful.
HBA = f"""\
local   all all                     trust
hostssl all {TLS_CERT_USER} 0.0.0.0/0    cert
hostssl all {TLS_CERT_USER} ::0/0        cert
hostssl all all             0.0.0.0/0    scram-sha-256
hostssl all all             ::0/0        scram-sha-256
"""


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=True)


def _make_certificates(directory: Path) -> dict[str, Path]:
    """A CA, a server certificate for 'localhost', and a client certificate.

    The server CN must be 'localhost' for verify-full to pass, and the client CN
    must match the database role name for certificate authentication.
    """
    paths = {
        name: directory / f"{name}.pem"
        for name in ("ca", "ca-key", "server", "server-key", "client", "client-key")
    }
    _run(
        "openssl", "req", "-new", "-x509", "-nodes", "-days", "1",
        "-subj", "/CN=pa-central-test-ca",
        "-keyout", str(paths["ca-key"]), "-out", str(paths["ca"]),
    )
    for role, cn in (("server", "localhost"), ("client", TLS_CERT_USER)):
        csr = directory / f"{role}.csr"
        _run(
            "openssl", "req", "-new", "-nodes", "-subj", f"/CN={cn}",
            "-keyout", str(paths[f"{role}-key"]), "-out", str(csr),
        )
        extra: list[str] = []
        if role == "server":
            # OpenSSL 3 requires a subjectAltName: CN-only matching was removed
            # from Python's ssl hostname check, so verify-full against a
            # CN-only certificate fails regardless of what the CN says.
            ext = directory / "server.ext"
            ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
            extra = ["-extfile", str(ext)]
        _run(
            "openssl", "x509", "-req", "-days", "1", "-in", str(csr),
            "-CA", str(paths["ca"]), "-CAkey", str(paths["ca-key"]),
            "-CAcreateserial", "-out", str(paths[role]), *extra,
        )
    return paths


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _install_server_files(certs: Path, hba: Path) -> None:
    """Copy the server's TLS material into the container and fix ownership.

    A read-only bind mount would be simpler, but PostgreSQL rejects a key file
    it does not own or that is readable beyond its owner, and the host-side
    ownership of a bind mount cannot be changed from inside the container.
    """
    _run("docker", "exec", "-u", "0", TLS_CONTAINER, "mkdir", "-p", "/certs")
    for src, dest in (
        (certs / "server.pem", "/certs/server.pem"),
        (certs / "server-key.pem", "/certs/server-key.pem"),
        (certs / "ca.pem", "/certs/ca.pem"),
        (hba, "/certs/pg_hba.conf"),
    ):
        _run("docker", "cp", str(src), f"{TLS_CONTAINER}:{dest}")
    _run("docker", "exec", "-u", "0", TLS_CONTAINER,
         "chown", "-R", f"{PG_UID}:{PG_GID}", "/certs")
    _run("docker", "exec", "-u", "0", TLS_CONTAINER,
         "chmod", "0600", "/certs/server-key.pem", "/certs/pg_hba.conf")


def _server_ready(url: str) -> bool:
    engine = sa.create_engine(
        url, connect_args={"sslmode": "require", "connect_timeout": 2}
    )
    try:
        with engine.connect() as conn:
            conn.execute(sa.text("SELECT 1"))
        return True
    except Exception:  # noqa: BLE001 — any connection failure means "not ready"
        return False
    finally:
        engine.dispose()


@pytest.fixture(scope="session")
def postgres_tls(tmp_path_factory) -> Iterator[tuple[str, str, str, str]]:
    """(sync url, ca path, client cert path, client key path), or skip."""
    if not _docker_available():
        pytest.skip("Docker not available — skipping TLS integration tests")
    if not _openssl_available():
        pytest.skip("openssl binary not available — skipping TLS integration tests")

    certs = tmp_path_factory.mktemp("pgtls")
    paths = _make_certificates(certs)
    hba = certs / "pg_hba.conf"
    hba.write_text(HBA)

    subprocess.run(
        ["docker", "rm", "-f", TLS_CONTAINER], capture_output=True, check=False
    )

    url = (
        f"postgresql+psycopg2://postgres:{TLS_PASSWORD}"
        f"@localhost:{TLS_PORT}/postgres"
    )
    try:
        # Started plain, then restarted with TLS: the certificates have to be
        # inside the container with postgres-owned permissions before the server
        # reads them, and `docker cp` needs a container to copy into.
        #
        # No `-c` arguments here — command-line settings outrank postgresql.conf
        # permanently, so an `-c ssl=off` at start would silently defeat the
        # `ssl = on` appended to the config file before the restart.
        _run(
            "docker", "run", "-d", "--name", TLS_CONTAINER,
            "-e", f"POSTGRES_PASSWORD={TLS_PASSWORD}",
            "-p", f"{TLS_PORT}:5432",
            TLS_IMAGE,
        )
        for _ in range(60):
            probe = subprocess.run(
                ["docker", "exec", TLS_CONTAINER, "pg_isready", "-U", "postgres"],
                capture_output=True, check=False,
            )
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            pytest.fail("TLS PostgreSQL container did not initialise")

        # A role authenticated by client certificate (CN=certuser), created
        # before the hostssl-only pg_hba.conf takes effect.
        _run(
            "docker", "exec", "-u", str(PG_UID), TLS_CONTAINER,
            "psql", "-U", "postgres", "-c",
            f"DROP ROLE IF EXISTS {TLS_CERT_USER}; "
            f"CREATE ROLE {TLS_CERT_USER} LOGIN",
        )

        _install_server_files(certs, hba)
        _run(
            "docker", "exec", "-u", "0", TLS_CONTAINER, "sh", "-c",
            "printf '%s\\n' "
            "\"ssl = on\" "
            "\"ssl_cert_file = '/certs/server.pem'\" "
            "\"ssl_key_file = '/certs/server-key.pem'\" "
            "\"ssl_ca_file = '/certs/ca.pem'\" "
            "\"hba_file = '/certs/pg_hba.conf'\" "
            ">> /var/lib/postgresql/data/postgresql.conf",
        )
        _run("docker", "restart", TLS_CONTAINER)

        for _ in range(60):
            if _server_ready(url):
                break
            time.sleep(1)
        else:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "40", TLS_CONTAINER],
                capture_output=True, text=True, check=False,
            )
            pytest.fail(
                "TLS PostgreSQL container did not become ready.\n"
                f"{logs.stdout}\n{logs.stderr}"
            )

        yield (
            url,
            str(paths["ca"]),
            str(paths["client"]),
            str(paths["client-key"]),
        )
    finally:
        # check=False: teardown is best-effort and must not mask a test result.
        subprocess.run(
            ["docker", "rm", "-f", TLS_CONTAINER], capture_output=True, check=False
        )
