"""package_index credentials: URL rules, type-dependent fields, and the in-use 409."""
import pytest

from app.models import RepoScan, repo_scan_package_indexes
from tests.conftest import auth

BASE = {"name": "internal-pypi", "credential_type": "package_index",
        "credential_value": "s3cret-token", "index_url": "https://pypi.internal.example/simple"}


@pytest.fixture(autouse=True)
def use_localstack(credentials_in_localstack):
    """Credentials are stored through Secrets Manager, against LocalStack (CLAUDE.md)."""


async def _create(client, token, **over):
    return await client.post("/api/repo-credentials", json={**BASE, **over}, headers=auth(token))


@pytest.mark.asyncio
class TestCreate:
    async def test_created_with_url_and_username(self, client, operator_token):
        r = await _create(client, operator_token, index_username="reader")
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["credential_type"] == "package_index"
        assert body["index_url"] == "https://pypi.internal.example/simple"
        assert body["index_username"] == "reader"
        assert "credential_value" not in body

    @pytest.mark.parametrize("url", [None, "", "http://pypi.internal.example", "ftp://x.example",
                                     "https://user:pw@pypi.internal.example", "https://tok@pypi.internal.example",
                                     "https://", "pypi.internal.example", "https://x.example/" + "a" * 500,
                                     "https://pypi.internal.example/simple?token=s3cret",
                                     "https://pypi.internal.example/simple#s3cret",
                                     "https://pypi.internal.example/simple?"])
    async def test_bad_url_is_rejected(self, client, operator_token, url):
        r = await _create(client, operator_token, index_url=url)
        assert r.status_code == 400, r.text

    async def test_secret_is_required(self, client, operator_token):
        r = await _create(client, operator_token, credential_value=None)
        assert r.status_code == 400

    @pytest.mark.parametrize("ctype, value", [("https_token", "ghp_x"), ("none", None)])
    async def test_index_fields_are_rejected_on_git_types(self, client, operator_token, ctype, value):
        r = await _create(client, operator_token, credential_type=ctype, credential_value=value)
        assert r.status_code == 400

    async def test_passphrase_is_rejected(self, client, operator_token):
        r = await _create(client, operator_token, ssh_key_passphrase="pp")
        assert r.status_code == 400


@pytest.mark.asyncio
class TestUpdate:
    async def test_url_can_change(self, client, operator_token):
        cid = (await _create(client, operator_token)).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}", json={"index_url": "https://other.example/simple"},
                               headers=auth(operator_token))
        assert r.status_code == 200, r.text
        assert r.json()["index_url"] == "https://other.example/simple"

    async def test_bad_url_update_is_rejected(self, client, operator_token):
        cid = (await _create(client, operator_token)).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}", json={"index_url": "http://plain.example"},
                               headers=auth(operator_token))
        assert r.status_code == 400

    async def test_switching_to_package_index_needs_a_url(self, client, operator_token):
        r = await client.post("/api/repo-credentials", json={"name": "g", "credential_type": "https_token",
                                                              "credential_value": "ghp"}, headers=auth(operator_token))
        cid = r.json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}",
                               json={"credential_type": "package_index", "credential_value": "tok"},
                               headers=auth(operator_token))
        assert r.status_code == 400

    async def test_switching_away_clears_index_fields(self, client, operator_token):
        cid = (await _create(client, operator_token, index_username="u")).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}",
                               json={"credential_type": "https_token", "credential_value": "ghp"},
                               headers=auth(operator_token))
        assert r.status_code == 200, r.text
        assert r.json()["index_url"] is None and r.json()["index_username"] is None

    async def test_query_or_fragment_update_is_rejected(self, client, operator_token):
        cid = (await _create(client, operator_token)).json()["id"]
        for url in ("https://other.example/simple?token=s3cret", "https://other.example/simple#s3cret"):
            r = await client.patch(f"/api/repo-credentials/{cid}", json={"index_url": url},
                                   headers=auth(operator_token))
            assert r.status_code == 400, url


async def _scan(db, admin_user, **over):
    scan = RepoScan(name="s", url="https://example.invalid/s", branch="main",
                    min_notify_severity="medium", created_by_id=admin_user.id, **over)
    db.add(scan)
    await db.commit()
    return scan


@pytest.mark.asyncio
class TestTypeChangeWhileInUse:
    """Changing credential_type of an in-use credential would break the scans using it."""

    async def _git(self, client, token):
        r = await client.post("/api/repo-credentials", json={"name": "g", "credential_type": "https_token",
                                                              "credential_value": "ghp"}, headers=auth(token))
        return r.json()["id"]

    async def test_git_credential_of_a_scan_cannot_become_package_index(self, client, operator_token, db, admin_user):
        cid = await self._git(client, operator_token)
        await _scan(db, admin_user, credential_id=cid)
        r = await client.patch(f"/api/repo-credentials/{cid}",
                               json={"credential_type": "package_index", "credential_value": "tok",
                                     "index_url": "https://pypi.internal.example/simple"},
                               headers=auth(operator_token))
        assert r.status_code == 409, r.text
        r = await client.get("/api/repo-credentials", headers=auth(operator_token))
        assert next(c for c in r.json() if c["id"] == cid)["credential_type"] == "https_token"

    async def test_linked_package_index_cannot_become_git(self, client, operator_token, db, admin_user):
        cid = (await _create(client, operator_token)).json()["id"]
        scan = await _scan(db, admin_user)
        await db.execute(repo_scan_package_indexes.insert().values(repo_scan_id=scan.id, credential_id=cid))
        await db.commit()
        r = await client.patch(f"/api/repo-credentials/{cid}",
                               json={"credential_type": "https_token", "credential_value": "ghp"},
                               headers=auth(operator_token))
        assert r.status_code == 409, r.text
        r = await client.get("/api/repo-credentials", headers=auth(operator_token))
        row = next(c for c in r.json() if c["id"] == cid)
        assert row["credential_type"] == "package_index"
        assert row["index_url"] == "https://pypi.internal.example/simple"

    async def test_other_fields_of_an_in_use_credential_can_change(self, client, operator_token, db, admin_user):
        cid = (await _create(client, operator_token)).json()["id"]
        scan = await _scan(db, admin_user)
        await db.execute(repo_scan_package_indexes.insert().values(repo_scan_id=scan.id, credential_id=cid))
        await db.commit()
        r = await client.patch(f"/api/repo-credentials/{cid}",
                               json={"name": "renamed", "index_url": "https://other.example/simple",
                                     "credential_type": "package_index", "credential_value": "new"},
                               headers=auth(operator_token))
        assert r.status_code == 200, r.text

    async def test_git_type_change_allowed_when_not_in_use(self, client, operator_token):
        cid = await self._git(client, operator_token)
        r = await client.patch(f"/api/repo-credentials/{cid}",
                               json={"credential_type": "package_index", "credential_value": "tok",
                                     "index_url": "https://pypi.internal.example/simple"},
                               headers=auth(operator_token))
        assert r.status_code == 200, r.text


@pytest.mark.asyncio
class TestDelete:
    async def test_linked_credential_is_409(self, client, operator_token, admin_token, db, admin_user):
        cid = (await _create(client, operator_token)).json()["id"]
        scan = await _scan(db, admin_user)
        await db.execute(repo_scan_package_indexes.insert().values(repo_scan_id=scan.id, credential_id=cid))
        await db.commit()
        r = await client.delete(f"/api/repo-credentials/{cid}", headers=auth(admin_token))
        assert r.status_code == 409

    async def test_unlinked_credential_deletes(self, client, operator_token, admin_token):
        cid = (await _create(client, operator_token)).json()["id"]
        r = await client.delete(f"/api/repo-credentials/{cid}", headers=auth(admin_token))
        assert r.status_code == 204

    async def test_git_credential_of_a_scan_is_409(self, client, operator_token, admin_token, db, admin_user):
        r = await client.post("/api/repo-credentials", json={"name": "g", "credential_type": "https_token",
                                                              "credential_value": "ghp"}, headers=auth(operator_token))
        cid = r.json()["id"]
        await _scan(db, admin_user, credential_id=cid)
        r = await client.delete(f"/api/repo-credentials/{cid}", headers=auth(admin_token))
        assert r.status_code == 409


@pytest.mark.asyncio
class TestReviewFollowUps:
    async def test_an_explicit_null_username_clears_it(self, client, operator_token):
        # Switching from username/password to a token: the stale username would keep uv on --username.
        cid = (await _create(client, operator_token, index_username="reader")).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}", json={"index_username": None},
                               headers=auth(operator_token))
        assert r.status_code == 200, r.text
        assert r.json()["index_username"] is None

    async def test_an_omitted_username_is_kept(self, client, operator_token):
        cid = (await _create(client, operator_token, index_username="reader")).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}", json={"name": "renamed"}, headers=auth(operator_token))
        assert r.status_code == 200, r.text
        assert r.json()["index_username"] == "reader"

    async def test_an_explicit_null_url_is_refused_not_kept(self, client, operator_token):
        cid = (await _create(client, operator_token)).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}", json={"index_url": None}, headers=auth(operator_token))
        assert r.status_code == 400
        assert "index_url is required" in r.json()["detail"]

    @pytest.mark.parametrize("url", ["https://[::1/simple", "https://[not-an-ip]/simple"])
    async def test_a_malformed_url_is_a_400_not_a_500(self, client, operator_token, url):
        r = await _create(client, operator_token, index_url=url)
        assert r.status_code == 400, r.text
        assert "not a valid URL" in r.json()["detail"]
        cid = (await _create(client, operator_token, name="ok")).json()["id"]
        r = await client.patch(f"/api/repo-credentials/{cid}", json={"index_url": url}, headers=auth(operator_token))
        assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_the_secret_is_deleted_only_after_the_credential_row(client, admin_token, db, monkeypatch):
    # A delete that failed to commit used to have destroyed the secret first.
    import sqlalchemy as sa

    from app.api import repo_credentials
    from app.models import RepoCredential

    cid = (await _create(client, admin_token)).json()["id"]
    await db.execute(sa.update(RepoCredential).where(RepoCredential.id == cid)
                     .values(credential_secret_arn="arn:aws:secretsmanager:eu-west-1:1:secret:pa-x"))
    await db.commit()
    seen = []

    class FakeSecrets:  # never real AWS
        async def delete_secret(self, arn):
            row = (await db.execute(sa.select(RepoCredential.id).where(RepoCredential.id == cid))).first()
            seen.append((arn, row))

    monkeypatch.setattr(repo_credentials, "_sm", lambda: FakeSecrets())
    r = await client.delete(f"/api/repo-credentials/{cid}", headers=auth(admin_token))
    assert r.status_code == 204, r.text
    assert seen == [("arn:aws:secretsmanager:eu-west-1:1:secret:pa-x", None)]


@pytest.mark.asyncio
async def test_the_token_is_stored_in_secrets_manager(client, operator_token, db, credentials_in_localstack):
    # The production path, not the debug-only local:// storage.
    import sqlalchemy as sa

    from app.models import RepoCredential

    cid = (await _create(client, operator_token)).json()["id"]
    arn = (await db.execute(sa.select(RepoCredential.credential_secret_arn)
                            .where(RepoCredential.id == cid))).scalar_one()
    assert arn.startswith("arn:aws:secretsmanager:")
    stored = credentials_in_localstack.get_secret_value(SecretId=arn)["SecretString"]
    assert "s3cret-token" in stored


@pytest.mark.asyncio
async def test_a_reused_id_does_not_collide_with_a_secret_not_yet_deleted(client, admin_token, db, monkeypatch):
    # SQLite reuses the highest id after a delete, and the secret is removed only after the row: a
    # credential created in between must not ask Secrets Manager for a name that still exists.
    import sqlalchemy as sa

    from app.api import repo_credentials
    from app.models import RepoCredential

    first = (await _create(client, admin_token, name="first")).json()["id"]
    old_arn = (await db.execute(sa.select(RepoCredential.credential_secret_arn)
                                .where(RepoCredential.id == first))).scalar_one()
    real_sm = repo_credentials._sm

    class SlowCleanup:  # the old secret is still there when the next credential is created
        def __getattr__(self, name):
            return getattr(real_sm(), name)

        async def delete_secret(self, arn):
            pass

    monkeypatch.setattr(repo_credentials, "_sm", lambda: SlowCleanup())
    assert (await client.delete(f"/api/repo-credentials/{first}", headers=auth(admin_token))).status_code == 204
    monkeypatch.setattr(repo_credentials, "_sm", real_sm)
    r = await _create(client, admin_token, name="second")
    assert r.status_code == 201, r.text
    assert r.json()["id"] == first  # the reuse this guards against
    new_arn = (await db.execute(sa.select(RepoCredential.credential_secret_arn)
                                .where(RepoCredential.id == first))).scalar_one()
    assert new_arn != old_arn
