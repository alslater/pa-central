"""Authorization tests for /api/repo-credentials endpoints."""
import pytest

from app.core.config import settings as app_settings
from tests.conftest import auth

CRED_PAYLOAD = {
    "name": "my-cred",
    "credential_type": "https_token",
    "credential_value": "ghp_test123",
}


@pytest.fixture(autouse=True)
def use_localstack(localstack, monkeypatch):
    # Point the Secrets Manager client at LocalStack instead of real AWS.
    monkeypatch.setattr(app_settings, "aws_endpoint_url", localstack)
    monkeypatch.setattr(app_settings, "aws_region", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    yield
    # Clean up all test secrets so re-runs don't hit ResourceExistsException.
    # The in-memory DB resets between tests (IDs restart at 1) but LocalStack
    # state persists across the session.
    import boto3
    sm = boto3.client(
        "secretsmanager",
        endpoint_url=localstack,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    paginator = sm.get_paginator("list_secrets")
    for page in paginator.paginate(Filters=[{"Key": "name", "Values": ["pa-central/repo-creds/"]}]):
        for secret in page.get("SecretList", []):
            sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)


@pytest.mark.asyncio
class TestListRepoCredentials:
    async def test_requires_auth(self, client):
        r = await client.get("/api/repo-credentials")
        assert r.status_code == 401

    async def test_viewer_cannot_list(self, client, viewer_token):
        r = await client.get("/api/repo-credentials", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_operator_can_list(self, client, operator_token):
        r = await client.get("/api/repo-credentials", headers=auth(operator_token))
        assert r.status_code == 200


@pytest.mark.asyncio
class TestCreateRepoCredential:
    async def test_requires_auth(self, client):
        r = await client.post("/api/repo-credentials", json=CRED_PAYLOAD)
        assert r.status_code == 401

    async def test_viewer_cannot_create(self, client, viewer_token):
        r = await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_operator_can_create(self, client, operator_token):
        r = await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))
        assert r.status_code == 201


@pytest.mark.asyncio
class TestUpdateRepoCredential:
    async def test_requires_auth(self, client, operator_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.patch(f"/api/repo-credentials/{created['id']}", json={"name": "renamed"})
        assert r.status_code == 401

    async def test_viewer_cannot_update(self, client, operator_token, viewer_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.patch(f"/api/repo-credentials/{created['id']}", json={"name": "renamed"}, headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_operator_can_update(self, client, operator_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.patch(f"/api/repo-credentials/{created['id']}", json={"name": "renamed"}, headers=auth(operator_token))
        assert r.status_code == 200


@pytest.mark.asyncio
class TestDeleteRepoCredential:
    async def test_requires_auth(self, client, operator_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.delete(f"/api/repo-credentials/{created['id']}")
        assert r.status_code == 401

    async def test_viewer_cannot_delete(self, client, operator_token, viewer_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.delete(f"/api/repo-credentials/{created['id']}", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_operator_cannot_delete(self, client, operator_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.delete(f"/api/repo-credentials/{created['id']}", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_admin_can_delete(self, client, admin_token, operator_token):
        created = (await client.post("/api/repo-credentials", json=CRED_PAYLOAD, headers=auth(operator_token))).json()
        r = await client.delete(f"/api/repo-credentials/{created['id']}", headers=auth(admin_token))
        assert r.status_code == 204
