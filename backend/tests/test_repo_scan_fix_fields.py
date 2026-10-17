"""Repo scan fix-plan fields: fix_plans_enabled and package-index links."""
import uuid

import pytest

from tests.conftest import auth

SCAN = {"name": "s", "url": "https://github.com/x/s", "branch": "main"}


@pytest.fixture(autouse=True)
def use_localstack(credentials_in_localstack):
    """Credentials are stored through Secrets Manager, against LocalStack (CLAUDE.md)."""


async def _cred(client, token, ctype="package_index"):
    body = {"name": f"c-{ctype}-{uuid.uuid4().hex[:8]}", "credential_type": ctype, "credential_value": "v"}
    if ctype == "package_index":
        body["index_url"] = "https://pypi.internal.example/simple"
    r = await client.post("/api/repo-credentials", json=body, headers=auth(token))
    return r.json()["id"]


@pytest.mark.asyncio
class TestRepoScanFixFields:
    async def test_defaults(self, client, operator_token):
        r = await client.post("/api/repo-scans", json=SCAN, headers=auth(operator_token))
        assert r.status_code == 201, r.text
        assert r.json()["fix_plans_enabled"] is False
        assert r.json()["package_index_credential_ids"] == []

    async def test_create_with_links_round_trips_everywhere(self, client, operator_token):
        a = await _cred(client, operator_token)
        r = await client.post("/api/repo-scans", json={**SCAN, "fix_plans_enabled": True,
                                                        "package_index_credential_ids": [a]},
                              headers=auth(operator_token))
        sid = r.json()["id"]
        assert r.json()["package_index_credential_ids"] == [a]
        got = (await client.get(f"/api/repo-scans/{sid}", headers=auth(operator_token))).json()
        listed = next(s for s in (await client.get("/api/repo-scans", headers=auth(operator_token))).json()
                      if s["id"] == sid)
        assert got["fix_plans_enabled"] is True and got["package_index_credential_ids"] == [a]
        assert listed["package_index_credential_ids"] == [a]

    async def test_update_replaces_links_and_omission_keeps_them(self, client, operator_token):
        a, b = await _cred(client, operator_token), await _cred(client, operator_token)
        sid = (await client.post("/api/repo-scans", json={**SCAN, "package_index_credential_ids": [a]},
                                 headers=auth(operator_token))).json()["id"]
        r = await client.patch(f"/api/repo-scans/{sid}", json={"name": "renamed"}, headers=auth(operator_token))
        assert r.json()["package_index_credential_ids"] == [a]
        r = await client.patch(f"/api/repo-scans/{sid}", json={"package_index_credential_ids": [b]},
                               headers=auth(operator_token))
        assert r.json()["package_index_credential_ids"] == [b]
        r = await client.patch(f"/api/repo-scans/{sid}", json={"package_index_credential_ids": []},
                               headers=auth(operator_token))
        assert r.json()["package_index_credential_ids"] == []

    async def test_git_credential_in_links_is_rejected(self, client, operator_token):
        g = await _cred(client, operator_token, "https_token")
        r = await client.post("/api/repo-scans", json={**SCAN, "package_index_credential_ids": [g]},
                              headers=auth(operator_token))
        assert r.status_code == 400

    async def test_unknown_or_repeated_link_is_rejected(self, client, operator_token):
        a = await _cred(client, operator_token)
        for ids in ([999], [a, a]):
            r = await client.post("/api/repo-scans", json={**SCAN, "package_index_credential_ids": ids},
                                  headers=auth(operator_token))
            assert r.status_code == 400, ids

    async def test_package_index_as_git_credential_is_rejected(self, client, operator_token):
        a = await _cred(client, operator_token)
        r = await client.post("/api/repo-scans", json={**SCAN, "credential_id": a}, headers=auth(operator_token))
        assert r.status_code == 400
        sid = (await client.post("/api/repo-scans", json=SCAN, headers=auth(operator_token))).json()["id"]
        r = await client.patch(f"/api/repo-scans/{sid}", json={"credential_id": a}, headers=auth(operator_token))
        assert r.status_code == 400

    async def test_deleting_the_scan_removes_its_links(self, client, operator_token, admin_token):
        a = await _cred(client, operator_token)
        sid = (await client.post("/api/repo-scans", json={**SCAN, "package_index_credential_ids": [a]},
                                 headers=auth(operator_token))).json()["id"]
        assert (await client.delete(f"/api/repo-scans/{sid}", headers=auth(admin_token))).status_code == 204
        assert (await client.delete(f"/api/repo-credentials/{a}", headers=auth(admin_token))).status_code == 204

    async def test_viewer_cannot_set_fields(self, client, viewer_token):
        r = await client.post("/api/repo-scans", json={**SCAN, "fix_plans_enabled": True},
                              headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_update_rejects_bad_links_and_keeps_existing(self, client, operator_token):
        a = await _cred(client, operator_token)
        g = await _cred(client, operator_token, "https_token")
        sid = (await client.post("/api/repo-scans", json={**SCAN, "package_index_credential_ids": [a]},
                                 headers=auth(operator_token))).json()["id"]
        for ids in ([g], [999], [a, a]):
            r = await client.patch(f"/api/repo-scans/{sid}", json={"package_index_credential_ids": ids},
                                   headers=auth(operator_token))
            assert r.status_code == 400, ids
        got = (await client.get(f"/api/repo-scans/{sid}", headers=auth(operator_token))).json()
        assert got["package_index_credential_ids"] == [a]


@pytest.mark.asyncio
class TestRepoScanPaVersion:
    async def test_create_and_update_round_trip(self, client, operator_token):
        r = await client.post("/api/repo-scans", json={**SCAN, "pa_version": " 0.10.0rc1 "}, headers=auth(operator_token))
        assert r.status_code == 201, r.text
        assert r.json()["pa_version"] == "0.10.0rc1"
        sid = r.json()["id"]
        r = await client.patch(f"/api/repo-scans/{sid}", json={"pa_version": "0.10.0"}, headers=auth(operator_token))
        assert r.status_code == 200, r.text
        assert r.json()["pa_version"] == "0.10.0"
        r = await client.patch(f"/api/repo-scans/{sid}", json={"name": "renamed"}, headers=auth(operator_token))
        assert r.json()["pa_version"] == "0.10.0"
        r = await client.patch(f"/api/repo-scans/{sid}", json={"pa_version": None}, headers=auth(operator_token))
        assert r.json()["pa_version"] is None

    @pytest.mark.parametrize("bad", ["latest", "0.10.0 --index-url=http://x", ">=0.9", "0.10.0+local", "v0.10.0"])
    async def test_rejects_non_versions(self, client, operator_token, bad):
        r = await client.post("/api/repo-scans", json={**SCAN, "pa_version": bad}, headers=auth(operator_token))
        assert r.status_code == 422, r.text
        r = await client.post("/api/repo-scans", json=SCAN, headers=auth(operator_token))
        sid = r.json()["id"]
        r = await client.patch(f"/api/repo-scans/{sid}", json={"pa_version": bad}, headers=auth(operator_token))
        assert r.status_code == 422, r.text

    async def test_blank_means_unset(self, client, operator_token):
        r = await client.post("/api/repo-scans", json={**SCAN, "pa_version": "  "}, headers=auth(operator_token))
        assert r.status_code == 201, r.text
        assert r.json()["pa_version"] is None
