"""Tests for /api/config-templates endpoints."""
import pytest
from tests.conftest import auth


async def _create_template(client, token, name="base-cfg", content="[x]\ny=1"):
    r = await client.post("/api/config-templates", json={
        "name": name,
        "toml_content": content,
    }, headers=auth(token))
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
class TestListTemplates:
    async def test_returns_empty(self, client, admin_token):
        r = await client.get("/api/config-templates", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_returns_templates(self, client, admin_token):
        await _create_template(client, admin_token)
        r = await client.get("/api/config-templates", headers=auth(admin_token))
        assert len(r.json()) == 1

    async def test_requires_auth(self, client):
        r = await client.get("/api/config-templates")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestCreateTemplate:
    async def test_operator_can_create(self, client, operator_token):
        r = await client.post("/api/config-templates", json={
            "name": "prod-cfg",
            "description": "production config",
            "toml_content": "[pa]\nlevel = 'high'",
        }, headers=auth(operator_token))
        assert r.status_code == 201
        assert r.json()["name"] == "prod-cfg"
        assert r.json()["toml_content"] == "[pa]\nlevel = 'high'"

    async def test_viewer_cannot_create(self, client, viewer_token):
        r = await client.post("/api/config-templates", json={
            "name": "v", "toml_content": ""
        }, headers=auth(viewer_token))
        assert r.status_code == 403


@pytest.mark.asyncio
class TestUpdateTemplate:
    async def test_operator_can_update(self, client, operator_token):
        tmpl = await _create_template(client, operator_token)
        r = await client.patch(f"/api/config-templates/{tmpl['id']}", json={
            "toml_content": "[updated]\nfoo=1",
        }, headers=auth(operator_token))
        assert r.status_code == 200
        assert r.json()["toml_content"] == "[updated]\nfoo=1"

    async def test_update_missing_returns_404(self, client, admin_token):
        r = await client.patch("/api/config-templates/999999", json={
            "toml_content": "x"
        }, headers=auth(admin_token))
        assert r.status_code == 404


@pytest.mark.asyncio
class TestDeleteTemplate:
    async def test_admin_can_delete(self, client, admin_token):
        tmpl = await _create_template(client, admin_token)
        r = await client.delete(f"/api/config-templates/{tmpl['id']}", headers=auth(admin_token))
        assert r.status_code == 204

    async def test_operator_cannot_delete(self, client, operator_token):
        tmpl = await _create_template(client, operator_token, name="op-cfg")
        r = await client.delete(f"/api/config-templates/{tmpl['id']}", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_delete_missing_returns_404(self, client, admin_token):
        r = await client.delete("/api/config-templates/999999", headers=auth(admin_token))
        assert r.status_code == 404


@pytest.mark.asyncio
class TestAssignTemplate:
    async def test_operator_can_assign_to_host(self, client, operator_token, host):
        tmpl = await _create_template(client, operator_token, name="assign-cfg")
        r = await client.post(
            f"/api/config-templates/{tmpl['id']}/assign/{host.id}",
            headers=auth(operator_token),
        )
        assert r.status_code == 201
        assert r.json()["host_id"] == host.id
        assert r.json()["template_id"] == tmpl["id"]

    async def test_for_host_returns_assigned_template(self, client, admin_token, host):
        tmpl = await _create_template(client, admin_token, name="for-host-cfg")
        await client.post(
            f"/api/config-templates/{tmpl['id']}/assign/{host.id}",
            headers=auth(admin_token),
        )
        r = await client.get(f"/api/config-templates/for-host/{host.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["id"] == tmpl["id"]

    async def test_for_host_returns_null_when_unassigned(self, client, admin_token, host):
        r = await client.get(f"/api/config-templates/for-host/{host.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() is None

    async def test_assign_missing_template_returns_404(self, client, operator_token, host):
        r = await client.post(
            f"/api/config-templates/999999/assign/{host.id}",
            headers=auth(operator_token),
        )
        assert r.status_code == 404


@pytest.mark.asyncio
class TestConfigTemplateDeletionGuard:
    async def test_delete_fails_when_assigned_to_host(self, client, admin_token, host, db, admin_user):
        from app.models import ConfigTemplate, ConfigAssignment
        tmpl = ConfigTemplate(name="guarded-tmpl", toml_content="[osv]", created_by_id=admin_user.id)
        db.add(tmpl)
        await db.commit()
        await db.refresh(tmpl)
        assignment = ConfigAssignment(host_id=host.id, template_id=tmpl.id, assigned_by_id=admin_user.id)
        db.add(assignment)
        await db.commit()

        r = await client.delete(f"/api/config-templates/{tmpl.id}", headers=auth(admin_token))
        assert r.status_code == 409
        assert "host" in r.json()["detail"].lower()

    async def test_delete_fails_when_assigned_to_repo_scan(self, client, admin_token, db, admin_user):
        from app.models import ConfigTemplate, RepoScan, AlertSeverity
        tmpl = ConfigTemplate(name="repo-tmpl", toml_content="[osv]", created_by_id=admin_user.id)
        db.add(tmpl)
        await db.commit()
        await db.refresh(tmpl)
        scan = RepoScan(
            name="my-repo",
            url="https://github.com/example/repo",
            branch="main",
            min_notify_severity=AlertSeverity.medium,
            config_template_id=tmpl.id,
            created_by_id=admin_user.id,
        )
        db.add(scan)
        await db.commit()

        r = await client.delete(f"/api/config-templates/{tmpl.id}", headers=auth(admin_token))
        assert r.status_code == 409
        assert "repo scan" in r.json()["detail"].lower()

    async def test_delete_succeeds_when_not_assigned(self, client, admin_token, db, admin_user):
        from app.models import ConfigTemplate
        tmpl = ConfigTemplate(name="free-tmpl", toml_content="[osv]", created_by_id=admin_user.id)
        db.add(tmpl)
        await db.commit()
        await db.refresh(tmpl)

        r = await client.delete(f"/api/config-templates/{tmpl.id}", headers=auth(admin_token))
        assert r.status_code == 204


@pytest.mark.asyncio
class TestDefaultTemplate:
    async def test_set_default_flag(self, client, admin_token):
        tmpl = await _create_template(client, admin_token, name="cfg-a")
        r = await client.patch(
            f"/api/config-templates/{tmpl['id']}",
            json={"is_default": True},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["is_default"] is True

    async def test_setting_new_default_clears_old(self, client, admin_token):
        a = await _create_template(client, admin_token, name="cfg-a2")
        b = await _create_template(client, admin_token, name="cfg-b2")
        await client.patch(
            f"/api/config-templates/{a['id']}",
            json={"is_default": True},
            headers=auth(admin_token),
        )
        await client.patch(
            f"/api/config-templates/{b['id']}",
            json={"is_default": True},
            headers=auth(admin_token),
        )
        r_a = await client.get(f"/api/config-templates/{a['id']}", headers=auth(admin_token))
        r_b = await client.get(f"/api/config-templates/{b['id']}", headers=auth(admin_token))
        assert r_a.json()["is_default"] is False
        assert r_b.json()["is_default"] is True

    async def test_unset_default(self, client, admin_token):
        tmpl = await _create_template(client, admin_token, name="cfg-c")
        await client.patch(
            f"/api/config-templates/{tmpl['id']}",
            json={"is_default": True},
            headers=auth(admin_token),
        )
        r = await client.patch(
            f"/api/config-templates/{tmpl['id']}",
            json={"is_default": False},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["is_default"] is False

    async def test_list_includes_is_default(self, client, admin_token):
        tmpl = await _create_template(client, admin_token, name="cfg-d")
        await client.patch(
            f"/api/config-templates/{tmpl['id']}",
            json={"is_default": True},
            headers=auth(admin_token),
        )
        r = await client.get("/api/config-templates", headers=auth(admin_token))
        defaults = [t for t in r.json() if t["is_default"]]
        assert len(defaults) == 1
        assert defaults[0]["id"] == tmpl["id"]
