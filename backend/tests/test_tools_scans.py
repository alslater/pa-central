"""`pa scan-tools` scans (package-alert #117, pa-central #26): ingest and the host's latest view.

A tools scan is one Scan per pipx or uv tools directory (`scan_type` "tools", `root` the
directory). It carries the run that produced it so a directory a later run no longer reports
can be retired from the host's latest view: for each (host, home, manager), only the newest
run by its shared scanned_at counts, and a root missing from that run's run_roots is hidden.
Retired scans stay in GET /scans history.
"""
import logging
from datetime import UTC, datetime, timedelta

import pytest

from tests.conftest import auth

PIPX = "/home/al/.local/share/pipx/venvs"
PIPX_OLD = "/home/al/.local/pipx/venvs"
UV = "/home/al/.local/share/uv/tools"
T0 = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)

TOOL = {
    "manager": "pipx", "name": "awscli", "version": "1.33.0", "python": "3.12",
    "venv_root": f"{PIPX}/awscli",
    "provenance": {"kind": "pypi", "editable": False},
    "orphaned": [], "unchecked": [],
}


def tools_payload(root: str = PIPX, *, manager: str = "pipx", run_roots: list[str] | None = None,
                  scanned_at: datetime = T0, home: str | None = "/home/al", run_id: str = "run-1",
                  **extra) -> dict:
    body = {
        "hostname": "tools-host", "root": root, "scan_type": "tools", "status": "clean",
        "finding_count": 0, "findings": [], "risks": [],
        "manager": manager, "active": True, "exists": True, "run_id": run_id,
        "managers_scanned": [manager], "run_roots": run_roots if run_roots is not None else [root],
        "home": home, "tools": [], "unchecked": [], "scanned_at": scanned_at.isoformat(),
    }
    if home is None:
        del body["home"]
    return {**body, **extra}


async def post(client, raw_key, body):
    r = await client.post("/api/ingest/scans", json=body, headers={"X-API-Key": raw_key})
    assert r.status_code == 201, r.text
    return r.json()


async def latest(client, token, host_id) -> list[dict]:
    r = await client.get(f"/api/hosts/{host_id}/latest-scans", headers=auth(token))
    assert r.status_code == 200, r.text
    return r.json()


async def latest_roots(client, token, host_id) -> set[str]:
    return {s["project_path"] for s in await latest(client, token, host_id)}


@pytest.mark.asyncio
class TestToolsIngest:
    async def test_tools_scan_round_trips(self, client, api_key, admin_token):
        raw, _ = api_key
        local = {**TOOL, "name": "pa", "provenance": {
            "kind": "local", "editable": True, "path": "/home/al/dev/package-alert",
            "index_source": "config"}}
        extra = {**TOOL, "name": "httpie", "provenance": {"kind": "pypi", "editable": False, "extra_index": True},
                 "orphaned": [f"{PIPX}/httpie/lib/python3.11"], "unchecked": [f"{PIPX}/httpie/lib/python3.9"]}
        body = await post(client, raw, tools_payload(
            tools=[TOOL, local, extra], unchecked=[f"{PIPX}/locked", f"{PIPX}/httpie/lib/python3.9"],
            managers_scanned=["pipx", "uv"], run_roots=[PIPX, UV], status="degraded"))
        [scan] = await latest(client, admin_token, body["host_id"])
        assert scan["scan_type"] == "tools"
        assert (scan["manager"], scan["active"], scan["exists"], scan["home"], scan["run_id"]) == \
            ("pipx", True, True, "/home/al", "run-1")
        assert (scan["managers_scanned"], scan["run_roots"]) == (["pipx", "uv"], [PIPX, UV])
        assert scan["unchecked"] == [f"{PIPX}/locked", f"{PIPX}/httpie/lib/python3.9"]
        assert scan["tools"] == [TOOL, local, extra]       # unknown provenance keys survive
        assert scan["status"] == "degraded"

    async def test_project_scan_has_no_tools_fields(self, client, api_key):
        raw, _ = api_key
        body = await post(client, raw, {"hostname": "h", "root": "/app", "status": "clean"})
        assert (body["manager"], body["tools"], body["run_roots"], body["home"]) == (None, None, None, None)
        assert (body["active"], body["exists"], body["unchecked"]) == (True, True, [])

    async def test_malformed_tool_entries_are_dropped_not_rejected(self, client, api_key):
        """A 422 loses the whole scan; one bad inventory entry is not worth that."""
        raw, _ = api_key
        body = await post(client, raw, tools_payload(tools=[
            "not-a-dict", {"name": ["not", "a", "string"]}, {"version": "1.0"}, TOOL,
            {**TOOL, "name": "x", "provenance": "not-a-dict"},
        ]))
        assert [t["name"] for t in body["tools"]] == ["awscli", "x"]
        assert body["tools"][1]["provenance"] is None

    async def test_non_list_tools_and_unchecked_are_absent(self, client, api_key):
        raw, _ = api_key
        body = await post(client, raw, tools_payload(tools={"name": "x"}, unchecked="/a/dir"))
        assert (body["tools"], body["unchecked"]) == (None, [])

    async def test_non_string_unchecked_entries_are_dropped(self, client, api_key):
        raw, _ = api_key
        body = await post(client, raw, tools_payload(
            unchecked=["/a", 3, None, "/b"], tools=[{**TOOL, "unchecked": ["/c", {"x": 1}], "orphaned": ["/d", 5]}]))
        assert body["unchecked"] == ["/a", "/b"]
        assert (body["tools"][0]["unchecked"], body["tools"][0]["orphaned"]) == (["/c"], ["/d"])

    @pytest.mark.parametrize(("url", "stripped"), [
        ("https://user:s3cret@corp.example/simple", "https://corp.example/simple"),
        ("https://token@corp.example:8443/simple/", "https://corp.example:8443/simple/"),
        ("git+https://user:pw@github.com/org/repo.git@v1", "git+https://github.com/org/repo.git@v1"),
        ("https://corp.example/simple", "https://corp.example/simple"),
    ])
    async def test_provenance_url_credentials_are_stripped(self, client, api_key, url, stripped):
        """A backstop to package-alert's own stripping."""
        raw, _ = api_key
        body = await post(client, raw, tools_payload(
            tools=[{**TOOL, "provenance": {"kind": "index", "editable": False, "url": url}}]))
        assert body["tools"][0]["provenance"]["url"] == stripped

    async def test_a_dropped_entry_is_not_logged_with_its_credentials(self, client, api_key, caplog):
        """Stripping happens while validating, so an entry that fails validation is unstripped."""
        raw, _ = api_key
        bad = {"name": ["not", "a", "string"],
               "provenance": {"kind": "index", "url": "https://user:s3cret@corp.example/simple"}}
        with caplog.at_level(logging.WARNING):
            body = await post(client, raw, tools_payload(tools=[bad, TOOL]))
        assert [t["name"] for t in body["tools"]] == ["awscli"]
        assert any("tools entry" in r.getMessage() for r in caplog.records)
        assert "s3cret" not in caplog.text

    async def test_remediation_source_is_kept(self, client, api_key):
        raw, _ = api_key
        rem = {"package": "urllib3", "ecosystem": "PyPI", "version": "1.26.0", "source": "pipx:awscli"}
        body = await post(client, raw, tools_payload(remediations=[rem, {**rem, "source": "pipx:httpie"}]))
        assert [r["source"] for r in body["remediations"]] == ["pipx:awscli", "pipx:httpie"]

    async def test_findings_and_risks_keep_source(self, client, api_key, admin_token):
        """The client's `pa central scan <id>` view groups rows by source."""
        raw, _ = api_key
        finding = {"package": "urllib3", "version": "1.26.0", "source": "pipx:awscli"}
        risk = {"package": "x", "score": 40, "source": "pipx:awscli"}
        body = await post(client, raw, tools_payload(findings=[finding], risks=[risk], finding_count=1,
                                                     status="findings"))
        r = await client.get(f"/api/scans/{body['id']}", headers={"X-API-Key": raw})
        assert r.status_code == 200, r.text
        assert (r.json()["findings"][0]["source"], r.json()["risks"][0]["source"]) == ("pipx:awscli", "pipx:awscli")
        assert r.json()["unchecked"] == []


@pytest.mark.asyncio
class TestLatestScansPartition:
    async def test_same_path_different_scan_type_are_both_latest(self, client, api_key, admin_token):
        """A project and its --scan-installed environment share a path: each is its own row."""
        raw, _ = api_key
        a = await post(client, raw, {"hostname": "h", "root": "/app", "scan_type": "project", "status": "clean",
                                     "scanned_at": T0.isoformat()})
        await post(client, raw, {"hostname": "h", "root": "/app", "scan_type": "installed", "status": "clean",
                                 "scanned_at": (T0 + timedelta(minutes=1)).isoformat()})
        rows = await latest(client, admin_token, a["host_id"])
        assert sorted(s["scan_type"] for s in rows) == ["installed", "project"]


@pytest.mark.asyncio
class TestToolsRootRetirement:
    async def test_root_missing_from_the_newest_run_is_retired(self, client, api_key, admin_token):
        raw, _ = api_key
        roots = [PIPX, PIPX_OLD]
        a = await post(client, raw, tools_payload(PIPX, run_roots=roots))
        await post(client, raw, tools_payload(PIPX_OLD, run_roots=roots))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, PIPX_OLD}
        await post(client, raw, tools_payload(PIPX, run_roots=[PIPX], scanned_at=T0 + timedelta(hours=1),
                                              run_id="run-2"))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX}

    async def test_retired_scan_stays_in_history(self, client, api_key):
        raw, _ = api_key
        await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX, PIPX_OLD]))
        await post(client, raw, tools_payload(PIPX, run_roots=[PIPX], scanned_at=T0 + timedelta(hours=1)))
        r = await client.get("/api/scans", headers={"X-API-Key": raw})
        assert PIPX_OLD in {s["project_path"] for s in r.json()}

    async def test_a_late_older_run_does_not_bring_a_retired_root_back(self, client, api_key, admin_token):
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX, run_roots=[PIPX], scanned_at=T0 + timedelta(hours=1),
                                                  run_id="run-2"))
        # run-1 started earlier but its payload for the old layout arrives afterwards.
        await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX, PIPX_OLD], run_id="run-1"))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX}

    async def test_a_late_older_run_does_not_retire_a_root(self, client, api_key, admin_token):
        raw, _ = api_key
        later = T0 + timedelta(hours=1)
        a = await post(client, raw, tools_payload(PIPX, run_roots=[PIPX, PIPX_OLD], scanned_at=later,
                                                  run_id="run-2"))
        await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX, PIPX_OLD], scanned_at=later,
                                              run_id="run-2"))
        await post(client, raw, tools_payload(PIPX, run_roots=[PIPX], run_id="run-1"))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, PIPX_OLD}

    async def test_tied_scanned_at_is_broken_by_received_at(self, client, api_key, admin_token):
        """A retried payload of the same run shares scanned_at; the one received last counts."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX, PIPX_OLD]))
        await post(client, raw, tools_payload(PIPX, run_roots=[PIPX]))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX}

    async def test_another_managers_run_does_not_retire(self, client, api_key, admin_token):
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX, run_roots=[PIPX]))
        await post(client, raw, tools_payload(UV, manager="uv", run_roots=[UV], scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, UV}

    async def test_another_homes_run_does_not_retire(self, client, api_key, admin_token):
        """`sudo pa scan-tools` (home /root) must not hide al's tools under the same key."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX, run_roots=[PIPX]))
        root_pipx = "/root/.local/share/pipx/venvs"
        await post(client, raw, tools_payload(root_pipx, run_roots=[root_pipx], home="/root",
                                              scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, root_pipx}

    async def test_payloads_without_home_are_one_scope_of_their_own(self, client, api_key, admin_token):
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX, run_roots=[PIPX]))
        await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD], home=None))
        await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD], home=None,
                                              scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, PIPX_OLD}
        await post(client, raw, tools_payload("/elsewhere", run_roots=["/elsewhere"], home=None,
                                              scanned_at=T0 + timedelta(hours=2)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, "/elsewhere"}

    @pytest.mark.parametrize("absent", ["missing", "null"])
    async def test_a_run_without_run_roots_retires_nothing(self, client, api_key, admin_token, absent):
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD]))
        body = tools_payload(PIPX, scanned_at=T0 + timedelta(hours=1))
        if absent == "missing":
            del body["run_roots"]
        else:
            body["run_roots"] = None
        await post(client, raw, body)
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, PIPX_OLD}

    async def test_a_root_shared_by_two_homes_stays_while_either_run_lists_it(self, client, api_key, admin_token):
        """A system-wide PIPX_HOME is the same root for every account. When one account's runs
        stop listing it, the other account's latest scan of it must stay."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload("/opt/pipx/venvs", home="/home/b", run_roots=["/opt/pipx/venvs"]))
        await post(client, raw, tools_payload("/opt/pipx/venvs", home="/home/al", run_roots=["/opt/pipx/venvs"],
                                              scanned_at=T0 + timedelta(hours=1)))
        await post(client, raw, tools_payload(PIPX, home="/home/al", run_roots=[PIPX], run_id="run-2",
                                              scanned_at=T0 + timedelta(hours=2)))
        scans = await latest(client, admin_token, a["host_id"])
        assert {(s["project_path"], s["home"]) for s in scans} == {("/opt/pipx/venvs", "/home/b"), (PIPX, "/home/al")}

    @pytest.mark.parametrize("run_roots", ["/home/al/.local/share/pipx/venvs", [PIPX, 3], {"a": 1}])
    async def test_a_malformed_run_roots_retires_nothing(self, client, api_key, admin_token, run_roots):
        """A partial or mangled list is not an inventory: trusting it would hide live roots."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD]))
        b = await post(client, raw, tools_payload(PIPX, run_roots=run_roots, scanned_at=T0 + timedelta(hours=1)))
        assert b["run_roots"] is None
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX, PIPX_OLD}

    async def test_a_combined_run_retires_every_scanned_managers_roots(self, client, api_key, admin_token):
        """Every payload of a pipx-and-uv run carries both managers' roots, so the uv payload
        alone shows a pipx root has gone, even if the run's pipx payload never arrives."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD]))
        await post(client, raw, tools_payload(UV, manager="uv", managers_scanned=["pipx", "uv"],
                                              run_roots=[PIPX, UV], run_id="run-2",
                                              scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {UV}

    async def test_a_later_single_manager_run_does_not_bring_a_root_back(self, client, api_key, admin_token):
        """The combined run that hid the pipx root stays its newest pipx run after a later
        uv-only run replaces that run's uv row in the latest view."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD]))
        await post(client, raw, tools_payload(UV, manager="uv", managers_scanned=["pipx", "uv"],
                                              run_roots=[PIPX, UV], run_id="run-2",
                                              scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {UV}
        await post(client, raw, tools_payload(UV, manager="uv", run_roots=[UV], run_id="run-3",
                                              scanned_at=T0 + timedelta(hours=2)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {UV}

    async def test_a_manager_name_is_matched_whole(self, client, api_key, admin_token):
        """managers_scanned is matched in its JSON text: a run listing "pipx" must not count as
        a run of "pip", and a LIKE wildcard in a name ("pip_") is literal."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload("/pip", manager="pip", run_roots=["/pip"]))
        await post(client, raw, tools_payload("/pip_", manager="pip_", run_roots=["/pip_"]))
        await post(client, raw, tools_payload(UV, manager="uv", managers_scanned=["uv", "pipx"], run_roots=[UV],
                                              run_id="run-2", scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {"/pip", "/pip_", UV}

    @pytest.mark.parametrize("managers_scanned", ["missing", "null"])
    async def test_a_run_without_managers_scanned_still_retires_its_own_managers_roots(
            self, client, api_key, admin_token, managers_scanned):
        """An older client's payload has no managers_scanned: its own manager still makes it a run."""
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD]))
        body = tools_payload(PIPX, run_roots=[PIPX], run_id="run-2", scanned_at=T0 + timedelta(hours=1))
        if managers_scanned == "missing":
            del body["managers_scanned"]
        else:
            body["managers_scanned"] = None
        await post(client, raw, body)
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX}

    @pytest.mark.parametrize("managers_scanned", ["missing", "null", "pipx", ["uv", 3]])
    async def test_without_a_valid_managers_scanned_a_run_covers_its_own_manager(
            self, client, api_key, admin_token, managers_scanned):
        raw, _ = api_key
        a = await post(client, raw, tools_payload(PIPX_OLD, run_roots=[PIPX_OLD]))
        await post(client, raw, tools_payload(UV, manager="uv", run_roots=[UV], scanned_at=T0 + timedelta(hours=1)))
        body = tools_payload(UV, manager="uv", run_roots=[UV], scanned_at=T0 + timedelta(hours=2), run_id="run-3")
        if managers_scanned == "missing":
            del body["managers_scanned"]
        else:
            body["managers_scanned"] = None if managers_scanned == "null" else managers_scanned
        await post(client, raw, body)
        assert await latest_roots(client, admin_token, a["host_id"]) == {PIPX_OLD, UV}

    async def test_project_scans_are_never_retired(self, client, api_key, admin_token):
        raw, _ = api_key
        a = await post(client, raw, {"hostname": "tools-host", "root": "/app", "status": "clean",
                                     "scanned_at": T0.isoformat()})
        await post(client, raw, tools_payload(PIPX, run_roots=[PIPX], scanned_at=T0 + timedelta(hours=1)))
        assert await latest_roots(client, admin_token, a["host_id"]) == {"/app", PIPX}


@pytest.mark.asyncio
class TestRetirementQueryPlans:
    """The newest-run lookup runs once per (home, manager) on every host-page load, and reads
    newest first until a scan covers the manager. An index whose leading columns are the
    filter then the sort lets it stop at the first match instead of sorting the host's whole
    tools history. SQLite has no table statistics here, so its plan is stable to assert on."""

    @pytest.mark.parametrize("home", ["/home/al", None])
    async def test_newest_run_lookup_reads_an_index_newest_first(self, db, home):
        from sqlalchemy import text
        from sqlalchemy.dialects import sqlite

        from app.api.hosts import _newest_run_stmt
        sql = str(_newest_run_stmt(1, home, "pipx").compile(
            dialect=sqlite.dialect(), compile_kwargs={"literal_binds": True}))
        plan = " ".join(r[-1] for r in (await db.execute(text(f"EXPLAIN QUERY PLAN {sql}"))).all())
        assert "ix_scans_host_type_home_scanned_received_id" in plan, plan
        assert "TEMP B-TREE" not in plan, plan

