"""fix_plan on repo-scan-result ingest: stored leniently, never rejecting the scan."""
import json

import pytest

from app.core.config import settings as app_settings
from app.models import (
    AlertSeverity,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    ScanTrigger,
)
from tests.conftest import auth

KEY = "test-fleet-system-key-for-tests"

PLAN = {
    "status": "planned", "lockfile": "backend/uv.lock", "exit_code": 1,
    "duration_seconds": 344.2, "timeout_seconds": 900,
    "plan": {
        "lockfile": "backend/uv.lock",
        "planned": [{"package": "requests", "version": "2.31.0", "target": "2.33.0", "direct": True,
                     "path": ["proj", "requests"], "advisories": ["GHSA-9hjg"], "left_open": [],
                     "fixes_all": None, "fixes_all_advisories": [], "cooldown_checked": True, "verified": True,
                     "changes": [], "parent": None, "more_parents": [], "forced": None, "by_relock": False}],
        "held": [{"package": "ecdsa", "version": "0.19.2", "target": None, "reason": "no fix known",
                  "advisories": ["GHSA-wj6h"], "detail": "", "cadence": None, "needs_major": []}],
        "commands": [["uv", "lock", "--upgrade-package", "requests==2.33.0"], ["uv", "sync"]],
        "command_changes": [], "yanked_locked": [], "trial_failure": None, "lock_drift": [],
        "lock_drift_unchecked": 0, "sync": {"flags": [], "warning": None}, "separate": False,
        "separate_reason": None, "deferred": [], "osv_failures": 0, "not_public": 0, "yank_failures": 0,
        "verified": True, "unverified_reason": None,
    },
}


@pytest.fixture(autouse=True)
def system_key(monkeypatch):
    monkeypatch.setattr(app_settings, "fleet_system_api_key", KEY)
    monkeypatch.setattr("app.api.ingest._send_result_email", lambda *a, **kw: None)


@pytest.fixture
async def running(db, admin_user):
    scan = RepoScan(name="f", url="https://github.com/t/f", branch="main",
                    min_notify_severity=AlertSeverity.medium, created_by_id=admin_user.id)
    db.add(scan)
    await db.commit()
    res = RepoScanResult(repo_scan_id=scan.id, status=RepoScanStatus.running, triggered_by=ScanTrigger.manual)
    db.add(res)
    await db.commit()
    await db.refresh(res)
    return scan, res


async def _post(client, rid, **extra):
    return await client.post("/api/ingest/repo-scan-result", json={
        "repo_scan_result_id": rid, "status": "success", "finding_count": 1, "findings": [], **extra,
    }, headers={"X-API-Key": KEY})


async def _out(client, scan_id, token):
    return (await client.get(f"/api/repo-scans/{scan_id}/results", headers=auth(token))).json()[0]["fix_plan"]


@pytest.mark.asyncio
class TestIngestFixPlan:
    async def test_round_trip(self, client, running, admin_token):
        scan, res = running
        assert (await _post(client, res.id, fix_plan=PLAN)).status_code == 204
        out = await _out(client, scan.id, admin_token)
        assert out["status"] == "planned" and out["lockfile"] == "backend/uv.lock"
        assert out["plan"]["planned"][0]["target"] == "2.33.0"
        assert out["plan"]["commands"][0][0] == "uv"
        assert out["near_timeout"] is False

    async def test_all_results_endpoint_exposes_it(self, client, running, admin_token):
        _, res = running
        await _post(client, res.id, fix_plan=PLAN)
        r = await client.get("/api/repo-scans/results", headers=auth(admin_token))
        assert r.json()[0]["fix_plan"]["status"] == "planned"

    async def test_absent_is_null(self, client, running, db):
        _, res = running
        await _post(client, res.id)
        await db.refresh(res)
        assert res.fix_plan is None

    @pytest.mark.parametrize("duration, timeout, status, near", [
        (720.0, 900, "planned", True), (719.9, 900, "planned", False), (900.0, 900, "timeout", False),
        (None, 900, "planned", False), (500.0, None, "error", False),
    ])
    async def test_near_timeout(self, client, running, admin_token, duration, timeout, status, near):
        scan, res = running
        fp = {"status": status, "duration_seconds": duration, "timeout_seconds": timeout}
        await _post(client, res.id, fix_plan=fp)
        assert (await _out(client, scan.id, admin_token))["near_timeout"] is near

    async def test_malformed_entries_are_dropped(self, client, running, admin_token):
        scan, res = running
        bad = {**PLAN, "plan": {**PLAN["plan"], "planned": [PLAN["plan"]["planned"][0], {"path": "not-a-list"}],
                                "held": ["nope", PLAN["plan"]["held"][0]]}}
        assert (await _post(client, res.id, fix_plan=bad)).status_code == 204
        out = await _out(client, scan.id, admin_token)
        assert [p["package"] for p in out["plan"]["planned"]] == ["requests"]
        assert [h["package"] for h in out["plan"]["held"]] == ["ecdsa"]

    @pytest.mark.parametrize("fix_plan", [
        "a string", [1, 2], {"status": 5}, {"duration_seconds": "slow"}, {"plan": {"planned": {"a": 1}}},
        {"plan": "nope"},
    ])
    async def test_malformed_shapes_never_reject_the_scan(self, client, running, db, fix_plan):
        _, res = running
        r = await _post(client, res.id, fix_plan=fix_plan)
        assert r.status_code == 204, r.text
        await db.refresh(res)
        assert res.status == RepoScanStatus.success

    async def test_unknown_keys_are_ignored(self, client, running, admin_token):
        scan, res = running
        await _post(client, res.id, fix_plan={**PLAN, "future": 1, "plan": {**PLAN["plan"], "apply": {}}})
        out = await _out(client, scan.id, admin_token)
        assert "future" not in out and out["status"] == "planned"


    async def test_one_wrong_typed_field_keeps_the_rest(self, client, running, admin_token):
        scan, res = running
        plan = {**PLAN["plan"], "deferred": [1], "osv_failures": "x", "sync": "no", "verified": "yes",
                "trial_failure": 5, "lock_drift_unchecked": None}
        await _post(client, res.id, fix_plan={**PLAN, "plan": plan})
        out = await _out(client, scan.id, admin_token)
        assert out["plan"] is not None
        assert out["plan"]["planned"][0]["package"] == "requests"
        assert out["plan"]["commands"][0][0] == "uv"
        assert out["plan"]["deferred"] == [] and out["plan"]["osv_failures"] == 0
        assert out["plan"]["sync"] is None and out["plan"]["verified"] is None
        assert out["plan"]["trial_failure"] is None

    async def test_str_list_keeps_valid_items(self, client, running, admin_token):
        scan, res = running
        p = {**PLAN["plan"], "deferred": ["a", 1, "b"],
             "planned": [{**PLAN["plan"]["planned"][0], "advisories": ["G1", 2, None]}]}
        await _post(client, res.id, fix_plan={**PLAN, "plan": p})
        out = await _out(client, scan.id, admin_token)
        assert out["plan"]["deferred"] == ["a", "b"]
        assert out["plan"]["planned"][0]["advisories"] == ["G1"]

    @pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
    async def test_non_finite_duration_becomes_none(self, client, running, admin_token, db, literal):
        scan, res = running
        body = json.dumps({"repo_scan_result_id": res.id, "status": "success", "finding_count": 1,
                           "findings": [], "fix_plan": {"status": "planned", "duration_seconds": 0,
                                                         "timeout_seconds": 900}})
        body = body.replace('"duration_seconds": 0', f'"duration_seconds": {literal}')
        r = await client.post("/api/ingest/repo-scan-result", content=body,
                              headers={"X-API-Key": KEY, "Content-Type": "application/json"})
        assert r.status_code == 204, r.text
        out = await _out(client, scan.id, admin_token)
        assert out["status"] == "planned" and out["duration_seconds"] is None
        await db.refresh(res)
        assert res.fix_plan["status"] == "planned" and res.fix_plan["duration_seconds"] is None

    @pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
    async def test_non_finite_in_untyped_plan_fields_becomes_none(self, client, running, admin_token, db, literal):
        # PostgreSQL's json type rejects NaN/Infinity: one nested in an untyped field would fail
        # the commit and lose the whole scan result.
        scan, res = running
        plan = json.loads(json.dumps(PLAN))
        plan["plan"]["planned"][0]["changes"] = [{"package": "idna", "score": "@X@"}]
        plan["plan"]["planned"][0]["parent"] = {"package": "p", "n": "@X@"}
        plan["plan"]["planned"][0]["forced"] = {"x": ["@X@"]}
        plan["plan"]["planned"][0]["more_parents"] = [{"n": "@X@"}]
        plan["plan"]["lock_drift"] = [{"package": "a", "delta": "@X@"}]
        plan["plan"]["sync"] = {"flags": [], "ratio": "@X@"}
        plan["plan"]["command_changes"] = ["@X@"]
        plan["plan"]["yanked_locked"] = [{"v": "@X@"}]
        plan["plan"]["commands"] = [["uv", "@X@"]]
        body = json.dumps({"repo_scan_result_id": res.id, "status": "success", "finding_count": 1,
                           "findings": [], "fix_plan": plan}).replace('"@X@"', literal)
        assert literal in body
        r = await client.post("/api/ingest/repo-scan-result", content=body,
                              headers={"X-API-Key": KEY, "Content-Type": "application/json"})
        assert r.status_code == 204, r.text
        await db.refresh(res)
        stored = res.fix_plan["plan"]
        assert stored["planned"][0]["changes"] == [{"package": "idna", "score": None}]
        assert stored["planned"][0]["parent"] == {"package": "p", "n": None}
        assert stored["planned"][0]["forced"] == {"x": [None]}
        assert stored["planned"][0]["more_parents"] == [{"n": None}]
        assert stored["lock_drift"] == [{"package": "a", "delta": None}]
        assert stored["sync"] == {"flags": [], "ratio": None}
        assert stored["command_changes"] == [None]
        assert stored["yanked_locked"] == [{"v": None}]
        assert stored["commands"] == [["uv", None]]
        assert "NaN" not in json.dumps(res.fix_plan) and "Infinity" not in json.dumps(res.fix_plan)
        out = await _out(client, scan.id, admin_token)
        assert out["plan"]["lock_drift"] == [{"package": "a", "delta": None}]

    @pytest.mark.parametrize("depth", [1500, 5000])
    async def test_deeply_nested_body_is_refused_by_the_middleware_not_a_500(self, client, running, depth):
        # Over HTTP, http_middleware rejects bodies nested past MAX_JSON_NESTING_DEPTH with a 400 before
        # validation runs, so the RecursionError path below is unreachable through the API today.
        _, res = running
        deep = "[" * depth + "1" + "]" * depth
        body = json.dumps({"repo_scan_result_id": res.id, "status": "success", "finding_count": 1,
                           "findings": [], "fix_plan": PLAN}).replace('"lock_drift": []', f'"lock_drift": {deep}')
        assert deep in body
        r = await client.post("/api/ingest/repo-scan-result", content=body,
                              headers={"X-API-Key": KEY, "Content-Type": "application/json"})
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize("depth", [1500, 5000])
    def test_deeply_nested_fix_plan_never_raises_in_schema_validation(self, depth):
        # The binding rule: a fix-plan problem never costs the scan its result. Validation of the ingest
        # model must not raise (RecursionError is not a ValidationError); the plan is kept sanitised or dropped.
        from app.schemas import RepoScanResultIngest

        deep: object = 1
        for _ in range(depth):
            deep = [deep]
        plan = json.loads(json.dumps(PLAN))
        plan["plan"]["lock_drift"] = deep
        m = RepoScanResultIngest.model_validate({
            "repo_scan_result_id": 1, "status": "success", "finding_count": 1, "findings": [], "fix_plan": plan,
        })
        assert m.fix_plan is not None and m.fix_plan.status == "planned"
        assert m.fix_plan.plan is not None
        assert m.fix_plan.plan.lock_drift is not None

    def test_recursion_error_in_plan_validation_drops_the_plan(self, monkeypatch):
        # Backstop: even if something below recurses too deep, the plan/fix_plan is dropped like a malformed one.
        from app import schemas

        def boom(*a, **kw):
            raise RecursionError

        monkeypatch.setattr(schemas.FixPlan, "model_validate", boom)
        assert schemas._plan_or_none({"lockfile": "x"}) is None
        monkeypatch.setattr(schemas.FixPlanResult, "model_validate", boom)
        assert schemas._fix_plan_or_none({"status": "planned"}) is None

    def test_finite_tree_sanitises_deep_nan_without_recursion(self):
        from app.schemas import _finite_tree

        depth = 3000
        v: object = float("nan")
        for _ in range(depth):
            v = [v]
        out = _finite_tree(v)
        for _ in range(depth):
            assert isinstance(out, list) and len(out) == 1
            out = out[0]
        assert out is None

    def test_finite_tree_leaves_other_values_alone(self):
        from app.schemas import _finite_tree

        src = {"a": [True, 1, "s", 1.5, float("inf")], "b": {"c": float("-inf"), "d": None}}
        assert _finite_tree(src) == {"a": [True, 1, "s", 1.5, None], "b": {"c": None, "d": None}}

    @pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
    def test_non_finite_duration_schema(self, value):
        from app.schemas import RepoScanResultIngest

        body = RepoScanResultIngest.model_validate(
            {"repo_scan_result_id": 1, "status": "success", "fix_plan": {"status": "planned", "duration_seconds": value}}
        )
        assert body.fix_plan.status == "planned" and body.fix_plan.duration_seconds is None

    def test_huge_int_duration_schema(self):
        from app.schemas import FixPlanResult

        r = FixPlanResult.model_validate({"status": "planned", "duration_seconds": 10**400, "osv": 1})
        assert r.status == "planned" and r.duration_seconds is None

    async def test_huge_int_duration_endpoint(self, client, running, admin_token, db):
        _, res = running
        big = "9" * 400
        body = (
            f'{{"repo_scan_result_id": {res.id}, "status": "success", "finding_count": 1, "findings": [], '
            f'"fix_plan": {{"status": "planned", "duration_seconds": {big}, "timeout_seconds": {big}}}}}'
        )
        r = await client.post("/api/ingest/repo-scan-result", content=body,
                              headers={"X-API-Key": KEY, "Content-Type": "application/json"})
        assert r.status_code == 204, r.text
        await db.refresh(res)
        assert res.fix_plan["status"] == "planned"
        assert res.fix_plan["duration_seconds"] is None and res.fix_plan["timeout_seconds"] is None

    def test_integral_float_accepted_for_int_fields(self):
        from app.schemas import FixPlanResult

        r = FixPlanResult.model_validate(
            {"status": "planned", "timeout_seconds": 900.0, "exit_code": 1.5, "plan": {"osv_failures": 3.0}}
        )
        assert r.timeout_seconds == 900 and r.exit_code is None and r.plan.osv_failures == 3
        assert FixPlanResult.model_validate({"timeout_seconds": True}).timeout_seconds is None

    def test_planned_fix_bool_fields_are_lenient(self):
        from app.schemas import PlannedFix

        p = PlannedFix.model_validate(
            {"package": "a", "direct": "yes", "cooldown_checked": 1, "by_relock": [], "verified": True}
        )
        assert p.package == "a" and p.direct is None and p.cooldown_checked is None
        assert p.by_relock is None and p.verified is True

