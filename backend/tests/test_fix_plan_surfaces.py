"""Fix plans outside the result panel: the Scans-page endpoint and headline count, and the findings email."""
from datetime import timedelta

import pytest

from app.core.email import build_findings_email
from app.models import AlertSeverity, RepoScan, RepoScanResult, RepoScanStatus, utcnow
from tests.conftest import auth

PLAN = {
    "status": "planned", "lockfile": "uv.lock", "exit_code": 1, "duration_seconds": 32.3, "timeout_seconds": 900,
    "plan": {
        "lockfile": "uv.lock", "verified": True,
        "planned": [
            {"package": "anyio", "version": "4.14.1", "target": "4.14.2", "verified": True},
            {"package": "urllib3", "version": "2.6.3", "target": "2.8.0", "verified": True},
        ],
        "held": [{"package": "pip", "version": "26.1", "target": "26.2", "reason": "blocked", "detail": "chalice"}],
        "commands": [["uv", "lock", "--upgrade-package", "anyio==4.14.2", "--upgrade-package", "urllib3==2.8.0"],
                     ["uv", "sync"]],
    },
}
FINDINGS = [{"package": "anyio", "severity": "high", "advisory_id": "GHSA-a", "summary": "x"}]


def _email(fix_plan):
    return build_findings_email(
        repo_name="iam", branch="master", pa_version="0.10.0rc1", findings=FINDINGS,
        min_severity=AlertSeverity.medium, recipients=["a@example.com"], from_addr="f@example.com",
        fix_plan=fix_plan,
    )


class TestFindingsEmailFixPlan:
    def test_planned_upgrades_commands_and_held(self):
        msg = _email(PLAN)
        assert msg["Subject"].endswith("— 2 fixes available")
        body = msg.get_content()
        assert "Fix plan (uv.lock): 2 upgrades, verified:" in body
        assert "anyio" in body and "4.14.1 -> 4.14.2" in body and "2.6.3 -> 2.8.0" in body
        assert "  uv lock --upgrade-package anyio==4.14.2 --upgrade-package urllib3==2.8.0\n  uv sync\n" in body
        assert "Held: 1 (see PA Central for reasons)" in body

    def test_one_fix_is_singular(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "planned": PLAN["plan"]["planned"][:1]}}
        msg = _email(plan)
        assert msg["Subject"].endswith("— 1 fix available")
        assert "1 upgrade, verified" in msg.get_content()

    def test_unverified_plan_says_why(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "verified": False, "unverified_reason": "network is disabled"}}
        assert "not verified (network is disabled)" in _email(plan).get_content()

    def test_a_shared_trial_failure_is_not_reported_as_no_upgrades(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "planned": [], "commands": [],
                                 "trial_failure": "uv lock failed: 401 Unauthorized"}}
        body = _email(plan).get_content()
        assert "no upgrades available" not in body
        assert "Fix plan (uv.lock): upgrades could not be checked." in body
        assert "Trial resolves failed: uv lock failed: 401 Unauthorized" in body

    def test_a_trial_failure_is_reported_alongside_planned_upgrades(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "trial_failure": "network unreachable"}}
        assert "Trial resolves failed: network unreachable" in _email(plan).get_content()

    def test_separate_mode_says_the_commands_apply_only_the_first_fix(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "separate": True, "separate_reason": "their upgrades conflict",
                                 "deferred": ["urllib3"]}}
        body = _email(plan).get_content()
        assert ("These fixes could not be verified as one command: their upgrades conflict. "
                "Only the first is printed.\nCommands:") in body
        assert "Next, after applying that and re-running pa fix: urllib3\n" in body

    def test_unchecked_withdrawn_releases_are_disclosed_before_the_commands(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "lock_drift_unchecked": 2}}
        body = _email(plan).get_content()
        assert ("Warning: 2 version(s) that re-locking the project installs could not be checked for withdrawn "
                "releases.\nCommands:") in body
        assert "withdrawn" not in _email(PLAN).get_content()

    def test_a_combined_plan_has_no_separate_mode_lines(self):
        body = _email(PLAN).get_content()
        assert "one command" not in body and "re-running pa fix" not in body

    def test_nothing_planned(self):
        plan = {**PLAN, "plan": {**PLAN["plan"], "planned": [], "commands": []}}
        msg = _email(plan)
        assert "fix" not in msg["Subject"]
        assert "Fix plan (uv.lock): no upgrades available." in msg.get_content()

    @pytest.mark.parametrize("stored, text", [
        ({"status": "timeout", "timeout_seconds": 900}, "Fix plan: timed out after 900s"),
        ({"status": "error", "error": "pa fix exited 3"}, "Fix plan: failed: pa fix exited 3"),
        ({"status": "unsupported", "error": "no lockfile"}, "Fix plan: not supported for this project: no lockfile"),
    ])
    def test_unfinished_plans_are_one_line(self, stored, text):
        msg = _email(stored)
        assert "fix" not in msg["Subject"]
        assert text in msg.get_content()

    @pytest.mark.parametrize("stored", [None, "garbage", {"status": "planned", "plan": "garbage"}])
    def test_no_or_unusable_plan_leaves_the_email_unchanged(self, stored):
        body = _email(stored).get_content()
        assert "Fix plan" not in body
        assert body == _email(None).get_content()


@pytest.fixture
async def scan(db, admin_user):
    s = RepoScan(name="iam", url="https://bitbucket.org/x/iam", branch="master", min_notify_severity="medium",
                 created_by_id=admin_user.id)
    db.add(s)
    await db.commit()
    return s


async def _result(db, scan, status, fix_plan, age_minutes):
    started = utcnow() - timedelta(minutes=age_minutes)
    r = RepoScanResult(repo_scan_id=scan.id, status=status, started_at=started,
                       completed_at=started + timedelta(minutes=1), fix_plan=fix_plan)
    db.add(r)
    await db.commit()
    return r.id


@pytest.mark.asyncio
class TestLatestFixPlanEndpoint:
    async def test_requires_auth(self, client, scan):
        assert (await client.get(f"/api/repo-scans/{scan.id}/fix-plan")).status_code == 401

    async def test_viewer_is_forbidden(self, client, viewer_token, scan):
        r = await client.get(f"/api/repo-scans/{scan.id}/fix-plan", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_unknown_scan_is_404(self, client, operator_token):
        assert (await client.get("/api/repo-scans/999999/fix-plan", headers=auth(operator_token))).status_code == 404

    async def test_null_before_any_successful_scan(self, client, operator_token, db, scan):
        await _result(db, scan, RepoScanStatus.failed, None, 5)
        r = await client.get(f"/api/repo-scans/{scan.id}/fix-plan", headers=auth(operator_token))
        assert r.status_code == 200
        assert r.json() is None

    async def test_latest_successful_result_wins(self, client, operator_token, db, scan):
        await _result(db, scan, RepoScanStatus.success, {"status": "timeout", "timeout_seconds": 900}, 30)
        want = await _result(db, scan, RepoScanStatus.success, PLAN, 20)
        await _result(db, scan, RepoScanStatus.failed, None, 10)  # newer, but not successful
        await _result(db, scan, RepoScanStatus.running, None, 1)
        r = await client.get(f"/api/repo-scans/{scan.id}/fix-plan", headers=auth(operator_token))
        assert r.status_code == 200
        body = r.json()
        assert body["result_id"] == want
        assert [p["package"] for p in body["fix_plan"]["plan"]["planned"]] == ["anyio", "urllib3"]
        assert body["fix_plan"]["near_timeout"] is False

    async def test_latest_success_without_a_plan_is_reported_as_such(self, client, operator_token, db, scan):
        await _result(db, scan, RepoScanStatus.success, PLAN, 20)
        want = await _result(db, scan, RepoScanStatus.success, None, 10)
        body = (await client.get(f"/api/repo-scans/{scan.id}/fix-plan", headers=auth(operator_token))).json()
        assert body == {"result_id": want, "completed_at": body["completed_at"], "fix_plan": None}


@pytest.mark.asyncio
class TestHeadlineFixCount:
    async def _count(self, client, token, scan_id):
        r = await client.get("/api/repo-scans/headlines", headers=auth(token))
        assert r.status_code == 200
        return next(h for h in r.json() if h["id"] == scan_id)["fix_count"]

    async def test_counts_planned_upgrades_of_latest_success(self, client, operator_token, db, scan):
        await _result(db, scan, RepoScanStatus.success, PLAN, 20)
        await _result(db, scan, RepoScanStatus.failed, None, 10)
        assert await self._count(client, operator_token, scan.id) == 2

    @pytest.mark.parametrize("stored", [None, {"status": "timeout", "timeout_seconds": 900}])
    async def test_null_without_a_usable_plan(self, client, operator_token, db, scan, stored):
        await _result(db, scan, RepoScanStatus.success, stored, 20)
        assert await self._count(client, operator_token, scan.id) is None

    async def test_null_with_no_results(self, client, operator_token, scan):
        assert await self._count(client, operator_token, scan.id) is None


@pytest.mark.asyncio
async def test_only_the_winning_results_plans_are_read(db, scan):
    # The ranking window covers every historical result; it must not carry their plan JSON along.
    from sqlalchemy import event

    from app.services.fix_plan_latest import latest_fix_plans

    for age in (30, 20, 10):
        await _result(db, scan, RepoScanStatus.success, PLAN, age)
    statements = []

    def record(conn, cursor, statement, *_a):
        statements.append(statement)

    engine = db.bind.sync_engine if hasattr(db.bind, "sync_engine") else db.bind
    event.listen(engine, "before_cursor_execute", record)
    try:
        out = await latest_fix_plans(db, [scan.id])
    finally:
        event.remove(engine, "before_cursor_execute", record)
    assert out[scan.id][2] is not None
    query = next(s for s in statements if "row_number" in s.lower())
    assert query.count("fix_plan") == 1, query
