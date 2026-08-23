# PA Central — Roadmap

## Planned

### Redis Pub/Sub for SSE alert broadcasting

Currently `_sse_queues` in `backend/app/api/alerts.py` is an in-process set, so the live alert stream (`GET /alerts/stream`) only works correctly with a single worker process. Multiple uvicorn workers or container replicas each maintain independent queues, meaning clients miss alerts ingested by a different worker.

**Proposed solution:** Replace the in-process set with Redis Pub/Sub. The ingest endpoint publishes new alerts to a Redis channel; each worker subscribes and fans out to its local SSE clients. This makes the stream correct across any number of workers or replicas.

**Files affected:** `backend/app/api/alerts.py`, likely a new `backend/app/core/pubsub.py`, and `docker-compose.yml` / deployment config to add a Redis service.

---

### Short-lived public ID tokens via Redis (ID enumeration hardening)

Sequential integer PKs exposed in API responses allow enumeration attacks — an authenticated user who can access `/api/hosts/1` can trivially probe 2, 3, 4... This is a defence-in-depth measure on top of (not a substitute for) proper per-endpoint authorisation checks.

**Approach:** Keep integer PKs for all internal DB operations and joins. When serialising a response, map each exposed resource ID to a short-lived random token stored in Redis. Clients use the token in subsequent requests (route params, query params); the server resolves it back to the integer PK before any DB access.

**Design decisions:**

- **Token format:** `secrets.token_urlsafe(16)` — 128 bits of randomness, 22 URL-safe chars
- **TTL:** 15–30 minutes, sliding (refreshed on access), configurable
- **Scope:** Only IDs used as route or query params need tokens — `host_id`, `scan_id`, `alert_id`, `repo_scan_id`, `result_id`, `api_key_id`, `user_id`. Embedded FK values not used as route params (e.g. `config_template_id` in a response body) can stay as integers
- **Failure mode:** If Redis is unavailable, requests fail closed (401/503) rather than falling back to raw integer IDs — availability is sacrificed to preserve the security property. Acceptable once Redis is a hard infrastructure dependency anyway (see SSE roadmap item)
- **Token store:** `token:{token} → {resource_type}:{integer_id}` with TTL. Optionally also `id:{resource_type}:{integer_id} → token` to return the same token for the same resource within its TTL window (avoids token explosion on repeated fetches)

**Frontend token refresh:** Tokens expire mid-session if the UI holds references to resources without re-fetching them. Any page that stores an ID for later use (e.g. a selected host, an open scan row) must re-fetch the resource at an interval comfortably below the TTL — e.g. if TTL is 20 minutes, refresh every 10 minutes. Alternatively, a lightweight `GET /api/tokens/refresh` endpoint could accept a list of current tokens and return fresh ones, avoiding full resource re-fetches. The API client (`api.ts`) should handle 404s on token-keyed requests by triggering a re-fetch of the parent list and retrying, rather than surfacing a hard error to the user.

**Files affected:** new `backend/app/core/id_tokens.py`, `backend/app/api/deps.py` (resolver dependency), all route handlers that accept an ID path parameter, `backend/app/schemas/__init__.py` (response serialisation hook), `frontend/src/lib/api.ts` (token refresh interval logic, 404 retry handling), any page component that holds a selected resource ID in state.

**Prerequisite:** Redis/Valkey service (shared with SSE broadcasting roadmap item).

---

### GET /findings pagination is unused; the live unpaginated path is now GET /repo-scans/{id}/findings

`GET /findings` already has server-side `page`/`page_size`/`sort`/`sort_dir`
support (`backend/app/api/findings.py`, `api.findings.list()` in
`frontend/src/lib/api.ts`), added by an earlier pagination effort. That work
is still correct but is now dead from the UI's perspective: the ui-overhaul
branch removed the standalone Vulnerabilities page that called it, and
**no frontend view calls `api.findings.list()` any more.**

Current findings consumers, for accuracy:
- `Scans.tsx` calls `api.findings.listAllForRepo(scanId)` →
  `GET /repo-scans/{id}/findings` (`backend/app/api/repo_scans.py`,
  `get_repo_scan_findings`) — this returns every open finding for one scan
  as a plain `list[FindingRecordOut]`, with **no pagination and no row cap
  at all** (not even a fixed limit like the old `GET /findings` had).
- `HostDetail.tsx` reads `findings`/`risks` directly off the `Scan` object's
  embedded JSON columns (from `GET /hosts/{id}/latest-scans`) — there is no
  separate findings fetch on that page to paginate.

So the original entry's proposed fix (add pagination to `GET /findings`)
would not touch either live view — `GET /findings` isn't in their call
path at all. The unbounded-fetch risk that actually matters today is on
the per-repo-scan endpoint instead, and it's scoped differently: one scan's
finding count, not the whole table.

**Proposed solution:** If a repo scan's finding count becomes large enough
to matter, add pagination to `GET /repo-scans/{id}/findings` (and the
sibling `/risks` endpoint) and to `Scans.tsx`'s `RecordTabs`/`FindingsTable`
consumption of it, rather than to `GET /findings`.

**Files affected:** `backend/app/api/repo_scans.py` (`get_repo_scan_findings`,
`get_repo_scan_risks`), `frontend/src/lib/api.ts` (`listAllForRepo`
signature), `frontend/src/pages/Scans.tsx`.

**GET /findings' existing pagination:** left in place rather than removed —
it's correct, tested, and still reachable directly (e.g. for external API
use or a future admin view), even though nothing in the current UI calls
it. If it's confirmed to have no remaining consumer at all (internal or
external) by the time this is revisited, removing the dead
`api.findings.list()` client method and the unused query params would be
the simpler cleanup.

**Known limitations carried over from the original `GET /findings` design**
(apply if that endpoint's pagination is ever exercised again): when `breach`
or `accepted` filtering is active, the endpoint caps the SQL scan at
`limit * 10` rows (oldest-first) and filters in Python, so sparse matches
can under-return; and for `breach=true` with no `repo_scan_id`, the
pre-filter age cutoff uses the minimum effective SLA across *all* scans
rather than just those with open findings in scope, widening the candidate
set unnecessarily when any scan has a strict SLA override.

**Trigger:** When a single repo scan's finding count makes `Scans.tsx`
visibly slow to expand, or `GET /repo-scans/{id}/findings` becomes
expensive to fetch/render in one shot.

---

### Clickable table rows — accessibility refinement

Four table components in `frontend/src/components/ui.tsx` — `FindingsTable`, `RisksTable`, `FindingRecordsTable`, `RiskRecordsTable` — use `role="button"` + `tabIndex` on `<tr>` elements to make rows open a detail drawer. This pattern is widely supported (keyboard nav, `aria-label`, Enter/Space handlers all present) but is semantically impure — some screen readers treat `<tr role="button">` inconsistently.

**Note (2026-08-23):** originally written against the standalone Vulnerabilities page (removed by the ui-overhaul branch) and later narrowed to just `FindingsTable`/`RisksTable`, consumed by `ScanDetailTabs` on the Repo Scans/Host Detail pages. That missed `FindingRecordsTable`/`RiskRecordsTable`, a second, separate pair of table components with the identical `<tr role="button">` pattern, consumed by `RecordTabs` on the Scans page only. All four need the same fix — narrowing to one pair would leave the other unchanged.

**Preferred alternative:** Move the interactive affordance to a dedicated "View" `<button>` inside a `<td>`, keeping the row purely tabular. This is a layout change (adds a visible or visually-hidden button column) so it is deferred until there is appetite for the UI churn.

**Files affected:** `frontend/src/components/ui.tsx` (`FindingsTable`, `RisksTable`, `FindingRecordsTable`, `RiskRecordsTable`)

---

### Extract finding components out of ui.tsx

`ui.tsx` currently imports `api` and contains network-coupled components (`FindingAcceptForm`, `FindingRevokeButton`, `FindingRecordDetail`, `FindingsTable`). This increases the load cost for every page that imports `@/components/ui` and couples the UI layer to the data layer.

**Proposed solution:** Move the finding-specific components to a dedicated module (e.g. `frontend/src/components/findings.tsx` or `components/findings/index.tsx`). Update import sites in `RepoScans.tsx`, `Scans.tsx`, `HostDetail.tsx`, and the test file. `ui.tsx` then has no direct `api` dependency and remains a pure presentational layer.

**Note (2026-08-22):** `Vulnerabilities.tsx` (a prior import site) was removed by the ui-overhaul branch; `Scans.tsx` (new in that branch) is now an import site instead — file list below updated accordingly.

**Files affected:** new `frontend/src/components/findings.tsx`, `frontend/src/components/ui.tsx` (remove finding components and `api` import), `frontend/src/pages/RepoScans.tsx`, `frontend/src/pages/Scans.tsx`, `frontend/src/pages/HostDetail.tsx`, `frontend/src/test/findingsTable.test.tsx`.

**Trigger:** When the bundle size becomes a concern or when adding further feature-specific components to ui.tsx would compound the problem.

---

### Open scan issues (failing → resolved lifecycle)

When a host project or repo scan produces findings or errors, it should open an **issue** for that project. A subsequent clean scan for the same project closes any open issues. This mirrors how monitoring systems handle alert state (firing → resolved).

**Scope:**

- A new `scan_issues` table tracking open issues per scan key
- **Host scan key:** `(host_id, project_path)` — a clean scan for the same host+path resolves all open issues for that key
- **Repo scan key:** `repo_scan_id` (the scan definition) — a clean result resolves open issues for that repo scan
- **Opens on:** `status = 'findings'` or `status = 'error'`
- **Closes on:** `status = 'clean'` for the same key
- An issue records: scan key, first failing scan reference, finding count at open time, opened_at, resolved_at, resolved_by_scan reference
- Resolution should optionally fire a notification through the existing SMTP/alert system
- Frontend: an "Open issues" view (or badge on Dashboard) showing which projects are currently failing, since when, and finding count

**Files affected:** `backend/app/models/__init__.py`, new migration, `backend/app/api/ingest.py` (open/close logic on scan ingest), new `backend/app/api/issues.py` endpoint, `frontend/src/lib/api.ts`, new frontend page or dashboard widget.

---

### Dashboard exposure-history endpoint's remaining cost scales with open-finding count

**Resolved (2026-08-23):** the original version of this entry — `GET
/dashboard/exposure-history` fetching every `FindingRecord` ever created,
with no scan or date bound — is fixed. The query is now filtered by
`could_contribute_to_exposure_window_sql_expr(window_start)`
(`backend/app/services/finding_lifecycle.py`): a record closed before the
requested window even starts is excluded before it's loaded, since it can
never contribute to any day in that window. The acceptance-events fetch
(`load_finding_acceptance_events`) naturally inherits the same bound, since
it only ever queries events for the record IDs already selected.

**What's left:** the query is bounded by *open-or-recently-closed* finding
count, not by total historical count — which is a real improvement, but
still unbounded in its own right. A fleet with a very large number of
simultaneously open findings (across all repo scans, since this endpoint
has no per-scan scope) still loads all of them into Python and iterates
`window_days` times per record in `compute_exposure_history`. This is a
narrower, more defensible cost than before, not a fully bounded one.

**Proposed fix (preferred direction):** move the computation out of the
request path entirely. Have the scheduler (`backend/app/scheduler/main.py`'s
poll loop, alongside `recover_stuck_scans`/`prune_old_results`/
`run_one_tick`) precompute and persist each day's exposure point(s) once
per interval, and have `GET /dashboard/exposure-history` (and the per-scan
variant) just read the precomputed rows back for the requested window.
Today the cost is paid on every dashboard poll (every 30s) for every
concurrently viewing user — with many simultaneous dashboard viewers, that
duplicated recomputation is the part that gets heavy fastest, independent
of open-finding volume. A scheduler-side job amortizes it to once per poll
interval regardless of viewer count.

Needs its own design pass before implementation: a new table (or columns)
to store precomputed daily points per scan (and fleet-wide for the
dashboard-wide endpoint), how "today" is handled when it's still partial
and changing intraday, backfill for the existing window on first deploy,
and whether acceptance/revoke actions should trigger an incremental
recompute of just the affected day(s) rather than waiting for the next
scheduler tick.

**Files affected:** `backend/app/scheduler/scheduler.py` (new periodic
job), `backend/app/scheduler/main.py` (wire it into the poll loop),
`backend/app/models/__init__.py` (new table), a new migration,
`backend/app/api/dashboard.py`, `backend/app/api/repo_scans.py`
(read precomputed rows instead of recomputing), `backend/app/services/finding_lifecycle.py`.

**Trigger:** When either open-finding volume or concurrent dashboard
viewer count makes the exposure-history request visibly slow — the latter
is not addressed by the existing SQL-filter fix at all, since that only
bounds the query per request, not the number of requests.

---

### Test suite can silently migrate the real dev database

`backend/app/main.py` auto-runs `alembic upgrade head` on startup. Any test
that boots the actual FastAPI app (rather than a fully isolated test DB) can
migrate/stamp `backend/pa_central.db` — the real dev database — as a side
effect, even though nobody explicitly ran Alembic against it. This already
caused one incident (2026-08-22, acceptance-history migration task): the dev
DB ended up stamped to a new revision without the corresponding schema
change actually applied, requiring manual recovery (backup, reset
`alembic_version` to the prior revision, re-run `upgrade head` properly).

**Proposed fix:** Either gate the startup auto-migration behind an explicit
flag/env var so test runs never trigger it implicitly, or ensure every test
that boots the app is forced onto an isolated database regardless of how it
constructs the app instance.

**Files affected:** `backend/app/main.py`, test fixtures that construct the
FastAPI app.

**Trigger:** Before the next migration-related task, to avoid repeating the
same manual-recovery incident.

---

### Dialog stack for nested Escape handling

`useDialogAccessibility` in `ui.tsx` registers a `keydown` capture listener on `document`. `stopImmediatePropagation()` prevents sibling dialogs from firing, but if two dialogs are nested (e.g., a Modal opened from inside a Drawer), the first-registered listener wins — which is the *outer* dialog, not the topmost one. The wrong dialog would close on Escape.

**Current state:** No nested dialogs exist today (Modals and Drawers are always siblings, never parent/child), so this is not a live bug.

**Proposed fix when nesting is introduced:** Maintain a module-level dialog stack in `ui.tsx`. Each `useDialogAccessibility` call pushes an `onClose` reference onto the stack on mount and pops it on unmount. The single shared document listener (or the overlay element's own listener) calls only the topmost entry. This is O(1) per keydown and avoids the capture-order race entirely.

**Alternative:** Attach the Escape listener to the overlay/panel element rather than `document` so the DOM event path naturally routes to the deepest rendered dialog first (bubbling order). Requires the panel to be focusable or always contain focus — already true with the current focus-trap logic.

**Files affected:** `frontend/src/components/ui.tsx` (`useDialogAccessibility`, `Modal`, `Drawer`). No backend changes.

**Trigger:** When the first nested dialog pattern is introduced (e.g., a confirmation Modal inside a Drawer).

---

### Host scans (`Scan`) have no retention and no delete endpoint

Unlike `RepoScanResult` (governed by `scan_result_retention_days`/`scan_result_retention_count`, purged in `prune_old_results`) and `FindingRecord`/`RiskRecord` (governed by `finding_retention_days`), the `Scan` model — host-agent-submitted scan history, one row per `pa` CLI submission — has no retention mechanism at all. The only way a `Scan` row is ever deleted today is `ondelete="CASCADE"` on `host_id` when the owning `Host` itself is deleted (`DELETE /hosts/{id}`); short of deleting the whole host, scan history accumulates forever. There's also no way to delete an individual scan — no `DELETE /scans/{id}` exists, so an admin or the host's owner has no way to remove a single bad/duplicate/test submission without deleting the entire host.

This table is already the one place in the codebase that needed a dedicated composite index (`ix_scans_host_project_scanned_received_id`) and a SQL-side `row_number()` ranking just to answer "what's this host's latest scan per project" — see `GET /hosts/{id}/latest-scans`. Unbounded growth here is a real, already-demonstrated cost, not a hypothetical one.

**Proposed solution:**
- **Retention:** add `scan_retention_days`/`scan_retention_count` settings (or reuse the existing `scan_result_retention_*` keys/semantics, since the age/count-based purge logic in `prune_old_results` for `RepoScanResult` is directly analogous) and a new purge step for `Scan`, most naturally per `(host_id, project_path)` for the count-based variant, mirroring `RepoScanResult`'s per-`repo_scan_id` count purge.
- **Delete endpoint:** `DELETE /scans/{id}`, following the exact ownership pattern already used by `GET /hosts/{id}/latest-scans` and `PATCH /hosts/{id}` — allowed for `UserRole.admin` or the scan's host's `owner_user_id == user.id`, 404 (not 403) otherwise to avoid confirming the scan's existence to a non-owner. Needs its own authorization tests per this project's standing rule (401/403/200 cases) — see `backend/tests/test_auth_gaps.py` or a dedicated test file.
- Confirm neither change touches `backend/app/api/scans.py`'s existing `GET /scans`/`GET /scans/{id}` shape — those are the package-alert CLI's protected, must-not-change surface. A new `DELETE /scans/{id}` on the same router is additive and should be safe, but verify against the `pa` CLI source before shipping, per this project's standing package-alert-API-care rule.

**Files affected:** `backend/app/scheduler/scheduler.py` (new purge step), `backend/app/api/system_settings.py` (new setting keys, if not reusing `scan_result_retention_*`), `backend/app/api/scans.py` (new `DELETE /scans/{id}`), `backend/tests/test_scheduler.py`, `backend/tests/test_scans.py`, `backend/tests/test_auth_gaps.py`, `frontend/src/lib/api.ts` (delete method), `frontend/src/pages/HostDetail.tsx` (delete action on a scan row).

**Trigger:** When host-agent scan history volume becomes a storage or query-performance concern, or when an admin/owner first needs to remove an individual bad scan submission without deleting the whole host.
