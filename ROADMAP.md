# PA Central — Roadmap

## Planned

### Redis Pub/Sub for SSE alert broadcasting

`_sse_queues` in `backend/app/api/alerts.py` is an in-process set, so the live alert stream (`GET /alerts/stream`) only works correctly with a single worker process. Multiple uvicorn workers or container replicas each maintain independent queues, meaning clients miss alerts ingested by a different worker.

**Proposed solution:** Replace the in-process set with Redis Pub/Sub. The ingest endpoint publishes new alerts to a Redis channel; each worker subscribes and fans out to its local SSE clients.

**Files affected:** `backend/app/api/alerts.py`, likely a new `backend/app/core/pubsub.py`, and deployment config to add a Redis service.

---

### Short-lived public ID tokens via Redis (ID enumeration hardening)

Sequential integer PKs exposed in API responses allow enumeration — an authenticated user who can access `/api/hosts/1` can trivially probe 2, 3, 4... Defence-in-depth on top of (not a substitute for) proper per-endpoint authorisation.

**Approach:** Keep integer PKs for all internal DB operations. When serialising a response, map each exposed resource ID to a short-lived random token stored in Redis; resolve it back to the integer PK before any DB access.

**Design decisions:**
- Token format: `secrets.token_urlsafe(16)`. TTL 15–30 min, sliding.
- Scope: only IDs used as route/query params — `host_id`, `scan_id`, `alert_id`, `repo_scan_id`, `result_id`, `api_key_id`, `user_id`.
- Failure mode: if Redis is unavailable, fail closed (401/503) rather than falling back to raw integer IDs.
- Store shape: `token:{token} → {resource_type}:{integer_id}` with TTL, optionally `id:{resource_type}:{integer_id} → token` to avoid token explosion on repeated fetches of the same resource.

**Frontend:** any page holding a resource ID in state for longer than the TTL needs a refresh strategy (re-fetch interval, or a `GET /api/tokens/refresh` batch-refresh endpoint). `api.ts` should retry a 404 on a token-keyed request by re-fetching the parent list, not surface a hard error.

**Prerequisite:** Redis/Valkey as a hard dependency (shared with the SSE item above).

**Files affected:** new `backend/app/core/id_tokens.py`, `backend/app/api/deps.py`, all route handlers taking an ID path param, `backend/app/schemas/__init__.py`, `frontend/src/lib/api.ts`, any page component holding a selected resource ID.

---

### Pagination for `GET /repo-scans/{id}/findings`

`Scans.tsx` fetches every open finding for one scan via `GET /repo-scans/{id}/findings` (`get_repo_scan_findings` in `backend/app/api/repo_scans.py`) with no pagination and no row cap. (`GET /findings` already has full server-side pagination, but no current frontend view calls it — that endpoint is otherwise unaffected by this item.)

**Proposed solution:** Add pagination to `GET /repo-scans/{id}/findings` and the sibling `/risks` endpoint, and update `Scans.tsx`'s `RecordTabs`/`FindingsTable` consumption accordingly.

**Files affected:** `backend/app/api/repo_scans.py` (`get_repo_scan_findings`, `get_repo_scan_risks`), `frontend/src/lib/api.ts` (`listAllForRepo`), `frontend/src/pages/Scans.tsx`.

**Trigger:** When a single repo scan's finding count makes `Scans.tsx` visibly slow to expand.

---

### Clickable table rows — accessibility refinement

`FindingsTable`, `RisksTable`, `FindingRecordsTable`, `RiskRecordsTable` (`frontend/src/components/ui.tsx`) use `role="button"` + `tabIndex` on `<tr>` elements to make rows open a detail drawer. Works, but is semantically impure — some screen readers treat `<tr role="button">` inconsistently.

**Preferred alternative:** Move the interactive affordance to a dedicated "View" `<button>` inside a `<td>`, keeping the row purely tabular. Deferred as a layout change (adds a button column) until there's appetite for the UI churn.

**Files affected:** `frontend/src/components/ui.tsx` (all four table components).

---

### Extract finding components out of ui.tsx

`ui.tsx` imports `api` and contains network-coupled components (`FindingAcceptForm`, `FindingRevokeButton`, `FindingRecordDetail`, `FindingsTable`), increasing load cost for every page importing `@/components/ui` and coupling the UI layer to the data layer.

**Proposed solution:** Move finding-specific components to a dedicated module (e.g. `frontend/src/components/findings.tsx`). Update import sites in `RepoScans.tsx`, `Scans.tsx`, `HostDetail.tsx`, and the test file. `ui.tsx` then has no `api` dependency.

**Files affected:** new `frontend/src/components/findings.tsx`, `frontend/src/components/ui.tsx`, `frontend/src/pages/RepoScans.tsx`, `frontend/src/pages/Scans.tsx`, `frontend/src/pages/HostDetail.tsx`, `frontend/src/test/findingsTable.test.tsx`.

**Trigger:** When bundle size becomes a concern, or adding further feature-specific components to `ui.tsx` would compound the problem.

---

### Open scan issues (failing → resolved lifecycle)

When a host project or repo scan produces findings or errors, open an **issue** for that project; a subsequent clean scan closes any open issues. Mirrors monitoring-system alert state (firing → resolved).

**Scope:**
- New `scan_issues` table tracking open issues per scan key.
- Host scan key: `(host_id, project_path)`. Repo scan key: `repo_scan_id`.
- Opens on `status = 'findings'` or `'error'`; closes on `status = 'clean'` for the same key.
- An issue records: scan key, first failing scan reference, finding count at open time, opened_at, resolved_at, resolved_by_scan reference.
- Resolution should optionally fire a notification through the existing SMTP/alert system.
- Frontend: an "Open issues" view or Dashboard badge showing which projects are currently failing, since when, and finding count.

**Files affected:** `backend/app/models/__init__.py`, new migration, `backend/app/api/ingest.py`, new `backend/app/api/issues.py`, `frontend/src/lib/api.ts`, new frontend page or dashboard widget.

---

### Precompute dashboard exposure-history instead of computing it per request

`GET /dashboard/exposure-history` is now bounded per request (filtered by open-or-recently-closed finding count, not the whole table), but every concurrently-viewing user still triggers the same recomputation on every poll (every 30s). With many simultaneous dashboard viewers, that duplicated work is the part that gets heavy fastest, independent of finding volume.

**Proposed solution:** Have the scheduler precompute and persist each day's exposure point(s) once per poll interval; have the endpoint (and its per-scan variant) just read the precomputed rows back.

Needs its own design pass: a new table/columns for precomputed daily points, how "today" is handled while still partial/changing intraday, backfill on first deploy, and whether accept/revoke actions should trigger an incremental recompute of the affected day(s) rather than waiting for the next tick.

**Files affected:** `backend/app/scheduler/scheduler.py`, `backend/app/scheduler/main.py`, `backend/app/models/__init__.py`, new migration, `backend/app/api/dashboard.py`, `backend/app/api/repo_scans.py`, `backend/app/services/finding_lifecycle.py`.

**Trigger:** When open-finding volume or concurrent dashboard viewer count makes the request visibly slow.

---

### Gate the startup auto-migration in test runs

`backend/app/main.py` auto-runs `alembic upgrade head` on startup. Any test that boots the actual FastAPI app rather than a fully isolated test DB can migrate/stamp `backend/pa_central.db` — the real dev database — as an unintended side effect.

**Proposed fix:** Either gate the startup auto-migration behind an explicit flag/env var so test runs never trigger it implicitly, or force every test that boots the app onto an isolated database regardless of how it constructs the app instance.

**Files affected:** `backend/app/main.py`, test fixtures that construct the FastAPI app.

---

### Dialog stack for nested Escape handling

`useDialogAccessibility` in `ui.tsx` registers a `keydown` capture listener on `document`; with two nested dialogs, the first-registered (outer) listener wins on Escape, not the topmost one. No nested dialogs exist today, so this is not a live bug.

**Proposed fix when nesting is introduced:** Maintain a module-level dialog stack — each `useDialogAccessibility` call pushes/pops its `onClose` reference, and the shared listener calls only the topmost entry.

**Alternative:** Attach the Escape listener to the overlay/panel element rather than `document`, so DOM bubbling naturally routes to the deepest rendered dialog first.

**Files affected:** `frontend/src/components/ui.tsx` (`useDialogAccessibility`, `Modal`, `Drawer`).

**Trigger:** When the first nested dialog pattern is introduced.

---

### Host scans (`Scan`) have no retention and no delete endpoint

Unlike `RepoScanResult`/`FindingRecord`/`RiskRecord`, the `Scan` model (host-agent-submitted scan history) has no retention mechanism — rows are only ever removed via `ondelete="CASCADE"` when the owning `Host` is deleted. There's also no `DELETE /scans/{id}` for removing an individual bad/duplicate submission.

**Proposed solution:**
- **Retention:** add `scan_retention_days`/`scan_retention_count` settings (or reuse `scan_result_retention_*` semantics) and a purge step, per `(host_id, project_path)` for the count-based variant.
- **Delete endpoint:** `DELETE /scans/{id}`, following the ownership pattern already used by `GET /hosts/{id}/latest-scans`/`PATCH /hosts/{id}` (admin or the host's `owner_user_id`; 404 not 403 for non-owners). Needs authorization tests per the standing 401/403/200 rule.
- Verify a new `DELETE /scans/{id}` doesn't touch `GET /scans`/`GET /scans/{id}`'s existing shape — those are the package-alert CLI's protected surface; check against the CLI source before shipping.

**Files affected:** `backend/app/scheduler/scheduler.py`, `backend/app/api/system_settings.py`, `backend/app/api/scans.py`, `backend/tests/test_scheduler.py`, `backend/tests/test_scans.py`, `backend/tests/test_auth_gaps.py`, `frontend/src/lib/api.ts`, `frontend/src/pages/HostDetail.tsx`.

**Trigger:** When host-agent scan history volume becomes a storage/query concern, or an admin/owner needs to remove an individual bad scan submission.

---

### `must_change_password` on admin-generated passwords

Open design question: should an admin-generated password (the non-SMTP fallback when self-service reset is off) force a password change at next login? Not resolved by the self-service-reset work — self-service reset itself already ends with the user choosing their own password, so this only matters for the fallback path.

**Trigger:** If the non-SMTP fallback path stays in active use.

---

### SQLite ignores `FOR UPDATE` in findings/risks accept/revoke

The four `with_for_update=True` call sites in `api/findings.py` and `api/risks.py` (accept/revoke) are inert on SQLite, this project's default database — acknowledged in their own code comments. Consequence: accept/revoke ordering can diverge from the replayed event history under concurrency — a data-consistency issue, not a reusable-credential one (contrast the password-reset token claim, which needed a real fix for the same class of gap).

**Proposed fix:** Replace the locking read with a single atomic conditional `UPDATE`, following the pattern already used for password-reset token consumption.

**Trigger:** If SQLite stays the default for multi-worker deployments.
