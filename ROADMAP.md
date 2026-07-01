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

### Server-side pagination and sorting for GET /findings

Currently `GET /findings` fetches up to 500 records and sorting/paging is done client-side in the Vulnerabilities page. This is fine at low finding volumes but will become slow and bandwidth-heavy as findings grow.

**Proposed solution:** Add `page`, `page_size`, `sort`, and `sort_dir` query params to `GET /findings`. Return total count alongside results (response envelope or `X-Total-Count` header). Replace client-side `useMemo` sort + pagination in `Vulnerabilities.tsx` with server-driven state that refetches on page/sort change.

**Files affected:** `backend/app/api/findings.py`, `backend/app/schemas/__init__.py` (paginated response shape), `frontend/src/lib/api.ts` (`findings.listAll` signature), `frontend/src/pages/Vulnerabilities.tsx` (remove client-side sort/page state, add server-driven refetch).

**Known interim limitation:** When `breach` or `accepted` filtering is active, the endpoint caps the SQL scan at `limit * 10` rows (oldest-first) and filters in Python. If matching rows are sparse in that window, fewer than `limit` results are returned even when more exist further in the dataset. Server-side pagination eliminates this by iterating pages until the result set is full.

**Secondary issue — over-broad age cutoff:** For `breach=true` with no `repo_scan_id`, the pre-filter cutoff uses the minimum effective SLA across *all* scans, not just those with open findings in scope. If any scan has a very strict SLA override (e.g. `sla_high_days=1`), the cutoff becomes 1 day, causing every open finding older than 1 day to pass into Python evaluation — widening the candidate set and increasing the likelihood of hitting the `limit * 10` cap and under-returning results. The correct fix is either (a) compute the minimum SLA only across scans that have open findings matching the current filters (joined query), or (b) move breach evaluation fully server-side as part of pagination. Both require the server-side pagination work to be worthwhile.

**Trigger:** When the 500-row fetch becomes visibly slow, users report the cap, or breach/accepted filters visibly under-return results.

---

### Clickable table rows — accessibility refinement

The Vulnerabilities page uses `role="button"` + `tabIndex` on `<tr>` elements to make rows open a detail drawer. This pattern is widely supported (keyboard nav, `aria-label`, Enter/Space handlers all present) but is semantically impure — some screen readers treat `<tr role="button">` inconsistently.

**Preferred alternative:** Move the interactive affordance to a dedicated "View" `<button>` inside a `<td>`, keeping the row purely tabular. This is a layout change (adds a visible or visually-hidden button column) so it is deferred until there is appetite for the UI churn.

**Files affected:** `frontend/src/pages/Vulnerabilities.tsx`

---

### Extract finding components out of ui.tsx

`ui.tsx` currently imports `api` and contains network-coupled components (`FindingAcceptForm`, `FindingRevokeButton`, `FindingRecordDetail`, `FindingsTable`). This increases the load cost for every page that imports `@/components/ui` and couples the UI layer to the data layer.

**Proposed solution:** Move the finding-specific components to a dedicated module (e.g. `frontend/src/components/findings.tsx` or `components/findings/index.tsx`). Update import sites in `RepoScans.tsx`, `Vulnerabilities.tsx`, `Scans.tsx`, `HostDetail.tsx`, and the test file. `ui.tsx` then has no direct `api` dependency and remains a pure presentational layer.

**Files affected:** new `frontend/src/components/findings.tsx`, `frontend/src/components/ui.tsx` (remove finding components and `api` import), `frontend/src/pages/RepoScans.tsx`, `frontend/src/pages/Vulnerabilities.tsx`, `frontend/src/pages/Scans.tsx`, `frontend/src/pages/HostDetail.tsx`, `frontend/src/test/findingsTable.test.tsx`.

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

### Dialog stack for nested Escape handling

`useDialogAccessibility` in `ui.tsx` registers a `keydown` capture listener on `document`. `stopImmediatePropagation()` prevents sibling dialogs from firing, but if two dialogs are nested (e.g., a Modal opened from inside a Drawer), the first-registered listener wins — which is the *outer* dialog, not the topmost one. The wrong dialog would close on Escape.

**Current state:** No nested dialogs exist today (Modals and Drawers are always siblings, never parent/child), so this is not a live bug.

**Proposed fix when nesting is introduced:** Maintain a module-level dialog stack in `ui.tsx`. Each `useDialogAccessibility` call pushes an `onClose` reference onto the stack on mount and pops it on unmount. The single shared document listener (or the overlay element's own listener) calls only the topmost entry. This is O(1) per keydown and avoids the capture-order race entirely.

**Alternative:** Attach the Escape listener to the overlay/panel element rather than `document` so the DOM event path naturally routes to the deepest rendered dialog first (bubbling order). Requires the panel to be focusable or always contain focus — already true with the current focus-trap logic.

**Files affected:** `frontend/src/components/ui.tsx` (`useDialogAccessibility`, `Modal`, `Drawer`). No backend changes.

**Trigger:** When the first nested dialog pattern is introduced (e.g., a confirmation Modal inside a Drawer).
