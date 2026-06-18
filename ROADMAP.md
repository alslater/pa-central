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
