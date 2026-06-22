# PA Central — Claude Instructions

## Full-stack consistency rule

Whenever a backend change affects any of the following, the corresponding
frontend code **must** be updated in the same session before the task is
considered complete:

- API response shapes (`schemas/__init__.py` → `frontend/src/lib/api.ts` interfaces)
- Enum values (`models/__init__.py` enums → `api.ts` union types and any badge/colour maps in `components/ui.tsx`)
- New or removed endpoints (`api/*.py` → `api.ts` `api.*` methods)
- Field renames or additions on any model exposed to the frontend

After making backend changes, explicitly grep the frontend for affected type
names and verify TypeScript compiles cleanly (`npx tsc --noEmit` from
`frontend/`).

## Ruff

After all changes to Python files, run:

```bash
cd backend && .venv/bin/ruff check .
```

Fix every issue before considering the task complete. Auto-fix where safe (`--fix`), then resolve remaining issues manually.

## Unused imports

After editing any Python or TypeScript/TSX file, check that no names from
newly-touched import lines are unused. Remove any that are.

- **Python**: targets Ruff F401. Quick check: `grep -n "^from\|^import" <file>`
  then confirm each imported name appears in the file body.
- **TypeScript**: verify with `npx tsc --noEmit` from `frontend/`. Also grep
  the edited file to confirm each imported name is referenced outside its
  import line.

## AWS tests must use LocalStack

Any test that exercises a code path touching AWS (Secrets Manager, ECS, or any
other AWS service) must be routed through LocalStack, never real AWS.

**Pattern:**

1. Use the `localstack` fixture from `tests/conftest_aws.py` (session-scoped;
   skips automatically if LocalStack CLI is not installed).
2. Monkeypatch `app_settings.aws_endpoint_url` to the LocalStack URL so
   `_sm()` and other client factories pick it up:

```python
@pytest.fixture(autouse=True)
def use_localstack(localstack, monkeypatch):
    monkeypatch.setattr(app_settings, "aws_endpoint_url", localstack)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
```

3. Any new AWS client factory (like `_sm()` in `repo_credentials.py`) must
   accept `endpoint_url` from `app_settings.aws_endpoint_url` so LocalStack
   can be injected without further code changes.

Never use `local_docker_scan=True` or other app-level workarounds as a
substitute for proper LocalStack isolation.

## SQLAlchemy column comparisons

Use SQLAlchemy's column methods for all comparisons inside `.where()` clauses —
never Python's `==`, `!=`, or `is` operators directly against literal values:

| Instead of              | Use                        |
|-------------------------|----------------------------|
| `Col == True`           | `Col.is_(True)`            |
| `Col == False`          | `Col.is_(False)`           |
| `Col == None`           | `Col.is_(None)`            |
| `Col != None`           | `Col.isnot(None)`          |

`== True` / `== False` trigger Ruff E712; `== None` / `!= None` bypass
SQLAlchemy's NULL-safe `IS` / `IS NOT` translation and can produce incorrect
SQL in edge cases.

## package-alert version bumps

When upgrading `package-alert` in `backend/pyproject.toml`, work through this
checklist before considering the upgrade done:

- [ ] **Exclusion pairs** — run `pa scan-project --help` and compare against
  `_ALL_KNOWN_EXCLUSIONS` in `backend/app/services/scan_options.py`. Add any
  new mutually-exclusive flag pairs.

- [ ] **Excluded params** — check `_EXCLUDED_PARAMS` in the same file. If the
  new version adds flags whose names collide with `path`, `format`, `fmt`,
  `details`, or `config` (or adds new dangerous overrides), extend the set.

- [ ] **Scan options shape** — run the backend and call `GET /api/repo-scans/scan-options`.
  Verify the returned flags and exclusions look correct. New flags should appear;
  removed flags should be gone.

- [ ] **`ScanFlag.type` classifications** — for any new `str`-typed option,
  confirm it is classified as `"str"` (not `"bool"`) in the response. The
  classifier in `get_scan_options()` uses `is_flag` to distinguish presence
  flags from value flags; a new value-bearing option with a misleading
  `is_flag=True` attribute would be misclassified.

- [ ] **Config lint** — check `AppConfig` in the new version for added or
  renamed top-level or sub-section keys. Update `_OVERLAY_IGNORED_TOP`,
  `_OVERLAY_IGNORED_PLUGINS`, or the known-key allowlist in
  `backend/app/services/config_lint.py` if needed.

- [ ] **scan_task Docker image** — `docker/scan_task/scan_task.py` installs
  `package-alert` at runtime via pip. Verify the new version's `pa scan-project`
  still exits 0 on clean repos and 1 when findings are found (non-zero exit
  codes other than 1 are treated as hard failures).

- [ ] **Backend tests** — run `cd backend && .venv/bin/pytest` and confirm all
  scan-options and config-lint tests still pass.

## Authorization tests

Every new API endpoint must have authorization tests covering:

- Unauthenticated requests return 401
- Roles that lack permission return 403
- Roles that have permission return the expected success status

Add these to `backend/tests/test_auth_gaps.py` (or a dedicated file for the
resource) before the task is considered complete.
