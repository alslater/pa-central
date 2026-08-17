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

## Dialect-divergent code needs a PostgreSQL test

The suite runs on SQLite; production runs on PostgreSQL. Whenever you add or
change functionality that behaves differently across the two, add a test to
`backend/tests/test_postgres_behaviour.py` (runtime behaviour) or
`test_postgres_migrations.py` (schema/DDL). A SQLite-only test cannot catch
these, and several such bugs have shipped looking perfectly green.

**Every new Alembic migration must be exercised against PostgreSQL**, whether
or not it looks dialect-specific. `test_upgrade_head_succeeds` already runs
`upgrade head`, so a new revision is smoke-tested for free — but that is the
only part that keeps up automatically. When a migration adds or alters schema,
also update `backend/tests/test_postgres_migrations.py`:

- add new `(table, column) -> ondelete` entries to `EXPECTED_ONDELETE`; the
  constraint-count and action assertions only inspect tables listed there, so
  a new table is otherwise silently unchecked
- if the migration is a new head, check whether `BASE_REVISION` still names the
  revision the downgrade tests should unwind to
- run the downgrade against a database holding *representative data*, not an
  empty one. A downgrade that restores `NOT NULL` or narrows a type passes
  trivially on empty tables and fails in production.

Do not assume a migration is dialect-neutral because it uses ORM constructs:
`batch_alter_table` rebuilds the table on SQLite but emits `ALTER TABLE` on
PostgreSQL, and that difference has already shipped a bug that looked green on
SQLite.

**Never run Alembic against the default database configuration when experimenting.**
`backend/pa_central.db` is real dev data, and a throwaway revision stamps its
`alembic_version` table. Deleting the migration file afterwards then leaves the
database pointing at a revision that no longer exists, and startup dies with
`Can't locate revision identified by '<rev>'`. Always pass an explicit
throwaway target:

```bash
DATABASE_TYPE=sqlite DATABASE_NAME=/tmp/scratch.db .venv/bin/alembic upgrade head
```

To recover a database stranded this way: drop whatever the revision created,
then `UPDATE alembic_version SET version_num = '<real head>'`.

**This rule also applies when you:**

- branch on the dialect (`if is_postgres:`, `bind.dialect.name == "sqlite"`)
- use a Postgres-only feature (advisory locks, `JSONB`, `ILIKE`, `ON CONFLICT`,
  partial indexes, `RETURNING`)
- write raw DDL or SQL via `op.execute` / `sa.text` instead of ORM constructs
- add or change a FK `ondelete`/`onupdate` action — batch migrations rebuild
  the table on SQLite but emit `ALTER TABLE` on PostgreSQL, and `copy_from` is
  ignored there, so a constraint can silently end up duplicated
- add a `TypeDecorator` or custom type whose job is papering over a SQLite
  limitation (see `UtcDateTime`)
- rely on constraint enforcement at all — SQLite ignores FK actions unless
  `PRAGMA foreign_keys` is on for that connection

**Pattern:** use the `postgres_url` fixture from `tests/conftest_postgres.py`.
It provisions a throwaway database per test and skips automatically when
neither Docker nor `PA_TEST_POSTGRES_URL` is set, so the suite stays green in
environments without them.

```python
def test_something_postgres_specific(postgres_url):
    assert alembic(postgres_url, "upgrade", "head").returncode == 0
    # ... assert against pg_constraint / pg_indexes, or exercise the behaviour
```

Point `PA_TEST_POSTGRES_URL` at an existing server to skip the container.

**Verify the test earns its place:** break the behaviour it covers and confirm
it fails. A dialect test that passes against the broken code is worse than
none — it implies coverage that does not exist.

Do *not* add PostgreSQL variants of dialect-neutral tests (auth, RBAC, request
validation, serialisation). They double the runtime and catch nothing.

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

## API handler return annotations

Every `@router.*` handler must have an explicit return type annotation. It
should match the decorator's `response_model`:

```python
@router.get("", response_model=list[UserOut])
async def list_users(db: DbDep, _: AdminDep) -> list[UserOut]:
    ...
```

Rules for the cases that aren't a plain `response_model`:

| Handler shape | Annotation |
|--------------------------------------------|------------------------------|
| `response_model=X` | `-> X` |
| `status_code=204` with bare/no `return` | `-> None` |
| Returns a `Response` subclass directly | `-> Response` (or the subclass, e.g. `PlainTextResponse`) |
| Returns one of several schemas | `-> A \| B` |
| Returns a plain dict | `-> dict[str, bool]` (or the actual shape) |

Handlers that return ORM rows still annotate the schema type (`-> UserOut`,
not `-> User`) — FastAPI serialises through `response_model`, and this matches
FastAPI's own documented convention.

Annotating a handler that previously had none will add its schema to the
OpenAPI docs where it was `{}` before. That's the point, but diff
`app.openapi()` before/after if the endpoint is consumed by the frontend, and
mirror any resulting shape change into `frontend/src/lib/api.ts` per the
full-stack consistency rule above.

To find gaps: grep for handlers whose `def` line ends in `):` rather than
`) -> ...:`.

## Authorization tests

Every new API endpoint must have authorization tests covering:

- Unauthenticated requests return 401
- Roles that lack permission return 403
- Roles that have permission return the expected success status

Add these to `backend/tests/test_auth_gaps.py` (or a dedicated file for the
resource) before the task is considered complete.
