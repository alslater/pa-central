# PA Central

Central management server for [package-alert](https://github.com/alslater/package-alert) installations.

## What it does

| Feature | Details |
|---------|---------|
| **Fleet health** | Daemon status, uptime, pa version, last-seen per host |
| **Alert aggregation** | All OSV / heuristic / cooldown alerts in one place, with acknowledge workflow |
| **Live alerts** | SSE stream — new alerts appear in the UI instantly, with badge count in sidebar |
| **Scan results** | Per-host project scan history with finding details |
| **Config management** | TOML templates assigned to hosts; agents pull via `GET /api/ingest/config` |
| **Cooldown allowlist** | Fleet-wide or per-host package pre-clearances |
| **API key management** | Per-host keys for agent auth; shown once on creation |
| **User roles** | admin / operator / viewer with appropriate guards throughout |
| **Scheduled repo scans** | Cron-driven vulnerability scans of Git repos; results ingested by an ephemeral task |
| **System settings** | SMTP / email config, scan result retention, app base URL — managed in the UI |

## Architecture

```
pa-central/
├── backend/                FastAPI + SQLAlchemy (async)
│   ├── app/
│   │   ├── api/            Route handlers (auth, hosts, alerts, scans, configs, cooldown, ingest,
│   │   │                                  users, repo_scans, system_settings)
│   │   ├── models/         SQLAlchemy ORM (User, Host, Alert, Scan, ConfigTemplate, ApiKey,
│   │   │                                  CooldownEntry, RepoScan, RepoScanResult, SystemSetting)
│   │   ├── schemas/        Pydantic v2 request/response schemas
│   │   ├── scheduler/      Standalone scheduler service (cron eval, ECS/Docker launch, stuck-job
│   │   │                   recovery, result retention pruning)
│   │   └── core/           Config, Database, Security, encryption (AES-256-GCM), Valkey locks,
│   │                       AWS wrappers (ECS + Secrets Manager), Docker runner, email service
│   └── migrations/         Alembic — run automatically on startup
├── frontend/               React 18 + TypeScript + Vite
│   └── src/
│       ├── pages/          Dashboard, Hosts, HostDetail, Alerts, Scans, Cooldown, Configs,
│       │                   ApiKeys, Users, RepoScans, SystemSettings, Login
│       ├── components/     Shell (sidebar nav + live alert badge), shared UI primitives
│       ├── hooks/          useAuth (JWT context)
│       └── lib/api.ts      Typed API client
├── docker/scan_task/       Ephemeral ECS / local-Docker scan task
│   ├── scan_task.py        Standalone script: installs pa, clones repo, runs scan, POSTs result
│   ├── Dockerfile
│   └── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

## Scheduled repo scanning

PA Central can periodically clone a Git repository, run `pa scan-project`, and ingest the findings. Each scan is executed in an ephemeral container so the fleet server itself never touches the repo.

### How it works

1. A **RepoScan** record holds the repo URL, branch, cron schedule, credential reference, and notification settings.
2. The **scheduler** (`backend/app/scheduler/main.py`) polls the database every 60 seconds, evaluates cron expressions, and launches a task for any scan that is due.
3. The **scan task** (`docker/scan_task/scan_task.py`) runs in its own container. It installs the requested `pa` version, clones the repo, runs `pa scan-project --format json`, and POSTs the result back to `POST /api/ingest/repo-scan-result`.
4. The fleet server stores the result, optionally emails admins/recipients, and releases the dedup lock.

Credentials (SSH keys, HTTPS tokens) are stored in **AWS Secrets Manager** — never in the database. The scan task retrieves them at runtime via the ARN recorded on the RepoScan.

### Production (AWS ECS Fargate)

```env
ECS_CLUSTER_ARN=arn:aws:ecs:us-east-1:123456789:cluster/my-cluster
SCAN_TASK_DEFINITION_ARN=arn:aws:ecs:us-east-1:123456789:task-definition/pa-central-scan:1
SCAN_TASK_SUBNET_IDS=subnet-abc,subnet-def
SCAN_TASK_SECURITY_GROUP_IDS=sg-abc
FLEET_BASE_URL=https://pa-central.example.com
FLEET_SYSTEM_API_KEY=<generate with: python3 -c "import secrets; print(secrets.token_hex(32))">
```

Push the scan task image to ECR and reference it in your task definition.

Run the scheduler as a separate single-replica container/service:

```bash
python -m app.scheduler.main
```

### Development (local Docker)

No AWS account needed. The scan task runs as a local Docker container that calls back to the host.

```bash
# 1. Build the scan task image
docker compose --profile local-scan build scan-task

# 2. Add to backend/.env
LOCAL_DOCKER_SCAN=true
FLEET_SYSTEM_API_KEY=any-dev-key
UVICORN_HOST=0.0.0.0   # required — scan containers reach the server via the Docker bridge
# SCAN_TASK_FLEET_URL defaults to http://host.docker.internal:8000

# 3. Start the fleet server
cd backend && uv run python -m app.main

# 4. Trigger a scan from the Repo Scans page (or via the API)
#    The scan container will POST results back automatically.
```

The "task ARN" stored for local runs is prefixed `local-docker://` so you can tell them apart from ECS runs.

---

## Agent API (called by the package-alert plugin on each host)

All ingest endpoints authenticate with `X-API-Key: <key>` where the key is bound to a specific host.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/ingest/heartbeat` | Report daemon status and uptime |
| `POST` | `/api/ingest/alerts` | Upload a new alert |
| `POST` | `/api/ingest/scans` | Upload scan results (pa scan-project --format json) |
| `GET`  | `/api/ingest/config` | Pull assigned TOML config (200 with body, or 204 if none) |

## Quick start (development)

### Backend

```bash
cd backend
uv sync

cp .env.example .env
# Generate a secure SECRET_KEY:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
# Edit .env: set SECRET_KEY and BOOTSTRAP_ADMIN_PASSWORD

uv run python -m app.main
# → http://localhost:8000
# → http://localhost:8000/api/docs  (Swagger UI)
```

To run scheduled repo scans, start the scheduler in a second terminal:

```bash
cd backend
uv run python -m app.scheduler.main
```

The scheduler polls every 60 seconds and fires any cron-scheduled repo scans that are due. Without it, scheduled scans will not run — manual triggers from the UI still work.

Uvicorn settings (host, port, reload, graceful shutdown timeout) are read from `UVICORN_*` environment variables in `backend/.env` — no CLI flags needed. The defaults in `.env.example` bind to `127.0.0.1`. For local Docker scan mode, set `UVICORN_HOST=0.0.0.0` so scan containers can reach the server via the Docker bridge.

### Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

Login with `admin@localhost` and the password you set in `BOOTSTRAP_ADMIN_PASSWORD`.

> **Tip:** Set `DEBUG=1` in `backend/.env` to skip TOTP entirely during development — the login flow will issue a token immediately without prompting for a second factor.

## Production with Docker

```bash
# Copy and edit env
cp backend/.env.example .env
# Generate a secure SECRET_KEY:
#   python3 -c "import secrets; print(secrets.token_hex(32))"
# Set: SECRET_KEY, BOOTSTRAP_ADMIN_PASSWORD

# Build frontend first
cd frontend && npm install && npm run build && cd ..

# Run (SQLite, single container)
docker compose up -d

# Run with PostgreSQL
POSTGRES_PASSWORD=secret \
DATABASE_URL=postgresql+asyncpg://pa_central:secret@postgres/pa_central \
docker compose --profile pg up -d
```

## Running the tests

### Requirements

| Service | Purpose | Notes |
|---------|---------|-------|
| None (in-memory SQLite) | Core API tests | No setup needed |
| Redis or Valkey on `localhost:6379` | Concurrency / locking tests | Either is compatible |
| LocalStack on `localhost:4566` | AWS service tests (Secrets Manager, ECS) | Managed automatically — see below |

### LocalStack

The test suite checks whether LocalStack is already running before each session. If it is not, it starts it automatically (`localstack start -d`) and stops it when the session ends. If it is already running, it is left running after the tests complete.

LocalStack must be installed:

```bash
pip install localstack
```

### Redis / Valkey

The test suite assumes a Redis-compatible server is available at `localhost:6379`. Tests use a dedicated key prefix and clean up after themselves — the existing keyspace is not affected.

Start one if needed:

```bash
# Redis
docker run -d -p 6379:6379 redis:7

# or Valkey
docker run -d -p 6379:6379 valkey/valkey:8
```

### Running

```bash
cd backend
uv run pytest
```

Run a specific test file:

```bash
uv run pytest tests/test_ingest.py -v
```

---

## Switching databases

Change `DATABASE_URL` in `.env` or the Docker environment:

```env
# SQLite (default — good for small fleets)
DATABASE_URL=sqlite+aiosqlite:///./data/pa_central.db

# PostgreSQL (recommended for production)
DATABASE_URL=postgresql+asyncpg://user:password@localhost/pa_fleet
```

For PostgreSQL: `asyncpg` is already included in the Docker image (via `uv sync --no-dev --frozen`).

## User roles

| Role | Permissions |
|------|-------------|
| `viewer` | Read-only access to everything |
| `operator` | + acknowledge alerts, manage cooldowns, assign configs, create API keys |
| `admin` | + manage users, delete hosts, revoke any API key |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `changeme-...` | JWT signing key — **change this in production** |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/pa_central.db` | Database connection string |
| `BOOTSTRAP_ADMIN_PASSWORD` | *(unset)* | Creates `admin@localhost` on first startup if set |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | Session duration (8 hours) |
| `DEBUG` | `false` | Enables SQLAlchemy query logging **and disables TOTP entirely** — tokens are issued immediately on `POST /auth/login` with no second factor. Never set this in production. |
| `VALKEY_URL` | *(unset)* | Redis/Valkey URL for distributed locks — required for multi-replica deployments |
| `SETTINGS_ENCRYPTION_KEY` | `changeme-...` | AES-256 key for encrypting secret system settings (SMTP password etc.) — **change in production**. Generate with: `python3 -c "import secrets; print(secrets.token_hex(16))"` |
| `FLEET_BASE_URL` | `http://localhost:8000` | Public base URL of this app (used in email links etc.) |
| `FLEET_SYSTEM_API_KEY` | *(unset)* | Pre-shared key authenticating scan tasks and the scheduler |
| `ECS_CLUSTER_ARN` | *(unset)* | ECS cluster to launch scan tasks in |
| `SCAN_TASK_DEFINITION_ARN` | *(unset)* | ECS task definition for the scan task |
| `SCAN_TASK_SUBNET_IDS` | *(unset)* | Comma-separated subnet IDs for ECS Fargate |
| `SCAN_TASK_SECURITY_GROUP_IDS` | *(unset)* | Comma-separated security group IDs for ECS Fargate |
| `LOCAL_DOCKER_SCAN` | `false` | Use local Docker instead of ECS (development) |
| `SCAN_TASK_IMAGE` | `pa-central-scan-task:latest` | Image name for local Docker scan mode |
| `SCAN_TASK_FLEET_URL` | *(unset)* | Fleet URL passed to scan containers in local Docker mode — defaults to `http://host.docker.internal:8000` when unset |
