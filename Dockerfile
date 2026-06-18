# uv version comes from required-version in backend/pyproject.toml, passed via docker/build.sh
ARG UV_VERSION=0.11.18
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ── Stage 1: build frontend ───────────────────────────────────────────────────
FROM node:24-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Install uv
COPY --from=uv /uv /usr/local/bin/uv
ENV PATH="/app/.venv/bin:$PATH"

# Install dependencies via uv (no-dev for production image)
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --no-dev --frozen

# Copy backend
COPY backend/ .

# Copy pre-built frontend from stage 1
COPY --from=frontend-build /app/frontend/dist/ frontend/dist/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
