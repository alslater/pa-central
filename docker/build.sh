#!/usr/bin/env bash
# Build the PA Central Docker image, pinning uv to the version in pyproject.toml.
# The frontend is built inside the Dockerfile (multi-stage) — no pre-build required.
set -euo pipefail

UV_VERSION=$(grep 'required-version' backend/pyproject.toml | sed 's/.*>=\([0-9.]*\).*/\1/')
echo "Building with uv ${UV_VERSION}"
docker build --build-arg UV_VERSION="${UV_VERSION}" -t pa-central "$@" .
