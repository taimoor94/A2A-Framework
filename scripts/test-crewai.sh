#!/usr/bin/env bash
# Run the CrewAI adapter tests in their own environment. Run from anywhere:
#
#   scripts/test-crewai.sh               # tests/adapters/test_crewai.py
#   scripts/test-crewai.sh -k cancel     # extra arguments go to pytest
#
# crewai pins mcp<2 and openai<3, so it cannot share the dev environment (mcp>=2.3,
# openai-agents). The `crewai-test` dependency group (pytest, pytest-asyncio, crewai) is
# declared conflicting with the dev group and the mcp/openai/adk/all extras in pyproject.toml,
# and is installed into its own virtualenv, .venv-crewai (git-ignored), from the same uv.lock:
# the main .venv is never re-synced.
#
# Network: the first run (or CREWAI_TEST_ONLINE=1) checks uv.lock against pyproject.toml
# (`uv lock --check`) and syncs .venv-crewai online. After a successful sync a marker file
# records the uv.lock it was synced from; while the marker matches, runs are offline
# (--offline: nothing is resolved or downloaded), and the lock check uses uv's cache only.
#
# A2AGW_CREWAI_TESTS=1 makes test_crewai.py fail, instead of skip, if crewai is missing, so
# this script can never pass by testing nothing. CrewAI telemetry and tracing are off, and
# CrewAI writes nothing under the real home: HOME, XDG_CONFIG_HOME, XDG_DATA_HOME and
# CREWAI_STORAGE_DIR point into a temporary directory (removed on exit).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

VENV="${ROOT}/.venv-crewai"
MARKER="${VENV}/.a2agw-crewai-synced"  # holds the uv.lock digest the env was synced from
export UV_PROJECT_ENVIRONMENT="${VENV}"
# uv's cache lives under HOME by default: pin it before HOME moves.
export UV_CACHE_DIR="${UV_CACHE_DIR:-$(uv cache dir)}"

lock_digest() { shasum -a 256 uv.lock | cut -d' ' -f1; }

OFFLINE=()
if [ -z "${CREWAI_TEST_ONLINE:-}" ] && [ -f "${MARKER}" ] \
  && [ "$(cat "${MARKER}")" = "$(lock_digest)" ]; then
  OFFLINE=(--offline)
fi

if ! uv lock --check ${OFFLINE[@]+"${OFFLINE[@]}"} >/dev/null 2>&1; then
  if [ ${#OFFLINE[@]} -gt 0 ]; then
    echo "crewai tests: uv.lock does not match pyproject.toml, or could not be checked offline" \
      "(uv's cache lacks some metadata). Run 'uv lock', or rerun with CREWAI_TEST_ONLINE=1." >&2
  else
    echo "crewai tests: uv.lock does not match pyproject.toml: run 'uv lock' first." >&2
  fi
  exit 1
fi

if [ ${#OFFLINE[@]} -eq 0 ]; then
  rm -f "${MARKER}"
  uv sync --frozen --no-default-groups --group crewai-test
  lock_digest > "${MARKER}"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
export A2AGW_REAL_HOME="${HOME}"  # the tests check that nothing new appears under it
export HOME="${TMP}/home"
export XDG_CONFIG_HOME="${HOME}/.config"
export XDG_DATA_HOME="${HOME}/.local/share"
export CREWAI_STORAGE_DIR="${TMP}/crewai-storage"  # absolute
mkdir -p "${XDG_CONFIG_HOME}" "${XDG_DATA_HOME}" "${CREWAI_STORAGE_DIR}"
export A2AGW_CREWAI_TESTS=1
export CREWAI_DISABLE_TELEMETRY=true
export CREWAI_DISABLE_TRACKING=true
export CREWAI_TRACING_ENABLED=false
export OTEL_SDK_DISABLED=true

LOG="${TMP}/pytest.log"
set +e
uv run --frozen --no-sync --no-default-groups --group crewai-test --offline \
  pytest tests/adapters/test_crewai.py -q -W error -p no:randomly -p no:cacheprovider "$@" \
  2>&1 | tee "${LOG}"
status=${PIPESTATUS[0]}
set -e

summary="$(grep -E '^[=]* ?[0-9]+ (passed|failed|error)' "${LOG}" | tail -1 || true)"
passed="$(printf '%s' "${summary}" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo 0)"
echo "crewai tests: ${passed} passed (pytest exit ${status})"
if [ "${status}" -eq 0 ] && [ "${passed}" -eq 0 ]; then
  echo "crewai tests: nothing passed" >&2
  exit 1
fi
exit "${status}"
