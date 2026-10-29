#!/usr/bin/env bash
# Run the CrewAI adapter tests in their own environment. Run from anywhere:
#
#   scripts/test-crewai.sh               # tests/adapters/test_crewai.py
#   scripts/test-crewai.sh -k cancel     # extra arguments go to pytest
#
# crewai pins mcp<2 and openai<3, so it cannot share the dev environment (mcp>=2.3,
# openai-agents). The `crewai-test` dependency group (pytest, pytest-asyncio, crewai) is
# declared conflicting with the dev group and the mcp/openai/all extras in pyproject.toml, and
# is installed into its own virtualenv, .venv-crewai (git-ignored), from the same uv.lock: the
# main .venv is never re-synced. Once that virtualenv exists the run is offline (--offline:
# nothing is resolved or downloaded; set CREWAI_TEST_ONLINE=1 to let uv fetch a changed lock).
#
# A2AGW_CREWAI_TESTS=1 makes test_crewai.py fail, instead of skip, if crewai is missing, so
# this script can never pass by testing nothing. CrewAI telemetry and tracing are off, and its
# storage directory is a temporary one.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

export UV_PROJECT_ENVIRONMENT="${ROOT}/.venv-crewai"
export A2AGW_CREWAI_TESTS=1
export CREWAI_DISABLE_TELEMETRY=true
export CREWAI_DISABLE_TRACKING=true
export CREWAI_TRACING_ENABLED=false
export OTEL_SDK_DISABLED=true
STORAGE="$(mktemp -d)"
trap 'rm -rf "${STORAGE}"' EXIT
export CREWAI_STORAGE_DIR="${STORAGE}"

UV_FLAGS=(--frozen --no-default-groups --group crewai-test)
if [ -d "${UV_PROJECT_ENVIRONMENT}" ] && [ -z "${CREWAI_TEST_ONLINE:-}" ]; then
  UV_FLAGS+=(--offline)
fi

LOG="${STORAGE}/pytest.log"
set +e
uv run "${UV_FLAGS[@]}" pytest tests/adapters/test_crewai.py -q -W error -p no:randomly \
  -p no:cacheprovider "$@" 2>&1 | tee "${LOG}"
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
