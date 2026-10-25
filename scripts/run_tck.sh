#!/usr/bin/env bash
# Run the official A2A TCK (github.com/a2aproject/a2a-tck) against the a2agw SUT in
# examples/tck_sut/sut_agent.py. Run from the repo root:
#
#   scripts/run_tck.sh                 # MUST level (exit nonzero if any MUST test fails)
#   TCK_LEVEL=should scripts/run_tck.sh
#   scripts/run_tck.sh -- -k cancel    # extra pytest args go to the TCK
#
# The TCK is cloned into .tck/a2a-tck (git-ignored) at the pinned commit below and runs in
# its own virtualenv there; none of its dependencies enter this project.
set -euo pipefail

TCK_REPO="https://github.com/a2aproject/a2a-tck.git"
TCK_SHA="d4d6fae7887f88ef607fb461c13e3b0e1802f19b"  # keep in sync with docs/conformance.md
TCK_LEVEL="${TCK_LEVEL:-must}"
SUT_PORT=9999
SUT_URL="http://localhost:${SUT_PORT}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TCK_DIR="${ROOT}/.tck/a2a-tck"
SUT_LOG="${ROOT}/.tck/sut.log"

if [ ! -d "${TCK_DIR}/.git" ]; then
  mkdir -p "${ROOT}/.tck"
  git clone --quiet "${TCK_REPO}" "${TCK_DIR}"
fi
if [ "$(git -C "${TCK_DIR}" rev-parse HEAD)" != "${TCK_SHA}" ]; then
  git -C "${TCK_DIR}" fetch --quiet origin
  git -C "${TCK_DIR}" checkout --quiet --detach "${TCK_SHA}"
fi
if [ ! -x "${TCK_DIR}/.venv/bin/python" ]; then
  (cd "${TCK_DIR}" && uv venv --quiet && uv pip install --quiet -e .)
fi

if curl -fsS -o /dev/null "${SUT_URL}/.well-known/agent-card.json" 2>/dev/null; then
  echo "something is already listening on ${SUT_URL}; stop it first" >&2
  exit 2
fi

cd "${ROOT}"
uv run python -m examples.tck_sut.sut_agent >"${SUT_LOG}" 2>&1 &
SUT_PID=$!
cleanup() {
  kill "${SUT_PID}" 2>/dev/null || true
  wait "${SUT_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "${SUT_URL}/.well-known/agent-card.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "${SUT_PID}" 2>/dev/null; then
    echo "SUT exited during startup; see ${SUT_LOG}" >&2
    exit 1
  fi
  sleep 0.5
done
curl -fsS -o /dev/null "${SUT_URL}/.well-known/agent-card.json" || {
  echo "SUT did not come up on ${SUT_URL}; see ${SUT_LOG}" >&2
  exit 1
}

cd "${TCK_DIR}"
.venv/bin/python run_tck.py --sut-host "${SUT_URL}" --level "${TCK_LEVEL}" "$@"
