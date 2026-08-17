#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-safeclaw-formal-v1-main}"
FORMAL_CONFIG="${2:-configs/experiments/safeclaw_formal_v1.yaml}"
PREFLIGHT_CONFIG="${3:-configs/environments/safeclaw_openclaw_v1.yaml}"
PYTHON_BIN="${STAC_PYTHON:-${PROJECT_ROOT}/.venv/bin/python}"
RUN_ROOT_REL="experiments/safeclaw_runs/${RUN_ID}"
RUN_ROOT="${PROJECT_ROOT}/${RUN_ROOT_REL}"
LOG_FILE="${RUN_ROOT}/tmux-run.log"

if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid run id: use only letters, numbers, dot, underscore, and hyphen." >&2
  exit 2
fi
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Python environment not found: ${PYTHON_BIN}" >&2
  exit 2
fi
if [[ ! -f "${PROJECT_ROOT}/${FORMAL_CONFIG}" ]]; then
  echo "Formal config not found: ${FORMAL_CONFIG}" >&2
  exit 2
fi
if [[ ! -f "${PROJECT_ROOT}/${PREFLIGHT_CONFIG}" ]]; then
  echo "Preflight config not found: ${PREFLIGHT_CONFIG}" >&2
  exit 2
fi

mkdir -p "${RUN_ROOT}"
exec > >(tee -a "${LOG_FILE}") 2>&1

LOCK_PATH="${TMPDIR:-/tmp}/stac-safeclaw-formal.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${LOCK_PATH}"
  if ! flock -n 9; then
    echo "Another SafeClaw formal run is active: ${LOCK_PATH}"
    exit 3
  fi
fi

finish() {
  local status=$?
  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] finished status=${status} log=${LOG_FILE}"
}
trap finish EXIT

cd "${PROJECT_ROOT}"
echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] starting run_id=${RUN_ID}"
echo "project_root=${PROJECT_ROOT}"
echo "formal_config=${FORMAL_CONFIG}"
echo "preflight_config=${PREFLIGHT_CONFIG}"
echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unavailable)"

export PYTHONPATH="${PROJECT_ROOT}/src"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw preflight \
  --config "${PREFLIGHT_CONFIG}"

# Always use --resume. It is valid for a new run and makes rerunning this exact
# command continue from the last fully recorded case after interruption/error.
"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw run \
  --config "${FORMAL_CONFIG}" \
  --run-id "${RUN_ID}" \
  --resume

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw audit-run \
  --run-root "${RUN_ROOT_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw formal-report \
  --run-root "${RUN_ROOT_REL}"

echo "result_root=${RUN_ROOT}"
