#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="safeclaw-formal-main"
FORMAL_CONFIG="configs/experiments/formal_evaluation.yaml"
PREFLIGHT_CONFIG="configs/environments/safeclaw.yaml"
UPSTREAM_REL="integrations/safeclaw/upstream/SafeClawArena"
PSE_TASK_REL="tasks/pse/pse-2.1-001.json"
PYTHON_BIN="${STAC_PYTHON:-${PROJECT_ROOT}/.venv/bin/python}"

usage() {
  printf '%s\n' \
    "Usage: bash scripts/run_formal_evaluation.sh [options]" \
    "" \
    "Options:" \
    "  --run-id ID            Resume-safe formal run id." \
    "  --config PATH          Formal experiment config." \
    "  --preflight PATH       SafeClaw preflight config." \
    "  --print-output-dir     Print the configured output directory and exit." \
    "  --preflight-only       Run official PSE and preflight checks, then exit." \
    "  -h, --help             Show this help."
}

PRINT_OUTPUT=false
PREFLIGHT_ONLY=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      [[ $# -ge 2 ]] || { echo "Missing value for --run-id" >&2; exit 2; }
      RUN_ID="$2"
      shift 2
      ;;
    --config)
      [[ $# -ge 2 ]] || { echo "Missing value for --config" >&2; exit 2; }
      FORMAL_CONFIG="$2"
      shift 2
      ;;
    --preflight)
      [[ $# -ge 2 ]] || { echo "Missing value for --preflight" >&2; exit 2; }
      PREFLIGHT_CONFIG="$2"
      shift 2
      ;;
    --print-output-dir)
      PRINT_OUTPUT=true
      shift
      ;;
    --preflight-only)
      PREFLIGHT_ONLY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid run id: use only letters, numbers, dot, underscore, and hyphen." >&2
  exit 2
fi
if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Python environment not found: ${PYTHON_BIN}" >&2
  exit 2
fi
for path in "${FORMAL_CONFIG}" "${PREFLIGHT_CONFIG}"; do
  if [[ ! -f "${PROJECT_ROOT}/${path}" ]]; then
    echo "Required config not found: ${path}" >&2
    exit 2
  fi
done

RUN_ROOT_REL="experiments/safeclaw_runs/${RUN_ID}"
RUN_ROOT="${PROJECT_ROOT}/${RUN_ROOT_REL}"
LOG_FILE="${RUN_ROOT}/tmux-run.log"

if [[ "${PRINT_OUTPUT}" == "true" ]]; then
  printf '%s\n' "${RUN_ROOT_REL}"
  exit 0
fi

mkdir -p "${RUN_ROOT}"
exec > >(tee -a "${LOG_FILE}") 2>&1

LOCK_PATH="${TMPDIR:-/tmp}/stac-safeclaw-formal.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${LOCK_PATH}"
  if ! flock -n 9; then
    echo "Another SafeClaw formal run is active: ${LOCK_PATH}" >&2
    exit 3
  fi
fi

finish() {
  local status=$?
  echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] finished status=${status} log=${LOG_FILE}"
}
trap finish EXIT

cd "${PROJECT_ROOT}"
export PYTHONPATH="${PROJECT_ROOT}/src"
echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] starting run_id=${RUN_ID}"
echo "formal_config=${FORMAL_CONFIG}"
echo "preflight_config=${PREFLIGHT_CONFIG}"
echo "output_root=${RUN_ROOT_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw pse-smoke \
  --upstream "${UPSTREAM_REL}" \
  --task "${PSE_TASK_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw preflight \
  --config "${PREFLIGHT_CONFIG}"

if [[ "${PREFLIGHT_ONLY}" == "true" ]]; then
  echo "formal_preflight=passed"
  exit 0
fi

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw run \
  --config "${FORMAL_CONFIG}" \
  --run-id "${RUN_ID}" \
  --resume

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw audit-run \
  --run-root "${RUN_ROOT_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli safeclaw report \
  --run-root "${RUN_ROOT_REL}"

echo "formal_output=${RUN_ROOT}"
