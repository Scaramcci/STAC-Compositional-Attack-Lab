#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="configs/experiments/stac_sample_build_gpt_gemini_50.yaml"
PYTHON_BIN="${STAC_PYTHON:-${PROJECT_ROOT}/.venv/bin/python}"

usage() {
  printf '%s\n' \
    "Usage: bash scripts/run_sample_collection.sh [--config PATH] [--print-output-dir]" \
    "" \
    "Collects and audits the configured resumable GPT/Gemini sample dataset." \
    "Default config: configs/experiments/stac_sample_build_gpt_gemini_50.yaml"
}

PRINT_OUTPUT=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      [[ $# -ge 2 ]] || { echo "Missing value for --config" >&2; exit 2; }
      CONFIG="$2"
      shift 2
      ;;
    --print-output-dir)
      PRINT_OUTPUT=true
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

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Python environment not found: ${PYTHON_BIN}" >&2
  exit 2
fi
if [[ ! -f "${PROJECT_ROOT}/${CONFIG}" ]]; then
  echo "Sample collection config not found: ${CONFIG}" >&2
  exit 2
fi

mapfile -t RUN_METADATA < <(
  PYTHONPATH="${PROJECT_ROOT}/src" "${PYTHON_BIN}" - "${PROJECT_ROOT}/${CONFIG}" <<'PY'
import sys
from pathlib import Path

from stac_attack_lab.config import load_experiment_config
from stac_attack_lab.hashing import stable_hash

config = load_experiment_config(Path(sys.argv[1]))
if config.profile != "stac_offline":
    raise SystemExit("sample_collection_requires_stac_offline_profile")
if config.models["victim"].provider != "gemini":
    raise SystemExit("sample_collection_requires_gemini_victim")
config_hash = stable_hash(config.model_dump(mode="json"))
run_id = f"{config.experiment_id}-{config_hash[:12]}"
print(run_id)
print(f"data/generated/{run_id}")
PY
)

RUN_ID="${RUN_METADATA[0]}"
OUTPUT_REL="${RUN_METADATA[1]}"
OUTPUT_ROOT="${PROJECT_ROOT}/${OUTPUT_REL}"
LOG_FILE="${OUTPUT_ROOT}/sample-collection.log"

if [[ "${PRINT_OUTPUT}" == "true" ]]; then
  printf '%s\n' "${OUTPUT_REL}"
  exit 0
fi
if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid derived run id" >&2
  exit 2
fi

mkdir -p "${OUTPUT_ROOT}"
exec > >(tee -a "${LOG_FILE}") 2>&1

LOCK_PATH="${TMPDIR:-/tmp}/stac-sample-collection-${RUN_ID}.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${LOCK_PATH}"
  if ! flock -n 9; then
    echo "Another sample collection is active: ${LOCK_PATH}" >&2
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
echo "config=${CONFIG}"
echo "output_root=${OUTPUT_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli offline build --config "${CONFIG}"
"${PYTHON_BIN}" -u -m stac_attack_lab.cli dataset audit --dataset "${OUTPUT_REL}"

echo "sample_output=${OUTPUT_ROOT}"
