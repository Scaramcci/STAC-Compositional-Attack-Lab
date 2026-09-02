#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="configs/sample_generation/pilot_collection.yaml"
PYTHON_BIN="${STAC_PYTHON:-${PROJECT_ROOT}/.venv/bin/python}"
PREFLIGHT_ONLY=false
PRINT_OUTPUT=false

usage() {
  printf '%s\n' \
    "Usage: bash scripts/run_safeclaw_sample_collection.sh [options]" \
    "" \
    "Options:" \
    "  --config PATH          Versioned sample-generation config." \
    "  --preflight-only       Run deterministic preflight and exit." \
    "  --print-output-dir     Print the configured collection directory and exit." \
    "  -h, --help             Show this help."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      [[ $# -ge 2 ]] || { echo "Missing value for --config" >&2; exit 2; }
      CONFIG="$2"
      shift 2
      ;;
    --preflight-only)
      PREFLIGHT_ONLY=true
      shift
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

RUN_METADATA="$(
  PYTHONPATH="${PROJECT_ROOT}/src" "${PYTHON_BIN}" - "${PROJECT_ROOT}/${CONFIG}" <<'PY'
import sys
from pathlib import Path

from stac_attack_lab.execution.sample_generation import load_sample_generation_config

config = load_sample_generation_config(Path(sys.argv[1]))
values = (
    config.library_version,
    config.pipeline_id,
    Path(config.output_root) / config.library_version,
    Path(config.output_root)
    / config.library_version
    / "interactions/raw"
    / config.pipeline_id,
)
print("\t".join(str(value) for value in values))
PY
)"

IFS=$'\t' read -r LIBRARY_VERSION PIPELINE_ID BUILD_REL COLLECTION_REL <<< "${RUN_METADATA}"
BUILD_ROOT="${PROJECT_ROOT}/${BUILD_REL}"
LOG_FILE="${BUILD_ROOT}/tmux-collection.log"

if [[ "${PRINT_OUTPUT}" == "true" ]]; then
  printf '%s\n' "${COLLECTION_REL}"
  exit 0
fi
if [[ ! "${LIBRARY_VERSION}" =~ ^[A-Za-z0-9._-]+$ ]] || \
   [[ ! "${PIPELINE_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid library version or pipeline id" >&2
  exit 2
fi

mkdir -p "${BUILD_ROOT}"
exec > >(tee -a "${LOG_FILE}") 2>&1

LOCK_PATH="${TMPDIR:-/tmp}/stac-safeclaw-collection-${LIBRARY_VERSION}.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${LOCK_PATH}"
  if ! flock -n 9; then
    echo "Another collection for ${LIBRARY_VERSION} is active." >&2
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
echo "[$(date '+%Y-%m-%dT%H:%M:%S%z')] starting library_version=${LIBRARY_VERSION}"
echo "config=${CONFIG}"
echo "collection_root=${COLLECTION_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli sample collect-preflight --config "${CONFIG}"

if [[ "${PREFLIGHT_ONLY}" == "true" ]]; then
  echo "sample_collection_preflight=passed"
  exit 0
fi

"${PYTHON_BIN}" -u -m stac_attack_lab.cli sample collect --config "${CONFIG}"
echo "sample_collection=${PROJECT_ROOT}/${COLLECTION_REL}"
