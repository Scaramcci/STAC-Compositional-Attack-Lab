#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "${PROJECT_ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/.env"
  set +a
fi
CONFIG="configs/sample_generation/pilot_collection.yaml"
RUN_ID=""
PYTHON_BIN="${STAC_PYTHON:-python3}"
PREFLIGHT_ONLY=false
PRINT_OUTPUT=false

usage() {
  printf '%s\n' \
    "Usage: bash scripts/run_safeclaw_sample_collection.sh [options]" \
    "" \
    "Options:" \
    "  --config PATH          Versioned sample-generation config." \
    "  --run-id ID            Unique output id; reuse explicitly to resume." \
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
    --run-id)
      [[ $# -ge 2 ]] || { echo "Missing value for --run-id" >&2; exit 2; }
      RUN_ID="$2"
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

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Python environment not found: ${PYTHON_BIN}" >&2
  exit 2
fi
if [[ ! -f "${PROJECT_ROOT}/${CONFIG}" ]]; then
  echo "Sample collection config not found: ${CONFIG}" >&2
  exit 2
fi
if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="collection-$(${PYTHON_BIN} -c 'import uuid; print(uuid.uuid4().hex[:12])')"
fi
if [[ ! "${RUN_ID}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid run id: use only letters, numbers, dot, underscore, and hyphen." >&2
  exit 2
fi

RUN_ROOT="${PROJECT_ROOT}/experiments/runs/${RUN_ID}"
mkdir -p "${RUN_ROOT}"
RUNTIME_CONFIG="${RUN_ROOT}/runtime_collection_config.json"
DERIVATION_METADATA="${RUN_ROOT}/runtime_collection_config_derivation.json"
"${PYTHON_BIN}" - "${PROJECT_ROOT}/${CONFIG}" "${RUNTIME_CONFIG}" "${DERIVATION_METADATA}" "${RUN_ID}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
metadata_path = Path(sys.argv[3])
run_id = sys.argv[4]
value = json.loads(source.read_text(encoding="utf-8"))
original_output_root = value.get("output_root")
value["output_root"] = str(Path("experiments/runs") / run_id)
encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
if target.exists() and target.read_text(encoding="utf-8") != encoded:
    raise SystemExit("runtime_collection_config_conflict")
target.write_text(encoded, encoding="utf-8")
source_bytes = source.read_bytes()
metadata = {
    "schema_version": "1.0",
    "source_config_path": str(source),
    "source_config_sha256": hashlib.sha256(source_bytes).hexdigest(),
    "runtime_config_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
    "overrides": {
        "output_root": {"before": original_output_root, "after": value["output_root"]}
    },
}
metadata_encoded = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
if metadata_path.exists() and metadata_path.read_text(encoding="utf-8") != metadata_encoded:
    raise SystemExit("runtime_collection_derivation_conflict")
metadata_path.write_text(metadata_encoded, encoding="utf-8")
PY

RUN_METADATA="$(
  PYTHONPATH="${PROJECT_ROOT}/src" "${PYTHON_BIN}" - "${RUNTIME_CONFIG}" <<'PY'
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
echo "run_id=${RUN_ID}"
echo "collection_root=${COLLECTION_REL}"

"${PYTHON_BIN}" -u -m stac_attack_lab.cli sample collect-preflight --config "${RUNTIME_CONFIG}"

if [[ "${PREFLIGHT_ONLY}" == "true" ]]; then
  echo "sample_collection_preflight=passed"
  exit 0
fi

"${PYTHON_BIN}" -u -m stac_attack_lab.cli sample collect --config "${RUNTIME_CONFIG}"
echo "sample_collection=${PROJECT_ROOT}/${COLLECTION_REL}"
