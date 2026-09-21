#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
STAC_PYTHON="${STAC_PYTHON:-python}"

run_cli() {
  cd -- "$PROJECT_ROOT"
  "$STAC_PYTHON" -m stac_attack_lab.cli "$@"
}
