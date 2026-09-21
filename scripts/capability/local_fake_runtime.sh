#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -lt 1 ]]; then
  echo "usage: $0 OUTPUT_ROOT [--scenario P0|P1|P2|P1_REJECTED|P2_INCOMPLETE]..." >&2
  exit 64
fi
cd -- "$PROJECT_ROOT"
"$STAC_PYTHON" scripts/capability/run_local_fake_runtime.py "$@"
