#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -ne 1 ]]; then echo "usage: $0 OUTPUT_ROOT" >&2; exit 64; fi
OUTPUT_ROOT="$1"
mkdir -- "$OUTPUT_ROOT"
cd -- "$PROJECT_ROOT"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 "$STAC_PYTHON" -m pytest -q \
  tests/unit/test_provider_relay.py -k precommit_guard \
  tests/integration/test_capability_m2.py | tee "$OUTPUT_ROOT/pytest.log"
printf '%s\n' '{"network":"loopback_fake_only","provider_requests":0,"real_model_requests":0}' \
  > "$OUTPUT_ROOT/scope.json"
