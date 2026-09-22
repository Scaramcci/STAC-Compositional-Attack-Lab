#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -ne 1 ]]; then echo "usage: $0 OUTPUT_ROOT" >&2; exit 64; fi
OUTPUT_ROOT="$1"
mkdir -- "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd -- "$OUTPUT_ROOT" && pwd)"
printf '%s\n' '{"network":"loopback_fake_only","fake_http_attempts":null,"fake_http_accounting":"not_aggregated; see test assertions and pytest.log","real_model_requests":0}' \
  > "$OUTPUT_ROOT/scope.json"
cd -- "$PROJECT_ROOT"
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 "$STAC_PYTHON" -m pytest -q \
  tests/unit/test_provider_relay.py -k precommit_guard \
  tests/integration/test_capability_m2_fake_http.py | tee "$OUTPUT_ROOT/pytest.log"
