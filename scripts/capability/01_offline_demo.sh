#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -ne 1 ]]; then echo "usage: $0 OUTPUT_ROOT" >&2; exit 64; fi
run_cli capability demo --config configs/capability/f1_status_acceptance.json --output "$1"
