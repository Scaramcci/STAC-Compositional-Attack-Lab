#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -ne 2 ]]; then echo "usage: $0 RUN_ROOT OUTPUT_ROOT" >&2; exit 64; fi
run_cli capability compatibility-report --run-root "$1" --output "$2"
