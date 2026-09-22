#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -ne 2 ]]; then echo "usage: $0 RUN_ROOT REPORT_ROOT" >&2; exit 64; fi
run_cli capability m2-validate --run-root "$1"
run_cli capability m2-report --run-root "$1" --output "$2"
run_cli capability m2-annotation-export --run-root "$1" --output "$2/annotation-review.json"

