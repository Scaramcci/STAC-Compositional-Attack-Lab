#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -lt 1 ]]; then echo "usage: $0 RUN_ROOT [--dry-run|--authorize-live]" >&2; exit 64; fi
run_cli capability probe --run-root "$1" --stage P2 "${@:2}"
