#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
if [[ $# -lt 1 ]]; then
  echo "usage: $0 bind RUN_ROOT APPROVAL_REF | run RUN_ROOT UNIT_ID" >&2
  exit 64
fi
MODE="$1"; shift
case "$MODE" in
  bind)
    if [[ $# -ne 2 ]]; then echo "usage: $0 bind RUN_ROOT APPROVAL_REF" >&2; exit 64; fi
    run_cli capability m2-bind --run-root "$1" --authorization-reference "$2" --authorize-live
    ;;
  run)
    if [[ $# -ne 2 ]]; then echo "usage: $0 run RUN_ROOT UNIT_ID" >&2; exit 64; fi
    run_cli capability m2-run-unit --run-root "$1" --unit "$2" --authorize-live
    ;;
  *) echo "unknown mode: $MODE" >&2; exit 64 ;;
esac
