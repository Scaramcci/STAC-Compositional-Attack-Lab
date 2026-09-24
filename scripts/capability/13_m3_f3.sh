#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 prepare RUN_ROOT | validate RUN_ROOT | status RUN_ROOT | report RUN_ROOT OUTPUT | review-export RUN_ROOT OUTPUT | bind RUN_ROOT AUTH_REF | run RUN_ROOT UNIT" >&2
  exit 64
fi

MODE="$1"
shift
case "$MODE" in
  prepare)
    [[ $# -eq 1 ]] || { echo "usage: $0 prepare RUN_ROOT" >&2; exit 64; }
    run_cli capability m3-f3-prepare --config configs/capability/m3a_f3.disabled.json --output "$1"
    ;;
  validate)
    [[ $# -eq 1 ]] || { echo "usage: $0 validate RUN_ROOT" >&2; exit 64; }
    run_cli capability m3-f3-validate --run-root "$1"
    ;;
  status)
    [[ $# -eq 1 ]] || { echo "usage: $0 status RUN_ROOT" >&2; exit 64; }
    run_cli capability m3-f3-status --run-root "$1"
    ;;
  report)
    [[ $# -eq 2 ]] || { echo "usage: $0 report RUN_ROOT OUTPUT" >&2; exit 64; }
    run_cli capability m3-f3-report --run-root "$1" --output "$2"
    ;;
  review-export)
    [[ $# -eq 2 ]] || { echo "usage: $0 review-export RUN_ROOT OUTPUT" >&2; exit 64; }
    run_cli capability m3-f3-review-export --run-root "$1" --output "$2"
    ;;
  bind)
    [[ $# -eq 2 ]] || { echo "usage: $0 bind RUN_ROOT AUTH_REF" >&2; exit 64; }
    run_cli capability m3-f3-bind --run-root "$1" --authorization-reference "$2" --authorize-live
    ;;
  run)
    [[ $# -eq 2 ]] || { echo "usage: $0 run RUN_ROOT UNIT" >&2; exit 64; }
    run_cli capability m3-f3-run-unit --run-root "$1" --unit "$2" --authorize-live
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 64
    ;;
esac
