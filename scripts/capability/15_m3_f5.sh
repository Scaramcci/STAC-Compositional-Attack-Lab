#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mode="${1:-}"
shift || :
case "$mode" in
  prepare)
    [[ $# -eq 1 || ( $# -eq 3 && "$2" == "--config" ) ]] || exit 64
    if [[ $# -eq 3 ]]; then
      run_cli capability m3-f5-prepare --output "$1" --config "$3"
    else
      run_cli capability m3-f5-prepare --output "$1"
    fi
    ;;
  validate|status)
    [[ $# -eq 1 ]] || exit 64
    run_cli capability "m3-f5-$mode" --run-root "$1"
    ;;
  bind)
    [[ $# -ge 3 && "$3" == "--authorize-live" ]] || exit 64
    run_root="$1"
    authorization_reference="$2"
    shift 3
    run_cli capability m3-f5-bind --run-root "$run_root" --authorization-reference "$authorization_reference" --authorize-live "$@"
    ;;
  run)
    [[ $# -eq 3 && "$3" == "--authorize-live" ]] || exit 64
    run_cli capability m3-f5-run-unit --run-root "$1" --unit "$2" --authorize-live
    ;;
  report)
    [[ $# -eq 2 ]] || exit 64
    run_cli capability m3-f5-report --run-root "$1" --output "$2"
    ;;
  reanalyze)
    [[ $# -eq 2 ]] || exit 64
    run_cli capability m3-f5-reanalyze --run-root "$1" --output "$2"
    ;;
  *) exit 64 ;;
esac
