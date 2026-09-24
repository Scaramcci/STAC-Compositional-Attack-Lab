#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mode="${1:-}"
shift || :
case "$mode" in
  prepare|validate)
    [[ $# -eq 1 ]] || exit 64
    PYTHONPATH=src "${STAC_PYTHON:-python}" scripts/capability/f5_repeat_plan.py "$mode" "$1"
    ;;
  report)
    [[ $# -eq 2 ]] || exit 64
    PYTHONPATH=src "${STAC_PYTHON:-python}" scripts/capability/f5_repeat_plan.py report "$1" "$2"
    ;;
  status)
    [[ $# -eq 2 ]] || exit 64
    group_root="$(PYTHONPATH=src "${STAC_PYTHON:-python}" scripts/capability/f5_repeat_plan.py group-root "$1" "$2")"
    bash scripts/capability/15_m3_f5.sh status "$group_root"
    ;;
  bind)
    [[ $# -eq 4 && "$4" == "--authorize-live" ]] || exit 64
    group_root="$(PYTHONPATH=src "${STAC_PYTHON:-python}" scripts/capability/f5_repeat_plan.py ready "$1" "$2")"
    bash scripts/capability/15_m3_f5.sh bind "$group_root" "$3" --authorize-live --allowed-unit benign --allowed-unit direct --allowed-unit semantic --max-victim-http-attempts 30
    ;;
  run)
    [[ $# -eq 4 && "$4" == "--authorize-live" ]] || exit 64
    group_root="$(PYTHONPATH=src "${STAC_PYTHON:-python}" scripts/capability/f5_repeat_plan.py group-root "$1" "$2")"
    [[ "$3" == benign || "$3" == direct || "$3" == semantic ]] || exit 64
    bash scripts/capability/15_m3_f5.sh run "$group_root" "$3" --authorize-live
    ;;
  *) exit 64 ;;
esac
