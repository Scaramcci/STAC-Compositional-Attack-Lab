#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mode="${1:-}"
shift || :
case "$mode" in
  prepare)
    [[ $# -eq 1 ]] || exit 64
    run_cli capability m2-ai-review-prepare --config configs/capability/m3_f3_ai_review.disabled.json --output "$1"
    ;;
  validate|dry-run|status)
    [[ $# -eq 1 ]] || exit 64
    run_cli capability "m2-ai-review-$mode" --run-root "$1"
    ;;
  bind)
    [[ $# -eq 3 && "$3" == "--authorize-live" ]] || exit 64
    run_cli capability m2-ai-review-bind --run-root "$1" --authorization-reference "$2" --authorize-live
    ;;
  run)
    [[ $# -eq 2 && "$2" == "--authorize-live" ]] || exit 64
    run_cli capability m2-ai-review-run --run-root "$1" --authorize-live
    ;;
  report)
    [[ $# -eq 2 ]] || exit 64
    run_cli capability m2-ai-review-report --run-root "$1" --output "$2"
    ;;
  import)
    [[ $# -eq 2 ]] || exit 64
    run_cli capability m3-f3-ai-review-import --run-root "$1" --output "$2"
    ;;
  revalidate)
    [[ $# -eq 2 ]] || exit 64
    run_cli capability m3-f3-ai-review-revalidate --run-root "$1" --output "$2"
    ;;
  *) exit 64 ;;
esac
