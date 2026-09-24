#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"

usage() {
  cat >&2 <<'EOF'
usage:
  12_m2_ai_review.sh prepare RUN_ROOT [CONFIG]
  12_m2_ai_review.sh validate|dry-run|status RUN_ROOT
  12_m2_ai_review.sh bind RUN_ROOT AUTHORIZATION_REFERENCE --authorize-live
  12_m2_ai_review.sh run|resume RUN_ROOT --authorize-live
  12_m2_ai_review.sh report RUN_ROOT OUTPUT
  12_m2_ai_review.sh import AI_RUN_ROOT M2_RUN_ROOT OUTPUT
  12_m2_ai_review.sh merge BASE_AI_RUN SUPPLEMENT_AI_RUN OUTPUT
EOF
  exit 64
}

[[ $# -ge 1 ]] || usage
MODE="$1"
shift
case "$MODE" in
  prepare)
    [[ $# -ge 1 && $# -le 2 ]] || usage
    args=(capability m2-ai-review-prepare --output "$1")
    [[ $# -eq 2 ]] && args+=(--config "$2")
    run_cli "${args[@]}"
    ;;
  validate|dry-run|status)
    [[ $# -eq 1 ]] || usage
    run_cli capability "m2-ai-review-$MODE" --run-root "$1"
    ;;
  bind)
    [[ $# -eq 3 && "$3" == "--authorize-live" ]] || usage
    run_cli capability m2-ai-review-bind --run-root "$1" \
      --authorization-reference "$2" --authorize-live
    ;;
  run|resume)
    [[ $# -eq 2 && "$2" == "--authorize-live" ]] || usage
    args=(capability m2-ai-review-run --run-root "$1" --authorize-live)
    [[ "$MODE" == "resume" ]] && args+=(--resume)
    run_cli "${args[@]}"
    ;;
  report)
    [[ $# -eq 2 ]] || usage
    run_cli capability m2-ai-review-report --run-root "$1" --output "$2"
    ;;
  import)
    [[ $# -eq 3 ]] || usage
    run_cli capability m2-ai-review-import --run-root "$1" \
      --m2-run-root "$2" --output "$3"
    ;;
  merge)
    [[ $# -eq 3 ]] || usage
    run_cli capability m2-ai-review-merge --base-run "$1" \
      --supplement-run "$2" --output "$3"
    ;;
  *) usage ;;
esac
