#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
args=(capability prepare-compatibility --config configs/capability/provider_compatibility.disabled.json)
if [[ "${1:-}" == "bind" ]]; then
  if [[ $# -ne 4 || "$4" != "--authorize-live" ]]; then
    echo "usage: $0 bind RUN_ROOT AUTHORIZATION_REFERENCE --authorize-live" >&2
    exit 64
  fi
  run_cli capability bind-compatibility --run-root "$2" --authorization-reference "$3" --authorize-live
  exit
fi
if [[ $# -gt 1 ]]; then echo "usage: $0 [RUN_ID]" >&2; exit 64; fi
if [[ $# -eq 1 ]]; then args+=(--run-id "$1"); fi
run_cli "${args[@]}"
