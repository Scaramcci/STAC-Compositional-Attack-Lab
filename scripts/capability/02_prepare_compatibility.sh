#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
args=(capability prepare-compatibility --config configs/capability/provider_compatibility.disabled.json)
if [[ $# -gt 1 ]]; then echo "usage: $0 [RUN_ID]" >&2; exit 64; fi
if [[ $# -eq 1 ]]; then args+=(--run-id "$1"); fi
run_cli "${args[@]}"
