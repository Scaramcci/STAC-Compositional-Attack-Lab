#!/usr/bin/env bash
set -euo pipefail
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
CONFIG="${1:-configs/capability/provider_compatibility.disabled.json}"
run_cli capability doctor --config "$CONFIG"
