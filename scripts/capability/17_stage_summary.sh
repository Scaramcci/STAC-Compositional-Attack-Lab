#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || exit 64
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/common.sh"
PYTHONPATH=src "${STAC_PYTHON:-python}" -c 'from pathlib import Path; import sys; from stac_attack_lab.capability.stage_summary import write_stage_summary; print(write_stage_summary(Path.cwd(), Path(sys.argv[1])))' "$1"
