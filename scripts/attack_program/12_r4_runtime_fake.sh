#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
"$PYTHON" -m stac_attack_lab.attack_program.cli r4-local-fake "$@"
