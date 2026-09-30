#!/usr/bin/env bash
set -euo pipefail
exec "${PYTHON:-python}" -m stac_attack_lab.attack_program.r4_real_diagnosis_cli "$@"
