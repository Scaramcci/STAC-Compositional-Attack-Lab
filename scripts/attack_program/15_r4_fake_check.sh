#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
if [[ $# -ne 1 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  printf '%s\n' 'Usage: 15_r4_fake_check.sh <unique-run-id>' >&2
  exit 2
fi
RUN_ID="$1"
RUN_DIR="experiments/runs/attack-program/${RUN_ID}"
EXIT_FILE="experiments/runs/attack-program/${RUN_ID}-exit-code.txt"
if [[ -e "$RUN_DIR" || -e "$EXIT_FILE" ]]; then
  printf '%s\n' 'Run directory or exit file already exists; choose a new run id.' >&2
  exit 2
fi
trap 'status=$?; printf "%s\n" "$status" > "$EXIT_FILE"' EXIT
"$PYTHON" -m stac_attack_lab.attack_program.cli r4-doctor
"$PYTHON" -m stac_attack_lab.attack_program.cli r4-local-fake \
  --candidate configs/attack_program/r4_development_candidate.json \
  --output "$RUN_DIR"
for case in baseline-normal r4-dev-one rejected-tool; do
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-replay \
    --case "$RUN_DIR/$case" \
    --output "${RUN_DIR}-external-audit/$case"
done
"$PYTHON" - "$RUN_DIR" <<'PY'
import json
import sys
from pathlib import Path
root = Path(sys.argv[1])
report = json.loads((root / "report.json").read_text())
if report["assigned"] != 3 or report["completed"] != 3 or report["not_started"] != 0:
    raise SystemExit("R4 fake batch did not complete all three assigned cases")
for case in ("baseline-normal", "r4-dev-one", "rejected-tool"):
    audit = json.loads((Path(str(root) + "-external-audit") / case / "audit.json").read_text())
    if audit["status"] != "valid":
        raise SystemExit(f"R4 external audit invalid: {case}")
print(json.dumps({"status": "r4_local_fake_valid", "report": str(root / "report.json"), "external_audits": 3}))
PY
