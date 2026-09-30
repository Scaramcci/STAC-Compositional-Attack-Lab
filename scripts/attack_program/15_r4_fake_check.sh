#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
if [[ $# -ne 1 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  printf '%s\n' 'Usage: 15_r4_fake_check.sh <unique-run-id>' >&2
  exit 2
fi
RUN_ID="$1"
RUN_DIR="experiments/runs/attack-program/${RUN_ID}"
EXIT_FILE="experiments/runs/attack-program/${RUN_ID}-exit-code.txt"
if [[ -e "$RUN_DIR" || -e "$EXIT_FILE" || -e "${RUN_DIR}-external-audit" ]]; then
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
    --case "$RUN_DIR/prepared/$case/execution/case" \
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
    batch = root / "prepared" / case
    manifest = json.loads((batch / "manifest.json").read_text())
    binding = json.loads((batch / "binding.json").read_text())
    terminal = json.loads((batch / "execution/terminal.json").read_text())
    bundle = json.loads((batch / "execution/case/runtime_bundle.json").read_text())
    raw_archive = json.loads((batch / "execution/runtime-evidence.json").read_text())
    if (manifest["schema_version"] != "attack-r4-prepared-batch/2"
        or manifest["execution_enabled"] is not False or manifest["binding"] is not None
        or binding["scope"] != "local_fake" or terminal["status"] != "completed"
        or bundle["source"] != "local_fake" or bundle["cleanup"]["status"] != "completed"
        or terminal["binding_hash"] != binding["binding_hash"]
        or bundle["execution_binding_hash"] != binding["binding_hash"]
        or raw_archive["provider_requests_frozen"] is not True
        or raw_archive["run_id"] != manifest["run_id"]
        or raw_archive["relay_reservations"] != bundle["relay_reservations"]):
        raise SystemExit(f"R4 lifecycle fake acceptance failed: {case}")
    audit = json.loads((Path(str(root) + "-external-audit") / case / "audit.json").read_text())
    if audit["status"] != "valid":
        raise SystemExit(f"R4 external audit invalid: {case}")
print(json.dumps({"status": "r4_local_fake_valid", "report": str(root / "report.json"), "external_audits": 3,
                  "real_requests": 0, "real_candidate": "pending independent receipt"}))
PY
