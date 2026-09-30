#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
set -euo pipefail
if [[ $# -ne 1 || ! "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
  printf '%s\n' 'Usage: 16_r4_generation_fake_check.sh <unique-run-id>' >&2
  exit 2
fi
RUN_ID="$1"
ROOT_RUN="experiments/runs/attack-program/${RUN_ID}"
EXIT_FILE="experiments/runs/attack-program/${RUN_ID}-exit-code.txt"
if [[ -e "$ROOT_RUN" || -e "$EXIT_FILE" ]]; then
  printf '%s\n' 'Run directory already exists; choose a new run id.' >&2
  exit 2
fi
mkdir -m 700 "$ROOT_RUN"
FAKE_PID=''
cleanup() { status=$?; if [[ -n "$FAKE_PID" ]]; then kill "$FAKE_PID" 2>/dev/null || true; wait "$FAKE_PID" 2>/dev/null || true; fi; printf '%s\n' "$status" > "$EXIT_FILE"; }
trap cleanup EXIT
"$PYTHON" -m stac_attack_lab.attack_program.r4_fake_provider \
  --config configs/attack_program/r4_generation_fake_provider.json --port 18794 &
FAKE_PID=$!
sleep 1
export STAC_R4_ATTACKER_KEY='local-only-generation-key'
"$PYTHON" -m stac_attack_lab.attack_program.cli r4-generation-run \
  --plan configs/attack_program/r4_generation_plan_v1.json \
  --prompt configs/attack_program/r4_attacker_prompt_v1.txt \
  --model-id attacker-local-fake --base-url http://127.0.0.1:18794/v1 \
  --api-key-env STAC_R4_ATTACKER_KEY --local-fake --output "$ROOT_RUN/generation"
"$PYTHON" -m stac_attack_lab.attack_program.cli r4-generation-prepare-victim \
  --generation "$ROOT_RUN/generation" --local-fake-mode harm --output "$ROOT_RUN/victim"
export STAC_R4_FAKE_DATED_MEMORY=1
for batch in "$ROOT_RUN"/victim/slot-*/manifest.json; do
  batch="${batch%/manifest.json}"
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-validate --batch "$batch"
  "$PYTHON" - "$batch" <<'PY'
import json, sys
from pathlib import Path
from stac_attack_lab.attack_program.file_io import write_json_exclusive
from stac_attack_lab.attack_program.r4_batch import authorization_text
batch = Path(sys.argv[1])
manifest = json.loads((batch / 'manifest.json').read_text())
write_json_exclusive(batch / 'fake-authorization.json', {
    'schema_version': 'attack-r4-authorization/1',
    'scope': 'local_fake',
    'manifest_hash': manifest['manifest_hash'],
    'text': authorization_text(manifest),
}, private=True, sort_keys=True, durable=True)
PY
  digest="$(sha256sum "$batch/fake-authorization.json" | cut -d' ' -f1)"
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-bind --batch "$batch" \
    --authorization "$batch/fake-authorization.json" --authorization-sha256 "$digest" --local-fake-authorized
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-run-batch --batch "$batch" \
    --authorization "$batch/fake-authorization.json" --authorization-sha256 "$digest" --local-fake-authorized
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-replay \
    --case "$batch/execution/case" --output "$ROOT_RUN/$(basename "$batch")-external-audit"
done
"$PYTHON" - "$ROOT_RUN" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
generation = json.loads((root / 'generation/summary.json').read_text())
victim = json.loads((root / 'victim/summary.json').read_text())
if (generation['assigned_slots'], generation['attacker_http_attempts'], generation['valid_candidates'],
    generation['duplicate_candidates'], victim['prepared']) != (3, 3, 1, 2, 1):
    raise SystemExit('generation denominator mismatch')
batch = root / 'victim/slot-001'
terminal = json.loads((batch / 'execution/terminal.json').read_text())
observation = json.loads((batch / 'execution/case/observation.json').read_text())
audit = json.loads((root / 'slot-001-external-audit/audit.json').read_text())
if terminal['status'] != 'completed' or audit['status'] != 'valid':
    raise SystemExit('Victim terminal or replay invalid')
if not any(e['event_type'] == 'state_write' and e['status'] == 'committed'
           and e.get('resource_id') == 'memory/2026-09-30.md' for e in observation['events']):
    raise SystemExit('dated memory committed write missing')
print(json.dumps({'status': 'r4_generation_fake_valid', 'attacker_http_attempts': 3,
                  'victim_prepared': 1, 'victim_completed': 1, 'real_requests': 0}))
PY
