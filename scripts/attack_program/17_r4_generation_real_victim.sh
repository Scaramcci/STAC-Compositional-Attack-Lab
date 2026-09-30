#!/usr/bin/env bash
source "$(dirname "$0")/_common.sh"
set -u -o pipefail

ROOT_RUN="experiments/runs/attack-program/r4-generation-real-20260930-v1"
VICTIM_ROOT="$ROOT_RUN/victim-disabled"
PYTHON="${STAC_PYTHON:-$PYTHON}"

if [[ -z "${SAFECLAW_API_KEY:-}" && -f .env ]]; then
  # Parse only the explicitly required credential assignment; never source .env.
  while IFS='=' read -r key value; do
    if [[ "$key" == "SAFECLAW_API_KEY" ]]; then
      value="${value%\"}"; value="${value#\"}"
      value="${value%'}"; value="${value#'}"
      export SAFECLAW_API_KEY="$value"
      break
    fi
  done < .env
fi
if [[ -z "${SAFECLAW_API_KEY:-}" ]]; then
  printf '%s\n' 'SAFECLAW_API_KEY is required in the environment; it is never printed or persisted.' >&2
  exit 2
fi

for slot in slot-001 slot-002 slot-003; do
  batch="$VICTIM_ROOT/$slot"
  auth="$batch/authorization.json"
  "$PYTHON" - "$batch" "$auth" <<'PY'
import json, sys
from pathlib import Path
from stac_attack_lab.attack_program.file_io import write_json_exclusive
from stac_attack_lab.attack_program.r4_batch import authorization_text

batch, auth = map(Path, sys.argv[1:])
manifest = json.loads((batch / "manifest.json").read_text(encoding="utf-8"))
write_json_exclusive(
    auth,
    {
        "schema_version": "attack-r4-authorization/1",
        "scope": manifest["scope"],
        "manifest_hash": manifest["manifest_hash"],
        "text": authorization_text(manifest),
    },
    private=True,
    sort_keys=True,
    durable=True,
)
PY
  digest="$(sha256sum "$auth" | cut -d' ' -f1)"
  printf '%s\n' "$digest" > "$batch/authorization-sha256.txt"

  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-validate --batch "$batch" \
    > "$batch/validate.json" || { printf '%s\n' 'validate failed; stopping before bind' >&2; exit 1; }

  set +e
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-bind --batch "$batch" \
    --authorization "$auth" --authorization-sha256 "$digest" \
    --acknowledge-real-authorization > "$batch/bind.json"
  bind_code=$?
  set -e
  printf '%s\n' "$bind_code" > "$batch/bind-exit-code.txt"
  if [[ "$bind_code" -ne 0 ]]; then
    printf '%s\n' 'bind failed; stopping before any Victim request' >&2
    exit "$bind_code"
  fi

  set +e
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-run-batch --batch "$batch" \
    --authorization "$auth" --authorization-sha256 "$digest" \
    --acknowledge-real-authorization > "$batch/run.json"
  run_code=$?
  set -e
  printf '%s\n' "$run_code" > "$batch/run-exit-code.txt"
  "$PYTHON" -m stac_attack_lab.attack_program.cli r4-status --batch "$batch" \
    > "$batch/status-after-run.json" || true

  if [[ ! -f "$batch/execution/terminal.json" ]]; then
    printf '%s\n' 'terminal missing; request state is uncertain, stopping subsequent slots' >&2
    exit 1
  fi
  if [[ "$run_code" -ne 0 ]]; then
    printf '%s\n' 'run returned nonzero; terminal preserved, stopping subsequent slots for review' >&2
    exit "$run_code"
  fi
done

exit 0
