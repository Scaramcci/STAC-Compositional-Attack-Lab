#!/usr/bin/env bash
# Run once from a dedicated tmux session. Never resume a launched run.
set -Eeuo pipefail
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PYTHONPATH="$PWD/src"
PY="${STAC_PYTHON:-/home/scarramcci/miniconda3/envs/stac/bin/python}"
export STAC_REVALIDATION_RUN="construction-cross-session-$(date +%Y%m%d-%H%M%S)-$("$PY" -c 'import uuid; print(uuid.uuid4().hex[:8])')"
R="experiments/runs/$STAC_REVALIDATION_RUN"
mkdir "$R"
exec > >(tee "$R/workflow.log") 2>&1
echo "RUN_ROOT=$PWD/$R"
finish() { echo "workflow_exit=$? RUN_ROOT=$PWD/$R"; }
trap finish EXIT

stage() {
  local name="$1" result
  shift
  if "$@" > "$R/$name.log" 2>&1; then result=0; else result=$?; fi
  cat "$R/$name.log"
  printf '%s\t%s\n' "$name" "$result" >> "$R/exit_codes.tsv"
  return "$result"
}

# Full quality gate; failure stops before any collection.
git rev-parse HEAD > "$R/head.txt"
git diff --binary > "$R/worktree.patch"
git status --short > "$R/worktree-status.txt"
stage quality-check make check PYTHON="$PY"

# Derive fresh identities; do not copy the old launch marker or results.
"$PY" - <<'PY'
import json
import os
import shutil
from pathlib import Path

run = os.environ['STAC_REVALIDATION_RUN']
r = Path('experiments/runs') / run
old = Path('experiments/runs/construction-cross-session-20260915-133610-ed850eda')
c = json.loads((old / 'runtime_config.json').read_text())
c.update(pipeline_id=run, output_root=str(r), execution_enabled=True)
assert c['source_task_ids'] == ['pse-2.1-002'] and c['seeds'] == [20260827]
expected = dict(attacker_decision_budget=16, attacker_request_budget=48,
                attacker_http_502_retries=2, provider_request_budget=40,
                embedding_request_budget=12, max_wall_time_seconds=1800,
                max_sessions=4, max_turns=12, max_actions=24,
                max_tool_calls=36, max_tokens=384000, max_events=450,
                max_collection_trajectories=1, target_accepted_samples=1,
                provider_timeout_seconds=90, timeout_seconds=600)
assert all(c[k] == v for k, v in expected.items())
import yaml
model = yaml.safe_load(Path(c['construction_attacker_model_config_path']).read_text())
assert model['model'] == 'gpt-5.6-sol' and model['timeout_seconds'] == 60
(r / 'runtime_config.json').write_text(json.dumps(c, indent=2) + '\n')
review = json.loads((old / 'configuration_review.json').read_text())
review.update(run_id=run, batch_id=run, quality='See this run quality-check.log and exit_codes.tsv')
(r / 'configuration_review.json').write_text(json.dumps(review, indent=2) + '\n')
(r / 'provenance.json').write_text(json.dumps({'head': (r / 'head.txt').read_text().strip()}, indent=2) + '\n')
for name in ('launch_once.py', 'summarize.py'):
    shutil.copyfile(old / name, r / name)
print(json.dumps(review, indent=2))
PY
stage preflight "$PY" -m stac_attack_lab.cli sample collect-preflight --config "$R/runtime_config.json"

# Native 1800-second deadline retains the normal abort/finish cleanup path.
# A partial collection must still go through offline evidence processing.
stage construction "$PY" -u "$R/launch_once.py" || true
C="$R/single-construction/interactions/raw/$STAC_REVALIDATION_RUN"
stage normalize-mine "$PY" -m stac_attack_lab.cli sample mine --collection "$C" --output "$R/mining" || true
stage audit "$PY" -m stac_attack_lab.cli sample audit --library "$R/mining/library" || true
stage admission "$PY" -m stac_attack_lab.cli sample admission --collection "$C" --library "$R/mining/library" || true
stage summary "$PY" "$R/summarize.py" || true
echo 'All stages attempted; inspect individual exit codes (workflow completion is not admission).'
cat "$R/exit_codes.tsv"
