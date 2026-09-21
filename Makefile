.PHONY: help check lint typecheck test schemas capability-demo doctor-benign benign-prepare \
	legacy-sample-preflight legacy-sample-collection sample-preflight sample-collection \
	formal-preflight formal-evaluation formal-report

PYTHON ?= python3
RUFF=$(PYTHON) -m ruff
MYPY=$(PYTHON) -m mypy
PYTEST=PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $(PYTHON) -m pytest
PYTHONPATH=src

help:
	@printf '%s\n' \
		'Quality:' \
		'  make check                   Run lint, typecheck, and tests.' \
		'  make schemas                 Regenerate current JSON schemas.' \
		'' \
		'SafeClaw workflow:' \
		'  make capability-demo RUN_ID=<id>  Run the nine-primitive fake/offline loop.' \
		'  make doctor-benign           Offline diagnosis of the disabled benign pilot.' \
		'  make benign-prepare          Create a disabled benign preparation snapshot.' \
		'  make legacy-sample-preflight Check the legacy adversarial pilot.' \
		'  make legacy-sample-collection Run/resume legacy adversarial collection.' \
		'  make formal-preflight        Check the formal environment.' \
		'  make formal-evaluation       Run/resume the formal matrix.' \
		'  make formal-report RUN_ROOT=experiments/runs/<run-id>'

check: lint typecheck test

lint:
	$(RUFF) format --check .
	$(RUFF) check .

typecheck:
	$(MYPY) src

test:
	$(PYTEST) -q

schemas:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli schemas build

capability-demo:
	@test -n "$(RUN_ID)" || (printf '%s\n' 'RUN_ID is required.' >&2; exit 2)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli capability demo \
		--config configs/capability/f1_status_acceptance.json \
		--output experiments/runs/capability/$(RUN_ID)

doctor-benign:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli doctor --workflow-kind benign_collection --config configs/benign_collection/live_pilot.disabled.json

benign-prepare:
	@test -n "$(RUN_ID)" || (printf '%s\n' 'RUN_ID is required.' >&2; exit 2)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli benign prepare --config configs/benign_collection/live_pilot.disabled.json --run-id $(RUN_ID)

legacy-sample-preflight:
	bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/pilot_collection.yaml --preflight-only

legacy-sample-collection:
	bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/pilot_collection.yaml

# Compatibility aliases. Both retain legacy adversarial semantics.
sample-preflight: legacy-sample-preflight

sample-collection: legacy-sample-collection

formal-preflight:
	bash scripts/run_formal_evaluation.sh --preflight-only

formal-evaluation:
	bash scripts/run_formal_evaluation.sh

formal-report:
	@test -n "$(RUN_ROOT)" || (printf '%s\n' 'RUN_ROOT is required.' >&2; exit 2)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli safeclaw report --run-root $(RUN_ROOT)
