.PHONY: help check lint typecheck test schemas synthetic-library \
	sample-preflight sample-collection formal-preflight formal-evaluation formal-report \
	legacy-smoke-offline legacy-smoke-online legacy-smoke-report legacy-smoke-shade

PYTHON=.venv/bin/python
RUFF=.venv/bin/ruff
MYPY=$(PYTHON) -m mypy
PYTEST=$(PYTHON) -m pytest
PYTHONPATH=src

help:
	@printf '%s\n' \
		'Quality:' \
		'  make check                   Run lint, typecheck, and tests.' \
		'  make schemas                 Regenerate JSON schemas.' \
		'' \
		'Current SafeClaw formal-v2 workflow:' \
		'  make sample-preflight CONFIG=<versioned-config>' \
		'  make sample-collection CONFIG=<authorized-versioned-config>' \
		'  make formal-preflight        Run official PSE and environment checks.' \
		'  make formal-evaluation       Run/resume the gated 15-case evaluation.' \
		'  make formal-report RUN_ROOT=experiments/safeclaw_runs/<run-id>' \
		'' \
		'Legacy and synthetic targets are retained for regression only.'

check: lint typecheck test

lint:
	$(RUFF) format --check .
	$(RUFF) check .

typecheck:
	$(MYPY) src

test:
	$(PYTEST)

schemas:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli schemas build

synthetic-library:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample attack-build --config configs/sample_generation/formal_v1.yaml
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample audit --library data/primitive_libraries/generated/formal-v2-attack-synthetic/library

sample-preflight:
	@test -n "$(CONFIG)" || (printf '%s\n' 'CONFIG is required.' >&2; exit 2)
	bash scripts/run_safeclaw_sample_collection.sh --config $(CONFIG) --preflight-only

sample-collection:
	@test -n "$(CONFIG)" || (printf '%s\n' 'CONFIG is required.' >&2; exit 2)
	bash scripts/run_safeclaw_sample_collection.sh --config $(CONFIG)

formal-preflight:
	bash scripts/run_formal_evaluation.sh --preflight-only

formal-evaluation:
	bash scripts/run_formal_evaluation.sh

formal-report:
	@test -n "$(RUN_ROOT)" || (printf '%s\n' 'RUN_ROOT is required.' >&2; exit 2)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli safeclaw formal-report --run-root $(RUN_ROOT)

legacy-smoke-offline:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli offline build --config configs/experiments/mvp_offline.yaml

legacy-smoke-online:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli online run --config configs/experiments/mvp_online.yaml --dataset-version mvp-v0.1

legacy-smoke-report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli report build --run-root experiments/runs/latest

legacy-smoke-shade:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli integration smoke-shade
