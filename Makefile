.PHONY: help check lint typecheck test schemas \
	sample-preflight sample-collection formal-preflight formal-evaluation formal-report

PYTHON=.venv/bin/python
RUFF=.venv/bin/ruff
MYPY=$(PYTHON) -m mypy
PYTEST=$(PYTHON) -m pytest
PYTHONPATH=src

help:
	@printf '%s\n' \
		'Quality:' \
		'  make check                   Run lint, typecheck, and tests.' \
		'  make schemas                 Regenerate current JSON schemas.' \
		'' \
		'SafeClaw workflow:' \
		'  make sample-preflight        Check the canonical pilot.' \
		'  make sample-collection       Run/resume the canonical pilot.' \
		'  make formal-preflight        Check the formal environment.' \
		'  make formal-evaluation       Run/resume the formal matrix.' \
		'  make formal-report RUN_ROOT=experiments/safeclaw_runs/<run-id>'

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

sample-preflight:
	bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/pilot_collection.yaml --preflight-only

sample-collection:
	bash scripts/run_safeclaw_sample_collection.sh --config configs/sample_generation/pilot_collection.yaml

formal-preflight:
	bash scripts/run_formal_evaluation.sh --preflight-only

formal-evaluation:
	bash scripts/run_formal_evaluation.sh

formal-report:
	@test -n "$(RUN_ROOT)" || (printf '%s\n' 'RUN_ROOT is required.' >&2; exit 2)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli safeclaw report --run-root $(RUN_ROOT)
