.PHONY: help check lint typecheck test schemas doctor demo-r2 demo-r3

PYTHON ?= python3
RUFF=$(PYTHON) -m ruff
MYPY=$(PYTHON) -m mypy
PYTEST=PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 $(PYTHON) -m pytest

help:
	@printf '%s\n' 'make check' 'make schemas' 'make doctor' 'make demo-r2 RUN_ID=<id>' 'make demo-r3 RUN_ID=<id>'

check: lint typecheck test

lint:
	$(RUFF) format --check .
	$(RUFF) check .

typecheck:
	$(MYPY) src

test:
	$(PYTEST) -q

schemas:
	PYTHONPATH=src $(PYTHON) -m stac_attack_lab.schema_registry

doctor:
	PYTHONPATH=src $(PYTHON) -m stac_attack_lab.cli doctor

demo-r2:
	@test -n "$(RUN_ID)" || (printf '%s\n' 'RUN_ID is required.' >&2; exit 2)
	STAC_PYTHON=$(PYTHON) bash scripts/attack_program/10_demo_r2.sh --output experiments/runs/attack-program/$(RUN_ID)

demo-r3:
	@test -n "$(RUN_ID)" || (printf '%s\n' 'RUN_ID is required.' >&2; exit 2)
	STAC_PYTHON=$(PYTHON) bash scripts/attack_program/11_demo_r3.sh --output experiments/runs/attack-program/$(RUN_ID)
