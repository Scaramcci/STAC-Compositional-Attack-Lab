.PHONY: lint typecheck test smoke-offline smoke-online smoke-report smoke-shade schemas

PYTHON=.venv/bin/python
RUFF=.venv/bin/ruff
MYPY=$(PYTHON) -m mypy
PYTEST=$(PYTHON) -m pytest
PYTHONPATH=src

lint:
	$(RUFF) format --check .
	$(RUFF) check .

typecheck:
	$(MYPY) src

test:
	$(PYTEST)

schemas:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli schemas build

smoke-offline:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli offline build --config configs/experiments/mvp_offline.yaml
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli dataset audit --dataset data/generated/latest
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli dataset freeze --dataset data/generated/latest --version mvp-v0.1

smoke-online:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli online run --config configs/experiments/mvp_online.yaml --dataset-version mvp-v0.1

smoke-report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli report build --run-root experiments/runs/latest

smoke-shade:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli integration smoke-shade
