.PHONY: lint typecheck test smoke-offline smoke-online smoke-report smoke-shade schemas schemas-v2 smoke-sample-library sample-collect-preflight sample-collect safeclaw-preflight formal-sample-freeze formal-evaluation formal-report

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
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli dataset freeze --dataset data/generated/latest --version smoke-v0.1

smoke-online:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli online run --config configs/experiments/mvp_online.yaml --dataset-version mvp-v0.1

smoke-report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli report build --run-root experiments/runs/latest

smoke-shade:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli integration smoke-shade
schemas-v2: schemas

smoke-sample-library:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample attack-build --config configs/sample_generation/formal_v1.yaml
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample audit --library data/primitive_libraries/generated/formal-v2-attack-synthetic/library

sample-collect-preflight:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample collect-preflight --config configs/sample_generation/safeclaw_adversarial_v1.yaml

sample-collect:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample collect --config configs/sample_generation/safeclaw_adversarial_v1.yaml
safeclaw-preflight:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli safeclaw preflight --config configs/environments/safeclaw_openclaw_v1.yaml

formal-sample-freeze: smoke-sample-library
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli sample freeze --library data/primitive_libraries/generated/formal-v2-attack-synthetic/library --version formal-v2-attack-synthetic

formal-evaluation:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli safeclaw run --config configs/experiments/safeclaw_formal_v1.yaml

formal-report:
	PYTHONPATH=$(PYTHONPATH) $(PYTHON) -m stac_attack_lab.cli safeclaw formal-report --run-root $(RUN_ROOT)
