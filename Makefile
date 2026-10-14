# Developer shortcuts. `make help` lists them. Everything runs offline.
PY ?= python
.DEFAULT_GOAL := help

help:  ## list targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

install:  ## editable install with dev tools
	$(PY) -m pip install -e ".[dev]"

lint:  ## ruff
	ruff check .

test:  ## unit, property, integration tests (no network, no API key)
	$(PY) -m pytest -q

cov:  ## tests with coverage; fails under 90%
	$(PY) -m pytest -q --cov --cov-report=term --cov-report=json:coverage.json

evals:  ## labelled evals, dev and held-out, with the CI gates
	$(PY) evals/build_cases.py --check
	$(PY) evals/run_evals.py --no-categories --min-accuracy 0.97 --max-unsafe-allow 20 --max-over-block 20
	$(PY) evals/run_evals.py --split heldout --no-categories --min-accuracy 0.97

sweep:  ## threshold frontier: unsafe ALLOW vs over-BLOCK, dev vs held-out
	$(PY) evals/run_evals.py --sweep

injection:  ## prompt-injection evaluation (exit 1 if the verdict invariant breaks)
	$(PY) evals/injection_eval.py

cases:  ## regenerate evals/cases.jsonl from the seeded templates
	$(PY) evals/build_cases.py > evals/cases.jsonl

docs:  ## regenerate docs/RULES.md and the generated README blocks
	$(PY) scripts/gen_rules_doc.py
	$(PY) scripts/update_readme.py

docs-check:  ## fail if generated docs are stale
	$(PY) scripts/gen_rules_doc.py --check
	$(PY) scripts/update_readme.py --check

diagrams:  ## re-render docs/diagrams/*.mmd to SVG (needs node; see the script header)
	./scripts/render_diagrams.sh

live:  ## opt-in tests against a real mainnet node: TXWARDEN_LIVE_RPC=https://... make live
	$(PY) -m pytest -m live -v

check: lint cov evals injection docs-check  ## everything CI runs

docker:  ## build the image
	docker build -t txwarden .

clean:
	rm -rf .pytest_cache .ruff_cache .coverage coverage.json htmlcov build dist src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

.PHONY: help install lint test cov evals sweep injection cases docs docs-check diagrams live check docker clean
