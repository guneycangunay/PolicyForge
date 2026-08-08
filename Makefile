PYTHON ?= python3

.PHONY: test check run clean

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

check:
	$(PYTHON) -m compileall -q src tests

run:
	PYTHONPATH=src $(PYTHON) -m policyforge.server

clean:
	rm -rf build dist .coverage htmlcov .pytest_cache .ruff_cache
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +
