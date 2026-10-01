.PHONY: setup lint test report bench ci audit

setup:
	python -m pip install -e ".[dev]"

lint:
	python -m ruff check .
	python -m ruff format --check .

test:
	python -m pytest -q

# Per-rule detection table (attack events caught, benign events flagged); exits 1 on any failure.
report:
	python -m detection_as_code.cli

bench: report

# Known vulnerabilities in the installed dependencies.
audit:
	python -m pip_audit --skip-editable

ci: setup lint test report
