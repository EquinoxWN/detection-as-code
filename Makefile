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
# Known vulnerabilities in the installed dependencies.
# Ignored: diskcache 5.6.3 (PYSEC-2026-2447 / CVE-2025-69872 / GHSA-w8v5-vhqr-4h9v), pickle loading from its
# cache folder, no fixed release yet. Only pySigma's optional ATT&CK cache uses it; this project never loads
# that module, which test_vulnerable_diskcache_is_never_loaded enforces.
audit:
	python -m pip_audit --skip-editable --cache-dir .tmp/pip-audit --ignore-vuln PYSEC-2026-2447 --ignore-vuln GHSA-w8v5-vhqr-4h9v

ci: setup lint test report
