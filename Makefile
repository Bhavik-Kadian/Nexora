# SecureGate: common tasks.
#   make setup      create .venv (Python 3.12) and install SecureGate with its dev tools
#   make test       run the tests (the demo scorecard is printed at the end)
#   make lint       check code style with ruff
#   make check      lint + test (run this before every commit)
#   make demo       build the demo repo with planted secrets in ../securegate-demo
#   make scan-demo  scan the demo repo; SecureGate exits 1 there because it finds secrets
#                   to block, so make reports "Error 1"
#   make ui         open the dashboard on the demo scan (http://127.0.0.1:5000, Ctrl+C stops)
#   make menu       open SecureGate's menu: scan, see the rules and open the dashboard without
#                   typing commands (what Start SecureGate.cmd opens; Q quits)
#   make sample-report  write sample_findings.json (about 20 findings) for the designers
#   make hooks      install the laptop gate: scan staged changes before every commit
#   make docs-pdf   rebuild docs/pdf/*.pdf from docs/*.md (needs Edge or Chrome)
#
# Works from PowerShell, cmd and Git Bash on Windows, and from macOS/Linux shells.
# Use another interpreter with:  make setup PYTHON=python3

ifeq ($(OS),Windows_NT)
PYTHON := py -3.12
VENV_PY := .venv/Scripts/python.exe
else
PYTHON := python3.12
VENV_PY := .venv/bin/python
endif

DEMO_DIR := ../securegate-demo

.PHONY: setup test lint check demo scan-demo ui menu sample-report hooks docs-pdf

setup:
	$(PYTHON) -m venv .venv
	"$(VENV_PY)" -m pip install --upgrade pip
	"$(VENV_PY)" -m pip install -e ".[dev]"

test:
	"$(VENV_PY)" -m pytest

lint:
	"$(VENV_PY)" -m ruff check .
	"$(VENV_PY)" -m ruff format --check .

check: lint test

demo:
	"$(VENV_PY)" -m securegate demo-repo --out "$(DEMO_DIR)" --seed 42 --force

scan-demo:
	"$(VENV_PY)" -m securegate scan "$(DEMO_DIR)" --mode repo --out findings-demo.json

ui:
	"$(VENV_PY)" -m securegate ui --report findings-demo.json --open

menu:
	"$(VENV_PY)" -m securegate menu

sample-report:
	"$(VENV_PY)" -m securegate sample-report --out sample_findings.json

hooks:
	"$(VENV_PY)" -m pre_commit install --install-hooks

docs-pdf:
	"$(VENV_PY)" tools/docs_pdf.py
