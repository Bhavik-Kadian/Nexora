# SecureGate: common tasks.
#   make setup   create .venv (Python 3.12) and install SecureGate with its dev tools
#   make test    run the tests
#   make lint    check code style with ruff
#   make check   lint + test (run this before every commit)
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

.PHONY: setup test lint check

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
