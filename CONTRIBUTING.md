# Contributing to Logscan

Thanks for helping improve Logscan!

## Setup

```bash
git clone https://github.com/essvega/Logscan.git && cd Logscan
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional
```

## Before opening a pull request

```bash
pytest --cov
ruff check . && ruff format --check .
mypy
```

## Guidelines

- Keep the runtime free of third-party dependencies; development tools are fine.
- Python 3.9 must keep working (CI tests 3.9–3.13 on Linux, macOS and Windows).
- Every bug fix comes with a test that fails without it. For extraction bugs, add the offending log line
  (redacted) to `tests/test_extract.py`.
- Never include real customer logs or private addresses you are not allowed to share in tests or issues.
- Update `README.md` and `CHANGELOG.md` when behaviour or options change.
