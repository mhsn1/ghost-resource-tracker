# Contributing to Ghost Resource Tracker

Thank you for your interest in contributing. This document covers everything you need to get started.

---

## Code of Conduct

Be respectful. This is a security research tool — contributions must be defensive in nature. No offensive capabilities will be merged.

---

## How to Contribute

### Reporting Bugs

Open an issue with:
- macOS version and Python version
- Full error traceback
- Steps to reproduce
- What you expected vs what happened

### Suggesting Features

Open an issue tagged `enhancement`. Describe:
- The security problem it solves
- The scientific/mathematical basis (if detection-related)
- How it fits the existing architecture

### Submitting Code

1. Fork the repository
2. Create a branch: `git checkout -b feat/your-feature-name`
3. Write your code
4. Add tests in `tests/`
5. Run the test suite: `pytest tests/ -v`
6. Commit with a clear message (see format below)
7. Push and open a Pull Request

---

## Commit Message Format

```
type: short description (max 72 chars)

Optional longer explanation.
```

Types:
- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `test:` — adding or updating tests
- `refactor:` — code change with no feature/fix
- `perf:` — performance improvement

Examples:
```
feat: add Apple Silicon M-series power estimation via powermetrics
fix: correct z-score calculation for processes with zero variance
docs: add entropy explanation to README
```

---

## Architecture

```
ghost_tracker/
├── core.py       # Analysis engine — NO new dependencies here
│                 # Only stdlib + psutil allowed
├── dashboard.py  # Terminal UI — rich library
├── cli.py        # Argument parsing — entry point only
└── __init__.py   # Version info
```

**Rule:** `core.py` must stay dependency-free (stdlib + psutil only).
All UI concerns belong in `dashboard.py`.

---

## Adding a Detection Heuristic

Every new heuristic in `core.py` must:

1. Have a clear mathematical or statistical basis — document it in a docstring
2. Have a unit test in `tests/test_core.py`
3. Be weighted into `compute_threat_score()` with justification for the weight
4. Not produce false positives on common macOS system processes

Example structure:
```python
def my_new_signal(proc: ProcessSnapshot) -> float:
    """
    Short description.

    Mathematical basis:
      formula here

    Returns: score in [0, 100]
    """
    ...
```

---

## Running Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install psutil rich pytest
pytest tests/ -v
```

---

## Questions

Open a Discussion on GitHub — not an Issue.
