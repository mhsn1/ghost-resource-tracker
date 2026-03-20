# Changelog

All notable changes to Ghost Resource Tracker are documented here.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`

---

## [1.0.0] — 2026-03-20

### Initial Release

**Core detection engine (`core.py`)**
- Power-to-Process ratio estimation using CPU share × device TDP
- Shannon entropy scoring per process (30-sample rolling window)
- Welford's online algorithm for per-process CPU baseline (mean + std dev)
- z-score anomaly detection (flags deviations > 3σ from baseline)
- Network × Power correlation scoring
- Multi-factor DEFCON threat scorer (weighted: power 35%, entropy 25%, network 20%, z-score 20%)
- Ghost process detection — logs processes that live under 10 seconds
- Process genealogy (parent → child chain tracking)

**Terminal dashboard (`dashboard.py`)**
- Live Rich-based terminal UI with 2-second refresh
- DEFCON 1–5 threat level display with color coding
- System health panel (CPU %, RAM %, power, swap)
- Process table sorted by threat score (top 20)
- Ghost Process Log panel
- macOS native notifications via `osascript`
- JSONL alert log output to `logs/alerts.jsonl`

**CLI (`cli.py`)**
- `--threshold` — configurable power threshold in watts
- `--defcon` — minimum DEFCON level for notifications
- `--refresh` — dashboard refresh rate
- `--log-dir` — custom log directory
- `--export-snapshot` — one-shot JSON forensic export
- `--verbose` — debug logging

**Infrastructure**
- `pyproject.toml` packaging (setuptools)
- GitHub Actions CI (macOS, Python 3.10/3.11/3.12)
- `install.sh` one-line installer
- MIT License
- Full test suite with pytest

---

## Upcoming — [1.1.0]

- Apple Silicon M-series native power via `powermetrics`
- Known malware process signature database
- CSV export
- Homebrew tap
