"""
Tests for Ghost Resource Tracker core engine.
Run: pytest tests/ -v
"""

import math
import time
from collections import deque
from unittest.mock import MagicMock, patch

import pytest

from ghost_tracker.core import (
    ProcessSnapshot,
    SystemPower,
    compute_entropy,
    compute_threat_score,
    update_baseline,
)


# ─── Entropy tests ────────────────────────────────────────────────────────────

class TestShannonEntropy:

    def test_empty_samples_returns_max_entropy(self):
        """Insufficient data → assume benign → max entropy."""
        samples = deque([10.0, 20.0, 30.0])  # < 5 samples
        result = compute_entropy(samples)
        assert result == pytest.approx(3.32, abs=0.01)

    def test_constant_load_low_entropy(self):
        """Cryptominer pattern: constant ~90% CPU → entropy near 0."""
        samples = deque([90.0] * 30)
        result = compute_entropy(samples)
        assert result < 0.5, f"Expected low entropy for constant load, got {result:.3f}"

    def test_variable_load_high_entropy(self):
        """Normal browser: variable CPU → entropy near max."""
        import random
        random.seed(42)
        samples = deque([random.uniform(0, 100) for _ in range(50)])
        result = compute_entropy(samples)
        assert result > 2.0, f"Expected high entropy for variable load, got {result:.3f}"

    def test_entropy_bounded(self):
        """Entropy is always in [0, log₂(10) ≈ 3.32]."""
        for load in [0.0, 25.0, 50.0, 75.0, 100.0]:
            samples = deque([load] * 20)
            result = compute_entropy(samples)
            assert 0.0 <= result <= 3.32 + 0.001

    def test_uniform_distribution_max_entropy(self):
        """10 samples spread evenly across all 10 buckets → max entropy."""
        samples = deque([5.0, 15.0, 25.0, 35.0, 45.0,
                         55.0, 65.0, 75.0, 85.0, 95.0])
        result = compute_entropy(samples)
        assert result == pytest.approx(math.log2(10), abs=0.01)


# ─── Baseline / z-score tests ─────────────────────────────────────────────────

class TestBaseline:

    def _make_snap(self, samples: list, current_cpu: float) -> ProcessSnapshot:
        snap = ProcessSnapshot(
            pid=1, name="test", exe="", status="running",
            cpu_percent=current_cpu, memory_mb=100,
            estimated_watts=0, net_bytes_sent=0, net_bytes_recv=0,
            parent_pid=None, parent_name="", children_pids=[],
            create_time=time.time(), username="user", cmdline="",
        )
        snap.cpu_samples = deque(samples, maxlen=30)
        return snap

    def test_z_score_zero_for_stable_process(self):
        """Process running consistently at 10% → z-score ≈ 0."""
        snap = self._make_snap([10.0] * 20, current_cpu=10.0)
        update_baseline(snap)
        assert snap.z_score == pytest.approx(0.0, abs=0.01)

    def test_z_score_high_for_spike(self):
        """Process suddenly at 90% after stable 10% → z-score > 3."""
        snap = self._make_snap([10.0] * 25 + [90.0], current_cpu=90.0)
        update_baseline(snap)
        assert snap.z_score > 3.0, f"Expected z > 3 for spike, got {snap.z_score:.2f}"

    def test_single_sample_no_crash(self):
        """Single sample should not raise and z-score defaults to 0."""
        snap = self._make_snap([50.0], current_cpu=50.0)
        update_baseline(snap)  # Should not raise
        assert snap.z_score == 0.0


# ─── Threat scoring tests ─────────────────────────────────────────────────────

class TestThreatScoring:

    def _snap(self, watts: float, entropy: float, z: float, net_kb: float = 0) -> ProcessSnapshot:
        snap = ProcessSnapshot(
            pid=999, name="suspicious", exe="/usr/local/bin/suspicious",
            status="running", cpu_percent=80.0, memory_mb=200,
            estimated_watts=watts, net_bytes_sent=net_kb * 512,
            net_bytes_recv=net_kb * 512, parent_pid=1,
            parent_name="launchd", children_pids=[],
            create_time=time.time() - 60, username="user", cmdline="",
        )
        snap.entropy_score = entropy
        snap.z_score = z
        # Populate samples so entropy/z are trusted
        snap.cpu_samples = deque([80.0] * 20, maxlen=30)
        snap.baseline_mean = 10.0
        snap.baseline_std = 5.0
        return snap

    def test_low_threat_safe_process(self):
        """Low watts, high entropy, no anomaly → DEFCON 1."""
        snap = self._snap(watts=0.1, entropy=3.0, z=0.5)
        score, level, reasons = compute_threat_score(snap)
        assert level == 1
        assert len(reasons) == 0

    def test_high_power_triggers_flag(self):
        """Process consuming > 5W → reason in list."""
        snap = self._snap(watts=8.0, entropy=2.0, z=1.0)
        _, _, reasons = compute_threat_score(snap)
        assert any("power" in r.lower() for r in reasons), f"No power reason: {reasons}"

    def test_low_entropy_triggers_flag(self):
        """Low entropy + sufficient samples → cryptominer flag."""
        snap = self._snap(watts=6.0, entropy=0.2, z=0.5)
        snap.cpu_samples = deque([85.0] * 20, maxlen=30)
        _, _, reasons = compute_threat_score(snap)
        assert any("entropy" in r.lower() for r in reasons), f"No entropy reason: {reasons}"

    def test_combined_indicators_defcon5(self):
        """High watts + low entropy + network + z-score → DEFCON 5."""
        snap = self._snap(watts=12.0, entropy=0.1, z=6.0, net_kb=1000)
        snap.cpu_samples = deque([90.0] * 20, maxlen=30)
        score, level, reasons = compute_threat_score(snap)
        assert level >= 4, f"Expected DEFCON 4+, got {level} (score={score:.1f})"

    def test_defcon_levels_monotone(self):
        """Higher threat scores should yield higher DEFCON levels."""
        snaps = [
            self._snap(watts=0.1, entropy=3.0, z=0.0),
            self._snap(watts=2.0, entropy=2.0, z=1.5),
            self._snap(watts=5.0, entropy=1.0, z=3.0),
            self._snap(watts=10.0, entropy=0.1, z=6.0, net_kb=1000),
        ]
        for s in snaps:
            s.cpu_samples = deque([80.0] * 20, maxlen=30)

        levels = [compute_threat_score(s)[1] for s in snaps]
        assert levels == sorted(levels), f"DEFCON levels not monotone: {levels}"


# ─── Ghost detection integration ──────────────────────────────────────────────

class TestGhostDetection:

    def test_ghost_log_populated_on_short_lived_process(self):
        """A process that vanishes within 10s should appear in ghost log."""
        from ghost_tracker.core import ProcessCollector

        collector = ProcessCollector()
        power = SystemPower(total_watts=10.0, cpu_watts=10.0)

        # First collect — includes PID 99999 (fake)
        fake_proc = MagicMock()
        fake_proc.info = {
            "pid": 99999, "name": "suspicious_script", "exe": "/tmp/evil.py",
            "status": "running", "cpu_percent": 85.0,
            "memory_info": MagicMock(rss=50 * 1024 ** 2),
            "net_connections": [], "ppid": 1, "create_time": time.time() - 2,
            "username": "root", "cmdline": ["/tmp/evil.py"], "num_threads": 1,
        }

        with patch("psutil.process_iter", return_value=[fake_proc]):
            with patch("psutil.cpu_percent", return_value=85.0):
                collector.collect(power)

        # Second collect — PID 99999 gone
        with patch("psutil.process_iter", return_value=[]):
            with patch("psutil.cpu_percent", return_value=5.0):
                collector.collect(power)

        assert len(collector.ghost_log) == 1
        assert collector.ghost_log[0]["name"] == "suspicious_script"
        assert collector.ghost_log[0]["lived_seconds"] < 15.0
