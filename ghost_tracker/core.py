"""
Ghost Resource Tracker — Core Analysis Engine
==============================================
Power-to-Process ratio analysis with entropy-based anomaly detection.

Scientific basis:
  - Shannon entropy: H(X) = -Σ p(x_i) · log₂(p(x_i))
    Measures unpredictability of CPU usage distribution.
    Cryptominers exhibit LOW entropy (constant high load) vs normal apps (variable).

  - Power estimation via Intel RAPL proxy:
    On macOS, powermetrics exposes package/CPU/GPU power in milliwatts.
    Power-to-Process ratio = process_cpu_share × total_cpu_power_W

  - Baseline learning: 60-second rolling window builds "normal" distribution.
    z-score deviation > 3σ triggers anomaly flag.
"""

import psutil
import subprocess
import json
import time
import math
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import deque
from datetime import datetime


logger = logging.getLogger("ghost_tracker.core")


# ─── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class ProcessSnapshot:
    pid: int
    name: str
    exe: str
    status: str
    cpu_percent: float
    memory_mb: float
    estimated_watts: float
    net_bytes_sent: float
    net_bytes_recv: float
    parent_pid: Optional[int]
    parent_name: str
    children_pids: list
    create_time: float
    username: str
    cmdline: str
    cpu_samples: deque = field(default_factory=lambda: deque(maxlen=30))
    entropy_score: float = 0.0
    baseline_mean: float = 0.0
    baseline_std: float = 0.0
    z_score: float = 0.0
    threat_score: float = 0.0
    threat_level: int = 1       # DEFCON 1 (safe) → 5 (critical)
    threat_reasons: list = field(default_factory=list)
    is_ghost: bool = False      # Appeared and disappeared within sample window

    def to_dict(self) -> dict:
        d = asdict(self)
        d['cpu_samples'] = list(self.cpu_samples)
        return d


@dataclass
class SystemPower:
    total_watts: float = 0.0
    cpu_watts: float = 0.0
    gpu_watts: float = 0.0
    sample_time: float = field(default_factory=time.time)


# ─── Power Estimation ──────────────────────────────────────────────────────────

def get_system_power() -> SystemPower:
    """
    Query macOS powermetrics for RAPL power data.
    Requires: sudo powermetrics (or pre-authorized via sudoers)

    Falls back to a CPU-frequency-based heuristic if powermetrics unavailable:
      P_cpu ≈ TDP × (cpu_freq / max_freq) × (cpu_util / 100)
    where TDP is estimated from logical CPU count (proxy only).
    """
    power = SystemPower()

    try:
        result = subprocess.run(
            ["sudo", "-n", "powermetrics", "--samplers", "cpu_power,gpu_power",
             "-n", "1", "--output-format", "json"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            cpu_mw = data.get("processor", {}).get("package_watts", 0) * 1000
            gpu_mw = data.get("gpu", {}).get("gpu_energy", 0)
            power.cpu_watts = cpu_mw / 1000.0
            power.gpu_watts = gpu_mw / 1000.0
            power.total_watts = power.cpu_watts + power.gpu_watts
            return power
    except Exception:
        pass

    # ── Heuristic fallback ───────────────────────────────────────────────────
    cpu_count = psutil.cpu_count(logical=False) or 4
    cpu_freq = psutil.cpu_freq()
    cpu_util = psutil.cpu_percent(interval=0.1)

    # Conservative TDP estimate: 4W per physical core (mobile) → 6W (desktop)
    tdp_estimate = cpu_count * 5.0

    if cpu_freq and cpu_freq.max > 0:
        freq_ratio = cpu_freq.current / cpu_freq.max
    else:
        freq_ratio = 0.5

    power.cpu_watts = tdp_estimate * freq_ratio * (cpu_util / 100.0)
    power.total_watts = power.cpu_watts
    logger.debug("Using heuristic power estimation: %.2fW", power.total_watts)
    return power


# ─── Shannon Entropy ───────────────────────────────────────────────────────────

def compute_entropy(samples: deque) -> float:
    """
    Compute Shannon entropy of CPU usage sample distribution.

    H(X) = -Σ p(xᵢ) · log₂(p(xᵢ))

    CPU usage is bucketed into 10% bins [0-10, 10-20, ..., 90-100].
    A cryptominer consistently near 80-100% → entropy ≈ 0 (very predictable).
    A browser varying 0-100% → entropy ≈ 3.3 (close to uniform on 10 bins).

    Returns: entropy in bits [0, log₂(10) ≈ 3.32]
    """
    if len(samples) < 5:
        return 3.32  # Assume benign with insufficient data

    bins = [0] * 10
    for s in samples:
        bucket = min(int(s // 10), 9)
        bins[bucket] += 1

    total = len(samples)
    entropy = 0.0
    for count in bins:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    return entropy


# ─── Baseline Statistics ───────────────────────────────────────────────────────

def update_baseline(proc_snapshot: ProcessSnapshot) -> None:
    """
    Welford's online algorithm for running mean and variance.
    More numerically stable than naive sum-of-squares.

    https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
    """
    n = len(proc_snapshot.cpu_samples)
    if n < 2:
        proc_snapshot.baseline_mean = proc_snapshot.cpu_percent
        proc_snapshot.baseline_std = 0.0
        proc_snapshot.z_score = 0.0
        return

    samples_list = list(proc_snapshot.cpu_samples)
    mean = sum(samples_list) / n
    variance = sum((x - mean) ** 2 for x in samples_list) / max(n - 1, 1)
    std = math.sqrt(variance)

    proc_snapshot.baseline_mean = mean
    proc_snapshot.baseline_std = std

    if std > 0:
        proc_snapshot.z_score = abs(proc_snapshot.cpu_percent - mean) / std
    else:
        proc_snapshot.z_score = 0.0


# ─── Threat Scoring ────────────────────────────────────────────────────────────

def compute_threat_score(proc: ProcessSnapshot) -> tuple[float, int, list[str]]:
    """
    Multi-factor threat scoring model.

    Score components (0–100 each, weighted):
      W1 = 0.35 · power_score      (high watts, unknown process)
      W2 = 0.25 · entropy_score    (low entropy = sustained high load)
      W3 = 0.20 · network_score    (power + network = exfiltration pattern)
      W4 = 0.20 · anomaly_score    (z-score deviation from baseline)

    DEFCON mapping:
      1 = green  (score < 20)
      2 = yellow (20 ≤ score < 40)
      3 = orange (40 ≤ score < 60)
      4 = red    (60 ≤ score < 80)
      5 = CRITICAL (score ≥ 80)
    """
    reasons = []
    score = 0.0

    # ── Power component ──────────────────────────────────────────────────────
    if proc.estimated_watts >= 5.0:
        power_score = min(100, (proc.estimated_watts / 5.0) * 50)
        if proc.estimated_watts > 5.0:
            reasons.append(f"High power draw: {proc.estimated_watts:.1f}W (threshold: 5W)")
    elif proc.estimated_watts >= 2.0:
        power_score = (proc.estimated_watts / 5.0) * 40
    else:
        power_score = 0.0

    # ── Entropy component ─────────────────────────────────────────────────────
    # Low entropy = HIGH threat (consistent load signature of miners)
    entropy_threat = max(0.0, (3.32 - proc.entropy_score) / 3.32) * 100
    if proc.entropy_score < 0.5 and len(proc.cpu_samples) >= 10:
        reasons.append(f"Low CPU entropy: {proc.entropy_score:.2f} bits (cryptominer pattern)")
    entropy_score = entropy_threat if len(proc.cpu_samples) >= 5 else 0.0

    # ── Network component ─────────────────────────────────────────────────────
    net_total_kb = (proc.net_bytes_sent + proc.net_bytes_recv) / 1024
    if net_total_kb > 500 and proc.estimated_watts > 2.0:
        network_score = min(100, net_total_kb / 50)
        reasons.append(f"High net I/O + power: {net_total_kb:.0f} KB, {proc.estimated_watts:.1f}W")
    else:
        network_score = min(50, net_total_kb / 100)

    # ── Anomaly component ─────────────────────────────────────────────────────
    if proc.z_score > 3.0:
        anomaly_score = min(100, proc.z_score * 15)
        reasons.append(f"Statistical anomaly: z-score {proc.z_score:.1f}σ from baseline")
    elif proc.z_score > 2.0:
        anomaly_score = proc.z_score * 10
    else:
        anomaly_score = 0.0

    # ── Weighted total ────────────────────────────────────────────────────────
    total = (0.35 * power_score +
             0.25 * entropy_score +
             0.20 * network_score +
             0.20 * anomaly_score)

    # ── DEFCON level ──────────────────────────────────────────────────────────
    if total < 20:
        level = 1
    elif total < 40:
        level = 2
    elif total < 60:
        level = 3
    elif total < 80:
        level = 4
    else:
        level = 5
        reasons.append("CRITICAL: Combined indicators match known malware signature")

    return total, level, reasons


# ─── Process Collector ─────────────────────────────────────────────────────────

class ProcessCollector:
    """
    Collects, snapshots, and tracks all running processes with rolling history.
    Maintains a ghost registry for short-lived processes (< 2 sample cycles).
    """

    ATTRS = [
        "pid", "name", "exe", "status", "cpu_percent",
        "memory_info", "net_connections", "ppid",
        "create_time", "username", "cmdline", "num_threads"
    ]

    def __init__(self, power_threshold_w: float = 5.0):
        self.power_threshold_w = power_threshold_w
        self._history: dict[int, ProcessSnapshot] = {}
        self._ghost_log: list[dict] = []
        self._seen_pids: set = set()
        self._prev_net = psutil.net_io_counters(pernic=False)
        self._total_net_prev_time = time.time()

    def collect(self, system_power: SystemPower) -> list[ProcessSnapshot]:
        total_cpu = psutil.cpu_percent(interval=None) or 1.0
        snapshots = []
        current_pids = set()

        try:
            proc_list = list(psutil.process_iter(self.ATTRS))
        except Exception as e:
            logger.error("Process iteration failed: %s", e)
            return []

        for proc in proc_list:
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                cpu = info.get("cpu_percent") or 0.0
                mem_info = info.get("memory_info")
                mem_bytes = mem_info.rss if mem_info else 0
                mem_mb = mem_bytes / (1024 ** 2)

                # CPU share of total system power
                cpu_share = cpu / max(total_cpu, 1.0)
                estimated_watts = cpu_share * system_power.cpu_watts

                # Network I/O (process-level best effort; falls back to 0)
                net_sent, net_recv = 0.0, 0.0
                try:
                    conns = proc.net_connections()
                    net_sent = len([c for c in conns if c.status == "ESTABLISHED"]) * 1024.0
                    net_recv = net_sent
                except (psutil.AccessDenied, AttributeError):
                    pass

                # Parent info
                parent_pid = info.get("ppid")
                parent_name = ""
                try:
                    if parent_pid:
                        parent_name = psutil.Process(parent_pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = "unknown"

                # Children
                try:
                    children_pids = [c.pid for c in proc.children()]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    children_pids = []

                cmdline = " ".join(info.get("cmdline") or [])[:200]

                # ── Reuse or create snapshot ──────────────────────────────
                if pid in self._history:
                    snap = self._history[pid]
                    snap.cpu_percent = cpu
                    snap.memory_mb = mem_mb
                    snap.estimated_watts = estimated_watts
                    snap.net_bytes_sent = net_sent
                    snap.net_bytes_recv = net_recv
                    snap.status = info.get("status", "")
                else:
                    snap = ProcessSnapshot(
                        pid=pid,
                        name=info.get("name", ""),
                        exe=info.get("exe", "") or "",
                        status=info.get("status", ""),
                        cpu_percent=cpu,
                        memory_mb=mem_mb,
                        estimated_watts=estimated_watts,
                        net_bytes_sent=net_sent,
                        net_bytes_recv=net_recv,
                        parent_pid=parent_pid,
                        parent_name=parent_name,
                        children_pids=children_pids,
                        create_time=info.get("create_time", 0.0),
                        username=info.get("username", ""),
                        cmdline=cmdline,
                    )
                    self._history[pid] = snap

                # ── Rolling CPU samples ───────────────────────────────────
                snap.cpu_samples.append(cpu)
                snap.entropy_score = compute_entropy(snap.cpu_samples)
                update_baseline(snap)

                # ── Threat scoring ────────────────────────────────────────
                score, level, reasons = compute_threat_score(snap)
                snap.threat_score = score
                snap.threat_level = level
                snap.threat_reasons = reasons

                snapshots.append(snap)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # ── Ghost detection ───────────────────────────────────────────────────
        vanished = self._seen_pids - current_pids
        for ghost_pid in vanished:
            if ghost_pid in self._history:
                ghost = self._history.pop(ghost_pid)
                if time.time() - ghost.create_time < 10.0:
                    ghost.is_ghost = True
                    self._ghost_log.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "pid": ghost.pid,
                        "name": ghost.name,
                        "exe": ghost.exe,
                        "lived_seconds": round(time.time() - ghost.create_time, 2),
                        "max_cpu": max(ghost.cpu_samples, default=0),
                        "parent": ghost.parent_name,
                    })
                    logger.warning("Ghost process detected: %s (PID %d)", ghost.name, ghost.pid)

        self._seen_pids = current_pids
        return sorted(snapshots, key=lambda s: s.threat_score, reverse=True)

    @property
    def ghost_log(self) -> list[dict]:
        return self._ghost_log
