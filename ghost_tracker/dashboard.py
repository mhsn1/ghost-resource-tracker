"""
Ghost Resource Tracker — Terminal Dashboard
============================================
Rich-based live terminal UI with DEFCON threat visualization.
"""

from __future__ import annotations

import time
import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

from .core import ProcessCollector, SystemPower, get_system_power


# ─── Threat Level Styling ──────────────────────────────────────────────────────

DEFCON_CONFIG = {
    1: {"label": "DEFCON 1  SECURE",   "color": "bright_green",  "bar": "█"},
    2: {"label": "DEFCON 2  ELEVATED", "color": "yellow",         "bar": "█"},
    3: {"label": "DEFCON 3  GUARDED",  "color": "orange1",        "bar": "█"},
    4: {"label": "DEFCON 4  HIGH",     "color": "red",            "bar": "█"},
    5: {"label": "DEFCON 5  CRITICAL", "color": "bright_red",     "bar": "█"},
}

PROCESS_LIMIT = 20   # Max processes shown in the table


# ─── Notification ─────────────────────────────────────────────────────────────

def send_macos_notification(title: str, message: str, subtitle: str = "") -> None:
    """Send a native macOS notification via osascript."""
    if platform.system() != "Darwin":
        return
    script = (
        f'display notification "{message}" '
        f'with title "{title}" subtitle "{subtitle}"'
    )
    try:
        subprocess.run(["osascript", "-e", script],
                       capture_output=True, timeout=2)
    except Exception:
        pass


# ─── Dashboard Builder ─────────────────────────────────────────────────────────

class GhostDashboard:

    ALERT_COOLDOWN_S = 30  # Don't spam alerts for same PID

    def __init__(
        self,
        power_threshold_w: float = 5.0,
        log_dir: Optional[Path] = None,
        alert_on_defcon: int = 4,
    ):
        self.console = Console()
        self.collector = ProcessCollector(power_threshold_w)
        self.power_threshold = power_threshold_w
        self.alert_on_defcon = alert_on_defcon
        self.log_dir = log_dir or Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        self._alert_history: dict[int, float] = {}
        self._start_time = time.time()
        self._frame = 0
        self._max_threat_seen = 1
        self._last_system_power = SystemPower()

    # ── Panels ────────────────────────────────────────────────────────────────

    def _header_panel(self) -> Panel:
        elapsed = time.time() - self._start_time
        h, m, s = int(elapsed // 3600), int((elapsed % 3600) // 60), int(elapsed % 60)
        uptime = f"{h:02d}:{m:02d}:{s:02d}"
        now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

        title = Text()
        title.append("👻  GHOST RESOURCE TRACKER", style="bold bright_white")
        title.append(f"   ·   {now}   ·   uptime {uptime}", style="dim white")

        return Panel(Align.center(title), style="dim white", padding=(0, 2))

    def _system_panel(self, power: SystemPower) -> Panel:
        import psutil

        cpu_pct  = psutil.cpu_percent(interval=None)
        mem      = psutil.virtual_memory()
        mem_pct  = mem.percent
        swap     = psutil.swap_memory()

        def bar(pct: float, width: int = 20) -> Text:
            filled = int(pct / 100 * width)
            color = "bright_green" if pct < 60 else ("yellow" if pct < 80 else "red")
            t = Text()
            t.append("█" * filled, style=color)
            t.append("░" * (width - filled), style="dim white")
            t.append(f"  {pct:.1f}%", style="white")
            return t

        table = Table.grid(expand=True, padding=(0, 2))
        table.add_column(style="dim cyan", width=12)
        table.add_column()
        table.add_column(style="dim cyan", width=12)
        table.add_column()

        table.add_row("CPU",   bar(cpu_pct),  "RAM",    bar(mem_pct))
        table.add_row(
            "Power",
            Text(f"{power.cpu_watts:.1f} W CPU  /  {power.gpu_watts:.1f} W GPU  /  {power.total_watts:.1f} W total",
                 style="bright_yellow"),
            "Swap",
            Text(f"{swap.used / 1e9:.1f} GB / {swap.total / 1e9:.1f} GB", style="white"),
        )

        return Panel(table, title="[bold white]System Health", border_style="dim white")

    def _defcon_panel(self, level: int) -> Panel:
        cfg = DEFCON_CONFIG[level]
        color = cfg["color"]
        label = cfg["label"]
        bar_width = 40
        filled = int(level / 5 * bar_width)

        t = Text()
        t.append(f"\n  {label}\n\n", style=f"bold {color}")
        t.append("  [", style="dim white")
        t.append("█" * filled, style=color)
        t.append("░" * (bar_width - filled), style="dim white")
        t.append("]\n", style="dim white")
        t.append(f"\n  Max threat seen: DEFCON {self._max_threat_seen}", style="dim white")

        return Panel(t, title="[bold white]Threat Level", border_style=color)

    def _process_table(self, snapshots: list) -> Table:
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold dim white",
            expand=True,
            padding=(0, 1),
        )

        table.add_column("PID",      width=7,  style="dim white")
        table.add_column("Process",  width=22)
        table.add_column("CPU %",    width=7,  justify="right")
        table.add_column("RAM MB",   width=8,  justify="right")
        table.add_column("~Watts",   width=8,  justify="right")
        table.add_column("Entropy",  width=9,  justify="right")
        table.add_column("z-score",  width=8,  justify="right")
        table.add_column("DEFCON",   width=9,  justify="center")
        table.add_column("Flags",    min_width=20)

        shown = 0
        for snap in snapshots:
            if shown >= PROCESS_LIMIT:
                break

            cfg = DEFCON_CONFIG[snap.threat_level]
            color = cfg["color"]

            defcon_text = Text(str(snap.threat_level), style=f"bold {color}")

            # Flag summary (first reason, truncated)
            flag_str = snap.threat_reasons[0][:35] if snap.threat_reasons else ""
            flag_text = Text(flag_str, style="dim yellow" if snap.threat_reasons else "dim white")

            # Ghost indicator
            name_display = snap.name[:20]
            if snap.is_ghost:
                name_display = "👻 " + name_display[:18]

            name_text = Text(name_display, style=color if snap.threat_level >= 3 else "white")

            table.add_row(
                str(snap.pid),
                name_text,
                f"{snap.cpu_percent:.1f}",
                f"{snap.memory_mb:.0f}",
                f"{snap.estimated_watts:.2f}",
                f"{snap.entropy_score:.2f}",
                f"{snap.z_score:.1f}σ",
                defcon_text,
                flag_text,
            )
            shown += 1

        return table

    def _ghost_log_panel(self, ghosts: list) -> Panel:
        if not ghosts:
            content = Text("  No ghost processes detected this session", style="dim white")
        else:
            content = Table.grid(padding=(0, 2))
            content.add_column(style="dim red", width=10)
            content.add_column(style="white")
            content.add_column(style="dim white")
            for g in ghosts[-5:]:
                content.add_row(
                    g["name"][:10],
                    f"PID {g['pid']}  lived {g['lived_seconds']:.1f}s",
                    f"parent: {g['parent']}",
                )

        return Panel(
            content,
            title="[bold red]👻 Ghost Process Log",
            border_style="dim red",
        )

    # ── Alert System ──────────────────────────────────────────────────────────

    def _maybe_alert(self, snapshots: list) -> None:
        for snap in snapshots:
            if snap.threat_level < self.alert_on_defcon:
                continue
            last_alert = self._alert_history.get(snap.pid, 0)
            if time.time() - last_alert < self.ALERT_COOLDOWN_S:
                continue
            self._alert_history[snap.pid] = time.time()
            reason = snap.threat_reasons[0] if snap.threat_reasons else "Anomalous behavior"
            send_macos_notification(
                title=f"🚨 DEFCON {snap.threat_level} — Ghost Tracker",
                subtitle=f"Process: {snap.name} (PID {snap.pid})",
                message=reason[:100],
            )
            self._log_alert(snap)

    def _log_alert(self, snap) -> None:
        log_file = self.log_dir / "alerts.jsonl"
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "defcon": snap.threat_level,
            "pid": snap.pid,
            "name": snap.name,
            "exe": snap.exe,
            "cpu_percent": snap.cpu_percent,
            "estimated_watts": snap.estimated_watts,
            "entropy": snap.entropy_score,
            "z_score": snap.z_score,
            "reasons": snap.threat_reasons,
        }
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    # ── Main render ───────────────────────────────────────────────────────────

    def _render(self) -> Layout:
        power = get_system_power()
        self._last_system_power = power
        snapshots = self.collector.collect(power)

        # Determine overall system DEFCON
        system_defcon = max((s.threat_level for s in snapshots), default=1)
        self._max_threat_seen = max(self._max_threat_seen, system_defcon)

        self._maybe_alert(snapshots)

        layout = Layout()
        layout.split_column(
            Layout(self._header_panel(),   name="header",  size=3),
            Layout(name="middle",          ratio=2),
            Layout(name="table",           ratio=5),
            Layout(self._ghost_log_panel(self.collector.ghost_log), name="ghost", size=8),
        )
        layout["middle"].split_row(
            Layout(self._system_panel(power), name="system", ratio=3),
            Layout(self._defcon_panel(system_defcon), name="defcon", ratio=1),
        )
        layout["table"].update(
            Panel(
                self._process_table(snapshots),
                title=f"[bold white]Process Monitor  ·  {len(snapshots)} processes",
                border_style="dim white",
            )
        )

        self._frame += 1
        return layout

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self, refresh_rate: float = 2.0) -> None:
        self.console.clear()
        try:
            with Live(
                self._render(),
                console=self.console,
                refresh_per_second=1 / refresh_rate,
                screen=True,
            ) as live:
                while True:
                    time.sleep(refresh_rate)
                    live.update(self._render())
        except KeyboardInterrupt:
            self.console.print("\n[dim]Ghost Tracker stopped. Stay secure.[/dim]")
