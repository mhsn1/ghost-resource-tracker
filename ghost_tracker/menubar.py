"""
Ghost Resource Tracker — macOS Menu Bar App
Pure pyobjc implementation (no rumps dependency)
"""

import objc
from AppKit import (
    NSApplication, NSStatusBar, NSMenu, NSMenuItem,
    NSVariableStatusItemLength, NSObject, NSTimer, NSApp
)
import psutil
import math
from collections import deque
from datetime import datetime


TDP_WATTS = 28.0
_cpu_history: dict = {}

DEFCON_LABEL = {
    1: "🟢 DEFCON 1 — SECURE",
    2: "🟡 DEFCON 2 — ELEVATED",
    3: "🟠 DEFCON 3 — GUARDED",
    4: "🔴 DEFCON 4 — HIGH RISK",
    5: "⚠️ DEFCON 5 — CRITICAL",
}


def _entropy(samples):
    if len(samples) < 5:
        return 3.32
    bins = [0] * 10
    for s in samples:
        bins[min(int(s // 10), 9)] += 1
    total = len(samples)
    h = 0.0
    for c in bins:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def get_stats():
    cpu_pct = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    watts = min(cpu_pct / 100.0, 1.0) * TDP_WATTS

    procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info"]):
        try:
            info = proc.info
            pid = info["pid"]
            cpu = info["cpu_percent"] or 0.0

            if pid not in _cpu_history:
                _cpu_history[pid] = deque(maxlen=30)
            _cpu_history[pid].append(cpu)

            cpu_share = min(cpu / max(cpu_pct, 1.0), 1.0)
            pw = cpu_share * TDP_WATTS
            entropy = _entropy(_cpu_history[pid])

            score = 0.0
            if pw >= 5.0:
                score += 35 * min(1.0, pw / 10.0)
            score += 25 * max(0.0, (3.32 - entropy) / 3.32)
            level = (1 if score < 20 else 2 if score < 40 else
                     3 if score < 60 else 4 if score < 80 else 5)

            procs.append({
                "name": (info["name"] or "")[:24],
                "cpu": cpu,
                "watts": pw,
                "level": level,
            })
        except Exception:
            continue

    procs.sort(key=lambda x: x["level"] * 100 + x["watts"], reverse=True)
    defcon = max((p["level"] for p in procs[:20]), default=1)

    return {
        "cpu_pct": cpu_pct,
        "mem_used": mem.used / 1e9,
        "mem_total": mem.total / 1e9,
        "watts": watts,
        "defcon": defcon,
        "procs": procs[:5],
        "time": datetime.now().strftime("%H:%M:%S"),
    }


class AppDelegate(NSObject):

    def applicationDidFinishLaunching_(self, notification):
        self.statusItem = (NSStatusBar.systemStatusBar()
                           .statusItemWithLength_(NSVariableStatusItemLength))
        self.statusItem.setTitle_("👻")
        self.statusItem.setHighlightMode_(True)

        self.menu = NSMenu.alloc().init()
        self.statusItem.setMenu_(self.menu)

        self.defcon_item = self._make_item("Loading...")
        self.time_item   = self._make_item("")
        self.cpu_item    = self._make_item("")
        self.ram_item    = self._make_item("")
        self.power_item  = self._make_item("")
        self.proc_items  = [self._make_item("") for _ in range(5)]

        self.menu.addItem_(self.defcon_item)
        self.menu.addItem_(self.time_item)
        self.menu.addItem_(NSMenuItem.separatorItem())
        self.menu.addItem_(self.cpu_item)
        self.menu.addItem_(self.ram_item)
        self.menu.addItem_(self.power_item)
        self.menu.addItem_(NSMenuItem.separatorItem())
        self.menu.addItem_(self._make_item("⚡ Top Processes", enabled=False))
        for p in self.proc_items:
            self.menu.addItem_(p)
        self.menu.addItem_(NSMenuItem.separatorItem())

        open_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Open Full Dashboard", "openDashboard:", "")
        open_item.setTarget_(self)
        self.menu.addItem_(open_item)
        self.menu.addItem_(NSMenuItem.separatorItem())

        quit_item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            "Quit Ghost Tracker", "terminate:", "")
        quit_item.setTarget_(NSApp)
        self.menu.addItem_(quit_item)

        psutil.cpu_percent(interval=0.5)

        NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            3.0, self, "refreshStats:", None, True)
        self.refreshStats_(None)

    def _make_item(self, title, enabled=True):
        item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, None, "")
        item.setEnabled_(enabled)
        return item

    @objc.python_method
    def _icons(self):
        return {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴", 5: "⚠️"}

    def refreshStats_(self, timer):
        try:
            s = get_stats()
            d = s["defcon"]
            icons = {1: "🟢", 2: "🟡", 3: "🟠", 4: "🔴", 5: "⚠️"}

            self.statusItem.setTitle_(f"👻 {icons[d]}")
            self.defcon_item.setTitle_(DEFCON_LABEL[d])
            self.time_item.setTitle_(f"Updated: {s['time']}")
            self.cpu_item.setTitle_(f"CPU:    {s['cpu_pct']:.1f}%")
            self.ram_item.setTitle_(
                f"RAM:    {s['mem_used']:.1f} GB / {s['mem_total']:.1f} GB")
            self.power_item.setTitle_(f"Power:  ~{s['watts']:.1f} W")

            for i, item in enumerate(self.proc_items):
                if i < len(s["procs"]):
                    p = s["procs"][i]
                    e = icons[p["level"]]
                    item.setTitle_(
                        f"  {e} {p['name']:<22} {p['cpu']:>5.1f}%  ~{p['watts']:.1f}W")
                else:
                    item.setTitle_("  —")
        except Exception as ex:
            self.defcon_item.setTitle_(f"Error: {str(ex)[:40]}")

    def openDashboard_(self, sender):
        import subprocess
        import os
        proj = os.path.expanduser("~/Downloads/ghost-resource-tracker")
        script = f'''tell application "Terminal"
            activate
            do script "cd '{proj}' && source .venv/bin/activate && python3 -m ghost_tracker.cli"
        end tell'''
        subprocess.run(["osascript", "-e", script])


def main():
    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(1)  # Accessory — no Dock icon
    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)
    app.run()


if __name__ == "__main__":
    main()