"""
Ghost Resource Tracker — CLI Entry Point
"""

import argparse
import sys
import logging
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        prog="ghost-tracker",
        description="Ghost Resource Tracker — detect hidden power-hungry processes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ghost-tracker                        # Start with defaults
  ghost-tracker --threshold 3.0        # Alert on > 3W unknown processes
  ghost-tracker --defcon 3             # Alert at DEFCON 3 and above
  ghost-tracker --refresh 1.0          # 1-second refresh rate
  ghost-tracker --log-dir ./my-logs    # Custom log directory
  ghost-tracker --export-snapshot      # Dump current state to JSON and exit
        """,
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=5.0,
        metavar="WATTS",
        help="Power draw threshold in watts to flag a process (default: 5.0)",
    )
    parser.add_argument(
        "--defcon",
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=4,
        metavar="LEVEL",
        help="Minimum DEFCON level to trigger macOS notification (default: 4)",
    )
    parser.add_argument(
        "--refresh",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Dashboard refresh interval in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("logs"),
        metavar="PATH",
        help="Directory to write alert and ghost logs (default: ./logs)",
    )
    parser.add_argument(
        "--export-snapshot",
        action="store_true",
        help="Export a one-shot JSON snapshot of all processes and exit",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging to stderr",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ghost-tracker 1.0.0",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    else:
        logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    if args.export_snapshot:
        _export_snapshot(args)
        return

    from ghost_tracker.dashboard import GhostDashboard
    dashboard = GhostDashboard(
        power_threshold_w=args.threshold,
        log_dir=args.log_dir,
        alert_on_defcon=args.defcon,
    )
    dashboard.run(refresh_rate=args.refresh)


def _export_snapshot(args):
    import json
    from ghost_tracker.core import ProcessCollector, get_system_power
    from datetime import datetime

    power = get_system_power()
    collector = ProcessCollector(args.threshold)
    snapshots = collector.collect(power)

    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "system_power": {
            "cpu_watts": power.cpu_watts,
            "gpu_watts": power.gpu_watts,
            "total_watts": power.total_watts,
        },
        "processes": [s.to_dict() for s in snapshots],
        "ghost_log": collector.ghost_log,
    }

    print(json.dumps(output, indent=2, default=str))


if __name__ == "__main__":
    main()
