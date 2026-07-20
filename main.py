#!/usr/bin/env python3
"""
main.py
=======

File Integrity Monitoring (FIM) System - Command Line Interface.

Author: Kajja Owen
Cybersecurity Analyst | IT Support Specialist

A defensive security tool that creates a trusted baseline of files in a
monitored directory, then detects and reports unauthorized modifications,
additions, or deletions -- conceptually similar to enterprise File
Integrity Monitoring solutions such as Tripwire, OSSEC, and Wazuh.

USAGE
-----
    python main.py --create-baseline
    python main.py --scan
    python main.py --report
    python main.py --monitor
    python main.py --scan --directory monitored_directory
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from file_scanner import FileScanner
from hash_engine import HashEngine
from baseline_manager import BaselineManager
from integrity_checker import IntegrityChecker
from alert_manager import AlertManager
from report_generator import ReportGenerator

DEFAULT_CONFIG_PATH = "config.json"


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    """Load system configuration from a JSON file, exiting with a clear
    error message if the file is missing or malformed."""
    path = Path(config_path)
    if not path.exists():
        print(f"[ERROR] Configuration file '{config_path}' not found.")
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as error:
        print(f"[ERROR] Invalid JSON in configuration file: {error}")
        sys.exit(1)


def setup_logging(log_path: str) -> logging.Logger:
    """Configure logging to both a rotating log file and the console."""
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("FIM")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(file_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def run_create_baseline(config: dict, logger: logging.Logger) -> None:
    """Handle the --create-baseline command."""
    scanner = FileScanner(config)
    baseline_manager = BaselineManager(config)

    scanned_files = scanner.scan()
    if not scanned_files:
        logger.warning("No files found to baseline. Check monitor_directory in config.json.")

    baseline = baseline_manager.create_baseline(
        scanned_files, Path(config.get("monitor_directory", "monitored_directory"))
    )

    print(f"\nBaseline created successfully with {len(baseline)} file(s).")
    print(f"Baseline stored at: {config.get('baseline_path')}\n")


def run_scan(config: dict, logger: logging.Logger, generate_reports: bool = True) -> list[dict]:
    """Handle the --scan command. Returns the list of generated alerts."""
    scanner = FileScanner(config)
    baseline_manager = BaselineManager(config)
    checker = IntegrityChecker(config)
    alert_manager = AlertManager(config)

    baseline = baseline_manager.load_baseline()
    if not baseline:
        print("[ERROR] No baseline available. Run 'python main.py --create-baseline' first.")
        return []

    scanned_files = scanner.scan()
    integrity_results = checker.check(scanned_files, baseline)
    alerts = alert_manager.build_alerts(integrity_results)

    print(f"\nScan complete: {len(scanned_files)} file(s) scanned.")
    print(
        f"  Modified: {len(integrity_results['modified'])}   "
        f"New: {len(integrity_results['new'])}   "
        f"Deleted: {len(integrity_results['deleted'])}   "
        f"Unchanged: {integrity_results['unchanged_count']}\n"
    )

    if alerts:
        print(f"{len(alerts)} alert(s) generated:\n")
        for alert in alerts:
            print(AlertManager.format_alert_text(alert))
            print()
    else:
        print("No integrity violations detected. All monitored files match baseline.\n")

    if generate_reports:
        reporter = ReportGenerator(config)
        reporter.generate_json_report(alerts)
        reporter.generate_csv_report(alerts)
        reporter.generate_text_summary(len(scanned_files), integrity_results, alerts)
        print(f"Reports written to '{config.get('reports_directory')}'\n")

    return alerts


def run_report(config: dict, logger: logging.Logger) -> None:
    """Handle the --report command: run a fresh scan and generate reports."""
    run_scan(config, logger, generate_reports=True)


def run_monitor(config: dict, logger: logging.Logger) -> None:
    """Handle the --monitor command: continuously poll for changes."""
    interval = config.get("monitor_poll_interval_seconds", 5)
    print(f"Starting continuous monitoring (poll interval: {interval}s). Press Ctrl+C to stop.\n")

    try:
        while True:
            run_scan(config, logger, generate_reports=True)
            print(f"Sleeping for {interval} seconds before next scan...\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        logger.info("Continuous monitoring stopped by user (KeyboardInterrupt).")


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="File Integrity Monitoring (FIM) System - detect unauthorized "
        "file changes using cryptographic hashing.",
    )
    parser.add_argument(
        "--create-baseline", action="store_true", help="Create a new trusted baseline."
    )
    parser.add_argument(
        "--scan", action="store_true", help="Run a single integrity scan against the baseline."
    )
    parser.add_argument(
        "--report", action="store_true", help="Run a scan and generate JSON/CSV/text reports."
    )
    parser.add_argument(
        "--monitor", action="store_true", help="Continuously monitor for changes."
    )
    parser.add_argument(
        "--directory", type=str, default=None, help="Override the monitored directory path."
    )
    parser.add_argument(
        "--config", type=str, default=DEFAULT_CONFIG_PATH, help="Path to config.json."
    )
    return parser


def main() -> None:
    """Program entry point."""
    parser = build_arg_parser()
    args = parser.parse_args()

    config = load_config(args.config)

    if args.directory:
        config["monitor_directory"] = args.directory

    logger = setup_logging(config.get("log_path", "logs/fim.log"))

    if not any([args.create_baseline, args.scan, args.report, args.monitor]):
        parser.print_help()
        sys.exit(0)

    if args.create_baseline:
        run_create_baseline(config, logger)

    if args.scan and not args.report:
        run_scan(config, logger, generate_reports=True)

    if args.report:
        run_report(config, logger)

    if args.monitor:
        run_monitor(config, logger)


if __name__ == "__main__":
    main()
