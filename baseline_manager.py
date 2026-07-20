"""
baseline_manager.py
====================

Baseline management module for the File Integrity Monitoring (FIM) System.

A "baseline" is the trusted, known-good snapshot of every monitored file's
hash and metadata at a specific point in time. This is the security
reference point: all future scans are compared against the baseline to
detect drift (unauthorized modification, deletion, or addition of files).

SECURITY NOTE: In a real production deployment, the baseline file itself
should be protected with strict file permissions, stored on read-only or
write-once media, and ideally signed/hashed separately, so that an
attacker who modifies a monitored file cannot simply edit the baseline to
hide their tracks. This project stores the baseline as a local JSON file
for portfolio/demo purposes, but the README calls out this limitation and
how it would be hardened in production.
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from hash_engine import HashEngine

logger = logging.getLogger("FIM")


class BaselineManager:
    """Creates, loads, and updates the trusted baseline of file states."""

    def __init__(self, config: dict):
        self.baseline_path = Path(config.get("baseline_path", "baseline/baseline.json"))
        self.hash_engine = HashEngine(config.get("hash_algorithm", "sha256"))

    def create_baseline(self, scanned_files: list[dict], monitor_directory: Path) -> dict:
        """
        Build a new trusted baseline from a freshly scanned file list and
        write it to disk.

        Args:
            scanned_files: Output of FileScanner.scan().
            monitor_directory: Root directory the relative paths are under.

        Returns:
            The baseline dictionary that was written to disk.
        """
        baseline = {}

        for entry in scanned_files:
            full_path = monitor_directory / entry["path"]
            file_hash = self.hash_engine.calculate_hash(full_path)

            if file_hash is None:
                logger.warning("Skipping '%s' in baseline (unreadable).", entry["path"])
                continue

            baseline[entry["path"]] = {
                "hash": file_hash,
                "size": entry["size"],
                "extension": entry["extension"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

        self._write_baseline(baseline)
        logger.info(
            "Baseline created with %d file(s) at '%s'.", len(baseline), self.baseline_path
        )
        return baseline

    def load_baseline(self) -> dict:
        """
        Load the existing baseline from disk.

        Returns:
            The baseline dictionary, or an empty dict if no baseline
            exists yet (e.g. first run, before --create-baseline).
        """
        if not self.baseline_path.exists():
            logger.warning(
                "No baseline found at '%s'. Run --create-baseline first.",
                self.baseline_path,
            )
            return {}

        try:
            with open(self.baseline_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as error:
            logger.error("Failed to load baseline: %s", error)
            return {}

    def update_baseline(self, new_baseline: dict) -> None:
        """
        Overwrite the stored baseline with a new trusted state. Typically
        called after a scan's findings have been manually reviewed and
        approved as legitimate changes.
        """
        self._write_baseline(new_baseline)
        logger.info("Baseline updated at '%s'.", self.baseline_path)

    def _write_baseline(self, baseline: dict) -> None:
        """Internal helper to persist the baseline dictionary as JSON."""
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2)
