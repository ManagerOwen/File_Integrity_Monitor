"""
integrity_checker.py
=====================

Core comparison engine for the File Integrity Monitoring (FIM) System.

This module compares the CURRENT state of the monitored directory
against the trusted BASELINE state to detect three categories of
integrity events:

    1. MODIFIED - a file exists in both baseline and current scan, but
                   its hash differs.
    2. NEW      - a file exists in the current scan but was not present
                   in the baseline (unexpected/unauthorized addition).
    3. DELETED  - a file exists in the baseline but is missing from the
                   current scan (unexpected/unauthorized removal, or
                   possible anti-forensic activity).
"""

import logging
from pathlib import Path

from hash_engine import HashEngine

logger = logging.getLogger("FIM")


class IntegrityChecker:
    """Compares current filesystem state against a trusted baseline."""

    def __init__(self, config: dict):
        self.hash_engine = HashEngine(config.get("hash_algorithm", "sha256"))
        self.monitor_directory = Path(config.get("monitor_directory", "monitored_directory"))

    def check(self, scanned_files: list[dict], baseline: dict) -> dict:
        """
        Compare freshly scanned files against the trusted baseline.

        Args:
            scanned_files: Output of FileScanner.scan().
            baseline: Trusted baseline dict, as produced by BaselineManager.

        Returns:
            dict with keys:
                - modified: list of {"path", "baseline_hash", "current_hash"}
                - new:      list of {"path", "current_hash"}
                - deleted:  list of {"path", "baseline_hash"}
                - unchanged_count: int
        """
        modified, new, deleted = [], [], []
        current_paths = set()

        for entry in scanned_files:
            relative_path = entry["path"]
            current_paths.add(relative_path)
            full_path = self.monitor_directory / relative_path
            current_hash = self.hash_engine.calculate_hash(full_path)

            if current_hash is None:
                logger.error("Skipping unreadable file during check: %s", relative_path)
                continue

            if relative_path not in baseline:
                # File was not present when the baseline was created.
                new.append({"path": relative_path, "current_hash": current_hash})
                continue

            baseline_hash = baseline[relative_path]["hash"]
            if current_hash != baseline_hash:
                modified.append(
                    {
                        "path": relative_path,
                        "baseline_hash": baseline_hash,
                        "current_hash": current_hash,
                    }
                )

        # Any baseline entry whose path was not seen in the current scan
        # has been deleted (or moved/renamed, which appears as a delete +
        # new pair -- consistent with how most FIM tools report renames).
        for baseline_path, baseline_data in baseline.items():
            if baseline_path not in current_paths:
                deleted.append(
                    {"path": baseline_path, "baseline_hash": baseline_data["hash"]}
                )

        unchanged_count = len(current_paths) - len(modified) - len(new)

        logger.info(
            "Integrity check complete: %d modified, %d new, %d deleted, %d unchanged.",
            len(modified),
            len(new),
            len(deleted),
            unchanged_count,
        )

        return {
            "modified": modified,
            "new": new,
            "deleted": deleted,
            "unchanged_count": unchanged_count,
        }
