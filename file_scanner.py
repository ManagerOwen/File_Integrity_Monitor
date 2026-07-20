"""
file_scanner.py
================

File discovery module for the File Integrity Monitoring (FIM) System.

Responsible for recursively walking a monitored directory tree and 
collecting metadata (path, size, extension, modification time) for every
file that is not explicitly excluded by configuration. This module does
NOT compute hashes -- that responsibility belongs to hash_engine.py, in
keeping with the single-responsibility principle and modular design.
"""

import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("FIM")


class FileScanner:
    """Discovers files within a monitored directory, honoring exclusion
    rules defined in the system configuration."""

    def __init__(self, config: dict):
        self.monitor_directory = Path(config.get("monitor_directory", "monitored_directory"))
        self.excluded_extensions = set(
            ext.lower() for ext in config.get("excluded_extensions", [])
        )
        self.excluded_files = set(config.get("excluded_files", []))

    def _is_excluded(self, file_path: Path) -> bool:
        """Determine whether a file should be skipped based on configured
        exclusion rules (extension or exact filename)."""
        if file_path.name in self.excluded_files:
            return True
        if file_path.suffix.lower() in self.excluded_extensions:
            return True
        return False

    def scan(self) -> list[dict]:
        """
        Recursively scan the monitored directory.

        Returns:
            A list of dictionaries, one per discovered file, containing:
                - path: string path relative to the monitored directory
                - file: file name
                - size: size in bytes
                - extension: file extension (lowercase)
                - modified: last modified timestamp (ISO-like string)
        """
        if not self.monitor_directory.exists():
            logger.error("Monitored directory '%s' does not exist.", self.monitor_directory)
            return []

        discovered_files = []

        for path in sorted(self.monitor_directory.rglob("*")):
            if not path.is_file():
                continue
            if self._is_excluded(path):
                logger.debug("Skipping excluded file: %s", path)
                continue

            try:
                stat_result = path.stat()
            except OSError as error:
                logger.error("Could not stat file '%s': %s", path, error)
                continue

            relative_path = path.relative_to(self.monitor_directory)

            discovered_files.append(
                {
                    "path": str(relative_path),
                    "file": path.name,
                    "size": stat_result.st_size,
                    "extension": path.suffix.lower(),
                    "modified": datetime.fromtimestamp(
                        stat_result.st_mtime
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }
            )

        logger.info(
            "File scan complete: %d file(s) discovered in '%s'.",
            len(discovered_files),
            self.monitor_directory,
        )
        return discovered_files
