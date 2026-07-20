"""
hash_engine.py
==============

Cryptographic Hash Engine for the File Integrity Monitoring (FIM) System.

SECURITY RATIONALE
-------------------
File Integrity Monitoring relies on cryptographic hash functions (such as
SHA-256) to produce a fixed-length "fingerprint" of a file's contents.

Why hashes matter for security:

1. DETERMINISM   - The same file content always produces the same hash.
                    If a file's content changes even by a single bit, the
                    resulting hash changes completely (the "avalanche
                    effect"). This makes hashes ideal for detecting
                    unauthorized or unexpected modifications.

2. COLLISION      - SHA-256 is a cryptographically secure hash function,
   RESISTANCE       meaning it is computationally infeasible for an
                    attacker to craft two different files that produce the
                    same hash. This prevents attackers from tampering with
                    a file while keeping its "fingerprint" unchanged.

3. ONE-WAY         Hashes cannot be reversed to recover the original file
   FUNCTION         content, so storing hashes in a baseline does not
                    expose sensitive file contents.

4. LOW STORAGE      Instead of storing full copies of every monitored
   OVERHEAD          file (which would be expensive and could itself be
                    tampered with), FIM tools store only the small hash
                    value, which is compared against freshly computed
                    hashes during each scan.

This is exactly how enterprise tools such as Tripwire, OSSEC, and Wazuh
detect unauthorized changes to critical system files, configuration
files, and executables.
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger("FIM")

# Files are read in fixed-size chunks to avoid loading very large files
# entirely into memory at once.
CHUNK_SIZE = 65536  # 64 KB


class HashEngine:
    """Computes cryptographic hashes for files using a configurable
    hashing algorithm (default: SHA-256)."""

    SUPPORTED_ALGORITHMS = {
        "sha256": hashlib.sha256,
        "sha1": hashlib.sha1,
        "md5": hashlib.md5,  # included for compatibility only; NOT
                              # recommended for security-critical use
    }

    def __init__(self, algorithm: str = "sha256"):
        algorithm = algorithm.lower()
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            logger.warning(
                "Unsupported hash algorithm '%s' requested, defaulting to sha256",
                algorithm,
            )
            algorithm = "sha256"
        self.algorithm = algorithm

    def calculate_hash(self, file_path: Path) -> str | None:
        """
        Calculate the cryptographic hash of a single file.

        Args:
            file_path: Path to the target file.

        Returns:
            The hex digest string of the file's hash, or None if the file
            could not be read (e.g. permissions error, file removed
            mid-scan, broken symlink).
        """
        hasher = self.SUPPORTED_ALGORITHMS[self.algorithm]()

        try:
            with open(file_path, "rb") as f:
                # Stream the file in chunks so large files do not exhaust
                # memory. This mirrors how production FIM agents handle
                # multi-gigabyte files (e.g. log archives, disk images).
                for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()

        except (OSError, PermissionError) as error:
            logger.error("Could not hash file '%s': %s", file_path, error)
            return None

    def verify_hash(self, file_path: Path, expected_hash: str) -> bool:
        """
        Verify that a file's current hash matches an expected hash value.

        Args:
            file_path: Path to the file being verified.
            expected_hash: The known-good (baseline) hash to compare against.

        Returns:
            True if the current hash matches expected_hash, False otherwise.
        """
        current_hash = self.calculate_hash(file_path)
        if current_hash is None:
            return False
        return current_hash == expected_hash
