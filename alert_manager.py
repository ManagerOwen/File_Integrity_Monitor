"""
alert_manager.py
=================

Alert generation and severity classification module for the File
Integrity Monitoring (FIM) System.

This module takes raw integrity events (modified / new / deleted files)
produced by integrity_checker.py and turns them into structured,
human-readable security alerts with an assigned severity level and
recommended response actions -- similar to how a SIEM or SOC playbook
would triage findings.

SEVERITY MODEL
--------------
LOW      - Routine, low-risk changes (e.g. non-sensitive file updates).
MEDIUM   - Unexpected file creation that is not obviously malicious.
HIGH     - Modification of sensitive/config files, or executable changes.
CRITICAL - System file modification, suspicious new executables, or a
           burst of multiple unauthorized changes in a single scan
           (a common indicator of automated/malicious activity such as
           ransomware or a dropper script).
"""

import logging
from datetime import datetime

logger = logging.getLogger("FIM")

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Mapping of event types to illustrative MITRE ATT&CK techniques.
# This is a simplified, educational mapping intended to demonstrate
# awareness of threat frameworks used in real SOC environments.
MITRE_MAPPING = {
    "MODIFIED": "T1565 - Data Manipulation",
    "DELETED": "T1070 - Indicator Removal",
    "NEW_EXECUTABLE": "T1547 - Boot or Logon Autostart Execution",
}

RECOMMENDATIONS = {
    "MODIFIED": [
        "Verify change authorization with the responsible team.",
        "Investigate recent user and process activity on the host.",
        "Review system and application logs around the timestamp.",
        "Check the file and host for signs of malware infection.",
    ],
    "NEW": [
        "Confirm whether the new file was part of an approved change.",
        "Scan the new file with an up-to-date antivirus/EDR engine.",
        "Review process creation logs for the file's origin.",
    ],
    "NEW_EXECUTABLE": [
        "Treat as a potential malware dropper until proven otherwise.",
        "Isolate the host from the network pending investigation.",
        "Submit the file hash to a threat intelligence platform.",
        "Review autorun/startup locations for persistence mechanisms.",
    ],
    "DELETED": [
        "Confirm whether deletion was part of an authorized maintenance task.",
        "Check for signs of anti-forensic activity (log/indicator removal).",
        "Restore the file from a known-good backup if unauthorized.",
    ],
}


class AlertManager:
    """Classifies integrity events by severity and generates structured
    alert records."""

    def __init__(self, config: dict):
        self.sensitive_files = set(config.get("sensitive_files", []))
        self.executable_extensions = set(
            ext.lower() for ext in config.get("executable_extensions", [])
        )
        self.critical_multi_change_threshold = config.get(
            "critical_multi_change_threshold", 3
        )

    def _classify_modified(self, file_path: str) -> str:
        """Classify severity of a MODIFIED file event."""
        extension = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""

        if file_path in self.sensitive_files:
            return "HIGH"
        if extension in self.executable_extensions:
            return "HIGH"
        if extension in {".conf", ".cfg", ".ini", ".yaml", ".yml", ".json"}:
            return "HIGH"
        return "LOW"

    def _classify_new(self, file_path: str) -> str:
        """Classify severity of a NEW file event."""
        extension = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        if extension in self.executable_extensions:
            return "CRITICAL"
        return "MEDIUM"

    def _classify_deleted(self, file_path: str) -> str:
        """Classify severity of a DELETED file event."""
        if file_path in self.sensitive_files or "system" in file_path.lower():
            return "CRITICAL"
        return "HIGH"

    def build_alerts(self, integrity_results: dict) -> list[dict]:
        """
        Convert integrity_checker results into a list of structured alert
        dictionaries, ordered by descending severity.

        Args:
            integrity_results: dict with keys 'modified', 'new', 'deleted'
                                (each a list of file path strings or event dicts).

        Returns:
            List of alert dictionaries.
        """
        alerts = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for event in integrity_results.get("modified", []):
            severity = self._classify_modified(event["path"])
            alerts.append(
                {
                    "event_type": "MODIFIED FILE",
                    "file": event["path"],
                    "severity": severity,
                    "previous_hash": event.get("baseline_hash"),
                    "current_hash": event.get("current_hash"),
                    "timestamp": timestamp,
                    "mitre_attack": MITRE_MAPPING["MODIFIED"],
                    "recommendation": RECOMMENDATIONS["MODIFIED"],
                }
            )

        for event in integrity_results.get("new", []):
            extension = "." + event["path"].rsplit(".", 1)[-1].lower() if "." in event["path"] else ""
            is_executable = extension in self.executable_extensions
            severity = self._classify_new(event["path"])
            alerts.append(
                {
                    "event_type": "NEW FILE",
                    "file": event["path"],
                    "severity": severity,
                    "previous_hash": None,
                    "current_hash": event.get("current_hash"),
                    "timestamp": timestamp,
                    "mitre_attack": MITRE_MAPPING["NEW_EXECUTABLE"] if is_executable else "N/A",
                    "recommendation": RECOMMENDATIONS["NEW_EXECUTABLE"]
                    if is_executable
                    else RECOMMENDATIONS["NEW"],
                }
            )

        for event in integrity_results.get("deleted", []):
            severity = self._classify_deleted(event["path"])
            alerts.append(
                {
                    "event_type": "DELETED FILE",
                    "file": event["path"],
                    "severity": severity,
                    "previous_hash": event.get("baseline_hash"),
                    "current_hash": None,
                    "timestamp": timestamp,
                    "mitre_attack": MITRE_MAPPING["DELETED"],
                    "recommendation": RECOMMENDATIONS["DELETED"],
                }
            )

        # Escalate to CRITICAL if a burst of unauthorized changes occurred
        # in a single scan -- a common indicator of automated/malicious
        # activity (e.g. ransomware sweeping a directory).
        total_changes = len(alerts)
        if total_changes >= self.critical_multi_change_threshold:
            for alert in alerts:
                if SEVERITY_ORDER[alert["severity"]] < SEVERITY_ORDER["CRITICAL"]:
                    alert["severity"] = "CRITICAL"
                    alert["recommendation"] = alert["recommendation"] + [
                        f"NOTE: {total_changes} changes detected in a single scan -- "
                        "escalated due to possible mass unauthorized activity."
                    ]

        alerts.sort(key=lambda a: SEVERITY_ORDER[a["severity"]], reverse=True)

        for alert in alerts:
            logger.warning(
                "%s detected: %s [Severity: %s]",
                alert["event_type"],
                alert["file"],
                alert["severity"],
            )

        return alerts

    @staticmethod
    def format_alert_text(alert: dict) -> str:
        """Render a single alert as the formatted plain-text block used
        in console output and the text incident summary report."""
        lines = [
            "=====================================",
            "FILE INTEGRITY ALERT",
            "=====================================",
            "",
            "Event Type:",
            alert["event_type"],
            "",
            "File:",
            alert["file"],
            "",
            "Severity:",
            alert["severity"],
            "",
        ]

        if alert.get("previous_hash"):
            lines += ["Previous Hash:", "", alert["previous_hash"], ""]
        if alert.get("current_hash"):
            lines += ["Current Hash:", "", alert["current_hash"], ""]

        lines += [
            "Timestamp:",
            alert["timestamp"],
            "",
            "MITRE ATT&CK Reference:",
            alert.get("mitre_attack", "N/A"),
            "",
            "Recommendation:",
            "",
        ]
        lines += [f"- {rec}" for rec in alert["recommendation"]]
        lines += ["", "====================================="]

        return "\n".join(lines)
