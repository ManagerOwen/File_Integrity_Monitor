"""
report_generator.py
====================

Security reporting module for the File Integrity Monitoring (FIM) System.

Produces three report formats commonly expected in SOC / incident
response workflows:

    - JSON  : machine-readable, suitable for ingestion by a SIEM or
              downstream automation.
    - CSV   : tabular, suitable for spreadsheet review or ticketing
              system import.
    - TEXT  : human-readable executive/incident summary.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("FIM")


class ReportGenerator:
    """Generates JSON, CSV, and text security reports from scan results
    and alerts."""

    def __init__(self, config: dict):
        self.reports_directory = Path(config.get("reports_directory", "reports"))
        self.reports_directory.mkdir(parents=True, exist_ok=True)

    def generate_json_report(self, alerts: list[dict], filename: str = "integrity_report.json") -> Path:
        """Write all alerts to a JSON report file."""
        output_path = self.reports_directory / filename

        report_records = [
            {
                "incident_type": alert["event_type"].title(),
                "file": alert["file"],
                "severity": alert["severity"],
                "timestamp": alert["timestamp"],
                "previous_hash": alert.get("previous_hash"),
                "current_hash": alert.get("current_hash"),
                "mitre_attack": alert.get("mitre_attack"),
                "recommendation": "; ".join(alert["recommendation"]),
            }
            for alert in alerts
        ]

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_records, f, indent=2)

        logger.info("JSON report written to '%s'.", output_path)
        return output_path

    def generate_csv_report(self, alerts: list[dict], filename: str = "integrity_report.csv") -> Path:
        """Write all alerts to a CSV report file."""
        output_path = self.reports_directory / filename

        fieldnames = [
            "Timestamp",
            "Event Type",
            "File",
            "Old Hash",
            "New Hash",
            "Severity",
            "Recommendation",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for alert in alerts:
                writer.writerow(
                    {
                        "Timestamp": alert["timestamp"],
                        "Event Type": alert["event_type"],
                        "File": alert["file"],
                        "Old Hash": alert.get("previous_hash") or "",
                        "New Hash": alert.get("current_hash") or "",
                        "Severity": alert["severity"],
                        "Recommendation": "; ".join(alert["recommendation"]),
                    }
                )

        logger.info("CSV report written to '%s'.", output_path)
        return output_path

    def generate_text_summary(
        self,
        scanned_files_count: int,
        integrity_results: dict,
        alerts: list[dict],
        filename: str = "incident_summary.txt",
    ) -> Path:
        """Write a human-readable incident summary report."""
        output_path = self.reports_directory / filename

        critical_count = sum(1 for a in alerts if a["severity"] == "CRITICAL")
        high_count = sum(1 for a in alerts if a["severity"] == "HIGH")
        medium_count = sum(1 for a in alerts if a["severity"] == "MEDIUM")
        low_count = sum(1 for a in alerts if a["severity"] == "LOW")

        lines = [
            "File Integrity Monitoring Summary",
            "=" * 40,
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"Files Scanned:      {scanned_files_count}",
            f"Modified:           {len(integrity_results.get('modified', []))}",
            f"New:                {len(integrity_results.get('new', []))}",
            f"Deleted:            {len(integrity_results.get('deleted', []))}",
            f"Unchanged:          {integrity_results.get('unchanged_count', 0)}",
            "",
            "Alert Breakdown by Severity",
            "-" * 40,
            f"CRITICAL Alerts:    {critical_count}",
            f"HIGH Alerts:        {high_count}",
            f"MEDIUM Alerts:      {medium_count}",
            f"LOW Alerts:         {low_count}",
            "",
        ]

        if alerts:
            lines.append("Detailed Alerts")
            lines.append("-" * 40)
            for alert in alerts:
                lines.append("")
                lines.append(f"[{alert['severity']}] {alert['event_type']} - {alert['file']}")
                lines.append(f"  Timestamp: {alert['timestamp']}")
                if alert.get("previous_hash"):
                    lines.append(f"  Previous Hash: {alert['previous_hash']}")
                if alert.get("current_hash"):
                    lines.append(f"  Current Hash:  {alert['current_hash']}")
                lines.append(f"  MITRE ATT&CK: {alert.get('mitre_attack', 'N/A')}")
        else:
            lines.append("No integrity violations detected. All monitored files match baseline.")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        logger.info("Text summary report written to '%s'.", output_path)
        return output_path
