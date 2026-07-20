# File Integrity Monitoring System (FIM)
A Python-based defensive security tool that detects unauthorized file changes using cryptographic hashing, baseline comparison, and automated security reporting.

This project demonstrates practical cybersecurity concepts used in **Security Operations (SOC), Endpoint Security, Incident Response, and Security Automation**.

---

## Cybersecurity Focus Areas

- Security Operations Center (SOC)
- Endpoint Security
- Threat Detection
- Incident Response
- Security Automation
- Defensive Security

---

# Project Overview
File Integrity Monitoring (FIM) is a security capability used to identify unauthorized changes to important files, configurations, and system resources.

Unexpected file changes can indicate:
- Malware activity
- Unauthorized modifications
- Insider threats
- Configuration tampering
- Possible security compromise

This project implements a lightweight File Integrity Monitoring engine that:

1. Creates a trusted baseline of monitored files using SHA-256 cryptographic hashes and metadata.
2. Scans directories and compares current file states against the trusted baseline.
3. Detects modified, newly created, and deleted files.
4. Classifies security events based on severity.
5. Generates investigation reports in JSON, CSV, and text formats.

---

# Features

## File Integrity Monitoring
- SHA-256 cryptographic hashing
- Recursive directory scanning
- File metadata collection
- Baseline creation and verification
- Detection of file modifications
- Detection of new files
- Detection of deleted files

---

## Security Detection
The system identifies:
- Unauthorized file modifications
- Suspicious executable creation
- Configuration changes
- Missing critical files
- Multiple file changes during a single scan

---

## Security Alerting

Events are classified into:
| Severity | Description |
|----------|-------------|
| LOW | Expected or low-risk changes |
| MEDIUM | Suspicious file activity requiring review |
| HIGH | Potential security incident |
| CRITICAL | Indicators of possible compromise |

---

## Reporting
Generates:
- JSON security reports
- CSV investigation reports
- Human-readable incident summaries
- Audit logs

---

# Technologies Used
- Python 3
- SHA-256 Hashing
- JSON
- CSV
- argparse
- pathlib
- hashlib
- Python Logging Module

---

## Installation

```bash
git clone https://github.com/ManagerOwen/File_Integrity_Monitor.git
cd File_Integrity_Monitor

# Optional — only needed for the bonus real-time/colored-output features
pip install -r requirements.txt
```

Requires Python 3.10+ (uses modern type-hint syntax).

---

## Usage

Create the trusted baseline (run this first, and again any time changes
are reviewed and approved):

```bash
python main.py --create-baseline
```

Run a single integrity scan against the baseline:

```bash
python main.py --scan
```

Run a scan and generate JSON/CSV/text reports:

```bash
python main.py --report
```

Continuously monitor the directory (polls on an interval defined in
`config.json`):

```bash
python main.py --monitor
```

Target a different directory:

```bash
python main.py --scan --directory /path/to/other/directory
```

---

## Example Output

```
=====================================
FILE INTEGRITY ALERT
=====================================

Event Type:
MODIFIED FILE

File:
important_config.conf

Severity:
HIGH

Previous Hash:

d73bb3fec31c1a3f69d84fd7cc5c9d7ad0333693a51ddd5aabb70fa6b135284f

Current Hash:

08ff79df1147cb6c476cef41c98903e3d7971f70ca1518a026894b5855a91f86

Timestamp:
2026-07-20 09:13:40

MITRE ATT&CK Reference:
T1565 - Data Manipulation

Recommendation:

- Verify change authorization with the responsible team.
- Investigate recent user and process activity on the host.
- Review system and application logs around the timestamp.
- Check the file and host for signs of malware infection.

=====================================
```

See [`sample_output.txt`](sample_output.txt) for a full walkthrough
covering four scenarios: a routine low-risk update, an unauthorized
sensitive-config change, a suspicious new executable, and a deleted
system configuration file — showing how each is classified LOW, HIGH,
CRITICAL, and CRITICAL respectively.

---

## Security Concepts Demonstrated

- **Cryptographic integrity verification** Using SHA-256 hashing to detect unauthorized changes to files.
- **Endpoint security monitoring** Applying file monitoring concepts used in enterprise security environments.
- **Digital forensics fundamentals** — Creating trusted baselines and identifying changes from known-good states.
- **Threat detection & triage** — Classifying security events based on risk and investigation priority.
- **MITRE ATT&CK mapping** — connecting observed events (data
  manipulation, indicator removal, autostart execution) to known
  adversary techniques
- **Security automation** — Automating repetitive security monitoring and reporting tasks.
- **Audit logging** — Maintaining records of security-relevant events for investigation.
---

## Future Improvements

- Real-time monitoring using the `watchdog` library instead of polling
- Risk-score calculation that blends severity, asset sensitivity, and change frequency
- SQLite-backed hash comparison history for longer-term trend analysis
- HTML security dashboard report
- Simulated email/webhook alert delivery
- Digital signing of the baseline file to detect baseline tampering
- Integration with a real SIEM (e.g. via Syslog/CEF output)

---

## Disclaimer

This is a defensive security portfolio project built for educational and
demonstration purposes. `suspicious_tool.exe` referenced in the sample
walkthrough is a plain text placeholder file used only to demonstrate
detection logic — it contains no executable code and is not malware.
