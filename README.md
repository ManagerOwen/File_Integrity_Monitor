# File Integrity Monitoring System (FIM)

A Python-based defensive security tool that detects unauthorized file
changes using cryptographic hashing - conceptually similar to enterprise
File Integrity Monitoring solutions such as *Tripwire*, *OSSEC*, and
*Wazuh*.

*Cybersecurity Focus:* SOC Operations · Endpoint Security · Incident Response · Threat Detection · Security Automation

---

## Project Overview

File Integrity Monitoring (FIM) is a core control in most security
frameworks (PCI-DSS, NIST 800-53, CIS Controls) because it detects when
critical files — configuration files, executables, system files - have
been changed, added, or removed without authorization. These changes are
often early indicators of malware infection, insider misuse, or an
active intrusion.

This project implements a lightweight, dependency-free FIM engine that:

1. Builds a **trusted baseline** of every file in a monitored directory,
   recording its SHA-256 hash and metadata.
2. Re-scans the directory on demand (or continuously) and **compares**
   the current state against the baseline.
3. Classifies each detected change — **modified**, **new**, or
   **deleted** — with a **severity level** (LOW / MEDIUM / HIGH /
   CRITICAL) and maps it to a relevant **MITRE ATT&CK** technique.
4. Produces **JSON, CSV, and plain-text** security reports suitable for
   SIEM ingestion, ticketing systems, or human review.

---

## Features

- SHA-256 (or SHA-1/MD5) cryptographic hashing of every monitored file
- Recursive directory scanning with configurable file/extension exclusions
- Trusted baseline creation, loading, and controlled updates
- Detection of **modified**, **new**, and **deleted** files
- Four-tier severity classification (LOW / MEDIUM / HIGH / CRITICAL)
- Automatic escalation to CRITICAL when multiple unauthorized changes
  occur in a single scan (a common ransomware/mass-tampering indicator)
- MITRE ATT&CK technique mapping for each event type
- JSON, CSV, and human-readable text report generation
- Full audit logging to `logs/fim.log`
- Continuous monitoring mode (`--monitor`) with configurable poll interval
- Command-line interface built with `argparse`
- Zero required third-party dependencies (standard library only)

---

## Architecture

```
File_Integrity_Monitor/
│
├── main.py                  # CLI entry point / orchestration
├── file_scanner.py          # Recursive file discovery
├── hash_engine.py           # SHA-256 hashing
├── baseline_manager.py      # Trusted baseline create/load/update
├── integrity_checker.py     # Baseline vs. current-state comparison
├── alert_manager.py         # Severity classification + alert formatting
├── report_generator.py      # JSON / CSV / text report generation
├── config.json               # System configuration
│
├── monitored_directory/     # Example files being watched
├── baseline/                # Stored trusted baseline (baseline.json)
├── reports/                 # Generated JSON / CSV / TXT reports
├── logs/                    # fim.log audit trail
│
├── requirements.txt
├── README.md
└── sample_output.txt        # Example end-to-end run
```

Each module has a single responsibility, which keeps the system easy to
test, extend, and reason about — the same modular design philosophy used
in production security tooling.

**Design note:** the baseline is stored as a local JSON file for this
portfolio project. In a production deployment it would additionally be
protected with restrictive file permissions, stored on separate/read-only
media, and integrity-checked itself (e.g. via a signature) so an attacker
who tampers with a monitored file cannot also silently edit the baseline
to hide the change.

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

- **Cryptographic integrity verification** using SHA-256
- **Endpoint security monitoring** patterns used by EDR/FIM agents
- **Digital forensics fundamentals** — establishing a trusted baseline
  and detecting drift from it
- **Threat detection & triage** — severity classification and escalation
  logic modeled on SOC playbooks
- **MITRE ATT&CK mapping** — connecting observed events (data
  manipulation, indicator removal, autostart execution) to known
  adversary techniques
- **Security automation** — scheduled/continuous scanning and automatic
  report generation
- **Audit logging** — a durable, timestamped record of all security-
  relevant activity for incident investigation

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
