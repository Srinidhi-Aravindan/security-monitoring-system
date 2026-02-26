# Security Monitoring System (Python)

A lightweight Python‑based security monitoring system that performs **log parsing**, **rule‑based anomaly detection**, and **file integrity monitoring**.

## Features
- Parse authentication logs (login failed/success, privilege escalation)
- Detect brute‑force attacks by IP (threshold: 2+ failed logins)
- File integrity checks using SHA256
- JSON config for rules
- CLI interface

## Technologies
- Python 3.9+
- Regular expressions
- SHA256 hashing
- JSON configuration

## Quick Start
```bash
python main.py
```

## Production Demo

**Multi‑format SIEM: SSH syslog + CSV/ISO → 16 events analyzed**

<img src="image.png" alt="Production SIEM Output" width="600">

**Key Features:**
- **Universal parsing**: SSH syslog + CSV/ISO formats
- **Timezone‑aware**: IST/MYT/SGT/PST via `config.json` timezone_table
- **Config‑driven**: threshold/window from JSON rules
- **Multi‑source**: Combines all log files automatically

**config.json timezone_table:**
```json
{
  "IST": "+05:30", "MYT": "+08:00", "SGT": "+08:00", 
  "PST": "-08:00", "UTC": "+00:00", "CET": "+01:00"
}
