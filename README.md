# Security Monitoring System (Python)

A lightweight Python‑based security monitoring system that performs **log parsing**, **rule‑based anomaly detection**, and **file integrity monitoring**.

## Features
- Parse authentication logs (login failed/success, privilege escalation)
- Detect brute‑force attacks by IP (threshold: 2+ failed logins)
- File integrity checks using SHA256
- JSON config for rules
- CLI interface

# Security Monitoring System (Python)

A lightweight Python‑based security monitoring system that performs **log parsing**, **rule‑based anomaly detection**, and **file integrity monitoring**.

## Features
- Parse authentication logs (login failed/success, privilege escalation)
[...etc]

## Technologies
- Python 3.9+
- Regular expressions
- SHA256 hashing
- JSON configuration

## Quick Start
```bash
python main.py

## Sample Output

```
Anomalies detected:
{
"192.168.1.100": 2
}
```
