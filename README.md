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

## Live Demo

**Real brute-force detection across 20 SSH logs:**

<img width="343" height="160" alt="image" src="https://github.com/user-attachments/assets/4f43a8da-d74e-443e-b03e-a3a1ed719562" />

**4 attackers identified** (threshold: 2+ failed logins):
- `192.168.1.100`: **3 attempts** (high risk)
- `10.0.0.99`, `10.0.0.50`, `192.168.1.200`: **2 attempts each**
