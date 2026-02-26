#!/usr/bin/env python3
"""
Production SIEM using config.json timezone_table
"""

import json
from parser import parse_log
from rule_engine import detect_bruteforce


def main():
    # Load your config
    with open("config.json", "r") as f:
        config = json.load(f)

    rules = config["rules"]
    tz_table = config.get("timezone_table", {})
    default_tz = config["default_timezone"]

    print(f"🔍 Config: threshold={rules['failed_login_threshold']} window={rules['time_window_seconds']}s")
    print(f"🌍 TZ: default={default_tz} table={list(tz_table.keys())}")

    # Multi-source
    log_sources = ["sample_logs.txt", "csv_auth_logs.txt"]
    all_events = []
    
    for filename in log_sources:
        print(f"\n📂 {filename}")
        try:
            with open(filename, "r") as f:
                lines = f.readlines()
            events = [parse_log(line.strip()) for line in lines if line.strip()]
            valid_events = [e for e in events if e]
            all_events.extend(valid_events)
            print(f"  ✓ {len(valid_events)} events")
        except FileNotFoundError:
            print("  ⚠ skipped")

    print(f"\n📊 {len(all_events)} total events")

    # Detection using your config.json timezone_table
    anomalies = detect_bruteforce(
        all_events,
        threshold=rules["failed_login_threshold"],
        window_seconds=rules["time_window_seconds"],
        timezone_table=tz_table,
        default_timezone=default_tz
    )

    print(f"\n🚨 Brute-force alerts:")
    print(json.dumps(anomalies, indent=2))


if __name__ == "__main__":
    main()
