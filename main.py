import json
from parser import parse_log
from rule_engine import detect_bruteforce


def main():
    # Load configuration
    with open("config.json", "r") as f:
        config = json.load(f)

    rules = config["rules"]
    threshold = rules["failed_login_threshold"]
    window_seconds = rules.get("time_window_seconds", 300)

    # Load and parse logs
    with open("sample_logs.txt", "r") as f:
        logs_text = f.readlines()

    events = [parse_log(line.strip()) for line in logs_text]

    # DEBUG: Uncomment to verify parsing
    """
    failed_events = [e for e in events if e and e["status"] == "failed"]
    print(f"DEBUG: {len(failed_events)} failed events parsed:")
    for e in failed_events[:5]:
        print(f"  {e['ip']} @ {e['timestamp']}")
    """

    # Timezone-aware brute-force detection
    anomalies = detect_bruteforce(
        events,
        threshold=threshold,
        window_seconds=window_seconds,
        timezone_offset_hours=5.5  # IST (UTC+5.5)
    )

    # Production output
    print(f"Anomalies detected (threshold: {threshold}, window: {window_seconds}s IST):")
    print(json.dumps(anomalies, indent=2))


if __name__ == "__main__":
    main()
