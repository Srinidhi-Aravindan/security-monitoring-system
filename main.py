from logging import config

from parser import parse_log
from rule_engine import check_failed_logins
import json

def main():
    # Load config
    with open('config.json', 'r') as f:
        config = json.load(f)
    
    with open('sample_logs.txt', 'r') as f:
        logs_text = f.readlines()
    threshold = config['rules']['failed_logins']
    parsed = [parse_log(line.strip()) for line in logs_text]
    anomalies = check_failed_logins(parsed, threshold)
    print("Anomalies detected (threshold:", config['rules']['failed_logins'], "):")
    print(json.dumps(anomalies, indent=2))

if __name__ == "__main__":
    main()
