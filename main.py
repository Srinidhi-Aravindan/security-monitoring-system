from parser import parse_log
from rule_engine import check_failed_logins
import json

def main():
    with open('sample_logs.txt', 'r') as f:
        logs_text = f.readlines()
    
    logs = [parse_log(line.strip()) for line in logs_text]
    anomalies = check_failed_logins(logs)
    
    print("Anomalies detected:")
    print(json.dumps(anomalies, indent=2))

if __name__ == "__main__":
    main()
