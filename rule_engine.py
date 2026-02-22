def check_failed_logins(logs, threshold):
    failed_by_ip = {}
    for log in logs:
        if log and log['status'] == 'failed':
            ip = log['ip']
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1
            print(f"DEBUG: {ip} → {failed_by_ip[ip]} fails")
    
    # Apply threshold
    anomalies = {ip: count for ip, count in failed_by_ip.items() if count >= threshold}
    print({anomalies})
    print(f"DEBUG: Threshold {threshold}, anomalies: {anomalies}")
    return anomalies
