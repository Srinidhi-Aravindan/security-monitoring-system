def check_failed_logins(logs, threshold):
    failed_by_ip = {}
    for log in logs:
        if log and log['status'] == 'failed':
            ip = log['ip']
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1   
    # Apply threshold
    anomalies = {ip: count for ip, count in failed_by_ip.items() if count >= threshold}
    return anomalies
