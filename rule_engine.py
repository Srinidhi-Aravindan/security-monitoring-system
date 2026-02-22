def check_failed_logins(logs, threshold=2):
    ip_fails = {}
    for log in logs:
        if log and log['event'] == 'login_failed':
            ip = log['ip']
            ip_fails[ip] = ip_fails.get(ip, 0) + 1
    return {ip: count for ip, count in ip_fails.items() if count >= threshold}
