import re
from datetime import datetime

def parse_log(log_line):
    line = log_line.strip()
    
    # NEW: CSV/ISO format (YYYY-MM-DDTHH:MM:SS±HH:MM)
    if line.startswith('20'):
        try:
            parts = line.split(',')
            if len(parts) >= 5:
                timestamp_str = parts[0].strip()
                result = parts[3].strip().lower()
                source_ip = parts[4].strip()
                
                ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return {
                    'timestamp': ts.strftime('%Y-%m-%dT%H:%M:%S') + timestamp_str[-6:],
                    'status': 'failed' if 'fail' in result else 'success',
                    'ip': source_ip
                }
        except:
            pass
    
    # EXISTING: Syslog/Splunk
    patterns = [
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?(Failed|Accepted).*?from\s+(\S+)',
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd.*?(Failed|Accepted).*?from\s+(\S+)'
    ]
    
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return {
                'timestamp': match.group(1),
                'status': match.group(2).lower(),
                'ip': match.group(3)
            }
    return None
