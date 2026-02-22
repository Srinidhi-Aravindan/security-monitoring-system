import re
from datetime import datetime

def parse_log(line):
    pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) (\w+) ([\d.]+)'
    match = re.match(pattern, line)
    if match:
        return {
            'timestamp': datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S'),
            'event': match.group(2),
            'user': match.group(3),
            'ip': match.group(4)
        }
    return None
