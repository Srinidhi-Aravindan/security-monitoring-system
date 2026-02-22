from ast import pattern
import re

def parse_log(log_line):
    pattern = r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) sshd\[\d+\]: (Accepted|Failed) password .* from (\S+)'
    match = re.search(pattern, log_line)
    
    if match:
        return {
            'timestamp': match.group(1),
            'ip': match.group(4),      # IP at end
            'status': match.group(3).lower()
        }
    return None
