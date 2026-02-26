"""
Security Monitoring System - Advanced Brute-Force Detection
Srinidhi Aravindan | JHU Cybersecurity Portfolio | Feb 2026
Supports config.json timezone_table + default_timezone
"""

from collections import defaultdict
from datetime import datetime, timedelta
import re


def resolve_timestamp(timestamp_str, timezone_table, default_timezone="+05:30"):
    """
    Normalizes timestamp to UTC using config.json timezone_table.
    """
    s = timestamp_str.strip()
    
    # 1) ISO with offset: "2026-02-23T22:10:00+05:30"
    iso_match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})([+-]\d{2}:\d{2})', s)
    if iso_match:
        base, offset_str = iso_match.groups()
        dt = datetime.fromisoformat(base)
        sign = 1 if offset_str[0] == '+' else -1
        hours, minutes = map(int, offset_str[1:].split(':'))
        delta = timedelta(hours=sign * hours, minutes=sign * minutes)
        return dt + delta
    
    # 2) Syslog + TZ name: "Feb 23 22:10:00 IST"
    name_match = re.match(r'^(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})\s+(\w+)$', s)
    if name_match:
        base, tz_name = name_match.groups()
        dt = datetime.strptime(base, "%b %d %H:%M:%S").replace(year=datetime.now().year)
        offset_str = timezone_table.get(tz_name.upper(), default_timezone)
    else:
        # 3) Plain syslog: use default
        try:
            dt = datetime.strptime(s, "%b %d %H:%M:%S").replace(year=datetime.now().year)
        except ValueError:
            return datetime.utcnow()
        offset_str = default_timezone
    
    # Apply offset like "+05:30"
    sign = 1 if offset_str[0] == '+' else -1
    hours, minutes = map(int, offset_str[1:].split(':'))
    delta = timedelta(hours=sign * hours, minutes=sign * minutes)
    return dt + delta


def detect_bruteforce(events, threshold=2, window_seconds=300, 
                      timezone_table={}, default_timezone="+05:30"):
    """
    Detect brute-force using pre-normalized UTC timestamps or resolves from config.
    """
    failed_attempts = defaultdict(list)
    
    for event in events:
        if not event or event.get("status") != "failed":
            continue
            
        # Use pre-resolved UTC if available, otherwise resolve now
        if "timestamp_utc" in event:
            ts_utc = event["timestamp_utc"]
        else:
            ts_utc = resolve_timestamp(event["timestamp"], timezone_table, default_timezone)
        
        failed_attempts[event["ip"]].append(ts_utc)
    
    # Sliding window analysis (UTC timeline)
    alerts = {}
    for ip, timestamps in failed_attempts.items():
        if len(timestamps) < threshold:
            continue
            
        timestamps.sort()
        window_end = timestamps[-1]
        window_start = window_end - timedelta(seconds=window_seconds)
        recent_count = sum(1 for ts in timestamps if window_start <= ts <= window_end)
        
        if recent_count >= threshold:
            alerts[ip] = recent_count
    
    return alerts
