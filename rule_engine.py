"""
Security Monitoring System - Advanced Brute-Force Detection
Supports multi-timezone logs with configurable analysis window.
"""

from collections import defaultdict
from datetime import datetime, timezone, timedelta
import re


def detect_bruteforce(events, threshold=2, window_seconds=300, timezone_offset_hours=0):
    """
    Detect brute-force attacks within sliding time window.
    
    Args:
        events: List of parsed log events
        threshold: Min failed logins to alert (default: 2)
        window_seconds: Time window for attack detection (default: 5min)
        timezone_offset_hours: Log timezone offset from UTC (e.g., +5.5 for IST)
    
    Returns:
        dict: {ip: attack_count}
    """
    failed_attempts = defaultdict(list)
    
    # Convert to UTC for consistent analysis
    tz_offset = timedelta(hours=timezone_offset_hours)
    
    for event in events:
        if not event or event.get("status") != "failed":
            continue
            
        try:
            # Parse flexible timestamp formats
            timestamp_str = event["timestamp"]
            # Handle "Feb 23 22:10:00" or "Feb 23 22:10:00 +0530"
            ts_match = re.match(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})(?:\s+([+-]\d{4}))?', timestamp_str)
            
            if ts_match:
                ts_local = datetime.strptime(ts_match.group(1), "%b %d %H:%M:%S")
                # Assume log year = current year
                ts_local = ts_local.replace(year=datetime.now().year)
                
                # Apply timezone offset to get UTC
                ts_utc = ts_local + tz_offset
                failed_attempts[event["ip"]].append(ts_utc)
                
        except (ValueError, KeyError):
            continue  # Skip unparseable events
    
    # Sliding window analysis
    alerts = {}
    for ip, timestamps in failed_attempts.items():
        if len(timestamps) < threshold:
            continue
            
        timestamps.sort()
        window_end = timestamps[-1]  # Most recent attack
        window_start = window_end - timedelta(seconds=window_seconds)
        
        # Count attacks in window
        recent_attacks = [ts for ts in timestamps if window_start <= ts <= window_end]
        
        if len(recent_attacks) >= threshold:
            alerts[ip] = len(recent_attacks)
    
    return alerts
