import os
import re
import json
import sqlite3
import platform
import subprocess
from datetime import datetime


def collect_browser_history(browser="chrome", limit=50):
    """
    Extract browser history from Chrome/Firefox/Edge.
    Attackers often use browsers to download malware or
    visit C2 servers - this finds those visits.
    """
    history  = []
    system   = platform.system()

    # Chrome history database path
    if system == "Windows":
        paths = {
            "chrome"  : os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"),
            "edge"    : os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"),
            "firefox" : os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles"),
        }
    else:  # Linux/Kali
        home = os.path.expanduser("~")
        paths = {
            "chrome"  : f"{home}/.config/google-chrome/Default/History",
            "firefox" : f"{home}/.mozilla/firefox",
        }

    db_path = paths.get(browser, "")

    if not db_path or not os.path.exists(db_path):
        return {
            'browser' : browser,
            'found'   : False,
            'note'    : f'{browser} history not found on this system',
            'history' : []
        }

    try:
        # Copy DB first (browser locks the original)
        import shutil
        temp_db = f"/tmp/history_temp_{browser}.db"
        shutil.copy2(db_path, temp_db)

        conn   = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time DESC
            LIMIT ?
        """, (limit,))

        for row in cursor.fetchall():
            url, title, visits, last_visit = row
            history.append({
                'url'       : url,
                'title'     : title or 'No title',
                'visits'    : visits,
                'last_visit': last_visit
            })

        conn.close()
        os.remove(temp_db)

        return {
            'browser'  : browser,
            'found'    : True,
            'total'    : len(history),
            'history'  : history
        }

    except Exception as e:
        return {
            'browser' : browser,
            'found'   : False,
            'error'   : str(e),
            'history' : []
        }


def collect_recent_files():
    """
    Find recently accessed/modified files.
    Helps identify what files attacker accessed or created.
    """
    recent = []
    system = platform.system()

    if system == "Windows":
        recent_path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent")
        if os.path.exists(recent_path):
            for f in os.listdir(recent_path)[:30]:
                full_path = os.path.join(recent_path, f)
                try:
                    mtime = os.path.getmtime(full_path)
                    recent.append({
                        'name'     : f,
                        'path'     : full_path,
                        'modified' : datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
                except Exception:
                    continue
    else:
        # Linux - check home directory for recent files
        home = os.path.expanduser("~")
        try:
            result = subprocess.run(
                ['find', home, '-maxdepth', '3', '-type', 'f',
                 '-newer', '/tmp', '-not', '-path', '*/.*'],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n')[:30]:
                if line.strip():
                    try:
                        mtime = os.path.getmtime(line.strip())
                        recent.append({
                            'name'     : os.path.basename(line),
                            'path'     : line.strip(),
                            'modified' : datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
                        })
                    except Exception:
                        continue
        except Exception:
            pass

    return recent


def collect_running_processes():
    """
    Get currently running processes on live system.
    Uses psutil for cross-platform support.
    """
    processes = []
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'username',
                                          'cpu_percent', 'memory_percent',
                                          'create_time', 'connections']):
            try:
                info = proc.info
                proc_data = {
                    'pid'      : info['pid'],
                    'name'     : info['name'],
                    'username' : info.get('username', 'Unknown'),
                    'cpu'      : round(info.get('cpu_percent', 0), 1),
                    'memory'   : round(info.get('memory_percent', 0), 2),
                }

                # Flag suspicious processes
                suspicious_names = [
                    'nc', 'netcat', 'ncat', 'powershell',
                    'mimikatz', 'meterpreter', 'metasploit'
                ]
                name_lower = info['name'].lower()
                if any(s in name_lower for s in suspicious_names):
                    proc_data['suspicious'] = True
                    proc_data['reason']     = f'Suspicious process name: {info["name"]}'

                processes.append(proc_data)
            except Exception:
                continue
    except ImportError:
        processes = [{'error': 'psutil not installed - run: pip install psutil'}]

    return sorted(processes, key=lambda x: x.get('memory', 0), reverse=True)[:30]


def collect_startup_items():
    """
    Find programs that run at startup.
    Malware commonly adds itself to startup for persistence.
    This is MITRE ATT&CK T1547 - Boot or Logon Autostart Execution.
    """
    startup_items = []
    system        = platform.system()

    if system == "Windows":
        # Check registry startup keys
        reg_keys = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        ]
        for key in reg_keys:
            try:
                result = subprocess.run(
                    ['reg', 'query', key],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if '    ' in line and line.strip():
                        parts = line.strip().split('    ')
                        if len(parts) >= 3:
                            startup_items.append({
                                'name'     : parts[0].strip(),
                                'type'     : parts[1].strip(),
                                'value'    : parts[2].strip(),
                                'location' : key
                            })
            except Exception:
                continue

    else:
        # Linux - check common persistence locations
        locations = [
            '/etc/rc.local',
            '/etc/cron.d/',
            os.path.expanduser('~/.bashrc'),
            os.path.expanduser('~/.profile'),
            '/etc/systemd/system/',
        ]
        for loc in locations:
            if os.path.exists(loc):
                startup_items.append({
                    'name'     : os.path.basename(loc),
                    'location' : loc,
                    'exists'   : True
                })

    return startup_items


def collect_network_connections():
    """
    Get active network connections on live system.
    Find connections to suspicious IPs or ports.
    """
    connections = []
    try:
        import psutil
        for conn in psutil.net_connections(kind='inet'):
            try:
                conn_data = {
                    'type'   : 'TCP' if conn.type.name == 'SOCK_STREAM' else 'UDP',
                    'local'  : f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote' : f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status' : conn.status,
                    'pid'    : conn.pid
                }

                # Flag suspicious ports
                suspicious_ports = [4444, 1337, 31337, 8888, 9999, 6667]
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    conn_data['suspicious'] = True
                    conn_data['reason']     = f'Suspicious port: {conn.raddr.port}'

                if conn_data['remote']:
                    connections.append(conn_data)
            except Exception:
                continue
    except ImportError:
        pass

    return connections[:20]


def collect_user_accounts():
    """
    List user accounts on the system.
    Attackers often create backdoor accounts.
    """
    users  = []
    system = platform.system()

    if system == "Windows":
        try:
            result = subprocess.run(
                ['net', 'user'],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            for line in lines[4:-3]:
                names = line.strip().split()
                for name in names:
                    if name and not name.startswith('-'):
                        users.append({'username': name})
        except Exception:
            pass
    else:
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 4:
                        uid = int(parts[2]) if parts[2].isdigit() else 0
                        if uid >= 1000 or parts[0] == 'root':
                            users.append({
                                'username' : parts[0],
                                'uid'      : parts[2],
                                'home'     : parts[5],
                                'shell'    : parts[6]
                            })
        except Exception:
            pass

    return users


def run_full_artifact_collection():
    """
    Main function - runs all artifact collection.
    Called by app.py for live system forensics.
    """
    print("[artifacts] Starting collection...")

    result = {
        'collected_at'    : datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'system'          : platform.system(),
        'hostname'        : platform.node(),
        'scan_type'       : 'Live System Forensics',
    }

    print("[artifacts] Collecting processes...")
    result['processes']   = collect_running_processes()

    print("[artifacts] Collecting network connections...")
    result['connections'] = collect_network_connections()

    print("[artifacts] Collecting startup items...")
    result['startup']     = collect_startup_items()

    print("[artifacts] Collecting user accounts...")
    result['users']       = collect_user_accounts()

    print("[artifacts] Collecting recent files...")
    result['recent_files']= collect_recent_files()

    # Count suspicious items
    suspicious_count = 0
    reasons          = []

    suspicious_procs = [p for p in result['processes'] if p.get('suspicious')]
    if suspicious_procs:
        suspicious_count += len(suspicious_procs)
        reasons.append(f"{len(suspicious_procs)} suspicious processes running")

    suspicious_conns = [c for c in result['connections'] if c.get('suspicious')]
    if suspicious_conns:
        suspicious_count += len(suspicious_conns) * 2
        reasons.append(f"{len(suspicious_conns)} suspicious network connections")

    result['suspicious_count'] = suspicious_count
    result['reasons']          = reasons
    result['verdict']          = 'SUSPICIOUS' if suspicious_count > 0 else 'CLEAN'
    result['is_phishing']      = suspicious_count > 0
    result['confidence']       = min(90, 50 + suspicious_count * 10)
    result['threat_score']     = suspicious_count

    print(f"[artifacts] Done. Found {suspicious_count} suspicious items.")
    return result
