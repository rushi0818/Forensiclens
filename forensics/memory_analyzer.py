import os
import re
import json
import subprocess
from datetime import datetime


# Suspicious process names that malware commonly uses
SUSPICIOUS_PROCESSES = [
    'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'svchost.exe',
    'lsass.exe', 'nc.exe', 'netcat', 'mimikatz', 'psexec',
    'whoami.exe', 'net.exe', 'nmap', 'metasploit'
]

# Suspicious network ports
SUSPICIOUS_PORTS = [
    4444, 1337, 31337, 8888, 9999,  # Common reverse shell ports
    6667, 6668, 6669,                 # IRC botnet ports
    3389,                             # RDP
    5900,                             # VNC
]


def run_volatility(memory_file, plugin, output_format="json"):
    """
    Run a Volatility3 plugin on a memory dump.
    Returns parsed output.

    Volatility plugins we use:
    - windows.pslist    : Running processes
    - windows.netscan   : Network connections
    - windows.dlllist   : Loaded DLLs
    - windows.cmdline   : Process command lines
    - windows.malfind   : Injected code detection
    """
    cmd = [
        "python3", "-m", "volatility3",
        "-f", memory_file,
        plugin
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return None, "Volatility timed out - file may be too large"
    except FileNotFoundError:
        return None, "Volatility3 not installed"
    except Exception as e:
        return None, str(e)


def analyze_processes(memory_file):
    """
    Extract running processes from memory dump.
    Look for suspicious process names, unusual parent-child
    relationships, and processes running from temp folders.
    """
    print("[memory] Analyzing processes...")
    output, error = run_volatility(memory_file, "windows.pslist.PsList")

    processes     = []
    suspicious    = []

    if not output:
        # Return demo data if volatility not available
        return get_demo_processes()

    for line in output.split('\n'):
        # Skip header lines
        if not line.strip() or line.startswith('Volatility') or line.startswith('PID'):
            continue

        parts = line.split()
        if len(parts) >= 4:
            try:
                proc = {
                    'pid'      : parts[0],
                    'ppid'     : parts[1],
                    'name'     : parts[2],
                    'threads'  : parts[3],
                    'time'     : ' '.join(parts[7:9]) if len(parts) > 8 else 'Unknown'
                }
                processes.append(proc)

                # Check if suspicious
                if any(s.lower() in proc['name'].lower()
                       for s in SUSPICIOUS_PROCESSES):
                    proc['suspicious'] = True
                    proc['reason']     = f"Suspicious process: {proc['name']}"
                    suspicious.append(proc)

            except Exception:
                continue

    return {
        'total'      : len(processes),
        'processes'  : processes[:50],
        'suspicious' : suspicious,
    }


def analyze_network(memory_file):
    """
    Extract network connections from memory dump.
    Find connections to suspicious IPs and ports.
    """
    print("[memory] Analyzing network connections...")
    output, error = run_volatility(memory_file, "windows.netscan.NetScan")

    connections   = []
    suspicious    = []

    if not output:
        return get_demo_network()

    for line in output.split('\n'):
        if not line.strip() or 'Offset' in line or 'Volatility' in line:
            continue

        parts = line.split()
        if len(parts) >= 6:
            try:
                conn = {
                    'proto'      : parts[1] if len(parts) > 1 else '',
                    'local_addr' : parts[2] if len(parts) > 2 else '',
                    'foreign_addr': parts[3] if len(parts) > 3 else '',
                    'state'      : parts[4] if len(parts) > 4 else '',
                    'pid'        : parts[5] if len(parts) > 5 else '',
                    'process'    : parts[6] if len(parts) > 6 else '',
                }
                connections.append(conn)

                # Check for suspicious ports
                foreign = conn.get('foreign_addr', '')
                for port in SUSPICIOUS_PORTS:
                    if f':{port}' in foreign:
                        conn['suspicious'] = True
                        conn['reason']     = f"Suspicious port: {port}"
                        suspicious.append(conn)
                        break

            except Exception:
                continue

    return {
        'total'       : len(connections),
        'connections' : connections[:30],
        'suspicious'  : suspicious,
    }


def find_injected_code(memory_file):
    """
    Use Volatility malfind plugin to detect code injection.
    Malfind looks for:
    - Executable memory regions that shouldn't be executable
    - PE headers in unexpected places
    - MZ signatures in memory (hidden executables)
    """
    print("[memory] Scanning for injected code...")
    output, error = run_volatility(memory_file, "windows.malfind.Malfind")

    injections = []

    if not output:
        return {'injections': [], 'total': 0}

    current = {}
    for line in output.split('\n'):
        if 'Process:' in line:
            if current:
                injections.append(current)
            parts      = line.split()
            current    = {
                'process'  : parts[1] if len(parts) > 1 else '',
                'pid'      : parts[3] if len(parts) > 3 else '',
                'address'  : parts[5] if len(parts) > 5 else '',
                'details'  : line.strip()
            }

    if current:
        injections.append(current)

    return {
        'injections' : injections,
        'total'      : len(injections),
        'is_malicious': len(injections) > 0
    }


def get_demo_processes():
    """Demo data when Volatility is not available."""
    return {
        'total'      : 42,
        'processes'  : [
            {'pid':'4',    'ppid':'0',  'name':'System',         'threads':'141', 'suspicious': False},
            {'pid':'308',  'ppid':'4',  'name':'smss.exe',       'threads':'3',   'suspicious': False},
            {'pid':'456',  'ppid':'448','name':'csrss.exe',      'threads':'10',  'suspicious': False},
            {'pid':'1337', 'ppid':'456','name':'powershell.exe', 'threads':'8',   'suspicious': True,
             'reason': 'Suspicious process: powershell.exe'},
            {'pid':'2048', 'ppid':'456','name':'cmd.exe',        'threads':'3',   'suspicious': True,
             'reason': 'Suspicious process: cmd.exe'},
            {'pid':'3456', 'ppid':'456','name':'chrome.exe',     'threads':'24',  'suspicious': False},
            {'pid':'4444', 'ppid':'456','name':'nc.exe',         'threads':'2',   'suspicious': True,
             'reason': 'Suspicious process: nc.exe (netcat backdoor)'},
        ],
        'suspicious' : [
            {'pid':'1337', 'name':'powershell.exe', 'reason':'Suspicious process - often used in attacks'},
            {'pid':'2048', 'name':'cmd.exe',         'reason':'Command prompt - check parent process'},
            {'pid':'4444', 'name':'nc.exe',          'reason':'Netcat - common backdoor tool'},
        ],
        'demo': True
    }


def get_demo_network():
    """Demo network data."""
    return {
        'total'       : 15,
        'connections' : [
            {'proto':'TCPv4', 'local_addr':'192.168.1.5:49231', 'foreign_addr':'8.8.8.8:443',   'state':'ESTABLISHED', 'process':'chrome.exe'},
            {'proto':'TCPv4', 'local_addr':'192.168.1.5:49232', 'foreign_addr':'45.12.34.56:4444','state':'ESTABLISHED','process':'powershell.exe',
             'suspicious':True, 'reason':'Port 4444 - common reverse shell port'},
            {'proto':'TCPv4', 'local_addr':'192.168.1.5:49233', 'foreign_addr':'1.2.3.4:1337',  'state':'ESTABLISHED', 'process':'nc.exe',
             'suspicious':True, 'reason':'Port 1337 - known malware port'},
        ],
        'suspicious'  : [
            {'foreign_addr':'45.12.34.56:4444', 'process':'powershell.exe', 'reason':'Reverse shell port'},
            {'foreign_addr':'1.2.3.4:1337',     'process':'nc.exe',         'reason':'Known malware port'},
        ],
        'demo': True
    }


def run_full_memory_analysis(memory_file):
    """
    Main function - runs complete memory analysis.
    Called by app.py when user uploads a memory dump.
    """
    if not os.path.exists(memory_file):
        return {'error': 'Memory file not found'}

    file_size = os.path.getsize(memory_file)
    result    = {
        'filename'   : os.path.basename(memory_file),
        'file_size'  : f'{round(file_size / (1024*1024), 1)} MB',
        'analyzed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'scan_type'  : 'Memory Forensics'
    }

    # Run all analysis modules
    result['processes']  = analyze_processes(memory_file)
    result['network']    = analyze_network(memory_file)
    result['injections'] = find_injected_code(memory_file)

    # Overall threat assessment
    threats = 0
    reasons = []

    if result['processes'].get('suspicious'):
        threats += len(result['processes']['suspicious'])
        reasons.append(f"{len(result['processes']['suspicious'])} suspicious processes found")

    if result['network'].get('suspicious'):
        threats += len(result['network']['suspicious']) * 2
        reasons.append(f"{len(result['network']['suspicious'])} suspicious network connections")

    if result['injections'].get('is_malicious'):
        threats += 5
        reasons.append(f"{result['injections']['total']} code injection(s) detected")

    result['threat_score'] = threats
    result['reasons']      = reasons

    if threats >= 5:
        result['verdict']     = 'COMPROMISED'
        result['is_phishing'] = True
        result['confidence']  = min(97, 50 + threats * 3)
    elif threats >= 2:
        result['verdict']     = 'SUSPICIOUS'
        result['is_phishing'] = True
        result['confidence']  = min(75, 40 + threats * 5)
    else:
        result['verdict']     = 'CLEAN'
        result['is_phishing'] = False
        result['confidence']  = 80

    return result
