# 🔬 ForensicLens — Digital Forensics & Incident Response Toolkit

> A web-based Digital Forensics and Incident Response (DFIR) platform built for
> SOC analysts and forensic investigators. Combines Memory Analysis, Live Artifact
> Collection, Timeline Reconstruction, and Evidence Integrity verification in one
> unified interface.

![Python](https://img.shields.io/badge/Python-3.14-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)
![Volatility](https://img.shields.io/badge/Volatility3-Memory_Analysis-purple)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)

---

## 📌 What is ForensicLens?

ForensicLens is a DFIR toolkit that helps analysts investigate security incidents
after they occur. While traditional threat detection tools (like ThreatLens) prevent
attacks in real time, ForensicLens answers the question:

> **"An attack happened — what exactly occurred, when, and how?"**

It was built to demonstrate real-world DFIR workflows used by Incident Response
teams in enterprise environments.

---

## ⚡ Modules

| Module | Description | Real World Use |
|--------|-------------|----------------|
| 🧠 Memory Analyzer | RAM dump analysis using Volatility3 | Find hidden malware in memory |
| 🗂️ Artifact Collector | Live system forensics | Browser history, processes, startup items |
| 📅 Timeline Builder | Chronological event reconstruction | Reconstruct attack sequence |
| 🔐 Hash Verifier | Evidence integrity + Chain of Custody | Legal forensic evidence logging |

---

## 🆚 ForensicLens vs Industry Standard Tools

This is the most important section — understanding where ForensicLens fits
in the professional forensics ecosystem.

### Direct Tool Comparison

| Feature | Autopsy | EnCase | FTK | Volatility3 | **ForensicLens** |
|---------|---------|--------|-----|-------------|-----------------|
| **Price** | Free | $3,000+/yr | $2,000+/yr | Free | **Free** |
| **Platform** | Win/Linux | Windows | Windows | CLI only | **Web Browser** |
| **Memory Analysis** | ✅ Basic | ✅ Deep | ✅ Deep | ✅ Expert | ⚠️ Basic |
| **Disk Forensics** | ✅ Full | ✅ Full | ✅ Full | ❌ | ❌ |
| **Timeline Analysis** | ✅ | ✅ | ✅ | ❌ | ✅ Basic |
| **Chain of Custody** | ✅ Certified | ✅ Certified | ✅ Certified | ❌ | ✅ Basic |
| **Court Admissible** | ⚠️ | ✅ | ✅ | ❌ | ❌ |
| **Learning Curve** | High | Very High | Very High | Expert | **Low** |
| **Web Interface** | ❌ | ❌ | ❌ | ❌ | **✅** |
| **All-in-One UI** | ❌ | ✅ | ✅ | ❌ | **✅** |
| **Custom Rules** | ⚠️ | ⚠️ | ⚠️ | ✅ | **✅** |
| **API Integration** | ❌ | ❌ | ❌ | ❌ | **✅ VirusTotal** |
| **Open Source** | ✅ | ❌ | ❌ | ✅ | **✅** |

### What ForensicLens Does Better

```
┌─────────────────────────────────────────────────────┐
│  Professional Tools Problem:                        │
│  Analyst needs 4-5 separate tools open at once     │
│  → Volatility (terminal)                           │
│  → Autopsy (GUI)                                   │
│  → Hash calculator (separate)                      │
│  → Timeline (manual Excel)                         │
│  → Report (manual Word)                            │
│                                                     │
│  ForensicLens Solution:                            │
│  Everything in ONE browser tab ✅                  │
└─────────────────────────────────────────────────────┘
```

### What Professional Tools Do Better

```
ForensicLens is NOT a replacement for:
→ Court-certified forensic investigations
→ Deep disk forensics (file carving, deleted partition recovery)
→ Mobile device forensics
→ Enterprise-scale incident response
→ Chain of custody for legal proceedings

ForensicLens IS a great tool for:
→ Learning DFIR concepts practically
→ Quick triage during initial IR
→ SOC portfolio demonstration
→ Teaching forensics workflows
→ Rapid artifact collection
```

### The Real Value Proposition

```
Other tools exist. ForensicLens was built to UNDERSTAND them.

Anyone can run Autopsy.
Building a forensics platform from scratch proves you understand
what Autopsy is actually doing under the hood.

That understanding is what recruiters pay for.
```

---

## 🏗️ Project Structure

```
ForensicLens/
├── app.py                       # Flask web application
├── requirements.txt             # Python dependencies
├── README.md
├── forensics/
│   ├── __init__.py
│   ├── memory_analyzer.py       # Volatility3 integration
│   ├── artifact_collector.py    # Live system forensics
│   ├── timeline_builder.py      # Log parsing & timeline
│   └── hash_verifier.py         # MD5/SHA1/SHA256 + VT
├── templates/
│   └── index.html               # ForensicLens UI
├── uploads/                     # Evidence files (gitignored)
└── reports/                     # Generated reports (gitignored)
```

---

## 🖥️ Screenshots

### Memory Analysis
> Upload RAM dump — get processes, network connections, injected code

![Memory Analysis](screenshots/memory_analysis.png)

### Artifact Collection
> One click — collect all live system forensic artifacts

![Artifact Collection](screenshots/artifact_collection.png)

### Timeline Builder
> Upload any log file — get chronological attack reconstruction

![Timeline](screenshots/timeline.png)

### Hash Verifier & Chain of Custody
> Upload evidence file — get hashes + formal evidence log

![Hash Verifier](screenshots/hash_verifier.png)

---

## 🚀 How to Run

### Windows (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/YOUR_USERNAME/forensiclens.git
cd forensiclens

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python app.py

# 4. Open browser
# http://127.0.0.1:5002
```

### Linux / Kali

```bash
git clone https://github.com/YOUR_USERNAME/forensiclens.git
cd forensiclens
pip3 install -r requirements.txt
python3 app.py
```

---

## 📦 Requirements

```
flask
psutil
requests
volatility3
python-dotenv
```

Install all:
```bash
pip install -r requirements.txt
```

---

## 🧠 Module Deep Dive

### Module 1 — Memory Analyzer

Uses **Volatility3** (industry standard) to analyze RAM dumps.

**What it extracts:**
- Running processes and their PIDs
- Network connections at time of capture
- Injected code (malfind plugin)
- Suspicious process detection

**Supported Volatility plugins:**
```
windows.pslist   → Process list
windows.netscan  → Network connections
windows.malfind  → Code injection detection
windows.cmdline  → Process command lines
```

**Real DFIR workflow:**
```
Incident detected
      ↓
Take memory dump (WinPmem / LiME)
      ↓
Upload to ForensicLens
      ↓
Get instant analysis report
      ↓
Escalate findings
```

---

### Module 2 — Artifact Collector

Collects live system artifacts using **psutil** and system APIs.

**What it collects:**
- Running processes (CPU, memory usage)
- Active network connections
- Startup/persistence items
- User accounts
- Recently accessed files

**MITRE ATT&CK Coverage:**
```
T1547 — Boot or Logon Autostart (startup items)
T1078 — Valid Accounts (user accounts)
T1057 — Process Discovery (processes)
T1049 — System Network Connections (connections)
```

---

### Module 3 — Timeline Builder

Parses log files and reconstructs chronological event timeline.

**Supported log formats:**
- Linux auth.log / syslog
- Windows Event Log exports
- Apache / Nginx access logs
- Any custom text log file

**Event detection:**
```
FAILED_LOGIN   → Brute force attempts
SUCCESS_LOGIN  → Successful authentication
SUDO_USAGE     → Privilege escalation
USER_CREATED   → Persistence via new account
DOWNLOAD       → Malware download attempts
EXECUTION      → Command execution
```

---

### Module 4 — Hash Verifier & Chain of Custody

Computes cryptographic hashes and generates formal evidence logs.

**Hash algorithms:**
- MD5 (32 chars) — Legacy compatibility
- SHA1 (40 chars) — Medium strength
- SHA256 (64 chars) — Industry standard

**Chain of Custody log includes:**
```json
{
  "case_number"  : "CASE-2026-001",
  "analyst"      : "Analyst Name",
  "collected_at" : "2026-07-04 10:30:00",
  "evidence": {
    "filename"   : "suspicious.exe",
    "md5"        : "...",
    "sha1"       : "...",
    "sha256"     : "..."
  },
  "vt_result"    : { "malicious": 45, "total": 72 }
}
```

---

## 🔑 API Keys (Optional)

For VirusTotal hash checking:

1. Sign up at [virustotal.com](https://www.virustotal.com)
2. Go to Profile → API Key
3. Open `forensics/hash_verifier.py`
4. Replace `YOUR_VIRUSTOTAL_API_KEY_HERE`

---

## 📚 Skills Demonstrated

- ✅ Digital Forensics & Incident Response (DFIR)
- ✅ Memory Forensics (Volatility3)
- ✅ Live Artifact Collection
- ✅ Log Analysis & Timeline Reconstruction
- ✅ Evidence Integrity & Chain of Custody
- ✅ MITRE ATT&CK Framework Mapping
- ✅ Python Development (Flask, psutil)
- ✅ VirusTotal API Integration

---

## 🔗 Related Projects

> ForensicLens is part of a complete SOC portfolio:

| Project | Description | Link |
|---------|-------------|------|
| 🔍 ThreatLens | Phishing & Malware Detection Platform | [GitHub](#) |
| 📊 Wazuh SOC | Enterprise SIEM Setup | [GitHub](#) |

---

## ⚠️ Disclaimer

ForensicLens is built for **educational and authorized forensic investigation
purposes only**. Always obtain proper legal authorization before performing
forensic analysis on any system. Do not use on systems you do not own or
have explicit permission to investigate.

---

## 📄 License

MIT License — free to use, modify, and distribute with attribution.

---

*Built as part of SOC Analyst Portfolio — Demonstrating DFIR Skills*
