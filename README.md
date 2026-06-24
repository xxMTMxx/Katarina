# ⚔️ Katarina v3.0

```
 ██╗  ██╗ █████╗ ████████╗ █████╗ ██████╗ ██╗███╗   ██╗ █████╗
 ██║ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗
 █████╔╝ ███████║   ██║   ███████║██████╔╝██║██╔██╗ ██║███████║
 ██╔═██╗ ██╔══██║   ██║   ██╔══██║██╔══██╗██║██║╚██╗██║██╔══██║
 ██║  ██╗██║  ██║   ██║   ██║  ██║██║  ██║██║██║ ╚████║██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
              Penetration Testing Recon Tool
                        by MTM
       ──────────────────────────────────────────
              Hunt. Enumerate. Exploit.
```

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ⚠️ Disclaimer
This tool is for **educational purposes** and **authorized penetration testing ONLY**.  
Do not use against systems you don't own or have explicit written permission to test.

---

## 📥 Installation

```bash
git clone https://github.com/xxMTMxx/Katarina.git

```

---

## 🔍 What it does

- Host Discovery 
- Port Scanning
- Firewall Analysis
- Service & Version Detection
- Service Enumeration
- Vulnerability Search
- Recommendations 
- Scan Metadata & Report Generation

---

## 🚀 Usage

```
./katarina.py <target> [options]
try ./katarina.py --help

TARGET:
  192.168.1.1            Single IP
  192.168.1.1-20         Range (last octet 1 to 20)
  192.168.1.0/24         Full subnet
  192.168.1.1,1.2,1.3   Comma-separated IPs

PORT OPTIONS (-p):
  all           All 65535 ports
  top100        Top 100 most common ports
  top1000       Top 1000 most common ports (default)
  21            Single port
  20-100        Port range
  21,22,80,443  Comma-separated list

SCAN TYPE (-s):
  tcp           TCP only
  udp           UDP only
  both          TCP + UDP (default)

TIMING (-t):
  stealth       Very slow, avoids IDS (T2)
  normal        Default speed (T3)
  aggressive    Fast scan (T4)

OUTPUT (-o):
  report.pdf    PDF report
  report.html   HTML report
  report.txt    Text report

EXAMPLES:
  ./katarina.py 192.168.1.1
  ./katarina.py 192.168.1.1 -p top100 -s tcp -o report.pdf
  ./katarina.py 192.168.1.0/24 -p top100 -s tcp
  ./katarina.py 192.168.1.1 -p all -t stealth -o report.html
```
