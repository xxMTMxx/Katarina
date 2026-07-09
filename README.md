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

katarina.py [-h help menu] [-p PORTS] [-s {tcp,udp,both}] [-t {stealth,normal,aggressive}] [-o OUTPUT]

EXAMPLES:
  ./katarina.py 192.168.1.1
  ./katarina.py 192.168.1.1 -p top100 -s tcp -o report.pdf
  ./katarina.py 192.168.1.1-20 -p top1000 -t aggressive -o scan.html
  ./katarina.py 192.168.1.0/24 -p top100 -s tcp
  ./katarina.py 192.168.1.1,192.168.1.5 -p 22,80,443 -s tcp -o results.pdf
  ./katarina.py 192.168.1.1 -p all -t stealth -o report.html


```
