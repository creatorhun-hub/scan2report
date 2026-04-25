"""
Nmap scan output parser.
Extracts hosts, ports, services, OS information, NSE script results,
MAC addresses, and risk flags for common dangerous services.
"""

import re

# Ports commonly associated with security risk — used to flag entries
_RISKY_PORTS = {
    21:    "FTP — unencrypted file transfer",
    23:    "Telnet — unencrypted remote access",
    25:    "SMTP — mail relay (check for open relay)",
    69:    "TFTP — unauthenticated file transfer",
    110:   "POP3 — unencrypted mail retrieval",
    111:   "rpcbind — RPC portmapper exposure",
    135:   "MSRPC — Windows RPC (lateral movement risk)",
    139:   "NetBIOS — SMB legacy protocol",
    445:   "SMB — common ransomware/exploit vector",
    512:   "rexec — unauthenticated remote exec",
    513:   "rlogin — unauthenticated remote login",
    514:   "rsh — unauthenticated remote shell",
    873:   "rsync — may allow unauthenticated file access",
    1433:  "MSSQL — database exposed to network",
    1521:  "Oracle DB — database exposed to network",
    2049:  "NFS — network file system (check exports)",
    3306:  "MySQL — database exposed to network",
    3389:  "RDP — remote desktop, brute-force target",
    4444:  "Common backdoor/shell port",
    5432:  "PostgreSQL — database exposed to network",
    5900:  "VNC — remote desktop (often unauthenticated)",
    6379:  "Redis — often runs without authentication",
    8080:  "HTTP-alt — check for admin panels",
    27017: "MongoDB — often runs without authentication",
}


def parse_nmap(content: str) -> dict:
    """
    Parse Nmap scan output into structured data.

    Returns a dict with keys:
        tool, scan_type, scan_command, hosts, summary
    """
    result = {
        "tool":         "Nmap",
        "scan_type":    _detect_scan_type(content),
        "scan_command": _extract_scan_command(content),
        "hosts":        [],
        "summary":      {},
    }

    hosts = _extract_hosts(content)
    result["hosts"] = hosts
    result["summary"] = _build_summary(content, hosts)

    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_scan_command(content: str) -> str | None:
    """Pull the original nmap command from the comment header."""
    match = re.search(r"# Nmap .+ as: (.+)", content)
    return match.group(1).strip() if match else None


def _detect_scan_type(content: str) -> str:
    """Identify the type of Nmap scan from flags or output markers."""
    if "-sV" in content or "VERSION" in content:
        return "Version Detection"
    if "-sU" in content:
        return "UDP Scan"
    if "-O" in content or "OS details" in content:
        return "OS Detection"
    if "-sS" in content:
        return "SYN Stealth Scan"
    if "-sA" in content:
        return "ACK Scan"
    if "--script" in content or "NSE:" in content:
        return "Script Scan"
    return "Port Scan"


def _extract_hosts(content: str) -> list:
    """Split content into per-host blocks and parse each one."""
    hosts = []
    host_blocks = re.split(r"(?=Nmap scan report for)", content)

    for block in host_blocks:
        if "Nmap scan report for" not in block:
            continue

        host = {}

        # Address / hostname
        m = re.search(r"Nmap scan report for (.+)", block)
        if m:
            host["address"] = m.group(1).strip()

        # Status
        status_m = re.search(r"Host is (up|down)", block)
        host["status"] = status_m.group(1) if status_m else "unknown"

        # Latency
        lat_m = re.search(r"\((.+?) latency\)", block)
        host["latency"] = lat_m.group(1) if lat_m else None

        # MAC address
        mac_m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})(?:\s+\((.+?)\))?", block)
        if mac_m:
            host["mac_address"] = mac_m.group(1)
            host["mac_vendor"] = mac_m.group(2) if mac_m.group(2) else None
        else:
            host["mac_address"] = None
            host["mac_vendor"] = None

        # OS detection
        os_m = re.search(r"OS details?: (.+)", block)
        host["os"] = os_m.group(1).strip() if os_m else None

        # Port counts
        not_shown_m = re.search(r"Not shown: (\d+) (\w+)", block)
        if not_shown_m:
            host["ports_not_shown"] = {
                "count":  int(not_shown_m.group(1)),
                "state":  not_shown_m.group(2),
            }
        else:
            host["ports_not_shown"] = None

        # Ports
        host["ports"] = _extract_ports(block)

        # NSE script output
        host["scripts"] = _extract_scripts(block)

        hosts.append(host)

    return hosts


def _extract_ports(block: str) -> list:
    """
    Parse port table lines into structured port dicts.
    Also flags ports that are commonly associated with risk.
    """
    ports = []
    # Format: 80/tcp   open  http   Apache httpd 2.4 ((Ubuntu))
    port_re = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\s+(\S+)(?:\s+(.+))?$"
    )

    for line in block.splitlines():
        m = port_re.match(line.strip())
        if not m:
            continue

        port_num = int(m.group(1))
        entry = {
            "port":      port_num,
            "protocol":  m.group(2),
            "state":     m.group(3),
            "service":   m.group(4),
            "version":   m.group(5).strip() if m.group(5) else None,
            "risk_note": _RISKY_PORTS.get(port_num),
        }
        ports.append(entry)

    return ports


def _extract_scripts(block: str) -> list:
    """
    Extract NSE script results from a host block.

    Script output looks like:
        |_ http-title: Apache2 Ubuntu Default Page
        | ssl-cert: Subject: commonName=example.com
    """
    scripts = []
    script_re = re.compile(r"^\|[_\s]?\s*([a-z][a-z0-9\-]+):\s*(.+)$")

    current_name = None
    current_output = []

    for line in block.splitlines():
        m = script_re.match(line.strip())
        if m:
            # Save previous script if any
            if current_name:
                scripts.append({
                    "name":   current_name,
                    "output": " ".join(current_output).strip(),
                })
            current_name = m.group(1)
            current_output = [m.group(2).strip()]
        elif current_name and line.strip().startswith("|"):
            # Continuation line of the same script
            current_output.append(line.strip().lstrip("|").strip())
        elif current_name and line.strip() == "":
            pass
        elif current_name:
            # End of script block
            scripts.append({
                "name":   current_name,
                "output": " ".join(current_output).strip(),
            })
            current_name = None
            current_output = []

    # Flush the last script
    if current_name:
        scripts.append({
            "name":   current_name,
            "output": " ".join(current_output).strip(),
        })

    return scripts


def _build_summary(content: str, hosts: list) -> dict:
    """Build a top-level summary dict for the whole scan."""
    all_ports = [p for h in hosts for p in h.get("ports", [])]

    summary = {
        "hosts_up":          sum(1 for h in hosts if h.get("status") == "up"),
        "hosts_down":        sum(1 for h in hosts if h.get("status") == "down"),
        "total_open_ports":  sum(1 for p in all_ports if p["state"] == "open"),
        "total_filtered":    sum(1 for p in all_ports if "filtered" in p["state"]),
        "risky_ports":       [
            {"host": h["address"], "port": p["port"], "note": p["risk_note"]}
            for h in hosts
            for p in h.get("ports", [])
            if p.get("risk_note") and p["state"] == "open"
        ],
    }

    # Scan duration from footer line
    dur_m = re.search(r"Nmap done.+?(\d+\.\d+) seconds", content)
    summary["duration"] = dur_m.group(1) + "s" if dur_m else None

    return summary
