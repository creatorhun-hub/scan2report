"""
Nikto web server scan output parser.
Extracts target info, findings (with severity, OSVDB refs, and URL paths),
and calculates scan duration.
"""

import re
from datetime import datetime


def parse_nikto(content: str) -> dict:
    """
    Parse Nikto scan output into structured data.

    Returns a dict with keys:
        tool, targets, findings, summary
    """
    result = {
        "tool":     "Nikto",
        "targets":  [],
        "findings": [],
        "summary":  {},
    }

    result["targets"]  = _extract_targets(content)
    result["findings"] = _extract_findings(content)
    result["summary"]  = _build_summary(result["findings"], result["targets"])

    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_targets(content: str) -> list:
    """Extract target host, port, server, and timing details."""
    targets = []

    ip_m      = re.search(r"\+ Target IP:\s+(.+)",       content)
    host_m    = re.search(r"\+ Target Hostname:\s+(.+)",  content)
    port_m    = re.search(r"\+ Target Port:\s+(\d+)",     content)
    server_m  = re.search(r"\+ Server:\s+(.+)",           content)
    start_m   = re.search(r"\+ Start Time:\s+(.+)",       content)
    end_m     = re.search(r"\+ End Time:\s+(.+)",         content)

    if ip_m or host_m:
        start_str = start_m.group(1).strip() if start_m else None
        end_str   = end_m.group(1).strip()   if end_m   else None

        targets.append({
            "ip":         ip_m.group(1).strip()   if ip_m   else None,
            "hostname":   host_m.group(1).strip() if host_m else None,
            "port":       int(port_m.group(1))    if port_m else None,
            "server":     server_m.group(1).strip() if server_m else None,
            "start_time": start_str,
            "end_time":   end_str,
            "duration":   _calc_duration(start_str, end_str),
        })

    return targets


def _calc_duration(start: str | None, end: str | None) -> str | None:
    """Calculate elapsed scan time from Nikto's timestamp strings."""
    if not start or not end:
        return None
    # Nikto timestamps: 2026-04-25 10:15:22 (GMT0)
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        # Strip trailing timezone annotation if present
        s = re.sub(r"\s*\(.*\)$", "", start).strip()
        e = re.sub(r"\s*\(.*\)$", "", end).strip()
        delta = datetime.strptime(e, fmt) - datetime.strptime(s, fmt)
        secs = int(delta.total_seconds())
        if secs < 60:
            return f"{secs}s"
        return f"{secs // 60}m {secs % 60}s"
    except ValueError:
        return None


def _extract_findings(content: str) -> list:
    """
    Extract individual vulnerability/finding lines from Nikto output.

    Each finding includes:
        description  — full text
        severity     — HIGH / MEDIUM / INFO
        osvdb_id     — OSVDB reference number (if present)
        url_path     — affected URL path (if found in the description)
    """
    findings = []

    # Lines to skip — they are header/footer metadata, not findings
    skip_prefixes = (
        "Target IP:", "Target Hostname:", "Target Port:",
        "Server:", "Start Time:", "End Time:",
        "Scan terminated", "Nikto v", "- Nikto",
        "host(s) tested", "+ 0 error",
    )

    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("+ "):
            continue
        text = line[2:].strip()

        if not text:
            continue
        if any(text.startswith(p) for p in skip_prefixes):
            continue

        findings.append({
            "description": text,
            "severity":    _classify_severity(text),
            "osvdb_id":    _extract_osvdb(text),
            "url_path":    _extract_url_path(text),
            "cve":         _extract_cve(text),
        })

    return findings


def _classify_severity(text: str) -> str:
    """
    Classify a finding's severity based on keyword matching.
    Returns HIGH, MEDIUM, or INFO.
    """
    t = text.lower()

    high_keywords = [
        "xss", "cross-site scripting",
        "sql injection", "sqli",
        "rce", "remote code execution",
        "command injection", "os command",
        "directory traversal", "path traversal",
        "local file inclusion", "remote file inclusion",
        "lfi", "rfi",
        "shell upload", "file upload",
        "exploit", "arbitrary code",
        "authentication bypass",
        "default credentials", "default password",
        "unauthenticated", "no authentication",
        "buffer overflow", "format string",
    ]
    medium_keywords = [
        "outdated", "deprecated", "end-of-life",
        "csrf", "cross-site request forgery",
        "clickjacking", "x-frame-options",
        "information disclosure",
        "x-content-type", "x-xss-protection",
        "cookie", "httponly", "secure flag",
        "version", "server banner",
        "directory indexing", "directory listing",
        "backup", "configuration file",
        "phpinfo", "php info",
        "admin", "login page",
        "robots.txt", "sitemap",
        "ssl", "tls", "certificate",
    ]

    if any(k in t for k in high_keywords):
        return "HIGH"
    if any(k in t for k in medium_keywords):
        return "MEDIUM"
    return "INFO"


def _extract_osvdb(text: str) -> str | None:
    """Extract OSVDB reference ID from a finding description."""
    m = re.search(r"OSVDB-(\d+)", text)
    return m.group(1) if m else None


def _extract_cve(text: str) -> str | None:
    """Extract a CVE identifier from a finding description, if present."""
    m = re.search(r"(CVE-\d{4}-\d+)", text, re.IGNORECASE)
    return m.group(1).upper() if m else None


def _extract_url_path(text: str) -> str | None:
    """
    Pull out an affected URL path from a finding description.
    Looks for patterns like /admin/, /login.php, etc.
    """
    m = re.search(r"(/[\w\-./]+\.[a-z]{2,4}|/[\w\-./]+/)", text)
    return m.group(1) if m else None


def _build_summary(findings: list, targets: list) -> dict:
    """Summarise findings by severity and include target metadata."""
    counts = {"HIGH": 0, "MEDIUM": 0, "INFO": 0}
    osvdb_refs = []
    cve_refs = []

    for f in findings:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        if f.get("osvdb_id"):
            osvdb_refs.append(f["osvdb_id"])
        if f.get("cve"):
            cve_refs.append(f["cve"])

    target = targets[0] if targets else {}

    return {
        "total":       len(findings),
        "HIGH":        counts["HIGH"],
        "MEDIUM":      counts["MEDIUM"],
        "INFO":        counts["INFO"],
        "osvdb_refs":  sorted(set(osvdb_refs)),
        "cve_refs":    sorted(set(cve_refs)),
        "duration":    target.get("duration"),
        "server":      target.get("server"),
    }
