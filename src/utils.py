"""
Utility helpers for scan2report.
Provides JSON serialization for parsed scan data.
"""

import json
import os
from datetime import datetime


def to_json(data: dict, indent: int = 2) -> str:
    """
    Serialize any parsed scan dict to a pretty-printed JSON string.

    Args:
        data:   A parsed result dict (from parse_nmap, parse_nikto, etc.)
        indent: JSON indentation level (default 2 spaces)

    Returns:
        A formatted JSON string.
    """
    return json.dumps(data, indent=indent, ensure_ascii=False, default=str)


def save_json(data: dict, output_dir: str = ".") -> str:
    """
    Write parsed scan data to a timestamped .json file.

    Args:
        data:       A parsed result dict.
        output_dir: Directory to save the file (created if missing).

    Returns:
        The full path of the saved file.
    """
    tool = data.get("tool", "unknown").lower()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"parsed_{tool}_{timestamp}.json"

    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(to_json(data))

    return filepath


def summarize(data: dict) -> str:
    """
    Return a one-line human-readable summary of a parsed scan dict.
    Useful for quick display in the CLI without showing the full structure.
    """
    tool = data.get("tool", "Unknown")
    summary = data.get("summary", {})

    if tool == "Nmap":
        hosts_up = summary.get("hosts_up", 0)
        open_ports = summary.get("total_open_ports", 0)
        risky = len(summary.get("risky_ports", []))
        return (
            f"Nmap — {hosts_up} host(s) up, "
            f"{open_ports} open port(s), "
            f"{risky} risky service(s) flagged"
        )

    if tool == "Nikto":
        total = summary.get("total", 0)
        high  = summary.get("HIGH", 0)
        med   = summary.get("MEDIUM", 0)
        return (
            f"Nikto — {total} finding(s): "
            f"{high} HIGH, {med} MEDIUM"
        )

    if tool == "SQLmap":
        params = summary.get("injectable_params", 0)
        dbs    = summary.get("databases_found", 0)
        rows   = summary.get("rows_dumped", 0)
        waf    = " [WAF detected]" if summary.get("waf_detected") else ""
        return (
            f"SQLmap — {params} injectable param(s), "
            f"{dbs} database(s) found, "
            f"{rows} row(s) dumped{waf}"
        )

    return f"{tool} scan — no summary available"
