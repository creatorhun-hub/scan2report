"""
Analyzer module.
Takes parsed scan data and produces a human-readable analysis summary,
pulling from all available parsed fields including risk flags,
OSVDB/CVE refs, WAF detection, and dump data.
"""


def analyze(parsed_data: dict) -> dict:
    """
    Analyze parsed scan data and return a structured analysis dict.

    Returns keys: tool, overview, findings, recommendations,
    plus tool-specific keys.
    """
    tool = parsed_data.get("tool", "Unknown")

    if tool == "Nmap":
        return _analyze_nmap(parsed_data)
    elif tool == "Nikto":
        return _analyze_nikto(parsed_data)
    elif tool == "SQLmap":
        return _analyze_sqlmap(parsed_data)
    else:
        return {
            "tool":            tool,
            "overview":        "Unknown tool — cannot analyze.",
            "findings":        [],
            "recommendations": [],
        }


# ── Nmap ──────────────────────────────────────────────────────────────────────

def _analyze_nmap(data: dict) -> dict:
    """Analyze Nmap parsed data."""
    hosts   = data.get("hosts", [])
    summary = data.get("summary", {})

    host_findings    = []
    recommendations  = []
    seen_recs        = set()

    for host in hosts:
        address    = host.get("address", "unknown")
        open_ports = [p for p in host.get("ports", []) if p["state"] == "open"]
        scripts    = host.get("scripts", [])

        host_entry = {
            "host":        address,
            "status":      host.get("status", "unknown"),
            "os":          host.get("os"),
            "mac_address": host.get("mac_address"),
            "mac_vendor":  host.get("mac_vendor"),
            "latency":     host.get("latency"),
            "open_ports":  len(open_ports),
            "ports":       open_ports,
            "scripts":     scripts,
        }
        host_findings.append(host_entry)

        # Recommendations from risky port flags (set by the parser)
        for port in open_ports:
            note = port.get("risk_note")
            if note:
                rec = f"[{address}] Port {port['port']} — {note}"
                if rec not in seen_recs:
                    recommendations.append(rec)
                    seen_recs.add(rec)

        # Recommendations from NSE script output
        for script in scripts:
            name   = script.get("name", "")
            output = script.get("output", "").lower()
            vuln_keywords = ["vulnerable", "exploit", "cve-", "overflow", "injection"]
            if any(k in output for k in vuln_keywords):
                rec = f"[{address}] NSE script '{name}' flagged a potential vulnerability"
                if rec not in seen_recs:
                    recommendations.append(rec)
                    seen_recs.add(rec)

    if not recommendations:
        recommendations.append("No immediately high-risk open ports detected.")

    overview = (
        f"Scanned {len(hosts)} host(s). "
        f"{summary.get('hosts_up', 0)} up, {summary.get('hosts_down', 0)} down. "
        f"{summary.get('total_open_ports', 0)} open port(s), "
        f"{summary.get('total_filtered', 0)} filtered. "
        f"{len(summary.get('risky_ports', []))} risky service(s) flagged."
    )

    return {
        "tool":            "Nmap",
        "scan_type":       data.get("scan_type", "Port Scan"),
        "scan_command":    data.get("scan_command"),
        "overview":        overview,
        "findings":        host_findings,
        "risky_ports":     summary.get("risky_ports", []),
        "recommendations": recommendations,
    }


# ── Nikto ─────────────────────────────────────────────────────────────────────

def _analyze_nikto(data: dict) -> dict:
    """Analyze Nikto parsed data."""
    findings = data.get("findings", [])
    targets  = data.get("targets", [])
    summary  = data.get("summary", {})

    target_info = targets[0] if targets else {}

    high   = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    info   = [f for f in findings if f["severity"] == "INFO"]

    recommendations = []
    for f in high:
        desc = f["description"]
        cve  = f" ({f['cve']})" if f.get("cve") else ""
        recommendations.append(f"[HIGH]{cve} {desc}")
    for f in medium:
        desc = f["description"]
        recommendations.append(f"[MEDIUM] {desc}")

    if not recommendations:
        recommendations.append("No high or medium severity issues detected.")

    host_label = target_info.get("hostname") or target_info.get("ip", "unknown")
    port_label = f":{target_info['port']}" if target_info.get("port") else ""
    duration   = summary.get("duration", "unknown")

    overview = (
        f"Web scan against {host_label}{port_label}. "
        f"Server: {summary.get('server') or 'unknown'}. "
        f"Duration: {duration}. "
        f"Found {summary.get('total', 0)} issue(s): "
        f"{summary.get('HIGH', 0)} HIGH, {summary.get('MEDIUM', 0)} MEDIUM, "
        f"{summary.get('INFO', 0)} INFO."
    )

    return {
        "tool":            "Nikto",
        "target":          target_info,
        "overview":        overview,
        "findings":        findings,
        "high_count":      len(high),
        "medium_count":    len(medium),
        "info_count":      len(info),
        "osvdb_refs":      summary.get("osvdb_refs", []),
        "cve_refs":        summary.get("cve_refs", []),
        "recommendations": recommendations,
    }


# ── SQLmap ────────────────────────────────────────────────────────────────────

def _analyze_sqlmap(data: dict) -> dict:
    """Analyze SQLmap parsed data."""
    injections = data.get("injections", [])
    databases  = data.get("databases", [])
    tables     = data.get("tables", {})
    columns    = data.get("columns", {})
    dump       = data.get("dump", {})
    waf        = data.get("waf", {})
    target     = data.get("target", {})
    summary    = data.get("summary", {})

    recommendations = []

    if waf.get("detected"):
        waf_name = waf.get("name") or "unknown"
        recommendations.append(
            f"WAF/IPS detected ({waf_name}) — SQLmap may have bypassed it. "
            "Review WAF rules and ensure they cover all injection vectors."
        )

    if injections:
        types = summary.get("injection_types", [])
        type_str = ", ".join(types) if types else "unknown types"
        recommendations.append(
            f"SQL injection found in {len(injections)} parameter(s) "
            f"({type_str}). Use parameterized queries or prepared statements immediately."
        )

    if databases:
        db_list = ", ".join(databases[:5]) + ("..." if len(databases) > 5 else "")
        recommendations.append(
            f"Database names exposed ({db_list}). "
            "Restrict the web app DB account to only the tables it needs."
        )

    if tables:
        total_tables = sum(len(v) for v in tables.values())
        recommendations.append(
            f"Schema exposed: {total_tables} table(s) enumerated. "
            "Ensure the DB user has no access to information_schema in production."
        )

    if dump:
        total_rows = sum(len(v.get("rows", [])) for v in dump.values())
        recommendations.append(
            f"Data dumped: {total_rows} row(s) from {len(dump)} table(s). "
            "Treat all exposed data as compromised — rotate credentials immediately."
        )

    if not recommendations:
        recommendations.append("No injection points found. Verify target and tested parameters.")

    waf_note = f" WAF detected: {waf.get('name') or 'yes'}." if waf.get("detected") else ""
    overview = (
        f"Target: {target.get('url', 'unknown')}. "
        f"DBMS: {summary.get('dbms') or 'unknown'}.{waf_note} "
        f"{summary.get('injectable_params', 0)} injectable parameter(s). "
        f"{summary.get('databases_found', 0)} database(s), "
        f"{summary.get('tables_found', 0)} table(s), "
        f"{summary.get('rows_dumped', 0)} row(s) dumped."
    )

    return {
        "tool":            "SQLmap",
        "target":          target,
        "waf":             waf,
        "overview":        overview,
        "injections":      injections,
        "databases":       databases,
        "tables":          tables,
        "columns":         columns,
        "dump":            dump,
        "recommendations": recommendations,
    }
