"""
AI-powered analysis module for scan2report.
Sends parsed scan data to a Replicate-hosted LLM and returns a structured
vulnerability summary, risk level, and recommended fixes.

Requires the REPLICATE_API_TOKEN environment variable to be set.
"""

import os
import re
import replicate


# Model to use — Llama 3 8B Instruct is fast and well-suited to security tasks
_MODEL = "meta/meta-llama-3-8b-instruct"

# Input parameters for the model
_MODEL_INPUT = {
    "max_tokens":        1024,
    "temperature":       0.3,   # Low temp = consistent, factual output
    "top_p":             0.9,
    "system_prompt": (
        "You are a senior penetration tester and cybersecurity analyst. "
        "Your job is to analyse security scan results and produce clear, "
        "accurate, and actionable reports. Be concise and professional. "
        "Do not invent findings that are not present in the data."
    ),
}


def check_api_key() -> bool:
    """Return True if REPLICATE_API_TOKEN is set in the environment."""
    return bool(os.environ.get("REPLICATE_API_TOKEN"))


def analyze_with_ai(analysis: dict, parsed: dict) -> dict:
    """
    Send scan analysis data to the AI model and return a structured result.

    Args:
        analysis: Output from analyzer.analyze()
        parsed:   Raw output from the parser (for extra context)

    Returns:
        Dict with keys:
            vulnerability_summary  — plain-text summary
            risk_level             — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
            recommended_fixes      — list of actionable fix strings
            raw_response           — full model output (for debugging)

    Raises:
        EnvironmentError: if REPLICATE_API_TOKEN is not set
        RuntimeError:     on API errors
    """
    if not check_api_key():
        raise EnvironmentError(
            "REPLICATE_API_TOKEN is not set. "
            "Add it to your environment secrets and restart."
        )

    prompt = _build_prompt(analysis, parsed)

    try:
        output_chunks = replicate.run(_MODEL, input={**_MODEL_INPUT, "prompt": prompt})
        raw_response  = "".join(output_chunks)
    except Exception as e:
        raise RuntimeError(f"Replicate API error: {e}") from e

    return _parse_response(raw_response)


# ── Prompt builder ────────────────────────────────────────────────────────────

def _build_prompt(analysis: dict, parsed: dict) -> str:
    """
    Build a compact, structured prompt from the scan data.
    We summarise the data rather than dumping raw JSON so the context
    stays within token limits and stays focused on what matters.
    """
    tool    = analysis.get("tool", "Unknown")
    summary = _summarise_scan(analysis, parsed, tool)

    return f"""\
Analyse the following security scan results and respond in the exact format shown below.

=== SCAN RESULTS ===
Tool: {tool}
{summary}
=== END OF SCAN RESULTS ===

Respond using EXACTLY this format — no extra commentary before or after:

## Vulnerability Summary
[Write 2-4 sentences summarising what was found, what is at risk, and the overall severity. \
Be specific about the tool, targets, and types of vulnerabilities found.]

## Risk Level
[Write exactly one word: CRITICAL, HIGH, MEDIUM, or LOW]

## Recommended Fixes
1. [Specific, actionable fix for the most critical issue]
2. [Next most important fix]
3. [Next fix]
4. [Next fix — add or remove items as needed, aim for 4-6 total]
"""


def _summarise_scan(analysis: dict, parsed: dict, tool: str) -> str:
    """Build a compact plain-text summary of scan findings for the prompt."""
    lines = []

    if tool == "Nmap":
        findings = analysis.get("findings", [])
        risky    = analysis.get("risky_ports", [])
        lines.append(f"Hosts scanned: {len(findings)}")
        lines.append(f"Hosts up: {sum(1 for h in findings if h.get('status') == 'up')}")
        lines.append(f"Total open ports: {sum(h.get('open_ports', 0) for h in findings)}")
        lines.append(f"Risky services flagged: {len(risky)}")

        for host in findings:
            addr  = host.get("host", "?")
            os_   = host.get("os") or "Unknown OS"
            ports = host.get("ports", [])
            lines.append(f"\nHost {addr} ({os_}):")
            for p in ports:
                note = f" [RISK: {p['risk_note']}]" if p.get("risk_note") else ""
                ver  = f" ({p['version']})" if p.get("version") else ""
                lines.append(f"  {p['port']}/{p['protocol']} {p['service']}{ver}{note}")
            for s in host.get("scripts", []):
                lines.append(f"  [Script] {s['name']}: {s['output'][:120]}")

    elif tool == "Nikto":
        target = analysis.get("target", {})
        lines.append(f"Target: {target.get('hostname') or target.get('ip', '?')}:{target.get('port', '?')}")
        lines.append(f"Server: {target.get('server', 'Unknown')}")
        lines.append(f"Scan duration: {target.get('duration', 'Unknown')}")
        lines.append(f"Total findings: {len(analysis.get('findings', []))}")
        lines.append(f"HIGH: {analysis.get('high_count', 0)}, "
                     f"MEDIUM: {analysis.get('medium_count', 0)}, "
                     f"INFO: {analysis.get('info_count', 0)}")

        cve_refs = analysis.get("cve_refs", [])
        if cve_refs:
            lines.append(f"CVEs referenced: {', '.join(cve_refs)}")

        lines.append("\nFindings:")
        for f in analysis.get("findings", []):
            sev  = f.get("severity", "INFO")
            path = f" [{f['url_path']}]" if f.get("url_path") else ""
            cve  = f" (CVE: {f['cve']})" if f.get("cve") else ""
            lines.append(f"  [{sev}]{path}{cve} {f['description'][:120]}")

    elif tool == "SQLmap":
        target = analysis.get("target", {})
        waf    = analysis.get("waf", {})
        lines.append(f"Target URL: {target.get('url', '?')}")
        lines.append(f"DBMS: {target.get('dbms', 'Unknown')}")
        lines.append(f"Web OS: {target.get('web_os', 'Unknown')}")
        lines.append(f"Web Tech: {target.get('web_tech', 'Unknown')}")
        if waf.get("detected"):
            lines.append(f"WAF detected: {waf.get('name') or 'Yes'}")

        for inj in analysis.get("injections", []):
            types = ", ".join(inj.get("injection_types", []))
            lines.append(f"\nInjectable parameter: {inj['parameter']} ({inj['method']})")
            lines.append(f"  Injection types: {types}")
            for payload in inj.get("payloads", [])[:2]:
                lines.append(f"  Payload: {payload[:100]}")

        dbs = analysis.get("databases", [])
        if dbs:
            lines.append(f"\nDatabases found: {', '.join(dbs)}")

        tables = analysis.get("tables", {})
        for db, tbl_list in tables.items():
            lines.append(f"  {db}: {', '.join(tbl_list)}")

        dump = analysis.get("dump", {})
        if dump:
            for tbl, tbl_data in dump.items():
                rows = len(tbl_data.get("rows", []))
                cols = ", ".join(tbl_data.get("columns", []))
                lines.append(f"\nData dumped from '{tbl}': {rows} row(s) — columns: {cols}")

    return "\n".join(lines)


# ── Response parser ───────────────────────────────────────────────────────────

def _parse_response(raw: str) -> dict:
    """
    Parse the LLM's response into structured fields.
    Falls back to the raw text if the expected format is not found.
    """
    result = {
        "vulnerability_summary": "",
        "risk_level":            "UNKNOWN",
        "recommended_fixes":     [],
        "raw_response":          raw,
    }

    # Extract vulnerability summary
    summary_m = re.search(
        r"##\s*Vulnerability Summary\s*\n(.*?)(?=##|\Z)",
        raw, re.DOTALL | re.IGNORECASE
    )
    if summary_m:
        result["vulnerability_summary"] = summary_m.group(1).strip()

    # Extract risk level
    risk_m = re.search(
        r"##\s*Risk Level\s*\n\s*(CRITICAL|HIGH|MEDIUM|LOW)\b",
        raw, re.IGNORECASE
    )
    if risk_m:
        result["risk_level"] = risk_m.group(1).upper()
    else:
        # Fallback: scan whole response for a standalone risk keyword
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if re.search(rf"\b{level}\b", raw, re.IGNORECASE):
                result["risk_level"] = level
                break

    # Extract recommended fixes — numbered list items
    fixes_m = re.search(
        r"##\s*Recommended Fixes\s*\n(.*?)(?=##|\Z)",
        raw, re.DOTALL | re.IGNORECASE
    )
    if fixes_m:
        fixes_block = fixes_m.group(1)
        fixes = re.findall(r"^\s*\d+\.\s+(.+)", fixes_block, re.MULTILINE)
        result["recommended_fixes"] = [f.strip() for f in fixes if f.strip()]

    return result
