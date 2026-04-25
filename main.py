"""
scan2report — CLI entry point.

Turn raw security scan outputs into professional AI-powered reports.

Usage:
    python main.py

Environment variables:
    REPLICATE_API_TOKEN  — Required for AI analysis (option 5)
"""

import os
import sys

# ── Import core modules from src/ ─────────────────────────────────────────────
_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, _SRC)

from detector import detect_tool
from parsers import parse_nmap, parse_nikto, parse_sqlmap
from analyzer import analyze
from reporter import generate_report
from md_reporter import generate_md_report
from ai_analyzer import analyze_with_ai, check_api_key
from utils import save_json, summarize


# ── Shared state ──────────────────────────────────────────────────────────────

state = {
    "filepath":    None,   # Path to the uploaded scan file
    "content":     None,   # Raw text content
    "tool":        None,   # Detected tool ("nmap", "nikto", "sqlmap")
    "parsed":      None,   # Structured data from the parser
    "analysis":    None,   # Analysis dict from the analyzer
    "ai_analysis": None,   # AI-generated analysis dict
}

# ── Display helpers ───────────────────────────────────────────────────────────

SEPARATOR = "─" * 52
WIDTH     = 52

BANNER = f"""
{'═' * WIDTH}
  scan2report  ·  Security Scan Analyzer
  Turn raw scan outputs into professional reports.
{'═' * WIDTH}"""


def clear():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    """Print the tool banner and current file status."""
    print(BANNER)


def print_status():
    """Show the current loaded file and its processing state."""
    if state["filepath"]:
        tool_label = state["tool"].upper() if state["tool"] else "not detected"
        flags = []
        if state["analysis"]:
            flags.append("analyzed")
        if state["ai_analysis"]:
            flags.append("AI")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  File   : {os.path.basename(state['filepath'])}")
        print(f"  Tool   : {tool_label}{flag_str}")
    else:
        print("  File   : (none loaded)")
    print(SEPARATOR)


def pause():
    """Wait for the user to press Enter before returning to the menu."""
    input("\nPress Enter to return to the menu...")


# ── Menu actions ──────────────────────────────────────────────────────────────

def upload_file():
    """Option 1 — Ask for a file path and load it into memory."""
    print("\n[1] Upload Scan File")
    print(SEPARATOR)
    filepath = input("  Path to scan file: ").strip()

    if not filepath:
        print("  No path entered.")
        pause()
        return

    filepath = os.path.expanduser(filepath)

    if not os.path.isfile(filepath):
        print(f"  Error: File not found — '{filepath}'")
        pause()
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        print(f"  Error reading file: {exc}")
        pause()
        return

    if not content.strip():
        print("  Error: The file is empty.")
        pause()
        return

    # Auto-detect the scan tool
    tool = detect_tool(content)

    # Reset all downstream state on each new upload
    state.update({
        "filepath":    filepath,
        "content":     content,
        "tool":        tool,
        "parsed":      None,
        "analysis":    None,
        "ai_analysis": None,
    })

    print(f"\n  Loaded  : {os.path.basename(filepath)}")
    if tool == "unknown":
        print("  Warning : Could not detect the scan tool.")
        print("            Supported tools: Nmap, Nikto, SQLmap")
    else:
        print(f"  Detected: {tool.upper()} scan")

    pause()


def analyze_scan():
    """Option 2 — Parse and analyze the loaded scan file."""
    print("\n[2] Analyze Scan")
    print(SEPARATOR)

    if not state["content"]:
        print("  No file loaded. Please upload a scan file first (option 1).")
        pause()
        return

    if state["tool"] == "unknown":
        print("  Cannot analyze: unknown scan tool.")
        print("  Supported tools: Nmap, Nikto, SQLmap")
        pause()
        return

    parsers = {"nmap": parse_nmap, "nikto": parse_nikto, "sqlmap": parse_sqlmap}

    print(f"  Parsing {state['tool'].upper()} output...", end=" ", flush=True)
    try:
        parsed = parsers[state["tool"]](state["content"])
    except Exception as exc:
        print(f"\n  Error during parsing: {exc}")
        pause()
        return
    print("done.")

    print("  Analyzing...", end=" ", flush=True)
    try:
        analysis = analyze(parsed)
    except Exception as exc:
        print(f"\n  Error during analysis: {exc}")
        pause()
        return
    print("done.\n")

    state["parsed"]      = parsed
    state["analysis"]    = analysis
    state["ai_analysis"] = None  # Reset AI on re-analysis

    # Show overview
    print(SEPARATOR)
    print("  OVERVIEW")
    print(SEPARATOR)
    print(f"  {analysis.get('overview', 'No overview available.')}")

    _print_findings_preview(analysis)
    pause()


def _print_findings_preview(analysis: dict):
    """Print a quick tool-specific summary to the terminal."""
    tool = analysis.get("tool", "")

    print()
    print(SEPARATOR)
    print("  QUICK SUMMARY")
    print(SEPARATOR)

    if tool == "Nmap":
        for host in analysis.get("findings", []):
            icon  = "+" if host["status"] == "up" else "-"
            mac   = f"  MAC: {host['mac_address']}" if host.get("mac_address") else ""
            os_   = f"  OS: {host['os']}" if host.get("os") else ""
            print(f"  [{icon}] {host['host']}  ({host['open_ports']} open port(s)){mac}{os_}")
            for p in host.get("ports", [])[:6]:
                ver   = f" — {p['version']}" if p.get("version") else ""
                risky = " [!]" if p.get("risk_note") else ""
                print(f"        {p['port']}/{p['protocol']}  {p['service']}{ver}{risky}")
            if len(host.get("ports", [])) > 6:
                print(f"        ... and {len(host['ports']) - 6} more")
            for s in host.get("scripts", [])[:3]:
                print(f"        [script] {s['name']}: {s['output'][:60]}")

        risky = analysis.get("risky_ports", [])
        if risky:
            print()
            print(f"  Risky services: {len(risky)}")
            for r in risky[:5]:
                print(f"    ! {r['host']}:{r['port']} — {r['note']}")

    elif tool == "Nikto":
        h = analysis.get("high_count", 0)
        m = analysis.get("medium_count", 0)
        i = analysis.get("info_count", 0)
        print(f"  HIGH: {h}  MEDIUM: {m}  INFO: {i}")
        cve_refs = analysis.get("cve_refs", [])
        if cve_refs:
            print(f"  CVEs     : {', '.join(cve_refs)}")
        print()
        for f in analysis.get("findings", [])[:10]:
            sev      = f.get("severity", "INFO")
            url_hint = f"  [{f['url_path']}]" if f.get("url_path") else ""
            print(f"  [{sev:6}]{url_hint} {f['description'][:65]}")
        total = len(analysis.get("findings", []))
        if total > 10:
            print(f"  ... and {total - 10} more finding(s)")

    elif tool == "SQLmap":
        waf = analysis.get("waf", {})
        if waf.get("detected"):
            print(f"  [WAF] Detected: {waf.get('name') or 'unknown'}")
        for inj in analysis.get("injections", []):
            print(f"  [INJECT] {inj['parameter']} ({inj['method']})")
            for t in inj.get("injection_types", []):
                print(f"           Type: {t}")
        dbs = analysis.get("databases", [])
        if dbs:
            print(f"  [DB]     Databases: {', '.join(dbs)}")
        dump = analysis.get("dump", {})
        if dump:
            print()
            total_rows = sum(len(v.get("rows", [])) for v in dump.values())
            print(f"  [DUMP]   {total_rows} row(s) across {len(dump)} table(s)")


def generate_text_report():
    """Option 3 — Write a plain-text report and optionally a JSON export."""
    print("\n[3] Generate Text Report")
    print(SEPARATOR)

    if not state["analysis"]:
        print("  No analysis yet. Please run option 2 first.")
        pause()
        return

    output_dir = input("  Save to directory [default: results/]: ").strip() or "results"
    output_dir = os.path.expanduser(output_dir)

    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as exc:
        print(f"  Error creating directory: {exc}")
        pause()
        return

    try:
        txt_path = generate_report(state["analysis"], output_dir)
        print(f"\n  Text report : {txt_path}")
    except Exception as exc:
        print(f"  Error generating text report: {exc}")

    want_json = input("\n  Also export raw parsed data as JSON? (y/N): ").strip().lower()
    if want_json == "y" and state["parsed"]:
        try:
            json_path = save_json(state["parsed"], output_dir)
            print(f"  JSON export : {json_path}")
        except Exception as exc:
            print(f"  Error saving JSON: {exc}")

    pause()


def generate_markdown_report():
    """Option 4 — Generate a professional Markdown penetration testing report."""
    print("\n[4] Generate Markdown Report")
    print(SEPARATOR)

    if not state["analysis"]:
        print("  No analysis yet. Please run option 2 first.")
        pause()
        return

    output_dir  = input("  Save to directory [default: results/]: ").strip() or "results"
    output_dir  = os.path.expanduser(output_dir)
    custom_name = input("  Filename [default: report.md]: ").strip() or "report.md"
    if not custom_name.endswith(".md"):
        custom_name += ".md"

    # Merge AI results into the report if available
    analysis = dict(state["analysis"])
    if state["ai_analysis"]:
        ai = state["ai_analysis"]
        analysis["ai_summary"]    = ai.get("vulnerability_summary", "")
        analysis["ai_risk_level"] = ai.get("risk_level", "")
        analysis["ai_fixes"]      = ai.get("recommended_fixes", [])

    try:
        md_path = generate_md_report(analysis, output_dir, custom_name)
        print(f"\n  Markdown report saved to: {md_path}")
    except Exception as exc:
        print(f"  Error generating Markdown report: {exc}")

    pause()


def run_ai_analysis():
    """Option 5 — Send scan data to the Replicate AI model for deep analysis."""
    print("\n[5] Analyze with AI")
    print(SEPARATOR)

    if not state["analysis"] or not state["parsed"]:
        print("  No scan analyzed yet. Please run option 2 first.")
        pause()
        return

    if not check_api_key():
        print("  REPLICATE_API_TOKEN is not set.")
        print("  Add it to your .env file and restart the tool.")
        print("  See .env.example for details.")
        pause()
        return

    tool = state["tool"].upper() if state["tool"] else "scan"
    print(f"  Sending {tool} data to AI model...")
    print("  This may take 15-30 seconds...\n")

    try:
        ai_result = analyze_with_ai(state["analysis"], state["parsed"])
    except EnvironmentError as exc:
        print(f"  Configuration error: {exc}")
        pause()
        return
    except RuntimeError as exc:
        print(f"  API error: {exc}")
        pause()
        return
    except Exception as exc:
        print(f"  Unexpected error: {exc}")
        pause()
        return

    state["ai_analysis"] = ai_result

    # Display results
    risk       = ai_result.get("risk_level", "UNKNOWN")
    icons      = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
    icon       = icons.get(risk, "⚪")
    summary    = ai_result.get("vulnerability_summary", "No summary returned.")
    fixes      = ai_result.get("recommended_fixes", [])

    print(SEPARATOR)
    print("  AI ANALYSIS RESULTS")
    print(SEPARATOR)
    print(f"\n  Risk Level: {icon} {risk}\n")

    print("  Summary:")
    print("  " + "-" * 46)
    for line in _wrap(summary, 46):
        print(f"  {line}")

    if fixes:
        print()
        print("  Recommended Fixes:")
        print("  " + "-" * 46)
        for i, fix in enumerate(fixes, 1):
            print(f"  {i}. {fix}")

    print()
    print("  Tip: Run option 4 to include this AI analysis in your Markdown report.")
    pause()


def _wrap(text: str, width: int) -> list:
    """Word-wrap a string to the given column width."""
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current += (" " if current else "") + word
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


# ── Main menu loop ────────────────────────────────────────────────────────────

def menu():
    """Display the main menu and dispatch user choices."""
    while True:
        clear()
        print_header()
        print_status()
        print("  1. Upload scan file")
        print("  2. Analyze scan")
        print("  3. Generate text report      (.txt + optional JSON)")
        print("  4. Generate Markdown report  (report.md)")
        print("  5. Analyze with AI           (requires API key)")
        print("  6. Exit")
        print(SEPARATOR)

        choice = input("  Choose an option (1-6): ").strip()

        if   choice == "1": upload_file()
        elif choice == "2": analyze_scan()
        elif choice == "3": generate_text_report()
        elif choice == "4": generate_markdown_report()
        elif choice == "5": run_ai_analysis()
        elif choice == "6":
            print("\n  Goodbye!\n")
            sys.exit(0)
        else:
            print("  Invalid choice. Please enter a number from 1 to 6.")
            pause()


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Goodbye!\n")
        sys.exit(0)
