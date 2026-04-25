"""
scan2report — Flask web application entry point.

Turn raw security scan outputs into professional AI-powered reports.

Usage:
    python app.py
    # Then open http://localhost:5000 in your browser

Environment variables:
    REPLICATE_API_TOKEN  — Required for AI analysis features
    SESSION_SECRET       — Flask session secret (change in production)
    PORT                 — Port to listen on (default: 5000)
"""

import os
import sys
import json
import uuid
import tempfile
import markdown as md_lib

# ── Import core modules from src/ ─────────────────────────────────────────────
_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, _SRC)

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    send_file,
    flash,
)

from detector import detect_tool
from parsers import parse_nmap, parse_nikto, parse_sqlmap
from analyzer import analyze
from md_reporter import generate_md_report
from ai_analyzer import analyze_with_ai, check_api_key

# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "scan2report-dev-fallback-change-in-prod")

# Temporary directory for session data files
_STORE = tempfile.gettempdir()

PARSERS = {
    "nmap":   parse_nmap,
    "nikto":  parse_nikto,
    "sqlmap": parse_sqlmap,
}


# ── Session helpers ───────────────────────────────────────────────────────────

def _data_path(sid: str) -> str:
    """Return the filesystem path for a session's data file."""
    return os.path.join(_STORE, f"s2r_{sid}.json")


def _load() -> dict | None:
    """
    Load the current session's scan data from disk.
    Returns None if the session is missing or expired.
    """
    sid = session.get("scan_id")
    if not sid:
        return None
    path = _data_path(sid)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict):
    """Persist scan data for the current session."""
    sid = session.get("scan_id")
    if not sid:
        return
    with open(_data_path(sid), "w", encoding="utf-8") as f:
        json.dump(data, f, default=str)


def _merge_ai(data: dict) -> dict:
    """
    Merge AI analysis results into the main analysis dict.
    Called before generating the Markdown report so AI insights are included.
    """
    analysis = dict(data["analysis"])
    ai = data.get("ai_analysis")
    if ai:
        analysis["ai_summary"]    = ai.get("vulnerability_summary", "")
        analysis["ai_risk_level"] = ai.get("risk_level", "")
        analysis["ai_fixes"]      = ai.get("recommended_fixes", [])
    return analysis


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def index():
    """
    GET  — Render the file upload page.
    POST — Accept a scan file, auto-detect the tool, parse and analyze it,
           then redirect to the results page.
    """
    if request.method == "POST":
        file = request.files.get("scanfile")

        if not file or not file.filename:
            flash("No file selected.", "error")
            return render_template("index.html")

        try:
            content = file.read().decode("utf-8", errors="replace")
        except Exception as exc:
            flash(f"Could not read file: {exc}", "error")
            return render_template("index.html")

        if not content.strip():
            flash("The uploaded file is empty.", "error")
            return render_template("index.html")

        # Auto-detect which security tool produced this output
        tool = detect_tool(content)
        if tool == "unknown":
            flash(
                "Could not identify the scan tool. "
                "Supported formats: Nmap, Nikto, SQLmap.",
                "error",
            )
            return render_template("index.html")

        try:
            parsed   = PARSERS[tool](content)
            analysis = analyze(parsed)
        except Exception as exc:
            flash(f"Error processing scan file: {exc}", "error")
            return render_template("index.html")

        # Create a fresh session for each upload
        session["scan_id"] = str(uuid.uuid4())
        _save({"parsed": parsed, "analysis": analysis, "filename": file.filename})

        return redirect(url_for("results"))

    return render_template("index.html")


@app.route("/results")
def results():
    """Display the parsed and analyzed scan results."""
    data = _load()
    if not data:
        flash("Session expired or no file uploaded.", "error")
        return redirect(url_for("index"))

    return render_template(
        "results.html",
        analysis=data["analysis"],
        filename=data.get("filename", "unknown"),
        ai=data.get("ai_analysis"),
        has_api_key=check_api_key(),
    )


@app.route("/ai", methods=["POST"])
def ai_analyze():
    """
    JSON endpoint — send the scan data to the Replicate LLM and return:
        vulnerability_summary, risk_level, recommended_fixes
    """
    data = _load()
    if not data:
        return jsonify({"error": "Session expired — please upload again."}), 400

    if not check_api_key():
        return jsonify({"error": "REPLICATE_API_TOKEN is not configured."}), 500

    try:
        ai_result = analyze_with_ai(data["analysis"], data["parsed"])
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Persist the AI result so it can be included in the report
    data["ai_analysis"] = ai_result
    _save(data)

    return jsonify(ai_result)


@app.route("/report")
def report():
    """
    Generate the professional Markdown report, render it to HTML,
    and display it in the browser.
    """
    data = _load()
    if not data:
        flash("Session expired — please upload again.", "error")
        return redirect(url_for("index"))

    analysis        = _merge_ai(data)
    report_filename = f"s2r_{session['scan_id']}.md"
    md_path         = generate_md_report(analysis, _STORE, report_filename)

    with open(md_path, encoding="utf-8") as f:
        raw_md = f.read()

    rendered = md_lib.markdown(
        raw_md,
        extensions=["tables", "fenced_code", "nl2br"],
    )

    return render_template("report.html", rendered=rendered, raw_md=raw_md)


@app.route("/report/download")
def report_download():
    """Generate and serve the Markdown report as a file download."""
    data = _load()
    if not data:
        flash("Session expired — please upload again.", "error")
        return redirect(url_for("index"))

    analysis        = _merge_ai(data)
    report_filename = f"s2r_{session['scan_id']}.md"
    md_path         = generate_md_report(analysis, _STORE, report_filename)

    return send_file(md_path, as_attachment=True, download_name="report.md")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  scan2report Web App")
    print(f"  Turn raw security scan outputs into professional AI-powered reports.")
    print(f"\n  Open http://localhost:{port} in your browser\n")
    app.run(host="0.0.0.0", port=port, debug=False)
