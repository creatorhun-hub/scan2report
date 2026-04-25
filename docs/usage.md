# Usage Guide

## Quick Start

### Web Interface

```bash
python app.py
```

Open **http://localhost:5000** in your browser, then:

1. Drag and drop (or click to browse) your scan file onto the upload area
2. Wait for parsing — results appear automatically
3. Review findings organized by severity
4. Optionally click **"Analyze with AI"** for an LLM summary
5. Click **"View Markdown Report"** or **"Download report.md"**

### CLI

```bash
python main.py
```

Follow the numbered menu. Use the sample files in `samples/` to try the tool
without running a real scan:

```
Enter path: samples/sample_nmap.txt
```

---

## Supported Input Formats

scan2report auto-detects the scan tool from the file content. No file extension
or manual selection is required.

### Nmap

Any Nmap plain-text output (default or with `-sV`, `-O`, `-A`, `--script` flags):

```
nmap -sV -O 192.168.1.0/24 -oN scan.txt
```

### Nikto

Standard Nikto text output:

```
nikto -h http://example.com -o scan.txt
```

### SQLmap

Standard SQLmap console output (copy/paste from terminal or redirect to file):

```
sqlmap -u "http://example.com/page?id=1" --dbs --tables --dump 2>&1 | tee scan.txt
```

---

## Output Files

| File | Description |
|------|-------------|
| `results/report_<tool>_<timestamp>.txt` | Plain-text report (option 3 / CLI) |
| `results/report.md` | Professional Markdown report (option 4 / web) |
| `results/parsed_<tool>_<timestamp>.json` | Raw parsed data export (optional) |

---

## AI Analysis

The AI analysis feature requires a **Replicate API token**.

1. Sign up at [replicate.com](https://replicate.com)
2. Go to **Account → API Tokens** and create a token
3. Add it to your `.env` file:
   ```
   REPLICATE_API_TOKEN=r8_your_token_here
   ```
4. Restart the app

The AI model used is **Llama 3 8B Instruct** (fast, free tier available).
Analysis typically takes 15–30 seconds.

### What the AI returns

- **Vulnerability Summary** — 2–4 sentence expert overview of what was found
- **Risk Level** — CRITICAL / HIGH / MEDIUM / LOW
- **Recommended Fixes** — 4–6 specific, actionable remediation steps

If you run AI analysis before generating the Markdown report, the AI insights
are automatically embedded in the report.

---

## Markdown Report Sections

| Section | Contents |
|---------|----------|
| Cover Page | Tool, date, classification, overall risk badge |
| Executive Summary | Non-technical narrative + key metrics table |
| Scope & Methodology | What was tested, scan command used, disclaimer |
| Findings | Severity-grouped findings with evidence, CVEs, paths |
| Risk Assessment | Severity breakdown table + risk level definitions |
| Recommendations | Numbered, prioritized remediation with context |
| Appendix | Full data tables (ports, databases, schema, dumps) |

---

## Troubleshooting

**"Could not identify the scan tool"**
Make sure you're uploading raw text output from Nmap, Nikto, or SQLmap.
XML output from Nmap is not currently supported — use plain text (`-oN`).

**AI analysis button is disabled**
`REPLICATE_API_TOKEN` is not set. Add it to your `.env` file and restart.

**Session expired error**
Sessions are stored in the system temp directory. Re-upload your file to start a new session.

**Port already in use**
Change the port: `PORT=8080 python app.py`
