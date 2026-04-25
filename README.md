# scan2report 🛡

> **Turn raw security scan outputs into professional AI-powered reports.**

scan2report is an open-source security reporting tool that automatically parses output files from **Nmap**, **Nikto**, and **SQLmap**, analyzes the findings, and produces professional penetration testing reports — with optional AI-powered analysis via a large language model.

Use it through the **browser-based web interface** or directly from the **command line**.

---

## Features

- 🔍 **Auto-detection** — Identifies Nmap, Nikto, and SQLmap scan files automatically
- 📊 **Deep parsing** — Extracts hosts, ports, services, CVEs, injection points, dumped data, WAF detection, and more
- 🧠 **AI analysis** — Sends findings to a Llama 3 model (via Replicate) for a vulnerability summary, risk rating, and recommended fixes
- 📝 **Professional reports** — Generates a structured Markdown penetration testing report with cover page, executive summary, findings by severity, risk matrix, and prioritized remediation steps
- 🌐 **Web interface** — Upload files and view results in the browser; no terminal required
- 💻 **CLI interface** — Full interactive menu for terminal workflows
- 📋 **JSON export** — Export parsed data for use in other tools or pipelines

---

## Screenshots

### Upload Page
```
┌─────────────────────────────────────────┐
│  scan2report                            │
│  Security Scan Analyzer                 │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   📂  Drop your scan file here   │   │
│  │       or click to browse         │   │
│  └─────────────────────────────────┘   │
│                                         │
│  🔍 Nmap   🌐 Nikto   💉 SQLmap        │
└─────────────────────────────────────────┘
```

### Results Page
```
🌐 Nikto Scan Results           🔴 HIGH
───────────────────────────────────────────
Overview: Web scan against example.local:80.
          16 issues: 3 HIGH, 8 MEDIUM, 5 INFO

 HIGH   3  │  MEDIUM   8  │  INFO   5  │  Total  16
────────────────────────────────────────────────────
[HIGH]   /phpmyadmin/ — phpMyAdmin exposed (OSVDB-5765)
[HIGH]   CVE-2021-41773 — Apache path traversal detected
[MEDIUM] X-Content-Type-Options header missing
...
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/scan2report.git
cd scan2report

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env and add your API keys (see Environment Variables below)
```

---

## Usage

### Web Interface (Recommended)

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

**Workflow:**

1. Upload your Nmap, Nikto, or SQLmap output file
2. View the parsed results — findings grouped by severity, host details, injection points, etc.
3. Click **"Analyze with AI"** for an LLM-powered vulnerability summary and recommended fixes _(requires `REPLICATE_API_TOKEN`)_
4. Click **"View Markdown Report"** to generate and read the full penetration testing report in your browser
5. Click **"Download report.md"** to save the report

### CLI Interface

```bash
python main.py
```

| Option | Action |
|--------|--------|
| 1 | Upload a scan file |
| 2 | Parse and analyze the scan |
| 3 | Generate plain-text report (`.txt` + optional JSON) |
| 4 | Generate Markdown report (`report.md`) |
| 5 | Analyze with AI _(requires API key)_ |
| 6 | Exit |

Reports are saved to the `results/` directory by default.

---

## Example Input / Output

### Input — Nmap Output File

```
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1
80/tcp   open  http    Apache httpd 2.4.52
3306/tcp open  mysql   MySQL 8.0.28
```

### Output — Executive Summary (from `report.md`)

```markdown
## Executive Summary

A network port scan identified **1 reachable host** with **2 high-risk services**
exposed to the network. The MySQL database port (3306) is publicly accessible
with no apparent network-level access control, and the Apache web server version
may be susceptible to known CVEs. Immediate remediation is recommended.

| Metric              | Value       |
|---------------------|-------------|
| Overall Risk        | 🔴 HIGH     |
| Hosts Scanned       | 1           |
| Open Ports          | 3           |
| Risky Services      | 2           |
```

### Output — AI Analysis _(optional)_

```
Risk Level: 🔴 HIGH

Vulnerability Summary:
The scan reveals a host with three open ports, two of which present
significant risk. The MySQL port is exposed publicly — a common source
of data breaches. The Apache version has known CVEs. Immediate patching
and firewall restriction are essential.

Recommended Fixes:
1. Restrict MySQL (port 3306) to localhost only using firewall rules
2. Update Apache to the latest stable release and apply security patches
3. Review SSH configuration and disable password authentication
```

---

## Supported Scan Tools

| Tool | What is Parsed |
|------|----------------|
| **Nmap** | Live hosts, open TCP/UDP ports, service names, version banners, OS fingerprints, NSE script results, MAC addresses, risk flags |
| **Nikto** | Web server findings, severity classification (HIGH/MEDIUM/INFO), CVE references, OSVDB IDs, affected URL paths, server headers, scan duration |
| **SQLmap** | Injectable parameters, injection techniques, proof-of-concept payloads, DBMS type, database names, table/column schema, extracted data rows, WAF/IPS detection |

---

## Report Structure

Every generated `report.md` follows professional penetration testing standards:

| Section | Contents |
|---------|----------|
| **Cover Page** | Classification, date, tool, overall risk rating |
| **Executive Summary** | Non-technical narrative, key metrics table |
| **Scope & Methodology** | What was tested, how, with the exact scan command |
| **Findings** | Detailed findings grouped by severity with evidence |
| **Risk Assessment** | Severity breakdown table, risk rating definitions |
| **Recommendations** | Numbered, prioritized, tool-specific remediation steps |
| **Appendix** | Full port tables, database schema, extracted data |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Python 3.9+ |
| Web framework | Flask |
| AI / LLM | Replicate API (Llama 3 8B Instruct) |
| Report format | Markdown |
| Markdown rendering | Python `markdown` library |
| Frontend | Vanilla HTML / CSS / JavaScript |

---

## Project Structure

```
scan2report/
├── app.py                    # Flask web app entry point
├── main.py                   # CLI entry point
│
├── src/                      # Core logic modules
│   ├── analyzer.py           # Converts parsed data into analysis + recommendations
│   ├── detector.py           # Score-based scan tool detection
│   ├── md_reporter.py        # Professional Markdown report generator
│   ├── ai_analyzer.py        # Replicate LLM integration
│   ├── reporter.py           # Plain-text report generator
│   ├── utils.py              # JSON export utilities
│   └── parsers/              # Tool-specific parsers
│       ├── __init__.py
│       ├── nmap_parser.py    # Nmap output parser
│       ├── nikto_parser.py   # Nikto output parser
│       └── sqlmap_parser.py  # SQLmap output parser
│
├── templates/                # Flask HTML templates
│   ├── base.html
│   ├── index.html            # Upload page
│   ├── results.html          # Results display
│   └── report.html           # Report viewer
│
├── static/
│   └── style.css             # Dark security-themed UI
│
├── samples/                  # Example scan files for testing
│   ├── sample_nmap.txt
│   ├── sample_nikto.txt
│   └── sample_sqlmap.txt
│
├── results/                  # Generated reports saved here (gitignored)
├── docs/                     # Additional documentation
│
├── requirements.txt
├── .env.example
├── .gitignore
└── LICENSE
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `REPLICATE_API_TOKEN` | For AI features | API token from [replicate.com](https://replicate.com/account/api-tokens) |
| `SESSION_SECRET` | For web app | Flask session secret key — use a random string in production |
| `PORT` | Optional | Port for the Flask web app (default: `5000`) |

Copy `.env.example` to `.env` and fill in your values. Never commit `.env` to version control.

---

## Testing with Sample Files

The `samples/` directory includes pre-made scan output files you can use immediately without running a real security scan:

```bash
# Web interface — just upload the file through the browser
python app.py
# Open http://localhost:5000 and upload samples/sample_nmap.txt

# CLI
python main.py
# Choose option 1, then enter:  samples/sample_nmap.txt
# Choose option 2 to analyze
# Choose option 4 to generate the Markdown report
```

---

## Future Improvements

- [ ] Support for additional scan tools (Masscan, Burp Suite, OpenVAS, Metasploit)
- [ ] PDF report generation
- [ ] CVSS v3 scoring integration
- [ ] Severity trend tracking across multiple scans
- [ ] Scan comparison (diff between two scan results)
- [ ] Docker containerization for one-command setup
- [ ] REST API for CI/CD pipeline integration
- [ ] Custom report templates
- [ ] Dark / light mode toggle in the web UI
- [ ] Bulk scan file upload (analyze multiple files at once)

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Commit your changes with a clear message
4. Open a Pull Request with a description of what you changed and why

Please make sure your code is clean and includes docstrings on new functions.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

*Built for the security community. Use responsibly and only on systems you have explicit permission to test.*
