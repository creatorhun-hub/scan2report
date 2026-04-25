"""
SQLmap scan output parser.
Extracts target info, WAF detection, injection points, databases,
tables, columns, and any dumped credential/data rows.
"""

import re


def parse_sqlmap(content: str) -> dict:
    """
    Parse SQLmap scan output into structured data.

    Returns a dict with keys:
        tool, target, waf, injections, databases, tables, columns,
        dump, summary
    """
    result = {
        "tool":       "SQLmap",
        "target":     _extract_target(content),
        "waf":        _extract_waf(content),
        "injections": _extract_injections(content),
        "databases":  _extract_databases(content),
        "tables":     _extract_tables(content),
        "columns":    _extract_columns(content),
        "dump":       _extract_dump(content),
        "summary":    {},
    }

    result["summary"] = _build_summary(result)

    return result


# ── Internal helpers ──────────────────────────────────────────────────────────

def _extract_target(content: str) -> dict:
    """Extract target URL, DBMS, OS, and web technology."""
    target = {}

    # URL — prefer explicit "URL:" label, fall back to log messages
    for pattern in [
        r"URL:\s*(https?://\S+)",
        r"\[INFO\] testing connection to the target URL\s+\n?.+(https?://\S+)",
    ]:
        m = re.search(pattern, content)
        if m:
            target["url"] = m.group(1).strip().rstrip("'\"")
            break
    else:
        # Last resort: grab first http URL in a testing message
        m = re.search(r"testing (?:URL |connection to )(https?://\S+)", content)
        target["url"] = m.group(1).strip().rstrip("'\"") if m else None

    # DBMS
    for pattern in [
        r"the back-end DBMS is (.+)",
        r"back-end DBMS:\s+(.+)",
    ]:
        m = re.search(pattern, content)
        if m:
            target["dbms"] = m.group(1).strip()
            break
    else:
        target["dbms"] = None

    # DBMS version (if separately stated)
    ver_m = re.search(r"DBMS version:\s+(.+)", content)
    target["dbms_version"] = ver_m.group(1).strip() if ver_m else None

    # Web server OS
    os_m = re.search(r"web server operating system:\s+(.+)", content)
    target["web_os"] = os_m.group(1).strip() if os_m else None

    # Web technology stack
    tech_m = re.search(r"web application technology:\s+(.+)", content)
    target["web_tech"] = tech_m.group(1).strip() if tech_m else None

    # HTTP status of the target
    status_m = re.search(r"target URL content is stable.*?(\d{3})", content)
    target["http_status"] = int(status_m.group(1)) if status_m else None

    return target


def _extract_waf(content: str) -> dict:
    """
    Detect if a WAF/IPS was identified by SQLmap.

    Returns {"detected": bool, "name": str | None}.
    """
    # SQLmap prints: "WAF/IPS identified as '<name>'" or
    #               "the target is protected by some kind of WAF/IPS"
    name_m = re.search(r"WAF/IPS identified as ['\"]?([^'\"\n]+)['\"]?", content)
    if name_m:
        return {"detected": True, "name": name_m.group(1).strip()}

    generic_m = re.search(
        r"target (?:URL )?(?:is |appears to be )?protected by (?:some kind of )?WAF/IPS",
        content, re.IGNORECASE
    )
    if generic_m:
        return {"detected": True, "name": None}

    return {"detected": False, "name": None}


def _extract_injections(content: str) -> list:
    """
    Extract each vulnerable parameter block.

    Each entry contains:
        parameter, method, injection_types, titles, payloads
    """
    injections = []

    # Each parameter block starts with "Parameter: name (METHOD)"
    param_blocks = re.split(r"(?=^\s*Parameter:\s)", content, flags=re.MULTILINE)

    for block in param_blocks:
        m = re.match(r"\s*Parameter:\s+(\S+)\s+\((\w+)\)", block)
        if not m:
            continue

        param_name = m.group(1)
        method     = m.group(2)

        # Extract all Type/Title/Payload lines in this block
        types    = [t.strip() for t in re.findall(r"^\s*Type:\s+(.+)$",    block, re.MULTILINE)]
        titles   = [t.strip() for t in re.findall(r"^\s*Title:\s+(.+)$",   block, re.MULTILINE)]
        payloads = [t.strip() for t in re.findall(r"^\s*Payload:\s+(.+)$", block, re.MULTILINE)]

        injections.append({
            "parameter":       param_name,
            "method":          method,
            "injection_types": types,
            "titles":          titles,
            "payloads":        payloads,
        })

    return injections


def _extract_databases(content: str) -> list:
    """
    Extract enumerated database names.

    Handles both:
        available databases [N entries]:
        [*] db_name
    """
    databases = []

    # Primary: tightly scoped regex that only accepts simple db names on [*] lines
    db_section_m = re.search(
        r"available databases[^\n]*\n((?:\[\*\] [A-Za-z0-9_\-]+\s*\n?)+)",
        content
    )
    if db_section_m:
        for line in db_section_m.group(1).splitlines():
            m = re.match(r"\[\*\] ([A-Za-z0-9_\-]+)\s*$", line.strip())
            if m:
                databases.append(m.group(1))
        return databases

    # Fallback: scan line-by-line after the "available databases" header
    in_section = False
    for line in content.splitlines():
        if "available databases" in line.lower():
            in_section = True
            continue
        if in_section:
            stripped = line.strip()
            m = re.match(r"\[\*\] ([A-Za-z0-9_\-]+)\s*$", stripped)
            if m:
                databases.append(m.group(1))
            elif stripped and not stripped.startswith("[*]"):
                in_section = False

    return databases


def _extract_tables(content: str) -> dict:
    """
    Extract table names grouped by database.
    Parses SQLmap's ASCII table output:
        Database: webapp_db
        | users    |
        | products |
    """
    tables: dict[str, list[str]] = {}
    db_name = None

    for line in content.splitlines():
        db_m = re.search(r"^Database:\s+(\S+)", line.strip())
        if db_m:
            db_name = db_m.group(1)
            if db_name not in tables:
                tables[db_name] = []
            continue

        # Match a table row: | tablename |
        if db_name:
            row_m = re.match(r"^\|\s+([A-Za-z0-9_\-]+)\s+\|$", line.strip())
            if row_m:
                name = row_m.group(1)
                # Skip header rows
                if name.lower() not in ("tables", "table"):
                    tables[db_name].append(name)

    return tables


def _extract_columns(content: str) -> dict:
    """
    Extract column names and types grouped by table.
    Parses SQLmap's ASCII column table:
        Table: users
        | username | varchar |
        | password | varchar |
    """
    columns: dict[str, list[dict]] = {}
    current_table = None

    for line in content.splitlines():
        tbl_m = re.search(r"^Table:\s+(\S+)", line.strip())
        if tbl_m:
            current_table = tbl_m.group(1)
            if current_table not in columns:
                columns[current_table] = []
            continue

        if current_table:
            # Match: | col_name | type |
            col_m = re.match(r"^\|\s+(\S+)\s+\|\s+(\S+)\s+\|$", line.strip())
            if col_m:
                col_name = col_m.group(1)
                col_type = col_m.group(2)
                if col_name.lower() not in ("column", "---", "type"):
                    columns[current_table].append({
                        "name": col_name,
                        "type": col_type,
                    })

    return columns


def _extract_dump(content: str) -> dict:
    """
    Extract any dumped data rows from the output.

    SQLmap prints dumped table data like:
        Database: webapp_db
        Table: users
        [2 entries]
        +----------+----------+
        | username | password |
        +----------+----------+
        | admin    | s3cr3t   |
        | user1    | pass123  |
        +----------+----------+

    Returns: {table_name: {"columns": [...], "rows": [...]}}
    """
    dump: dict[str, dict] = {}

    # Find all "Table: X\n[N entries]" blocks
    blocks = re.split(r"(?=^Table:\s+\S+\n\[\d+ entr)", content, flags=re.MULTILINE)

    for block in blocks:
        tbl_m = re.match(r"Table:\s+(\S+)\n\[(\d+) entr", block)
        if not tbl_m:
            continue

        table_name = tbl_m.group(1)
        entry_count = int(tbl_m.group(2))

        # Extract column headers from the first data row (between +---+ and +---+)
        header_m = re.search(r"\+[-+]+\+\n\|(.+?)\|\n\+[-+]+\+", block, re.DOTALL)
        if not header_m:
            continue

        headers = [h.strip() for h in header_m.group(1).split("|") if h.strip()]

        # Extract data rows — lines between header and last separator
        rows = []
        data_section = block[header_m.end():]
        for line in data_section.splitlines():
            if line.strip().startswith("|") and not line.strip().startswith("+"):
                cells = [c.strip() for c in line.strip().strip("|").split("|")]
                if len(cells) == len(headers):
                    rows.append(dict(zip(headers, cells)))

        if rows or entry_count == 0:
            dump[table_name] = {
                "columns": headers,
                "rows":    rows,
            }

    return dump


def _build_summary(result: dict) -> dict:
    """Produce a concise top-level summary dict."""
    return {
        "injectable_params": len(result["injections"]),
        "injection_types":   list({
            t for inj in result["injections"]
            for t in inj.get("injection_types", [])
        }),
        "databases_found":   len(result["databases"]),
        "tables_found":      sum(len(v) for v in result["tables"].values()),
        "columns_found":     sum(len(v) for v in result["columns"].values()),
        "rows_dumped":       sum(
            len(v.get("rows", [])) for v in result["dump"].values()
        ),
        "waf_detected":      result["waf"]["detected"],
        "dbms":              result["target"].get("dbms"),
    }
