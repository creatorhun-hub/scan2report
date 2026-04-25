"""
Tool detector module.
Reads a scan file and figures out which tool produced it.

Uses a score-based approach: tallies how many signatures match for each
tool and picks the winner. This handles files that contain incidental
keywords from multiple tools without false-positives.
"""


# Each entry is (signature_string, score_weight).
# Higher-confidence signatures carry more weight.
_NMAP_SIGNATURES = [
    ("Starting Nmap",         10),
    ("Nmap scan report for",  10),
    ("Nmap done:",            10),
    ("# Nmap",                 8),
    ("/tcp   open",            5),
    ("/udp   open",            5),
    ("Host is up",             5),
    ("Host is down",           5),
    ("OS details:",            4),
    ("Service Info:",          4),
    ("Not shown:",             3),
    ("PORT     STATE",         3),
]

_NIKTO_SIGNATURES = [
    ("Nikto v",               10),
    ("- Nikto",               10),
    ("+ Target IP:",           9),
    ("+ Target Hostname:",     9),
    ("+ Target Port:",         9),
    ("+ Server:",              6),
    ("OSVDB-",                 6),
    ("+ Start Time:",          5),
    ("host(s) tested",         5),
    ("+ Allowed HTTP Methods", 4),
    ("+ Retrieved ",           3),
]

_SQLMAP_SIGNATURES = [
    ("[*] starting",          10),
    ("sqlmap identified",     10),
    ("back-end DBMS is",       9),
    ("available databases",    9),
    ("injection point",        8),
    ("sqlmap/",                8),
    ("Type: boolean-based",    7),
    ("Type: time-based",       7),
    ("Type: UNION query",      7),
    ("Parameter:",             5),
    ("Payload:",               4),
    ("[INFO] testing",         3),
]


def detect_tool(content: str) -> str:
    """
    Detect which security tool generated the scan content.

    Scores each tool by counting weighted signature matches, then returns
    the tool with the highest score.

    Returns one of: "nmap", "nikto", "sqlmap", or "unknown".
    """
    scores = {
        "nmap":   _score(content, _NMAP_SIGNATURES),
        "nikto":  _score(content, _NIKTO_SIGNATURES),
        "sqlmap": _score(content, _SQLMAP_SIGNATURES),
    }

    best_tool = max(scores, key=lambda t: scores[t])
    best_score = scores[best_tool]

    # Require a minimum score to avoid false positives on empty/random files
    if best_score < 5:
        return "unknown"

    return best_tool


def _score(content: str, signatures: list) -> int:
    """Sum the weights of all signatures present in content."""
    total = 0
    for sig, weight in signatures:
        if sig.lower() in content.lower():
            total += weight
    return total
