"""
PhantomLog — Attack Pattern Detectors
═══════════════════════════════════════════════════════════════
Takes normalized events (from parsers.py) and identifies security-
relevant patterns: brute-force auth attempts, web attack payloads
(SQLi/XSS/path traversal/command injection), known scanner tools,
directory enumeration bursts, and abnormal request rates.

Fully offline — pure pattern matching over already-parsed data.

Query strings and paths are URL-decoded before pattern matching.
This matters: attackers routinely URL-encode payloads (%3Cscript%3E
instead of <script>) specifically to evade naive string matching —
decoding first is the correct approach, not an afterthought.
"""

import re
import datetime
import urllib.parse
from collections import defaultdict

# ════════════════════════════════════════════════════════════════
#  ATTACK SIGNATURE PATTERNS
# ════════════════════════════════════════════════════════════════

SQLI_PATTERNS = [
    (r"\bunion\s+select\b", "UNION SELECT"),
    (r"\bor\b\s*'?\"?\s*1\s*=\s*1", "OR 1=1 tautology"),
    (r"'\s*or\s*'1'\s*=\s*'1", "classic ' OR '1'='1"),
    (r";\s*drop\s+table\b", "DROP TABLE"),
    (r";\s*delete\s+from\b", "DELETE FROM"),
    (r"\bexec(\s|\()+\s*(sp|xp)_\w+", "stored procedure exec"),
    (r"\binformation_schema\b", "information_schema probe"),
    (r"--\s*$", "SQL comment terminator"),
    (r"\bwaitfor\s+delay\b", "time-based blind SQLi"),
    (r"\bsleep\(\d+\)", "SQL SLEEP() time-based probe"),
    (r"'\s*and\s*'?\"?\d+\s*=\s*\d+", "AND-based boolean probe"),
]

XSS_PATTERNS = [
    (r"<script[\s>]", "<script> tag"),
    (r"javascript:", "javascript: URI scheme"),
    (r"on(error|load|click|mouseover|focus)\s*=", "inline event handler"),
    (r"<img[^>]+src\s*=", "img tag with src injection"),
    (r"<svg[^>]*onload", "SVG onload vector"),
    (r"document\.cookie", "cookie theft attempt"),
    (r"document\.location", "location hijack attempt"),
    (r"<iframe[\s>]", "<iframe> injection"),
]

TRAVERSAL_PATTERNS = [
    (r"\.\./", "../ traversal sequence"),
    (r"\.\.\\", "..\\ traversal sequence (Windows)"),
    (r"/etc/passwd", "/etc/passwd probe"),
    (r"/etc/shadow", "/etc/shadow probe"),
    (r"boot\.ini", "boot.ini probe (Windows)"),
    (r"win\.ini", "win.ini probe (Windows)"),
    (r"/proc/self/environ", "/proc/self/environ probe"),
]

CMDI_PATTERNS = [
    (r";\s*cat\s+", "; cat command chaining"),
    (r"\|\s*nc\s+", "| nc (netcat) piping"),
    (r";\s*wget\s+", "; wget download chaining"),
    (r";\s*curl\s+", "; curl download chaining"),
    (r"\$\([^)]+\)", "$(...) command substitution"),
    (r"`[^`]+`", "`...` backtick command substitution"),
]

SENSITIVE_PATHS = [
    "/wp-admin", "/wp-login", "/.env", "/.git/config", "/.git/head",
    "/phpmyadmin", "/administrator", "/xmlrpc.php", "/.aws/credentials",
    "/config.php.bak", "/.ssh/id_rsa", "/server-status", "/.htaccess",
    "/actuator/env", "/debug/vars", "/.docker/config.json",
]

SCANNER_USER_AGENT_SIGNATURES = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wpscan",
    "metasploit", "nessus", "acunetix", "burpsuite", "zgrab", "havij",
    "w3af", "arachni", "skipfish", "openvas",
]

_COMPILED_SQLI = [(re.compile(p, re.IGNORECASE), label) for p, label in SQLI_PATTERNS]
_COMPILED_XSS = [(re.compile(p, re.IGNORECASE), label) for p, label in XSS_PATTERNS]
_COMPILED_TRAVERSAL = [(re.compile(p, re.IGNORECASE), label) for p, label in TRAVERSAL_PATTERNS]
_COMPILED_CMDI = [(re.compile(p, re.IGNORECASE), label) for p, label in CMDI_PATTERNS]


def _decoded_target(event: dict) -> str:
    """URL-decode path+query for pattern matching, so encoded payloads aren't missed."""
    raw = (event.get("path") or "") + "?" + (event.get("query_string") or "")
    try:
        return urllib.parse.unquote(raw)
    except Exception:
        return raw


# ════════════════════════════════════════════════════════════════
#  WEB ATTACK DETECTION
# ════════════════════════════════════════════════════════════════

def detect_web_attacks(events: list) -> list:
    """Scan each access-log event's decoded path+query for attack signatures."""
    findings = []
    for e in events:
        if e["log_type"] != "access" or not e["parse_success"]:
            continue
        target = _decoded_target(e)

        for pattern, label in _COMPILED_SQLI:
            if pattern.search(target):
                findings.append(_make_finding("sqli", "critical", e,
                    f"SQL injection pattern detected: {label}", matched=label))
                break  # one finding per event per category is enough

        for pattern, label in _COMPILED_XSS:
            if pattern.search(target):
                findings.append(_make_finding("xss", "high", e,
                    f"Cross-site scripting pattern detected: {label}", matched=label))
                break

        for pattern, label in _COMPILED_TRAVERSAL:
            if pattern.search(target):
                findings.append(_make_finding("path_traversal", "critical", e,
                    f"Path traversal pattern detected: {label}", matched=label))
                break

        for pattern, label in _COMPILED_CMDI:
            if pattern.search(target):
                findings.append(_make_finding("command_injection", "critical", e,
                    f"Command injection pattern detected: {label}", matched=label))
                break

        path_lower = (e.get("path") or "").lower()
        for sensitive in SENSITIVE_PATHS:
            if path_lower.startswith(sensitive):
                findings.append(_make_finding("sensitive_path", "medium", e,
                    f"Request to sensitive path: {sensitive}", matched=sensitive))
                break

    return findings


def detect_suspicious_user_agents(events: list) -> list:
    """Flag requests from known scanner/attack-tool user agents."""
    findings = []
    for e in events:
        if e["log_type"] != "access" or not e["parse_success"]:
            continue
        ua = (e.get("user_agent") or "").lower()
        if not ua:
            continue
        for sig in SCANNER_USER_AGENT_SIGNATURES:
            if sig in ua:
                findings.append(_make_finding("scanner_tool", "high", e,
                    f"Known scanning tool user-agent: '{sig}'", matched=sig))
                break
    return findings


# ════════════════════════════════════════════════════════════════
#  BRUTE FORCE DETECTION (auth logs)
# ════════════════════════════════════════════════════════════════

def detect_auth_bruteforce(events: list, threshold: int = 5, window_minutes: int = 5) -> list:
    """
    Groups auth failures by source IP, uses a sliding time window to find
    IPs exceeding `threshold` failures within any `window_minutes` span.
    Also flags the especially critical case: brute force followed by a
    SUCCESSFUL login from the same IP (possible account compromise).
    """
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["log_type"] == "auth" and e.get("source_ip") and e.get("timestamp"):
            by_ip[e["source_ip"]].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])
        failures = [e for e in ip_events if e["auth_result"] == "failure"]
        successes = [e for e in ip_events if e["auth_result"] == "success"]

        # Sliding window over failure timestamps
        window = datetime.timedelta(minutes=window_minutes)
        max_in_window = 0
        window_start_idx = 0
        for i in range(len(failures)):
            while failures[i]["timestamp"] - failures[window_start_idx]["timestamp"] > window:
                window_start_idx += 1
            max_in_window = max(max_in_window, i - window_start_idx + 1)

        if max_in_window >= threshold:
            usernames = sorted(set(e["username"] for e in failures if e.get("username")))
            severity = "high"
            detail = (f"{len(failures)} failed login attempts from this IP "
                     f"(peak {max_in_window} within {window_minutes} min), "
                     f"trying {len(usernames)} distinct username(s): {', '.join(usernames[:8])}"
                     f"{'...' if len(usernames) > 8 else ''}")

            # Critical escalation: did a SUCCESS follow the brute-force burst?
            if successes and successes[-1]["timestamp"] > failures[0]["timestamp"]:
                compromised_user = successes[-1].get("username", "unknown")
                severity = "critical"
                detail += (f". ⚠ A SUCCESSFUL login as '{compromised_user}' followed this burst — "
                          f"possible account compromise, investigate immediately.")

            findings.append({
                "category": "auth_bruteforce", "severity": severity,
                "source_ip": ip, "title": "SSH Brute-Force Attempt",
                "detail": detail, "line_number": failures[0]["line_number"],
                "timestamp": str(failures[0]["timestamp"]), "count": len(failures),
            })

    return findings


def detect_web_bruteforce(events: list, threshold: int = 8, window_minutes: int = 5,
                          login_path_keywords=("login", "signin", "wp-login", "auth")) -> list:
    """Detects repeated 401/403 responses to login-like paths from the same IP."""
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["log_type"] != "access" or not e.get("timestamp"):
            continue
        path = (e.get("path") or "").lower()
        if e.get("status_code") in (401, 403) and any(k in path for k in login_path_keywords):
            by_ip[e["source_ip"]].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])
        window = datetime.timedelta(minutes=window_minutes)
        max_in_window, start_idx = 0, 0
        for i in range(len(ip_events)):
            while ip_events[i]["timestamp"] - ip_events[start_idx]["timestamp"] > window:
                start_idx += 1
            max_in_window = max(max_in_window, i - start_idx + 1)

        if max_in_window >= threshold:
            findings.append({
                "category": "web_bruteforce", "severity": "high",
                "source_ip": ip, "title": "Web Login Brute-Force Attempt",
                "detail": f"{len(ip_events)} failed login attempts to "
                         f"'{ip_events[0].get('path')}' (peak {max_in_window} within {window_minutes} min).",
                "line_number": ip_events[0]["line_number"],
                "timestamp": str(ip_events[0]["timestamp"]), "count": len(ip_events),
            })
    return findings


# ════════════════════════════════════════════════════════════════
#  ENUMERATION / SCANNING DETECTION
# ════════════════════════════════════════════════════════════════

def detect_enumeration(events: list, threshold: int = 15, window_minutes: int = 5) -> list:
    """Flags IPs generating many 404s in a short window — directory/content enumeration."""
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["log_type"] == "access" and e.get("status_code") == 404 and e.get("timestamp"):
            by_ip[e["source_ip"]].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])
        window = datetime.timedelta(minutes=window_minutes)
        max_in_window, start_idx = 0, 0
        for i in range(len(ip_events)):
            while ip_events[i]["timestamp"] - ip_events[start_idx]["timestamp"] > window:
                start_idx += 1
            max_in_window = max(max_in_window, i - start_idx + 1)

        if max_in_window >= threshold:
            unique_paths = len(set(e.get("path") for e in ip_events))
            findings.append({
                "category": "enumeration", "severity": "medium",
                "source_ip": ip, "title": "Directory/Content Enumeration",
                "detail": f"{len(ip_events)} not-found (404) requests across {unique_paths} "
                         f"distinct paths (peak {max_in_window} within {window_minutes} min) — "
                         f"consistent with automated directory brute-forcing.",
                "line_number": ip_events[0]["line_number"],
                "timestamp": str(ip_events[0]["timestamp"]), "count": len(ip_events),
            })
    return findings


def detect_rate_anomaly(events: list, threshold: int = 60, window_minutes: int = 1) -> list:
    """Flags IPs with an abnormally high request rate — possible DoS/scraping."""
    findings = []
    by_ip = defaultdict(list)
    for e in events:
        if e["log_type"] == "access" and e.get("timestamp"):
            by_ip[e["source_ip"]].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e["timestamp"])
        window = datetime.timedelta(minutes=window_minutes)
        max_in_window, start_idx = 0, 0
        for i in range(len(ip_events)):
            while ip_events[i]["timestamp"] - ip_events[start_idx]["timestamp"] > window:
                start_idx += 1
            max_in_window = max(max_in_window, i - start_idx + 1)

        if max_in_window >= threshold:
            findings.append({
                "category": "rate_anomaly", "severity": "medium",
                "source_ip": ip, "title": "Abnormal Request Rate",
                "detail": f"Peak of {max_in_window} requests within {window_minutes} minute(s) "
                         f"from a single IP — possible DoS, scraping, or automated abuse.",
                "line_number": ip_events[0]["line_number"],
                "timestamp": str(ip_events[0]["timestamp"]), "count": len(ip_events),
            })
    return findings


# ════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════

def _make_finding(category, severity, event, detail, matched=None):
    return {
        "category": category, "severity": severity,
        "source_ip": event.get("source_ip"), "title": _category_title(category),
        "detail": detail, "line_number": event["line_number"],
        "timestamp": str(event.get("timestamp")) if event.get("timestamp") else None,
        "path": event.get("path"), "matched_pattern": matched, "count": 1,
    }


def _category_title(category):
    return {
        "sqli": "SQL Injection Attempt", "xss": "Cross-Site Scripting Attempt",
        "path_traversal": "Path Traversal Attempt", "command_injection": "Command Injection Attempt",
        "sensitive_path": "Sensitive Path Access", "scanner_tool": "Known Scanner Tool Detected",
    }.get(category, category)


# ════════════════════════════════════════════════════════════════
#  RUN EVERYTHING
# ════════════════════════════════════════════════════════════════

def run_all_detectors(events: list, config: dict = None) -> list:
    """Runs every detector and returns a single combined, sorted findings list."""
    config = config or {}
    findings = []
    findings += detect_web_attacks(events)
    findings += detect_suspicious_user_agents(events)
    findings += detect_auth_bruteforce(events,
        threshold=config.get("bruteforce_threshold", 5),
        window_minutes=config.get("bruteforce_window", 5))
    findings += detect_web_bruteforce(events,
        threshold=config.get("web_bruteforce_threshold", 8),
        window_minutes=config.get("web_bruteforce_window", 5))
    findings += detect_enumeration(events,
        threshold=config.get("enum_threshold", 15),
        window_minutes=config.get("enum_window", 5))
    findings += detect_rate_anomaly(events,
        threshold=config.get("rate_threshold", 60),
        window_minutes=config.get("rate_window", 1))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 5), -(f.get("count") or 1)))
    return findings
