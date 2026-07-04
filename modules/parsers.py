"""
PhantomLog — Log Parsers
═══════════════════════════════════════════════════════════════
Parses two of the most common log formats into a single normalized
event schema so detectors can work on both uniformly:

  • Apache/Nginx "Combined Log Format" (web access logs)
  • Linux auth.log / secure log (SSH authentication events)

100% offline — pure text parsing, no network or filesystem side effects.
Malformed lines never crash the parser; they're marked parse_success=False
and the raw line is preserved so nothing is silently dropped.
"""

import re
import datetime

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# ════════════════════════════════════════════════════════════════
#  APACHE / NGINX COMBINED LOG FORMAT
#  %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"
#  Example:
#  203.0.113.5 - - [10/Jul/2026:14:23:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://ref.com/" "Mozilla/5.0"
# ════════════════════════════════════════════════════════════════

ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>[0-9a-fA-F:.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

REQUEST_RE = re.compile(r'^(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/[\d.]+)$')

APACHE_TIME_RE = re.compile(
    r'(?P<day>\d{1,2})/(?P<month>\w{3})/(?P<year>\d{4}):'
    r'(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s*(?P<tz>[+-]\d{4})?'
)


def _parse_apache_timestamp(ts_str: str):
    m = APACHE_TIME_RE.match(ts_str)
    if not m:
        return None
    try:
        month = MONTHS.get(m.group("month"))
        if not month:
            return None
        return datetime.datetime(
            int(m.group("year")), month, int(m.group("day")),
            int(m.group("hour")), int(m.group("minute")), int(m.group("second")),
            tzinfo=datetime.timezone.utc,
        )
    except (ValueError, TypeError):
        return None


def parse_access_line(line: str, line_number: int = 0) -> dict:
    """Parse one Apache/Nginx Combined (or Common) Log Format line."""
    base = {
        "raw_line": line, "line_number": line_number, "log_type": "access",
        "parse_success": False, "timestamp": None, "source_ip": None,
        "method": None, "path": None, "query_string": None, "protocol": None,
        "status_code": None, "bytes_sent": None, "referer": None, "user_agent": None,
        "username": None, "auth_result": None, "auth_method": None,
    }

    m = ACCESS_LOG_RE.match(line.strip())
    if not m:
        return base

    d = m.groupdict()
    base["source_ip"] = d["ip"]
    base["timestamp"] = _parse_apache_timestamp(d["timestamp"])
    base["referer"] = d.get("referer") if d.get("referer") != "-" else None
    base["user_agent"] = d.get("user_agent") if d.get("user_agent") != "-" else None

    status = d["status"]
    base["status_code"] = int(status) if status.isdigit() else None
    size = d["size"]
    base["bytes_sent"] = int(size) if size.isdigit() else 0

    request = d["request"]
    rm = REQUEST_RE.match(request)
    if rm:
        base["method"] = rm.group("method")
        full_path = rm.group("path")
        base["protocol"] = rm.group("protocol")
        if "?" in full_path:
            base["path"], base["query_string"] = full_path.split("?", 1)
        else:
            base["path"], base["query_string"] = full_path, ""
    else:
        # Malformed request line (e.g. raw garbage hitting an HTTP port) —
        # still record it since this itself can be a signal, just without
        # method/path breakdown.
        base["path"] = request

    base["parse_success"] = True
    return base


# ════════════════════════════════════════════════════════════════
#  LINUX AUTH.LOG / SECURE LOG (SSH)
#  Jan 10 13:55:36 myhost sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2
# ════════════════════════════════════════════════════════════════

SYSLOG_PREFIX_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[\w.\-/]+?)(?:\[(?P<pid>\d+)\])?:\s*'
    r'(?P<message>.*)$'
)

FAILED_PW_RE = re.compile(
    r'Failed password for (?:(?P<invalid>invalid user) )?(?P<user>\S+) '
    r'from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)'
)
ACCEPTED_RE = re.compile(
    r'Accepted (?P<method>password|publickey|keyboard-interactive) for (?P<user>\S+) '
    r'from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)'
)
INVALID_USER_RE = re.compile(
    r'^Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)'
)
TOO_MANY_AUTH_RE = re.compile(
    r'Disconnecting.*Too many authentication failures for (?P<user>\S+)'
)


def _parse_syslog_timestamp(month_str, day, hour, minute, second, now=None):
    """
    Classic syslog format has no year. Assume current year; if that would
    place the timestamp in the future (log rolled over a year boundary),
    roll back one year — a common, well-understood convention.
    """
    now = now or datetime.datetime.now(datetime.timezone.utc)
    month = MONTHS.get(month_str)
    if not month:
        return None
    try:
        ts = datetime.datetime(now.year, month, int(day), int(hour), int(minute), int(second),
                               tzinfo=datetime.timezone.utc)
        if ts > now + datetime.timedelta(days=1):
            ts = ts.replace(year=now.year - 1)
        return ts
    except ValueError:
        return None


def parse_auth_line(line: str, line_number: int = 0, now=None) -> dict:
    """Parse one Linux auth.log / secure log line (SSH events)."""
    base = {
        "raw_line": line, "line_number": line_number, "log_type": "auth",
        "parse_success": False, "timestamp": None, "source_ip": None,
        "method": None, "path": None, "query_string": None, "protocol": None,
        "status_code": None, "bytes_sent": None, "referer": None, "user_agent": None,
        "username": None, "auth_result": None, "auth_method": None,
    }

    m = SYSLOG_PREFIX_RE.match(line.strip())
    if not m:
        return base

    d = m.groupdict()
    base["timestamp"] = _parse_syslog_timestamp(d["month"], d["day"], d["hour"], d["minute"], d["second"], now=now)
    message = d["message"]
    base["parse_success"] = True  # syslog prefix parsed even if we don't recognize the message type

    fm = FAILED_PW_RE.search(message)
    if fm:
        base["source_ip"] = fm.group("ip")
        base["username"] = fm.group("user")
        base["auth_result"] = "failure"
        base["auth_method"] = "password"
        return base

    am = ACCEPTED_RE.search(message)
    if am:
        base["source_ip"] = am.group("ip")
        base["username"] = am.group("user")
        base["auth_result"] = "success"
        base["auth_method"] = am.group("method")
        return base

    iu = INVALID_USER_RE.search(message)
    if iu:
        base["source_ip"] = iu.group("ip")
        base["username"] = iu.group("user")
        base["auth_result"] = "failure"
        base["auth_method"] = "invalid_user"
        return base

    tm = TOO_MANY_AUTH_RE.search(message)
    if tm:
        base["username"] = tm.group("user")
        base["auth_result"] = "lockout"
        return base

    return base  # recognized syslog line, but not an auth event we track


# ════════════════════════════════════════════════════════════════
#  AUTO-DETECTION + FULL FILE PARSING
# ════════════════════════════════════════════════════════════════

def detect_line_format(line: str) -> str:
    """Returns 'access', 'auth', or 'unknown' based on line shape."""
    line = line.strip()
    if not line:
        return "unknown"
    if ACCESS_LOG_RE.match(line):
        return "access"
    if SYSLOG_PREFIX_RE.match(line):
        return "auth"
    return "unknown"


def parse_log_text(text: str, log_type: str = "auto", max_lines: int = None) -> dict:
    """
    Parse a full log file's text content.
    log_type: "auto", "access", or "auth"
    max_lines: cap the number of lines processed (for web upload limits);
               None = unlimited (CLI default)

    Returns {"events": [...], "stats": {...}}
    """
    lines = text.splitlines()
    truncated = False
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = True

    events = []
    format_counts = {"access": 0, "auth": 0, "unknown": 0}
    now = datetime.datetime.now(datetime.timezone.utc)

    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        fmt = log_type if log_type != "auto" else detect_line_format(line)

        if fmt == "access":
            event = parse_access_line(line, line_number=i)
        elif fmt == "auth":
            event = parse_auth_line(line, line_number=i, now=now)
        else:
            event = {
                "raw_line": line, "line_number": i, "log_type": "unknown",
                "parse_success": False, "timestamp": None, "source_ip": None,
                "method": None, "path": None, "query_string": None, "protocol": None,
                "status_code": None, "bytes_sent": None, "referer": None, "user_agent": None,
                "username": None, "auth_result": None, "auth_method": None,
            }

        format_counts[event["log_type"]] = format_counts.get(event["log_type"], 0) + 1
        events.append(event)

    total = len(events)
    parsed_ok = sum(1 for e in events if e["parse_success"])

    return {
        "events": events,
        "stats": {
            "total_lines": total,
            "parsed_successfully": parsed_ok,
            "parse_success_rate": round(parsed_ok / total * 100, 1) if total else 0.0,
            "format_counts": format_counts,
            "truncated": truncated,
        },
    }
