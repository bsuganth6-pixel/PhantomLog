# 📜 PhantomLog

**Log File Analyzer** — parses Apache/Nginx access logs and Linux auth.log,
flags brute-force attempts, SQLi/XSS/path-traversal payloads, known scanner
tools, and directory enumeration. 100% offline.

Day 5 of the Phantom Security toolkit.

---

## Testing philosophy: known-answer testing

This tool is fully offline and deterministic, which made it possible to test
far more rigorously than tools requiring live network access. The approach:

1. **`sample_logs.py`** generates realistic synthetic logs with attacks
   injected at **known, exact counts** — 6 SQLi payloads, 5 XSS payloads,
   4 traversal payloads, an 18-failure brute-force, a 22-failure brute-force
   that *succeeds* on the 23rd attempt, etc. — mixed in with 120 lines of
   ordinary legitimate traffic.
2. Every detector was tested against this data and required to find **exactly**
   the injected count — not "roughly," not "at least." Zero tolerance for
   both false negatives and false positives.
3. The legitimate traffic (36 distinct normal IPs) was checked explicitly:
   **zero findings** are allowed against any of them.

Result: every single detection category — SQLi, XSS, traversal, scanner UAs,
sensitive paths, web brute-force, SSH brute-force, enumeration — matched its
injected count exactly, with zero false positives across 120 legitimate
requests and 25 legitimate SSH logins.

One real bug was caught this way: my first draft of the XSS test payload
contained a literal, un-escaped double-quote character, which broke the log
line's own quoting (Apache/Nginx wrap the request field in `"..."`). A real
browser or attack tool would URL-encode that quote as `%22` — so I fixed the
test data to be realistic, and made sure the detector URL-decodes query
strings before pattern matching (attackers routinely encode payloads
specifically to evade naive string search — decoding first is the correct
approach, not just a fix for my test).

---

## Features

| Feature | Web UI | CLI |
|---|---|---|
| Apache/Nginx Combined Log Format parsing | ✅ | ✅ |
| Linux auth.log (SSH) parsing | ✅ | ✅ |
| Auto-detect format per line (mixed files OK) | ✅ | ✅ |
| SSH brute-force detection + compromise escalation | ✅ | ✅ |
| Web login brute-force detection | ✅ | ✅ |
| SQL injection pattern detection (11 patterns) | ✅ | ✅ |
| XSS pattern detection (8 patterns) | ✅ | ✅ |
| Path traversal / command injection detection | ✅ | ✅ |
| Known scanner tool fingerprinting (17 tools) | ✅ | ✅ |
| Sensitive path probe detection (16 paths) | ✅ | ✅ |
| Directory enumeration detection | ✅ | ✅ |
| Request rate anomaly detection | ✅ | ✅ |
| Top-offenders risk ranking | ✅ | ✅ |
| Findings timeline (stacked severity chart) | ✅ | — |
| Built-in sample logs with injected attacks | ✅ | ✅ |
| `--json` output, configurable thresholds | — | ✅ |
| Exit codes reflecting threat level | — | ✅ |

---

## Setup

```bash
pip install -r requirements.txt

# Web UI → http://127.0.0.1:5054
python3 app.py

# CLI
python3 cli.py --help
```

---

## CLI Usage

```bash
# Try it immediately with a built-in sample (no log file needed)
python3 cli.py analyze --sample access
python3 cli.py analyze --sample auth

# Analyze your own log file (format auto-detected)
python3 cli.py analyze /var/log/nginx/access.log
python3 cli.py analyze /var/log/auth.log --type auth

# Save a sample log to disk to inspect it yourself
python3 cli.py sample access -o test.log

# Tune detection sensitivity
python3 cli.py analyze mylog.log --bf-threshold 3 --bf-window 10
python3 cli.py analyze mylog.log --enum-threshold 25

# JSON output for scripting / piping into other tools
python3 cli.py analyze mylog.log --json | jq '.summary.threat_level'
python3 cli.py analyze mylog.log --json | jq '.top_offenders'

# Show every finding (default caps display at 25)
python3 cli.py analyze mylog.log --all
```

**Exit codes:** `0` = CLEAN/LOW · `1` = MEDIUM/HIGH · `2` = CRITICAL or error

---

## Detection Reference

### SSH Brute-Force
Groups failed logins by source IP with a sliding time window (default: 5+
failures in 5 minutes). **If a successful login follows the burst from the
same IP, severity escalates to CRITICAL** — this is the single highest-value
signal in the tool, since it distinguishes "someone got scanned" from
"someone got in."

### Web Attack Payloads
Query strings and paths are **URL-decoded before matching** so encoded
payloads aren't missed. Covers SQLi (UNION SELECT, tautologies, stacked
queries, time-based blind), XSS (script tags, event handlers, javascript:
URIs), path traversal (../ sequences, /etc/passwd probes), and command
injection ($(...), backticks, pipe-to-netcat).

### Scanners & Enumeration
Fingerprints 17 known scanning tools by User-Agent (sqlmap, nikto, nmap,
gobuster, wpscan, masscan, etc.), flags probes to 16 common sensitive paths
(/.env, /.git/config, /wp-admin, etc.), and detects directory enumeration
bursts (15+ different 404s from one IP in 5 minutes).

Full pattern reference with examples is in the app's **Detection Reference**
tab.

---

## Known Limitations

- **Syslog timestamps have no year** (classic format limitation). PhantomLog
  assumes the current year, rolling back one year if that would place the
  timestamp in the future — a standard, well-understood convention, but
  worth knowing if you're analyzing very old archived logs.
- **Common Log Format vs Combined**: the parser handles both, but Referer/
  User-Agent fields will be `None` for bare Common Log Format lines (they
  don't exist in that format) rather than for suspicious reasons.
- **Regex-based detection**, not a full WAF engine — sophisticated evasion
  (double encoding, comment-obfuscated SQL, unusual casing beyond what's
  covered) could evade specific patterns. This is a log *analysis* and
  *triage* tool, not a substitute for a production WAF.
- Web upload caps at 50,000 lines for responsiveness; the CLI defaults to
  200,000 and can go higher with `--no-limit`.

---

## Project Structure

```
phantomlog/
├── app.py                  ← Flask web UI
├── cli.py                  ← CLI (same modules as web UI)
├── requirements.txt
├── vercel.json
├── modules/
│   ├── parsers.py          ← Apache/Nginx + auth.log parsing, auto-detection
│   ├── detectors.py        ← All attack pattern detection logic
│   ├── report.py           ← Timeline bucketing, top-offenders, summary
│   └── sample_logs.py      ← Synthetic log generator (demo + test fixtures)
├── templates/
│   ├── base.html
│   ├── index.html          ← Analyze Log (main workflow)
│   └── reference.html      ← Detection Reference (educational)
└── static/
    ├── css/style.css
    └── js/
        ├── app.js          ← findings renderer, pure-CSS timeline chart
        └── matrix.js
```

---

