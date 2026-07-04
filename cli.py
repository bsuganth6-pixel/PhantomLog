#!/usr/bin/env python3
"""
PhantomLog CLI — Apache/Nginx/Auth Log Analyzer
═══════════════════════════════════════════════════════════════
USAGE
  python3 cli.py analyze <logfile> [--type auto|access|auth]
  python3 cli.py sample access                    Print a sample access log with attacks
  python3 cli.py sample auth                      Print a sample auth log with brute-force
  python3 cli.py analyze --sample access          Analyze the built-in sample directly
  python3 cli.py --help
"""

import os
import sys
import json
import argparse

from modules import parsers, detectors, report, sample_logs

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
def _c(code): return code if _COLOR else ""
R=_c("\033[0m"); BOLD=_c("\033[1m"); DIM=_c("\033[2m")
RED=_c("\033[91m"); GRN=_c("\033[92m"); YLW=_c("\033[93m")
CYN=_c("\033[96m"); ORG=_c("\033[38;5;208m")

SEP = f"{DIM}{'─'*76}{R}"


def banner():
    print(f"""{CYN}{BOLD}
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗██╗      ██████╗  ██████╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║██║     ██╔═══██╗██╔════╝
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║██║     ██║   ██║██║  ███╗
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║██║     ██║   ██║██║   ██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║███████╗╚██████╔╝╚██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚═════╝
  {DIM}Apache / Nginx / Auth Log Analyzer{R}
""")


def err(msg):  print(f"{RED}✗ {msg}{R}", file=sys.stderr)
def ok(msg):   print(f"{GRN}✓ {msg}{R}")
def info(msg): print(f"{CYN}ℹ {msg}{R}")
def warn(msg): print(f"{YLW}⚠ {msg}{R}")


def threat_color(level):
    return {"CRITICAL": RED, "HIGH": ORG, "MEDIUM": YLW, "LOW": CYN, "CLEAN": GRN}.get(level, R)


def sev_color(sev):
    return {"critical": RED, "high": ORG, "medium": YLW, "low": CYN}.get(sev, R)


def bar(count, max_count, width=30):
    if max_count == 0:
        return ""
    filled = max(1, int((count / max_count) * width)) if count else 0
    return "█" * filled


# ════════════════════════════════════════════════════════════════
#  DISPLAY
# ════════════════════════════════════════════════════════════════

def print_report(full_report, show_all=False, max_findings=25):
    s = full_report["summary"]
    tc = threat_color(s["threat_level"])

    print()
    print(f"  {tc}{BOLD}THREAT LEVEL: {s['threat_level']}{R}")
    print(f"  {DIM}{s['total_findings']} finding(s) across {s['total_events']} log lines · "
          f"{s['unique_attacker_ips']} of {s['unique_source_ips']} unique IPs flagged{R}")
    if s["date_range"]:
        print(f"  {DIM}Time range: {s['date_range']['start']} → {s['date_range']['end']}{R}")
    print()

    print(SEP)
    print(f"  {BOLD}PARSE STATS{R}")
    print(SEP)
    ps = s["parse_stats"]
    print(f"  {DIM}Total lines:{R}      {ps['total_lines']}")
    print(f"  {DIM}Parsed OK:{R}        {ps['parsed_successfully']} ({ps['parse_success_rate']}%)")
    print(f"  {DIM}Format mix:{R}       {ps['format_counts']}")
    if ps.get("truncated"):
        warn(f"File truncated to first N lines for this run.")

    print()
    print(SEP)
    print(f"  {BOLD}FINDINGS BY SEVERITY{R}")
    print(SEP)
    fbs = s["findings_by_severity"]
    max_sev = max(fbs.values()) or 1
    for sev in ("critical", "high", "medium", "low"):
        c = sev_color(sev)
        print(f"  {c}{sev.upper():<10}{R} {fbs[sev]:>4}  {c}{bar(fbs[sev], max_sev)}{R}")

    if s["findings_by_category"]:
        print()
        print(SEP)
        print(f"  {BOLD}FINDINGS BY CATEGORY{R}")
        print(SEP)
        for cat, count in sorted(s["findings_by_category"].items(), key=lambda x: -x[1]):
            print(f"  {cat.replace('_',' '):<24} {count}")

    if full_report["top_offenders"]:
        print()
        print(SEP)
        print(f"  {BOLD}TOP OFFENDERS{R}")
        print(SEP)
        print(f"  {'RANK':<5}{'IP':<20}{'SCORE':<8}{'CATEGORIES'}")
        for i, o in enumerate(full_report["top_offenders"], 1):
            c = sev_color(o["worst_severity"])
            cats = ", ".join(cat.replace("_", " ") for cat in o["categories"])
            print(f"  {i:<5}{c}{o['ip']:<20}{R}{o['risk_score']:<8}{DIM}{cats}{R}")

    findings = full_report["findings"]
    shown = findings if show_all else findings[:max_findings]
    if findings:
        print()
        print(SEP)
        print(f"  {BOLD}FINDINGS{R} {DIM}(showing {len(shown)} of {len(findings)}"
              f"{' — use --all to show every finding' if len(shown) < len(findings) else ''}){R}")
        print(SEP)
        for f in shown:
            c = sev_color(f["severity"])
            print(f"  {c}[{f['severity'].upper():<8}]{R} {BOLD}{f['title']}{R}")
            print(f"  {DIM}{'':<10} {f['detail']}{R}")
            meta = []
            if f.get("source_ip"): meta.append(f"IP: {f['source_ip']}")
            if f.get("line_number"): meta.append(f"line {f['line_number']}")
            if meta:
                print(f"  {DIM}{'':<10} ({' · '.join(meta)}){R}")
            print()
    else:
        print()
        ok("No security findings detected.")
    print()


# ════════════════════════════════════════════════════════════════
#  COMMANDS
# ════════════════════════════════════════════════════════════════

def cmd_analyze(args):
    if args.sample:
        if args.sample == "access":
            sample = sample_logs.generate_sample_access_log()
        elif args.sample == "auth":
            sample = sample_logs.generate_sample_auth_log()
        else:
            err("Invalid --sample value. Use 'access' or 'auth'."); sys.exit(2)
        text = sample["text"]
        if not args.json:
            info(f"Using built-in sample '{args.sample}' log ({sample['injected']['total_lines']} lines).")
    else:
        if not os.path.exists(args.logfile):
            err(f"File not found: {args.logfile}"); sys.exit(2)
        with open(args.logfile, "r", errors="replace") as f:
            text = f.read()

    max_lines = None if args.no_limit else args.max_lines
    parsed = parsers.parse_log_text(text, log_type=args.type, max_lines=max_lines)

    if parsed["stats"]["total_lines"] == 0:
        err("No log lines found."); sys.exit(2)

    config = {
        "bruteforce_threshold": args.bf_threshold,
        "bruteforce_window": args.bf_window,
        "enum_threshold": args.enum_threshold,
    }
    findings = detectors.run_all_detectors(parsed["events"], config=config)
    full_report = report.build_full_report(parsed["events"], parsed["stats"], findings,
                                           bucket_minutes=args.bucket_minutes)

    if args.json:
        # Trim raw_line from events list if we ever include it — findings are self-contained
        print(json.dumps(full_report, indent=2, default=str))
    else:
        print_report(full_report, show_all=args.all)

    threat_exit = {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "CLEAN": 0}
    sys.exit(threat_exit.get(full_report["summary"]["threat_level"], 0))


def cmd_sample(args):
    if args.kind == "access":
        sample = sample_logs.generate_sample_access_log()
    elif args.kind == "auth":
        sample = sample_logs.generate_sample_auth_log()
    else:
        err("Use 'access' or 'auth'."); sys.exit(2)

    if args.output:
        with open(args.output, "w") as f:
            f.write(sample["text"])
        ok(f"Sample {args.kind} log written → {args.output}")
    else:
        print(sample["text"], end="")


# ════════════════════════════════════════════════════════════════
#  ARGPARSE
# ════════════════════════════════════════════════════════════════

def build_parser():
    p = argparse.ArgumentParser(
        prog="cli.py", description="PhantomLog — Apache/Nginx/Auth Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("analyze", help="Analyze a log file (exit: 0=clean/low, 1=medium/high, 2=critical/error)")
    sp.add_argument("logfile", nargs="?", default=None, help="Path to the log file")
    sp.add_argument("--sample", choices=["access", "auth"], default=None,
                    help="Analyze a built-in sample instead of a real file")
    sp.add_argument("--type", choices=["auto", "access", "auth"], default="auto")
    sp.add_argument("--max-lines", type=int, default=200_000, help="Cap lines processed (default 200k)")
    sp.add_argument("--no-limit", action="store_true", help="Remove the line cap entirely")
    sp.add_argument("--bf-threshold", type=int, default=5, help="Auth brute-force: failures to trigger")
    sp.add_argument("--bf-window", type=int, default=5, help="Auth brute-force: window in minutes")
    sp.add_argument("--enum-threshold", type=int, default=15, help="404s to trigger enumeration finding")
    sp.add_argument("--bucket-minutes", type=int, default=60, help="Timeline bucket size in minutes")
    sp.add_argument("--all", action="store_true", help="Show all findings, not just first 25")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_analyze)

    sp = sub.add_parser("sample", help="Print or save a built-in sample log with known attacks")
    sp.add_argument("kind", choices=["access", "auth"])
    sp.add_argument("-o", "--output", default=None, help="Save to this file instead of printing")
    sp.set_defaults(func=cmd_sample)

    return p


def main():
    if len(sys.argv) == 1:
        banner()
        build_parser().print_help()
        return
    args = build_parser().parse_args()

    if args.command == "analyze" and not args.sample and not args.logfile:
        err("Provide a logfile path or use --sample access|auth")
        sys.exit(2)

    try:
        args.func(args)
    except KeyboardInterrupt:
        print(); info("Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
