"""
PhantomLog — Report Aggregation
═══════════════════════════════════════════════════════════════
Takes raw events + findings and produces the summary views a human
actually wants to see: a time-bucketed activity timeline, a
top-offenders leaderboard, and an overall threat-level verdict.
"""

import datetime
from collections import defaultdict, Counter


def build_timeline(events: list, bucket_minutes: int = 60) -> list:
    """
    Buckets ALL events (not just findings) by time into fixed-size windows,
    annotated with how many were security findings vs normal traffic.
    Returns a chronologically sorted list — empty if no events have timestamps.
    """
    timed = [e for e in events if e.get("timestamp")]
    if not timed:
        return []

    bucket_size = datetime.timedelta(minutes=bucket_minutes)
    buckets = defaultdict(lambda: {"total": 0})

    earliest = min(e["timestamp"] for e in timed)

    for e in timed:
        offset = e["timestamp"] - earliest
        bucket_index = int(offset.total_seconds() // bucket_size.total_seconds())
        bucket_start = earliest + bucket_index * bucket_size
        buckets[bucket_start]["total"] += 1

    result = [{"bucket_start": str(k), "count": v["total"]} for k, v in sorted(buckets.items())]
    return result


def build_findings_timeline(findings: list, bucket_minutes: int = 60) -> list:
    """Same bucketing, but for findings specifically, broken down by severity per bucket."""
    timed = [f for f in findings if f.get("timestamp") and f["timestamp"] != "None"]
    if not timed:
        return []

    bucket_size = datetime.timedelta(minutes=bucket_minutes)
    parsed_times = []
    for f in timed:
        try:
            ts = datetime.datetime.fromisoformat(f["timestamp"])
            parsed_times.append((ts, f["severity"]))
        except (ValueError, TypeError):
            continue

    if not parsed_times:
        return []

    earliest = min(t for t, _ in parsed_times)
    buckets = defaultdict(lambda: Counter())

    for ts, sev in parsed_times:
        offset = ts - earliest
        bucket_index = int(offset.total_seconds() // bucket_size.total_seconds())
        bucket_start = earliest + bucket_index * bucket_size
        buckets[bucket_start][sev] += 1

    result = []
    for bucket_start, counts in sorted(buckets.items()):
        result.append({
            "bucket_start": str(bucket_start),
            "critical": counts.get("critical", 0), "high": counts.get("high", 0),
            "medium": counts.get("medium", 0), "low": counts.get("low", 0),
            "total": sum(counts.values()),
        })
    return result


def top_offenders(findings: list, limit: int = 10) -> list:
    """Aggregates findings by source IP, ranked by a simple severity-weighted risk score."""
    severity_weight = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    by_ip = defaultdict(lambda: {"score": 0, "findings": [], "categories": set()})

    for f in findings:
        ip = f.get("source_ip")
        if not ip:
            continue
        by_ip[ip]["score"] += severity_weight.get(f["severity"], 1) * (f.get("count") or 1)
        by_ip[ip]["findings"].append(f)
        by_ip[ip]["categories"].add(f["category"])

    ranked = []
    for ip, data in by_ip.items():
        worst_severity = min((f["severity"] for f in data["findings"]),
                             key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5))
        ranked.append({
            "ip": ip, "risk_score": data["score"],
            "finding_count": len(data["findings"]),
            "categories": sorted(data["categories"]),
            "worst_severity": worst_severity,
        })

    ranked.sort(key=lambda x: -x["risk_score"])
    return ranked[:limit]


def overall_summary(events: list, findings: list, parse_stats: dict) -> dict:
    """High-level headline stats for the top of the report."""
    timed = [e for e in events if e.get("timestamp")]
    date_range = None
    if timed:
        earliest = min(e["timestamp"] for e in timed)
        latest = max(e["timestamp"] for e in timed)
        date_range = {"start": str(earliest), "end": str(latest)}

    unique_ips = len(set(e["source_ip"] for e in events if e.get("source_ip")))
    unique_attacker_ips = len(set(f["source_ip"] for f in findings if f.get("source_ip")))

    sev_counts = Counter(f["severity"] for f in findings)

    if sev_counts.get("critical", 0) > 0:
        threat_level = "CRITICAL"
    elif sev_counts.get("high", 0) > 0:
        threat_level = "HIGH"
    elif sev_counts.get("medium", 0) > 0:
        threat_level = "MEDIUM"
    elif sev_counts.get("low", 0) > 0:
        threat_level = "LOW"
    else:
        threat_level = "CLEAN"

    return {
        "total_events": len(events),
        "parse_stats": parse_stats,
        "date_range": date_range,
        "unique_source_ips": unique_ips,
        "unique_attacker_ips": unique_attacker_ips,
        "total_findings": len(findings),
        "findings_by_severity": {
            "critical": sev_counts.get("critical", 0), "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0), "low": sev_counts.get("low", 0),
            "info": sev_counts.get("info", 0),
        },
        "findings_by_category": dict(Counter(f["category"] for f in findings)),
        "threat_level": threat_level,
    }


def build_full_report(events: list, parse_stats: dict, findings: list,
                      bucket_minutes: int = 60, top_n: int = 10) -> dict:
    """One call that produces everything the UI/CLI needs to render a complete report."""
    return {
        "summary": overall_summary(events, findings, parse_stats),
        "timeline": build_timeline(events, bucket_minutes=bucket_minutes),
        "findings_timeline": build_findings_timeline(findings, bucket_minutes=bucket_minutes),
        "top_offenders": top_offenders(findings, limit=top_n),
        "findings": findings,
    }
