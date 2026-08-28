#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import defaultdict

FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)


def parse_log(path):
    stats = defaultdict(lambda: {
        "failed_count": 0,
        "users": set(),
        "first_seen": None,
        "last_seen": None,
        "compromised": False,
    })

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            timestamp = line[:15]

            m = FAILED_RE.search(line)
            if m:
                ip = m.group("ip")
                entry = stats[ip]
                entry["failed_count"] += 1
                entry["users"].add(m.group("user"))
                if entry["first_seen"] is None:
                    entry["first_seen"] = timestamp
                entry["last_seen"] = timestamp
                continue

            m = ACCEPTED_RE.search(line)
            if m:
                ip = m.group("ip")
                if ip in stats and stats[ip]["failed_count"] > 0:
                    stats[ip]["compromised"] = True
                    stats[ip]["last_seen"] = timestamp

    return stats


def verdict_for(entry, threshold):
    if entry["compromised"]:
        return "HIGH — possible compromise"
    if entry["failed_count"] >= threshold:
        return "MEDIUM — brute-force suspected"
    return "LOW — below threshold"


def build_report(stats, threshold):
    rows = [(ip, entry) for ip, entry in stats.items() if entry["failed_count"] > 0]
    rows.sort(key=lambda item: item[1]["failed_count"], reverse=True)

    lines = [
        "# Log Bruteforce Detector — Report",
        "",
        f"Threshold: {threshold} failed attempts",
        "",
        "| IP | Failed Attempts | Unique Usernames | First Seen | Last Seen | Verdict |",
        "|---|---|---|---|---|---|",
    ]
    for ip, entry in rows:
        lines.append(
            f"| {ip} | {entry['failed_count']} | {len(entry['users'])} | "
            f"{entry['first_seen']} | {entry['last_seen']} | {verdict_for(entry, threshold)} |"
        )

    high = sum(1 for _, e in rows if e["compromised"])
    medium = sum(1 for _, e in rows if not e["compromised"] and e["failed_count"] >= threshold)
    low = len(rows) - high - medium

    lines += [
        "",
        f"Summary: {len(rows)} IP(s) flagged — {high} HIGH, {medium} MEDIUM, {low} LOW.",
    ]
    return "\n".join(lines) + "\n", (len(rows), high, medium, low)


def build_json_report(stats, threshold):
    rows = [(ip, entry) for ip, entry in stats.items() if entry["failed_count"] > 0]
    rows.sort(key=lambda item: item[1]["failed_count"], reverse=True)

    findings = [
        {
            "ip": ip,
            "failed_attempts": entry["failed_count"],
            "unique_usernames": len(entry["users"]),
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "compromised": entry["compromised"],
            "verdict": verdict_for(entry, threshold),
        }
        for ip, entry in rows
    ]

    high = sum(1 for f in findings if f["compromised"])
    medium = sum(1 for f in findings if not f["compromised"] and f["failed_attempts"] >= threshold)
    low = len(findings) - high - medium

    payload = {
        "threshold": threshold,
        "summary": {"total": len(findings), "high": high, "medium": medium, "low": low},
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n", (len(findings), high, medium, low)


def main():
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force attempts from an auth.log-style file."
    )
    parser.add_argument("--log", required=True, help="Path to the auth log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed-attempt threshold for MEDIUM verdict")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Report output format"
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    stats = parse_log(args.log)
    if args.format == "json":
        report, (total, high, medium, low) = build_json_report(stats, args.threshold)
    else:
        report, (total, high, medium, low) = build_report(stats, args.threshold)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"Flagged {total} IP(s): {high} HIGH, {medium} MEDIUM, {low} LOW.")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high > 0:
        return 1
    if args.fail_on == "medium" and (high > 0 or medium > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
