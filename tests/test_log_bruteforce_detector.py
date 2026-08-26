import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from log_bruteforce_detector import build_json_report, build_report, main, parse_log, verdict_for


def write_log(tmp_path, lines):
    path = tmp_path / "auth.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def test_failed_password_parses_user_and_ip(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for admin from 203.0.113.45 port 51422 ssh2",
    ])
    stats = parse_log(log)
    assert stats["203.0.113.45"]["failed_count"] == 1
    assert "admin" in stats["203.0.113.45"]["users"]


def test_failed_password_invalid_user_strips_prefix(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:10:07 srv sshd[4]: Failed password for invalid user ubuntu from 203.0.113.45 port 51425 ssh2",
    ])
    stats = parse_log(log)
    assert stats["203.0.113.45"]["users"] == {"ubuntu"}


def test_aggregates_multiple_attempts_same_ip(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:22:01 srv sshd[1]: Failed password for admin from 192.0.2.200 port 40001 ssh2",
        "Aug 20 03:22:05 srv sshd[2]: Failed password for invalid user support from 192.0.2.200 port 40003 ssh2",
        "Aug 20 03:22:11 srv sshd[3]: Failed password for admin from 192.0.2.200 port 40006 ssh2",
    ])
    entry = parse_log(log)["192.0.2.200"]
    assert entry["failed_count"] == 3
    assert entry["users"] == {"admin", "support"}
    assert entry["first_seen"] == "Aug 20 03:22:01"
    assert entry["last_seen"] == "Aug 20 03:22:11"


def test_verdict_threshold_boundary():
    below = {"failed_count": 4, "compromised": False}
    at = {"failed_count": 5, "compromised": False}
    above = {"failed_count": 6, "compromised": False}
    assert verdict_for(below, threshold=5) == "LOW — below threshold"
    assert verdict_for(at, threshold=5) == "MEDIUM — brute-force suspected"
    assert verdict_for(above, threshold=5) == "MEDIUM — brute-force suspected"


def test_verdict_compromise_overrides_threshold():
    entry = {"failed_count": 1, "compromised": True}
    assert verdict_for(entry, threshold=5) == "HIGH — possible compromise"


def test_accepted_after_failed_marks_compromised(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for root from 203.0.113.45 port 51422 ssh2",
        "Aug 20 03:10:19 srv sshd[2]: Accepted password for root from 203.0.113.45 port 51431 ssh2",
    ])
    entry = parse_log(log)["203.0.113.45"]
    assert entry["compromised"] is True


def test_accepted_only_ip_not_tracked(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:45:00 srv sshd[1]: Accepted password for kaan from 198.51.100.10 port 22010 ssh2",
    ])
    stats = parse_log(log)
    assert "198.51.100.10" not in stats


def test_accepted_only_ip_excluded_from_report(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for root from 203.0.113.45 port 51422 ssh2",
        "Aug 20 03:45:00 srv sshd[2]: Accepted password for kaan from 198.51.100.10 port 22010 ssh2",
    ])
    stats = parse_log(log)
    report, (total, _high, _medium, _low) = build_report(stats, threshold=5)
    assert total == 1
    assert "198.51.100.10" not in report
    assert "203.0.113.45" in report


def test_json_report_is_valid_and_has_expected_fields(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for root from 203.0.113.45 port 51422 ssh2",
        "Aug 20 03:10:19 srv sshd[2]: Accepted password for root from 203.0.113.45 port 51431 ssh2",
    ])
    stats = parse_log(log)
    report, (_total, _high, _medium, _low) = build_json_report(stats, threshold=5)
    payload = json.loads(report)

    assert payload["threshold"] == 5
    assert payload["summary"] == {"total": 1, "high": 1, "medium": 0, "low": 0}
    finding = payload["findings"][0]
    assert finding["ip"] == "203.0.113.45"
    assert finding["failed_attempts"] == 1
    assert finding["compromised"] is True
    assert finding["verdict"] == "HIGH — possible compromise"


def test_json_report_excludes_accepted_only_ip(tmp_path):
    log = write_log(tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for root from 203.0.113.45 port 51422 ssh2",
        "Aug 20 03:45:00 srv sshd[2]: Accepted password for kaan from 198.51.100.10 port 22010 ssh2",
    ])
    stats = parse_log(log)
    report, _ = build_json_report(stats, threshold=5)
    payload = json.loads(report)

    ips = [f["ip"] for f in payload["findings"]]
    assert "198.51.100.10" not in ips
    assert "203.0.113.45" in ips


def run_main(monkeypatch, tmp_path, log_lines, extra_args):
    log = write_log(tmp_path, log_lines)
    out = str(tmp_path / "out.md")
    argv = ["log_bruteforce_detector.py", "--log", log, "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_defaults_to_zero_exit_even_with_high_finding(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for root from 203.0.113.45 port 51422 ssh2",
        "Aug 20 03:10:19 srv sshd[2]: Accepted password for root from 203.0.113.45 port 51431 ssh2",
    ], [])
    assert exit_code == 0


def test_fail_on_high_exits_nonzero_when_compromised_ip_found(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, [
        "Aug 20 03:10:01 srv sshd[1]: Failed password for root from 203.0.113.45 port 51422 ssh2",
        "Aug 20 03:10:19 srv sshd[2]: Accepted password for root from 203.0.113.45 port 51431 ssh2",
    ], ["--fail-on", "high"])
    assert exit_code == 1


def test_fail_on_high_exits_zero_when_only_medium_findings(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, [
        "Aug 20 03:22:01 srv sshd[1]: Failed password for admin from 192.0.2.200 port 40001 ssh2",
    ] * 6, ["--threshold", "5", "--fail-on", "high"])
    assert exit_code == 0


def test_fail_on_medium_exits_nonzero_for_medium_findings(monkeypatch, tmp_path):
    exit_code = run_main(monkeypatch, tmp_path, [
        "Aug 20 03:22:01 srv sshd[1]: Failed password for admin from 192.0.2.200 port 40001 ssh2",
    ] * 6, ["--threshold", "5", "--fail-on", "medium"])
    assert exit_code == 1
