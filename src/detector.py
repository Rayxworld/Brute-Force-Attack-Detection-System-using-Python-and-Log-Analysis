"""Brute Force Attack Detection system for login logs."""
from __future__ import annotations

import argparse
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, List, Optional, Tuple

LOG_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
KNOWN_EVENTS = {"LOGIN_SUCCESS", "LOGIN_FAILED"}
ALERT_METADATA = {
    "brute_force": {
        "classification": "Brute force credential attack",
        "mitre_id": "T1110",
        "confidence": 0.88,
        "recommendation": "Block the source IP, tie it to IPS/IDS rules, and review authentication logs",
    },
    "credential_stuffing": {
        "classification": "Credential stuffing/username enumeration",
        "mitre_id": "T1110",
        "confidence": 0.72,
        "recommendation": "Throttle requests from the IP, reset impacted accounts, and enforce MFA",
    },
}


class LogEntry:
    """Simple holder for a parsed log row."""

    __slots__ = ("timestamp", "event_type", "username", "ip")

    def __init__(self, timestamp: datetime, event_type: str, username: str, ip: str) -> None:
        self.timestamp = timestamp
        self.event_type = event_type
        self.username = username
        self.ip = ip


def parse_log_line(line: str, line_number: int) -> Optional[LogEntry]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split()
    if len(parts) != 4:
        raise ValueError(f"line {line_number}: expected 4 columns, got {len(parts)}")

    timestamp_str, event_type, username, ip = parts
    if event_type not in KNOWN_EVENTS:
        raise ValueError(f"line {line_number}: event type '{event_type}' is not recognized")

    timestamp = datetime.strptime(timestamp_str, LOG_TIME_FORMAT)
    return LogEntry(timestamp=timestamp, event_type=event_type, username=username, ip=ip)


class BruteForceDetector:
    """Tracks failed login attempts and raises alerts when abuse patterns appear."""

    def __init__(self, config: Dict[str, int]) -> None:
        self.config = config
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.username_attempts: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        self.alerts: List[Dict[str, str]] = []
        self.last_alert: Dict[str, Dict[str, datetime]] = defaultdict(dict)

    def process_entry(self, entry: LogEntry) -> None:
        if entry.event_type == "LOGIN_FAILED":
            self._record_failed(entry)
            self._evaluate_brute_force(entry)
            self._record_username(entry)
            self._evaluate_credential_stuffing(entry)
        elif entry.event_type == "LOGIN_SUCCESS":
            self._reset_ip(entry.ip)

    def _record_failed(self, entry: LogEntry) -> None:
        failures = self.failed_attempts[entry.ip]
        failures.append(entry.timestamp)
        window = timedelta(seconds=self.config["window_seconds"])
        cutoff = entry.timestamp - window
        self.failed_attempts[entry.ip] = [t for t in failures if t >= cutoff]

    def _record_username(self, entry: LogEntry) -> None:
        usernames = self.username_attempts[entry.ip]
        usernames.append((entry.timestamp, entry.username))
        window = timedelta(seconds=self.config["credential_window_seconds"])
        cutoff = entry.timestamp - window
        self.username_attempts[entry.ip] = [(ts, user) for ts, user in usernames if ts >= cutoff]

    def _evaluate_brute_force(self, entry: LogEntry) -> None:
        failures = self.failed_attempts[entry.ip]
        threshold = self.config["brute_force_threshold"]
        if len(failures) >= threshold and self._should_alert(entry.ip, "brute_force", entry.timestamp):
            details = (
                f"{len(failures)} failed logins in the last {self.config['window_seconds']} seconds"
            )
            severity = self.config["severity_map"]["brute_force"]
            self._emit_alert(entry, "brute_force", severity, details)

    def _evaluate_credential_stuffing(self, entry: LogEntry) -> None:
        usernames = [user for _, user in self.username_attempts[entry.ip]]
        unique_usernames = set(usernames)
        threshold = self.config["credential_threshold"]
        if (
            len(unique_usernames) >= threshold
            and self._should_alert(entry.ip, "credential_stuffing", entry.timestamp)
        ):
            severity = self.config["severity_map"]["credential_stuffing"]
            details = (
                f"{len(unique_usernames)} distinct usernames attempted in {self.config['credential_window_seconds']} seconds"
            )
            self._emit_alert(entry, "credential_stuffing", severity, details)

    def _reset_ip(self, ip: str) -> None:
        self.failed_attempts.pop(ip, None)
        self.username_attempts.pop(ip, None)

    def _should_alert(self, ip: str, detector: str, now: datetime) -> bool:
        cooldown = timedelta(seconds=self.config["alert_cooldown_seconds"])
        last = self.last_alert[ip].get(detector)
        if not last:
            return True
        return now - last >= cooldown

    def _emit_alert(self, entry: LogEntry, detector: str, severity: str, details: str) -> None:
        metadata = ALERT_METADATA.get(detector, {})
        alert = {
            "timestamp": entry.timestamp.strftime(LOG_TIME_FORMAT),
            "ip": entry.ip,
            "event": detector,
            "severity": severity,
            "details": details,
            "classification": metadata.get("classification", detector),
            "mitre_id": metadata.get("mitre_id", "T1110"),
            "confidence": metadata.get("confidence", 0.5),
            "recommendation": metadata.get(
                "recommendation", "Investigate the IP and correlated events"
            ),
        }
        self.alerts.append(alert)
        self.last_alert[entry.ip][detector] = entry.timestamp
        print(
            f"[{alert['timestamp']}] [{severity}] {entry.ip} -> {alert['classification']} ({detector}, MITRE {alert['mitre_id']}): "
            f"{details} | Recommendation: {alert['recommendation']}"
        )

    def to_json(self) -> str:
        return json.dumps(self.alerts, indent=2)


def ensure_dir(path: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)


def parse_log_entries(log_path: str) -> Iterable[LogEntry]:
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"log file not found: {log_path}")

    with open(log_path, "r", encoding="utf-8") as handle:
        for idx, raw_line in enumerate(handle, start=1):
            try:
                entry = parse_log_line(raw_line, idx)
            except ValueError as exc:
                print(f"warning: {exc}")
                continue
            if entry:
                yield entry


def process_entries(
    detector: BruteForceDetector,
    entries: Iterable[LogEntry],
    pause_seconds: float = 0.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    for entry in entries:
        detector.process_entry(entry)
        if pause_seconds > 0:
            sleeper(pause_seconds)


def persist_alerts(alerts: List[Dict[str, str]], output_path: str) -> None:
    ensure_dir(output_path)
    with open(output_path, "w", encoding="utf-8") as out:
        out.write(json.dumps(alerts, indent=2))


def collect_alerts(
    log_path: str,
    config: Dict[str, int],
    pause_seconds: float = 0.0,
    sleeper: Callable[[float], None] = time.sleep,
) -> List[Dict[str, str]]:
    detector = BruteForceDetector(config)
    entries = parse_log_entries(log_path)
    process_entries(detector, entries, pause_seconds=pause_seconds, sleeper=sleeper)
    return detector.alerts


def export_incident_tickets(
    alerts: Sequence[Dict[str, str]], ticket_path: str, prefix: str = "INC"
) -> None:
    tickets: List[Dict[str, str]] = []
    for idx, alert in enumerate(alerts, start=1):
        tickets.append(
            {
                "ticket_id": f"{prefix}-{idx:03}",
                "alert_timestamp": alert["timestamp"],
                "ip": alert["ip"],
                "summary": f"{alert['severity']} {alert['classification']}",
                "details": alert["details"],
                "mitre_id": alert["mitre_id"],
                "confidence": alert["confidence"],
                "recommendation": alert["recommendation"],
            }
        )
    ensure_dir(ticket_path)
    with open(ticket_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(tickets, indent=2))
    print(f"{len(tickets)} incident tickets written to {ticket_path}")


def run_detector(log_path: str, output_path: str, config: Dict[str, int]) -> List[Dict[str, str]]:
    alerts = collect_alerts(log_path, config)
    persist_alerts(alerts, output_path)
    print(f"alerts written to {output_path} ({len(alerts)} entries)")
    return alerts


def run_streaming_detector(
    log_path: str,
    output_path: str,
    config: Dict[str, int],
    poll_seconds: float = 0.5,
    sleep_func: Callable[[float], None] = time.sleep,
) -> List[Dict[str, str]]:
    alerts = collect_alerts(
        log_path, config, pause_seconds=poll_seconds, sleeper=sleep_func
    )
    persist_alerts(alerts, output_path)
    print(f"streaming alerts persisted to {output_path} ({len(alerts)} entries)")
    return alerts


def build_config(args: argparse.Namespace) -> Dict[str, int]:
    return {
        "window_seconds": args.window_seconds,
        "brute_force_threshold": args.brute_force_threshold,
        "credential_window_seconds": args.credential_window_seconds,
        "credential_threshold": args.credential_threshold,
        "alert_cooldown_seconds": args.alert_cooldown_seconds,
        "severity_map": {
            "brute_force": args.brute_force_severity,
            "credential_stuffing": args.credential_severity,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Brute force attack detector for login logs")
    parser.add_argument("--log-file", default="logs/sample.log", help="path to the login event log")
    parser.add_argument("--output", default="results/alerts.json", help="where to write alerts JSON")
    parser.add_argument("--window-seconds", type=int, default=60, help="time window for brute force checks")
    parser.add_argument(
        "--brute-force-threshold",
        type=int,
        default=5,
        help="failed attempts to flag brute force",
    )
    parser.add_argument(
        "--credential-window-seconds",
        type=int,
        default=45,
        help="short window to watch for credential stuffing",
    )
    parser.add_argument(
        "--credential-threshold",
        type=int,
        default=4,
        help="number of distinct usernames before alerting credential stuffing",
    )
    parser.add_argument(
        "--alert-cooldown-seconds",
        type=int,
        default=120,
        help="minimum seconds between repeated alerts for the same IP/detector",
    )
    parser.add_argument(
        "--brute-force-severity",
        default="HIGH",
        help="severity label for brute force alerts (e.g., HIGH)",
    )
    parser.add_argument(
        "--credential-severity",
        default="MEDIUM",
        help="severity label for credential stuffing alerts",
    )
    parser.add_argument(
        "--mode",
        choices=["batch", "stream"],
        default="batch",
        help="operate in batch (default) or streaming mode",
    )
    parser.add_argument(
        "--stream-poll-seconds",
        type=float,
        default=0.5,
        help="pause between entries in streaming mode (0 disables sleeping)",
    )
    parser.add_argument(
        "--ticket-output",
        default="results/tickets.json",
        help="where to write incident tickets",
    )
    parser.add_argument(
        "--ticket-prefix",
        default="INC",
        help="prefix for ticket IDs",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = build_config(args)
    if args.mode == "stream":
        alerts = run_streaming_detector(
            args.log_file, args.output, config, poll_seconds=args.stream_poll_seconds
        )
    else:
        alerts = run_detector(args.log_file, args.output, config)

    export_incident_tickets(alerts, args.ticket_output, prefix=args.ticket_prefix)
    if not alerts:
        print("no alerts generated")


if __name__ == "__main__":
    main()
