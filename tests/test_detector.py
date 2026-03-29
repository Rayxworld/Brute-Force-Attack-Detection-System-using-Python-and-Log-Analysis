"""Unit coverage for the brute-force detector routines."""

from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace

from src import (
    BruteForceDetector,
    LOG_TIME_FORMAT,
    build_config,
    export_incident_tickets,
    parse_log_line,
    run_streaming_detector,
)


DEFAULT_ARGS = SimpleNamespace(
    window_seconds=60,
    brute_force_threshold=5,
    credential_window_seconds=45,
    credential_threshold=4,
    alert_cooldown_seconds=120,
    brute_force_severity="HIGH",
    credential_severity="MEDIUM",
)


class DetectorTests(unittest.TestCase):
    def _run_detector_from_file(self, path: str) -> BruteForceDetector:
        config = build_config(DEFAULT_ARGS)
        detector = BruteForceDetector(config)
        with open(path, "r", encoding="utf-8") as handle:
            for idx, raw in enumerate(handle, start=1):
                entry = parse_log_line(raw, idx)
                if entry:
                    detector.process_entry(entry)
        return detector

    def _process_lines(self, lines: list[str]) -> BruteForceDetector:
        config = build_config(DEFAULT_ARGS)
        detector = BruteForceDetector(config)
        for idx, raw in enumerate(lines, start=1):
            entry = parse_log_line(raw, idx)
            if entry:
                detector.process_entry(entry)
        return detector

    def _format_line(self, base: datetime, offset: int, event: str, user: str, ip: str) -> str:
        timestamp = (base + timedelta(seconds=offset)).strftime(LOG_TIME_FORMAT)
        return f"{timestamp} {event} {user} {ip}"

    def test_sample_log_triggers_expected_alerts(self) -> None:
        detector = self._run_detector_from_file("logs/sample.log")
        self.assertEqual(3, len(detector.alerts))
        events = {(alert["ip"], alert["event"]) for alert in detector.alerts}
        self.assertIn(("192.168.10.50", "brute_force"), events)
        self.assertIn(("203.0.113.10", "credential_stuffing"), events)
        self.assertIn(("203.0.113.10", "brute_force"), events)
        self.assertNotIn(("198.51.100.22", "brute_force"), events)
        annotation = next(
            alert for alert in detector.alerts if alert["ip"] == "192.168.10.50" and alert["event"] == "brute_force"
        )
        self.assertEqual("Brute force credential attack", annotation["classification"])
        self.assertTrue(all(0 <= alert["confidence"] <= 1 for alert in detector.alerts))

    def test_success_clears_inflight_bruteforce_state(self) -> None:
        base = datetime.strptime("2026-03-29T09:00:00Z", LOG_TIME_FORMAT)
        ip = "203.0.113.99"
        lines = []
        # Four rapid failures, then a success to force reset.
        for offset in [0, 10, 20, 30]:
            lines.append(self._format_line(base, offset, "LOGIN_FAILED", "victim", ip))
        lines.append(self._format_line(base, 40, "LOGIN_SUCCESS", "victim", ip))
        # Fresh wave of five failures should trigger exactly one alert.
        for offset in [45, 50, 55, 60, 65]:
            lines.append(self._format_line(base, offset, "LOGIN_FAILED", "victim", ip))

        detector = self._process_lines(lines)
        self.assertEqual(1, len(detector.alerts))
        alert = detector.alerts[0]
        self.assertEqual(ip, alert["ip"])
        self.assertEqual("brute_force", alert["event"])
        self.assertIn("Block", alert["recommendation"])

    def test_slow_attack_stays_below_window(self) -> None:
        ip = "203.0.113.50"
        lines = [
            "2026-03-29T08:35:00Z LOGIN_FAILED hacker 203.0.113.50",
            "2026-03-29T08:36:10Z LOGIN_FAILED hacker 203.0.113.50",
            "2026-03-29T08:37:30Z LOGIN_FAILED hacker 203.0.113.50",
            "2026-03-29T08:39:05Z LOGIN_FAILED hacker 203.0.113.50",
            "2026-03-29T08:41:20Z LOGIN_FAILED hacker 203.0.113.50",
            "2026-03-29T08:44:00Z LOGIN_FAILED hacker 203.0.113.50",
        ]
        detector = self._process_lines(lines)
        self.assertEqual(0, len(detector.alerts))

    def test_streaming_mode_reuses_log_replay(self) -> None:
        config = build_config(DEFAULT_ARGS)
        tmpdir = os.path.join("tests", "tmp_stream")
        os.makedirs(tmpdir, exist_ok=True)
        output_path = os.path.join(tmpdir, "stream_alerts.json")
        alerts = run_streaming_detector(
            "logs/sample.log", output_path, config, poll_seconds=0, sleep_func=lambda _: None
        )
        self.assertGreater(len(alerts), 0)
        self.assertTrue(os.path.exists(output_path))
        with open(output_path, encoding="utf-8") as handle:
            stored = json.load(handle)
        self.assertEqual(len(alerts), len(stored))
        os.remove(output_path)

    def test_ticket_exporter_persists_metadata(self) -> None:
        alerts = [
            {
                "timestamp": "2026-03-29T08:20:40Z",
                "ip": "192.168.10.50",
                "event": "brute_force",
                "severity": "HIGH",
                "details": "5 failed logins in the last 60 seconds",
                "classification": "Brute force credential attack",
                "mitre_id": "T1110",
                "confidence": 0.88,
                "recommendation": "Block the source IP, tie it to IPS/IDS rules, and review authentication logs",
            }
        ]
        tmpdir = os.path.join("tests", "tmp_tickets")
        os.makedirs(tmpdir, exist_ok=True)
        ticket_path = os.path.join(tmpdir, "tickets.json")
        export_incident_tickets(alerts, ticket_path, prefix="TEST")
        with open(ticket_path, encoding="utf-8") as handle:
            data = json.load(handle)
        self.assertEqual(1, len(data))
        self.assertEqual("TEST-001", data[0]["ticket_id"])
        self.assertEqual(alerts[0]["confidence"], data[0]["confidence"])
        os.remove(ticket_path)
