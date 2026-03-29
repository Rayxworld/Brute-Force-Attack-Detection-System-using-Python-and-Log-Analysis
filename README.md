# Brute Force Attack Detection System

This project mimics the sort of tooling a SOC/security detection engineer would build: it parses login logs, looks for brutish authentication patterns, and emits enriched alerts that tell responders what to do next.

## Detection strategy

1. **Sliding windows** keep track of failed logins and username diversity per IP. If an IP hits the configured failure threshold within `window_seconds`, a _brute force_ alert fires. If an IP tries multiple usernames in the credential window, a _credential stuffing_ alert fires.
2. **Response context** is baked into each alert with severity, confidence score, MITRE ATT&CK references, and recommended follow-up steps to mirror real SOC playbooks.
3. **Success resets** remove the tracked state for an IP so a legitimate user who finally succeeds clears the suspicion�this prevents alert fatigue even in noisy environments.

## Alert enrichment

Alerts (see `results/alerts.json`) now include:

- `classification` (e.g., �Brute force credential attack�)
- `severity` and `confidence` so analysts know how urgent the signal is
- `mitre_id` (currently T1110, credential access)
- `recommendation` for response actions (block the IP, enforce MFA, etc.)

## Sample dataset

The dataset under `logs/sample.log` is labeled with Scenarios A�G and covers the required cases: normal traffic, brute force scoring, credential stuffing, success after failures, and slow attacks that should not alert. It uses realistic, sequential timestamps so you can demo event timelines to stakeholders.

## Running the detector

```sh
py src/detector.py             # analyzes logs/sample.log and writes results/alerts.json + results/tickets.json
py -m unittest discover tests  # validates detection logic and SOC-style metadata
```

Use `--mode stream --stream-poll-seconds 0.25` to replay logs in streaming mode so you can demo per-event alerting; sleeping between entries introduces the feel of a SIEM feed.
Command-line flags let you tune window sizes, thresholds, cooldowns, severity labels, streaming cadence, and ticket ID prefixes without touching the code.

## Incident ticket export

Running the detector always writes an incident ticket file (default `results/tickets.json`) that mirrors the alert metadata while adding `ticket_id`, `summary`, and `details` so you can drop it straight into a ticketing system or SOC playbook. Use `--ticket-prefix` to align ticket IDs with internal SOPs (e.g., `SOC-` or `INC-2026`).

## Streamlit dashboard preview

```
pip install streamlit
streamlit run src/streamlit_app.py
```

The dashboard lets you tweak detection windows, watch the sample log preview, and export the enriched alerts/ticket payloads without rerunning the CLI manually. Use the ticket export controls to push SOC-ready recommendations into `results/tickets.json`.

## SOC response playbook

- When a **brute force** alert triggers, correlate with endpoint telemetry, apply an IP block, and consider flagging the user account for review.
- For **credential stuffing**, escalate to account protection teams, enforce MFA, and rotate exposed credentials if the same username/IP pair reappears.
- Log the `recommendation` field alongside ticket descriptions so analysts can trace decisions back to the detection logic.