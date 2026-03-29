from collections import Counter
from types import SimpleNamespace
from pathlib import Path

import streamlit as st

from src import build_config, collect_alerts, export_incident_tickets


st.set_page_config(
    page_title="Brute Force Attack Detector",
    layout="wide",
    initial_sidebar_state="expanded",
)


def build_args(
    window_seconds: int,
    brute_force_threshold: int,
    credential_window_seconds: int,
    credential_threshold: int,
    alert_cooldown_seconds: int,
    brute_force_severity: str,
    credential_severity: str,
) -> SimpleNamespace:
    return SimpleNamespace(
        window_seconds=window_seconds,
        brute_force_threshold=brute_force_threshold,
        credential_window_seconds=credential_window_seconds,
        credential_threshold=credential_threshold,
        alert_cooldown_seconds=alert_cooldown_seconds,
        brute_force_severity=brute_force_severity,
        credential_severity=credential_severity,
    )


def load_log_preview(path: Path, lines: int) -> str:
    if not path.is_file():
        return ""
    with path.open("r", encoding="utf-8") as handle:
        return "".join(handle.readlines()[:lines])


st.title("Brute Force Attack Detection Console")
st.markdown(
    "Use the sidebar to tune detection thresholds, replay the sample log, and persist the enriched alerts/tickets you would feed into a SOC dashboard."
)

log_path = Path(st.sidebar.text_input("Log file path", "logs/sample.log"))
preview_lines = st.sidebar.slider("Log preview size", 5, 40, 12)
st.sidebar.markdown("---")

window_seconds = st.sidebar.slider("Brute-force window (seconds)", 30, 180, 60)
brute_force_threshold = st.sidebar.slider("Failed attempts to alert", 3, 10, 5)
credential_window_seconds = st.sidebar.slider("Credential stuffing window (seconds)", 20, 90, 45)
credential_threshold = st.sidebar.slider("Distinct usernames to alert", 2, 10, 4)
alert_cooldown_seconds = st.sidebar.slider("Alert cooldown (seconds)", 30, 300, 120)
brute_force_severity = st.sidebar.selectbox(
    "Brute-force severity label", ["LOW", "MEDIUM", "HIGH"], index=2
)
credential_severity = st.sidebar.selectbox(
    "Credential-stuffing severity label", ["LOW", "MEDIUM", "HIGH"], index=1
)
st.sidebar.markdown("---")
st.sidebar.header("Ticket export")
ticket_output = st.sidebar.text_input("Ticket output path", "results/tickets.json")
ticket_prefix = st.sidebar.text_input("Ticket prefix", "INC")
export_clicked = st.sidebar.button("Export tickets")

if not log_path.is_file():
    st.error(f"Log file not found: {log_path}")
    st.stop()

args = build_args(
    window_seconds,
    brute_force_threshold,
    credential_window_seconds,
    credential_threshold,
    alert_cooldown_seconds,
    brute_force_severity,
    credential_severity,
)
config = build_config(args)
alerts = collect_alerts(log_path.as_posix(), config)
st.session_state["alerts"] = alerts

if export_clicked:
    if alerts:
        export_incident_tickets(alerts, ticket_output, prefix=ticket_prefix)
        st.sidebar.success(f"Tickets synced to {ticket_output}")
    else:
        st.sidebar.warning("No alerts to export; adjust thresholds or log source.")

preview = load_log_preview(log_path, preview_lines)

col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("Log preview")
    st.code(preview or "no data to display")
with col2:
    st.subheader("Alert metrics")
    st.metric("Alerts generated", len(alerts))
    severity_counts = Counter(alert["severity"] for alert in alerts)
    st.table(
        [{"severity": severity, "count": count} for severity, count in severity_counts.items()]
    )
    ip_counts = Counter(alert["ip"] for alert in alerts)
    st.table(
        [{"ip": ip, "alerts": count} for ip, count in ip_counts.most_common(5)]
    )

st.subheader("Alerts table")
if alerts:
    st.table(alerts)
else:
    st.info("No alerts detected with the current configuration.")
