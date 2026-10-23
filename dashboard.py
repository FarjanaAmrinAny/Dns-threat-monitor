import subprocess
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from reputation import lookup_domain_reputation

BASE = Path(__file__).resolve().parent

SOURCES = {
    "Sample DNS dataset": {
        "input": BASE / "sample_dns_queries.csv",
        "output": BASE / "dns_findings.csv",
        "script": BASE / "detect_dns.py",
    },
    "Live captured DNS": {
        "input": BASE / "live_dns_queries.csv",
        "output": BASE / "live_dns_findings.csv",
        "script": BASE / "analyze_live_dns.py",
    },
}

RISKS = ["High", "Medium", "Low", "Informational"]
REQUIRED = {
    "timestamp", "client_id", "query_name", "query_type",
    "new_domain", "high_query_volume", "suspicious_tld",
    "dga_like", "risk_score", "risk_level", "reasons",
}

st.set_page_config(
    page_title="DNS Threat Monitor",
    page_icon="🌐",
    layout="wide",
)

st.title("🌐 DNS Threat Monitor")
st.caption("SOC Analyst Lab | Sample and live DNS metadata analysis")

source_name = st.sidebar.radio("DNS data source", list(SOURCES))
source = SOURCES[source_name]

st.sidebar.header("Detection Controls")


def run_detection():
    if not source["input"].exists():
        st.error(f"Input file not found: {source['input'].name}")
        return False

    try:
        result = subprocess.run(
            [sys.executable, str(source["script"])],
            cwd=BASE,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        st.error(f"Detection could not finish: {exc}")
        return False

    if result.returncode != 0:
        st.error("Detection engine failed.")
        st.code(result.stderr or result.stdout or "No error details")
        return False

    st.session_state["last_detection_output"] = result.stdout
    return True


if st.sidebar.button("Run Detection", type="primary"):
    if run_detection():
        st.rerun()

if not source["input"].exists():
    st.info(
        f"{source['input'].name} does not exist yet. "
        "For Live mode, start capture first."
    )
    st.stop()

if not source["output"].exists():
    st.info("Findings file does not exist yet. Running detection...")
    if run_detection():
        st.rerun()
    st.stop()

try:
    df = pd.read_csv(source["output"])
except (OSError, pd.errors.ParserError) as exc:
    st.error(f"Could not read findings: {exc}")
    st.stop()

if not REQUIRED.issubset(df.columns):
    st.error("Findings CSV is missing required columns. Run detection again.")
    st.stop()

for column in [
    "new_domain", "high_query_volume", "suspicious_tld", "dga_like"
]:
    df[column] = (
        df[column].astype(str).str.strip().str.lower().eq("true")
    )

df["risk_score"] = pd.to_numeric(
    df["risk_score"], errors="coerce"
).fillna(0)

df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

st.caption(f"Selected source: **{source_name}**")

st.sidebar.header("Filters")
selected_risks = st.sidebar.multiselect(
    "Risk level", RISKS, default=RISKS
)
clients = sorted(df["client_id"].dropna().astype(str).unique().tolist())
selected_clients = st.sidebar.multiselect("Client", clients)
search = st.sidebar.text_input("Search domain").strip().lower()

filtered = df.copy()

if selected_risks:
    filtered = filtered[filtered["risk_level"].isin(selected_risks)]
else:
    filtered = filtered.iloc[0:0]

if selected_clients:
    filtered = filtered[filtered["client_id"].isin(selected_clients)]

if search:
    filtered = filtered[
        filtered["query_name"].astype(str).str.lower().str.contains(
            search, regex=False
        )
    ]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Queries Analyzed", len(filtered))
c2.metric("Unique Domains", filtered["query_name"].nunique())
c3.metric("High-Risk Findings", int((filtered["risk_level"] == "High").sum()))
c4.metric("New-Domain Flags", int(filtered["new_domain"].sum()))

left, right = st.columns(2)

with left:
    st.subheader("Risk Distribution")
    risk_counts = (
        filtered["risk_level"].value_counts()
        .reindex(RISKS, fill_value=0)
        .rename_axis("Risk").reset_index(name="Count")
    )
    st.plotly_chart(
        px.bar(risk_counts, x="Risk", y="Count", color="Risk"),
        use_container_width=True,
    )

with right:
    st.subheader("Detection Indicators")
    indicators = pd.DataFrame({
        "Indicator": [
            "New domain", "High query volume",
            "Suspicious TLD", "DGA-like name",
        ],
        "Count": [
            int(filtered["new_domain"].sum()),
            int(filtered["high_query_volume"].sum()),
            int(filtered["suspicious_tld"].sum()),
            int(filtered["dga_like"].sum()),
        ],
    })
    st.plotly_chart(
        px.bar(indicators, x="Indicator", y="Count"),
        use_container_width=True,
    )

st.subheader("DNS Findings")
st.dataframe(filtered, use_container_width=True, hide_index=True)

st.download_button(
    "Download filtered findings CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_dns_findings.csv",
    mime="text/csv",
)

st.caption(
    "Heuristic flags are investigation indicators, not proof of malicious activity."
)

st.divider()
st.subheader("🔎 Optional Domain Reputation Lookup")
st.warning(
    "A configured lookup may send the domain to VirusTotal. "
    "Only submit public, non-confidential domains you are authorized to investigate."
)

domain = st.text_input(
    "Public domain to investigate",
    placeholder="Enter a domain name",
)

if st.button("Check Domain Reputation"):
    if not domain.strip():
        st.error("Enter a domain first.")
    else:
        st.json(lookup_domain_reputation(domain))

st.caption(
    "Live mode analyzes captured metadata from live_dns_queries.csv. "
    "Capture must be started separately using live_dns_capture.py. "
    "Encrypted DNS such as DoH/DoT is not decoded by this capture method."
)
