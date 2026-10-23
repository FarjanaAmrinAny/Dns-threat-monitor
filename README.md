# DNS Threat Monitor

A Python-based SOC Analyst portfolio project for analyzing DNS query
metadata, detecting suspicious patterns, and prioritizing events for
investigation.

## Features

- Detect domains that are new relative to a known-domain baseline.
- Identify high DNS query volume from the same client to the same domain.
- Flag configured suspicious top-level domains (TLDs).
- Apply a heuristic to identify potentially DGA-like domain names.
- Assign risk scores and explain detection indicators.
- Capture visible DNS query metadata from an authorized network interface.
- Store DNS query timestamps, client IPs, domain names, and query types.
- Analyze captured DNS records with the detection engine.
- Visualize findings using an interactive Streamlit dashboard.
- Filter findings and export results to CSV.
- Provide optional VirusTotal domain-reputation lookup.

## Technology Stack

- Python
- Scapy
- Pandas
- Streamlit
- Plotly
- Requests
- CSV
- unittest

## Project Structure

```text
dns-threat-monitor/
├── dashboard.py
├── detect_dns.py
├── analyze_live_dns.py
├── live_dns_capture.py
├── reputation.py
├── sample_dns_queries.csv
├── known_domains.txt
├── requirements.txt
├── README.md
└── tests/
    └── test_detect_dns.py
