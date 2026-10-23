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

<img width="1918" height="853" alt="DNS-1" src="https://github.com/user-attachments/assets/fa6b0688-108e-4a45-aaae-4f6e394a5064" />
<img width="1920" height="858" alt="DNS-2" src="https://github.com/user-attachments/assets/74cb2bf6-a47d-4cf1-9ac1-ec7ba74ad124" />
<img width="1919" height="854" alt="DNS-3" src="https://github.com/user-attachments/assets/1798c523-0ce0-4207-bf98-06d5e3ac3996" />
<img width="1917" height="861" alt="DNS-4" src="https://github.com/user-attachments/assets/c24cb416-0973-47db-b6d7-39e5852c0e97" />


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
