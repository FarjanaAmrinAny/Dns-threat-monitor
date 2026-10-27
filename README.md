# DNS Threat Monitor

A Python-based DNS monitoring and threat-analysis lab project.
DNS Threat Monitor is an educational cybersecurity project designed to analyze DNS query records, flag potentially suspicious patterns, and visualize findings through a Streamlit dashboard.
The project combines rule-based detection, local DNS metadata capture, CSV-based analysis, and dashboard visualization to explore how DNS activity can support network security investigations.

Project status: Educational lab prototype. Detection results are indicators for further investigation, not definitive proof of malicious activity.

Overview

DNS is essential to everyday internet communication, but DNS activity can also provide useful signals during a security investigation. Unusual query frequency, newly observed domains, and suspicious domain-name patterns may deserve closer inspection.

This project explores these ideas using Python and a controlled Kali Linux lab environment.

The goal is to build practical experience with DNS traffic, detection logic, data analysis, and security monitoring—not to claim detection of every type of DNS-based attack.

Key Features

New-domain detection: Flags domains that are absent from a configured known-domain baseline.

Query-frequency analysis: Identifies repeated queries that meet a configurable frequency threshold.

Suspicious TLD checks: Flags domains matching a configurable list of top-level domains.

DGA-like heuristics: Examines basic domain-name characteristics that may warrant further investigation.

Rule-based risk scoring: Assigns risk levels and records reasons for findings.

DNS metadata capture: Uses Scapy to capture conventional DNS traffic in an authorized lab environment.

CSV-based analysis: Stores query records and findings for review.

Streamlit dashboard: Presents query statistics, domain counts, detection indicators, and risk distribution.

Optional reputation lookup: Includes code for VirusTotal domain-reputation lookups when correctly configured.

Architecture

The project follows a simple analysis workflow:

Obtain DNS records from a sample dataset or local lab capture.

Analyze query metadata using Python detection rules.

Compare domains against the known-domain baseline.

Apply frequency, TLD, and DGA-like heuristic checks.

Generate findings with risk levels and matched-rule explanations.

Review the results through CSV outputs and the Streamlit dashboard.

Technology Stack

Technology

Purpose

Python

Detection and analysis logic

Scapy

DNS traffic metadata capture

Pandas

Data processing and analysis

Streamlit

Interactive dashboard

Plotly

Data visualization

Requests

HTTP requests for reputation lookups

Pytest

Automated testing
<img width="1918" height="853" alt="DNS-1" src="https://github.com/user-attachments/assets/fa6b0688-108e-4a45-aaae-4f6e394a5064" />
<img width="1920" height="858" alt="DNS-2" src="https://github.com/user-attachments/assets/74cb2bf6-a47d-4cf1-9ac1-ec7ba74ad124" />
<img width="1919" height="854" alt="DNS-3" src="https://github.com/user-attachments/assets/1798c523-0ce0-4207-bf98-06d5e3ac3996" />
<img width="1917" height="861" alt="DNS-4" src="https://github.com/user-attachments/assets/c24cb416-0973-47db-b6d7-39e5852c0e97" />


Project Structure

dns-threat-monitor/
├── dashboard.py
├── detect_dns.py
├── live_dns_capture.py
├── analyze_live_dns.py
├── reputation.py
├── sample_dns_queries.csv
├── known_domains.txt
├── tests/
│   └── test_detect_dns.py
├── requirements.txt
├── .gitignore
└── README.md


The structure above describes the main project files; additional files may exist in the repository.

Installation

1. Clone the repository

git clone https://github.com/FarjanaAmrinAny/Dns-threat-monitor.git
cd Dns-threat-monitor

2. Create a virtual environment

python3 -m venv .venv
source .venv/bin/activate

3. Install dependencies

python -m pip install --upgrade pip
pip install -r requirements.txt

Usage

Run the dashboard

streamlit run dashboard.py

Open the local URL displayed by Streamlit in your browser.

Run sample-data detection

python detect_dns.py

The detector uses the configured input data and detection rules. Check the script configuration and terminal output to confirm the input and output file paths used by your version.

Capture DNS metadata in a lab

On a network interface you own or are authorized to monitor, run:

sudo python3 live_dns_capture.py

Follow the script's prompts or configuration for interface selection and capture duration, if applicable.

Analyze captured DNS records

python3 analyze_live_dns.py

Check the script output and generated CSV files to review the analysis results.

Note: The capture and analysis commands depend on the scripts' current configuration. Confirm the actual output paths and the complete live-capture-to-dashboard workflow before relying on live results.

Testing

Run the automated tests with:

pytest -q

Tests help verify the detection logic against the included test cases. A passing test suite does not establish that every detection rule is effective against real-world threats.

VirusTotal Integration

The project includes optional code for domain-reputation lookups using VirusTotal.

To use this functionality:

Obtain an API key from VirusTotal.

Configure it using the method expected by reputation.py.

Keep the key out of source code, screenshots, commits, and public files.

Test the lookup separately and confirm the API response before describing it as operational.

Reputation results should be treated as supporting context, not as a standalone verdict.

Limitations

This project is a learning prototype and has important limitations:

Detection relies on heuristics and configured rules; false positives are possible.

A newly observed domain is not necessarily malicious.

DGA-like patterns do not independently prove that a domain is malicious.

The project does not currently implement a dedicated, validated DNS-tunneling detector.

The live capture approach does not directly decode DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) traffic.

VirusTotal integration and the complete live-capture-to-dashboard workflow require validation in the target environment.

The tool has not been established as a production-ready intrusion detection system.

Security and Responsible Use

Use live capture only on networks and systems you own or have explicit permission to monitor.

Avoid publishing sensitive DNS logs, internal hostnames, private IP details, API keys, or other identifying network information. Review generated CSV files before uploading them to a public repository.

Future Improvements

Potential improvements include:

More robust baseline learning and configurable detection thresholds.

Better domain-name feature analysis and reduced false positives.

Additional validation against benign and suspicious DNS datasets.

More complete integration testing for live capture and dashboard workflows.

Validated domain-reputation enrichment.

Clearer detection explanations and investigation guidance.

Threat Research and Further Reading

This project was developed as a learning exercise informed by publicly available cybersecurity research.

Fortinet FortiGuard Labs — Inside a TrickBot Variant Using DNS Tunneling for C2

Microsoft Security Blog — CaptiveCrunch: Midnight Blizzard Targets Travelers Worldwide for Malware Delivery and Credential Theft

These reports provide threat context and motivation for exploring DNS monitoring. They do not imply that this project detects the specific malware or campaigns described in those reports.
