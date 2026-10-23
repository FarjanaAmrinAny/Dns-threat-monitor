import csv
from pathlib import Path

from detect_dns import (
    detect,
    load_known_domains,
    normalize_domain,
    parse_timestamp,
)

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "live_dns_queries.csv"
OUTPUT_FILE = BASE_DIR / "live_dns_findings.csv"

COLUMNS = [
    "timestamp",
    "client_id",
    "query_name",
    "query_type",
    "new_domain",
    "high_query_volume",
    "suspicious_tld",
    "dga_like",
    "risk_score",
    "risk_level",
    "reasons",
]


def main():
    if not INPUT_FILE.exists():
        raise SystemExit("Live DNS CSV not found. Start live capture first.")

    queries = []
    skipped = 0

    with INPUT_FILE.open(
        "r", encoding="utf-8", newline=""
    ) as file:
        reader = csv.DictReader(file)

        required = {
            "timestamp", "client_id", "query_name", "query_type"
        }

        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise SystemExit("Live DNS CSV has missing required columns.")

        for row in reader:
            domain = normalize_domain(row.get("query_name", ""))
            timestamp = parse_timestamp(row.get("timestamp", ""))
            client_id = str(row.get("client_id", "")).strip()
            query_type = str(row.get("query_type", "")).strip()

            if not domain or timestamp is None or not client_id or not query_type:
                skipped += 1
                continue

            queries.append({
                "timestamp": timestamp,
                "client_id": client_id,
                "query_name": domain,
                "query_type": query_type,
            })

    queries.sort(key=lambda item: item["timestamp"])
    findings = detect(queries, load_known_domains())

    with OUTPUT_FILE.open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(findings)

    print("Live DNS analysis complete")
    print(f"Live queries analyzed: {len(queries)}")
    print(f"Invalid records skipped: {skipped}")
    print(f"Findings saved to: {OUTPUT_FILE.name}")

    for level in ("High", "Medium", "Low", "Informational"):
        count = sum(item["risk_level"] == level for item in findings)
        print(f"{level}: {count}")

    print("Note: Heuristic flags require investigation; they are not proof of malicious activity.")


if __name__ == "__main__":
    main()


