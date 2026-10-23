import csv
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "sample_dns_queries.csv"
KNOWN_FILE = BASE_DIR / "known_domains.txt"
OUTPUT_FILE = BASE_DIR / "dns_findings.csv"

REQUIRED_COLUMNS = {
    "timestamp", "client_id", "query_name", "query_type"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "gq", "work", "country", "zip"
}

HIGH_VOLUME_THRESHOLD = 5
VOLUME_WINDOW_SECONDS = 60


def normalize_domain(domain):
    domain = str(domain).strip().lower().rstrip(".")
    if not domain or len(domain) > 253:
        return ""

    labels = domain.split(".")
    if len(labels) < 2:
        return ""

    if any(
        not label or len(label) > 63
        or label.startswith("-") or label.endswith("-")
        or not all(c.isalnum() or c == "-" for c in label)
        for label in labels
    ):
        return ""

    return domain


def load_known_domains():
    if not KNOWN_FILE.exists():
        return set()

    return {
        normalized
        for line in KNOWN_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and (normalized := normalize_domain(line))
    }


def entropy(text):
    if not text:
        return 0.0

    counts = Counter(text.lower())
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def looks_dga_like(domain):
    # Heuristic only: this does not prove malicious activity.
    label = domain.split(".")[0]
    digits = sum(character.isdigit() for character in label)
    digit_ratio = digits / len(label) if label else 0

    return (
        len(label) >= 12
        and (
            digit_ratio >= 0.25
            or entropy(label) >= 3.7
        )
    )


def parse_timestamp(value):
    try:
        return datetime.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None


def load_queries():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_FILE.name}"
        )

    with INPUT_FILE.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("Input CSV is empty.")

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError(
                "Missing CSV columns: " + ", ".join(sorted(missing))
            )

        queries = []

        for line_number, row in enumerate(reader, start=2):
            domain = normalize_domain(row.get("query_name", ""))
            timestamp = parse_timestamp(row.get("timestamp", ""))
            client = str(row.get("client_id", "")).strip()
            query_type = str(row.get("query_type", "")).strip()

            if not domain or timestamp is None or not client or not query_type:
                print(f"Skipping invalid record at CSV line {line_number}")
                continue

            queries.append({
                "timestamp": timestamp,
                "client_id": client,
                "query_name": domain,
                "query_type": query_type,
            })

    queries.sort(key=lambda item: item["timestamp"])
    return queries


def detect(queries, known_domains):
    seen_domains = set(known_domains)
    prior_queries = defaultdict(list)
    findings = []

    for query in queries:
        timestamp = query["timestamp"]
        client = query["client_id"]
        domain = query["query_name"]
        tld = domain.rsplit(".", 1)[-1]

        is_new = domain not in seen_domains
        seen_domains.add(domain)

        key = (client, domain)
        cutoff = timestamp - timedelta(
            seconds=VOLUME_WINDOW_SECONDS
        )

        recent = [
            previous_time
            for previous_time in prior_queries[key]
            if cutoff <= previous_time <= timestamp
        ]
        recent.append(timestamp)
        prior_queries[key] = recent

        high_volume = len(recent) >= HIGH_VOLUME_THRESHOLD
        suspicious_tld = tld in SUSPICIOUS_TLDS
        dga_like = looks_dga_like(domain)

        reasons = []
        score = 0

        if is_new:
            reasons.append("First seen against the known-domain baseline")
            score += 20

        if high_volume:
            reasons.append(
                f"High query volume: {len(recent)} queries in "
                f"{VOLUME_WINDOW_SECONDS}s"
            )
            score += 30

        if suspicious_tld:
            reasons.append(f"Configured suspicious TLD: .{tld}")
            score += 20

        if dga_like:
            reasons.append("DGA-like domain-name heuristic")
            score += 35

        score = min(score, 100)

        if score >= 70:
            risk = "High"
        elif score >= 40:
            risk = "Medium"
        elif score > 0:
            risk = "Low"
        else:
            risk = "Informational"

        findings.append({
            "timestamp": timestamp.isoformat(),
            "client_id": client,
            "query_name": domain,
            "query_type": query["query_type"],
            "new_domain": is_new,
            "high_query_volume": high_volume,
            "suspicious_tld": suspicious_tld,
            "dga_like": dga_like,
            "risk_score": score,
            "risk_level": risk,
            "reasons": "; ".join(reasons) if reasons else "No heuristic triggered",
        })

    return findings


def main():
    try:
        queries = load_queries()
        known_domains = load_known_domains()
        findings = detect(queries, known_domains)

        columns = [
            "timestamp", "client_id", "query_name", "query_type",
            "new_domain", "high_query_volume", "suspicious_tld",
            "dga_like", "risk_score", "risk_level", "reasons",
        ]

        with OUTPUT_FILE.open(
            "w", encoding="utf-8", newline=""
        ) as file:
            writer = csv.DictWriter(file, fieldnames=columns)
            writer.writeheader()
            writer.writerows(findings)

        print("DNS Threat Detection complete")
        print("------------------------------")
        print(f"Queries analyzed: {len(queries)}")
        print(f"Output file: {OUTPUT_FILE.name}")
        print(f"Known-domain baseline entries: {len(known_domains)}")
        print("\nRisk summary:")

        for level in ("High", "Medium", "Low", "Informational"):
            count = sum(
                finding["risk_level"] == level for finding in findings
            )
            print(f"  {level}: {count}")

        print(
            "\nWarning: Heuristic flags are investigation indicators, "
            "not proof of malicious activity."
        )

    except (OSError, ValueError) as error:
        raise SystemExit(f"Detection failed: {error}") from error


if __name__ == "__main__":
    main()
