import argparse
import csv
from datetime import datetime
from pathlib import Path

from scapy.all import DNS, DNSQR, IP, IPv6, sniff

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = BASE_DIR / "live_dns_queries.csv"

COLUMNS = [
    "timestamp",
    "client_id",
    "query_name",
    "query_type",
]

QTYPE_NAMES = {
    1: "A",
    28: "AAAA",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    2: "NS",
    12: "PTR",
    33: "SRV",
}


def prepare_csv():
    if not OUTPUT_FILE.exists() or OUTPUT_FILE.stat().st_size == 0:
        with OUTPUT_FILE.open(
            "w", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=COLUMNS)
            writer.writeheader()


def handle_packet(packet):
    if not packet.haslayer(DNS):
        return

    dns = packet[DNS]

    # Queries only, not DNS responses.
    if dns.qr != 0 or not packet.haslayer(DNSQR):
        return

    if packet.haslayer(IP):
        client_ip = packet[IP].src
    elif packet.haslayer(IPv6):
        client_ip = packet[IPv6].src
    else:
        return

    try:
        query_name = packet[DNSQR].qname.decode(
            "utf-8", errors="replace"
        ).rstrip(".").lower()

        query_type_number = int(packet[DNSQR].qtype)
        query_type = QTYPE_NAMES.get(
            query_type_number, f"TYPE{query_type_number}"
        )

        if not query_name:
            return

        event = {
            "timestamp": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            "client_id": client_ip,
            "query_name": query_name,
            "query_type": query_type,
        }

        with OUTPUT_FILE.open(
            "a", newline="", encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(file, fieldnames=COLUMNS)
            writer.writerow(event)
            file.flush()

        print(
            f"[DNS] {event['timestamp']} | "
            f"{client_ip} | {query_name} | {query_type}"
        )

    except (AttributeError, TypeError, ValueError) as error:
        print(f"[WARN] Could not parse DNS query: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="Capture DNS query metadata on an authorized interface."
    )
    parser.add_argument(
        "--interface",
        required=True,
        help="Network interface to monitor, e.g. eth0 or enp0s3",
    )
    args = parser.parse_args()

    prepare_csv()

    print(f"Monitoring interface: {args.interface}")
    print(f"DNS query log: {OUTPUT_FILE}")
    print("Capturing DNS metadata only. Press Ctrl+C to stop.")

    try:
        sniff(
            iface=args.interface,
            filter="udp port 53 or tcp port 53",
            prn=handle_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nDNS capture stopped.")
    except (OSError, ValueError) as error:
        raise SystemExit(
            f"Capture failed: {error}. Check interface and permissions."
        ) from error


if __name__ == "__main__":
    main()
