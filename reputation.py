import os
import re
import requests

VT_API_URL = "https://www.virustotal.com/api/v3/domains/{}"


def validate_public_domain(domain):
    domain = str(domain).strip().lower().rstrip(".")

    if not domain or len(domain) > 253:
        return None

    labels = domain.split(".")
    if len(labels) < 2:
        return None

    pattern = re.compile(
        r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )

    if not all(pattern.fullmatch(label) for label in labels):
        return None

    reserved_domains = {
        "example.com",
        "example.org",
        "example.net",
    }

    reserved_suffixes = (
        ".example.com",
        ".example.org",
        ".example.net",
    )

    if (
        domain in reserved_domains
        or domain.endswith(reserved_suffixes)
        or labels[-1] in {
            "local", "localhost", "internal", "test", "example"
        }
    ):
        return None

    return domain


def lookup_domain_reputation(domain):
    original_domain = str(domain).strip()
    domain = validate_public_domain(domain)

    if not domain:
        return {
            "domain": original_domain,
            "reputation_status": "SKIPPED",
            "reason": "Invalid, reserved, or test domain",
        }

    api_key = os.getenv("DNS_REPUTATION_API_KEY")

    if not api_key:
        return {
            "domain": domain,
            "reputation_status": "NOT_CONFIGURED",
            "reason": "API key is not configured",
        }

    try:
        response = requests.get(
            VT_API_URL.format(domain),
            headers={"x-apikey": api_key},
            timeout=10,
        )

        if response.status_code == 404:
            return {
                "domain": domain,
                "reputation_status": "NOT_FOUND",
                "reason": "No existing provider report",
            }

        if response.status_code == 429:
            return {
                "domain": domain,
                "reputation_status": "RATE_LIMITED",
                "reason": "Provider rate limit reached",
            }

        response.raise_for_status()
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        if malicious:
            status = "PROVIDER_FLAGGED"
        elif suspicious:
            status = "PROVIDER_SUSPICIOUS"
        else:
            status = "NO_MALICIOUS_VERDICT_REPORTED"

        return {
            "domain": domain,
            "reputation_status": status,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "reason": "Existing provider report",
        }

    except requests.Timeout:
        return {
            "domain": domain,
            "reputation_status": "TIMEOUT",
            "reason": "Lookup timed out",
        }

    except requests.RequestException as exc:
        return {
            "domain": domain,
            "reputation_status": "ERROR",
            "reason": type(exc).__name__,
        }

    except (TypeError, ValueError):
        return {
            "domain": domain,
            "reputation_status": "ERROR",
            "reason": "Unexpected provider response",
        }

