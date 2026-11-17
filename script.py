#!/usr/bin/env python3
"""
VirusTotal API v3 Hash Enrichment Module
Enriches file hashes (MD5, SHA-1, SHA-256) from security alerts with deterministic
rate-limit (HTTP 429) handling and structured verdict classification.
"""

import logging
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional
import requests

# Configure structured logging for SIEM/SOAR ingestion
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("vt_enricher")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


@dataclass
class EnrichmentResult:
    hash_value: str
    verdict: str
    malicious_count: int = 0
    suspicious_count: int = 0
    total_engines: int = 0
    threat_label: Optional[str] = None
    file_name: Optional[str] = None
    vt_link: Optional[str] = None
    error: Optional[str] = None


class VirusTotalClient:
    def __init__(self, api_key: str, max_retries: int = 3, default_rate_sleep: int = 60):
        if not api_key:
            raise ValueError("VT_API_KEY is missing. Set it via environment variables.")
        self.max_retries = max_retries
        self.default_rate_sleep = default_rate_sleep
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "SecOps-Alert-Enricher/1.0"
        })

    @staticmethod
    def is_valid_hash(file_hash: str) -> bool:
        return bool(HASH_REGEX.match(file_hash.strip()))

    @staticmethod
    def _calculate_verdict(stats: dict, reputation: int) -> str:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3 or (malicious >= 1 and reputation < -10):
            return "MALICIOUS"
        if malicious in (1, 2) or suspicious >= 2:
            return "SUSPICIOUS"
        return "CLEAN"

    def enrich_hash(self, file_hash: str) -> EnrichmentResult:
        clean_hash = file_hash.strip().lower()

        if not self.is_valid_hash(clean_hash):
            logger.error(f"Invalid hash format rejected locally: {clean_hash}")
            return EnrichmentResult(hash_value=clean_hash, verdict="ERROR", error="Invalid hash format")

        url = f"{VT_BASE_URL}/files/{clean_hash}"

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.get(url, timeout=10)

                # Case 1: Hash found
                if response.status_code == 200:
                    payload = response.json().get("data", {})
                    attrs = payload.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    reputation = attrs.get("reputation", 0)

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(
                        stats.get(k, 0)
                        for k in ("malicious", "suspicious", "undetected", "harmless")
                    )

                    threat_class = attrs.get("popular_threat_classification", {})
                    threat_label = threat_class.get("suggested_threat_label")

                    verdict = self._calculate_verdict(stats, reputation)
                    return EnrichmentResult(
                        hash_value=clean_hash,
                        verdict=verdict,
                        malicious_count=malicious,
                        suspicious_count=suspicious,
                        total_engines=total,
                        threat_label=threat_label,
                        file_name=attrs.get("meaningful_name"),
                        vt_link=f"https://www.virustotal.com/gui/file/{clean_hash}"
                    )

                # Case 2: Hash not present in VirusTotal database
                if response.status_code == 404:
                    logger.info(f"Hash not found in VT (404): {clean_hash}")
                    return EnrichmentResult(
                        hash_value=clean_hash,
                        verdict="UNKNOWN",
                        error="Hash not observed by VirusTotal"
                    )

                # Case 3: Rate limit exceeded (HTTP 429)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    sleep_seconds = int(retry_after) if (retry_after and retry_after.isdigit()) else self.default_rate_sleep
                    logger.warning(
                        f"Rate limit (429) hit on attempt {attempt}/{self.max_retries}. "
                        f"Pausing for {sleep_seconds}s..."
                    )
                    time.sleep(sleep_seconds)
                    continue

                # Case 4: Authentication/Authorization failure (Non-retryable)
                if response.status_code in (401, 403):
                    logger.critical(f"Authentication error ({response.status_code}). Check VT_API_KEY.")
                    return EnrichmentResult(
                        hash_value=clean_hash,
                        verdict="ERROR",
                        error=f"HTTP {response.status_code}: Unauthorized/Forbidden"
                    )

                # Case 5: Transient 5xx server errors
                if response.status_code >= 500:
                    backoff = 2 ** attempt
                    logger.warning(f"VT server error ({response.status_code}). Retrying in {backoff}s...")
                    time.sleep(backoff)
                    continue

                # Unhandled status code
                return EnrichmentResult(
                    hash_value=clean_hash,
                    verdict="ERROR",
                    error=f"Unexpected HTTP {response.status_code}"
                )

            except requests.RequestException as exc:
                backoff = 2 ** attempt
                logger.warning(f"Network exception ({exc}). Retrying in {backoff}s...")
                time.sleep(backoff)

        return EnrichmentResult(
            hash_value=clean_hash,
            verdict="ERROR",
            error="Max retries exceeded due to rate limiting or network failure"
        )


if __name__ == "__main__":
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        raise SystemExit("VT_API_KEY is not set")
    client = VirusTotalClient(api_key=api_key)
    
    # Simulated alert hashes (EICAR test hash + non-existent hash)
    alert_hashes = [
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR
        "44d88612fea8a8f36de82e1278abb02f",                                  # EICAR MD5
        "3395856ce81f2b7382dee72602f798b642f14140",                          # EICAR SHA1
        "1111111111111111111111111111111111111111111111111111111111111111",  # 404 test 1
        "2222222222222222222222222222222222222222222222222222222222222222",  # 404 test 2 (Triggers 429)
    ]

    for item in alert_hashes:
        result = client.enrich_hash(item)
        print(asdict(result))