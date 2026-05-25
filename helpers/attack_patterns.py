import json
import logging
import os
from functools import lru_cache
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


def _fetch_attack_pattern_from_ctibutler(stix_id):
    """Fetch an ATT&CK Enterprise attack-pattern object from CTI Butler."""
    ctibutler_base = os.getenv("CTIBUTLER_BASE_URL", "").rstrip("/")
    ctibutler_key = os.getenv("CTIBUTLER_API_KEY", "")

    if not ctibutler_base:
        logger.warning("CTIBUTLER_BASE_URL not set; skipping attack-pattern import")
        raise Exception("CTIBUTLER_BASE_URL not set")

    url = f"{ctibutler_base}/v1/attack-enterprise/objects/{stix_id}/"
    headers = {}
    if ctibutler_key:
        headers["API-KEY"] = ctibutler_key

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if "objects" in data:
            return data["objects"][0]
        return data
    except Exception as e:
        logger.warning(f"Failed to fetch attack-pattern from CTI Butler: {e}")
        raise


@lru_cache(maxsize=16)
def fetch_attack_pattern(stix_id):
    try:
        return _fetch_attack_pattern_from_ctibutler(stix_id)
    except Exception:
        pattern = (
            Path(__file__).resolve().parent / "data" / f"{stix_id}.json"
        ).read_text()
        logger.info("Using local attack-pattern fallback")
        return json.loads(pattern)
