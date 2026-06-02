import json
import logging
import os
from functools import lru_cache
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class RemoteFetchError(Exception):
    """Custom exception for remote fetch failures."""
    pass

def ctibutler_session():
    """Create a requests session for CTI Butler with appropriate headers."""
    session = requests.Session()
    ctibutler_key = os.getenv("CTIBUTLER_API_KEY", "")
    base_url = os.getenv("CTIBUTLER_BASE_URL", "").rstrip("/")
    if not base_url:
        logger.warning("CTIBUTLER_BASE_URL not set; skipping attack-pattern import")
        raise Exception("CTIBUTLER_BASE_URL not set")
    if ctibutler_key:
        session.headers.update({"API-KEY": ctibutler_key})
    else:
        logger.warning("CTIBUTLER_API_KEY not set; CTI Butler requests may fail")
    return session, base_url


def _fetch_attack_pattern_from_ctibutler(stix_id):
    """Fetch an ATT&CK Enterprise attack-pattern object from CTI Butler."""
    session, ctibutler_base = ctibutler_session()
    if not ctibutler_base:
        logger.warning("CTIBUTLER_BASE_URL not set; skipping attack-pattern import")
        raise Exception("CTIBUTLER_BASE_URL not set")
    url = f"{ctibutler_base}/v1/attack-enterprise/objects/{stix_id}/"
    try:
        resp = session.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if "objects" in data:
            return data["objects"][0]
        return data
    except Exception as e:
        logger.warning(f"Failed to fetch attack-pattern from CTI Butler: {e}")
        raise


@lru_cache(maxsize=1280)
def fetch_enterprise_attack_object(stix_id):
    try:
        return _fetch_attack_pattern_from_ctibutler(stix_id)
    except Exception as e:
        logger.warning("Using local attack-pattern fallback: %s", str(e))
        pattern = (
            Path(__file__).resolve().parent / "data" / f"{stix_id}.json"
        ).read_text()
        return json.loads(pattern)
    