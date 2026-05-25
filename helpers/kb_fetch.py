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
    except Exception:
        pattern = (
            Path(__file__).resolve().parent / "data" / f"{stix_id}.json"
        ).read_text()
        logger.info("Using local attack-pattern fallback")
        return json.loads(pattern)


def get_all_pages(session, url):
    """Helper function to fetch all pages of a paginated CTI Butler endpoint."""
    retval = []
    params = {'page': 1}
    while url:
        try:
            resp = session.get(url, timeout=30, params=params)
            resp.raise_for_status()
            data = resp.json()
            objects = data.get("objects", [])
            retval.extend(objects)
            params['page'] += 1
            if len(objects) < data['page_size'] or len(retval) >= data['total_results_count']:
                break  # No more pages
        except Exception as e:
            raise RemoteFetchError(f"Failed to fetch page at `{url}`: {e}") from e
    return retval


@lru_cache(maxsize=1)
def fetch_countries():
    """Fetch the list of country names from CTI Butler. Returns alpha-2 mapped to stix objects."""
    session, ctibutler_base = ctibutler_session()
    url = f"{ctibutler_base}/v1/location/objects/?location_type=country&sort=name_ascending"
    try:
        return {obj["country"]: obj for obj in get_all_pages(session, url)}
    except Exception as e:
        raise RemoteFetchError(f"Failed to fetch countries from CTI Butler: {e}") from e
