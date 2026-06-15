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


def vulmatch_session():
    """Create a requests session for CTI Butler with appropriate headers."""
    session = requests.Session()
    vulmatch_key = os.getenv("VULMATCH_API_KEY", "")
    base_url = os.getenv("VULMATCH_BASE_URL", "").rstrip("/")
    if not base_url:
        logger.warning("VULMATCH_BASE_URL not set; skipping attack-pattern import")
        raise Exception("VULMATCH_BASE_URL not set")
    if vulmatch_key:
        session.headers.update({"API-KEY": vulmatch_key})
    else:
        logger.warning("VULMATCH_API_KEY not set; Vulmatch requests may fail")
    return session, base_url    

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


def _fetch_kb_object_from_ctibutler(stix_id, knowledge_base="attack-enterprise"):
    """Fetch an ATT&CK Enterprise attack-pattern object from CTI Butler."""
    session, ctibutler_base = ctibutler_session()
    if not ctibutler_base:
        logger.warning("CTIBUTLER_BASE_URL not set; skipping attack-pattern import")
        raise Exception("CTIBUTLER_BASE_URL not set")
    url = f"{ctibutler_base}/v1/{knowledge_base}/objects/{stix_id}/"
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


def fetch_enterprise_attack_object(stix_id):
    return fetch_object_from_kb(stix_id, knowledge_base="attack-enterprise")
    

@lru_cache(maxsize=1280)
def fetch_object_from_kb(stix_id, knowledge_base):
    try:
        return _fetch_kb_object_from_ctibutler(stix_id, knowledge_base=knowledge_base)
    except Exception as e:
        logger.warning("Using local attack-pattern fallback: %s", str(e))
        p = Path(__file__).resolve().parent / "data" / f"{stix_id}.json"
        if not p.exists():
            logger.error(f"Local fallback file {p} does not exist. Cannot fetch {knowledge_base} object {stix_id}.")
            raise RemoteFetchError(f"Failed to fetch {stix_id} from CTI Butler and no local fallback available.")
        pattern = p.read_text()
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


def fetch_vulnerabilities(cve_ids):
    assert len(cve_ids) <= 50, "can't fetch more than 50 items at once"
    session, base_url = vulmatch_session()
    url = f"{base_url}/v1/cve/objects/?cve_id="+','.join(cve_ids)
    try:
        return {obj["name"]: obj for obj in get_all_pages(session, url)}
    except Exception as e:
        raise RemoteFetchError(f"Failed to fetch countries from Vulmatch: {e}") from e