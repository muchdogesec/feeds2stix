#!/usr/bin/env python3

import argparse
from functools import lru_cache
import io
import json
import logging
import os
from pathlib import Path
import sys
from collections import defaultdict
from datetime import UTC, datetime
import gzip

import requests
from stix2 import URL, AutonomousSystem, Indicator, IPv4Address
from stix2.patterns import StringConstant

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.utils import (
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    make_relationship,
    save_bundle_to_file,
    setup_output_directory,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

FEED_URL = "http://data.phishtank.com/data/online-valid.json.gz"
API_FEED_URL = "http://data.phishtank.com/data/API_KEY/online-valid.json.gz"
OUTPUT_DIR = "outputs/phishtank"
ATTACK_PATTERN_ID = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]


def create_phishtank_identity():
    return create_identity_object(
        name="PhishTank",
        description=(
            "PhishTank is a collaborative clearing house for data and information about phishing on the"
            " Internet. Also, PhishTank provides an open API for developers and researchers to integrate"
            " anti-phishing data into their applications at no charge."
        ),
        identity_class="system",
        contact_info="https://www.phishtank.com/",
    )


def create_phishtank_marking_definition():
    return create_marking_definition_object(f"Origin: {FEED_URL}")


def fetch_phishtank_data():
    headers = {"User-Agent": "feeds2stix/1.0"}
    url = FEED_URL
    if os.getenv("PHISHTANK_API_KEY"):
        url = API_FEED_URL.replace("API_KEY", os.getenv("PHISHTANK_API_KEY"))
    logger.info(f"Fetching PhishTank data from {url}")
    response = requests.get(url, headers=headers, timeout=120)
    response.raise_for_status()
    gzip_content = response.content
    gzip_file = gzip.GzipFile(fileobj=io.BytesIO(gzip_content))
    data = json.load(gzip_file)
    return data


def _fetch_attack_pattern_from_ctibutler():
    """Fetch the T1566 Phishing attack-pattern from CTI Butler."""
    ctibutler_base = os.getenv("CTIBUTLER_BASE_URL", "").rstrip("/")
    ctibutler_key = os.getenv("CTIBUTLER_API_KEY", "")

    if not ctibutler_base:
        logger.warning("CTIBUTLER_BASE_URL not set; skipping attack-pattern import")
        raise Exception("CTIBUTLER_BASE_URL not set")

    url = f"{ctibutler_base}/v1/attack-enterprise/objects/{ATTACK_PATTERN_ID}/"
    headers = {}
    if ctibutler_key:
        headers["API-KEY"] = ctibutler_key

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if "objects" in data:
            return data["objects"][0]
        else:
            return data
    except Exception as e:
        logger.warning(f"Failed to fetch attack-pattern from CTI Butler: {e}")
        raise


@lru_cache(maxsize=1)
def fetch_attack_pattern():
    try:
        return _fetch_attack_pattern_from_ctibutler()
    except Exception:
        pattern = Path(
            os.path.join(
                os.path.dirname(__file__),
                "data",
                "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b.json",
            )
        ).read_text()
        logger.info("Using local attack-pattern fallback")
        return json.loads(pattern)


def parse_time(ts_str):
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def create_stix_objects_for_phish(entry, identity_id, marking_id):
    """Create STIX objects for a single phish entry."""
    objects = []

    url_value = entry["url"]
    phish_id = entry["phish_id"]
    submission_time = parse_time(entry["submission_time"])
    verification_time = submission_time
    if entry.get("verification_time"):
        verification_time = parse_time(entry["verification_time"])

    external_refs = [
        {
            "source_name": "phishtank",
            "url": f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}&frame=details",
            "external_id": str(phish_id),
        }
    ]

    object_marking_refs = OBJECT_MARKING_REFS_BASE + [marking_id]

    # URL observable
    url_obj = URL(value=url_value)
    objects.append(url_obj)

    # Indicator
    indicator_name = f"URL: {url_value}"
    indicator_id = f"indicator--{generate_uuid5(indicator_name, marking_id)}"
    confidence = 100 if entry['verified'] == 'yes' else None
    revoked = entry['online'] != 'yes'
    indicator = Indicator(
        id=indicator_id,
        created_by_ref=identity_id,
        created=submission_time,
        modified=verification_time,
        valid_from=submission_time,
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=f"[url:value={StringConstant(url_value)}]",
        pattern_type="stix",
        object_marking_refs=object_marking_refs,
        external_references=external_refs,
        confidence=confidence,
        revoked=revoked,
    )
    objects.append(indicator)

    # Indicator → URL relationship (indicates)
    objects.append(
        make_relationship(
            source_ref=indicator_id,
            target_ref=url_obj.id,
            relationship_type="indicates",
            created_by_ref=identity_id,
            created=submission_time,
            modified=verification_time,
            marking_refs=object_marking_refs,
            external_references=external_refs,
            description="",
        )
    )

    # Indicator → ATT&CK T1566 Phishing relationship (indicates)
    objects.append(
        make_relationship(
            source_ref=indicator_id,
            target_ref=ATTACK_PATTERN_ID,
            relationship_type="indicates",
            created_by_ref=identity_id,
            created=submission_time,
            modified=verification_time,
            marking_refs=object_marking_refs,
            external_references=external_refs,
            description=f"{url_value} is known to be used for Phishing (T1566)",
        )
    )

    # Details: IPv4 and ASN
    for detail in entry.get("details", []):
        ip_address = detail.get("ip_address")
        if not ip_address:
            continue

        ipv4_obj = IPv4Address(value=ip_address)
        objects.append(ipv4_obj)

        # URL → IPv4 relationship (related-to)
        objects.append(
            make_relationship(
                source_ref=url_obj.id,
                target_ref=ipv4_obj.id,
                relationship_type="related-to",
                created_by_ref=identity_id,
                created=submission_time,
                modified=verification_time,
                marking_refs=object_marking_refs,
            )
        )

        announcing_network = detail.get("announcing_network")
        if announcing_network:
            asn, _, _ = announcing_network.partition(" ")
            asn_kwargs = {"number": int(asn)}
            if detail.get("rir"):
                asn_kwargs["rir"] = detail["rir"]
            asn_obj = AutonomousSystem(**asn_kwargs)
            objects.append(asn_obj)

            # IPv4 → ASN relationship (related-to)
            objects.append(
                make_relationship(
                    source_ref=ipv4_obj.id,
                    target_ref=asn_obj.id,
                    relationship_type="related-to",
                    created_by_ref=identity_id,
                    created=submission_time,
                    modified=verification_time,
                    marking_refs=object_marking_refs,
                )
            )

    return objects


def group_entries_to_max_N_elements(entries, max_per_group=500):
    groups = defaultdict(list)
    for i, entry in enumerate(entries):
        group_id = (i // max_per_group) + 1
        key = f'{group_id:03d}'
        groups[key].append(entry)
    return groups


def process_entries_for_date(
    entries, phishtank_identity, phishtank_marking, feeds2stix_marking
):
    all_stix_objects = [fetch_attack_pattern()]  # already cached by lru_cache
    for entry in entries:
        try:
            objects = create_stix_objects_for_phish(
                entry, phishtank_identity["id"], phishtank_marking["id"]
            )
            all_stix_objects.extend(objects)
        except Exception as e:
            logger.warning(f"Failed to process entry {entry.get('phish_id')}: {e}")
    return all_stix_objects


def filter_entries_by_date(entries, since_date):
    retval = []
    for entry in entries:
        times = [parse_time(entry["submission_time"])]
        if entry.get("verification_time"):
            times.append(parse_time(entry["verification_time"]))
        for detail in entry.get("details", []):
            if detail.get("detail_time"):
                times.append(parse_time(detail["detail_time"]))
        modified_time = max(times)
        entry["modified_time"] = modified_time
        if since_date and modified_time < since_date:
            continue
        retval.append(entry)
    retval.sort(key=lambda x: x["modified_time"])
    return retval


def main():
    parser = argparse.ArgumentParser(
        description="Process PhishTank feed and generate STIX bundles"
    )
    parser.add_argument(
        "--since-date",
        "--since_date",
        type=datetime.fromisoformat,
        help="Only process entries with submission_time on or after this date (ISO format)",
    )
    args = parser.parse_args()

    since_date = args.since_date and args.since_date.replace(tzinfo=UTC)

    bundles_dir, _data_dir = setup_output_directory(OUTPUT_DIR, clean=True)

    identity = create_phishtank_identity()
    marking = create_phishtank_marking_definition()
    feeds2stix_marking = fetch_external_objects()
    attack_pattern = (
        fetch_attack_pattern()
    )  # cache this to avoid repeated CTI Butler calls

    data = fetch_phishtank_data()
    logger.info(f"Fetched {len(data)} entries from PhishTank")

    data = list(filter_entries_by_date(data, since_date))
    logger.info(
        f"{len(data)} entries remain after filtering by since_date={since_date}"
    )
    N = 500
    grouped = group_entries_to_max_N_elements(data, N)
    logger.info(f"Grouped entries into {len(grouped)} parts with up to {N} entries each")

    bundle_paths = []

    for group_idx, entries in grouped.items():
        logger.info(f"Processing part {group_idx} of {len(grouped)} with {len(entries)} entries...")

        all_stix_objects = process_entries_for_date(
            entries, identity, marking, feeds2stix_marking
        )
        logger.info(f"Created {len(all_stix_objects)} STIX objects for part {group_idx}")
        bundle = create_bundle_with_metadata(
            stix_objects=all_stix_objects,
            source_identity=identity,
            source_marking=marking,
            feeds2stix_marking=feeds2stix_marking,
        )
        bundle_filename = f"phishtank_{group_idx}"
        path = save_bundle_to_file(
            bundle, bundles_dir, bundle_filename, add_timestamp=False
        )
        bundle_paths.append(path)

    logger.info(f"Processing complete. Created {len(bundle_paths)} bundles.")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            f.write(f"bundle_count={len(bundle_paths)}\n")


if __name__ == "__main__":
    main()
