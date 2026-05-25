#!/usr/bin/env python3

import argparse
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from stix2 import DomainName, Indicator
from stix2.patterns import StringConstant

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.attack_patterns import fetch_attack_pattern
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
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

PHISHING_ARMY_FEED_URL = "https://phishing.army/download/phishing_army_blocklist.txt"
BASE_OUTPUT_DIR = "outputs/phishing_army"
RAW_FEED_FILENAME = "phishing_army_blocklist.txt"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["phishing_army"]
ATTACK_PATTERN_ID = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]


def create_phishing_army_identity():
    """Create the Phishing Army identity object."""
    return create_identity_object(
        name="Phishing Army",
        description="Phishing Army maintains a curated phishing blocklist derived from public phishing intelligence sources.",
        identity_class="system",
        contact_info="https://www.phishing.army/",
    )


def create_phishing_army_marking_definition():
    """Create the Phishing Army marking definition object."""
    return create_marking_definition_object(
        f"Origin: {PHISHING_ARMY_FEED_URL}"
    )


def fetch_phishing_army_feed(data_dir: Path) -> List[str]:
    """Fetch the Phishing Army blocklist and save the raw feed."""
    logger.info(f"Fetching Phishing Army feed from: {PHISHING_ARMY_FEED_URL}")

    response = requests.get(PHISHING_ARMY_FEED_URL, timeout=300)
    response.raise_for_status()

    raw_path = data_dir / RAW_FEED_FILENAME
    raw_path.write_bytes(response.content)
    logger.info(f"Saved raw feed to {raw_path}")

    domains = []
    seen = set()
    for line in response.text.splitlines():
        if line.startswith('#'):
            continue
        domain = line.strip().lower()
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)

    logger.info(f"Found {len(domains)} unique domains in Phishing Army feed")
    return domains


def create_indicator_object(
    domain: str,
    source_identity_id: str,
    source_marking_id: str,
    script_run_time: str,
) -> Indicator:
    """Create an Indicator object for a phishing domain."""
    indicator_name = f"Domain Name: {domain}"
    indicator_id_full = "indicator--" + generate_uuid5(
        indicator_name, namespace=source_marking_id
    )

    return Indicator(
        id=indicator_id_full,
        created_by_ref=source_identity_id,
        created=script_run_time,
        modified=script_run_time,
        valid_from=script_run_time,
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=f"[domain-name:value = {StringConstant(domain)}]",
        pattern_type="stix",
        object_marking_refs=OBJECT_MARKING_REFS_BASE + [source_marking_id],
    )


def create_stix_objects(
    domains: List[str],
    phishing_army_identity,
    phishing_army_marking,
    script_run_time: str,
):
    """Create STIX objects for phishing domains."""

    stix_objects = []
    phishing_army_marking_id = phishing_army_marking["id"]
    phishing_army_identity_id = phishing_army_identity["id"]

    logger.info(f"Processing {len(domains)} domains...")

    for idx, domain in enumerate(domains, start=1):
        if idx % 3000 == 0:
            logger.info(f"Processed {idx}/{len(domains)} domains...")

        domain_obj = DomainName(value=domain)

        indicator = create_indicator_object(
            domain,
            phishing_army_identity_id,
            phishing_army_marking_id,
            script_run_time,
        )

        stix_objects.append(domain_obj)
        stix_objects.append(indicator)
        stix_objects.append(
            make_relationship(
                source_ref=indicator["id"],
                target_ref=domain_obj["id"],
                relationship_type="indicates",
                created_by_ref=phishing_army_identity_id,
                created=script_run_time,
                modified=script_run_time,
                marking_refs=indicator["object_marking_refs"],
            )
        )
        stix_objects.append(
            make_relationship(
                source_ref=indicator["id"],
                target_ref=ATTACK_PATTERN_ID,
                relationship_type="indicates",
                created_by_ref=phishing_army_identity_id,
                created=script_run_time,
                modified=script_run_time,
                marking_refs=indicator["object_marking_refs"],
                description=f"{domain} is known to be used for Phishing (T1566)",
            )
        )

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Convert Phishing Army threat intelligence feed to STIX 2.1 format"
    )

    parser.parse_args()

    try:
        output_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_marking = fetch_external_objects()
        phishing_army_identity = create_phishing_army_identity()
        phishing_army_marking = create_phishing_army_marking_definition()

        domains = fetch_phishing_army_feed(data_dir)

        logger.info("Creating STIX objects...")
        stix_objects = [fetch_attack_pattern(ATTACK_PATTERN_ID)] + create_stix_objects(
            domains, phishing_army_identity, phishing_army_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            phishing_army_identity,
            phishing_army_marking,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "phishing_army")

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing Phishing Army feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
