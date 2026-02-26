import os
import requests
import json
import logging
import argparse
from datetime import UTC, datetime
from stix2 import Indicator, IPv4Address

from helpers.helpers import (
    generate_uuid5,
    fetch_external_objects,
    create_identity_object,
    create_marking_definition_object,
    create_bundle_with_metadata,
    make_relationship,
    save_bundle_to_file,
    setup_output_directory,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

CINSSCORE_FEED_URL = "https://cinsscore.com/list/ci-badguys.txt"
BASE_OUTPUT_DIR = "bundles/cinsscore/"


def create_cinsscore_identity():
    """Create the CINS Score identity object"""
    return create_identity_object(
        name="CINS",
        description='Collective Intelligence Network Security (CINS, pronounced "sins," get it?) is our effort to use this information to significantly improve the security of our customers\' networks. We also provide this vital information to the InfoSec community free of charge.',
        identity_class="system",
        contact_info="https://cinsarmy.com/",
    )


def create_cinsscore_marking_definition():
    """Create a marking definition for CINS Score feed"""
    return create_marking_definition_object(f"Origin: {CINSSCORE_FEED_URL}")


def fetch_cinsscore_feed():
    """Fetch IP addresses from CINS Score feed"""
    logger.info(f"Fetching CINS Score feed from: {CINSSCORE_FEED_URL}")

    response = requests.get(CINSSCORE_FEED_URL)
    response.raise_for_status()

    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(ip_addresses)} IP addresses in CINS Score feed")
    return ip_addresses


def create_stix_objects(
    ip_addresses, cinsscore_identity, cinsscore_marking, script_run_time
):
    """Create STIX objects for IP addresses"""
    stix_objects = []

    cinsscore_marking_id = cinsscore_marking["id"]
    cinsscore_identity_id = cinsscore_identity["id"]

    logger.info(f"Processing {len(ip_addresses)} IP addresses...")

    for idx, ip in enumerate(ip_addresses):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(ip_addresses)} IP addresses...")

        ipv4_obj = IPv4Address(value=ip)

        indicator_name = f"IPv4: {ip}"
        indicator_id = generate_uuid5(indicator_name)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=cinsscore_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[ipv4-addr:value='{ip}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                cinsscore_marking_id,
            ],
        )

        stix_objects.append(ipv4_obj)
        stix_objects.append(indicator)
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=ipv4_obj["id"],
            relationship_type="indicates",
            created_by_ref=cinsscore_identity["id"],
            marking_refs=indicator["object_marking_refs"],
            created=script_run_time,
        )
        stix_objects.append(relationship)

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects





def main():
    parser = argparse.ArgumentParser(
        description="Convert CINS Score threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

        cinsscore_identity = create_cinsscore_identity()
        cinsscore_marking = create_cinsscore_marking_definition()

        ip_addresses = fetch_cinsscore_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            ip_addresses, cinsscore_identity, cinsscore_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            cinsscore_identity,
            cinsscore_marking,
            feeds2stix_identity,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "cinsscore")

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing CINS Score feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
