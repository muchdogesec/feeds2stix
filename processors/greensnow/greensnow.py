import argparse
import json
import logging
import os
import sys
from datetime import UTC, datetime

import requests
from stix2 import Indicator, IPv4Address, StringConstant

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

GREENSNOW_FEED_URL = "https://blocklist.greensnow.co/greensnow.txt"
BASE_OUTPUT_DIR = "outputs/greensnow"
# PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["greensnow"]


def create_greensnow_identity():
    """Create the Greensnow identity object"""
    return create_identity_object(
        name="Greensnow",
        description="GreenSnow is a team consisting of the best specialists in computer security, we harvest a large number of IPs from different computers located around the world. GreenSnow is comparable with SpamHaus.org for attacks of any kind except for spam. Our list is updated automatically and you can withdraw at any time your IP address if it has been listed.",
        identity_class="system",
        contact_info="https://greensnow.co/",

    )


def create_greensnow_marking_definition():
    """Create a marking definition for Greensnow feed"""
    return create_marking_definition_object(f"Origin: {GREENSNOW_FEED_URL}")


def fetch_greensnow_feed():
    """Fetch IP addresses from Greensnow feed"""
    logger.info(f"Fetching Greensnow feed from: {GREENSNOW_FEED_URL}")

    response = requests.get(GREENSNOW_FEED_URL)
    response.raise_for_status()

    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(ip_addresses)} IP addresses in Greensnow feed")
    return ip_addresses


def create_stix_objects(
    ip_addresses, greensnow_identity, greensnow_marking, script_run_time
):
    """Create STIX objects for IP addresses"""
    stix_objects = []

    greensnow_marking_id = greensnow_marking["id"]
    greensnow_identity_id = greensnow_identity["id"]

    logger.info(f"Processing {len(ip_addresses)} IP addresses...")

    for idx, ip in enumerate(ip_addresses):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(ip_addresses)} IP addresses...")

        ipv4_obj = IPv4Address(value=ip)

        indicator_name = f"IPv4: {ip}"
        indicator_id = generate_uuid5(indicator_name, namespace=greensnow_marking_id)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=greensnow_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[ipv4-addr:value = {StringConstant(ip)} ]",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                greensnow_marking_id,
            ],
        )

        stix_objects.append(ipv4_obj)
        stix_objects.append(indicator)
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=ipv4_obj["id"],
            relationship_type="indicates",
            created_by_ref=greensnow_identity["id"],
            marking_refs=indicator["object_marking_refs"],
            created=script_run_time,
            modified=script_run_time,
        )
        stix_objects.append(relationship)

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Convert Greensnow threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_marking = fetch_external_objects()

        greensnow_identity = create_greensnow_identity()
        greensnow_marking = create_greensnow_marking_definition()

        ip_addresses = fetch_greensnow_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            ip_addresses, greensnow_identity, greensnow_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            greensnow_identity,
            greensnow_marking,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "greensnow")

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing Greensnow feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
