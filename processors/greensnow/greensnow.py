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
from processors.cinsscore import cinsscore
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
        stix_objects = cinsscore.create_stix_objects(
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
