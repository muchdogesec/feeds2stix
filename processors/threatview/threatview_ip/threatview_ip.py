import os
import uuid
import requests
import json
import logging
import argparse
from datetime import UTC, datetime
from stix2 import Indicator, IPv4Address

from helpers.utils import (
    generate_uuid5,
    fetch_external_objects,
    create_identity_object,
    create_marking_definition_object,
    create_bundle_with_metadata,
    make_relationship,
    save_bundle_to_file,
    setup_output_directory,
    NAMESPACE_UUID,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

OASIS_NAMESPACE_UUID = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
THREATVIEW_IP_FEED_URL = "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
BASE_OUTPUT_DIR = "bundles/threatview_ip/"


def create_threatview_identity():
    """Create the ThreatView identity object"""
    return create_identity_object(
        name="ThreatView",
        description="Verified threat feeds for immediate perimeter enforcement across security stacks.",
        identity_class="organization",
        contact_info="https://threatview.io/",
    )


def create_threatview_marking_definition():
    """Create a marking definition for ThreatView feed"""
    return create_marking_definition_object(f"Origin: {THREATVIEW_IP_FEED_URL}")


def fetch_threatview_feed():
    """Fetch IP addresses from ThreatView feed"""
    logger.info(f"Fetching ThreatView IP feed from: {THREATVIEW_IP_FEED_URL}")

    response = requests.get(THREATVIEW_IP_FEED_URL)
    response.raise_for_status()

    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(ip_addresses)} IP addresses in ThreatView feed")
    return ip_addresses


def create_stix_objects(ip_addresses, threatview_identity, threatview_marking, script_run_time):
    """Create STIX objects for IP addresses"""
    stix_objects = []

    threatview_marking_id = threatview_marking["id"]
    threatview_identity_id = threatview_identity["id"]

    logger.info(f"Processing {len(ip_addresses)} IP addresses...")

    for idx, ip in enumerate(ip_addresses):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(ip_addresses)} IP addresses...")

        ipv4_obj = IPv4Address(value=ip)

        indicator_name = f"IPv4: {ip}"
        indicator_id = generate_uuid5(indicator_name, namespace=threatview_marking_id)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=threatview_identity_id,
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
                threatview_marking_id,
            ],
        )

        stix_objects.append(ipv4_obj)
        stix_objects.append(indicator)
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=ipv4_obj["id"],
            relationship_type="indicates",
            created_by_ref=threatview_identity["id"],
            marking_refs=indicator["object_marking_refs"],
            created=script_run_time,
        )
        stix_objects.append(relationship)

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Convert ThreatView IP threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

        threatview_identity = create_threatview_identity()
        threatview_marking = create_threatview_marking_definition()

        ip_addresses = fetch_threatview_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            ip_addresses, threatview_identity, threatview_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            threatview_identity,
            threatview_marking,
            feeds2stix_identity,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "threatview_ip")

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        print(f"BUNDLE_PATH={bundle_path}")

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing ThreatView IP feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
