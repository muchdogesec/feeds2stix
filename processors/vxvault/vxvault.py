import argparse
import json
import logging
import os
import shutil
import sys
from datetime import UTC, datetime

import requests
from stix2 import URL, Bundle, Indicator

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

OASIS_NAMESPACE_UUID = "00abedb4-aa42-466c-9c01-fed23315a9b7"
VXVAULT_FEED_URL = "http://vxvault.net/URL_List.php"
BASE_OUTPUT_DIR = "outputs/vxvault"


def create_vxvault_identity():
    """Create the VXVault identity object"""
    return create_identity_object(
        name="VXVault",
        description="Recently identified malware samples and the URLs used to distribute them",
        identity_class="system",
        contact_info="http://vxvault.net/",
    )


def create_vxvault_marking_definition():
    """Create a marking definition for VXVault feed"""
    return create_marking_definition_object(f"Origin: {VXVAULT_FEED_URL}")


def fetch_vxvault_feed():
    """Fetch URLs from VXVault feed"""
    logger.info(f"Fetching VXVault feed from: {VXVAULT_FEED_URL}")

    response = requests.get(VXVAULT_FEED_URL)
    response.raise_for_status()

    urls = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#") and line.strip().startswith("http")
    ]

    logger.info(f"Found {len(urls)} URLs in VXVault feed")
    return urls


def create_stix_objects(urls, vxvault_identity, vxvault_marking, script_run_time):
    """Create STIX objects for URLs"""
    stix_objects = []

    vxvault_marking_id = vxvault_marking["id"]
    vxvault_identity_id = vxvault_identity["id"]

    logger.info(f"Processing {len(urls)} URLs...")

    for idx, url in enumerate(urls):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(urls)} URLs...")

        url_obj = URL(value=url)

        indicator_name = f"URL: {url}"
        indicator_id = generate_uuid5(indicator_name, namespace=vxvault_marking_id)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=vxvault_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[url:value='{url}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                vxvault_marking_id,
            ],
        )

        stix_objects.append(url_obj)
        stix_objects.append(indicator)
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=url_obj["id"],
            relationship_type="indicates",
            created_by_ref=vxvault_identity["id"],
            marking_refs=indicator["object_marking_refs"],
            created=script_run_time,
        )
        stix_objects.append(relationship)

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Convert VXVault threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_marking = fetch_external_objects()

        vxvault_identity = create_vxvault_identity()
        vxvault_marking = create_vxvault_marking_definition()

        urls = fetch_vxvault_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            urls, vxvault_identity, vxvault_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            vxvault_identity,
            vxvault_marking,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "vxvault")

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing VXVault feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
