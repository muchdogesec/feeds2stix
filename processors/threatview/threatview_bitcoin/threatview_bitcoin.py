import argparse
import json
import logging
import os
import uuid
from datetime import UTC, datetime

import requests
from stix2 import Indicator
from stix2extensions import CryptocurrencyWallet

from helpers.utils import (
    NAMESPACE_UUID,
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

OASIS_NAMESPACE_UUID = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
THREATVIEW_BITCOIN_FEED_URL = (
    "https://threatview.io/Downloads/MALICIOUS-BITCOIN_FEED.txt"
)
BASE_OUTPUT_DIR = "bundles/threatview_bitcoin/"


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
    return create_marking_definition_object(f"Origin: {THREATVIEW_BITCOIN_FEED_URL}")


def fetch_threatview_feed():
    """Fetch Bitcoin wallet addresses from ThreatView feed"""
    logger.info(f"Fetching ThreatView Bitcoin feed from: {THREATVIEW_BITCOIN_FEED_URL}")

    response = requests.get(THREATVIEW_BITCOIN_FEED_URL)
    response.raise_for_status()

    wallets = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(wallets)} Bitcoin wallets in ThreatView feed")
    return wallets


def create_stix_objects(
    wallets, threatview_identity, threatview_marking, script_run_time
):
    """Create STIX objects for Bitcoin wallets"""
    stix_objects = []

    threatview_marking_id = threatview_marking["id"]
    threatview_identity_id = threatview_identity["id"]

    logger.info(f"Processing {len(wallets)} Bitcoin wallets...")

    for idx, wallet in enumerate(wallets):
        # Create cryptocurrency-wallet SCO using custom extension
        wallet_obj = CryptocurrencyWallet(
            value=wallet,
        )

        indicator_name = f"Cryptocurrency Wallet: {wallet}"
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
            pattern=f"[cryptocurrency-wallet:value='{wallet}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                threatview_marking_id,
            ],
        )

        stix_objects.append(wallet_obj)
        stix_objects.append(indicator)
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=wallet_obj["id"],
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
        description="Convert ThreatView Bitcoin threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_marking = fetch_external_objects()

        threatview_identity = create_threatview_identity()
        threatview_marking = create_threatview_marking_definition()

        wallets = fetch_threatview_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            wallets, threatview_identity, threatview_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            threatview_identity,
            threatview_marking,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "threatview_bitcoin")

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
        logger.error(f"Error processing ThreatView Bitcoin feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
