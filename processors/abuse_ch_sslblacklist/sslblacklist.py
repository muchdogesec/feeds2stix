#!/usr/bin/env python3

from collections import defaultdict
import os
import csv
import requests
import logging
import argparse
import sys
from datetime import datetime, timezone
from stix2 import File, Indicator, Malware, Relationship

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.helpers import (
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

CSV_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
BASE_OUTPUT_DIR = "bundles/abuse_ch_sslblacklist/"


def create_abuse_ch_identity():
    """Create the abuse.ch identity object"""
    return create_identity_object(
        name="abuse.ch",
        description="abuse.ch has been effecting change on cybercrime for almost twenty years, owing to global recognition of our identified and tracked cyber threat signals. Supported by a community of 15,000 specialist researchers, abuse.ch's independent intelligence is relied on by security researchers, network operators and law enforcement agencies.",
        identity_class="organization",
        contact_info="https://abuse.ch/",
    )


def create_sslbl_marking_definition():
    """Create a marking definition for SSLBL feed"""
    return create_marking_definition_object(
        "Origin data source: https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
    )


def clean_listing_reason(reason):
    if reason is None:
        return "Unknown"

    reason = reason.replace(" malware distribution", "")
    reason = reason.replace(" Malware distribution", "Malware")
    reason = reason.replace(" C&C", "")
    reason = reason.strip()
    if not reason:
        reason = "Unknown"
    return reason


def fetch_sslbl_feed():
    """Download and parse the CSV data"""
    logger.info(f"Fetching SSLBL feed from: {CSV_URL}")

    response = requests.get(CSV_URL)
    response.raise_for_status()

    lines = response.text.splitlines()
    retval = defaultdict(list)

    # Parse CSV data
    for line in lines:
        if line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) != 3:
            continue

        timestamp, sha1_hash, listing_reason = parts
        listing_reason = clean_listing_reason(listing_reason)

        listing_date_dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        listing_date_dt = listing_date_dt.replace(tzinfo=timezone.utc)

        retval[listing_reason].append(
            {
                "timestamp": listing_date_dt,
                "sha1_hash": sha1_hash,
                "listing_reason": listing_reason,
            }
        )

    logger.info(f"Found {len(retval)} unique malware families")
    return retval


def format_fingerprint(s):
    # Split into pairs and join with colon
    return ":".join(s[i : i + 2] for i in range(0, len(s), 2))


def create_all_stix_objects(
    malware_mapping, abuse_ch_identity, sslbl_marking, start_date=None
):
    """Create STIX objects for all malware families in a single bundle"""
    all_stix_objects = []
    sslbl_marking_id = sslbl_marking["id"]
    abuse_ch_identity_id = abuse_ch_identity["id"]
    start_date = start_date or datetime.min.replace(tzinfo=timezone.utc)

    total_files = sum(len(data) for data in malware_mapping.values())
    logger.info(
        f"Creating STIX objects for {len(malware_mapping)} malware families with {total_files} total files..."
    )
    marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        sslbl_marking_id,
    ]

    # Process each malware family
    for listing_reason, files_data in malware_mapping.items():
        dates = [file_data["timestamp"] for file_data in files_data]
        earliest_date = min(dates)
        latest_date = max(dates)
        if latest_date < start_date:
            logger.warning(
                f"Skipping '{listing_reason}' - all files listed before {start_date}"
            )
            continue

        logger.info(f"Processing '{listing_reason}' with {len(files_data)} files...")

        # Create File objects
        file_ids = []
        indicator_ids: list[tuple[str, datetime]] = []
        for file_data in files_data:
            file_obj = File(hashes={"SHA-1": file_data["sha1_hash"]})
            file_ids.append(file_obj.id)
            if file_data["timestamp"] <= start_date:
                continue
            all_stix_objects.append(file_obj)
            indicator_name = "Certificate: " + format_fingerprint(file_data["sha1_hash"])
            indicator_id = "indicator--"+generate_uuid5(indicator_name, sslbl_marking_id)
            indicator_obj = Indicator(
                id=indicator_id,
                created_by_ref=abuse_ch_identity_id,
                created=file_data["timestamp"],
                modified=file_data["timestamp"],
                valid_from=file_data["timestamp"],
                indicator_types=["malicious-activity"],
                name=indicator_name,
                pattern=f"[ file:hashes.'SHA-1' = '{file_data['sha1_hash']}' ]",
                pattern_type="stix",
                object_marking_refs=marking_refs,
                external_references=[
                    dict(
                        source_name="abuse.ch SSLBL",
                        url=f"https://sslbl.abuse.ch/ssl-certificates/sha1/{file_data['sha1_hash']}/",
                    )
                ],
            )
            all_stix_objects.append(indicator_obj)
            indicator_ids.append((indicator_obj.id, file_data["timestamp"]))

            # Create Relationship between Indicator and Malware
            file_relationship = make_relationship(
                source_ref=indicator_obj.id,
                target_ref=file_obj.id,
                relationship_type="indicates",
                created_by_ref=abuse_ch_identity_id,
                created=file_data["timestamp"],
                modified=file_data["timestamp"],
                marking_refs=marking_refs,
            )
            all_stix_objects.append(file_relationship)

        # Create Malware object
        if listing_reason != "Unknown":
            malware_id = generate_uuid5(listing_reason, sslbl_marking_id)
            malware_obj = Malware(
                id=f"malware--{malware_id}",
                created_by_ref=abuse_ch_identity_id,
                created=earliest_date,
                modified=latest_date,
                name=listing_reason,
                malware_types=["remote-access-trojan"],
                is_family=True,
                sample_refs=file_ids,
                object_marking_refs=marking_refs,
            )
            all_stix_objects.append(malware_obj)
            for indicator_id, timestamp in indicator_ids:
                relationship = make_relationship(
                    source_ref=indicator_id,
                    target_ref=malware_obj.id,
                    relationship_type="indicates",
                    created_by_ref=abuse_ch_identity_id,
                    created=timestamp,
                    modified=timestamp,
                    marking_refs=marking_refs,
                )
                all_stix_objects.append(relationship)

    logger.info(f"Created {len(all_stix_objects)} total STIX objects")
    return all_stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Process abuse.ch SSLBL feed and generate STIX bundles"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean output directory before processing",
    )
    parser.add_argument(
        "--start-date",
        type=datetime.fromisoformat,
        help="Only process records older than this date (YYYY-MM-DDTHH:MM:SS format)",
    )

    args = parser.parse_args()

    # Parse start_date if provided
    start_date = args.start_date and args.start_date.replace(tzinfo=timezone.utc)

    # Setup output directory
    bundle_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=args.clean)

    # Create identity and marking definition objects
    abuse_ch_identity = create_abuse_ch_identity()
    sslbl_marking = create_sslbl_marking_definition()

    # Fetch external objects
    feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

    # Fetch and parse CSV data
    malware_mapping = fetch_sslbl_feed()

    # Create all STIX objects in a single bundle
    stix_objects = create_all_stix_objects(
        malware_mapping, abuse_ch_identity, sslbl_marking, start_date=start_date
    )

    # Create single bundle with all objects
    bundle = create_bundle_with_metadata(
        stix_objects=stix_objects,
        source_identity=abuse_ch_identity,
        feeds2stix_identity=feeds2stix_identity,
        source_marking=sslbl_marking,
        feeds2stix_marking=feeds2stix_marking,
    )

    # Save single bundle
    bundle_filename = "sslblacklist"
    bundle_path = save_bundle_to_file(bundle, bundle_dir, bundle_filename)
    logger.info(f"Bundle saved to: {bundle_path}")
    logger.info(
        f"Processing complete. Created 1 bundle with {len(stix_objects)} STIX objects."
    )

    # Set GitHub Actions output
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundle_path}\n")


if __name__ == "__main__":
    main()
