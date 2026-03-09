#!/usr/bin/env python3

from collections import defaultdict
import os
import csv
import re
import requests
import logging
import argparse
import sys
from datetime import datetime, timezone
from stix2 import X509Certificate, Indicator, Malware, Relationship, Infrastructure

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

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
    C2_PATTERN = re.compile(r"^(.+?)(?:\s*C&C)$", re.IGNORECASE)
    DISTRIBUTION_PATTERN = re.compile(
        r"^(.+?)(?:\s*malware distribution)$", re.IGNORECASE
    )
    MITM_PATTERN = re.compile(r"^(.+?)(?:\s*MITM)$", re.IGNORECASE)
    if C2_PATTERN.match(reason):
        return C2_PATTERN.sub(r"\1", reason), "command-and-control"
    elif DISTRIBUTION_PATTERN.match(reason):
        return DISTRIBUTION_PATTERN.sub(r"\1", reason), "hosting-malware"
    # elif MITM_PATTERN.match(reason):
    #     return MITM_PATTERN.sub(r"\1", reason), "man-in-the-middle"
    else:
        return "Unknown", None


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

        listing_date_dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        listing_date_dt = listing_date_dt.replace(tzinfo=timezone.utc)
        malware_name, malware_type = clean_listing_reason(listing_reason)

        retval[malware_name].append(
            {
                "timestamp": listing_date_dt,
                "sha1_hash": sha1_hash,
                "infrastructure_type": malware_type,
            }
        )

    logger.info(f"Found {len(retval)} unique malware families")
    return retval


def format_fingerprint(s):
    # Split into pairs and join with colon
    return ":".join(s[i : i + 2] for i in range(0, len(s), 2))


def create_infrastructure_and_rels(malware_obj, infrastructure_type, cert_refs, marking_id):
    MAPPING = {
        "command-and-control": "C&C",
        "hosting-malware": "Malware distribution",
    }
    RELATION_MAP = {
        "command-and-control": "controls",
        "hosting-malware": "hosts",
    }
    objects = []
    infra_name = "{} {}".format(
        malware_obj.name, MAPPING.get(infrastructure_type, infrastructure_type)
    )
    infrastructure_id = "infrastructure--" + generate_uuid5(infra_name, marking_id)
    infrastructure_obj = Infrastructure(
        id=infrastructure_id,
        created_by_ref=malware_obj.created_by_ref,
        created=malware_obj.created,
        modified=malware_obj.modified,
        name=infra_name,
        infrastructure_types=[infrastructure_type],
        object_marking_refs=malware_obj.object_marking_refs,
    )
    objects.append(infrastructure_obj)
    infra_cert_rel = make_relationship(
        source_ref=infrastructure_obj.id,
        target_ref=malware_obj.id,
        relationship_type=RELATION_MAP[infrastructure_type],
        created_by_ref=malware_obj.created_by_ref,
        created=malware_obj.created,
        modified=malware_obj.modified,
        marking_refs=malware_obj.object_marking_refs,
    )
    objects.append(infra_cert_rel)
    for cert_ref, timestamp in cert_refs:
        infra_cert_rel = make_relationship(
            source_ref=infrastructure_obj.id,
            target_ref=cert_ref,
            relationship_type="related-to",
            created_by_ref=malware_obj.created_by_ref,
            created=timestamp,
            modified=timestamp,
            marking_refs=malware_obj.object_marking_refs,
        )
        objects.append(infra_cert_rel)
        mal_cert_rel = make_relationship(
            source_ref=malware_obj.id,
            target_ref=cert_ref,
            relationship_type="related-to",
            created_by_ref=malware_obj.created_by_ref,
            created=timestamp,
            modified=timestamp,
            marking_refs=malware_obj.object_marking_refs,
        )
        objects.append(mal_cert_rel)
    return objects


def create_stix_objects_for_malware(
    malware_name, files_data, abuse_ch_identity, sslbl_marking, start_date=None
):
    """Create STIX objects for a single malware family"""
    stix_objects = []
    sslbl_marking_id = sslbl_marking["id"]
    abuse_ch_identity_id = abuse_ch_identity["id"]
    start_date = start_date or datetime.min.replace(tzinfo=timezone.utc)

    marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        sslbl_marking_id,
    ]

    dates = [file_data["timestamp"] for file_data in files_data]
    earliest_date = min(dates)
    latest_date = max(dates)
    if latest_date < start_date:
        logger.warning(
            f"Skipping '{malware_name}' - all files listed before {start_date}"
        )
        return []

    logger.info(f"Processing '{malware_name}' with {len(files_data)} files...")

    # Create File objects
    indicator_ids: list[tuple[str, datetime]] = []
    infrastructure_cert_rels = defaultdict(list)
    for file_data in files_data:
        file_obj = X509Certificate(hashes={"SHA-1": file_data["sha1_hash"]})
        if file_data["timestamp"] <= start_date:
            continue
        infrastructure_cert_rels[file_data["infrastructure_type"]].append(
            (file_obj.id, file_data["timestamp"])
        )
        stix_objects.append(file_obj)
        indicator_name = "Certificate: " + format_fingerprint(file_data["sha1_hash"])
        indicator_id = "indicator--" + generate_uuid5(indicator_name, sslbl_marking_id)
        indicator_obj = Indicator(
            id=indicator_id,
            created_by_ref=abuse_ch_identity_id,
            created=file_data["timestamp"],
            modified=file_data["timestamp"],
            valid_from=file_data["timestamp"],
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[ x509-certificate:hashes.'SHA-1' = '{file_data['sha1_hash']}' ]",
            pattern_type="stix",
            object_marking_refs=marking_refs,
            external_references=[
                dict(
                    source_name="abuse.ch SSLBL",
                    url=f"https://sslbl.abuse.ch/ssl-certificates/sha1/{file_data['sha1_hash']}/",
                )
            ],
        )
        stix_objects.append(indicator_obj)
        indicator_ids.append((indicator_obj.id, file_data["timestamp"]))

        # Create Relationship between Indicator and File
        file_relationship = make_relationship(
            source_ref=indicator_obj.id,
            target_ref=file_obj.id,
            relationship_type="indicates",
            created_by_ref=abuse_ch_identity_id,
            created=file_data["timestamp"],
            modified=file_data["timestamp"],
            marking_refs=marking_refs,
        )
        stix_objects.append(file_relationship)

    # Create Malware object
    if malware_name != "Unknown":
        malware_id = generate_uuid5(malware_name, sslbl_marking_id)
        malware_obj = Malware(
            id=f"malware--{malware_id}",
            created_by_ref=abuse_ch_identity_id,
            created=earliest_date,
            modified=latest_date,
            name=malware_name,
            malware_types=["remote-access-trojan"],
            is_family=True,
            object_marking_refs=marking_refs,
        )
        stix_objects.append(malware_obj)
        for infrastructure_type, cert_refs in infrastructure_cert_rels.items():
            infrastructure_objects = create_infrastructure_and_rels(
                malware_obj, infrastructure_type, cert_refs, sslbl_marking_id
            )
            stix_objects.extend(infrastructure_objects)

    logger.info(f"Created {len(stix_objects)} STIX objects for '{malware_name}'")
    return stix_objects


def create_all_stix_objects(
    malware_mapping, abuse_ch_identity, sslbl_marking, start_date=None
):
    """Create STIX objects for all malware families in a single bundle"""
    total_files = sum(len(data) for data in malware_mapping.values())
    logger.info(
        f"Creating STIX objects for {len(malware_mapping)} malware families with {total_files} total files..."
    )
    objects_by_malwares = defaultdict(list)
    objects_created = 0
    # Process each malware family
    for malware_name, files_data in malware_mapping.items():
        stix_objects = create_stix_objects_for_malware(
            malware_name, files_data, abuse_ch_identity, sslbl_marking, start_date
        )
        if stix_objects:
            objects_by_malwares[malware_name].extend(stix_objects)
            objects_created += len(stix_objects)

    logger.info(f"Created {objects_created} total STIX objects")
    return objects_by_malwares


def main():
    parser = argparse.ArgumentParser(
        description="Process abuse.ch SSLBL feed and generate STIX bundles"
    )
    parser.add_argument(
        "--start-date",
        type=datetime.fromisoformat,
        help="Only process records older than this date (YYYY-MM-DDTHH:MM:SS format)",
    )
    parser.add_argument(
        "--no-split-bundle",
        action="store_true",
        help="Create a single bundle instead of splitting by listing_reason (malware family)",
    )

    args = parser.parse_args()

    # Parse start_date if provided
    start_date = args.start_date and args.start_date.replace(tzinfo=timezone.utc)

    # Setup output directory
    bundle_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

    # Create identity and marking definition objects
    abuse_ch_identity = create_abuse_ch_identity()
    sslbl_marking = create_sslbl_marking_definition()

    # Fetch external objects
    feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

    # Fetch and parse CSV data
    malware_mapping = fetch_sslbl_feed()
    bundle_path = bundle_dir

    objects_by_malwares = create_all_stix_objects(
        malware_mapping, abuse_ch_identity, sslbl_marking, start_date=start_date
    )
    if args.no_split_bundle:
        stix_objects = []
        for objects in objects_by_malwares.values():
            stix_objects.extend(objects)
        objects_by_malwares = {"all": stix_objects}
    for listing_reason, stix_objects in objects_by_malwares.items():
        bundle = create_bundle_with_metadata(
            stix_objects=stix_objects,
            source_identity=abuse_ch_identity,
            feeds2stix_identity=feeds2stix_identity,
            source_marking=sslbl_marking,
            feeds2stix_marking=feeds2stix_marking,
        )
        bundle_filename = (
            f"sslblacklist_{listing_reason}".replace(" ", "_")
            .replace("/", "_")
            .replace("&", "_")
        )
        bundle_path = save_bundle_to_file(bundle, bundle_dir, bundle_filename)
        logger.info(f"Bundle saved to: {bundle_path}")
        logger.info(
            f"Processing complete. Created 1 bundle with {len(stix_objects)} STIX objects."
        )

    # Set GitHub Actions output
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundle_dir}\n")


if __name__ == "__main__":
    main()
