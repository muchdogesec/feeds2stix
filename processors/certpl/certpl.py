import os
import uuid
import requests
import json
import logging
import argparse
from datetime import UTC, datetime
from stix2 import Indicator, DomainName

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
CERTPL_FEED_URL = "https://hole.cert.pl/domains/v2/domains.txt"
BASE_OUTPUT_DIR = "bundles/certpl/"


def create_certpl_identity():
    """Create the CERT.PL identity object"""
    return create_identity_object(
        name="CERT.PL",
        description="Poland's national computer security incident response team.",
        identity_class="organization",
        contact_info="https://cert.pl/",
    )


def create_certpl_marking_definition():
    """Create a marking definition for CERT.PL feed"""
    return create_marking_definition_object(f"Origin: {CERTPL_FEED_URL}")


def fetch_certpl_feed():
    """Fetch domain names from CERT.PL feed"""
    logger.info(f"Fetching CERT.PL feed from: {CERTPL_FEED_URL}")

    response = requests.get(CERTPL_FEED_URL)
    response.raise_for_status()

    domains = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(domains)} domains in CERT.PL feed")
    return domains


def create_stix_objects(domains, certpl_identity, certpl_marking, script_run_time):
    """Create STIX objects for domain names"""
    stix_objects = []

    certpl_marking_id = certpl_marking["id"]
    certpl_identity_id = certpl_identity["id"]

    logger.info(f"Processing {len(domains)} domains...")

    for idx, domain in enumerate(domains):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(domains)} domains...")

        domain_obj = DomainName(value=domain)

        indicator_name = f"Domain Name: {domain}"
        indicator_id = generate_uuid5(indicator_name, namespace=certpl_marking_id)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=certpl_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[domain-name:value='{domain}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                certpl_marking_id,
            ],
        )

        stix_objects.append(domain_obj)
        stix_objects.append(indicator)
        relationship = make_relationship(
            source_ref=indicator["id"],
            target_ref=domain_obj["id"],
            relationship_type="indicates",
            created_by_ref=certpl_identity["id"],
            marking_refs=indicator["object_marking_refs"],
            created=script_run_time,
        )
        stix_objects.append(relationship)

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Convert CERT.PL threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

        certpl_identity = create_certpl_identity()
        certpl_marking = create_certpl_marking_definition()

        domains = fetch_certpl_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            domains, certpl_identity, certpl_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            certpl_identity,
            certpl_marking,
            feeds2stix_identity,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "certpl")

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
        logger.error(f"Error processing CERT.PL feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
