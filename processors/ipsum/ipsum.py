import os
import shutil
import requests
import uuid
import json
import logging
import argparse
from datetime import UTC, datetime
from stix2 import Indicator, Identity, MarkingDefinition, Bundle

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

NAMESPACE_UUID = uuid.UUID("a1cb37d2-3bd3-5b23-8526-47a22694b7e0")
IPSUM_FEED_URL_TEMPLATE = (
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{level}.txt"
)
BASE_OUTPUT_DIR = "bundles/ipsum/"

FEEDS2STIX_IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"
FEEDS2STIX_MARKING_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json"


def generate_uuid5(namespace, name):
    """Generate UUIDv5 from namespace and name"""
    return str(uuid.uuid5(namespace, name))


def fetch_external_objects():
    """Fetch external STIX identity and marking definition objects"""
    logger.info("Fetching external STIX objects...")

    identity_response = requests.get(FEEDS2STIX_IDENTITY_URL)
    identity_response.raise_for_status()
    feeds2stix_identity = identity_response.json()

    marking_response = requests.get(FEEDS2STIX_MARKING_URL)
    marking_response.raise_for_status()
    feeds2stix_marking = marking_response.json()

    return feeds2stix_identity, feeds2stix_marking


def create_ipsum_identity():
    """Create the IPSum identity object"""
    identity_id = generate_uuid5(NAMESPACE_UUID, "IPSum")

    identity = Identity(
        id=f"identity--{identity_id}",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        created="2020-01-01T00:00:00.000Z",
        modified="2020-01-01T00:00:00.000Z",
        name="IPSum",
        description="IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses.",
        identity_class="system",
        contact_information="https://github.com/stamparm/ipsum",
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    )

    return identity


def create_level_marking_definition(level):
    """Create a marking definition for the specific feed level"""
    origin_url = IPSUM_FEED_URL_TEMPLATE.format(level=level)
    statement = f"Origin: {origin_url}"

    marking_id = generate_uuid5(NAMESPACE_UUID, statement)

    marking = MarkingDefinition(
        id=f"marking-definition--{marking_id}",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        created="2020-01-01T00:00:00.000Z",
        definition_type="statement",
        definition={"statement": statement},
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    )

    return marking


def fetch_ipsum_feed(level):
    """Fetch IP addresses from IPSum feed"""
    url = IPSUM_FEED_URL_TEMPLATE.format(level=level)
    logger.info(f"Fetching IPSum feed from: {url}")

    response = requests.get(url)
    response.raise_for_status()

    ip_addresses = [
        line.strip()
        for line in response.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]

    logger.info(f"Found {len(ip_addresses)} IP addresses in level {level} feed")
    return ip_addresses


def create_stix_objects(
    ip_addresses, level, ipsum_identity, level_marking, script_run_time
):
    """Create STIX objects for IP addresses"""
    stix_objects = []

    # Map level to confidence score (1=low, 8=high)
    # Level 1: ~12% confidence, Level 8: ~100% confidence
    confidence_map = {1: 12, 2: 25, 3: 37, 4: 50, 5: 62, 6: 75, 7: 87, 8: 100}
    confidence = confidence_map.get(level, 50)

    level_marking_id = level_marking["id"]
    ipsum_identity_id = ipsum_identity["id"]

    logger.info(f"Processing {len(ip_addresses)} IP addresses...")

    for idx, ip in enumerate(ip_addresses):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(ip_addresses)} IP addresses...")

        indicator_name = f"IPv4: {ip}"
        indicator_id = generate_uuid5(NAMESPACE_UUID, indicator_name)
        indicator_id_full = f"indicator--{indicator_id}"

        ipv4_obj = {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": f"ipv4-addr--{generate_uuid5(uuid.UUID('00abedb4-aa42-466c-9c01-fed23315a9b7'), ip)}",
            "value": ip,
        }

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=ipsum_identity_id,
            created=script_run_time,
            modified=script_run_time,
            valid_from=script_run_time,
            confidence=confidence,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[ipv4-addr:value='{ip}']",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                level_marking_id,
            ],
        )

        stix_objects.append(ipv4_obj)
        stix_objects.append(indicator)

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def create_bundle(
    stix_objects, feeds2stix_identity, feeds2stix_marking, ipsum_identity, level_marking
):
    """Create a STIX bundle with all objects"""
    all_objects = [
        feeds2stix_identity,
        feeds2stix_marking,
        ipsum_identity,
        level_marking,
    ] + stix_objects

    bundle = Bundle(objects=all_objects)
    return bundle


def save_bundle(bundle, level, output_dir):
    """Save bundle to file"""
    os.makedirs(output_dir, exist_ok=True)

    filename = f"ipsum_level_{level}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(bundle.serialize(indent=4))

    logger.info(f"Bundle saved to: {filepath}")
    return filepath


def main():
    parser = argparse.ArgumentParser(
        description="Convert IPSum threat intelligence feed to STIX 2.1 format"
    )
    parser.add_argument(
        "--category_score",
        type=int,
        required=True,
        choices=range(1, 9),
        metavar="1-8",
        help="Category score/level (1-8, where 1 has most false positives, 8 has least)",
    )

    args = parser.parse_args()
    level = args.category_score

    try:
        output_dir = os.path.join(BASE_OUTPUT_DIR, "bundles")

        if os.path.exists(output_dir):
            logger.info(f"Cleaning output directory: {output_dir}")
            shutil.rmtree(output_dir)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

        ipsum_identity = create_ipsum_identity()
        level_marking = create_level_marking_definition(level)

        ip_addresses = fetch_ipsum_feed(level)

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            ip_addresses, level, ipsum_identity, level_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle(
            stix_objects,
            feeds2stix_identity,
            feeds2stix_marking,
            ipsum_identity,
            level_marking,
        )

        bundle_path = save_bundle(bundle, level, output_dir)

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        print(f"BUNDLE_PATH={bundle_path}")
        return 0

    except Exception as e:
        logger.error(f"Error processing IPSum feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
