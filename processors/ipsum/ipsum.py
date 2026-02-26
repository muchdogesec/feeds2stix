import os
import shutil
import requests
import uuid
import json
import logging
import argparse
from datetime import UTC, datetime
from stix2 import Indicator, Identity, MarkingDefinition, Bundle, IPv4Address

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


def create_ipsum_marking_definition():
    """Create a marking definition for IPSum feed"""
    statement = "Origin: https://github.com/stamparm/ipsum"
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
    ip_addresses_by_level, ipsum_identity, ipsum_marking, script_run_time
):
    """Create STIX objects for IP addresses"""
    stix_objects = []

    confidence_map = {1: 12, 2: 25, 3: 37, 4: 50, 5: 62, 6: 75, 7: 87, 8: 100}

    ipsum_marking_id = ipsum_marking["id"]
    ipsum_identity_id = ipsum_identity["id"]

    total_ips = sum(len(ips) for ips in ip_addresses_by_level.values())
    logger.info(f"Processing {total_ips} unique IP addresses...")

    processed = 0
    for level in sorted(ip_addresses_by_level.keys(), reverse=True):
        ip_list = ip_addresses_by_level[level]
        confidence = confidence_map.get(level, 50)

        logger.info(
            f"Processing level {level} with {len(ip_list)} IPs (confidence: {confidence}%)..."
        )

        for ip in ip_list:
            processed += 1
            if processed % 1000 == 0:
                logger.info(f"Processed {processed}/{total_ips} IP addresses...")

            indicator_name = f"IPv4: {ip}"
            indicator_id = generate_uuid5(NAMESPACE_UUID, indicator_name)
            indicator_id_full = f"indicator--{indicator_id}"
            
            ipv4_obj = IPv4Address(value=ip)

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
                    ipsum_marking_id,
                ],
            )

            stix_objects.append(ipv4_obj)
            stix_objects.append(indicator)

    return stix_objects


def create_bundle(
    stix_objects, feeds2stix_identity, feeds2stix_marking, ipsum_identity, ipsum_marking
):
    """Create a STIX bundle with all objects"""
    all_objects = [
        feeds2stix_identity,
        feeds2stix_marking,
        ipsum_identity,
        ipsum_marking,
    ] + stix_objects

    bundle = Bundle(objects=all_objects)
    return bundle


def fetch_all_levels(min_level):
    """Fetch IP addresses from all levels, starting from level 8 down to min_level"""
    logger.info(f"Fetching IPSum feeds from level 8 down to level {min_level}...")

    seen_ips = set()
    ip_addresses_by_level = {}

    for level in range(8, min_level - 1, -1):
        ip_addresses = fetch_ipsum_feed(level)
        new_ips = []

        for ip in ip_addresses:
            if ip not in seen_ips:
                new_ips.append(ip)
                seen_ips.add(ip)

        if new_ips:
            ip_addresses_by_level[level] = new_ips
            logger.info(
                f"Level {level}: {len(new_ips)} new IPs (skipped {len(ip_addresses) - len(new_ips)} duplicates)"
            )

    logger.info(f"Total unique IPs collected: {len(seen_ips)}")
    return ip_addresses_by_level


def save_bundle(bundle, min_level, output_dir):
    """Save bundle to file"""
    os.makedirs(output_dir, exist_ok=True)

    filename = f"ipsum_level_{min_level}.json"
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
        "--min-level",
        type=int,
        required=True,
        choices=range(1, 9),
        metavar="1-8",
           help="Minimum category score/level (1-8). Fetches all levels from 8 down to this level.",
    )

    args = parser.parse_args()
    min_level = args.min_level

    try:
        output_dir = os.path.join(BASE_OUTPUT_DIR, "bundles")

        if os.path.exists(output_dir):
            logger.info(f"Cleaning output directory: {output_dir}")
            shutil.rmtree(output_dir)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

        ipsum_identity = create_ipsum_identity()
        ipsum_marking = create_ipsum_marking_definition()

        ip_addresses_by_level = fetch_all_levels(min_level)

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            ip_addresses_by_level, ipsum_identity, ipsum_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle(
            stix_objects,
            feeds2stix_identity,
            feeds2stix_marking,
            ipsum_identity,
            ipsum_marking,
        )

        bundle_path = save_bundle(bundle, min_level, output_dir)

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")
        return 0

    except Exception as e:
        logger.error(f"Error processing IPSum feed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())
