import os
import shutil
import requests
import uuid
import json
import logging
import argparse
from datetime import UTC, datetime
from stix2 import Indicator, Identity, MarkingDefinition, Bundle, URL

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

NAMESPACE_UUID = uuid.UUID("a1cb37d2-3bd3-5b23-8526-47a22694b7e0")
OASIS_NAMESPACE_UUID = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
VXVAULT_FEED_URL = "http://vxvault.net/URL_List.php"
BASE_OUTPUT_DIR = "bundles/vxvault/"

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


def create_vxvault_identity():
    """Create the VXVault identity object"""
    identity_id = generate_uuid5(NAMESPACE_UUID, "VXVault")

    identity = Identity(
        id=f"identity--{identity_id}",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        created="2020-01-01T00:00:00.000Z",
        modified="2020-01-01T00:00:00.000Z",
        name="VXVault",
        description="Recently identified malware samples and the URLs used to distribute them",
        identity_class="system",
        contact_information="http://vxvault.net/",
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    )

    return identity


def create_vxvault_marking_definition():
    """Create a marking definition for VXVault feed"""
    statement = f"Origin: {VXVAULT_FEED_URL}"
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
        indicator_id = generate_uuid5(NAMESPACE_UUID, indicator_name)
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

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def create_bundle(
    stix_objects,
    feeds2stix_identity,
    feeds2stix_marking,
    vxvault_identity,
    vxvault_marking,
):
    """Create a STIX bundle with all objects"""
    all_objects = [
        feeds2stix_identity,
        feeds2stix_marking,
        vxvault_identity,
        vxvault_marking,
    ] + stix_objects

    bundle = Bundle(objects=all_objects)
    return bundle


def save_bundle(bundle, output_dir):
    """Save bundle to file"""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"vxvault_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(bundle.serialize(indent=4))

    logger.info(f"Bundle saved to: {filepath}")
    return filepath


def main():
    parser = argparse.ArgumentParser(
        description="Convert VXVault threat intelligence feed to STIX 2.1 format"
    )

    args = parser.parse_args()

    try:
        output_dir = os.path.join(BASE_OUTPUT_DIR, "bundles")

        if os.path.exists(output_dir):
            logger.info(f"Cleaning output directory: {output_dir}")
            shutil.rmtree(output_dir)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_identity, feeds2stix_marking = fetch_external_objects()

        vxvault_identity = create_vxvault_identity()
        vxvault_marking = create_vxvault_marking_definition()

        urls = fetch_vxvault_feed()

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(
            urls, vxvault_identity, vxvault_marking, script_run_time
        )

        logger.info("Creating STIX bundle...")
        bundle = create_bundle(
            stix_objects,
            feeds2stix_identity,
            feeds2stix_marking,
            vxvault_identity,
            vxvault_marking,
        )

        bundle_path = save_bundle(bundle, output_dir)

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
    exit(main())
