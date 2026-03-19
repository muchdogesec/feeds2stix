import argparse
import json
import logging
import os
import uuid
from datetime import UTC, datetime

import requests
from stix2 import Indicator, IPv4Address

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
THREATVIEW_IP_FEED_URL = "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
IP_GUIDE_URL_TEMPLATE = "https://ip.guide/{ip}"
CHECKPOINT_SIZE = 1000
BASE_OUTPUT_DIR = "outputs/threatview_ip"


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


def fetch_ip_guide_metadata(ip):
    """Fetch enrichment data for an IP from ip.guide."""
    try:
        response = requests.get(IP_GUIDE_URL_TEMPLATE.format(ip=ip), timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        logger.debug("Failed to fetch ip.guide data for %s: %s", ip, exc)
        return {}

    data = response.json()

    network = data.get("network") or {}
    hosts = network.get("hosts") or {}
    autonomous_system = network.get("autonomous_system") or {}
    location = data.get("location") or {}

    metadata = {
        "x_ip_guide_cidr": network.get("cidr"),
        "x_ip_guide_hosts_start": hosts.get("start"),
        "x_ip_guide_hosts_end": hosts.get("end"),
        "x_ip_guide_asn": autonomous_system.get("asn"),
        "x_ip_guide_as_name": autonomous_system.get("name"),
        "x_ip_guide_as_organization": autonomous_system.get("organization"),
        "x_ip_guide_as_country": autonomous_system.get("country"),
        "x_ip_guide_as_rir": autonomous_system.get("rir"),
        "x_ip_guide_city": location.get("city"),
        "x_ip_guide_country": location.get("country"),
        "x_ip_guide_timezone": location.get("timezone"),
        "x_ip_guide_latitude": location.get("latitude"),
        "x_ip_guide_longitude": location.get("longitude"),
    }

    return {key: value for key, value in metadata.items() if value is not None}


def create_stix_objects(
    ip_addresses,
    threatview_identity,
    threatview_marking,
    script_run_time,
    geo_lookup_fn=fetch_ip_guide_metadata,
):
    """Create STIX objects for IP addresses"""
    stix_objects = []

    threatview_marking_id = threatview_marking["id"]
    threatview_identity_id = threatview_identity["id"]

    logger.info(f"Processing {len(ip_addresses)} IP addresses...")

    for idx, ip in enumerate(ip_addresses):
        if (idx + 1) % 1000 == 0:
            logger.info(f"Processed {idx + 1}/{len(ip_addresses)} IP addresses...")

        geo_metadata = geo_lookup_fn(ip)
        ipv4_obj = IPv4Address(
            value=ip,
            custom_properties=geo_metadata,
            allow_custom=True,
        )

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
        output_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)

        script_run_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        feeds2stix_marking = fetch_external_objects()

        threatview_identity = create_threatview_identity()
        threatview_marking = create_threatview_marking_definition()

        ip_addresses = fetch_threatview_feed()

        logger.info("Creating STIX objects and saving checkpoints...")
        stix_objects = []
        checkpoint_filename = (
            f"threatview_ip_{datetime.now(UTC).strftime('%Y%m%d')}"
        )

        for start_idx in range(0, len(ip_addresses), CHECKPOINT_SIZE):
            chunk = ip_addresses[start_idx : start_idx + CHECKPOINT_SIZE]
            chunk_stix_objects = create_stix_objects(
                chunk,
                threatview_identity,
                threatview_marking,
                script_run_time,
            )
            stix_objects.extend(chunk_stix_objects)

            bundle = create_bundle_with_metadata(
                stix_objects,
                threatview_identity,
                threatview_marking,
                feeds2stix_marking,
            )

            bundle_path = save_bundle_to_file(
                bundle,
                output_dir,
                checkpoint_filename,
                add_timestamp=False,
            )

            processed = min(start_idx + CHECKPOINT_SIZE, len(ip_addresses))
            logger.info(
                "Checkpoint saved: %s/%s IPs processed",
                processed,
                len(ip_addresses),
            )

        if not ip_addresses:
            bundle = create_bundle_with_metadata(
                stix_objects,
                threatview_identity,
                threatview_marking,
                feeds2stix_marking,
            )
            bundle_path = save_bundle_to_file(
                bundle,
                output_dir,
                checkpoint_filename,
                add_timestamp=False,
            )

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
