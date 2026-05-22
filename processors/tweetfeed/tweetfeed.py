#!/usr/bin/env python3

import argparse
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests
from stix2 import DomainName, File, Indicator, IPv4Address, URL, UserAccount
from stix2.patterns import StringConstant

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.utils import (
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    make_relationship,
    parse_since_date,
    save_bundle_to_file,
    setup_output_directory,
)
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

TWEETFEED_API_BASE = "https://api.tweetfeed.live/v1"
BASE_OUTPUT_DIR = "outputs/tweetfeed"
RAW_FEED_FILENAME = "tweetfeed_data.json"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["tweetfeed"]


def create_tweetfeed_identity():
    """Create the TweetFeed identity object."""
    return create_identity_object(
        name="TweetFeed",
        description="TweetFeed collects Indicators of Compromise (IOCs) shared by the infosec community on Twitter/X.",
        identity_class="system",
        contact_info="https://tweetfeed.live/",
    )


def create_tweetfeed_marking_definition():
    """Create the TweetFeed marking definition object."""
    return create_marking_definition_object("Origin: https://api.tweetfeed.live/v1/")


def build_feed_url(start_date: Optional[datetime] = None) -> str:
    """Build the TweetFeed API URL."""
    if start_date is None:
        return f"{TWEETFEED_API_BASE}/year"
    since_value = start_date.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{TWEETFEED_API_BASE}/since/{since_value}"


def fetch_tweetfeed_data(data_dir: Path, start_date: Optional[datetime] = None):
    """Fetch TweetFeed IOC records and save the raw JSON response."""
    feed_url = build_feed_url(start_date)
    logger.info(f"Fetching TweetFeed data from: {feed_url}")

    response = requests.get(feed_url, timeout=300)
    response.raise_for_status()

    raw_path = data_dir / RAW_FEED_FILENAME
    raw_path.write_bytes(response.content)
    logger.info(f"Saved raw feed to {raw_path}")

    return response.json()


def parse_record_timestamp(value: str) -> datetime:
    """Parse a TweetFeed timestamp into UTC."""
    dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=UTC)


def normalize_tag(tag: str) -> str:
    """Normalize TweetFeed tags to compact labels."""
    return tag.strip().lstrip("#@").lower()


def build_indicator_pattern(record: Dict[str, str]) -> str:
    """Create a STIX pattern for a TweetFeed IOC record."""
    value = record["value"].strip()
    ioc_type = record["type"].strip().lower()

    if ioc_type == "domain":
        return f"[domain-name:value = {StringConstant(value)}]"
    if ioc_type == "ip":
        return f"[ipv4-addr:value = {StringConstant(value)}]"
    if ioc_type == "url":
        return f"[url:value = {StringConstant(value)}]"
    if ioc_type == "md5":
        return f"[file:hashes.'MD5' = {StringConstant(value)}]"
    if ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = {StringConstant(value)}]"

    raise ValueError(f"Unsupported TweetFeed IOC type: {record['type']}")


def create_user_account_object(record: Dict[str, str], namespace: str) -> UserAccount:
    """Create a deterministic user-account SCO for the posting account."""
    user = record["user"].strip().lstrip("@")
    user_id = f"user-account--{generate_uuid5(f'tweetfeed:user:{user.lower()}', namespace)}"
    return UserAccount(
        id=user_id,
        account_type="twitter",
        display_name=user,
    )


def create_sco_object(record: Dict[str, str]):
    """Create the SCO that matches the IOC record type."""
    value = record["value"].strip()
    ioc_type = record["type"].strip().lower()

    if ioc_type == "domain":
        return DomainName(value=value)
    if ioc_type == "ip":
        return IPv4Address(value=value)
    if ioc_type == "url":
        return URL(value=value)
    if ioc_type == "md5":
        return File(hashes={"MD5": value})
    if ioc_type == "sha256":
        return File(hashes={"SHA-256": value})

    raise ValueError(f"Unsupported TweetFeed IOC type: {record['type']}")


def create_indicator_object(
    record: Dict[str, str], source_identity_id: str, source_marking_id: str
) -> Indicator:
    """Create an Indicator object for a TweetFeed IOC record."""
    record_time = parse_record_timestamp(record["date"])
    indicator_name = f"{record['type'].strip().upper()}: {record['value'].strip()}"
    indicator_id = "indicator--" + generate_uuid5(
        "|".join(
            [
                record_time.isoformat(),
                record["user"].strip().lstrip("@").lower(),
                record["type"].strip().lower(),
                record["value"].strip(),
                record.get("tweet", ""),
            ]
        ),
        namespace=source_marking_id,
    )

    labels = sorted(
        {
            normalized
            for tag in record.get("tags", [])
            if (normalized := normalize_tag(tag))
        }
    )

    return Indicator(
        id=indicator_id,
        created_by_ref=source_identity_id,
        created=record_time,
        modified=record_time,
        valid_from=record_time,
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=build_indicator_pattern(record),
        pattern_type="stix",
        labels=labels or None,
        external_references=[
            {"source_name": "x_url", "url": record["tweet"]},
        ],
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            source_marking_id,
        ],
    )


def create_stix_objects(
    records: List[Dict[str, str]],
    source_identity,
    source_marking,
):
    """Create TweetFeed STIX objects from raw IOC records."""
    stix_objects = []
    seen_user_ids = set()
    seen_sco_ids = set()

    source_identity_id = source_identity["id"]
    source_marking_id = source_marking["id"]

    for idx, record in enumerate(records, start=1):
        if idx % 1000 == 0:
            logger.info(f"Processed {idx}/{len(records)} TweetFeed records...")

        record_time = parse_record_timestamp(record["date"])

        user_account = create_user_account_object(record, source_marking_id)
        if user_account.id not in seen_user_ids:
            seen_user_ids.add(user_account.id)
            stix_objects.append(user_account)

        sco_object = create_sco_object(record)
        if sco_object.id not in seen_sco_ids:
            seen_sco_ids.add(sco_object.id)
            stix_objects.append(sco_object)

        indicator = create_indicator_object(record, source_identity_id, source_marking_id)
        stix_objects.append(indicator)

        stix_objects.append(
            make_relationship(
                source_ref=indicator["id"],
                target_ref=sco_object["id"],
                relationship_type="indicates",
                created_by_ref=source_identity_id,
                created=record_time,
                modified=record_time,
                marking_refs=indicator["object_marking_refs"],
                external_references=indicator["external_references"],
            )
        )

    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Convert TweetFeed IOC data to STIX 2.1 format"
    )
    parser.add_argument(
        "--start-date",
        "--start_date",
        "--since-date",
        "--since_date",
        dest="start_date",
        type=parse_since_date,
        help="Only process IOCs added since this date (YYYY-MM-DD format)",
    )

    args = parser.parse_args()

    try:
        output_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
        feeds2stix_marking = fetch_external_objects()

        source_identity = create_tweetfeed_identity()
        source_marking = create_tweetfeed_marking_definition()

        records = fetch_tweetfeed_data(data_dir, start_date=args.start_date)

        logger.info("Creating STIX objects...")
        stix_objects = create_stix_objects(records, source_identity, source_marking)

        logger.info("Creating STIX bundle...")
        bundle = create_bundle_with_metadata(
            stix_objects,
            source_identity,
            source_marking,
            feeds2stix_marking,
        )

        bundle_path = save_bundle_to_file(bundle, output_dir, "tweetfeed")

        logger.info(
            f"Successfully created STIX bundle with {len(stix_objects)} objects"
        )

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            with open(github_output, "a") as f:
                f.write(f"bundle_path={bundle_path}\n")

        return 0

    except Exception as e:
        logger.error(f"Error processing TweetFeed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
