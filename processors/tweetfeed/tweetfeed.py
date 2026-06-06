#!/usr/bin/env python3

import argparse
import csv
import glob
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
    parse_until_date,
    save_bundle_to_file,
    setup_output_directory,
    write_github_output,
)
from helpers.kb_fetch import fetch_enterprise_attack_object
from helpers.git_helper import clone_or_update_repo
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

TWEETFEED_API_BASE = "https://api.tweetfeed.live/v1"
BASE_OUTPUT_DIR = "outputs/tweetfeed"
RAW_FEED_FILENAME = "tweetfeed_data.json"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["tweetfeed"]
T1566_STIX_ID = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
GIT_REPO = "https://github.com/0xDanielLopez/TweetFeed"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


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
    dt = datetime.strptime(value, TIME_FORMAT)
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
    user_id = (
        f"user-account--{generate_uuid5(f'tweetfeed:user:{user.lower()}', namespace)}"
    )
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
    seen_attack_pattern_ids = set()

    source_identity_id = source_identity["id"]
    source_marking_id = source_marking["id"]

    for idx, record in enumerate(records, start=1):
        record_time = parse_record_timestamp(record["date"])
        user_account = create_user_account_object(record, source_marking_id)
        if user_account.id not in seen_user_ids:
            seen_user_ids.add(user_account.id)
            stix_objects.append(user_account)

        sco_object = create_sco_object(record)
        if sco_object.id not in seen_sco_ids:
            seen_sco_ids.add(sco_object.id)
            stix_objects.append(sco_object)

        indicator = create_indicator_object(
            record, source_identity_id, source_marking_id
        )
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
        stix_objects.append(
            make_relationship(
                target_ref=user_account["id"],
                source_ref=indicator["id"],
                relationship_type="related-to",
                created_by_ref=source_identity_id,
                created=record_time,
                modified=record_time,
                description="Indicator was created from post by @" + record["user"],
                marking_refs=indicator["object_marking_refs"],
                external_references=indicator["external_references"],
            )
        )

        labels = getattr(indicator, "labels", []) or []
        if "phishing" in labels:
            if T1566_STIX_ID not in seen_attack_pattern_ids:
                stix_objects.append(fetch_enterprise_attack_object(T1566_STIX_ID))
                seen_attack_pattern_ids.add(T1566_STIX_ID)
            stix_objects.append(
                make_relationship(
                    source_ref=indicator["id"],
                    target_ref=T1566_STIX_ID,
                    relationship_type="indicates",
                    created_by_ref=source_identity_id,
                    created=record_time,
                    modified=record_time,
                    description=(
                        f"{record['value']} is known to be used for Phishing (T1566)"
                    ),
                    marking_refs=indicator["object_marking_refs"],
                    external_references=indicator["external_references"][:1],
                )
            )
    return stix_objects


def get_data_for_time_range(repo_path, start_dt: datetime, end_dt: datetime):
    start_day_file = start_dt.strftime("%Y%m%d.csv")
    start_dt_str = start_dt.strftime(TIME_FORMAT)
    end_day_file = end_dt.strftime("%Y%m%d.csv")
    end_dt_str = end_dt.strftime(TIME_FORMAT)
    files = sorted(glob.glob(str(repo_path) + "/20*/*/*.csv"))

    for file in files:
        *_, month, name = file.split("/")
        if name < start_day_file or name > end_day_file:
            continue
        for record in load_data_from_csv(file, start_dt_str, end_dt_str):
            yield month, record


def group_data_by_month(records, max_per_bundle=500):
    bundle_records = []
    name = ""
    month_count = 0
    part = 1

    def clear_records():
        nonlocal month_count, part, bundle_records
        month_count -= month_count
        part += 1
        bundle_records = []

    for month, record in records:
        if not name.startswith(month):
            yield name, bundle_records
            clear_records()
            name = f"{month}p01"
            part = 1

        if month_count >= max_per_bundle:
            yield name, bundle_records
            clear_records()
            name = f"{month}p{part:02d}"
        month_count += 1
        bundle_records.append(record)
    yield name, bundle_records


def load_data_from_csv(path: Path, min_date, max_date):
    headers = [
        "date",
        "user",
        "type",
        "value",
        "tags",
        "tweet",
    ]
    headers_len = len(headers)
    with open(path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            assert len(row) == headers_len
            if row[0] < min_date or row[0] > max_date:
                continue
            record = dict(zip(headers, row))
            if not record["tweet"]:
                continue
            record["tags"] = tuple(x.strip("#") for x in record["tags"].split())
            yield record


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
        default=datetime(2020, 1, 1, tzinfo=UTC),
    )

    parser.add_argument(
        "--until-date",
        dest="until_date",
        type=parse_until_date,
        help="Only process IOCs added since this date (YYYY-MM-DD format)",
        default=datetime.now(UTC),
    )
    args = parser.parse_args()

    try:
        bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
        feeds2stix_marking = fetch_external_objects()
        bundle_paths = []

        source_identity = create_tweetfeed_identity()
        source_marking = create_tweetfeed_marking_definition()

        repo_path = data_dir / "tweetfeed.git/"
        repo = clone_or_update_repo(repo_path, GIT_REPO)

        data = get_data_for_time_range(
            repo_path, start_dt=args.start_date, end_dt=args.until_date
        )
        object_count = 0
        for bundle_name, records in group_data_by_month(data, max_per_bundle=1000):
            if not records:
                continue
            stix_objects = create_stix_objects(records, source_identity, source_marking)
            bundle = create_bundle_with_metadata(
                stix_objects,
                source_identity,
                source_marking,
                feeds2stix_marking,
            )
            bundle_path = save_bundle_to_file(
                bundle, bundles_dir, f"tweetfeed_{bundle_name}", add_timestamp=False
            )
            bundle_paths.append(bundle_path)
            logger.info(
                f"Successfully created STIX bundle with {len(stix_objects)} objects"
            )
            object_count += len(stix_objects)
        logger.info(
            f"Created total {len(bundle_paths)} bundles with {object_count} objects"
        )
        
        write_github_output(
            bundle_path=bundles_dir,
            bundle_count=len(bundle_paths),
        )
        return 0

    except Exception as e:
        logger.error(f"Error processing TweetFeed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
