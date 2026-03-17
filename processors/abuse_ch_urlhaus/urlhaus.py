#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests
from stix2 import (
    URL,
    Bundle,
    Indicator,
)
from stix2.patterns import StringConstant

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.utils import (
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    make_relationship,
    save_bundle_to_file,
    setup_output_directory,
)

# Constants
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OUTPUT_DIR = "outputs/abuse_ch_urlhaus"

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def create_urlhaus_identity():
    """Create the abuse.ch identity object."""
    return create_identity_object(
        name="abuse.ch",
        description="abuse.ch has been effecting change on cybercrime for almost twenty years, owing to global recognition of our identified and tracked cyber threat signals. Supported by a community of 15,000 specialist researchers, abuse.ch's independent intelligence is relied on by security researchers, network operators and law enforcement agencies.",
        identity_class="organization",
        contact_info="https://abuse.ch/",
    )


def create_urlhaus_marking_definition():
    """Create the URLhaus marking definition."""
    return create_marking_definition_object(
        statement="Origin data source: https://urlhaus.abuse.ch/downloads/csv_recent/"
    )


def download_urlhaus_data(data_dir: Path) -> Path:
    """Download the URLhaus CSV data."""
    logger.info(f"Downloading URLhaus data from {URLHAUS_URL}")
    response = requests.get(URLHAUS_URL, timeout=300)
    response.raise_for_status()

    # Save CSV data
    csv_path = data_dir / "urlhaus_data.csv"
    with open(csv_path, "wb") as f:
        f.write(response.content)
    logger.info(f"CSV data saved to {csv_path}")
    return csv_path


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse timestamp from CSV format to datetime object."""
    # Format: "2026-02-26 13:41:09"
    if not timestamp_str or timestamp_str.strip() == "":
        return None
    dt = datetime.strptime(timestamp_str.strip(), "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def parse_csv_data(
    csv_path: Path, start_date: Optional[datetime] = None
) -> tuple[datetime, List[Dict[str, str]]]:
    """Parse CSV data, skipping header comments and empty lines."""
    records = []
    latest_timestamp = start_date

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)

        for row in reader:
            # Skip comment lines and empty lines
            if not row or row[0].startswith("#"):
                continue

            # Parse the row
            # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
            assert len(row) == 9

            record = {
                "id": row[0],
                "dateadded": parse_timestamp(row[1]),
                "url": row[2],
                "url_status": row[3],
                "last_online": parse_timestamp(row[4]) if row[4] else None,
                "threat": row[5],
                "tags": row[6],
                "urlhaus_link": row[7],
                "reporter": row[8],
            }
            if start_date and record["dateadded"] < start_date:
                continue

            records.append(record)
            if latest_timestamp is None or record["dateadded"] > latest_timestamp:
                latest_timestamp = record["dateadded"]

    logger.info(f"Parsed {len(records)} records from CSV")
    return latest_timestamp, records


def create_url_object(url_value: str) -> URL:
    """Create a URL object."""
    return URL(value=url_value)


def create_indicator_object(
    record: Dict[str, str],
    source_identity_id: str,
    source_marking_id: str,
    object_marking_refs: List[str],
) -> Indicator:
    """Create an Indicator object from a URL record."""
    indicator_name = f"URL: {record['url']}"
    pattern = f"[ url:value = {StringConstant(record['url'])} ]"

    # Parse tags
    tags = []
    if record["tags"] and record["tags"] != "None":
        tags = [tag.strip() for tag in record["tags"].split(",")]

    # Add threat type as first label
    labels = []
    if record["threat"]:
        labels.append(record["threat"])
    labels.extend(tags)

    # Determine if revoked (offline)
    revoked = record["url_status"] == "offline"

    # Use last_online for modified, or dateadded if not available
    modified = record["last_online"] if record["last_online"] else record["dateadded"]

    external_refs = [
        {
            "source_name": "urlhaus_link",
            "url": record["urlhaus_link"],
        }
    ]

    indicator_id = "indicator--" + generate_uuid5(
        indicator_name, namespace=source_marking_id
    )

    indicator = Indicator(
        id=indicator_id,
        created_by_ref=source_identity_id,
        created=record["dateadded"],
        modified=modified,
        valid_from=record["dateadded"],
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=pattern,
        pattern_type="stix",
        revoked=revoked,
        labels=labels if labels else None,
        external_references=external_refs,
        object_marking_refs=object_marking_refs,
    )

    return indicator


def process_records(
    records: List[Dict[str, str]],
    source_identity: object,
    source_marking: object,
) -> str:
    """Process records and create a single bundle."""
    logger.info(f"Processing {len(records)} records")

    all_stix_objects = []

    object_marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        source_marking["id"],
    ]

    for record in records:
        url_obj = create_url_object(record["url"])
        all_stix_objects.append(url_obj)

        indicator = create_indicator_object(
            record,
            source_identity["id"],
            source_marking["id"],
            object_marking_refs,
        )
        all_stix_objects.append(indicator)

        relationship = make_relationship(
            source_ref=indicator.id,
            target_ref=url_obj.id,
            relationship_type="indicates",
            created_by_ref=source_identity["id"],
            marking_refs=object_marking_refs,
            created=indicator.created,
            modified=indicator.modified,
        )
        all_stix_objects.append(relationship)
    return all_stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Process URLhaus feed and generate STIX bundles"
    )
    parser.add_argument(
        "--start-date",
        "--start_date",
        type=datetime.fromisoformat,
        help="Only include records with dateadded after this date (YYYY-MM-DD[T[HH:MM[:SS]]])",
    )

    args = parser.parse_args()
    args.start_date = args.start_date and args.start_date.replace(tzinfo=timezone.utc)

    # Setup output directory
    bundles_dir, data_dir = setup_output_directory(OUTPUT_DIR, clean=True)

    # Create identity and marking definition objects
    source_identity = create_urlhaus_identity()
    source_marking = create_urlhaus_marking_definition()

    # Fetch external objects
    feeds2stix_marking = fetch_external_objects()

    # Download data
    csv_path = download_urlhaus_data(data_dir)
    # Parse CSV
    latest_timestamp, records = parse_csv_data(csv_path, start_date=args.start_date)

    # Process records
    all_stix_objects = process_records(
        records,
        source_identity,
        source_marking,
    )

    logger.info("Processing complete")
    logger.info(f"Creating bundle with {len(all_stix_objects)} objects...")
    bundle = create_bundle_with_metadata(
        all_stix_objects,
        source_identity,
        source_marking,
        feeds2stix_marking,
    )

    bundle_path = save_bundle_to_file(
        bundle,
        bundles_dir,
        "urlhaus",
    )

    logger.info(
        f"Processing complete. Created 1 bundle with {len(all_stix_objects)} objects."
    )

    # Set GitHub Actions output
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundle_path}\n")
            if latest_timestamp:
                f.write(f"latest_timestamp={latest_timestamp.isoformat()}\n")


if __name__ == "__main__":
    main()
