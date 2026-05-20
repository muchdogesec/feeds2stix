#!/usr/bin/env python3

import argparse
from dataclasses import dataclass
from functools import lru_cache
import io
import json
import logging
import os
from pathlib import Path
import sys
from collections import defaultdict
from datetime import UTC, datetime
import gzip

import requests
from stix2 import URL, AutonomousSystem, Indicator, IPv4Address, Malware
from stix2.patterns import StringConstant
import csv

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
    parse_since_date,
    parse_until_date,
)
from helpers.generics import BaseEntry, Group
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

FEED_URL = "https://tracker.viriback.com/dump.php"
OUTPUT_DIR = "outputs/viriback"
# PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["viriback"]
ATTACK_PATTERN_ID = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]
STATIC_DATE = datetime(2020, 1, 1)


def create_viriback_identity():
    return create_identity_object(
        name="Viriback",
        description=(
            "Viriback is a collaborative clearing house for data and information about phishing on the"
            " Internet. Also, Viriback provides an open API for developers and researchers to integrate"
            " anti-phishing data into their applications at no charge."
        ),
        identity_class="system",
        contact_info="https://www.viriback.com/",
    )


def create_viriback_marking_definition():
    return create_marking_definition_object(f"Origin: {FEED_URL}")


def fetch_viriback_data(data_dir: Path):
    url = FEED_URL
    headers = {"User-Agent": "feeds2stix/1.0"}
    logger.info(f"Fetching Viriback data from {url}")
    response = requests.get(url, headers=headers, timeout=120)
    response.raise_for_status()

    raw_path = data_dir / "viriback_dump.csv"
    raw_path.write_bytes(response.content)

    return response.text.splitlines()


@dataclass(slots=True)
class Entry(BaseEntry):
    family: str
    url: str
    ip: str

def group_entries_by_family(entries: list[Entry], start_date, until_date):
    Group.start_date = start_date or Group.start_date
    Group.end_date = until_date or Group.end_date
    groups = defaultdict(Group[Entry])
    for entry in entries:
        group = groups[entry.family]
        group.append(entry)
    return groups

def parse_entries(lines):
    lines[0] = lines[0].lower()
    for line in csv.DictReader(lines):
        first_seen = datetime.strptime(line.pop('firstseen'), "%d-%m-%Y").replace(tzinfo=UTC)
        line.update(modified=first_seen, created=first_seen)
        yield Entry(**line)


def create_objects_for_entry(entry: Entry, object_marking_refs, source_identity_id):
    url = URL(
        value=entry.url,
    )
    ip_addr = IPv4Address(
        value=entry.ip
    )
    indicator_name = "URL: " + entry.url
    indicator_id = f"indicator--{generate_uuid5(indicator_name, object_marking_refs[2])}"

    indicator = indicator = Indicator(
        id=indicator_id,
        created_by_ref=source_identity_id,
        created=entry.created,
        modified=entry.created,
        valid_from=entry.created,
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=f"[url:value={StringConstant(url.value)}]",
        pattern_type="stix",
        object_marking_refs=object_marking_refs,
    )
    rel_url_ip = make_relationship(
        url.id,
        ip_addr.id,
        "related-to",
        marking_refs=indicator.object_marking_refs,
        created=indicator.created,
        modified=indicator.modified,
        created_by_ref=indicator.created_by_ref,
    )
    rel_indicator = make_relationship(
        indicator.id,
        url.id,
        "indicates",
        marking_refs=indicator.object_marking_refs,
        created=indicator.created,
        modified=indicator.modified,
        created_by_ref=indicator.created_by_ref,
    )

    return (url, ip_addr, indicator, rel_url_ip, rel_indicator), ((entry.created, url.id), (entry.created, indicator_id))


def process_entries_for_malware(
    family_name: str,
    group: Group,
    source_identity: object,
    source_marking: object,
    feeds2stix_marking: dict,
    start_date: datetime = None,
):
    """Process records for a single family and create a bundle."""
    logger.info(f"Processing family: {family_name} with {len(group)} records")

    all_stix_objects = []
    obj_ids = []

    object_marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        source_marking["id"],
    ]
    for record in group.entries:
        objects, rels_to_create = create_objects_for_entry(record, object_marking_refs=object_marking_refs, source_identity_id=source_identity.id)
        all_stix_objects.extend(objects)
        obj_ids.extend(rels_to_create)

    # Create malware object if family is not unknown
    malware_objects = create_malware_objects(family_name, group, obj_ids, created_by_ref=source_identity.id, marking_refs=object_marking_refs)
    all_stix_objects.extend(malware_objects)
    # only save bundles if indicators were created
    return all_stix_objects

def create_malware_objects(malware_name, group: Group, rels_to_create: list[tuple[datetime,str]], created_by_ref, marking_refs):
    malware_id = generate_uuid5(malware_name, namespace=marking_refs[2])
    malware = Malware(
        id="malware--" + malware_id,
        created_by_ref=created_by_ref,
        created=group.created,
        modified=group.modified,
        name=malware_name,
        malware_types=["unknown"],
        is_family=True,
        object_marking_refs=marking_refs,
    )
    yield malware

    for timestamp, stix_id in rels_to_create:
        rel_type = "indicates" if stix_id.startswith("indicator") else "related-to"
        rel = make_relationship(
            source_ref=stix_id,
            target_ref=malware.id,
            relationship_type=rel_type,
            created_by_ref=created_by_ref,
            marking_refs=marking_refs,
            created=timestamp,
            modified=timestamp,
        )
        yield rel




def main():
    parser = argparse.ArgumentParser(
        description="Process Viriback feed and generate STIX bundles"
    )
    parser.add_argument(
        "--since-date",
        "--since_date",
        type=parse_since_date,
        help="Only process entries with submission_time on or after this date (ISO format)",
    )
    parser.add_argument(
        "--until-date",
        "--until_date",
        type=parse_until_date,
        help="Only process entries with modification time on or before this date (ISO format)",
    )
    args = parser.parse_args()

    bundles_dir, data_dir = setup_output_directory(OUTPUT_DIR, clean=True)

    identity = create_viriback_identity()
    marking = create_viriback_marking_definition()
    feeds2stix_marking = fetch_external_objects()

    data = fetch_viriback_data(data_dir)
    logger.info(f"Fetched {len(data)} entries from Viriback")
    entries = list(parse_entries(data))
    grouped = group_entries_by_family(entries, start_date=args.since_date, until_date=args.until_date)
    bundle_paths = []


    for family, group in grouped.items():
        if not group:
            continue
        logger.info(f"Processing part {family} of {len(grouped)} with {len(entries)} entries...")

        all_stix_objects = process_entries_for_malware(
            family,
            group, identity, marking, feeds2stix_marking
        )
        logger.info(f"Created {len(all_stix_objects)} STIX objects for part {family}")
        bundle = create_bundle_with_metadata(
            stix_objects=all_stix_objects,
            source_identity=identity,
            source_marking=marking,
            feeds2stix_marking=feeds2stix_marking,
        )
        bundle_filename = f"viriback_{family}"
        path = save_bundle_to_file(
            bundle, bundles_dir, bundle_filename, add_timestamp=False
        )
        bundle_paths.append(path)

    logger.info(f"Processing complete. Created {len(bundle_paths)} bundles.")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            f.write(f"bundle_count={len(bundle_paths)}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        exit(1)
