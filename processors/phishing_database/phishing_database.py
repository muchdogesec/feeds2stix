#!/usr/bin/env python3

import argparse
from collections import defaultdict
import logging
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from git import Repo
from stix2 import DomainName, IPv4Address, Indicator, URL
from stix2.patterns import StringConstant

from helpers.kb_fetch import fetch_enterprise_attack_object
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
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

REPO_URL = "https://github.com/Phishing-Database/Phishing.Database"
BASE_OUTPUT_DIR = "outputs/phishing_database"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["phishing_database"]
T1566_STIX_ID = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]


def create_phishing_database_identity():
    return create_identity_object(
        name="Phishing.Database",
        description=(
            "The Phishing.Database project is a comprehensive and regularly updated "
            "repository designed to help the community identify and mitigate "
            "phishing threats."
        ),
        identity_class="organization",
        contact_info="https://github.com/Phishing-Database/Phishing.Database",
    )


def create_phishing_database_marking_definition():
    return create_marking_definition_object(
        "Origin: https://github.com/Phishing-Database/Phishing.Database"
    )


def clone_or_update_repo(repo_path, repo_url):
    if os.path.exists(repo_path):
        logger.info("Repository already exists at %s, pulling latest changes...", repo_path)
        repo = Repo(repo_path)
        repo.remotes.origin.pull()
    else:
        logger.info("Cloning repository from %s...", repo_url)
        repo = Repo.clone_from(repo_url, repo_path)
    logger.info("Repository ready")
    logger.info("HEAD commit id: %s", repo.head.commit.hexsha)
    return repo


def get_target_feed_files(repo_path):
    target_files = []
    for top_level in Path(repo_path).iterdir():
        if not top_level.is_dir():
            continue
        if not (
            top_level.name.endswith("-ACTIVE") or top_level.name.endswith("-INACTIVE")
        ):
            continue
        for txt_file in top_level.rglob("*.txt"):
            if txt_file.is_file():
                target_files.append(str(txt_file.relative_to(repo_path)))
    target_files.sort()
    return target_files


def parse_feed_lines(content):
    values = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.add(line)
    return values


def get_lines_first_seen(repo, file_path):
    commits = list(repo.iter_commits(paths=file_path))
    commits.reverse()

    line_first_seen = {}
    previous_lines = set()

    for commit in commits:
        try:
            blob = commit.tree / file_path
            content = blob.data_stream.read().decode("utf-8", errors="ignore")
            current_lines = parse_feed_lines(content)
        except Exception:
            continue

        new_lines = current_lines - previous_lines
        for value in new_lines:
            if value not in line_first_seen:
                line_first_seen[value] = datetime.fromtimestamp(commit.committed_date, UTC)
        previous_lines = current_lines

    return line_first_seen

OBSERVABLE_MAP = {
    "url": "links",
    "domain-name": "domains",
    "ipv4-addr": "ips",
}

def infer_observable_type(file_path):
    top_dir = Path(file_path).parts[0].lower()
    if "links" in top_dir:
        return "url"
    if "domains" in top_dir:
        return "domain-name"
    if "ips" in top_dir:
        return "ipv4-addr"
    raise ValueError(f"Unsupported observable type for path: {file_path}")


def infer_status(file_path):
    top_dir = Path(file_path).parts[0]
    return "inactive" if top_dir.endswith("-INACTIVE") else "active"


def collect_observables(repo, repo_path, cutoff_date=None, type=None):
    records = {}
    target_files = get_target_feed_files(repo_path)
    logger.info("Found %s target .txt files in ACTIVE/INACTIVE directories", len(target_files))

    for file_path in target_files:
        observable_type = infer_observable_type(file_path)
        if type and OBSERVABLE_MAP[observable_type] != type:
            continue
        status = infer_status(file_path)
        line_first_seen = get_lines_first_seen(repo, file_path)

        for value, event_time in line_first_seen.items():
            key = (observable_type, value)
            record = records.setdefault(
                key,
                {
                    "observable_type": observable_type,
                    "value": value,
                    "first_seen": None,
                    "active_seen": None,
                    "inactive_seen": None,
                },
            )

            if record["first_seen"] is None or event_time < record["first_seen"]:
                record["first_seen"] = event_time

            if status == "inactive":
                if record["inactive_seen"] is None or event_time < record["inactive_seen"]:
                    record["inactive_seen"] = event_time
            else:
                if record["active_seen"] is None or event_time < record["active_seen"]:
                    record["active_seen"] = event_time

    filtered_records = []
    for record in records.values():
        if (
            cutoff_date
            and record["inactive_seen"]
            and record["inactive_seen"] < cutoff_date
        ):
            continue

        record["modified"] = record["inactive_seen"] or record["active_seen"] or record["first_seen"]
        record["revoked"] = record["inactive_seen"] is not None
        filtered_records.append(record)

    return filtered_records


def filter_records_by_date(records, since_date=None, until_date=None):
    filtered = []
    for record in records:
        modified = record["modified"]
        if since_date and modified < since_date:
            continue
        if until_date and modified > until_date:
            continue
        filtered.append(record)
    filtered.sort(key=lambda x: x["modified"])
    return filtered


def group_records_by_month_with_parts(records, max_per_bundle=500):
    by_month = defaultdict(list)
    for record in records:
        month_key = (
            OBSERVABLE_MAP[record["observable_type"]]
            + "_"
            + record["modified"].strftime("%Y%m")
        )
        by_month.setdefault(month_key, []).append(record)

    grouped = []
    for month_key in sorted(by_month):
        month_records = by_month[month_key]
        if len(month_records) <= max_per_bundle:
            grouped.append((month_key, month_records))
            continue

        part = 1
        total_parts = (len(month_records) + max_per_bundle - 1) // max_per_bundle
        just_length = len(str(total_parts))
        for idx in range(0, len(month_records), max_per_bundle):
            grouped.append(
                (f"{month_key}p{str(part).zfill(just_length)}", month_records[idx : idx + max_per_bundle])
            )
            part += 1
    return grouped


def create_observable(record):
    if record["observable_type"] == "url":
        return URL(value=record["value"])
    if record["observable_type"] == "domain-name":
        return DomainName(value=record["value"].lower())
    if record["observable_type"] == "ipv4-addr":
        return IPv4Address(value=record["value"])
    raise ValueError(f"Unsupported observable type: {record['observable_type']}")


def create_indicator(record, identity_id, marking_id, object_marking_refs):
    if record["observable_type"] == "url":
        indicator_name = f"URL: {record['value']}"
        pattern = f"[url:value={StringConstant(record['value'])}]"
    elif record["observable_type"] == "domain-name":
        indicator_name = f"Domain Name: {record['value']}"
        pattern = f"[domain-name:value={StringConstant(record['value'].lower())}]"
    else:
        indicator_name = f"IPv4: {record['value']}"
        pattern = f"[ipv4-addr:value={StringConstant(record['value'])}]"

    indicator_id = f"indicator--{generate_uuid5(indicator_name, marking_id)}"
    return Indicator(
        id=indicator_id,
        created_by_ref=identity_id,
        created=record["first_seen"],
        modified=record["modified"],
        valid_from=record["first_seen"],
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=pattern,
        pattern_type="stix",
        revoked=record["revoked"],
        object_marking_refs=object_marking_refs,
    )


def create_stix_objects(records, identity, marking):
    stix_objects = []
    object_marking_refs = OBJECT_MARKING_REFS_BASE + [marking["id"]]
    identity_id = identity["id"]

    for record in records:
        observable = create_observable(record)
        indicator = create_indicator(record, identity_id, marking["id"], object_marking_refs)

        stix_objects.extend([observable, indicator])
        stix_objects.append(
            make_relationship(
                source_ref=indicator.id,
                target_ref=observable.id,
                relationship_type="indicates",
                created_by_ref=identity_id,
                created=record["first_seen"],
                modified=record["modified"],
                marking_refs=object_marking_refs,
            )
        )
        stix_objects.append(
            make_relationship(
                source_ref=indicator.id,
                target_ref=T1566_STIX_ID,
                relationship_type="indicates",
                created_by_ref=identity_id,
                created=record["first_seen"],
                modified=record["modified"],
                marking_refs=object_marking_refs,
                description=f"{record['value']} is known to be used for Phishing (T1566)",
            )
        )

    return stix_objects


def process_records_for_group(records, identity, marking, feeds2stix_marking):
    stix_objects = [fetch_enterprise_attack_object(T1566_STIX_ID)] + create_stix_objects(
        records, identity, marking
    )
    return create_bundle_with_metadata(
        stix_objects=stix_objects,
        source_identity=identity,
        source_marking=marking,
        feeds2stix_marking=feeds2stix_marking,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Process Phishing.Database feed and generate STIX bundles"
    )
    parser.add_argument(
        "--since-date",
        "--since_date",
        type=parse_since_date,
        help="Only process records with modified time on or after this date (YYYY-MM-DD format)",
    )
    parser.add_argument(
        "--until-date",
        "--until_date",
        type=parse_until_date,
        help="Only process records with modified time on or before this date (YYYY-MM-DD format)",
    )
    parser.add_argument(
        "--cutoff-date",
        "--cutoff_date",
        type=parse_since_date,
        help="Skip records that became inactive before this date (YYYY-MM-DD format)",
    )
    parser.add_argument(
        "--type",
        choices=["links", "domains", "ips"],
        help="Process only one observable type: links, domains, or ips",
        default=None,
    )
    args = parser.parse_args()

    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    identity = create_phishing_database_identity()
    marking = create_phishing_database_marking_definition()
    feeds2stix_marking = fetch_external_objects()

    repo_path = os.path.join(data_dir, "phishing_database_repo")
    repo = clone_or_update_repo(repo_path, REPO_URL)

    records = collect_observables(repo, repo_path, args.cutoff_date, type=args.type)
    records = filter_records_by_date(records, args.since_date, args.until_date)
    grouped = group_records_by_month_with_parts(records, max_per_bundle=500)

    bundle_paths = []
    for group_key, group_records in grouped:
        bundle = process_records_for_group(
            group_records, identity, marking, feeds2stix_marking
        )
        bundle_path = save_bundle_to_file(
            bundle, bundles_dir, f"phishing_database_{group_key}", add_timestamp=False
        )
        bundle_paths.append(bundle_path)

    output_kwargs = {
        "bundle_path": bundles_dir,
        "bundle_count": len(bundle_paths),
    }
    if records:
        latest_timestamp = max(record["modified"] for record in records)
        output_kwargs["latest_timestamp"] = latest_timestamp.isoformat()
    write_github_output(**output_kwargs)

    logger.info("Processing complete. Created %s bundles.", len(bundle_paths))


if __name__ == "__main__":
    main()
