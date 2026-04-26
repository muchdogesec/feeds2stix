#!/usr/bin/env python3

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
from collections import defaultdict
from datetime import UTC, datetime, timezone

import requests
from git import Repo
from stix2 import URL, Bundle, Indicator
from stix2.patterns import StringConstant

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
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

GITHUB_REPO_URL = "https://github.com/openphish/public_feed"
FEED_FILE_PATH = "feed.txt"
BASE_OUTPUT_DIR = "outputs/openphish"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["openphish"]


def create_openphish_identity():
    """Create the OpenPhish identity object"""
    return create_identity_object(
        name="OpenPhish",
        description="Timely. Accurate. Relevant Phishing Intelligence.",
        identity_class="organization",
        contact_info="https://openphish.com/index.html",
    )


def create_openphish_marking_definition():
    """Create a marking definition for OpenPhish feed"""
    return create_marking_definition_object(
        f"Origin: https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    )


def clone_or_update_repo(repo_path, repo_url):
    """Clone the repository or pull latest changes if it already exists"""
    if os.path.exists(repo_path):
        logger.info(
            f"Repository already exists at {repo_path}, pulling latest changes..."
        )
        repo = Repo(repo_path)
        origin = repo.remotes.origin
        origin.pull()
    else:
        logger.info(f"Cloning repository from {repo_url}...")
        repo = Repo.clone_from(repo_url, repo_path)
    logger.info("Repository ready")
    return repo


def get_lines_since_date(repo, file_path, since_date=None):
    """
    Get all lines from the file along with their first seen commit times.

    Args:
        repo: Git repository object
        file_path: Path to the file within the repository
        since_date: Optional datetime to filter commits (only process commits after this date)

    Returns:
        dict: Mapping of line_content -> (commit_hash, commit_date)
    """
    logger.info(f"Analyzing git history for {file_path}...")

    commits = list(repo.iter_commits(paths=file_path))
    commits.reverse()  # Process from oldest to newest

    line_first_seen = {}  # line_content -> (commit_hash, date)
    previous_lines = set()

    for idx, commit in enumerate(commits, 1):
        if idx % 100 == 0:
            logger.info(f"Processed {idx}/{len(commits)} commits...")

        try:
            blob = commit.tree / file_path
            content = blob.data_stream.read().decode("utf-8", errors="ignore")
            current_lines = set()
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    current_lines.add(line)
        except Exception:
            continue  # file may not exist in early commits

        new_lines = current_lines - previous_lines

        for line in new_lines:
            if line and not line.startswith("#") and line not in line_first_seen:
                line_first_seen[line] = (
                    commit.hexsha[:8],
                    datetime.fromtimestamp(commit.committed_date, UTC),
                )

        previous_lines = current_lines

    logger.info(f"Found {len(line_first_seen)} unique URLs with commit times")
    if since_date:
        line_first_seen = {
            line: (sha, date)
            for line, (sha, date) in line_first_seen.items()
            if date >= since_date
        }
        logger.info(f"{len(line_first_seen)} URLs added since {since_date}")
    return line_first_seen


def create_stix_objects(url_data_for_date, openphish_identity, openphish_marking):
    """
    Create STIX objects for phishing URLs with their respective commit times.

    Args:
        url_data_for_date: dict mapping url -> (commit_hash, commit_date) for a specific date
        openphish_identity: Identity object for OpenPhish
        openphish_marking: Marking definition for OpenPhish

    Returns:
        list: STIX objects
    """
    stix_objects = []

    openphish_marking_id = openphish_marking["id"]
    openphish_identity_id = openphish_identity["id"]

    logger.info(f"Creating STIX objects for {len(url_data_for_date)} phishing URLs...")

    for idx, (url_value, (commit_hash, commit_time)) in enumerate(
        url_data_for_date.items(), 1
    ):
        if idx % 1000 == 0:
            logger.info(f"Processed {idx}/{len(url_data_for_date)} URLs...")

        # Create URL observable
        url_obj = URL(value=url_value)

        # Create Indicator
        indicator_name = f"URL: {url_value}"
        indicator_id = generate_uuid5(indicator_name, openphish_marking_id)
        indicator_id_full = f"indicator--{indicator_id}"

        indicator = Indicator(
            id=indicator_id_full,
            created_by_ref=openphish_identity_id,
            created=commit_time,
            modified=commit_time,
            valid_from=commit_time,
            indicator_types=["malicious-activity"],
            name=indicator_name,
            pattern=f"[url:value={StringConstant(url_value)}]",
            pattern_type="stix",
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                openphish_marking_id,
            ],
        )

        # Create relationship between indicator and URL
        relationship = make_relationship(
            source_ref=indicator_id_full,
            target_ref=url_obj.id,
            relationship_type="indicates",
            created_by_ref=openphish_identity_id,
            created=commit_time,
            modified=commit_time,
            marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                openphish_marking_id,
            ],
        )

        stix_objects.extend([url_obj, indicator, relationship])

    logger.info(f"Created {len(stix_objects)} STIX objects")
    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Process OpenPhish feed and generate STIX bundle"
    )

    parser.add_argument(
        "--since-date",
        "--since_date",
        type=datetime.fromisoformat,
        help="Only process URLs added since this date (YYYY-MM-DD format)",
    )

    args = parser.parse_args()

    # Parse since_date if provided
    since_date = args.since_date and args.since_date.replace(tzinfo=UTC)

    # Setup output directory
    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    bundle_paths = []

    # Create identity and marking definition objects
    openphish_identity = create_openphish_identity()
    openphish_marking = create_openphish_marking_definition()

    # Fetch external objects
    feeds2stix_marking = fetch_external_objects()
    # Use temporary directory for repo clone
    repo_clone_path = os.path.join(data_dir, "openphish_repo")

    # Clone or update repository
    repo = clone_or_update_repo(repo_clone_path, GITHUB_REPO_URL)

    # Get URLs with their commit times
    url_data = get_lines_since_date(repo, FEED_FILE_PATH, since_date)

    # Group URLs by date first (memory efficient - just references)

    urls_by_date = group_urls_by_date(url_data)

    # Process each date bucket separately to avoid holding too many objects in memory
    for date_key in sorted(urls_by_date.keys()):
        url_data_for_date = urls_by_date[date_key]
        logger.info(
            f"Processing date bucket {date_key} with {len(url_data_for_date)} URLs..."
        )
        bundle = process_urls_for_date(
            url_data_for_date,
            openphish_identity,
            openphish_marking,
            feeds2stix_marking,
        )
        # Save bundle with date in filename
        bundle_filename = f"openphish_{date_key}"
        bundle_path = save_bundle_to_file(
            bundle, bundles_dir, bundle_filename, add_timestamp=False
        )
        bundle_paths.append(bundle_path)

        logger.info(f"Processing complete. Created {len(bundle_paths)} bundles.")

    # Set GitHub Actions output
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            f.write(f"bundle_count={len(bundle_paths)}\n")


def process_urls_for_date(
    url_data_for_date,
    openphish_identity,
    openphish_marking,
    feeds2stix_marking,
):

    # Create STIX objects for this date
    stix_objects = create_stix_objects(
        url_data_for_date, openphish_identity, openphish_marking
    )

    # Create bundle
    bundle = create_bundle_with_metadata(
        stix_objects=stix_objects,
        source_identity=openphish_identity,
        source_marking=openphish_marking,
        feeds2stix_marking=feeds2stix_marking,
    )

    return bundle


def group_urls_by_date(url_data):
    urls_by_date = defaultdict(dict)

    logger.info("Grouping URLs by date...")
    for url_value, (commit_hash, commit_time) in url_data.items():
        date_key = commit_time.strftime("%Y%m%d_%H")
        urls_by_date[date_key][url_value] = (commit_hash, commit_time)

    logger.info(f"Grouped {len(url_data)} URLs into {len(urls_by_date)} date buckets")
    return urls_by_date


if __name__ == "__main__":
    main()
