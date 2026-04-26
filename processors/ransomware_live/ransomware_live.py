#!/usr/bin/env python3

import argparse
import logging
from datetime import UTC, datetime
import os
from ransomware2stix import __main__ as ransomware2stix_main

from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

from helpers.utils import (
    save_bundle_to_file,
    setup_output_directory,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


BASE_OUTPUT_DIR = "outputs/ransomware_live"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["ransomware_live"]

REQUIRED_ENV_VARS = [
    "CTIBUTLER_BASE_URL",
    "CTIBUTLER_API_KEY",
    "VULMATCH_BASE_URL",
    "VULMATCH_API_KEY",
    "RANSOMWARE_LIVE_API_KEY",
]



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
    parser.add_argument(
        "--until-date",
        "--until_date",
        type=datetime.fromisoformat,
        help="Only process URLs added until this date (YYYY-MM-DD format)",
    )
    parser.add_argument(
        "--groups",
        required=False,
        nargs="+",
        type=str.lower,
        help="Only process data related to specific groups. Default is all.",
    )

    parsed_args = parser.parse_args()

    missing = [v for v in REQUIRED_ENV_VARS if not os.environ.get(v)]
    if missing:
        parser.error(
            "The following required environment variables are not set: "
            + ", ".join(missing)
        )

    # Parse since_date if provided

    args = ransomware2stix_main.Args(
        min_discovered=parsed_args.since_date,
        max_discovered=parsed_args.until_date,
        groups=parsed_args.groups or [],
    )

    # Setup output directory
    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    bundle_paths = []
    for group_name, bundle in ransomware2stix_main.run(args):
        bundle_filename = group_name.lower().replace(" ", "_")
        print(f"Finished processing group {group_name}, bundle has {len(bundle.objects)} objects")
        bundle_path = save_bundle_to_file(
            bundle, bundles_dir, bundle_filename, add_timestamp=False
        )
        bundle_paths.append(bundle_path)
    
    # Set GitHub Actions output
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            f.write(f"bundle_count={len(bundle_paths)}\n")

if __name__ == "__main__":
    main()
