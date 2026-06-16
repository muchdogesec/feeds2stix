#!/usr/bin/env python3

import argparse
import json
import logging
import re
import sys
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
from stix2 import Note

from helpers.kb_fetch import fetch_vulnerabilities  # noqa: E402
from helpers.utils import (  # noqa: E402
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    save_bundle_to_file,
    setup_output_directory,
    write_github_output,
)
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

RSS_URL = "https://vuldb.com/rss/recent"
BASE_OUTPUT_DIR = "outputs/vuldb"
PENDING_CVE_FILENAME = "vuldb-cve-list.json"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["vuldb"]
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def create_vuldb_identity():
    return create_identity_object(
        name="VulDB",
        description=(
            "VulDB stands for Vulnerability Database. We are curating and "
            "documenting all security vulnerabilities that got published in "
            "electronic products. We are one of the most important sources for "
            "people responsible for handling vulnerabilities, vulnerability "
            "management, exploit analysis, cyber threat intelligence, and "
            "incident response handling."
        ),
        identity_class="system",
        contact_info="https://vuldb.com/",
    )


def create_vuldb_marking_definition():
    return create_marking_definition_object(f"Origin: {RSS_URL}")


def extract_cve_ids(text: str) -> list[str]:
    cve_ids = []
    seen = set()
    for match in CVE_RE.finditer(text or ""):
        cve_id = match.group(0).upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)
        cve_ids.append(cve_id)
    return cve_ids


def to_iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_pub_date(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    dt = parsedate_to_datetime(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_description(description: str | None) -> tuple[str, list[dict]]:
    if not description:
        return "", []

    try:
        root = ET.fromstring(f"<root>{description}</root>")
    except ET.ParseError:
        return " ".join((description or "").split()), []

    text = " ".join("".join(root.itertext()).split())
    external_references = []
    for anchor in root.iter("a"):
        href = anchor.attrib.get("href")
        if not href:
            continue
        reference = {"source_name": "vuldb", "url": href}
        label = " ".join("".join(anchor.itertext()).split())
        if label:
            reference["description"] = label
        external_references.append(reference)
    return text, external_references


def parse_rss_item(item: ET.Element) -> dict:
    title = ""
    link = ""
    description = ""
    description_refs = []
    pub_date = datetime.now(UTC)
    categories = {}

    for child in item:
        name = child.tag.rsplit("}", 1)[-1]
        if name == "title":
            title = " ".join((child.text or "").split())
        elif name == "link":
            link = " ".join((child.text or "").split())
        elif name == "description":
            description, description_refs = parse_description(child.text)
        elif name == "pubDate":
            pub_date = parse_pub_date(child.text)
        elif name == "category":
            key, _, value = (child.text or "").partition(":")
            key = key.strip()
            value = value.strip()
            categories[key] = value
    cve_ids = extract_cve_ids(f"{title} {description}")
    return {
        "cve_ids": cve_ids,
        "title": title,
        "link": link,
        "description": description,
        "description_references": description_refs,
        "pub_date": to_iso_z(pub_date),
        "categories": categories,
    }


def parse_rss_feed(xml_content: bytes | str) -> dict[str, dict]:
    root = ET.fromstring(xml_content)
    pending_cves = {}
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1] != "item":
            continue
        parsed_item = parse_rss_item(item)
        for cve_id in parsed_item["cve_ids"]:
            pending_cves[cve_id] = dict(parsed_item, cve_id=cve_id)
    return pending_cves


def fetch_vuldb_rss(data_dir: Path) -> dict[str, dict]:
    response = requests.get(RSS_URL, timeout=120)
    response.raise_for_status()
    raw_path = data_dir / "vuldb_recent.xml"
    raw_path.write_bytes(response.content)
    return parse_rss_feed(response.content)


def load_pending_cves(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}

    raw_text = path.read_text().strip()
    pending_cves = json.loads(raw_text)
    normalized_pending_cves = {}
    for cve_id, pending_item in pending_cves.items():
        normalized_cve_id = cve_id.strip().upper()
        normalized_pending_cves[normalized_cve_id] = dict(
            pending_item, cve_id=normalized_cve_id
        )
    return normalized_pending_cves


def save_pending_cves(path: Path, pending_cves: dict[str, dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pending_cves, indent=2, sort_keys=True) + "\n")
    logger.info("saved missing_cve_list to %s", path)
    return path


def fetch_vulnerabilities_for_cves(cve_ids: list[str]) -> dict[str, dict]:
    vulnerabilities = {}
    for idx in range(0, len(cve_ids), 50):
        chunk = cve_ids[idx : idx + 50]
        vulnerabilities.update(fetch_vulnerabilities(chunk))
    return vulnerabilities


def build_vuldb_note(
    cve_id: str,
    pending_item: dict,
    vulnerability: dict,
    source_identity_id: str,
    source_marking_id: str,
):
    external_references = [
        vulnerability['external_references'][0]
    ]
    if pending_item.get("link"):
        external_references.append(
            {"source_name": "vuldb", "url": pending_item["link"]}
        )
    external_references.extend(pending_item.get("description_references", []))

    pub_date = datetime.fromisoformat(pending_item["pub_date"].replace("Z", "+00:00"))
    labels = [
        f"{key}: {value}"
        for key, value in (pending_item.get("categories") or {}).items()
    ]

    return Note(
        id=f"note--{generate_uuid5(f'vuldb:{cve_id}', source_marking_id)}",
        created_by_ref=source_identity_id,
        created=pub_date,
        modified=pub_date,
        abstract=pending_item.get("title") or cve_id,
        content=pending_item.get("description") or pending_item.get("title") or cve_id,
        labels=labels or None,
        object_refs=[vulnerability["id"]],
        external_references=external_references or None,
        object_marking_refs=OBJECT_MARKING_REFS_BASE + [source_marking_id],
    )


def build_bundle_objects(
    vulnerabilities: list[dict],
    pending_cves: dict[str, dict],
    source_identity_id: str,
    source_marking_id: str,
) -> list:
    objects = []
    for vulnerability in vulnerabilities:
        cve_id = vulnerability["name"]
        pending_item = pending_cves.get(cve_id)
        if not pending_item:
            continue
        objects.append(vulnerability)
        objects.append(
            build_vuldb_note(
                cve_id,
                pending_item,
                vulnerability,
                source_identity_id,
                source_marking_id,
            )
        )
    return objects


def process_vuldb(cve_list_path: Path, data_dir: Path):
    parsed_cves = load_pending_cves(cve_list_path)
    logger.info("loaded %s missing CVEs from last run", len(parsed_cves))
    rss_pending_cves = fetch_vuldb_rss(data_dir)
    logger.info("loaded %s CVEs from VulDB RSS", len(rss_pending_cves))
    parsed_cves.update(rss_pending_cves)
    new_cve_list_path = data_dir / PENDING_CVE_FILENAME

    cve_ids = list(parsed_cves.keys())
    found_cves_by_name = fetch_vulnerabilities_for_cves(cve_ids)
    pending_cves = {
        cve_id: pending_item
        for cve_id, pending_item in parsed_cves.items()
        if cve_id not in found_cves_by_name
    }
    logger.info(
        "found %s CVEs and left %s missing", len(found_cves_by_name), len(pending_cves)
    )
    save_pending_cves(new_cve_list_path, pending_cves)
    (data_dir / "vuldb_found_cves.json").write_text(
        json.dumps(sorted(found_cves_by_name), indent=2) + "\n"
    )
    return (
        list(found_cves_by_name.values()),
        parsed_cves,
        pending_cves,
        new_cve_list_path,
    )


def make_bundles(
    vulnerabilities,
    parsed_cves,
    bundles_dir: Path,
    source_identity,
    source_marking,
    feeds2stix_marking,
    vulnerabilities_per_bundle=1000,
):
    bundle_paths = []
    for idx, vulnerability_group in enumerate(
        [
            vulnerabilities[i : i + vulnerabilities_per_bundle]
            for i in range(0, len(vulnerabilities), vulnerabilities_per_bundle)
        ],
        start=1,
    ):
        stix_objects = build_bundle_objects(
            vulnerability_group,
            parsed_cves,
            source_identity["id"],
            source_marking["id"],
        )
        if not stix_objects:
            continue
        bundle = create_bundle_with_metadata(
            stix_objects,
            source_identity,
            source_marking,
            feeds2stix_marking,
        )
        bundle_paths.append(
            save_bundle_to_file(
                bundle,
                bundles_dir,
                f"vuldb_part_{idx:03d}",
                add_timestamp=False,
            )
        )
    return bundle_paths


def main():
    parser = argparse.ArgumentParser(
        description="Process VulDB RSS CVEs and import matching Vulmatch vulnerabilities"
    )
    parser.add_argument(
        "cve_list",
        type=Path,
        help="Path to the persistent JSON file containing pending VulDB CVE items",
    )
    args = parser.parse_args()

    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    old_cve_list_path = args.cve_list.absolute()

    source_identity = create_vuldb_identity()
    source_marking = create_vuldb_marking_definition()
    feeds2stix_marking = fetch_external_objects()

    vulnerabilities, parsed_cves, pending_cves, new_cve_list_path = process_vuldb(
        old_cve_list_path, data_dir
    )
    bundle_paths = make_bundles(
        vulnerabilities,
        parsed_cves,
        bundles_dir,
        source_identity,
        source_marking,
        feeds2stix_marking,
        vulnerabilities_per_bundle=800,
    )

    write_github_output(
        bundle_path=bundles_dir,
        bundle_count=len(bundle_paths),
        cve_list_path=new_cve_list_path,
    )


if __name__ == "__main__":
    main()