#!/usr/bin/env python3

import argparse
import json
import logging
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import requests
from stix2 import Note

from helpers.kb_fetch import fetch_vulnerabilities
from helpers.utils import (
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    save_bundle_to_file,
    setup_output_directory,
    write_github_output,
)
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

RSS_URL = "https://api.msrc.microsoft.com/update-guide/rss"
BASE_OUTPUT_DIR = "outputs/microsoft_update_guide"
MISSING_CVE_FILENAME = "missing_cve_list.json"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["microsoft_update_guide"]
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def create_msrc_identity():
    return create_identity_object(
        name="MSRC Security Update Guide",
        description=(
            "The Microsoft Security Response Center (MSRC) investigates all reports "
            "of security vulnerabilities affecting Microsoft products and services, "
            "and provides the information here as part of the ongoing effort to help "
            "you manage security risks and help keep your systems protected."
        ),
        identity_class="system",
        contact_info="https://msrc.microsoft.com/update-guide/",
    )


def create_msrc_marking_definition():
    return create_marking_definition_object(f"Origin: {RSS_URL}")


def parse_pub_date(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    dt = parsedate_to_datetime(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_iso_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_description(description: str | None) -> tuple[str, list[dict]]:
    if not description:
        return "", []

    external_references = []

    def replace_link(match):
        label = " ".join(match.group(1).split())
        url = " ".join(match.group(2).split())
        reference = {"source_name": "msrc", "url": url}
        if label:
            reference["description"] = label
        external_references.append(reference)
        return label

    text = MARKDOWN_LINK_RE.sub(replace_link, description)
    return " ".join(text.split()), external_references


def parse_rss_item(item: ET.Element) -> dict | None:
    revision = float(item.attrib.get("Revision") or "0")
    if revision > 1.0:
        return None

    cve_id = ""
    title = ""
    link = ""
    description = ""
    description_refs = []
    pub_date = datetime.now(UTC)

    for child in item:
        name = child.tag.rsplit("}", 1)[-1]
        if name == "guid":
            cve_id = " ".join((child.text or "").split()).upper()
        elif name == "title":
            title = " ".join((child.text or "").split())
        elif name == "link":
            link = " ".join((child.text or "").split())
        elif name == "description":
            description, description_refs = parse_description(child.text)
        elif name == "pubDate":
            pub_date = parse_pub_date(child.text)

    if not cve_id:
        return None

    return {
        "cve_ids": [cve_id],
        "title": title,
        "link": link,
        "description": description,
        "description_references": description_refs,
        "pub_date": to_iso_z(pub_date),
    }


def parse_rss_feed(xml_content: bytes | str) -> dict[str, dict]:
    root = ET.fromstring(xml_content)
    missing_cves = {}
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1] != "item":
            continue
        parsed_item = parse_rss_item(item)
        if not parsed_item:
            continue
        cve_id = parsed_item["cve_ids"][0]
        missing_cves[cve_id] = dict(parsed_item, cve_id=cve_id)
    return missing_cves


def fetch_msrc_rss(data_dir: Path) -> dict[str, dict]:
    response = requests.get(RSS_URL, timeout=120)
    response.raise_for_status()
    raw_path = data_dir / "msrc_recent.xml"
    raw_path.write_bytes(response.content)
    return parse_rss_feed(response.content)


def load_missing_cve_list(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}

    missing_cves = json.loads(path.read_text().strip())
    normalized_missing_cves = {}
    for cve_id, pending_item in missing_cves.items():
        normalized_cve_id = cve_id.strip().upper()
        normalized_missing_cves[normalized_cve_id] = dict(
            pending_item, cve_id=normalized_cve_id
        )
    return normalized_missing_cves


def save_missing_cve_list(path: Path, missing_cves: dict[str, dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(missing_cves, indent=2, sort_keys=True) + "\n")
    logger.info("saved missing_cve_list to %s", path)
    return path


def fetch_vulnerabilities_for_cves(cve_ids: list[str]) -> dict[str, dict]:
    vulnerabilities = {}
    for idx in range(0, len(cve_ids), 50):
        vulnerabilities.update(fetch_vulnerabilities(cve_ids[idx : idx + 50]))
    return vulnerabilities


def build_msrc_note(
    cve_id: str,
    pending_item: dict,
    vulnerability: dict,
    source_identity_id: str,
    source_marking_id: str,
):
    external_references = [
        vulnerability["external_references"][0]
    ]
    if pending_item.get("link"):
        external_references.append({"source_name": "msrc", "url": pending_item["link"]})
    external_references.extend(pending_item.get("description_references", []))

    pub_date = datetime.fromisoformat(pending_item["pub_date"].replace("Z", "+00:00"))

    return Note(
        id=f"note--{generate_uuid5(f'msrc:{cve_id}', source_marking_id)}",
        created_by_ref=source_identity_id,
        created=pub_date,
        modified=pub_date,
        abstract=pending_item.get("title") or cve_id,
        content=pending_item.get("description") or pending_item.get("title") or cve_id,
        object_refs=[vulnerability["id"]],
        external_references=external_references or None,
        object_marking_refs=OBJECT_MARKING_REFS_BASE + [source_marking_id],
    )


def build_bundle_objects(
    vulnerabilities: list[dict],
    missing_cves: dict[str, dict],
    source_identity_id: str,
    source_marking_id: str,
) -> list:
    objects = []
    for vulnerability in vulnerabilities:
        cve_id = vulnerability["name"]
        pending_item = missing_cves.get(cve_id)
        if not pending_item:
            continue
        objects.append(vulnerability)
        objects.append(
            build_msrc_note(
                cve_id,
                pending_item,
                vulnerability,
                source_identity_id,
                source_marking_id,
            )
        )
    return objects


def process_msrc(missing_cve_list_path: Path, data_dir: Path):
    parsed_cves = load_missing_cve_list(missing_cve_list_path)
    logger.info("loaded %d missing CVEs from last run", len(parsed_cves))
    rss_missing_cves = fetch_msrc_rss(data_dir)
    logger.info("loaded %s CVEs from MSRC RSS", len(rss_missing_cves))
    parsed_cves.update(rss_missing_cves)
    new_missing_cve_list_path = data_dir / MISSING_CVE_FILENAME

    cve_ids = list(parsed_cves.keys())
    found_cves_by_name = fetch_vulnerabilities_for_cves(cve_ids)
    missing_cves = {
        cve_id: pending_item
        for cve_id, pending_item in parsed_cves.items()
        if cve_id not in found_cves_by_name
    }
    logger.info(
        "found %s CVEs and left %s missing", len(found_cves_by_name), len(missing_cves)
    )
    save_missing_cve_list(new_missing_cve_list_path, missing_cves)
    (data_dir / "msrc_found_cves.json").write_text(
        json.dumps(sorted(found_cves_by_name), indent=2) + "\n"
    )
    return list(found_cves_by_name.values()), parsed_cves, missing_cves, new_missing_cve_list_path


def save_bundles(
    vulnerabilities,
    parsed_cves,
    bundles_dir: Path,
    source_identity,
    source_marking,
    feeds2stix_marking,
):
    bundle_paths = []
    for idx, vulnerability_group in enumerate(
        [vulnerabilities[i : i + 1000] for i in range(0, len(vulnerabilities), 1000)],
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
                f"msrc_part_{idx:03d}",
                add_timestamp=False,
            )
        )
    return bundle_paths


def main():
    parser = argparse.ArgumentParser(
        description="Process MSRC RSS CVEs and import matching Vulmatch vulnerabilities"
    )
    parser.add_argument(
        "missing_cve_list",
        type=Path,
        help="Path to the persistent JSON file containing unresolved MSRC CVE items",
    )
    args = parser.parse_args()

    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    missing_cve_list_path = args.missing_cve_list.absolute()

    source_identity = create_msrc_identity()
    source_marking = create_msrc_marking_definition()
    feeds2stix_marking = fetch_external_objects()

    vulnerabilities, parsed_cves, missing_cves, new_missing_cve_list_path = process_msrc(
        missing_cve_list_path, data_dir
    )
    bundle_paths = save_bundles(
        vulnerabilities,
        parsed_cves,
        bundles_dir,
        source_identity,
        source_marking,
        feeds2stix_marking,
    )

    write_github_output(
        bundle_path=bundles_dir,
        bundle_count=len(bundle_paths),
        missing_cve_list_path=new_missing_cve_list_path,
    )


if __name__ == "__main__":
    main()
