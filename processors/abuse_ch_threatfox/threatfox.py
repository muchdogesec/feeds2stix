#!/usr/bin/env python3

import argparse
from io import BytesIO
import logging
import os
import re
import sys
import shutil
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from stix2 import (
    DomainName,
    File,
    IPv6Address,
    Indicator,
    IPv4Address,
    Malware,
    NetworkTraffic,
    URL,
    AutonomousSystem
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
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/full/"
OUTPUT_DIR = "outputs/abuse_ch_threatfox"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["abuse_ch_threatfox"]
AS_MATCH_RE = re.compile(r"ASN*(\d+)", re.IGNORECASE)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class BadRecordException(Exception):
    pass


def create_threatfox_identity():
    """Create the abuse.ch identity object."""
    return create_identity_object(
        name="abuse.ch",
        description="abuse.ch has been effecting change on cybercrime for almost twenty years, owing to global recognition of our identified and tracked cyber threat signals. Supported by a community of 15,000 specialist researchers, abuse.ch's independent intelligence is relied on by security researchers, network operators and law enforcement agencies.",
        identity_class="organization",
        contact_info="https://abuse.ch/",
    )


def create_threatfox_marking_definition():
    """Create the ThreatFox marking definition."""
    return create_marking_definition_object(
        statement="Origin data source: https://threatfox.abuse.ch/export/csv/recent/"
    )


def download_threatfox_data(data_dir: Path) -> Path:
    """Download ThreatFox ZIP data and extract the CSV file."""
    logger.info(f"Downloading ThreatFox data from {THREATFOX_URL}")
    response = requests.get(THREATFOX_URL, timeout=300)
    response.raise_for_status()

    csv_path = data_dir / "threatfox_data.csv"
    logger.info("Extracting CSV from ZIP archive...")
    with zipfile.ZipFile(BytesIO(response.content)) as zip_file:
        csv_filename = zip_file.namelist()[0]
        logger.info(f"Found CSV file: {csv_filename}")
        with zip_file.open(csv_filename) as csv_file:
            shutil.copyfileobj(csv_file, csv_path.open("wb"))

    logger.info(f"CSV data saved to {csv_path}")
    return csv_path


def parse_timestamp(timestamp_str: str) -> datetime:
    ts = timestamp_str.strip()
    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def _clean_string(value: str) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip().strip('"').strip()
    if cleaned in {"", "None", "n/a"}:
        return None
    return cleaned


def _split_csv_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return sorted({item.strip() for item in value.split(",") if item.strip()})


def mapper(value):
    if isinstance(value, str):
        value = value.strip().strip('"')
    if value in {"n/a", "None", ""}:
        return None
    return value.strip()


def parse_csv_data(csv_path: Path) -> Tuple[datetime, Dict[str, List[Dict[str, object]]]]:
    """Parse CSV data and group records by malware_printable."""
    by_malware = defaultdict(list)
    latest_timestamp = None
    total_records = 0

    with open(csv_path, "r", encoding="utf-8") as f:
        keys = None
        for line_number, line_raw in enumerate(f, start=1):
            line = line_raw.replace("\t", "")
            if line.startswith('# "first_seen_utc"'):
                header_line = line[2:]
                keys = [mapper(v) for v in header_line.strip().strip('"').split('","')]
                continue

            if line.startswith("#") or not line.strip():
                continue

            if not keys:
                continue

            line = line.strip().strip('"')
            line_values = tuple(map(mapper, line.split('", "')))
            if len(line_values) != len(keys):
                continue

            record = dict(zip(keys, line_values))

            first_seen = parse_timestamp(record["first_seen_utc"])

            record["first_seen_utc"] = first_seen
            record["last_seen_utc"] = parse_timestamp(record["last_seen_utc"]) if record.get("last_seen_utc") else first_seen
            record["confidence_level"] = int(record["confidence_level"]) if record.get("confidence_level") else None
            record["malware_printable"] = record.get("malware_printable") or "Unknown"
            record['raw'] = line_raw
            record['line_number'] = line_number

            by_malware[record["malware_printable"]].append(record)
            total_records += 1
            if latest_timestamp is None or first_seen > latest_timestamp:
                latest_timestamp = first_seen

    logger.info(f"Parsed {total_records} records from CSV")
    logger.info(f"Found {len(by_malware)} unique malware_printable values")
    return latest_timestamp, by_malware


def guess_malware_type(malware_name: str) -> str:
    malware_name = (malware_name or "").lower()
    if malware_name.endswith("rat"):
        return "remote-access-trojan"
    if malware_name.startswith("adware."):
        return "adware"
    if malware_name.startswith("ransomware."):
        return "ransomware"
    if malware_name.startswith("worm."):
        return "worm"
    return "unknown"


def _network_protocols(dst_port: int) -> List[str]:
    if dst_port == 80:
        return ["http", "tcp"]
    if dst_port == 443:
        return ["ssl", "tcp"]
    return ["tcp"]



def create_observables_for_record(record: Dict[str, object]) -> List[object]:
    ioc_type = record["ioc_type"]
    ioc_value = record["ioc_value"]

    tags = _split_csv_list(record.get("tags"))
    
            
    objects = []
    for tag in tags:
        if AS_MATCH_RE.match(tag):
            asn = AS_MATCH_RE.match(tag).group(1)
            objects.append(
                AutonomousSystem(number=int(asn), name=f"AS{asn}")
            )
    match ioc_type:
        case "url":
            objects.append(URL(value=ioc_value))
        case "domain":
            objects.append(DomainName(value=ioc_value))
        case "md5_hash":
            objects.append(File(hashes={"MD5": ioc_value}))
        case "sha1_hash":
            objects.append(File(hashes={"SHA-1": ioc_value}))
        case "sha256_hash":
            objects.append(File(hashes={"SHA-256": ioc_value}))
        case "ip:port":
            ip_value, port_raw = ioc_value.split(":", maxsplit=1)
            port = int(port_raw)
            ipv4_obj = IPv4Address(value=ip_value)
            net_obj = NetworkTraffic(
                dst_ref=ipv4_obj.id,
                dst_port=port,
                protocols=_network_protocols(port),
            )
            objects.extend([ipv4_obj, net_obj])
        case _:
            logger.warning(f"Skipping unsupported IOC type: {ioc_type}")
    return objects


def _build_indicator_pattern(observables: List[object]) -> str:
    ipv4_values = {ipaddr.id: ipaddr.value for ipaddr in observables if isinstance(ipaddr, (IPv4Address, IPv6Address))}
    patterns = []

    for observable in observables:
        match observable.type:
            case "url":
                patterns.append(
                    f"url:value = {StringConstant(observable.value)}"
                )
            case "domain-name":
                patterns.append(
                    f"domain-name:value = {StringConstant(observable.value)}"
                )
            case "file":
                for hash_name, hash_value in sorted(observable.hashes.items()):
                    patterns.append(
                        f"file:hashes.'{hash_name}' = {StringConstant(hash_value)}"
                    )
            case "network-traffic":
                ipvalue = ipv4_values.get(observable.dst_ref)
                ip_pattern = f'network-traffic:dst_port = {observable.dst_port}'
                if ipvalue:
                    ip_pattern += f' AND network-traffic:dst_ref.value = {StringConstant(ipvalue)}'
                    ip_pattern = f"( {ip_pattern} )"
                patterns.append(ip_pattern)


    if not patterns:
        raise ValueError("Unable to build indicator pattern from observables")

    return "[ " + " OR ".join(patterns) + " ]"


def create_indicator_object(
    record: Dict[str, object],
    observables: List[object],
    source_identity_id: str,
    source_marking_id: str,
    object_marking_refs: List[str],
) -> Indicator:
    pattern = _build_indicator_pattern(observables)

    tags = _split_csv_list(record.get("tags"))

    external_refs = []
    if record.get("ioc_id"):
        external_refs.append(
            {"source_name": "threatfox_ioc_id", "external_id": record["ioc_id"]}
        )
    if record.get("reporter"):
        external_refs.append(
            {"source_name": "threatfox_reporter", "external_id": record["reporter"]}
        )
    if record.get("reference"):
        for reference_value in _split_csv_list(record["reference"]):
            external_refs.append(
                {"source_name": "threatfox_reference", "external_id": reference_value}
            )

    indicator_name = record.get("malware_printable") or "Unknown"
    indicator_id = "indicator--" + generate_uuid5(
        f"{indicator_name}+{record['ioc_id']}",
        namespace=source_marking_id,
    )

    return Indicator(
        id=indicator_id,
        created_by_ref=source_identity_id,
        created=record["first_seen_utc"],
        modified=record["last_seen_utc"],
        valid_from=record["first_seen_utc"],
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=pattern,
        pattern_type="stix",
        confidence=record.get("confidence_level"),
        labels=tags if tags else None,
        external_references=external_refs if external_refs else None,
        object_marking_refs=object_marking_refs,
    )


def create_malware_objects(
    malware_name: str,
    records: List[Dict[str, object]],
    object_ids: List[Tuple[str, datetime, datetime]],
    source_identity_id: str,
    object_marking_refs: List[str],
    source_marking_id: str,
):
    if malware_name == "Unknown":
        return

    created = min(record["first_seen_utc"] for record in records)
    modified = max(record["last_seen_utc"] for record in records)
    fk_malware = None
    aliases = set()

    for record in records:
        created = min(created, record["first_seen_utc"])
        modified = max(modified, record["last_seen_utc"])
        fk_malware = fk_malware or record.get("fk_malware")
        aliases.update(_split_csv_list(record.get("malware_alias")))

    aliases.discard(malware_name)
    aliases = sorted(aliases)

    malware_types = sorted({guess_malware_type(malware_name) for malware_name in aliases + [malware_name]})
    if len(malware_types) > 1:
        malware_types.remove("unknown")

    malware = Malware(
        id="malware--" + generate_uuid5(malware_name, namespace=source_marking_id),
        created_by_ref=source_identity_id,
        created=created,
        modified=modified,
        name=malware_name,
        malware_types=malware_types,
        aliases=aliases or None,
        is_family=True,
        external_references=(
            [
                {
                    "source_name": "malpedia",
                    "external_id": f"https://malpedia.caad.fkie.fraunhofer.de/details/{fk_malware}",
                }
            ]
            if fk_malware
            else None
        ),
        object_marking_refs=object_marking_refs,
    )

    yield malware
    for obj_id, created, modified in object_ids:
        if obj_id.startswith("indicator--"):
            reltype = "indicates"
        else:
            reltype = "related-to"
        yield make_relationship(
                source_ref=obj_id,
                target_ref=malware.id,
                relationship_type=reltype,
                created_by_ref=source_identity_id,
                marking_refs=object_marking_refs,
                created=created,
                modified=modified,
            )

def process_records(
    malware_name: str,
    records: List[Dict[str, object]],
    source_identity: object,
    source_marking: object,
    feeds2stix_marking: dict,
    start_date: datetime = None,
) -> List[str]:
    """Process records for a single malware name and create one or more bundles."""
    logger.info(f"Processing malware_printable: {malware_name} with {len(records)} records")

    object_marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        source_marking["id"],
    ]

    all_stix_objects = []
    bundle_paths = []
    bundles_created = 0

    indicator_ids = []

    def flush_bundle(force=False):
        nonlocal bundles_created
        if not all_stix_objects:
            return
        if not force and len(all_stix_objects) < 10000:
            return

        bundle = create_bundle_with_metadata(
            all_stix_objects,
            source_identity,
            source_marking,
            feeds2stix_marking,
        )
        malware_safe = malware_name.replace(" ", "_").replace("/", "_")
        path = save_bundle_to_file(
            bundle,
            Path(OUTPUT_DIR) / "bundles" / malware_safe,
            f"{malware_safe}_{bundles_created}",
        )
        bundle_paths.append(path)
        bundles_created += 1
        all_stix_objects.clear()

    processed_records = 0
    for record in records:
        try:
            processed_records += 1
            if start_date and record["first_seen_utc"] < start_date:
                continue
            flush_bundle()

            observables = create_observables_for_record(record)
            if not observables:
                continue

            indicator = create_indicator_object(
                record,
                observables,
                source_identity["id"],
                source_marking["id"],
                object_marking_refs,
            )
            indicator_ids.append((indicator.id, indicator.created, indicator.modified))
            all_stix_objects.append(indicator)

            for observable in observables:
                all_stix_objects.append(observable)
                indicator_ids.append((observable.id, indicator.created, indicator.modified))
                if observable.type != 'autonomous-system':
                    all_stix_objects.append(
                        make_relationship(
                            source_ref=indicator.id,
                            target_ref=observable.id,
                            relationship_type="indicates",
                            created_by_ref=source_identity["id"],
                            marking_refs=object_marking_refs,
                            created=indicator.created,
                            modified=indicator.modified,
                        )
                    )

            flush_bundle()
        except Exception as e:
            msg = f"Error processing record on line {record.get('line_number')}: {record['raw']}"
            raise BadRecordException(msg) from e

    if malware_name != "Unknown":
        for obj in create_malware_objects(
            malware_name,
            records,
            indicator_ids,
            source_identity["id"],
            object_marking_refs,
            source_marking["id"],
        ):
            all_stix_objects.append(obj)
            flush_bundle()
    flush_bundle(force=True)
    return bundle_paths


def main():
    parser = argparse.ArgumentParser(
        description="Process ThreatFox feed and generate STIX bundles"
    )
    parser.add_argument(
        "--malware-printable",
        type=str,
        help="Process only records with this malware_printable value",
    )
    parser.add_argument(
        "--signature",
        type=str,
        help="Alias of --malware-printable for compatibility with MalwareBazaar workflow",
    )
    parser.add_argument(
        "--start-date",
        "--start_date",
        type=datetime.fromisoformat,
        help="Only include records with first_seen_utc after this date (YYYY-MM-DD[T[HH:MM[:SS]]])",
    )

    args = parser.parse_args()
    args.start_date = args.start_date and args.start_date.replace(tzinfo=timezone.utc)
    target_malware = args.malware_printable or args.signature

    bundles_dir, data_dir = setup_output_directory(OUTPUT_DIR, clean=True)

    source_identity = create_threatfox_identity()
    source_marking = create_threatfox_marking_definition()

    feeds2stix_marking = fetch_external_objects()

    csv_path = download_threatfox_data(data_dir)
    latest_timestamp, records_by_malware = parse_csv_data(csv_path)

    for malware_name, records in records_by_malware.items():
        if target_malware and target_malware != malware_name:
            continue
        process_records(
            malware_name,
            records,
            source_identity,
            source_marking,
            feeds2stix_marking,
            start_date=args.start_date,
        )

    logger.info("Processing complete")

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            if latest_timestamp:
                f.write(f"latest_timestamp={latest_timestamp.isoformat()}\n")


if __name__ == "__main__":
    main()
