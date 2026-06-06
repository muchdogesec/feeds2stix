#!/usr/bin/env python3

import argparse
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import requests
from stix2 import (
    URL,
    AutonomousSystem,
    DomainName,
    Identity,
    Indicator,
    IPv4Address,
    X509Certificate,
)
from stix2.patterns import StringConstant

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.kb_fetch import fetch_countries, fetch_enterprise_attack_object
from helpers.utils import (
    country_name_as_alpha2,
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
)
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

API_URL = "https://phishunt.io/api/v1/domains"
BASE_OUTPUT_DIR = "outputs/phishunt"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["phishunt"]
T1566_STIX_ID = "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]
STATIC_DATE = datetime(2020, 1, 1, tzinfo=UTC)
PAGE_SIZE = 1000


def create_phishunt_identity():
    return create_identity_object(
        name="phishunt",
        description=(
            "Real-time feed of suspicious phishing and scam sites, enriched with "
            "IP geolocation, hosting, TLS certificate, and detection verdict data."
        ),
        identity_class="system",
        contact_info="https://phishunt.io/",
    )


def create_phishunt_marking_definition():
    return create_marking_definition_object(f"Origin: {API_URL}")


def fetch_phishunt_data(data_dir: Path, since_date: datetime | None = None):
    logger.info("Fetching phishunt data from %s", API_URL)
    records = []
    offset = 0

    while True:
        params = {"limit": PAGE_SIZE, "offset": offset}
        if since_date:
            params["since"] = since_date.isoformat()

        response = requests.get(API_URL, params=params, timeout=120)
        response.raise_for_status()
        payload = response.json()

        if isinstance(payload, list):
            page_records = payload
            total = None
        else:
            page_records = payload.get("results", [])
            total = payload.get("count")

        records.extend(page_records)

        if not page_records or len(page_records) < PAGE_SIZE:
            break
        offset += len(page_records)
        if total is not None and offset >= total:
            break

    raw_path = data_dir / "phishunt_domains.json"
    raw_path.write_text(json.dumps({"results": records}, indent=2))
    logger.info("Saved raw feed to %s", raw_path)
    logger.info("Fetched %s phishunt records", len(records))
    return records


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_phishunt_records(raw_records):
    records = []
    for raw in raw_records:
        if not raw.get("url") or not raw.get("domain") or not raw.get("date"):
            logger.warning("Skipping phishunt record missing url/domain/date: %s", raw)
            continue

        checked_at = parse_time(raw["date"])
        first_seen = parse_time(raw.get("first_seen") or raw["date"])
        record = dict(raw)
        record["url"] = raw["url"].strip()
        record["domain"] = raw["domain"].strip().lower()
        record["date"] = checked_at
        record["first_seen"] = first_seen
        records.append(record)

    return records


def filter_records_by_date(records, since_date=None, until_date=None):
    filtered = []
    for record in records:
        modified_time = record["date"]
        if since_date and modified_time < since_date:
            continue
        if until_date and modified_time > until_date:
            continue
        filtered.append(record)
    filtered.sort(key=lambda item: item["date"])
    return filtered


def group_records_by_hour(records):
    grouped = defaultdict(list)
    for record in records:
        grouped[record["date"].strftime("%Y%m%d_%H")].append(record)
    return grouped


def create_company_identity(company, object_marking_refs):
    company_name = company.strip()
    company_id = f"identity--{generate_uuid5(company_name, object_marking_refs[-1])}"
    return Identity(
        id=company_id,
        created=STATIC_DATE,
        modified=STATIC_DATE,
        name=company_name,
        identity_class="organization",
        object_marking_refs=object_marking_refs,
    )


def get_country_object(record):
    country_name = record.get("country")
    if not country_name:
        return None
    countries_by_alpha2 = fetch_countries()

    try:
        alpha_2 = country_name_as_alpha2(country_name)
    except ValueError as e:
        logger.warning("Skipping country link for %s: %s", country_name, e)
        return None

    country_obj = countries_by_alpha2.get(alpha_2)
    if not country_obj:
        logger.warning("Country %s (%s) not found in CTI Butler", country_name, alpha_2)
    return country_obj


def create_indicator(
    record, source_identity_id, source_marking_id, object_marking_refs
):
    pattern_parts = [
        f"url:value = {StringConstant(record['url'])}",
        f"domain-name:value = {StringConstant(record['domain'])}",
    ]
    if record.get("ip"):
        pattern_parts.append(f"ipv4-addr:value = {StringConstant(record['ip'])}")

    indicator_name = f"Domain: {record['domain']}"
    external_references = [
        {
            "source_name": "phishunt",
            "url": API_URL,
        }
    ]
    if record.get("uuid"):
        external_references[0]["external_id"] = record["uuid"]

    return Indicator(
        id=f"indicator--{generate_uuid5(indicator_name, source_marking_id)}",
        created_by_ref=source_identity_id,
        created=record["first_seen"],
        modified=record["date"],
        valid_from=record["first_seen"],
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=f"[{' OR '.join(pattern_parts)}]",
        pattern_type="stix",
        object_marking_refs=object_marking_refs,
        external_references=external_references,
    )


def create_stix_objects(
    records, phishunt_identity, phishunt_marking
):
    stix_objects = []
    seen_ids = set()
    phishunt_identity_id = phishunt_identity["id"]
    phishunt_marking_id = phishunt_marking["id"]
    object_marking_refs = OBJECT_MARKING_REFS_BASE + [phishunt_marking_id]

    def append_once(stix_object):
        object_id = stix_object["id"]
        if object_id in seen_ids:
            return
        seen_ids.add(object_id)
        stix_objects.append(stix_object)

    for record in records:
        url_obj = URL(value=record["url"])
        domain_obj = DomainName(value=record["domain"])
        indicator = create_indicator(
            record, phishunt_identity_id, phishunt_marking_id, object_marking_refs
        )

        append_once(url_obj)
        append_once(domain_obj)
        append_once(indicator)

        created = record["first_seen"]
        modified = record["date"]

        for target_ref in [url_obj.id, domain_obj.id]:
            append_once(
                make_relationship(
                    source_ref=indicator.id,
                    target_ref=target_ref,
                    relationship_type="indicates",
                    created_by_ref=phishunt_identity_id,
                    created=created,
                    modified=modified,
                    marking_refs=object_marking_refs,
                ),
            )

        append_once(
            make_relationship(
                source_ref=indicator.id,
                target_ref=T1566_STIX_ID,
                relationship_type="indicates",
                created_by_ref=phishunt_identity_id,
                created=created,
                modified=modified,
                marking_refs=object_marking_refs,
                description=f"{record['domain']} is known to be used for Phishing (T1566)",
            ),
        )

        company_identity = create_company_identity(
            record["company"], object_marking_refs
        )
        append_once(company_identity)
        append_once(
            make_relationship(
                source_ref=indicator.id,
                target_ref=company_identity.id,
                relationship_type="indicates",
                created_by_ref=phishunt_identity_id,
                created=created,
                modified=modified,
                marking_refs=object_marking_refs,
            ),
        )

        ipv4_obj = IPv4Address(value=record["ip"])
        append_once(ipv4_obj)
        append_once(
            make_relationship(
                source_ref=indicator.id,
                target_ref=ipv4_obj.id,
                relationship_type="indicates",
                created_by_ref=phishunt_identity_id,
                created=created,
                modified=modified,
                marking_refs=object_marking_refs,
            ),
        )
        append_once(
            make_relationship(
                source_ref=domain_obj.id,
                target_ref=ipv4_obj.id,
                relationship_type="resolves-to",
                created_by_ref=phishunt_identity_id,
                created=created,
                modified=modified,
                marking_refs=object_marking_refs,
            ),
        )

        asn_kwargs = {}
        asn_obj = None
        if record.get('asn', '-') != '-':
            asn_kwargs['number'] = int(record["asn"])
        if record.get("org"):
            asn_kwargs["name"] = record["org"]
        if 'number' in asn_kwargs:
            asn_obj = AutonomousSystem(**asn_kwargs)
            append_once(asn_obj)
            append_once(
                make_relationship(
                    source_ref=ipv4_obj.id,
                    target_ref=asn_obj.id,
                    relationship_type="related-to",
                    created_by_ref=phishunt_identity_id,
                    created=created,
                    modified=modified,
                    marking_refs=object_marking_refs,
                ),
            )

        country_obj = get_country_object(record)
        append_once(country_obj)
        for source_obj in [ipv4_obj, asn_obj]:
            if source_obj:
                append_once(
                    make_relationship(
                        source_ref=source_obj.id,
                        target_ref=country_obj["id"],
                        relationship_type="related-to",
                        created_by_ref=phishunt_identity_id,
                        created=created,
                        modified=modified,
                        marking_refs=object_marking_refs,
                    ),
                )
        if record.get("cert") != "-":
            cert_obj = X509Certificate(
                id="x509-certificate--"
                + generate_uuid5(
                    f"x509-certificate:issuer:{record['cert']}",
                    phishunt_marking_id,
                ),
                issuer=record["cert"],
            )
            append_once(cert_obj)
            append_once(
                make_relationship(
                    source_ref=domain_obj.id,
                    target_ref=cert_obj.id,
                    relationship_type="related-to",
                    created_by_ref=phishunt_identity_id,
                    created=created,
                    modified=modified,
                    marking_refs=object_marking_refs,
                    description=f"{record['domain']} is associated with TLS certificate issued by {record['cert']}",
                ),
            )

    logger.info("Created %s STIX objects", len(stix_objects))
    return stix_objects


def process_records_for_hour(
    records,
    phishunt_identity,
    phishunt_marking,
    feeds2stix_marking,
    attack_pattern,
):
    stix_objects = [attack_pattern] + create_stix_objects(
        records, phishunt_identity, phishunt_marking
    )
    return create_bundle_with_metadata(
        stix_objects=stix_objects,
        source_identity=phishunt_identity,
        source_marking=phishunt_marking,
        feeds2stix_marking=feeds2stix_marking,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Process phishunt feed and generate STIX bundles"
    )
    parser.add_argument(
        "--since-date",
        "--since_date",
        type=parse_since_date,
        help="Only process entries checked on or after this date (YYYY-MM-DD format)",
    )
    parser.add_argument(
        "--until-date",
        "--until_date",
        type=parse_until_date,
        help="Only process entries checked on or before this date (YYYY-MM-DD format)",
    )
    args = parser.parse_args()

    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    phishunt_identity = create_phishunt_identity()
    phishunt_marking = create_phishunt_marking_definition()
    feeds2stix_marking = fetch_external_objects()
    attack_pattern = fetch_enterprise_attack_object(T1566_STIX_ID)

    raw_records = fetch_phishunt_data(data_dir, args.since_date)
    records = parse_phishunt_records(raw_records)
    records = filter_records_by_date(records, args.since_date, args.until_date)
    grouped_records = group_records_by_hour(records)

    bundle_paths = []
    for hour_key in sorted(grouped_records):
        bundle = process_records_for_hour(
            grouped_records[hour_key],
            phishunt_identity,
            phishunt_marking,
            feeds2stix_marking,
            attack_pattern,
        )
        bundle_path = save_bundle_to_file(
            bundle, bundles_dir, f"phishunt_{hour_key}", add_timestamp=False
        )
        bundle_paths.append(bundle_path)

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            f.write(f"bundle_count={len(bundle_paths)}\n")
            if records:
                latest_timestamp = max(record["date"] for record in records)
                f.write(f"latest_timestamp={latest_timestamp.isoformat()}\n")

    logger.info("Processing complete. Created %s bundles.", len(bundle_paths))


if __name__ == "__main__":
    main()
