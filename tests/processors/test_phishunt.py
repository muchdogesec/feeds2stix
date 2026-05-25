import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from processors.phishunt import phishunt
from tests import utils as test_utils
from tests.utils import stix_as_dict

LOCATION_US = {
    "type": "location",
    "spec_version": "2.1",
    "id": "location--11111111-1111-4111-8111-111111111111",
    "name": "United States",
    "country": "US",
}

ATTACK_PATTERN = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": phishunt.T1566_STIX_ID,
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "Phishing",
}

FEEDS2STIX_MARKING = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "2020-01-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {"statement": "feeds2stix"},
}


def sample_raw_record(**overrides):
    record = {
        "url": "https://office365notification.net/login",
        "domain": "OFFICE365NOTIFICATION.NET",
        "company": "microsoft",
        "date": "2026-05-21T11:55:53.447121+00:00",
        "first_seen": "2026-05-21T10:00:00+00:00",
        "uuid": "6253ce58-2390-4c3e-8eac-500d6a402de0",
        "ip": "172.174.53.244",
        "country": "United States",
        "asn": "8075",
        "org": "Microsoft Corporation",
        "cert": "Let's Encrypt",
        "malicious_google": False,
        "malicious_openphish": False,
        "malicious_phishtank": False,
        "malicious_tweetfeed": False,
        "malicious_urlscan": True,
    }
    record.update(overrides)
    return record


def parsed_sample_record(**overrides):
    return phishunt.parse_phishunt_records([sample_raw_record(**overrides)])[0]


def test_create_phishunt_identity():
    identity = phishunt.create_phishunt_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--97fd98f3-25bb-57c3-8608-e0712efb133d",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "phishunt",
        "description": "Real-time feed of suspicious phishing and scam sites, enriched with IP geolocation, hosting, TLS certificate, and detection verdict data.",
        "identity_class": "system",
        "contact_information": "https://phishunt.io/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_phishunt_marking_definition():
    marking = phishunt.create_phishunt_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--509a1231-9950-54f2-b679-8ba0a77b6a7c",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: https://phishunt.io/api/v1/domains"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_phishunt_data_paginates_and_saves_raw(tmp_path, monkeypatch):
    monkeypatch.setattr(phishunt, "PAGE_SIZE", 1)
    since_date = datetime(2026, 5, 21, 11, tzinfo=UTC)
    responses = [
        test_utils.FakeJSONResponse(
            {"count": 2, "offset": 0, "limit": 1, "results": [sample_raw_record()]}
        ),
        test_utils.FakeJSONResponse(
            {
                "count": 2,
                "offset": 1,
                "limit": 1,
                "results": [
                    sample_raw_record(
                        domain="paypal.example",
                        url="https://paypal.example/login",
                        uuid="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    )
                ],
            }
        ),
    ]

    with patch(
        "processors.phishunt.phishunt.requests.get", side_effect=responses
    ) as mock_get:
        records = phishunt.fetch_phishunt_data(tmp_path, since_date)

    assert len(records) == 2
    assert mock_get.call_args_list[0].kwargs["params"] == {
        "limit": 1,
        "offset": 0,
        "since": "2026-05-21T11:00:00+00:00",
    }
    assert mock_get.call_args_list[1].kwargs["params"]["offset"] == 1
    raw = json.loads((tmp_path / "phishunt_domains.json").read_text())
    assert raw["results"] == records


def test_parse_filter_and_group_records():
    raw_records = [
        sample_raw_record(),
        sample_raw_record(
            date="2026-05-21T13:10:00+00:00",
            first_seen="2026-05-21T12:00:00+00:00",
            domain="paypal.example",
            url="https://paypal.example/login",
        ),
        {"url": "https://missing-date.example", "domain": "missing-date.example"},
    ]
    records = phishunt.parse_phishunt_records(raw_records)

    assert len(records) == 2
    assert records[0]["domain"] == "office365notification.net"
    assert records[0]["date"] == datetime(2026, 5, 21, 11, 55, 53, 447121, tzinfo=UTC)
    assert records[0]["first_seen"] == datetime(2026, 5, 21, 10, tzinfo=UTC)

    filtered = phishunt.filter_records_by_date(
        records,
        since_date=datetime(2026, 5, 21, 12, tzinfo=UTC),
        until_date=datetime(2026, 5, 21, 14, tzinfo=UTC),
    )
    assert [record["domain"] for record in filtered] == ["paypal.example"]

    grouped = phishunt.group_records_by_hour(records)
    assert sorted(grouped) == ["20260521_11", "20260521_13"]


@pytest.fixture
def patched_lookup_country_objects():
    with patch(
        "processors.phishunt.phishunt.fetch_countries",
        return_value={"US": LOCATION_US},
    ):
        yield


def test_create_stix_objects_links_country_once_per_bundle(
    patched_lookup_country_objects,
):
    record = parsed_sample_record()
    identity = phishunt.create_phishunt_identity()
    marking = phishunt.create_phishunt_marking_definition()

    objects = phishunt.create_stix_objects(
        [record, record],
        identity,
        marking,
    )
    object_dicts = stix_as_dict(objects)

    assert len(object_dicts) == 18
    assert sum(1 for obj in object_dicts if obj["type"] == "location") == 1
    assert sum(1 for obj in object_dicts if obj["type"] == "x509-certificate") == 1

    indicator = next(obj for obj in object_dicts if obj["type"] == "indicator")
    assert indicator["id"] == "indicator--6509be96-f376-5b65-95db-a9c57914538d"
    assert indicator["created"] == "2026-05-21T10:00:00.000Z"
    assert indicator["modified"] == "2026-05-21T11:55:53.447121Z"
    assert (
        indicator["pattern"]
        == "[url:value = 'https://office365notification.net/login' OR domain-name:value = 'office365notification.net' OR ipv4-addr:value = '172.174.53.244']"
    )

    relationship_triples = {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in object_dicts
        if obj["type"] == "relationship"
    }
    print(relationship_triples)
    assert relationship_triples == {
        (
            "indicator--6509be96-f376-5b65-95db-a9c57914538d",
            "indicates",
            "ipv4-addr--c3d3b63e-0c83-52ff-9607-a075027e5193",
        ),
        (
            "autonomous-system--9ff0b22c-7efc-5c79-91e4-db72d5b02101",
            "related-to",
            "location--11111111-1111-4111-8111-111111111111",
        ),
        (
            "ipv4-addr--c3d3b63e-0c83-52ff-9607-a075027e5193",
            "related-to",
            "location--11111111-1111-4111-8111-111111111111",
        ),
        (
            "indicator--6509be96-f376-5b65-95db-a9c57914538d",
            "indicates",
            "domain-name--6d82cc1b-f0d4-5861-b512-3bf17f500a67",
        ),
        (
            "indicator--6509be96-f376-5b65-95db-a9c57914538d",
            "indicates",
            "url--d6d45bd8-99df-5745-bc8b-7fa14443b35f",
        ),
        (
            "indicator--6509be96-f376-5b65-95db-a9c57914538d",
            "indicates",
            "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
        ),
        (
            "ipv4-addr--c3d3b63e-0c83-52ff-9607-a075027e5193",
            "related-to",
            "autonomous-system--9ff0b22c-7efc-5c79-91e4-db72d5b02101",
        ),
        (
            "domain-name--6d82cc1b-f0d4-5861-b512-3bf17f500a67",
            "related-to",
            "x509-certificate--0a073ba1-eb30-5192-aca9-e3405df2f4c4",
        ),
        (
            "domain-name--6d82cc1b-f0d4-5861-b512-3bf17f500a67",
            "resolves-to",
            "ipv4-addr--c3d3b63e-0c83-52ff-9607-a075027e5193",
        ),
        (
            "indicator--6509be96-f376-5b65-95db-a9c57914538d",
            "indicates",
            "identity--7fa050ef-9020-5433-9fa8-d50e092bfe7a",
        ),
    }

def test_process_records_for_hour_includes_metadata_and_attack_pattern(
    patched_lookup_country_objects,
):
    identity = phishunt.create_phishunt_identity()
    marking = phishunt.create_phishunt_marking_definition()

    bundle = phishunt.process_records_for_hour(
        [parsed_sample_record()],
        identity,
        marking,
        FEEDS2STIX_MARKING,
        ATTACK_PATTERN,
    )
    bundle_dict = json.loads(bundle.serialize())

    object_ids = {obj["id"] for obj in bundle_dict["objects"]}
    assert "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0" in object_ids
    assert "identity--97fd98f3-25bb-57c3-8608-e0712efb133d" in object_ids
    assert "marking-definition--509a1231-9950-54f2-b679-8ba0a77b6a7c" in object_ids
    assert phishunt.T1566_STIX_ID in object_ids
    assert "location--11111111-1111-4111-8111-111111111111" in object_ids


def test_main_success_writes_hourly_bundle(
    monkeypatch, tmp_path, patched_lookup_country_objects
):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(
        sys, "argv", ["phishunt.py", "--since-date", "2026-05-21T11:00:00+00:00"]
    )
    monkeypatch.setattr(phishunt, "BASE_OUTPUT_DIR", str(tmp_path / "outputs"))

    with patch(
        "processors.phishunt.phishunt.fetch_external_objects",
        return_value=FEEDS2STIX_MARKING,
    ), patch(
        "processors.phishunt.phishunt.fetch_enterprise_attack_object",
        return_value=ATTACK_PATTERN,
    ), patch(
        "processors.phishunt.phishunt.fetch_phishunt_data",
        return_value=[sample_raw_record()],
    ) as mock_fetch:
        phishunt.main()

    assert mock_fetch.call_args.args[1] == datetime(2026, 5, 21, 11, tzinfo=UTC)
    content = out_file.read_text()
    assert "bundle_path=" in content
    assert "bundle_count=1" in content
    assert "latest_timestamp=2026-05-21T11:55:53.447121+00:00" in content

    bundles_dir = Path(content.split("bundle_path=")[1].split("\n")[0])
    bundle_files = list(bundles_dir.glob("*.json"))
    assert [path.name for path in bundle_files] == ["phishunt_20260521_11.json"]

    bundle = json.loads(bundle_files[0].read_text())
    assert phishunt.T1566_STIX_ID in {obj["id"] for obj in bundle["objects"]}
