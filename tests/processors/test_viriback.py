import json
import os
import sys
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
import textwrap
from unittest.mock import patch
from zipfile import ZipFile

import pytest

from processors.viriback import viriback
from helpers.generics import BaseEntry, Group
from tests.utilities import FakeResponse, stix_as_dict


# Fixture to reset Group.start_date and Group.end_date for each test
@pytest.fixture(autouse=True)
def reset_group_dates():
    original_start_date = Group.start_date
    original_end_date = Group.end_date
    yield
    Group.start_date = original_start_date
    Group.end_date = original_end_date


@pytest.fixture
def sample_viriback_csv_data():
    return (Path(viriback.__file__).parent / "sample_data" / "dump.csv").read_text()


def test_create_viriback_identity():
    identity = viriback.create_viriback_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--0d5f1965-508f-5f3e-8eba-f663f3a36b49",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "Viriback",
        "description": "Viriback is a collaborative clearing house for data and information about phishing on the Internet. Also, Viriback provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.",
        "identity_class": "system",
        "contact_information": "https://www.viriback.com/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_viriback_marking_definition():
    marking = viriback.create_viriback_marking_definition()
    print(stix_as_dict(marking))
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--54d628cf-8b45-5a90-9dcd-172236754cda",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: https://tracker.viriback.com/dump.php"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_viriback_data(monkeypatch, tmp_path, sample_viriback_csv_data):
    monkeypatch.chdir(tmp_path)
    with patch(
        "processors.viriback.viriback.requests.get",
        return_value=FakeResponse(content=sample_viriback_csv_data.encode()),
    ) as mock_get:
        lines = viriback.fetch_viriback_data(tmp_path)

    raw_path = tmp_path / "viriback_dump.csv"
    assert raw_path.exists()
    assert raw_path.read_text() == sample_viriback_csv_data
    assert lines == sample_viriback_csv_data.splitlines()
    mock_get.assert_called_once()


def test_parse_entries(sample_viriback_csv_data):
    lines = sample_viriback_csv_data.splitlines()
    entries = list(viriback.parse_entries(lines))
    assert len(entries) == 10
    print(entries)
    assert entries[:3] == [
        viriback.Entry(
            created=datetime(2026, 1, 3, tzinfo=UTC),
            modified=datetime(2026, 1, 3, tzinfo=UTC),
            family="Pony",
            url="http://officeman.tk/images/admin.php",
            ip="207.180.230.128",
        ),
        viriback.Entry(
            created=datetime(2026, 2, 14, tzinfo=UTC),
            modified=datetime(2026, 2, 14, tzinfo=UTC),
            family="Pony",
            url="http://learn.cloudience.com/ojekwaeng/yugo/admin.php",
            ip="192.145.234.108",
        ),
        viriback.Entry(
            created=datetime(2026, 3, 27, tzinfo=UTC),
            modified=datetime(2026, 3, 27, tzinfo=UTC),
            family="Pony",
            url="http://vman23.com/ba24/admin.php",
            ip="95.213.204.53",
        ),
    ]


def test_group_entries_by_family(sample_viriback_csv_data):
    lines = sample_viriback_csv_data.splitlines()
    entries = list(viriback.parse_entries(lines))

    grouped = viriback.group_entries_by_family(
        entries, start_date=None, until_date=None
    )

    assert len(grouped) == 2
    assert "Pony" in grouped
    assert "Lokibot" in grouped

    assert grouped["Pony"].created == datetime(2026, 1, 3, tzinfo=UTC)
    assert grouped["Pony"].modified == datetime(2026, 9, 29, tzinfo=UTC)
    assert grouped["Pony"].count == 9

    assert grouped["Lokibot"].created == datetime(2026, 10, 17, tzinfo=UTC)
    assert grouped["Lokibot"].modified == datetime(2026, 10, 17, tzinfo=UTC)
    assert grouped["Lokibot"].count == 1


def test_group_entries_by_family_with_date_filters(sample_viriback_csv_data):
    lines = sample_viriback_csv_data.splitlines()
    entries = list(viriback.parse_entries(lines))

    # Filter for entries modified on or after 2023-01-02 and before or on 2023-01-04
    start_date = datetime(2026, 1, 2, tzinfo=UTC)
    until_date = datetime(
        2026, 3, 4, 23, 59, 59, 999999, tzinfo=UTC
    )  # End of day 2023-01-04

    grouped = viriback.group_entries_by_family(
        entries, start_date=start_date, until_date=until_date
    )
    print([grouped[k].entries for k in grouped])

    assert len(grouped) == 2
    assert len(grouped["Pony"]) == 2  # Only phish3 (01-03)
    assert grouped["Pony"].entries == [
        viriback.Entry(
            created=datetime(2026, 1, 3, 0, 0, tzinfo=UTC),
            modified=datetime(2026, 1, 3, 0, 0, tzinfo=UTC),
            family="Pony",
            url="http://officeman.tk/images/admin.php",
            ip="207.180.230.128",
        ),
        viriback.Entry(
            created=datetime(2026, 2, 14, 0, 0, tzinfo=UTC),
            modified=datetime(2026, 2, 14, 0, 0, tzinfo=UTC),
            family="Pony",
            url="http://learn.cloudience.com/ojekwaeng/yugo/admin.php",
            ip="192.145.234.108",
        ),
    ]
    assert grouped["Pony"].created == datetime(2026, 1, 3, tzinfo=UTC)
    assert grouped["Pony"].modified == datetime(2026, 9, 29, tzinfo=UTC)
    assert len(grouped["Lokibot"]) == 0  # phish2 (01-02)
    assert grouped["Lokibot"].entries == []


def test_create_objects_for_entry():
    entry_data = {}
    entry = viriback.Entry(
        url="http://example.com/phish1",
        family="Pony",
        ip="1.1.1.1",
        created=datetime(2023, 1, 1, 0, 0, 0, tzinfo=UTC),
        modified=datetime(2023, 1, 1, 0, 0, 0, tzinfo=UTC),
    )

    identity_id = "identity--a0026e6f-5775-523c-992a-337326848148"
    marking_id = "marking-definition--20980482-1678-591b-857f-137887532f7a"
    object_marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        marking_id,
    ]

    stix_objects, rels_to_create = viriback.create_objects_for_entry(
        entry, object_marking_refs, identity_id
    )

    assert len(stix_objects) == 5  # URL, IPv4, Indicator, Rel_URL_IP, Rel_Indicator_URL
    assert len(rels_to_create) == 2

    # Check URL object
    url_obj = next(o for o in stix_objects if o.type == "url")
    assert url_obj.value == "http://example.com/phish1"

    # Check IPv4 object
    ipv4_obj = next(o for o in stix_objects if o.type == "ipv4-addr")
    assert ipv4_obj.value == "1.1.1.1"

    # Check Indicator object
    indicator_obj = next(o for o in stix_objects if o.type == "indicator")
    assert indicator_obj.name == "URL: http://example.com/phish1"
    assert indicator_obj.pattern == "[url:value='http://example.com/phish1']"
    assert indicator_obj.created == entry.created
    assert indicator_obj.modified == entry.created  # Modified from entry.created

    # Check relationships
    rel_url_ip = next(
        r
        for r in stix_objects
        if r.type == "relationship" and r.relationship_type == "related-to"
    )
    assert rel_url_ip.source_ref == url_obj.id
    assert rel_url_ip.target_ref == ipv4_obj.id

    rel_indicator_url = next(
        r
        for r in stix_objects
        if r.type == "relationship"
        and r.relationship_type == "indicates"
        and r.target_ref == url_obj.id
    )
    assert rel_indicator_url.source_ref == indicator_obj.id
    assert rel_indicator_url.target_ref == url_obj.id

    # Check rels_to_create
    assert rels_to_create[0] == (entry.created, url_obj.id)
    assert rels_to_create[1] == (entry.created, indicator_obj.id)


def test_create_malware_objects():
    malware_name = "Pony"
    group = Group[viriback.Entry]()
    group.created = datetime(2023, 1, 1, 0, 0, 0, tzinfo=UTC)
    group.modified = datetime(2023, 1, 5, 0, 0, 0, tzinfo=UTC)

    rels_to_create = [
        (
            datetime(2023, 1, 1, 0, 0, 0, tzinfo=UTC),
            "url--6b6681fc-bfcb-47b6-a956-073cacfc1bf4",
        ),
        (
            datetime(2023, 1, 1, 0, 0, 0, tzinfo=UTC),
            "indicator--6deee352-ff06-4556-be6c-9d763d4682e0",
        ),
        (
            datetime(2023, 1, 3, 0, 0, 0, tzinfo=UTC),
            "url--9cc7bce2-e8ed-468d-8f4f-12183d08d011",
        ),
        (
            datetime(2023, 1, 3, 0, 0, 0, tzinfo=UTC),
            "indicator--b903ed58-1b9a-4a5a-8fed-eacce239b705",
        ),
    ]
    created_by_ref = "identity--a0026e6f-5775-523c-992a-337326848148"
    marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        "marking-definition--20980482-1678-591b-857f-137887532f7a",
    ]

    malware_objects = list(
        viriback.create_malware_objects(
            malware_name, group, rels_to_create, created_by_ref, marking_refs
        )
    )

    assert len(malware_objects) == 1 + len(
        rels_to_create
    )  # 1 malware + 4 relationships

    malware_obj = next(o for o in malware_objects if o.type == "malware")
    assert malware_obj.name == malware_name
    assert malware_obj.created == group.created
    assert malware_obj.modified == group.modified
    assert malware_obj.is_family is True

    # Check relationships
    malware_rels = [o for o in malware_objects if o.type == "relationship"]
    assert len(malware_rels) == 4

    # Example: check one relationship
    rel_to_indicator = next(
        r for r in malware_rels if r.source_ref.startswith("indicator--")
    )
    assert rel_to_indicator.relationship_type == "indicates"
    assert rel_to_indicator.target_ref == malware_obj.id

    rel_to_url = next(r for r in malware_rels if r.source_ref.startswith("url--"))
    assert rel_to_url.relationship_type == "related-to"
    assert rel_to_url.target_ref == malware_obj.id


def test_process_entries_for_malware(sample_viriback_csv_data):
    lines = sample_viriback_csv_data.splitlines()
    entries = list(viriback.parse_entries(lines))
    grouped = viriback.group_entries_by_family(
        entries, start_date=None, until_date=None
    )

    family_a_group = grouped["Pony"]
    identity = viriback.create_viriback_identity()
    marking = viriback.create_viriback_marking_definition()
    feeds2stix_marking = (
        {}
    )  # Not directly used in this function, but required by signature

    all_stix_objects = viriback.process_entries_for_malware(
        "Pony", family_a_group, identity, marking, feeds2stix_marking
    )

    # Expected objects:
    # 3 entries in Pony:
    # Each entry: 1 URL, 1 IPv4, 1 Indicator, 1 Rel(URL,IPv4), 1 Rel(Indicator,URL) = 5 objects
    # Total for entries: 9 * 5 = 45 objects
    # 1 malware object
    # 2 relationships from malware to URL/Indicator = 2 * 9 entries = 18
    # Total: 45 + 1 + 18 objects.
    types = [o.type for o in all_stix_objects]
    assert len(all_stix_objects) == 64

    # Verify types of objects
    assert {(k, types.count(k)) for k in set(types)} == {
        ("ipv4-addr", 9),
        ("relationship", 36), # 9*(rel_url_ip + rel_indicator_url) + 9*(rel_url_malware + rel_indicator_malware) = 18 + 18
        ("url", 9),
        ("malware", 1),
        ("indicator", 9),
    }
    # Check specific relationships
    malware_obj = next(o for o in all_stix_objects if o.type == "malware")
    assert malware_obj.name == "Pony"

    # Check that relationships to malware exist
    malware_rels = [r for r in all_stix_objects if r.type == 'relationship' and r.target_ref == malware_obj.id]
    assert len(malware_rels) == 18  # 9 from URL, 9 from Indicator


def test_main_writes_outputs(monkeypatch, tmp_path, sample_viriback_csv_data):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["viriback.py"])
    monkeypatch.setattr(viriback, "OUTPUT_DIR", tmp_path / "output")

    with patch(
        "processors.viriback.viriback.fetch_viriback_data",
        return_value=sample_viriback_csv_data.splitlines(),
    ):
        viriback.main()

    text = out_file.read_text()
    assert "bundle_path=" in text
    assert "bundle_count=2" in text  # Pony, Lokibot

    bundle_dir = Path(text.split("bundle_path=")[1].splitlines()[0].strip())
    assert bundle_dir.is_dir()
    assert len(os.listdir(bundle_dir)) == 2 # 2 families

    # Check one bundle, e.g., Pony
    family_a_bundle_path = bundle_dir / "viriback_Pony.json"
    assert family_a_bundle_path.exists()
    bundle = json.loads(family_a_bundle_path.read_text())

    # Expected objects in Pony bundle:
    # 64 malware and ip and rels items
    # Plus 1 Identity, 1 MarkingDefinition, 1 Feeds2STIX Marking
    assert len(bundle["objects"]) == 64 + 3