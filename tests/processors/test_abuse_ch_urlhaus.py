import json
import sys
from datetime import UTC, datetime, timezone
from pathlib import Path
from unittest.mock import patch

import processors
from processors.abuse_ch_urlhaus import urlhaus
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_parse_timestamp_handles_blank():
    assert urlhaus.parse_timestamp("") is None


def test_parse_timestamp_valid():
    ts = urlhaus.parse_timestamp("2026-01-02 03:04:05")
    assert ts == datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_create_identity():
    identity = urlhaus.create_urlhaus_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "abuse.ch",
        "description": "abuse.ch has been effecting change on cybercrime for almost twenty years, owing to global recognition of our identified and tracked cyber threat signals. Supported by a community of 15,000 specialist researchers, abuse.ch's independent intelligence is relied on by security researchers, network operators and law enforcement agencies.",
        "identity_class": "organization",
        "contact_information": "https://abuse.ch/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_marking_definition():
    marking = urlhaus.create_urlhaus_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--89b3aa69-1f6d-5df0-a84b-cb31fba7e0f0",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin data source: https://urlhaus.abuse.ch/downloads/csv_recent/"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_download_urlhaus_data(monkeypatch, tmp_path):
    content = (
        b"id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
    )
    monkeypatch.chdir(tmp_path)
    with patch(
        "processors.abuse_ch_urlhaus.urlhaus.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ) as mock_get:
        path = urlhaus.download_urlhaus_data()
    assert path.exists()
    assert path.read_bytes() == content


def test_create_url_object():
    obj = urlhaus.create_url_object("http://x.test")
    assert stix_as_dict(obj) == {
        "type": "url",
        "spec_version": "2.1",
        "id": "url--16cf3603-dec8-5d7a-9d6a-19bca9810bff",
        "value": "http://x.test",
    }


def test_parse_csv_data(tmp_path, subtests):
    csv_file = tmp_path / "u.csv"
    csv_file.write_text(
        "#comment\n"
        "1,2026-01-02 01:08:00,http://a,online,2026-01-02 12:00:00,malware,tag1,http://u,rep\n"
        "2,2024-01-02 00:00:00,http://b,offline,2024-01-03 00:00:00,phish,tag2,http://u2,rep2\n"
    )
    latest, records = urlhaus.parse_csv_data(csv_file)
    assert len(records) == 2
    assert records == [
        {
            "id": "1",
            "dateadded": datetime(2026, 1, 2, 1, 8, tzinfo=UTC),
            "url": "http://a",
            "url_status": "online",
            "last_online": datetime(2026, 1, 2, 12, 0, tzinfo=UTC),
            "threat": "malware",
            "tags": "tag1",
            "urlhaus_link": "http://u",
            "reporter": "rep",
        },
        {
            "id": "2",
            "dateadded": datetime(2024, 1, 2, 0, 0, tzinfo=UTC),
            "url": "http://b",
            "url_status": "offline",
            "last_online": datetime(2024, 1, 3, 0, 0, tzinfo=UTC),
            "threat": "phish",
            "tags": "tag2",
            "urlhaus_link": "http://u2",
            "reporter": "rep2",
        },
    ]
    assert latest == datetime(2026, 1, 2, 1, 8, tzinfo=UTC)

    with subtests.test("filters by start_date"):
        latest, records = urlhaus.parse_csv_data(
            csv_file, start_date=datetime(2025, 1, 1, tzinfo=UTC)
        )
        assert len(records) == 1
        assert records[0]["dateadded"] == datetime(2026, 1, 2, 1, 8, tzinfo=UTC)


def test_create_indicator_object():
    record = {
        "id": "1",
        "dateadded": datetime(2026, 1, 1, tzinfo=UTC),
        "url": "http://bad.test",
        "url_status": "offline",
        "last_online": datetime(2026, 1, 2, tzinfo=UTC),
        "threat": "malware",
        "tags": "loader,bot",
        "urlhaus_link": "https://urlhaus.example/item",
        "reporter": "r",
    }
    valid_marking_id = "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ind = urlhaus.create_indicator_object(
        record,
        "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        valid_marking_id,
        [valid_marking_id],
    )
    assert stix_as_dict(ind) == {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--5887e7cc-e5ea-5955-853d-9f60d5d93c03",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-02T00:00:00.000Z",
        "name": "URL: http://bad.test",
        "indicator_types": ["malicious-activity"],
        "pattern": "[ url:value = 'http://bad.test' ]",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2026-01-01T00:00:00Z",
        "revoked": True,
        "labels": ["malware", "loader", "bot"],
        "external_references": [
            {"source_name": "urlhaus_link", "url": "https://urlhaus.example/item"}
        ],
        "object_marking_refs": [
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
        ],
    }


def test_process_records():
    record = {
        "id": "1",
        "dateadded": datetime(2026, 1, 1, tzinfo=UTC),
        "url": "http://bad.test",
        "url_status": "offline",
        "last_online": datetime(2026, 1, 2, tzinfo=UTC),
        "threat": "malware",
        "tags": "loader,bot",
        "urlhaus_link": "https://urlhaus.example/item",
        "reporter": "r",
    }
    valid_marking_id = "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    objs = urlhaus.process_records(
        [record],
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": valid_marking_id},
        {"id": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"},
    )
    assert len(objs) == 3


def test_create_indicator_with_none_tags_not_revoked():
    record = {
        "id": "1",
        "dateadded": datetime(2026, 1, 1, tzinfo=UTC),
        "url": "http://ok.test",
        "url_status": "online",
        "last_online": None,
        "threat": "malware",
        "tags": "None",
        "urlhaus_link": "https://urlhaus.example/item",
        "reporter": "r",
    }
    valid_marking_id = "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ind = urlhaus.create_indicator_object(
        record,
        "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        valid_marking_id,
        [valid_marking_id],
    )
    assert ind.revoked is False
    assert ind.labels == ["malware"]


def test_main_writes_outputs(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["urlhaus.py"])
    monkeypatch.setattr(urlhaus, "OUTPUT_DIR", str(tmp_path))

    csv_path = tmp_path / "u.csv"
    csv_path.write_text(
        "#comment\n"
        "1,2026-01-02 01:08:00,http://a,online,2026-01-02 12:00:00,malware,tag1,http://u,rep\n"
    )

    with patch(
        "processors.abuse_ch_urlhaus.urlhaus.download_urlhaus_data"
    ) as mock_download_urlhaus_data:
        mock_download_urlhaus_data.return_value = csv_path

        urlhaus.main()
    text = out_file.read_text()
    assert "bundle_path=" in text
    assert "latest_timestamp=" in text
    bundle_path = text.split("bundle_path=")[1].splitlines()[0].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",  # abuse.ch identity
        "marking-definition--89b3aa69-1f6d-5df0-a84b-cb31fba7e0f0",  # urlhaus marking
        "url--c348ae7c-d6bb-508d-a65f-9f2aa3802910",  # URL observable
        "indicator--40287512-f797-534e-ab85-91f3aa521ca3",  # indicator
        "relationship--508eaa6a-ed52-5cd9-a50f-cbedec0c34c6",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--40287512-f797-534e-ab85-91f3aa521ca3",
            "indicates",
            "url--c348ae7c-d6bb-508d-a65f-9f2aa3802910",
        ),
    }
