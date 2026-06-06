import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import pytest

from processors.tweetfeed import tweetfeed
from tests.utilities import stix_as_dict


@pytest.fixture
def sample_records():
    return [
        {
            "date": "2026-05-01 02:47:00",
            "user": "harugasumi",
            "type": "domain",
            "value": "nedabaci.z4.web.core.windows.net",
            "tags": ["#phishing", "#CobaltStrike"],
            "tweet": "https://x.com/harugasumi/status/2050044303926505846",
        },
        {
            "date": "2026-05-01 02:47:00",
            "user": "harugasumi",
            "type": "url",
            "value": "https://nedabaci.z4.web.core.windows.net",
            "tags": [],
            "tweet": "https://x.com/harugasumi/status/2050044303926505846",
        },
    ]


def test_parse_record_timestamp_returns_utc():
    timestamp = tweetfeed.parse_record_timestamp("2026-05-01 02:47:00")

    assert timestamp == datetime(2026, 5, 1, 2, 47, tzinfo=UTC)


def test_load_data_from_csv_filters_rows_and_parses_tags(tmp_path):
    csv_path = tmp_path / "20260501.csv"
    csv_path.write_text(
        "\n".join(
            [
                "2026-04-30 23:59:59,skip,url,https://skip.example/#,\"#ignore\",https://x.com/skip",
                "2026-05-01 02:47:00,harugasumi,domain,nedabaci.z4.web.core.windows.net,\"#phishing #CobaltStrike\",https://x.com/harugasumi/status/2050044303926505846",
                "2026-05-02 00:00:00,blank,url,https://blank.example/#,\"#phishing\",",
            ]
        )
        + "\n"
    )

    rows = list(
        tweetfeed.load_data_from_csv(
            csv_path,
            "2026-05-01 00:00:00",
            "2026-05-01 23:59:59",
        )
    )

    assert rows == [
        {
            "date": "2026-05-01 02:47:00",
            "user": "harugasumi",
            "type": "domain",
            "value": "nedabaci.z4.web.core.windows.net",
            "tags": ("phishing", "CobaltStrike"),
            "tweet": "https://x.com/harugasumi/status/2050044303926505846",
        }
    ]


def test_get_data_for_time_range_reads_repo_tree(tmp_path):
    repo_path = tmp_path / "TweetFeed"
    first_file = repo_path / "202605" / "202605" / "20260501.csv"
    second_file = repo_path / "202606" / "202606" / "20260602.csv"
    first_file.parent.mkdir(parents=True)
    second_file.parent.mkdir(parents=True)

    first_file.write_text(
        "2026-05-01 02:47:00,harugasumi,domain,nedabaci.z4.web.core.windows.net,\"#phishing\",https://x.com/harugasumi/status/2050044303926505846\n"
    )
    second_file.write_text(
        "2026-06-02 10:00:00,harugasumi,url,https://example.com,\"#phishing\",https://x.com/harugasumi/status/2050044303926505846\n"
    )

    records = list(
        tweetfeed.get_data_for_time_range(
            repo_path,
            start_dt=datetime(2026, 5, 1, tzinfo=UTC),
            end_dt=datetime(2026, 6, 30, tzinfo=UTC),
        )
    )

    assert [month for month, _ in records] == ["202605", "202606"]
    assert records[0][1]["value"] == "nedabaci.z4.web.core.windows.net"
    assert records[1][1]["value"] == "https://example.com"


@pytest.mark.parametrize(
    "record, expected_type, expected_value",
    [
        (
            {
                "date": "2026-05-01 02:47:00",
                "user": "harugasumi",
                "type": "domain",
                "value": "nedabaci.z4.web.core.windows.net",
                "tags": [],
                "tweet": "https://x.com/harugasumi/status/2050044303926505846",
            },
            "domain-name",
            "nedabaci.z4.web.core.windows.net",
        ),
        (
            {
                "date": "2026-05-01 02:47:00",
                "user": "harugasumi",
                "type": "ip",
                "value": "138.124.183.147",
                "tags": [],
                "tweet": "https://x.com/harugasumi/status/2050044303926505846",
            },
            "ipv4-addr",
            "138.124.183.147",
        ),
        (
            {
                "date": "2026-05-01 02:47:00",
                "user": "harugasumi",
                "type": "md5",
                "value": "8d777f385d3dfec8815d20f7496026dc",
                "tags": [],
                "tweet": "https://x.com/harugasumi/status/2050044303926505846",
            },
            "file",
            "8d777f385d3dfec8815d20f7496026dc",
        ),
        (
            {
                "date": "2026-05-01 02:47:00",
                "user": "harugasumi",
                "type": "sha256",
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "tags": [],
                "tweet": "https://x.com/harugasumi/status/2050044303926505846",
            },
            "file",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            {
                "date": "2026-05-01 02:47:00",
                "user": "harugasumi",
                "type": "url",
                "value": "https://nedabaci.z4.web.core.windows.net",
                "tags": [],
                "tweet": "https://x.com/harugasumi/status/2050044303926505846",
            },
            "url",
            "https://nedabaci.z4.web.core.windows.net",
        ),
    ],
)
def test_create_sco_object_for_supported_types(record, expected_type, expected_value):
    sco = tweetfeed.create_sco_object(record)
    sco_dict = stix_as_dict(sco)

    assert sco_dict["type"] == expected_type
    if expected_type == "file":
        assert expected_value in sco_dict["hashes"].values()
    else:
        assert sco_dict["value"] == expected_value


def test_create_indicator_object():
    record = {
        "date": "2026-05-01 02:47:00",
        "user": "harugasumi",
        "type": "url",
        "value": "https://nedabaci.z4.web.core.windows.net",
        "tags": ["#phishing", "#CobaltStrike"],
        "tweet": "https://x.com/harugasumi/status/2050044303926505846",
    }

    indicator = tweetfeed.create_indicator_object(
        record,
        "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",
        "marking-definition--fa842ad5-5a7b-56d9-a158-92fa8b0d94ad",
    )

    indicator_dict = stix_as_dict(indicator)
    print(indicator_dict)
    assert indicator_dict == {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--b4a772a0-5b50-5cb4-a298-ae3c398bde79",
        "created_by_ref": "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",
        "created": "2026-05-01T02:47:00.000Z",
        "modified": "2026-05-01T02:47:00.000Z",
        "name": "URL: https://nedabaci.z4.web.core.windows.net",
        "indicator_types": ["malicious-activity"],
        "pattern": "[url:value = 'https://nedabaci.z4.web.core.windows.net']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2026-05-01T02:47:00Z",
        "labels": ["cobaltstrike", "phishing"],
        "external_references": [
            {
                "source_name": "x_url",
                "url": "https://x.com/harugasumi/status/2050044303926505846",
            }
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "marking-definition--fa842ad5-5a7b-56d9-a158-92fa8b0d94ad",
        ],
    }


def test_create_stix_objects_dedupes_user_accounts_and_links_attack_pattern(sample_records):
    source_identity = tweetfeed.create_tweetfeed_identity()
    source_marking = tweetfeed.create_tweetfeed_marking_definition()

    with patch(
        "processors.tweetfeed.tweetfeed.fetch_enterprise_attack_object",
        return_value={
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Phishing",
        },
    ):
        objects = tweetfeed.create_stix_objects(
            sample_records,
            source_identity,
            source_marking,
        )

    object_types = [obj["type"] for obj in objects]

    assert object_types.count("user-account") == 1
    assert object_types.count("domain-name") == 1
    assert object_types.count("url") == 1
    assert object_types.count("indicator") == 2
    assert object_types.count("attack-pattern") == 1
    assert object_types.count("relationship") == 5
    rels = [
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in objects
        if obj["type"] == "relationship"
    ]
    assert rels == [
        (
            "indicator--3add6527-5a41-51a2-93fd-f1c0c40c7719",
            "indicates",
            "domain-name--1ec3675b-d139-5a9d-a859-e3e4dc9fbd4a",
        ),
        (
            "indicator--3add6527-5a41-51a2-93fd-f1c0c40c7719",
            "related-to",
            "user-account--1737445b-c4bc-50b4-a041-aeebc59fc49b",
        ),
        (
            "indicator--3add6527-5a41-51a2-93fd-f1c0c40c7719",
            "indicates",
            "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
        ),
        (
            "indicator--b4a772a0-5b50-5cb4-a298-ae3c398bde79",
            "indicates",
            "url--c524b1b4-77ee-5a21-8f96-3ce6734f1041",
        ),
        (
            "indicator--b4a772a0-5b50-5cb4-a298-ae3c398bde79",
            "related-to",
            "user-account--1737445b-c4bc-50b4-a041-aeebc59fc49b",
        ),
    ]


def test_main_uses_start_date_and_writes_bundle(
    monkeypatch, tmp_path, sample_records
):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(tweetfeed, "BASE_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "tweetfeed.py",
            "--start-date",
            "2026-05-01",
            "--until-date",
            "2026-06-30",
        ],
    )

    feeds2stix_marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "feeds2stix"},
    }

    grouped_records = [
        ("202605p01", [sample_records[0]]),
        ("202606p01", [sample_records[1]]),
    ]

    with patch(
        "processors.tweetfeed.tweetfeed.fetch_external_objects",
        return_value=feeds2stix_marking,
    ), patch(
        "processors.tweetfeed.tweetfeed.get_data_for_time_range",
        return_value=iter(
            [
                ("202605", sample_records[0]),
                ("202606", sample_records[1]),
            ]
        ),
    ), patch(
        "processors.tweetfeed.tweetfeed.group_data_by_month",
        return_value=iter(grouped_records),
    ), patch(
        "processors.tweetfeed.tweetfeed.fetch_enterprise_attack_object",
        return_value={
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Phishing",
        },
    ):
        assert tweetfeed.main() == 0

    assert out_file.exists()
    content = out_file.read_text()
    assert "bundle_path=" in content
    assert "bundle_count=2" in content

    bundle_dir = Path(content.split("bundle_path=")[1].splitlines()[0].strip())
    bundle_files = sorted(path.name for path in bundle_dir.glob("*.json"))
    assert bundle_files == [
        "tweetfeed_202605p01.json",
        "tweetfeed_202606p01.json",
    ]
