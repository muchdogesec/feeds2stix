from datetime import UTC, datetime
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from processors.tweetfeed import tweetfeed
from tests.utils import FakeJSONResponse, stix_as_dict


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


def test_build_feed_url_uses_since_when_start_date_is_provided():
    start_date = datetime(2026, 5, 1, tzinfo=UTC)
    assert (
        tweetfeed.build_feed_url(start_date)
        == "https://api.tweetfeed.live/v1/since/2026-05-01T00:00:00Z"
    )


def test_build_feed_url_defaults_to_year_window():
    assert tweetfeed.build_feed_url() == "https://api.tweetfeed.live/v1/year"


def test_fetch_tweetfeed_data_uses_since_endpoint(
    monkeypatch, tmp_path, sample_records
):
    monkeypatch.chdir(tmp_path)
    start_date = datetime(2026, 5, 1, tzinfo=UTC)

    with patch(
        "processors.tweetfeed.tweetfeed.requests.get",
        return_value=FakeJSONResponse(sample_records),
    ) as mock_get:
        records = tweetfeed.fetch_tweetfeed_data(tmp_path, start_date=start_date)

    assert records == sample_records
    mock_get.assert_called_once_with(
        "https://api.tweetfeed.live/v1/since/2026-05-01T00:00:00Z",
        timeout=300,
    )
    assert (tmp_path / "tweetfeed_data.json").exists()


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


def test_create_stix_objects_dedupes_user_accounts(sample_records):
    source_identity = tweetfeed.create_tweetfeed_identity()
    source_marking = tweetfeed.create_tweetfeed_marking_definition()

    objects = tweetfeed.create_stix_objects(
        sample_records, source_identity, source_marking
    )
    object_types = [obj["type"] for obj in objects]

    assert object_types.count("user-account") == 1
    assert object_types.count("domain-name") == 1
    assert object_types.count("url") == 1
    assert object_types.count("indicator") == 2
    assert object_types.count("relationship") == 2


def test_main_uses_start_date_and_writes_bundle(
    monkeypatch, tmp_path, sample_records, feeds2stix_marking
):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(tweetfeed, "BASE_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(sys, "argv", ["tweetfeed.py", "--start-date", "2026-05-01"])

    captured = {}

    def fake_fetch(data_dir, start_date=None):
        captured["data_dir"] = data_dir
        captured["start_date"] = start_date
        return sample_records

    with patch(
        "processors.tweetfeed.tweetfeed.fetch_external_objects",
        return_value=feeds2stix_marking,
    ), patch(
        "processors.tweetfeed.tweetfeed.fetch_tweetfeed_data",
        side_effect=fake_fetch,
    ), patch(
        "processors.tweetfeed.tweetfeed.save_bundle_to_file",
        wraps=tweetfeed.save_bundle_to_file,
    ) as mock_save:
        assert tweetfeed.main() == 0

    assert captured["start_date"] == datetime(2026, 5, 1, tzinfo=UTC)
    assert captured["data_dir"] == Path(tmp_path / "output" / "data")
    assert mock_save.call_count == 1
    assert out_file.read_text().startswith("bundle_path=")
