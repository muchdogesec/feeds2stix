import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import processors
from processors.ipsum import ipsum
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_ipsum_identity():
    identity = ipsum.create_ipsum_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--9d7266e0-e0e7-529a-a840-7df15fb8fcf2",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "IPSum",
        "description": "IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses.",
        "identity_class": "system",
        "contact_information": "https://github.com/stamparm/ipsum",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_ipsum_marking_definition():
    marking = ipsum.create_ipsum_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: https://github.com/stamparm/ipsum"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_ipsum_feed():
    content = b"#comment\n1.2.3.4\n\n5.6.7.8\n"
    with patch(
        "processors.ipsum.ipsum.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        ips = ipsum.fetch_ipsum_feed(level=8)

    assert ips == ["1.2.3.4", "5.6.7.8"]


def test_create_stix_objects():
    ip_addresses_by_level = {8: ["1.2.3.4"], 5: ["5.6.7.8"]}
    objects = ipsum.create_stix_objects(
        ip_addresses_by_level,
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "value": "1.2.3.4",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--7812c57d-b540-5bad-9952-00412705c8d4",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "IPv4: 1.2.3.4",
            "confidence": 100,
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value='1.2.3.4']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--b5b29cf9-8e4d-58ad-82b9-bc2cf125235b",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--7812c57d-b540-5bad-9952-00412705c8d4",
            "target_ref": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9",
            ],
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--2a20be58-fd0f-5a24-ac7a-f65ce409d7e4",
            "value": "5.6.7.8",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--4944b7ee-5de8-5b36-9579-3d28c3fb3286",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "IPv4: 5.6.7.8",
            "confidence": 70,
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value='5.6.7.8']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--7a833778-3287-5bd9-be92-27a42fb66c15",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--4944b7ee-5de8-5b36-9579-3d28c3fb3286",
            "target_ref": "ipv4-addr--2a20be58-fd0f-5a24-ac7a-f65ce409d7e4",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9",
            ],
        },
    ]


def test_fetch_all_levels():
    content_level_8 = b"1.2.3.4\n5.6.7.8\n"
    content_level_7 = b"1.2.3.4\n9.10.11.12\n"
    content_level_5 = b"13.14.15.16\n"

    def mock_get(url):
        if "levels/8.txt" in url:
            return test_utils.FakeResponse(content=content_level_8)
        elif "levels/7.txt" in url:
            return test_utils.FakeResponse(content=content_level_7)
        elif "levels/6.txt" in url:
            return test_utils.FakeResponse(content=b"")
        elif "levels/5.txt" in url:
            return test_utils.FakeResponse(content=content_level_5)
        return test_utils.FakeResponse(content=b"")

    with patch("processors.ipsum.ipsum.requests.get", side_effect=mock_get):
        result = ipsum.fetch_all_levels(min_level=5)

    assert result == {
        8: ["1.2.3.4", "5.6.7.8"],
        7: ["9.10.11.12"],
        5: ["13.14.15.16"],
    }


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["ipsum.py", "--min-level", "8"])
    monkeypatch.setattr(ipsum, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.ipsum.ipsum.fetch_all_levels", return_value={8: ["1.2.3.4"]}
    ):
        result = ipsum.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--9d7266e0-e0e7-529a-a840-7df15fb8fcf2",  # ipsum identity
        "marking-definition--86f47b9b-d446-511a-af0b-6bace17a72b9",  # ipsum marking
        "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",  # IP observable
        "indicator--7812c57d-b540-5bad-9952-00412705c8d4",  # indicator
        "relationship--b5b29cf9-8e4d-58ad-82b9-bc2cf125235b",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--7812c57d-b540-5bad-9952-00412705c8d4",
            "indicates",
            "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["ipsum.py", "--min-level", "8"])
    with patch(
        "processors.ipsum.ipsum.fetch_all_levels", side_effect=RuntimeError("boom")
    ):
        result = ipsum.main()

    assert result == 1
