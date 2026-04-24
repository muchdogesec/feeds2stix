import json
import sys
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import processors
from processors.threatview.threatview_sha1 import threatview_sha1
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_threatview_identity():
    identity = threatview_sha1.create_threatview_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "ThreatView",
        "description": "Verified threat feeds for immediate perimeter enforcement across security stacks.",
        "identity_class": "organization",
        "contact_information": "https://threatview.io/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_threatview_marking_definition():
    marking = threatview_sha1.create_threatview_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--8243f8ed-795a-5b6d-b1a4-c7d66d7ba53e",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: " + threatview_sha1.THREATVIEW_SHA_FEED_URL
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_threatview_feed():
    content = b"#comment\nda39a3ee5e6b4b0d3255bfef95601890afd80709\n\naaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d\n"
    with patch(
        "processors.threatview.threatview_sha1.threatview_sha1.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        items = threatview_sha1.fetch_threatview_feed()

    assert items == [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    ]


def test_create_stix_objects():
    objects = threatview_sha1.create_stix_objects(
        ["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
        {"id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52"},
        {"id": "marking-definition--8243f8ed-795a-5b6d-b1a4-c7d66d7ba53e"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--fa6e66a5-f019-51f9-8ab5-812023e58c6e",
            "hashes": {"SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--676e73d3-a40e-5f5d-8d00-9f95dc086d23",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "File SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "indicator_types": ["malicious-activity"],
            "pattern": "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709' ]",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--8243f8ed-795a-5b6d-b1a4-c7d66d7ba53e",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--cdb1213d-95b9-5c0c-9c2e-012c8f6d0df1",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--676e73d3-a40e-5f5d-8d00-9f95dc086d23",
            "target_ref": "file--fa6e66a5-f019-51f9-8ab5-812023e58c6e",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--8243f8ed-795a-5b6d-b1a4-c7d66d7ba53e",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatview_sha1.py"])
    monkeypatch.setattr(threatview_sha1, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.threatview.threatview_sha1.threatview_sha1.fetch_threatview_feed",
        return_value=["da39a3ee5e6b4b0d3255bfef95601890afd80709"],
    ):
        result = threatview_sha1.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--699c5731-66cb-5236-b314-68acb4ba3a52",  # threatview identity
        "marking-definition--8243f8ed-795a-5b6d-b1a4-c7d66d7ba53e",  # threatview marking
        "file--fa6e66a5-f019-51f9-8ab5-812023e58c6e",  # observable
        "indicator--676e73d3-a40e-5f5d-8d00-9f95dc086d23",  # indicator
        "relationship--cdb1213d-95b9-5c0c-9c2e-012c8f6d0df1",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--676e73d3-a40e-5f5d-8d00-9f95dc086d23",
            "indicates",
            "file--fa6e66a5-f019-51f9-8ab5-812023e58c6e",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threatview_sha1.py"])
    with patch(
        "processors.threatview.threatview_sha1.threatview_sha1.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = threatview_sha1.main()

    assert result == 1
