import json
import sys
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import processors
from processors.threatview.threatview_md5 import threatview_md5
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_threatview_identity():
    identity = threatview_md5.create_threatview_identity()
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
    marking = threatview_md5.create_threatview_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--3a1851ea-7073-59ba-a7f1-9af05b48bb56",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: " + threatview_md5.THREATVIEW_MD5_FEED_URL
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_threatview_feed():
    content = b"#comment\nd41d8cd98f00b204e9800998ecf8427e\n\n5d41402abc4b2a76b9719d911017c592\n"
    with patch(
        "processors.threatview.threatview_md5.threatview_md5.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        items = threatview_md5.fetch_threatview_feed()

    assert items == [
        "d41d8cd98f00b204e9800998ecf8427e",
        "5d41402abc4b2a76b9719d911017c592",
    ]


def test_create_stix_objects():
    objects = threatview_md5.create_stix_objects(
        ["d41d8cd98f00b204e9800998ecf8427e"],
        {"id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52"},
        {"id": "marking-definition--3a1851ea-7073-59ba-a7f1-9af05b48bb56"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--02fff920-f614-527c-81d1-6353633a6d21",
            "hashes": {"MD5": "d41d8cd98f00b204e9800998ecf8427e"},
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--c5842fad-445c-50a9-bc31-4bebe2a2cc57",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "File MD5: d41d8cd98f00b204e9800998ecf8427e",
            "indicator_types": ["malicious-activity"],
            "pattern": "[file:hashes.MD5='d41d8cd98f00b204e9800998ecf8427e']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--3a1851ea-7073-59ba-a7f1-9af05b48bb56",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--13890ff1-d06b-5639-873f-d710846b4c6b",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--c5842fad-445c-50a9-bc31-4bebe2a2cc57",
            "target_ref": "file--02fff920-f614-527c-81d1-6353633a6d21",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--3a1851ea-7073-59ba-a7f1-9af05b48bb56",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatview_md5.py"])
    monkeypatch.setattr(threatview_md5, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.threatview.threatview_md5.threatview_md5.fetch_threatview_feed",
        return_value=["d41d8cd98f00b204e9800998ecf8427e"],
    ):
        result = threatview_md5.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--699c5731-66cb-5236-b314-68acb4ba3a52",  # threatview identity
        "marking-definition--3a1851ea-7073-59ba-a7f1-9af05b48bb56",  # threatview marking
        "file--02fff920-f614-527c-81d1-6353633a6d21",  # observable
        "indicator--c5842fad-445c-50a9-bc31-4bebe2a2cc57",  # indicator
        "relationship--13890ff1-d06b-5639-873f-d710846b4c6b",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--c5842fad-445c-50a9-bc31-4bebe2a2cc57",
            "indicates",
            "file--02fff920-f614-527c-81d1-6353633a6d21",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threatview_md5.py"])
    with patch(
        "processors.threatview.threatview_md5.threatview_md5.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = threatview_md5.main()

    assert result == 1
