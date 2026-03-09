import json
from datetime import UTC
from unittest.mock import patch
from pathlib import Path
import sys

import processors
from processors.threatview.threatview_url import threatview_url

from tests.utils import stix_as_dict
from tests import utils as test_utils


def test_create_threatview_identity():
    identity = threatview_url.create_threatview_identity()
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
    marking = threatview_url.create_threatview_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--ed57066c-39b9-5cc0-93db-4e9696b6050d",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: " + threatview_url.THREATVIEW_URL_FEED_URL},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_threatview_feed():
    content = b"#comment\nhttps://example.com/malware\n\nhttp://badsite.org\n"
    with patch(
        "processors.threatview.threatview_url.threatview_url.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        items = threatview_url.fetch_threatview_feed()

    assert items == ["https://example.com/malware", "http://badsite.org"]


def test_create_stix_objects():
    objects = threatview_url.create_stix_objects(
        ["https://example.com/malware"],
        {"id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52"},
        {"id": "marking-definition--ed57066c-39b9-5cc0-93db-4e9696b6050d"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--b25c8d33-90b8-5006-82e8-0a75c2b4420b",
            "value": "https://example.com/malware",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--034b23a8-30ae-522b-b063-df53c5def942",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "URL: https://example.com/malware",
            "indicator_types": ["malicious-activity"],
            "pattern": "[url:value='https://example.com/malware']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--ed57066c-39b9-5cc0-93db-4e9696b6050d",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--9af50439-b538-5e89-bf34-0249b04d4b84",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--034b23a8-30ae-522b-b063-df53c5def942",
            "target_ref": "url--b25c8d33-90b8-5006-82e8-0a75c2b4420b",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--ed57066c-39b9-5cc0-93db-4e9696b6050d",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatview_url.py"])
    monkeypatch.setattr(threatview_url, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.threatview.threatview_url.threatview_url.fetch_threatview_feed",
        return_value=["https://example.com/malware"],
    ):
        result = threatview_url.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix identity
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--699c5731-66cb-5236-b314-68acb4ba3a52",  # threatview identity
        "marking-definition--ed57066c-39b9-5cc0-93db-4e9696b6050d",  # threatview marking
        "url--b25c8d33-90b8-5006-82e8-0a75c2b4420b",  # observable
        "indicator--034b23a8-30ae-522b-b063-df53c5def942",  # indicator
        "relationship--9af50439-b538-5e89-bf34-0249b04d4b84",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--034b23a8-30ae-522b-b063-df53c5def942",
            "indicates",
            "url--b25c8d33-90b8-5006-82e8-0a75c2b4420b",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threatview_url.py"])
    with patch(
        "processors.threatview.threatview_url.threatview_url.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = threatview_url.main()

    assert result == 1
