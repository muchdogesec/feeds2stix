import json
import sys
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import processors
from processors.threatview.threatview_domain import threatview_domain
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_threatview_identity():
    identity = threatview_domain.create_threatview_identity()
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
    marking = threatview_domain.create_threatview_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--fa335131-e752-5149-8f67-d6e21363d6bc",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: " + threatview_domain.THREATVIEW_DOMAIN_FEED_URL
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_threatview_feed():
    content = b"#comment\nexample.com\n\nmalware.org\n"
    with patch(
        "processors.threatview.threatview_domain.threatview_domain.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        items = threatview_domain.fetch_threatview_feed()

    assert items == ["example.com", "malware.org"]


def test_create_stix_objects():
    objects = threatview_domain.create_stix_objects(
        ["example.com"],
        {"id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52"},
        {"id": "marking-definition--fa335131-e752-5149-8f67-d6e21363d6bc"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
            "value": "example.com",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--69d09ead-6671-5690-ad2f-83daab3d1392",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Domain: example.com",
            "indicator_types": ["malicious-activity"],
            "pattern": "[domain-name:value='example.com']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--fa335131-e752-5149-8f67-d6e21363d6bc",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--674cf779-271e-5efe-a8e2-cccdedf289f6",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--69d09ead-6671-5690-ad2f-83daab3d1392",
            "target_ref": "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--fa335131-e752-5149-8f67-d6e21363d6bc",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatview_domain.py"])
    monkeypatch.setattr(threatview_domain, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.threatview.threatview_domain.threatview_domain.fetch_threatview_feed",
        return_value=["example.com"],
    ):
        result = threatview_domain.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--699c5731-66cb-5236-b314-68acb4ba3a52",  # threatview identity
        "marking-definition--fa335131-e752-5149-8f67-d6e21363d6bc",  # threatview marking
        "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",  # observable
        "indicator--69d09ead-6671-5690-ad2f-83daab3d1392",  # indicator
        "relationship--674cf779-271e-5efe-a8e2-cccdedf289f6",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--69d09ead-6671-5690-ad2f-83daab3d1392",
            "indicates",
            "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threatview_domain.py"])
    with patch(
        "processors.threatview.threatview_domain.threatview_domain.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = threatview_domain.main()

    assert result == 1
