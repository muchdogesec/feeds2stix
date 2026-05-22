import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from processors.phishing_army import phishing_army
from helpers.utils import generate_uuid5
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_phishing_army_identity():
    identity = phishing_army.create_phishing_army_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--" + generate_uuid5("Phishing Army"),
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "Phishing Army",
        "description": "Phishing Army maintains a curated phishing blocklist derived from public phishing intelligence sources.",
        "identity_class": "system",
        "contact_information": "https://www.phishing.army/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_phishing_army_marking_definition():
    marking = phishing_army.create_phishing_army_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--"
        + generate_uuid5(
            "Origin: https://phishing.army/download/phishing_army_blocklist.txt"
        ),
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://phishing.army/download/phishing_army_blocklist.txt"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_phishing_army_feed(tmp_path):
    content = b"#comment\nExample.com\nbad.example\nfoo.example\nExample.com\n"
    with patch(
        "processors.phishing_army.phishing_army.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        domains = phishing_army.fetch_phishing_army_feed(tmp_path)

    assert domains == ["example.com", "bad.example", "foo.example"]
    assert (tmp_path / "phishing_army_blocklist.txt").read_bytes() == content


def test_create_indicator_object():
    indicator = phishing_army.create_indicator_object(
        "example.com",
        "identity--33b0b1ce-a291-55ce-8257-f3fa68810da7",
        "marking-definition--FD1A4475-B407-52AB-82E3-9928D37F9C15",
        "2026-05-01T02:47:00.000Z",
    )

    assert stix_as_dict(indicator) == {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--bb7c7c20-9308-5e89-b402-1b4debada8e4",
        "created_by_ref": "identity--33b0b1ce-a291-55ce-8257-f3fa68810da7",
        "created": "2026-05-01T02:47:00.000Z",
        "modified": "2026-05-01T02:47:00.000Z",
        "valid_from": "2026-05-01T02:47:00Z",
        "indicator_types": ["malicious-activity"],
        "name": "Domain Name: example.com",
        "pattern": "[domain-name:value = 'example.com']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "marking-definition--FD1A4475-B407-52AB-82E3-9928D37F9C15",
        ],
    }


def test_create_stix_objects():
    marking_id = "marking-definition--fd1a4475-b407-52ab-82e3-9928d37f9c15"

    objects = phishing_army.create_stix_objects(
        ["example.com"],
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": marking_id},
        "2026-05-01T02:47:00.000Z",
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
            "id": "indicator--bb7c7c20-9308-5e89-b402-1b4debada8e4",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-05-01T02:47:00.000Z",
            "modified": "2026-05-01T02:47:00.000Z",
            "name": "Domain Name: example.com",
            "indicator_types": ["malicious-activity"],
            "pattern": "[domain-name:value = 'example.com']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-05-01T02:47:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--fd1a4475-b407-52ab-82e3-9928d37f9c15",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--36688b0e-b967-5779-b6d2-23a63b91c02d",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-05-01T02:47:00.000Z",
            "modified": "2026-05-01T02:47:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--bb7c7c20-9308-5e89-b402-1b4debada8e4",
            "target_ref": "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--fd1a4475-b407-52ab-82e3-9928d37f9c15",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path, feeds2stix_marking):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(sys, "argv", ["phishing_army.py"])
    monkeypatch.setattr(phishing_army, "BASE_OUTPUT_DIR", str(tmp_path / "output"))

    with patch(
        "processors.phishing_army.phishing_army.fetch_external_objects",
        return_value=feeds2stix_marking,
    ), patch(
        "processors.phishing_army.phishing_army.fetch_phishing_army_feed",
        return_value=["example.com"],
    ):
        result = phishing_army.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
        "identity--33b0b1ce-a291-55ce-8257-f3fa68810da7",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        "indicator--bb7c7c20-9308-5e89-b402-1b4debada8e4",
        "relationship--36688b0e-b967-5779-b6d2-23a63b91c02d",
        "marking-definition--fd1a4475-b407-52ab-82e3-9928d37f9c15",
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--bb7c7c20-9308-5e89-b402-1b4debada8e4",
            "indicates",
            "domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7",
        )
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["phishing_army.py"])
    with patch(
        "processors.phishing_army.phishing_army.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = phishing_army.main()

    assert result == 1
