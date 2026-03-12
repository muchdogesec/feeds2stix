import json
import sys
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import processors
from processors.blocklist_de import blocklist_de
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_blocklist_de_identity():
    identity = blocklist_de.create_blocklist_de_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--036b89f1-524e-5757-8651-a698c3c2bbd7",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "blocklist.de",
        "description": "www.blocklist.de is a free and voluntary service provided by a Fraud/Abuse-specialist, whose servers are often attacked via SSH-, Mail-Login-, FTP-, Webserver- and other services.",
        "identity_class": "system",
        "contact_information": "https://www.blocklist.de/en/index.html",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_blocklist_de_marking_definition():
    marking = blocklist_de.create_blocklist_de_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--aad171fe-8e6f-5bc2-aa9a-7cfd7ef38edf",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: https://lists.blocklist.de/lists/all.txt"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_blocklist_de_feed():
    content = b"#comment\n1.2.3.4\n\n5.6.7.8\n"
    with patch(
        "processors.blocklist_de.blocklist_de.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        ips = blocklist_de.fetch_blocklist_de_feed()

    assert ips == ["1.2.3.4", "5.6.7.8"]


def test_create_stix_objects():
    objects = blocklist_de.create_stix_objects(
        ["1.2.3.4"],
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
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
            "id": "indicator--716afde3-c644-54f0-a63b-9e707f0cfa26",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "IPv4: 1.2.3.4",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value='1.2.3.4']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--e3993871-8875-5820-89e7-19c00b49bdbb",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--716afde3-c644-54f0-a63b-9e707f0cfa26",
            "target_ref": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["blocklist_de.py"])
    monkeypatch.setattr(blocklist_de, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.blocklist_de.blocklist_de.fetch_blocklist_de_feed",
        return_value=["1.2.3.4"],
    ):
        result = blocklist_de.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--036b89f1-524e-5757-8651-a698c3c2bbd7",  # blocklist_de identity
        "marking-definition--aad171fe-8e6f-5bc2-aa9a-7cfd7ef38edf",  # blocklist_de marking
        "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",  # IP observable
        "indicator--5dc27fa7-3667-5db8-b242-aff63e973b8b",  # indicator
        "relationship--35c25c4e-02ff-534a-8f73-907fb7dae7f9",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--5dc27fa7-3667-5db8-b242-aff63e973b8b",
            "indicates",
            "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["blocklist_de.py"])
    with patch(
        "processors.blocklist_de.blocklist_de.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = blocklist_de.main()

    assert result == 1
