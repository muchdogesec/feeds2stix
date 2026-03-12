import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import processors
from processors.vxvault import vxvault
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_vxvault_identity():
    identity = vxvault.create_vxvault_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--aee958f7-4e54-55c5-aa62-ccb3a0bf11f3",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "VXVault",
        "description": "Recently identified malware samples and the URLs used to distribute them",
        "identity_class": "system",
        "contact_information": "http://vxvault.net/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_vxvault_marking_definition():
    marking = vxvault.create_vxvault_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--edc6fa46-17ed-5b5a-91d8-6307f8f486d6",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: http://vxvault.net/URL_List.php"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_vxvault_feed():
    content = (
        b"#comment\nhttp://example.com/malware.exe\n\nhttps://evil.com/bad\nnotaurl\n"
    )
    with patch(
        "processors.vxvault.vxvault.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        urls = vxvault.fetch_vxvault_feed()

    assert urls == ["http://example.com/malware.exe", "https://evil.com/bad"]


def test_create_stix_objects():
    objects = vxvault.create_stix_objects(
        ["http://example.com/malware.exe"],
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--afdf5315-f854-54d9-8b78-fdc90c16e3d8",
            "value": "http://example.com/malware.exe",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--bc8ca968-edd3-5f65-a01f-7ffdcaed1b65",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "URL: http://example.com/malware.exe",
            "indicator_types": ["malicious-activity"],
            "pattern": "[url:value='http://example.com/malware.exe']",
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
            "id": "relationship--501f2fb6-cbd5-5eff-b3ad-916110bcf983",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--bc8ca968-edd3-5f65-a01f-7ffdcaed1b65",
            "target_ref": "url--afdf5315-f854-54d9-8b78-fdc90c16e3d8",
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
    monkeypatch.setattr(sys, "argv", ["vxvault.py"])
    monkeypatch.setattr(vxvault, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.vxvault.vxvault.fetch_vxvault_feed",
        return_value=["http://example.com/malware.exe"],
    ):
        result = vxvault.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--aee958f7-4e54-55c5-aa62-ccb3a0bf11f3",  # vxvault identity
        "marking-definition--edc6fa46-17ed-5b5a-91d8-6307f8f486d6",  # vxvault marking
        "url--afdf5315-f854-54d9-8b78-fdc90c16e3d8",  # URL observable
        "indicator--bc8ca968-edd3-5f65-a01f-7ffdcaed1b65",  # indicator
        "relationship--099974e3-5d22-5c3d-981c-14a935878327",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--bc8ca968-edd3-5f65-a01f-7ffdcaed1b65",
            "indicates",
            "url--afdf5315-f854-54d9-8b78-fdc90c16e3d8",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["vxvault.py"])
    with patch(
        "processors.vxvault.vxvault.fetch_vxvault_feed",
        side_effect=RuntimeError("boom"),
    ):
        result = vxvault.main()

    assert result == 1
