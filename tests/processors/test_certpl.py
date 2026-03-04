from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sys

import processors
from processors.certpl import certpl
from helpers import utils as helper_utils

from tests.utils import stix_as_dict
from tests import utils as test_utils


def test_create_certpl_identity():
    identity = certpl.create_certpl_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--5f500688-dc80-5611-8435-dc1561d3817e",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "CERT.PL",
        "description": "Poland's national computer security incident response team.",
        "identity_class": "organization",
        "contact_information": "https://cert.pl/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_certpl_marking_definition():
    marking = certpl.create_certpl_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--83cddfd9-ec81-5521-b105-60482ecc9ba2",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://hole.cert.pl/domains/v2/domains.txt"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_certpl_feed():
    content = b"#comment\nexample.com\n\nbad.example\n"
    with patch(
        "processors.certpl.certpl.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        domains = certpl.fetch_certpl_feed()

    assert domains == ["example.com", "bad.example"]


def test_create_stix_objects():

    objects = certpl.create_stix_objects(
        ["evil.example"],
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "domain-name",
            "spec_version": "2.1",
            "id": "domain-name--69228563-c8d2-54ae-aeca-5f4134cb59aa",
            "value": "evil.example",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--c9846bc1-74b3-5195-9699-b404ef5c09f1",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Domain Name: evil.example",
            "indicator_types": ["malicious-activity"],
            "pattern": "[domain-name:value='evil.example']",
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
            "id": "relationship--056dcd32-2124-5ace-adb9-bfbf4fc7b252",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--c9846bc1-74b3-5195-9699-b404ef5c09f1",
            "target_ref": "domain-name--69228563-c8d2-54ae-aeca-5f4134cb59aa",
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
    monkeypatch.setattr(sys, "argv", ["certpl.py"])
    monkeypatch.setattr(certpl, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.certpl.certpl.fetch_certpl_feed", return_value=["evil.example"]
    ):
        result = certpl.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["certpl.py"])
    with patch(
        "processors.certpl.certpl.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = certpl.main()

    assert result == 1
