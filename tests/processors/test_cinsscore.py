import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import processors
from processors.cinsscore import cinsscore
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_cinsscore_identity():
    identity = cinsscore.create_cinsscore_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--c61334ee-05d8-5109-8c4e-14fa29bc4744",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "CINS",
        "description": 'Collective Intelligence Network Security (CINS, pronounced "sins," get it?) is our effort to use this information to significantly improve the security of our customers\' networks. We also provide this vital information to the InfoSec community free of charge.',
        "identity_class": "system",
        "contact_information": "https://cinsarmy.com/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_cinsscore_marking_definition():
    marking = cinsscore.create_cinsscore_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--8d6fa91a-011b-5755-8fd2-1b0bde36eec7",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://cinsscore.com/list/ci-badguys.txt"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_cinsscore_feed():
    content = b"#comment\n1.2.3.4\n\n5.6.7.8\n"
    with patch(
        "processors.cinsscore.cinsscore.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        ips = cinsscore.fetch_cinsscore_feed()

    assert ips == ["1.2.3.4", "5.6.7.8"]


def test_create_stix_objects():
    objects = cinsscore.create_stix_objects(
        ["1.2.3.4"],
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--8d6fa91a-011b-5755-8fd2-1b0bde36eec7"},
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
            "id": "indicator--729f4445-4463-544f-909a-bf7d2c4e19b2",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "IPv4: 1.2.3.4",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ipv4-addr:value = '1.2.3.4' ]",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--8d6fa91a-011b-5755-8fd2-1b0bde36eec7",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--b45594f5-0ed2-5b23-9b25-6a7fff78f247",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--729f4445-4463-544f-909a-bf7d2c4e19b2",
            "target_ref": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--8d6fa91a-011b-5755-8fd2-1b0bde36eec7",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["cinsscore.py"])
    monkeypatch.setattr(cinsscore, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.cinsscore.cinsscore.fetch_cinsscore_feed", return_value=["1.2.3.4"]
    ):
        result = cinsscore.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--c61334ee-05d8-5109-8c4e-14fa29bc4744",  # cinsscore identity
        "marking-definition--8d6fa91a-011b-5755-8fd2-1b0bde36eec7",  # cinsscore marking
        "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",  # IP observable
        "indicator--729f4445-4463-544f-909a-bf7d2c4e19b2",  # indicator
        "relationship--b45594f5-0ed2-5b23-9b25-6a7fff78f247",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--729f4445-4463-544f-909a-bf7d2c4e19b2",
            "indicates",
            "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["cinsscore.py"])
    with patch(
        "processors.cinsscore.cinsscore.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = cinsscore.main()

    assert result == 1
