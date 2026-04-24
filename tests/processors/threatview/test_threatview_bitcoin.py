import json
import sys
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import processors
from processors.threatview.threatview_bitcoin import threatview_bitcoin
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_threatview_identity():
    identity = threatview_bitcoin.create_threatview_identity()
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
    marking = threatview_bitcoin.create_threatview_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--6808dd62-9c8e-5450-9b02-22d6115cbede",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://threatview.io/Downloads/MALICIOUS-BITCOIN_FEED.txt"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_threatview_feed():
    content = b"#comment\n1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n\n1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n"
    with patch(
        "processors.threatview.threatview_bitcoin.threatview_bitcoin.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        items = threatview_bitcoin.fetch_threatview_feed()

    assert items == [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    ]


def test_create_stix_objects():
    objects = threatview_bitcoin.create_stix_objects(
        ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        {"id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52"},
        {"id": "marking-definition--6808dd62-9c8e-5450-9b02-22d6115cbede"},
        "2026-01-01T00:00:00.000Z",
    )

    assert stix_as_dict(objects) == [
        {
            "type": "cryptocurrency-wallet",
            "spec_version": "2.1",
            "id": "cryptocurrency-wallet--bfa4b8d0-956b-5468-b03d-be19bb5163dd",
            "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "extensions": {
                "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
                    "extension_type": "new-sco"
                }
            },
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--22692bd4-1b7f-52cb-a0b6-81d3ec1f24f1",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Cryptocurrency Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "indicator_types": ["malicious-activity"],
            "pattern": "[cryptocurrency-wallet:value = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--6808dd62-9c8e-5450-9b02-22d6115cbede",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--ff13723e-79c5-554d-bb7f-b3c573c5d832",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--22692bd4-1b7f-52cb-a0b6-81d3ec1f24f1",
            "target_ref": "cryptocurrency-wallet--bfa4b8d0-956b-5468-b03d-be19bb5163dd",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--6808dd62-9c8e-5450-9b02-22d6115cbede",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatview_bitcoin.py"])
    monkeypatch.setattr(threatview_bitcoin, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.threatview.threatview_bitcoin.threatview_bitcoin.fetch_threatview_feed",
        return_value=["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
    ):
        result = threatview_bitcoin.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--699c5731-66cb-5236-b314-68acb4ba3a52",  # threatview identity
        "marking-definition--6808dd62-9c8e-5450-9b02-22d6115cbede",  # threatview marking
        "cryptocurrency-wallet--bfa4b8d0-956b-5468-b03d-be19bb5163dd",  # observable
        "indicator--22692bd4-1b7f-52cb-a0b6-81d3ec1f24f1",  # indicator
        "relationship--ff13723e-79c5-554d-bb7f-b3c573c5d832",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--22692bd4-1b7f-52cb-a0b6-81d3ec1f24f1",
            "indicates",
            "cryptocurrency-wallet--bfa4b8d0-956b-5468-b03d-be19bb5163dd",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threatview_bitcoin.py"])
    with patch(
        "processors.threatview.threatview_bitcoin.threatview_bitcoin.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = threatview_bitcoin.main()

    assert result == 1
