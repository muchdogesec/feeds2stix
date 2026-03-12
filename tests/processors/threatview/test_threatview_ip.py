import json
import sys
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

import processors
from processors.threatview.threatview_ip import threatview_ip
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_threatview_identity():
    identity = threatview_ip.create_threatview_identity()
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
    marking = threatview_ip.create_threatview_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--a070d1fd-3989-5629-a0f6-44b589a8ec00",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: " + threatview_ip.THREATVIEW_IP_FEED_URL},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_fetch_threatview_feed():
    content = b"#comment\n1.2.3.4\n\n5.6.7.8\n"
    with patch(
        "processors.threatview.threatview_ip.threatview_ip.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        items = threatview_ip.fetch_threatview_feed()

    assert items == ["1.2.3.4", "5.6.7.8"]


def test_create_stix_objects():
    objects = threatview_ip.create_stix_objects(
        ["1.2.3.4"],
        {"id": "identity--699c5731-66cb-5236-b314-68acb4ba3a52"},
        {"id": "marking-definition--a070d1fd-3989-5629-a0f6-44b589a8ec00"},
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
            "id": "indicator--5f85e50e-3805-5a6d-8dee-c20e66a0174f",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
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
                "marking-definition--a070d1fd-3989-5629-a0f6-44b589a8ec00",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--7f3f901a-a23e-574c-838d-a8b214348549",
            "created_by_ref": "identity--699c5731-66cb-5236-b314-68acb4ba3a52",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--5f85e50e-3805-5a6d-8dee-c20e66a0174f",
            "target_ref": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a070d1fd-3989-5629-a0f6-44b589a8ec00",
            ],
        },
    ]


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatview_ip.py"])
    monkeypatch.setattr(threatview_ip, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.threatview.threatview_ip.threatview_ip.fetch_threatview_feed",
        return_value=["1.2.3.4"],
    ):
        result = threatview_ip.main()

    assert result == 0
    assert "bundle_path=" in out_file.read_text()
    bundle_path = out_file.read_text().split("bundle_path=")[1].strip()
    assert Path(bundle_path).exists()

    bundle = json.loads(Path(bundle_path).read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--699c5731-66cb-5236-b314-68acb4ba3a52",  # threatview identity
        "marking-definition--a070d1fd-3989-5629-a0f6-44b589a8ec00",  # threatview marking
        "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",  # observable
        "indicator--5f85e50e-3805-5a6d-8dee-c20e66a0174f",  # indicator
        "relationship--7f3f901a-a23e-574c-838d-a8b214348549",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--5f85e50e-3805-5a6d-8dee-c20e66a0174f",
            "indicates",
            "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
        ),
    }


def test_main_failure_returns_one(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["threatview_ip.py"])
    with patch(
        "processors.threatview.threatview_ip.threatview_ip.setup_output_directory",
        side_effect=RuntimeError("boom"),
    ):
        result = threatview_ip.main()

    assert result == 1
