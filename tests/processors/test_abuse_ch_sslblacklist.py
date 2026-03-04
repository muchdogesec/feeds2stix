from datetime import UTC, datetime
from unittest.mock import patch
import sys

import processors
from processors.abuse_ch_sslblacklist import sslblacklist

from tests.utils import stix_as_dict
from tests import utils as test_utils


def test_create_abuse_ch_identity():
    identity = sslblacklist.create_abuse_ch_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "abuse.ch",
        "description": "abuse.ch has been effecting change on cybercrime for almost twenty years, owing to global recognition of our identified and tracked cyber threat signals. Supported by a community of 15,000 specialist researchers, abuse.ch's independent intelligence is relied on by security researchers, network operators and law enforcement agencies.",
        "identity_class": "organization",
        "contact_information": "https://abuse.ch/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_sslbl_marking_definition():
    marking = sslblacklist.create_sslbl_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin data source: https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_clean_listing_reason(subtests):
    with subtests.test("c2"):
        assert sslblacklist.clean_listing_reason("MyFamily C&C") == (
            "MyFamily",
            "command-and-control",
        )

    with subtests.test("distribution"):
        assert sslblacklist.clean_listing_reason("Bad malware distribution") == (
            "Bad",
            "hosting-malware",
        )

    with subtests.test("fallback"):
        assert sslblacklist.clean_listing_reason("something else") == ("Unknown", None)


def test_fetch_sslbl_feed():
    content = (
        b"#comment\n"
        b"2026-01-01 12:00:00,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,MyFamily C&C\n"
        b"invalid\n"
    )
    with patch(
        "processors.abuse_ch_sslblacklist.sslblacklist.requests.get",
        return_value=test_utils.FakeResponse(content=content),
    ):
        records = sslblacklist.fetch_sslbl_feed()

    assert records == {
        "MyFamily": [
            {
                "timestamp": datetime(2026, 1, 1, 12, 0, tzinfo=UTC),
                "sha1_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "infrastructure_type": "command-and-control",
            }
        ]
    }


def test_format_fingerprint():
    assert sslblacklist.format_fingerprint("aabbcc") == "aa:bb:cc"


def test_create_infrastructure_and_rels():
    malware_obj = sslblacklist.Malware(
        id="malware--301f8c24-291b-5a8c-8ca4-6e83e9138fd0",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        created="2026-01-01T10:00:00.000Z",
        modified="2026-01-01T10:00:00.000Z",
        name="FamilyA",
        malware_types=["remote-access-trojan"],
        is_family=True,
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    )

    objs = sslblacklist.create_infrastructure_and_rels(
        malware_obj,
        "command-and-control",
        [
            (
                "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
                datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            )
        ],
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    )

    assert stix_as_dict(objs[0]) == {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": "infrastructure--2a3e48cd-d284-5b5c-b2a2-207ef9209925",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2026-01-01T10:00:00.000Z",
        "modified": "2026-01-01T10:00:00.000Z",
        "name": "FamilyA C&C",
        "infrastructure_types": ["command-and-control"],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }
    rels = [(obj.source_ref, obj.relationship_type, obj.target_ref) for obj in objs[1:]]
    assert rels == [
        (
            "infrastructure--2a3e48cd-d284-5b5c-b2a2-207ef9209925",
            "controls",
            "malware--301f8c24-291b-5a8c-8ca4-6e83e9138fd0",
        ),
        (
            "infrastructure--2a3e48cd-d284-5b5c-b2a2-207ef9209925",
            "related-to",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
        (
            "malware--301f8c24-291b-5a8c-8ca4-6e83e9138fd0",
            "related-to",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
    ]


def test_create_stix_objects_for_malware():
    files_data = [
        {
            "timestamp": datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            "sha1_hash": "a" * 40,
            "infrastructure_type": "command-and-control",
        }
    ]
    objects = sslblacklist.create_stix_objects_for_malware(
        "FamilyA",
        files_data,
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
    )
    # test certificate, indicator and relationship from indicator to certificate - rest are tested in create_infrastructure_and_rels
    assert stix_as_dict(objects[:3]) == [
        {
            "type": "x509-certificate",
            "spec_version": "2.1",
            "id": "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
            "hashes": {"SHA-1": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--e7bb9c81-6f74-5375-9db2-a4daed6aa9ba",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T10:00:00.000Z",
            "modified": "2026-01-01T10:00:00.000Z",
            "name": "Certificate: aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa",
            "indicator_types": ["malicious-activity"],
            "pattern": "[ x509-certificate:hashes.'SHA-1' = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' ]",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T10:00:00Z",
            "external_references": [
                {
                    "source_name": "abuse.ch SSLBL",
                    "url": "https://sslbl.abuse.ch/ssl-certificates/sha1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--559ba789-4910-5a34-9d2e-477519f48eb0",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T10:00:00.000Z",
            "modified": "2026-01-01T10:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--e7bb9c81-6f74-5375-9db2-a4daed6aa9ba",
            "target_ref": "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            ],
        },
    ]


def test_create_stix_objects_for_malware_all_before_start_date():
    files_data = [
        {
            "timestamp": datetime(2024, 1, 1, 10, 0, tzinfo=UTC),
            "sha1_hash": "a" * 40,
            "infrastructure_type": "command-and-control",
        }
    ]
    objects = sslblacklist.create_stix_objects_for_malware(
        "FamilyA",
        files_data,
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
        start_date=datetime(2025, 1, 1, tzinfo=UTC),
    )
    assert objects == []


def test_create_all_stix_objects():
    mapping = {
        "FamilyA": [
            {
                "timestamp": datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
                "sha1_hash": "a" * 40,
                "infrastructure_type": "command-and-control",
            }
        ]
    }
    grouped = sslblacklist.create_all_stix_objects(
        mapping,
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
    )
    assert "FamilyA" in grouped
    assert len(grouped["FamilyA"]) == 8


def test_main_writes_outputs(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["sslblacklist.py"])
    monkeypatch.setattr(sslblacklist, "BASE_OUTPUT_DIR", str(tmp_path))

    with patch(
        "processors.abuse_ch_sslblacklist.sslblacklist.fetch_sslbl_feed"
    ) as mock_fetch_feed:
        mock_fetch_feed.return_value = {
            "FamilyA": [
                {
                    "timestamp": datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
                    "sha1_hash": "a" * 40,
                    "infrastructure_type": "command-and-control",
                }
            ]
        }

        sslblacklist.main()

    text = out_file.read_text()
    assert "bundle_path=" in text
