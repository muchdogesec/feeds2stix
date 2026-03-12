import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import processors
from processors.abuse_ch_sslblacklist import sslblacklist
from tests import utils as test_utils
from tests.utils import stix_as_dict


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
            "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",
        ],
    )

    objs = sslblacklist.create_infrastructure_and_rels(
        malware_obj,
        "command-and-control",
        [
            (
                "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
                "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",
                datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            )
        ],
        "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",
    )

    assert stix_as_dict(objs[0]) == {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": "infrastructure--8099ce81-59b6-5316-a1c5-d6a15aaddc00",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2026-01-01T10:00:00.000Z",
        "modified": "2026-01-01T10:00:00.000Z",
        "name": "FamilyA C&C",
        "infrastructure_types": ["command-and-control"],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",
        ],
    }
    rels = [(obj.source_ref, obj.relationship_type, obj.target_ref) for obj in objs[1:]]
    assert rels == [
        (
            "infrastructure--8099ce81-59b6-5316-a1c5-d6a15aaddc00",
            "controls",
            "malware--301f8c24-291b-5a8c-8ca4-6e83e9138fd0",
        ),
        (
            "infrastructure--8099ce81-59b6-5316-a1c5-d6a15aaddc00",
            "related-to",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
        (
            "malware--301f8c24-291b-5a8c-8ca4-6e83e9138fd0",
            "related-to",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
        (
            "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",
            "indicates",
            "malware--301f8c24-291b-5a8c-8ca4-6e83e9138fd0",
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
        {"id": "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216"},
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
            "id": "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",
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
                "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--469b2848-2153-5034-a50b-8863d1d993e0",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T10:00:00.000Z",
            "modified": "2026-01-01T10:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",
            "target_ref": "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",
            ],
        },
    ]

def test_guess_malware_type():
    assert sslblacklist.guess_malware_type("BadRAT") == "remote-access-trojan"
    assert sslblacklist.guess_malware_type("UnknownFamily") == "unknown"

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
        {"id": "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216"},
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
        {"id": "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216"},
    )
    assert "FamilyA" in grouped
    assert len(grouped["FamilyA"]) == 9


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

    bundle_path = text.split("bundle_path=")[1].strip()
    # Find the actual bundle file in the directory
    bundle_files = list(Path(bundle_path).glob("*.json"))
    assert len(bundle_files) == 1
    bundle = json.loads(bundle_files[0].read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",  # abuse.ch identity
        "marking-definition--77164cc6-e945-50ab-96fb-574d72e8f216",  # sslblacklist marking
        "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",  # certificate observable
        "malware--8251c6a0-28e9-596c-9b77-0ca1a66ed61d",  # malware
        "infrastructure--8099ce81-59b6-5316-a1c5-d6a15aaddc00",  # infrastructure
        "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",  # indicator
        "relationship--46848ad3-fcaf-537b-8bbe-3dc22b880d55",  # relationship 1
        "relationship--469b2848-2153-5034-a50b-8863d1d993e0",  # relationship 2
        "relationship--a6382ce1-cdcf-5825-98aa-6c270428b348",  # relationship 3
        "relationship--c0807faf-58d3-5d1b-a779-433093a959d9",  # relationship 4
        "relationship--a6d2b059-83c1-5f12-baed-d9c5aa5500f7",  # relationship 5
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",
            "indicates",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
        (
            "infrastructure--8099ce81-59b6-5316-a1c5-d6a15aaddc00",
            "controls",
            "malware--8251c6a0-28e9-596c-9b77-0ca1a66ed61d",
        ),
        (
            "infrastructure--8099ce81-59b6-5316-a1c5-d6a15aaddc00",
            "related-to",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
        (
            "malware--8251c6a0-28e9-596c-9b77-0ca1a66ed61d",
            "related-to",
            "x509-certificate--1e901a93-d663-59b6-88a6-edc0114b78c9",
        ),
        (
            "indicator--8dde1a7c-f9bd-57ca-b178-1113195481b4",
            "indicates",
            "malware--8251c6a0-28e9-596c-9b77-0ca1a66ed61d",
        ),
    }
