import json
import sys
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import processors
from processors.phishtank import phishtank
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_phishtank_identity():
    identity = phishtank.create_phishtank_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--8018d80e-ad1d-505e-a89b-de7f36a38317",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "PhishTank",
        "description": "PhishTank is a collaborative clearing house for data and information about phishing on the Internet. Also, PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.",
        "identity_class": "system",
        "contact_information": "https://www.phishtank.com/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_phishtank_marking_definition():
    marking = phishtank.create_phishtank_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: http://data.phishtank.com/data/online-valid.json.gz"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


# def test_fetch_phishtank_data():
#     # Mock the file read
#     mock_data = [{"phish_id": 123, "url": "http://example.com"}]
#     mock_gzipped = json.dumps(mock_data).encode()
#     with patch("pathlib.Path.read_bytes", return_value=mock_gzipped):
#         with patch("gzip.GzipFile") as mock_gzip:
#             mock_gzip.return_value.__enter__.return_value = io.StringIO(json.dumps(mock_data))
#             data = phishtank.fetch_phishtank_data()
#             assert data == mock_data


def test_group_entries_to_max_N_elements():
    entries = [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5}]
    grouped = phishtank.group_entries_to_max_N_elements(entries, 2)
    assert grouped == {
        "001": [{"id": 1}, {"id": 2}],
        "002": [{"id": 3}, {"id": 4}],
        "003": [{"id": 5}],
    }


def test_filter_entries_by_date():
    from datetime import datetime, UTC

    entries = [
        {
            "submission_time": "2026-01-01T00:00:00+00:00",
            "verification_time": "2026-01-02T00:00:00+00:00",
            "details": [{"detail_time": "2026-01-03T00:00:00+00:00"}],
        },
        {
            "submission_time": "2025-01-01T00:00:00+00:00",
        },
    ]
    since_date = datetime(2026, 1, 1, tzinfo=UTC)
    filtered = list(phishtank.filter_entries_by_date(entries, since_date))
    assert len(filtered) == 1
    assert "modified_time" in filtered[0]


def test_create_stix_objects_for_phish_verified():
    entry = {
        "phish_id": 12345,
        "url": "http://malicious.com",
        "submission_time": "2026-01-01T00:00:00+00:00",
        "verification_time": "2026-01-02T00:00:00+00:00",
        "verified": "yes",
        "online": "no",
        "details": [
            {
                "ip_address": "192.168.1.1",
                "announcing_network": "12345",
                "rir": "arin",
            }
        ],
    }
    identity_id = "identity--8018d80e-ad1d-505e-a89b-de7f36a38317"
    marking_id = "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd"
    objects = phishtank.create_stix_objects_for_phish(entry, identity_id, marking_id)
    assert stix_as_dict(objects) == [
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--18e602e5-5c42-5a46-885b-6a51d832e45e",
            "value": "http://malicious.com",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--d1f3db35-e389-568c-af2c-9dbd8cf82983",
            "created_by_ref": "identity--8018d80e-ad1d-505e-a89b-de7f36a38317",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-02T00:00:00.000Z",
            "name": "URL: http://malicious.com",
            "indicator_types": ["malicious-activity"],
            "pattern": "[url:value='http://malicious.com']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "revoked": True,
            "confidence": 100,
            "external_references": [
                {
                    "source_name": "phishtank",
                    "url": "https://www.phishtank.com/phish_detail.php?phish_id=12345&frame=details",
                    "external_id": "12345",
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--11a4f533-7a4d-5fc8-bf93-b3c63fae012d",
            "created_by_ref": "identity--8018d80e-ad1d-505e-a89b-de7f36a38317",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-02T00:00:00.000Z",
            "relationship_type": "indicates",
            "description": "",
            "source_ref": "indicator--d1f3db35-e389-568c-af2c-9dbd8cf82983",
            "target_ref": "url--18e602e5-5c42-5a46-885b-6a51d832e45e",
            "external_references": [
                {
                    "source_name": "phishtank",
                    "url": "https://www.phishtank.com/phish_detail.php?phish_id=12345&frame=details",
                    "external_id": "12345",
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--8487463f-f75e-5a66-b299-63aef611346f",
            "created_by_ref": "identity--8018d80e-ad1d-505e-a89b-de7f36a38317",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-02T00:00:00.000Z",
            "relationship_type": "indicates",
            "description": "http://malicious.com is known to be used for Phishing (T1566)",
            "source_ref": "indicator--d1f3db35-e389-568c-af2c-9dbd8cf82983",
            "target_ref": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "external_references": [
                {
                    "source_name": "phishtank",
                    "url": "https://www.phishtank.com/phish_detail.php?phish_id=12345&frame=details",
                    "external_id": "12345",
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd",
            ],
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--cd2ddd9b-6ae2-5d22-aec9-a9940505e5d5",
            "value": "192.168.1.1",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--72dbe03f-e16f-5664-bf1f-095f28f3b8ff",
            "created_by_ref": "identity--8018d80e-ad1d-505e-a89b-de7f36a38317",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-02T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "url--18e602e5-5c42-5a46-885b-6a51d832e45e",
            "target_ref": "ipv4-addr--cd2ddd9b-6ae2-5d22-aec9-a9940505e5d5",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd",
            ],
        },
        {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--16567ba9-8e30-551f-91db-2861062225b9",
            "number": 12345,
            "rir": "arin",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--736bcfb7-5db0-5d8d-8f05-c9c76efb1a7f",
            "created_by_ref": "identity--8018d80e-ad1d-505e-a89b-de7f36a38317",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-02T00:00:00.000Z",
            "relationship_type": "related-to",
            "source_ref": "ipv4-addr--cd2ddd9b-6ae2-5d22-aec9-a9940505e5d5",
            "target_ref": "autonomous-system--16567ba9-8e30-551f-91db-2861062225b9",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd",
            ],
        },
    ]


def test_create_stix_objects_for_phish_not_verified():
    entry = {
        "phish_id": 12345,
        "url": "http://malicious.com",
        "submission_time": "2026-01-01T00:00:00+00:00",
        "verified": "no",
        "online": "no",
        "details": [],
    }
    identity_id = "identity--8018d80e-ad1d-505e-a89b-de7f36a38317"
    marking_id = "marking-definition--5b870f25-ca53-54be-aa51-407bedb499cd"
    objects = phishtank.create_stix_objects_for_phish(entry, identity_id, marking_id)

    # Check indicator does not have confidence
    indicator = next(obj for obj in objects if obj.type == "indicator")
    assert not hasattr(indicator, "confidence") or indicator.confidence is None
