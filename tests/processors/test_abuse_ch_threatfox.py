import sys
import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from processors.abuse_ch_threatfox import threatfox
from tests import utils as test_utils
from tests.utils import stix_as_dict


def test_create_identity():
    identity = threatfox.create_threatfox_identity()
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


def test_create_marking_definition():
    marking = threatfox.create_threatfox_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--da914f6d-2b1b-5713-bac0-b7e55284e9ed",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin data source: https://threatfox.abuse.ch/export/csv/recent/"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_parse_csv_data(tmp_path):
    csv_file = tmp_path / "t.csv"
    csv_file.write_text(
        "# header\n"
        '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"\n'
        '"2024-07-16 06:45:19", "1", "http://bad.test/a", "url", "botnet_cc", "win.lokipws", "Loki", "Loki Password Stealer (PWS)", "2024-07-16 08:11:39", "75", "https://ref.test/1", "lokibot", "0", "abuse_ch"\n'
        '"2024-07-16 05:25:36", "2", "8.134.12.90:7777", "ip:port", "botnet_cc", "win.cobalt_strike", "BEACON,CobaltStrike", "Cobalt Strike", "", "100", "None", "CobaltStrike,cs-watermark-987654321", "0", "abuse_ch"\n'
        "# Number of entries: 2\n"
    )

    latest, by_malware = threatfox.parse_csv_data(csv_file)

    assert latest == datetime(2024, 7, 16, 6, 45, 19, tzinfo=UTC)
    assert set(by_malware) == {"Loki Password Stealer (PWS)", "Cobalt Strike"}

    cobalt_record = by_malware["Cobalt Strike"][0]
    assert cobalt_record["last_seen_utc"] == cobalt_record["first_seen_utc"]
    assert cobalt_record["confidence_level"] == 100


def test_create_observables_for_record_ip_port():
    record = {
        "ioc_type": "ip:port",
        "ioc_value": "8.8.8.8:443",
    }

    objs = threatfox.create_observables_for_record(record)
    as_dict = stix_as_dict(objs)

    assert [obj["type"] for obj in as_dict] == ["ipv4-addr", "network-traffic"]
    assert as_dict[0]["value"] == "8.8.8.8"
    assert as_dict[1]["dst_port"] == 443
    assert as_dict[1]["protocols"] == ["ssl", "tcp"]
    assert as_dict[1]["dst_ref"] == as_dict[0]["id"]


def test_create_observables_for_record_sha1_hash():
    record = {
        "ioc_type": "sha1_hash",
        "ioc_value": "0123456789abcdef0123456789abcdef01234567",
    }

    objs = threatfox.create_observables_for_record(record)
    as_dict = stix_as_dict(objs)

    assert len(as_dict) == 1
    assert as_dict[0]["type"] == "file"
    assert as_dict[0]["hashes"] == {"SHA-1": "0123456789abcdef0123456789abcdef01234567"}


def test_create_observables__creates_autonomous_system():
    record = {
        "ioc_type": "ip:port",
        "ioc_value": "1.2.3.4:8080",
        "tags": "AS12345,malware,ASN56789,AS12BS",
    }

    objs = threatfox.create_observables_for_record(record)
    as_dict = stix_as_dict(objs)
    print(as_dict)
    assert as_dict == [
        {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--16567ba9-8e30-551f-91db-2861062225b9",
            "number": 12345,
            "name": "AS12345",
        },
        {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--32f0457c-6360-5468-9dae-a5efa787bb5a",
            "number": 12,
            "name": "AS12",
        },
        {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--ced08671-9035-5efc-a114-3c5a1d2998ad",
            "number": 56789,
            "name": "AS56789",
        },
        {
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "value": "1.2.3.4",
        },
        {
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": "network-traffic--af89bc26-e19b-5109-a91d-663045a255c9",
            "dst_ref": "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4",
            "dst_port": 8080,
            "protocols": ["tcp"],
        },
    ]


def test_create_indicator_object_for_url():
    record = {
        "ioc_id": "1",
        "first_seen_utc": datetime(2024, 7, 16, 6, 45, 19, tzinfo=UTC),
        "last_seen_utc": datetime(2024, 7, 16, 8, 11, 39, tzinfo=UTC),
        "ioc_value": "http://bad.test/a",
        "ioc_type": "url",
        "malware_printable": "Loki Password Stealer (PWS)",
        "confidence_level": 75,
        "tags": "lokibot,cred-theft",
        "reference": "https://ref.test/1",
        "reporter": "abuse_ch",
    }
    source_identity_id = "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95"
    source_marking_id = "marking-definition--6f0da662-ad3d-5266-94f8-7d8fec00cf88"
    marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        source_marking_id,
    ]
    observables = threatfox.create_observables_for_record(record)

    indicator = threatfox.create_indicator_object(
        record,
        observables,
        source_identity_id,
        source_marking_id,
        marking_refs,
    )
    d = stix_as_dict(indicator)

    assert d["type"] == "indicator"
    assert d["name"] == "Loki Password Stealer (PWS)"
    assert d["pattern"] == "[ url:value = 'http://bad.test/a' ]"
    assert d["confidence"] == 75
    assert d["labels"] == ["cred-theft", "lokibot"]
    assert d["external_references"] == [
        {"source_name": "threatfox_ioc_id", "external_id": "1"},
        {"source_name": "threatfox_reporter", "external_id": "abuse_ch"},
        {"source_name": "threatfox_reference", "external_id": "https://ref.test/1"},
    ]


def test_create_indicator_object_for_sha1_hash():
    record = {
        "ioc_id": "2",
        "first_seen_utc": datetime(2024, 7, 16, 6, 45, 19, tzinfo=UTC),
        "last_seen_utc": datetime(2024, 7, 16, 8, 11, 39, tzinfo=UTC),
        "ioc_value": "0123456789abcdef0123456789abcdef01234567",
        "ioc_type": "sha1_hash",
        "malware_printable": "Example Malware",
        "confidence_level": 50,
        "tags": None,
        "reference": None,
        "reporter": "abuse_ch",
    }
    source_identity_id = "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95"
    source_marking_id = "marking-definition--da914f6d-2b1b-5713-bac0-b7e55284e9ed"
    marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        source_marking_id,
    ]
    observables = threatfox.create_observables_for_record(record)

    indicator = threatfox.create_indicator_object(
        record,
        observables,
        source_identity_id,
        source_marking_id,
        marking_refs,
    )
    d = stix_as_dict(indicator)

    assert (
        d["pattern"]
        == "[ file:hashes.'SHA-1' = '0123456789abcdef0123456789abcdef01234567' ]"
    )
    assert d["external_references"] == [
        {"source_name": "threatfox_ioc_id", "external_id": "2"},
        {"source_name": "threatfox_reporter", "external_id": "abuse_ch"},
    ]


def test_create_indicator_object_for_ip_port_uses_observables():
    record = {
        "ioc_id": "3",
        "first_seen_utc": datetime(2024, 7, 16, 6, 45, 19, tzinfo=UTC),
        "last_seen_utc": datetime(2024, 7, 16, 8, 11, 39, tzinfo=UTC),
        "ioc_value": "8.8.8.8:443",
        "ioc_type": "ip:port",
        "malware_printable": "Example Malware",
        "confidence_level": 50,
        "tags": None,
        "reference": None,
        "reporter": "abuse_ch",
    }
    observables = threatfox.create_observables_for_record(record)
    source_identity_id = "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95"
    source_marking_id = "marking-definition--da914f6d-2b1b-5713-bac0-b7e55284e9ed"
    marking_refs = [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        source_marking_id,
    ]

    indicator = threatfox.create_indicator_object(
        record,
        observables,
        source_identity_id,
        source_marking_id,
        marking_refs,
    )
    d = stix_as_dict(indicator)

    assert (
        d["pattern"]
        == "[ ( network-traffic:dst_port = 443 AND network-traffic:dst_ref.value = '8.8.8.8' ) ]"
    )
    assert d["external_references"] == [
        {"source_name": "threatfox_ioc_id", "external_id": "3"},
        {"source_name": "threatfox_reporter", "external_id": "abuse_ch"},
    ]


def test_process_records_creates_malware_indicator_and_relationships():
    records = [
        {
            "first_seen_utc": datetime(2024, 7, 16, 6, 45, 19, tzinfo=UTC),
            "ioc_id": "1",
            "ioc_value": "http://bad.test/a",
            "ioc_type": "url",
            "threat_type": "botnet_cc",
            "fk_malware": "win.lokipws",
            "malware_alias": "Burkina,Loki",
            "malware_printable": "Loki Password Stealer (PWS)",
            "last_seen_utc": datetime(2024, 7, 16, 8, 11, 39, tzinfo=UTC),
            "confidence_level": 75,
            "reference": "https://ref.test/1",
            "tags": "lokibot",
            "anonymous": "0",
            "reporter": "abuse_ch",
        },
        {
            "first_seen_utc": datetime(2024, 7, 16, 5, 25, 36, tzinfo=UTC),
            "ioc_id": "2",
            "ioc_value": "aaaabbbbccccddddeeeeffff00001111",
            "ioc_type": "md5_hash",
            "threat_type": "payload_delivery",
            "fk_malware": "win.lokipws",
            "malware_alias": "LokiBot",
            "malware_printable": "Loki Password Stealer (PWS)",
            "last_seen_utc": datetime(2024, 7, 16, 5, 25, 36, tzinfo=UTC),
            "confidence_level": 100,
            "reference": None,
            "tags": "lokibot,stealer",
            "anonymous": "0",
            "reporter": "abuse_ch",
        },
    ]

    source_identity = threatfox.create_threatfox_identity()
    source_marking = threatfox.create_threatfox_marking_definition()
    feeds2stix_marking = {
        "type": "marking-definition",
        "id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        "spec_version": "2.1",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "feeds2stix"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }

    with patch(
        "processors.abuse_ch_threatfox.threatfox.OUTPUT_DIR", "outputs/test_threatfox"
    ):
        bundle_paths = threatfox.process_records(
            "Loki Password Stealer (PWS)",
            records,
            source_identity,
            source_marking,
            feeds2stix_marking,
        )

    assert len(bundle_paths) == 1
    objects = json.loads(Path(bundle_paths[0]).read_text())["objects"]
    rels = {
        o["id"]: (o["source_ref"], o["relationship_type"], o["target_ref"])
        for o in objects
        if o["type"] == "relationship"
    }
    malware = [obj for obj in objects if obj["type"] == "malware"][0]
    assert malware == {
        "type": "malware",
        "spec_version": "2.1",
        "id": "malware--a05524fe-e18a-5e3f-accd-e472771a32be",
        "created_by_ref": "identity--0619d6fb-5e76-5b35-87b9-a637bc2a0d95",
        "created": "2024-07-16T05:25:36.000Z",
        "modified": "2024-07-16T08:11:39.000Z",
        "name": "Loki Password Stealer (PWS)",
        "malware_types": ["unknown"],
        "is_family": True,
        "aliases": ["Burkina", "Loki", "LokiBot"],
        "external_references": [
            {
                "source_name": "malpedia",
                "external_id": "https://malpedia.caad.fkie.fraunhofer.de/details/win.lokipws",
            }
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "marking-definition--da914f6d-2b1b-5713-bac0-b7e55284e9ed",
        ],
    }
    assert rels == {
        "relationship--cac27e27-f9f5-5afe-8667-a1bdac64445d": (
            "indicator--92a9b7fd-e65b-50f4-9097-852ef5082727",
            "indicates",
            "url--6ae2aaeb-173b-5e57-a1bc-9565db2fbe85",
        ),
        "relationship--9844365a-b2f7-5ea0-870b-61c300e08f14": (
            "indicator--1a5c3be5-eb7c-57df-b097-972fda0eb633",
            "indicates",
            "file--8cb221c3-9095-5450-8606-1c3a2c7f5d49",
        ),
        "relationship--c0b500d0-f1e7-502e-928a-6e4050b01cee": (
            "indicator--92a9b7fd-e65b-50f4-9097-852ef5082727",
            "indicates",
            "malware--a05524fe-e18a-5e3f-accd-e472771a32be",
        ),
        "relationship--9a7a9d46-0ffc-54ec-aa10-725b1fd7b89e": (
            "url--6ae2aaeb-173b-5e57-a1bc-9565db2fbe85",
            "related-to",
            "malware--a05524fe-e18a-5e3f-accd-e472771a32be",
        ),
        "relationship--4e9ac06b-a35b-5e8e-bde5-17e76b1e1816": (
            "indicator--1a5c3be5-eb7c-57df-b097-972fda0eb633",
            "indicates",
            "malware--a05524fe-e18a-5e3f-accd-e472771a32be",
        ),
        "relationship--da03fa76-a6a0-50dc-98e1-05e5713a3e90": (
            "file--8cb221c3-9095-5450-8606-1c3a2c7f5d49",
            "related-to",
            "malware--a05524fe-e18a-5e3f-accd-e472771a32be",
        ),
    }


def test_main_writes_outputs(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["threatfox.py"])
    monkeypatch.setattr(threatfox, "OUTPUT_DIR", tmp_path / "threatfox")

    csv_path = tmp_path / "t.csv"
    csv_path.write_text(
        "# header\n"
        '# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"\n'
        '"2024-07-16 06:45:19", "1", "http://bad.test/a", "url", "botnet_cc", "win.lokipws", "Loki", "Loki Password Stealer (PWS)", "2024-07-16 08:11:39", "75", "https://ref.test/1", "lokibot", "0", "abuse_ch"\n'
        "# Number of entries: 1\n"
    )

    with patch(
        "processors.abuse_ch_threatfox.threatfox.download_threatfox_data"
    ) as mock_download:
        mock_download.return_value = csv_path
        threatfox.main()

    text = out_file.read_text()
    assert "bundle_path=" in text
    assert "latest_timestamp=" in text
