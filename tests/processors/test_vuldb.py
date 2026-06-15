import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from processors.vuldb import vuldb
from tests.utilities import FakeResponse, stix_as_dict


SOURCE_IDENTITY_ID = "identity--24c95c49-df92-561c-8955-7411e5fd3fd2"
SOURCE_MARKING_ID = "marking-definition--fd617b14-244a-5edc-99f0-46ce6f53e219"
FEEDS2STIX_MARKING = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--11111111-1111-4111-8111-111111111111",
    "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "2020-01-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {"statement": "Origin: test"},
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    ],
}
VULNERABILITY = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--11111111-1111-4111-8111-111111111111",
    "created": "2026-06-06T00:00:00.000Z",
    "modified": "2026-06-06T00:00:00.000Z",
    "name": "CVE-2026-11438",
    "external_references": [
        {
            "source_name": "vulmatch",
            "url": "https://vulmatch.test/cve/CVE-2026-11438",
        }
    ],
}


def test_create_identity():
    identity = vuldb.create_vuldb_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": SOURCE_IDENTITY_ID,
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "VulDB",
        "description": "VulDB stands for Vulnerability Database. We are curating and documenting all security vulnerabilities that got published in electronic products. We are one of the most important sources for people responsible for handling vulnerabilities, vulnerability management, exploit analysis, cyber threat intelligence, and incident response handling.",
        "identity_class": "system",
        "contact_information": "https://vuldb.com/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_marking_definition():
    marking = vuldb.create_vuldb_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": SOURCE_MARKING_ID,
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "Origin: https://vuldb.com/rss/recent"},
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_load_and_save_pending_cves_handles_json(tmp_path):
    cve_file = tmp_path / "vuldb-cve-list.json"
    cve_file.write_text(
        json.dumps(
            {
                "cve-2026-11438": {
                    "cve_ids": ["CVE-2026-11438"],
                    "title": "CVE-2026-11438",
                    "link": "https://vuldb.com/vuln/369018",
                    "description": "A vulnerability was found.",
                    "description_references": [],
                    "pub_date": "2026-06-05T22:26:13Z",
                    "categories": {"Vendor": "theonedev"},
                }
            }
        )
    )

    pending = vuldb.load_pending_cves(cve_file)
    assert pending == {
        "CVE-2026-11438": {
            "cve_ids": ["CVE-2026-11438"],
            "title": "CVE-2026-11438",
            "link": "https://vuldb.com/vuln/369018",
            "description": "A vulnerability was found.",
            "description_references": [],
            "pub_date": "2026-06-05T22:26:13Z",
            "categories": {"Vendor": "theonedev"},
            "cve_id": "CVE-2026-11438",
        }
    }

    vuldb.save_pending_cves(cve_file, pending)
    assert json.loads(cve_file.read_text()) == pending


def test_parse_rss_feed_uses_etree_and_regex_for_cve_ids():
    xml = b"""<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item>
          <title>CVE-2026-11438 | theonedev issue</title>
          <link>https://vuldb.com/vuln/369018</link>
          <guid isPermaLink="true">https://vuldb.com/vuln/369018</guid>
          <pubDate>Sat, 06 Jun 2026 00:26:13 +0200</pubDate>
          <description><![CDATA[A <a href="https://vuldb.com/cve/CVE-2026-11438">vulnerability</a> was found.]]></description>
          <category><![CDATA[Vendor: theonedev]]></category>
          <category><![CDATA[Risk: critical]]></category>
        </item>
      </channel>
    </rss>"""

    assert vuldb.parse_rss_feed(xml) == {
        "CVE-2026-11438": {
            "cve_ids": ["CVE-2026-11438"],
            "cve_id": "CVE-2026-11438",
            "title": "CVE-2026-11438 | theonedev issue",
            "link": "https://vuldb.com/vuln/369018",
            "description": "A vulnerability was found.",
            "description_references": [
                {
                    "source_name": "vuldb",
                    "url": "https://vuldb.com/cve/CVE-2026-11438",
                    "description": "vulnerability",
                }
            ],
            "pub_date": "2026-06-05T22:26:13Z",
            "categories": {"Vendor": "theonedev", "Risk": "critical"},
        }
    }


def test_fetch_vuldb_rss_saves_raw_feed(monkeypatch, tmp_path):
    xml = (
        b"<rss><channel><item><title>CVE-2026-11438</title>"
        b"<pubDate>Sat, 06 Jun 2026 00:26:13 +0200</pubDate>"
        b"</item></channel></rss>"
    )
    monkeypatch.setattr(
        vuldb.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(content=xml),
    )

    assert vuldb.fetch_vuldb_rss(tmp_path) == {
        "CVE-2026-11438": {
            "cve_ids": ["CVE-2026-11438"],
            "cve_id": "CVE-2026-11438",
            "title": "CVE-2026-11438",
            "link": "",
            "description": "",
            "description_references": [],
            "pub_date": "2026-06-05T22:26:13Z",
            "categories": {},
        }
    }
    assert (tmp_path / "vuldb_recent.xml").read_bytes() == xml


def test_fetch_vulnerabilities_for_cves_fetches_in_chunks_of_50(monkeypatch):
    cve_ids = [f"CVE-2026-{10000 + idx}" for idx in range(51)]
    calls = []

    def fake_fetch(chunk):
        calls.append(chunk)
        return {chunk[0]: {"id": f"vulnerability--{len(calls)}", "name": chunk[0]}}

    monkeypatch.setattr(vuldb, "fetch_vulnerabilities", fake_fetch)

    assert vuldb.fetch_vulnerabilities_for_cves(cve_ids) == {
        "CVE-2026-10000": {"id": "vulnerability--1", "name": "CVE-2026-10000"},
        "CVE-2026-10050": {"id": "vulnerability--2", "name": "CVE-2026-10050"},
    }
    assert [len(call) for call in calls] == [50, 1]


def test_build_vuldb_note():
    note = vuldb.build_vuldb_note(
        "CVE-2026-11438",
        {
            "cve_id": "CVE-2026-11438",
            "title": "CVE-2026-11438 | theonedev issue",
            "link": "https://vuldb.com/vuln/369018",
            "description": "A vulnerability was found. theonedev onedev up to 15.0.5",
            "description_references": [
                {
                    "source_name": "vuldb",
                    "url": "https://vuldb.com/cve/CVE-2026-11438",
                    "description": "vulnerability",
                },
                {
                    "source_name": "vuldb",
                    "url": "https://vuldb.com/product/theonedev:onedev",
                    "description": "theonedev onedev up to 15.0.5",
                },
            ],
            "pub_date": "2026-06-05T22:26:13Z",
            "categories": {"Vendor": "theonedev", "Risk": "critical"},
        },
        VULNERABILITY,
        SOURCE_IDENTITY_ID,
        SOURCE_MARKING_ID,
    )

    assert stix_as_dict(note) == {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--f8c1593b-5f35-50ab-9833-1d2e2da98f3f",
        "created_by_ref": SOURCE_IDENTITY_ID,
        "created": "2026-06-05T22:26:13.000Z",
        "modified": "2026-06-05T22:26:13.000Z",
        "abstract": "CVE-2026-11438 | theonedev issue",
        "content": "A vulnerability was found. theonedev onedev up to 15.0.5",
        "object_refs": ["vulnerability--11111111-1111-4111-8111-111111111111"],
        "labels": ["Vendor: theonedev", "Risk: critical"],
        "external_references": [
            {"source_name": "vuldb", "url": "https://vuldb.com/vuln/369018"},
            {
                "source_name": "vuldb",
                "url": "https://vuldb.com/cve/CVE-2026-11438",
                "description": "vulnerability",
            },
            {
                "source_name": "vuldb",
                "url": "https://vuldb.com/product/theonedev:onedev",
                "description": "theonedev onedev up to 15.0.5",
            },
            {
                "source_name": "vulmatch",
                "url": "https://vulmatch.test/cve/CVE-2026-11438",
            },
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_ID,
        ],
    }


def test_create_stix_objects_adds_note_for_feed_context():
    objects = vuldb.build_bundle_objects(
        [VULNERABILITY],
        {
            "CVE-2026-11438": {
                "cve_id": "CVE-2026-11438",
                "title": "CVE-2026-11438 | theonedev issue",
                "link": "https://vuldb.com/vuln/369018",
                "description": "A vulnerability was found. theonedev onedev up to 15.0.5",
                "description_references": [
                    {
                        "source_name": "vuldb",
                        "url": "https://vuldb.com/cve/CVE-2026-11438",
                        "description": "vulnerability",
                    },
                    {
                        "source_name": "vuldb",
                        "url": "https://vuldb.com/product/theonedev:onedev",
                        "description": "theonedev onedev up to 15.0.5",
                    },
                ],
                "pub_date": "2026-06-05T22:26:13Z",
                "categories": {"Vendor": "theonedev", "Risk": "critical"},
            }
        },
        SOURCE_IDENTITY_ID,
        SOURCE_MARKING_ID,
    )

    assert stix_as_dict(objects) == [
        VULNERABILITY,
        {
            "type": "note",
            "spec_version": "2.1",
            "id": "note--f8c1593b-5f35-50ab-9833-1d2e2da98f3f",
            "created_by_ref": SOURCE_IDENTITY_ID,
            "created": "2026-06-05T22:26:13.000Z",
            "modified": "2026-06-05T22:26:13.000Z",
            "abstract": "CVE-2026-11438 | theonedev issue",
            "content": "A vulnerability was found. theonedev onedev up to 15.0.5",
            "object_refs": ["vulnerability--11111111-1111-4111-8111-111111111111"],
            "labels": ["Vendor: theonedev", "Risk: critical"],
            "external_references": [
                {"source_name": "vuldb", "url": "https://vuldb.com/vuln/369018"},
                {
                    "source_name": "vuldb",
                    "url": "https://vuldb.com/cve/CVE-2026-11438",
                    "description": "vulnerability",
                },
                {
                    "source_name": "vuldb",
                    "url": "https://vuldb.com/product/theonedev:onedev",
                    "description": "theonedev onedev up to 15.0.5",
                },
                {
                    "source_name": "vulmatch",
                    "url": "https://vulmatch.test/cve/CVE-2026-11438",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_ID,
            ],
        },
    ]


def test_process_vuldb_merges_pending_and_rss_then_removes_found(monkeypatch, tmp_path):
    cve_file = tmp_path / "vuldb-cve-list.json"
    cve_file.write_text(
        json.dumps(
            {
                "CVE-2026-00001": {
                    "cve_id": "CVE-2026-00001",
                    "cve_ids": ["CVE-2026-00001"],
                    "title": "",
                    "link": "",
                    "description": "",
                    "description_references": [],
                    "pub_date": "2026-06-01T00:00:00Z",
                    "categories": {},
                }
            }
        )
    )
    monkeypatch.setattr(
        vuldb,
        "fetch_vuldb_rss",
        lambda data_dir: {
            "CVE-2026-11438": {
                "cve_id": "CVE-2026-11438",
                "cve_ids": ["CVE-2026-11438"],
                "title": "CVE-2026-11438",
                "link": "https://vuldb.com/vuln/369018",
                "description": "description",
                "description_references": [],
                "pub_date": "2026-06-05T22:26:13Z",
                "categories": {},
            }
        },
    )
    monkeypatch.setattr(
        vuldb,
        "fetch_vulnerabilities_for_cves",
        lambda cve_ids: {
            "CVE-2026-00001": {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--22222222-2222-4222-8222-222222222222",
                "name": "CVE-2026-00001",
            }
        },
    )

    vulnerabilities, parsed_cves, pending_cves, new_cve_list_path = vuldb.process_vuldb(
        cve_file,
        tmp_path,
    )

    assert vulnerabilities == [
        {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": "vulnerability--22222222-2222-4222-8222-222222222222",
            "name": "CVE-2026-00001",
        }
    ]
    assert parsed_cves == {
        "CVE-2026-00001": {
            "cve_id": "CVE-2026-00001",
            "cve_ids": ["CVE-2026-00001"],
            "title": "",
            "link": "",
            "description": "",
            "description_references": [],
            "pub_date": "2026-06-01T00:00:00Z",
            "categories": {},
        },
        "CVE-2026-11438": {
            "cve_id": "CVE-2026-11438",
            "cve_ids": ["CVE-2026-11438"],
            "title": "CVE-2026-11438",
            "link": "https://vuldb.com/vuln/369018",
            "description": "description",
            "description_references": [],
            "pub_date": "2026-06-05T22:26:13Z",
            "categories": {},
        }
    }
    assert pending_cves == {
        "CVE-2026-11438": {
            "cve_id": "CVE-2026-11438",
            "cve_ids": ["CVE-2026-11438"],
            "title": "CVE-2026-11438",
            "link": "https://vuldb.com/vuln/369018",
            "description": "description",
            "description_references": [],
            "pub_date": "2026-06-05T22:26:13Z",
            "categories": {},
        }
    }
    assert json.loads(cve_file.read_text()) == pending_cves
    assert new_cve_list_path == tmp_path / "vuldb-cve-list.json"


def test_main_writes_bundle_and_cve_list_outputs(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    cve_file = tmp_path / "state" / "vuldb-cve-list.json"
    cve_file.parent.mkdir()
    cve_file.write_text("{}")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(vuldb, "BASE_OUTPUT_DIR", str(tmp_path / "outputs"))
    monkeypatch.setattr(sys, "argv", ["vuldb.py", str(cve_file)])
    monkeypatch.setattr(vuldb, "fetch_external_objects", lambda: FEEDS2STIX_MARKING)
    monkeypatch.setattr(
        vuldb,
        "fetch_vuldb_rss",
        lambda data_dir: {
            "CVE-2026-11438": {
                "cve_id": "CVE-2026-11438",
                "cve_ids": ["CVE-2026-11438"],
                "title": "CVE-2026-11438 | theonedev issue",
                "link": "https://vuldb.com/vuln/369018",
                "description": "A vulnerability was found. theonedev onedev up to 15.0.5",
                "description_references": [
                    {
                        "source_name": "vuldb",
                        "url": "https://vuldb.com/cve/CVE-2026-11438",
                        "description": "vulnerability",
                    },
                    {
                        "source_name": "vuldb",
                        "url": "https://vuldb.com/product/theonedev:onedev",
                        "description": "theonedev onedev up to 15.0.5",
                    },
                ],
                "pub_date": "2026-06-05T22:26:13Z",
                "categories": {"Vendor": "theonedev", "Risk": "critical"},
            }
        },
    )
    monkeypatch.setattr(
        vuldb,
        "fetch_vulnerabilities_for_cves",
        lambda cve_ids: {"CVE-2026-11438": VULNERABILITY},
    )

    vuldb.main()

    output_text = out_file.read_text()
    assert "bundle_count=1" in output_text
    assert "bundle_path=" in output_text
    assert "cve_list_path=" in output_text
    assert json.loads(cve_file.read_text()) == {}

    bundle_dir = Path(output_text.split("bundle_path=")[1].splitlines()[0])
    bundle_files = sorted(bundle_dir.glob("*.json"))
    assert [path.name for path in bundle_files] == ["vuldb_part_001.json"]
