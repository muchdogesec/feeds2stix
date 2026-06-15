import logging
import json
import sys
from pathlib import Path

from processors.microsoft_update_guide import microsoft_update_guide as msrc
from tests.utilities import FakeResponse, stix_as_dict

SOURCE_IDENTITY_ID = "identity--18be240f-45ae-5de1-a535-561def6faac9"
SOURCE_MARKING_ID = "marking-definition--92fd3abd-22a1-53cd-b037-26a4e8cdd883"
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
    "created": "2026-06-10T00:00:00.000Z",
    "modified": "2026-06-10T00:00:00.000Z",
    "name": "CVE-2026-26030",
    "external_references": [
        {
            "source_name": "cve",
            "url": "https://vulmatch.test/cve/CVE-2026-26030",
            "external_id": "CVE-2026-26030",
        }
    ],
}


def test_create_identity():
    identity = msrc.create_msrc_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": SOURCE_IDENTITY_ID,
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "MSRC Security Update Guide",
        "description": "The Microsoft Security Response Center (MSRC) investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides the information here as part of the ongoing effort to help you manage security risks and help keep your systems protected.",
        "identity_class": "system",
        "contact_information": "https://msrc.microsoft.com/update-guide/",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_marking_definition():
    marking = msrc.create_msrc_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": SOURCE_MARKING_ID,
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://api.msrc.microsoft.com/update-guide/rss"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_parse_rss_feed_extracts_guid_and_markdown_links():
    xml = b"""<?xml version="1.0"?>
    <rss version="2.0">
      <channel>
        <item Revision="1.0000000000">
          <guid isPermaLink="false">CVE-2026-26030</guid>
          <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030</link>
          <title>CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable</title>
          <description>[CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) is a Remote Code Execution vulnerability. Please see [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) for more information.</description>
          <pubDate>Tue, 10 Mar 2026 07:00:00 -0700</pubDate>
        </item>
        <item Revision="1.1000000000">
          <guid isPermaLink="false">CVE-2026-99999</guid>
          <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99999</link>
          <title>Ignored revision</title>
          <description>Ignored</description>
          <pubDate>Wed, 11 Mar 2026 07:00:00 -0700</pubDate>
        </item>
      </channel>
    </rss>"""

    assert msrc.parse_rss_feed(xml) == {
        "CVE-2026-26030": {
            "cve_ids": ["CVE-2026-26030"],
            "cve_id": "CVE-2026-26030",
            "title": "CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable",
            "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
            "description": "CVE-2026-26030 is a Remote Code Execution vulnerability. Please see CVE-2026-26030 for more information.",
            "description_references": [
                {
                    "source_name": "msrc",
                    "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                    "description": "CVE-2026-26030",
                },
                {
                    "source_name": "msrc",
                    "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                    "description": "CVE-2026-26030",
                },
            ],
            "pub_date": "2026-03-10T14:00:00Z",
        }
    }


def test_load_and_save_missing_cve_list_handles_json(tmp_path):
    cve_file = tmp_path / "missing_cve_list.json"
    cve_file.write_text(
        json.dumps(
            {
                "cve-2026-26030": {
                    "cve_ids": ["CVE-2026-26030"],
                    "title": "CVE-2026-26030",
                    "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
                    "description": "CVE-2026-26030 is a Remote Code Execution vulnerability.",
                    "description_references": [],
                    "pub_date": "2026-03-10T14:00:00Z",
                }
            }
        )
    )

    missing = msrc.load_missing_cve_list(cve_file)
    assert missing == {
        "CVE-2026-26030": {
            "cve_ids": ["CVE-2026-26030"],
            "title": "CVE-2026-26030",
            "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
            "description": "CVE-2026-26030 is a Remote Code Execution vulnerability.",
            "description_references": [],
            "pub_date": "2026-03-10T14:00:00Z",
            "cve_id": "CVE-2026-26030",
        }
    }

    msrc.save_missing_cve_list(cve_file, missing)
    assert json.loads(cve_file.read_text()) == missing


def test_fetch_vulnerabilities_for_cves_fetches_in_chunks_of_50(monkeypatch):
    cve_ids = [f"CVE-2026-{26030 + idx}" for idx in range(51)]
    calls = []

    def fake_fetch(chunk):
        calls.append(chunk)
        return {chunk[0]: {"id": f"vulnerability--{len(calls)}", "name": chunk[0]}}

    monkeypatch.setattr(msrc, "fetch_vulnerabilities", fake_fetch)

    assert msrc.fetch_vulnerabilities_for_cves(cve_ids) == {
        "CVE-2026-26030": {"id": "vulnerability--1", "name": "CVE-2026-26030"},
        "CVE-2026-26080": {"id": "vulnerability--2", "name": "CVE-2026-26080"},
    }
    assert [len(call) for call in calls] == [50, 1]


def test_build_msrc_note():
    note = msrc.build_msrc_note(
        "CVE-2026-26030",
        {
            "cve_id": "CVE-2026-26030",
            "title": "CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable",
            "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
            "description": "CVE-2026-26030 is a Remote Code Execution vulnerability. Please see CVE-2026-26030 for more information.",
            "description_references": [
                {
                    "source_name": "msrc",
                    "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                    "description": "CVE-2026-26030",
                },
                {
                    "source_name": "msrc",
                    "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                    "description": "CVE-2026-26030",
                },
            ],
            "pub_date": "2026-03-10T14:00:00Z",
        },
        VULNERABILITY,
        SOURCE_IDENTITY_ID,
        SOURCE_MARKING_ID,
    )

    assert stix_as_dict(note) == {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--3571df6c-eb9b-52fa-be1e-661f29c6bd25",
        "created_by_ref": SOURCE_IDENTITY_ID,
        "created": "2026-03-10T14:00:00.000Z",
        "modified": "2026-03-10T14:00:00.000Z",
        "abstract": "CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable",
        "content": "CVE-2026-26030 is a Remote Code Execution vulnerability. Please see CVE-2026-26030 for more information.",
        "object_refs": ["vulnerability--11111111-1111-4111-8111-111111111111"],
        "external_references": [
            {
                "source_name": "cve",
                "url": "https://vulmatch.test/cve/CVE-2026-26030",
                "external_id": "CVE-2026-26030",
            },
            {
                "source_name": "msrc",
                "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
            },
            {
                "source_name": "msrc",
                "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                "description": "CVE-2026-26030",
            },
            {
                "source_name": "msrc",
                "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                "description": "CVE-2026-26030",
            },
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_ID,
        ],
    }


def test_create_stix_objects_adds_note_for_feed_context():
    objects = msrc.build_bundle_objects(
        [VULNERABILITY],
        {
            "CVE-2026-26030": {
                "cve_id": "CVE-2026-26030",
                "title": "CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable",
                "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
                "description": "CVE-2026-26030 is a Remote Code Execution vulnerability. Please see CVE-2026-26030 for more information.",
                "description_references": [
                    {
                        "source_name": "msrc",
                        "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                        "description": "CVE-2026-26030",
                    },
                    {
                        "source_name": "msrc",
                        "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                        "description": "CVE-2026-26030",
                    },
                ],
                "pub_date": "2026-03-10T14:00:00Z",
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
            "id": "note--3571df6c-eb9b-52fa-be1e-661f29c6bd25",
            "created_by_ref": SOURCE_IDENTITY_ID,
            "created": "2026-03-10T14:00:00.000Z",
            "modified": "2026-03-10T14:00:00.000Z",
            "abstract": "CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable",
            "content": "CVE-2026-26030 is a Remote Code Execution vulnerability. Please see CVE-2026-26030 for more information.",
            "object_refs": ["vulnerability--11111111-1111-4111-8111-111111111111"],
            "external_references": [
                {
                    "source_name": "cve",
                    "url": "https://vulmatch.test/cve/CVE-2026-26030",
                    "external_id": "CVE-2026-26030",
                },
                {
                    "source_name": "msrc",
                    "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
                },
                {
                    "source_name": "msrc",
                    "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                    "description": "CVE-2026-26030",
                },
                {
                    "source_name": "msrc",
                    "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                    "description": "CVE-2026-26030",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_ID,
            ],
        },
    ]


def test_process_msrc_merges_pending_and_rss_then_removes_found(
    monkeypatch, tmp_path, caplog
):
    missing_file = tmp_path / "missing_cve_list.json"
    missing_file.write_text(
        json.dumps(
            {
                "cve-2026-00001": {
                    "cve_id": "CVE-2026-00001",
                    "cve_ids": ["CVE-2026-00001"],
                    "title": "",
                    "link": "",
                    "description": "",
                    "description_references": [],
                    "pub_date": "2026-03-01T00:00:00Z",
                }
            }
        )
    )
    monkeypatch.setattr(
        msrc,
        "fetch_msrc_rss",
        lambda data_dir: {
            "CVE-2026-26030": {
                "cve_id": "CVE-2026-26030",
                "cve_ids": ["CVE-2026-26030"],
                "title": "CVE-2026-26030",
                "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
                "description": "description",
                "description_references": [],
                "pub_date": "2026-03-10T14:00:00Z",
            }
        },
    )
    monkeypatch.setattr(
        msrc,
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

    with caplog.at_level(logging.INFO):
        vulnerabilities, parsed_cves, missing_cves, new_missing_cve_list_path = (
            msrc.process_msrc(
                missing_file,
                tmp_path,
            )
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
            "pub_date": "2026-03-01T00:00:00Z",
        },
        "CVE-2026-26030": {
            "cve_id": "CVE-2026-26030",
            "cve_ids": ["CVE-2026-26030"],
            "title": "CVE-2026-26030",
            "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
            "description": "description",
            "description_references": [],
            "pub_date": "2026-03-10T14:00:00Z",
        },
    }
    assert missing_cves == {
        "CVE-2026-26030": {
            "cve_id": "CVE-2026-26030",
            "cve_ids": ["CVE-2026-26030"],
            "title": "CVE-2026-26030",
            "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
            "description": "description",
            "description_references": [],
            "pub_date": "2026-03-10T14:00:00Z",
        }
    }
    assert json.loads(missing_file.read_text()) == missing_cves
    assert new_missing_cve_list_path == tmp_path / "missing_cve_list.json"
    assert "loaded 1 missing CVEs from last run" in caplog.text
    assert "loaded 1 CVEs from MSRC RSS" in caplog.text
    assert "found 1 CVEs and left 1 missing" in caplog.text
    assert "saved missing_cve_list to" in caplog.text


def test_main_writes_bundle_and_missing_cve_list_outputs(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    missing_file = tmp_path / "state" / "missing_cve_list.json"
    missing_file.parent.mkdir()
    missing_file.write_text("{}")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(msrc, "BASE_OUTPUT_DIR", str(tmp_path / "outputs"))
    monkeypatch.setattr(sys, "argv", ["microsoft_update_guide.py", str(missing_file)])
    monkeypatch.setattr(msrc, "fetch_external_objects", lambda: FEEDS2STIX_MARKING)
    monkeypatch.setattr(
        msrc,
        "fetch_msrc_rss",
        lambda data_dir: {
            "CVE-2026-26030": {
                "cve_id": "CVE-2026-26030",
                "cve_ids": ["CVE-2026-26030"],
                "title": "CVE-2026-26030",
                "link": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030",
                "description": "CVE-2026-26030 is a Remote Code Execution vulnerability.",
                "description_references": [
                    {
                        "source_name": "msrc",
                        "url": "https://www.cve.org/CVERecord?id=CVE-2026-26030",
                        "description": "CVE-2026-26030",
                    }
                ],
                "pub_date": "2026-03-10T14:00:00Z",
            }
        },
    )
    monkeypatch.setattr(
        msrc,
        "fetch_vulnerabilities_for_cves",
        lambda cve_ids: {"CVE-2026-26030": VULNERABILITY},
    )

    msrc.main()

    output_text = out_file.read_text()
    assert "bundle_count=1" in output_text
    assert "bundle_path=" in output_text
    assert "missing_cve_list_path=" in output_text

    bundle_dir = Path(output_text.split("bundle_path=")[1].splitlines()[0])
    bundle_files = sorted(bundle_dir.glob("*.json"))
    assert [path.name for path in bundle_files] == ["msrc_part_001.json"]

    missing_cve_list_path = Path(
        output_text.split("missing_cve_list_path=")[1].splitlines()[0]
    )
    assert json.loads(missing_cve_list_path.read_text()) == {}
