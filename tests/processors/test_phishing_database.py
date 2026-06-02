import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from git import Repo

from processors.phishing_database import phishing_database
from tests.utils import stix_as_dict


def _commit_all(repo, message, dt):
    repo.git.add(A=True)
    repo.index.commit(message, commit_date=dt, author_date=dt)


def _build_repo(tmp_path):
    repo_path = tmp_path / "phishing_db_repo"
    repo_path.mkdir()
    repo = Repo.init(repo_path)
    with repo.config_writer() as config:
        config.set_value("user", "name", "Test User")
        config.set_value("user", "email", "test@example.com")

    (repo_path / "phishing-domains-ACTIVE").mkdir()
    (repo_path / "phishing-domains-INACTIVE").mkdir()
    (repo_path / "phishing-links-ACTIVE").mkdir()
    (repo_path / "phishing-IPs-ACTIVE").mkdir()
    (repo_path / "phishing-links-INVALID").mkdir()

    (repo_path / "phishing-domains-ACTIVE" / "list.txt").write_text(
        "a.example.com\nb.example.com\n"
    )
    (repo_path / "phishing-domains-ACTIVE" / "ignore.csv").write_text("not,txt\n")
    _commit_all(repo, "add active domains", datetime(2026, 1, 1, 10, 0, tzinfo=UTC))

    (repo_path / "phishing-domains-INACTIVE" / "list.txt").write_text("b.example.com\n")
    _commit_all(repo, "add inactive domain", datetime(2026, 1, 2, 10, 0, tzinfo=UTC))

    (repo_path / "phishing-links-ACTIVE" / "links.txt").write_text(
        "http://phish.example.com/login\n"
    )
    _commit_all(repo, "add active link", datetime(2026, 1, 3, 10, 0, tzinfo=UTC))

    (repo_path / "phishing-IPs-ACTIVE" / "ips.txt").write_text("1.2.3.4\n")
    _commit_all(repo, "add active ip", datetime(2026, 1, 4, 10, 0, tzinfo=UTC))

    (repo_path / "phishing-domains-INACTIVE" / "old.txt").write_text(
        "oldinactive.example.com\n"
    )
    (repo_path / "phishing-links-INVALID" / "invalid.txt").write_text(
        "http://ignore.example.com\n"
    )
    _commit_all(repo, "add old inactive and invalid", datetime(2026, 1, 5, 10, 0, tzinfo=UTC))

    return repo, repo_path


def test_create_identity_and_marking():
    identity = phishing_database.create_phishing_database_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--24698e88-2b61-5b9e-a700-db5402c9e0c0",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "Phishing.Database",
        "description": "The Phishing.Database project is a comprehensive and regularly updated repository designed to help the community identify and mitigate phishing threats.",
        "identity_class": "organization",
        "contact_information": "https://github.com/Phishing-Database/Phishing.Database",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }

    marking = phishing_database.create_phishing_database_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--32e09812-922a-5351-b4a3-07adecf7a701",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://github.com/Phishing-Database/Phishing.Database"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_target_files_and_collect_observables_with_cutoff(tmp_path):
    repo, repo_path = _build_repo(tmp_path)

    target_files = phishing_database.get_target_feed_files(repo_path)
    assert target_files == [
        "phishing-IPs-ACTIVE/ips.txt",
        "phishing-domains-ACTIVE/list.txt",
        "phishing-domains-INACTIVE/list.txt",
        "phishing-domains-INACTIVE/old.txt",
        "phishing-links-ACTIVE/links.txt",
    ]

    records = phishing_database.collect_observables(
        repo, repo_path, cutoff_date=datetime(2026, 1, 4, tzinfo=UTC)
    )
    values = {(r["observable_type"], r["value"]): r for r in records}

    # b.example.com became inactive before cutoff, so it is skipped entirely.
    assert ("domain-name", "b.example.com") not in values
    # oldinactive became inactive after cutoff, so it is retained and revoked.
    assert values[("domain-name", "oldinactive.example.com")]["revoked"] is True
    assert values[("domain-name", "a.example.com")]["revoked"] is False
    assert ("url", "http://phish.example.com/login") in values
    assert ("ipv4-addr", "1.2.3.4") in values
    # invalid directory data must not be collected.
    assert ("url", "http://ignore.example.com") not in values


def test_filter_group_and_create_stix_objects():
    identity = {"id": "identity--24698e88-2b61-5b9e-a700-db5402c9e0c0"}
    marking = {"id": "marking-definition--32e09812-922a-5351-b4a3-07adecf7a701"}
    records = [
        {
            "observable_type": "url",
            "value": "http://phish.example.com/login",
            "first_seen": datetime(2026, 1, 3, 10, 0, tzinfo=UTC),
            "modified": datetime(2026, 1, 3, 10, 0, tzinfo=UTC),
            "revoked": False,
        },
        {
            "observable_type": "domain-name",
            "value": "b.example.com",
            "first_seen": datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            "modified": datetime(2026, 1, 2, 10, 0, tzinfo=UTC),
            "revoked": True,
        },
    ]

    filtered = phishing_database.filter_records_by_date(
        records,
        since_date=datetime(2026, 1, 3, tzinfo=UTC),
        until_date=datetime(2026, 1, 3, 23, 59, tzinfo=UTC),
    )
    assert [r["value"] for r in filtered] == ["http://phish.example.com/login"]

    grouped = phishing_database.group_records_by_hour(records)
    assert sorted(grouped.keys()) == ["20260102_10", "20260103_10"]

    objects = stix_as_dict(phishing_database.create_stix_objects(records, identity, marking))
    assert {obj["type"] for obj in objects} == {"url", "domain-name", "indicator", "relationship"}
    indicators = [obj for obj in objects if obj["type"] == "indicator"]
    assert any(indicator.get("revoked") is True for indicator in indicators)
    assert any(
        obj["type"] == "relationship"
        and obj["target_ref"] == phishing_database.T1566_STIX_ID
        for obj in objects
    )


def test_main_success_writes_output(monkeypatch, tmp_path):
    repo, repo_path = _build_repo(tmp_path)
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "phishing_database.py",
            "--since-date",
            "2026-01-03",
            "--cutoff-date",
            "2026-01-04",
        ],
    )
    monkeypatch.setattr(
        phishing_database, "BASE_OUTPUT_DIR", str(tmp_path / "processor_outputs")
    )
    monkeypatch.setattr(phishing_database, "REPO_URL", str(repo_path))

    with patch(
        "processors.phishing_database.phishing_database.fetch_external_objects",
        return_value={
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "created": "2020-01-01T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {"statement": "feeds2stix"},
        },
    ), patch(
        "processors.phishing_database.phishing_database.fetch_enterprise_attack_object",
        return_value={
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": phishing_database.T1566_STIX_ID,
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "Phishing",
        },
    ):
        phishing_database.main()

    assert out_file.exists()
    content = out_file.read_text()
    assert "bundle_path=" in content
    assert "bundle_count=3" in content
    assert "latest_timestamp=2026-01-05T10:00:00+00:00" in content

    bundle_dir = Path(content.split("bundle_path=")[1].splitlines()[0].strip())
    bundle_files = sorted(path.name for path in bundle_dir.glob("*.json"))
    assert bundle_files == [
        "phishing_database_20260103_10.json",
        "phishing_database_20260104_10.json",
        "phishing_database_20260105_10.json",
    ]

    any_bundle = json.loads((bundle_dir / bundle_files[0]).read_text())
    assert phishing_database.T1566_STIX_ID in {obj["id"] for obj in any_bundle["objects"]}
