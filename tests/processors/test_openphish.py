import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from git import Repo

import processors
from processors.openphish import openphish
from tests import utils as test_utils
from tests.utils import stix_as_dict


@pytest.fixture
def tmp_git_repo(tmp_path):
    """Create a temporary git repository with 5 commits on different dates."""
    repo_path = tmp_path / "test_repo"
    repo_path.mkdir()

    # Initialize git repo
    repo = Repo.init(repo_path)

    # Configure git user for commits
    with repo.config_writer() as config:
        config.set_value("user", "name", "Test User")
        config.set_value("user", "email", "test@example.com")

    feed_file = repo_path / "feed.txt"

    # Commit 1: Jan 1, 2026 - Initial URLs
    feed_file.write_text("http://url1.example.com\nhttp://url2.example.com\n")
    repo.index.add([str(feed_file)])
    commit1_date = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    commit1 = repo.index.commit(
        "Initial commit",
        commit_date=commit1_date,
        author_date=commit1_date,
    )

    # Commit 2: Jan 5, 2026 - Add new URL
    feed_file.write_text(
        "http://url1.example.com\nhttp://url2.example.com\nhttp://url3.example.com\n"
    )
    repo.index.add([str(feed_file)])
    commit2_date = datetime(2026, 1, 5, 12, 30, 0, tzinfo=UTC)
    commit2 = repo.index.commit(
        "Add url3",
        commit_date=commit2_date,
        author_date=commit2_date,
    )

    # Commit 3: Jan 10, 2026 - Add another URL
    feed_file.write_text(
        "http://url1.example.com\nhttp://url2.example.com\nhttp://url3.example.com\nhttp://url4.example.com\n"
    )
    repo.index.add([str(feed_file)])
    commit3_date = datetime(2026, 1, 10, 14, 15, 0, tzinfo=UTC)
    commit3 = repo.index.commit(
        "Add url4",
        commit_date=commit3_date,
        author_date=commit3_date,
    )

    # Commit 4: Jan 15, 2026 - Complete replacement with new URLs
    feed_file.write_text(
        "http://url7.example.com\nhttp://url8.example.com\nhttp://url9.example.com\n"
    )
    repo.index.add([str(feed_file)])
    commit4_date = datetime(2026, 1, 15, 9, 45, 0, tzinfo=UTC)
    commit4 = repo.index.commit(
        "Complete replacement with new URLs",
        commit_date=commit4_date,
        author_date=commit4_date,
    )

    # Commit 5: Jan 20, 2026 - Add url10
    feed_file.write_text(
        "http://url7.example.com\nhttp://url8.example.com\nhttp://url9.example.com\nhttp://url10.example.com\n"
    )
    repo.index.add([str(feed_file)])
    commit5_date = datetime(2026, 1, 20, 16, 20, 0, tzinfo=UTC)
    commit5 = repo.index.commit(
        "Add url10",
        commit_date=commit5_date,
        author_date=commit5_date,
    )

    return repo, "feed.txt"


def test_create_openphish_identity():
    identity = openphish.create_openphish_identity()
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--a42856ab-ed95-54c5-b97f-eb5bf4dd8a6a",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "name": "OpenPhish",
        "description": "Timely. Accurate. Relevant Phishing Intelligence.",
        "identity_class": "organization",
        "contact_information": "https://openphish.com/index.html",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_openphish_marking_definition():
    marking = openphish.create_openphish_marking_definition()
    assert stix_as_dict(marking) == {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--f7187271-2598-5b00-9b1d-5b538f1e9b9b",
        "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {
            "statement": "Origin: https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
        },
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    }


def test_create_stix_objects():
    url_data_for_date = {
        "http://phishing.example.com/fake": (
            "abc12345",
            datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        )
    }

    objects = openphish.create_stix_objects(
        url_data_for_date,
        {"id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"},
        {"id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"},
    )

    assert stix_as_dict(objects) == [
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--e03c2093-b268-5dce-9ec7-ede044f4ca99",
            "value": "http://phishing.example.com/fake",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--2f656a3b-edaf-5fed-80e8-172c7b8e3913",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "URL: http://phishing.example.com/fake",
            "indicator_types": ["malicious-activity"],
            "pattern": "[url:value='http://phishing.example.com/fake']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2026-01-01T00:00:00Z",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--f6ac3844-ecc4-5150-80f5-21beaf47abb8",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--2f656a3b-edaf-5fed-80e8-172c7b8e3913",
            "target_ref": "url--e03c2093-b268-5dce-9ec7-ede044f4ca99",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            ],
        },
    ]


def test_group_urls_by_date():
    url_data = {
        "http://example1.com": ("abc123", datetime(2026, 1, 1, 10, 30, tzinfo=UTC)),
        "http://example2.com": ("def456", datetime(2026, 1, 1, 10, 45, tzinfo=UTC)),
        "http://example3.com": ("ghi789", datetime(2026, 1, 2, 14, 20, tzinfo=UTC)),
    }

    result = openphish.group_urls_by_date(url_data)

    assert len(result) == 2
    assert "20260101_10" in result
    assert "20260102_14" in result
    assert len(result["20260101_10"]) == 2
    assert len(result["20260102_14"]) == 1


def test_clone_or_update_repo(tmp_git_repo, tmp_path):
    """Test cloning and updating a git repository."""
    source_repo, _ = tmp_git_repo
    source_repo_path = source_repo.working_dir

    # Test cloning - first time, repo doesn't exist
    clone_path = tmp_path / "cloned_repo"
    assert not clone_path.exists()

    cloned_repo = openphish.clone_or_update_repo(str(clone_path), source_repo_path)

    assert clone_path.exists()
    assert cloned_repo.working_dir == str(clone_path)

    # Verify the cloned repo has the same commits
    cloned_commits = list(cloned_repo.iter_commits())
    source_commits = list(source_repo.iter_commits())
    assert len(cloned_commits) == len(source_commits)
    assert cloned_commits[0].hexsha == source_commits[0].hexsha

    # Test updating - repo already exists, should pull latest changes
    # First, add a new commit to the source repo
    feed_file = Path(source_repo_path) / "feed.txt"
    feed_file.write_text(
        "http://url7.example.com\nhttp://url8.example.com\nhttp://url9.example.com\nhttp://url10.example.com\nhttp://url11.example.com\n"
    )
    source_repo.index.add([str(feed_file)])
    new_commit_date = datetime(2026, 1, 25, 10, 0, 0, tzinfo=UTC)
    source_repo.index.commit(
        "Add url11",
        commit_date=new_commit_date,
        author_date=new_commit_date,
    )

    # Now update the cloned repo
    updated_repo = openphish.clone_or_update_repo(str(clone_path), source_repo_path)

    # Verify the update pulled the new commit
    updated_commits = list(updated_repo.iter_commits())
    source_commits_after = list(source_repo.iter_commits())
    assert len(updated_commits) == len(source_commits_after)
    assert updated_commits[0].hexsha == source_commits_after[0].hexsha


def test_get_lines_since_date_filters_by_date(tmp_git_repo):
    """Test that get_lines_since_date correctly filters URLs by commit date."""
    repo, file_path = tmp_git_repo

    # Test without date filter - should get all 8 URLs
    result_all = openphish.get_lines_since_date(repo, file_path, since_date=None)
    print(result_all)
    assert len(result_all) == 8
    assert result_all == {
        "http://url2.example.com": (
            "bec3a047",
            datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        ),
        "http://url1.example.com": (
            "bec3a047",
            datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        ),
        "http://url3.example.com": (
            "2c60a435",
            datetime(2026, 1, 5, 12, 30, tzinfo=UTC),
        ),
        "http://url4.example.com": (
            "dd772e92",
            datetime(2026, 1, 10, 14, 15, tzinfo=UTC),
        ),
        "http://url7.example.com": (
            "5f946b0e",
            datetime(2026, 1, 15, 9, 45, tzinfo=UTC),
        ),
        "http://url9.example.com": (
            "5f946b0e",
            datetime(2026, 1, 15, 9, 45, tzinfo=UTC),
        ),
        "http://url8.example.com": (
            "5f946b0e",
            datetime(2026, 1, 15, 9, 45, tzinfo=UTC),
        ),
        "http://url10.example.com": (
            "8eae9cf8",
            datetime(2026, 1, 20, 16, 20, tzinfo=UTC),
        ),
    }

    # Verify commit dates for url1 (first commit, Jan 1)
    url1_commit_hash, url1_date = result_all["http://url1.example.com"]
    assert url1_date == datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)

    # Test with since_date = Jan 8 - should get url4, url7, url8, url9, url10 (added after Jan 8)
    since_date = datetime(2026, 1, 8, tzinfo=UTC)
    result_filtered = openphish.get_lines_since_date(repo, file_path, since_date)
    assert len(result_filtered) == 5
    assert "http://url1.example.com" not in result_filtered  # Added Jan 1
    assert "http://url2.example.com" not in result_filtered  # Added Jan 1
    assert "http://url3.example.com" not in result_filtered  # Added Jan 5
    assert result_filtered == {
        "http://url4.example.com": (
            "dd772e92",
            datetime(2026, 1, 10, 14, 15, tzinfo=UTC),
        ),
        "http://url7.example.com": (
            "5f946b0e",
            datetime(2026, 1, 15, 9, 45, tzinfo=UTC),
        ),
        "http://url9.example.com": (
            "5f946b0e",
            datetime(2026, 1, 15, 9, 45, tzinfo=UTC),
        ),
        "http://url8.example.com": (
            "5f946b0e",
            datetime(2026, 1, 15, 9, 45, tzinfo=UTC),
        ),
        "http://url10.example.com": (
            "8eae9cf8",
            datetime(2026, 1, 20, 16, 20, tzinfo=UTC),
        ),
    }

    # Test with since_date = Jan 16 - should only get url10 (added Jan 20, which is after Jan 15)
    since_date = datetime(2026, 1, 16, tzinfo=UTC)
    result_filtered2 = openphish.get_lines_since_date(repo, file_path, since_date)
    assert len(result_filtered2) == 1
    assert "http://url10.example.com" in result_filtered2
    # url7, url8, url9 were added on Jan 15 (before Jan 16), so they shouldn't be included
    assert result_filtered2 == {
        "http://url10.example.com": (
            "8eae9cf8",
            datetime(2026, 1, 20, 16, 20, tzinfo=UTC),
        )
    }


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["openphish.py"])
    monkeypatch.setattr(openphish, "BASE_OUTPUT_DIR", str(tmp_path))

    mock_repo = MagicMock()
    url_data = {
        "http://phishing.example.com": (
            "abc123",
            datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
        )
    }

    with patch(
        "processors.openphish.openphish.clone_or_update_repo", return_value=mock_repo
    ), patch(
        "processors.openphish.openphish.get_lines_since_date", return_value=url_data
    ):
        openphish.main()

    assert out_file.exists()
    content = out_file.read_text()
    assert "bundle_path=" in content
    assert "bundle_count=1" in content

    bundles_dir = content.split("bundle_path=")[1].split("\n")[0].strip()
    # Find the actual bundle file in the directory
    bundle_files = list(Path(bundles_dir).glob("*.json"))
    assert len(bundle_files) == 1
    bundle = json.loads(bundle_files[0].read_text())
    assert {obj["id"] for obj in bundle["objects"]} == {
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",  # feeds2stix marking
        "identity--a42856ab-ed95-54c5-b97f-eb5bf4dd8a6a",  # openphish identity
        "marking-definition--f7187271-2598-5b00-9b1d-5b538f1e9b9b",  # openphish marking
        "url--792c59ad-b388-5dcb-bb99-918bd34e4504",  # URL observable
        "indicator--71ac46dc-a164-5bbf-b3c7-2178bc907d22",  # indicator
        "relationship--0e5aa9ef-4f2d-56bb-bf7a-d8ecb9def67a",  # relationship
    }

    assert {
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in bundle["objects"]
        if obj["type"] == "relationship"
    } == {
        (
            "indicator--71ac46dc-a164-5bbf-b3c7-2178bc907d22",
            "indicates",
            "url--792c59ad-b388-5dcb-bb99-918bd34e4504",
        ),
    }
