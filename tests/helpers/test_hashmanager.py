import json
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from helpers import hashmanager
from tests import utils as test_utils


# ── Hashing tests ───────────────────────────────────────────────────────────


def test_compute_object_hash_basic():
    obj = {"id": "indicator--123", "type": "indicator", "name": "test"}
    h = hashmanager.compute_object_hash(obj)
    assert isinstance(h, str)
    assert len(h) == 64  # SHA-256 hex


def test_compute_object_hash_ignores_time_properties():
    obj1 = {
        "id": "indicator--123",
        "type": "indicator",
        "name": "test",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-02T00:00:00Z",
    }
    obj2 = {
        "id": "indicator--123",
        "type": "indicator",
        "name": "test",
        "created": "2099-12-31T23:59:59Z",
        "modified": "2099-12-31T23:59:59Z",
    }
    # Hashes should be identical since time properties are stripped
    assert hashmanager.compute_object_hash(obj1) == hashmanager.compute_object_hash(
        obj2
    )


def test_compute_object_hash_different_for_different_content():
    obj1 = {"id": "indicator--123", "name": "foo"}
    obj2 = {"id": "indicator--123", "name": "bar"}
    assert hashmanager.compute_object_hash(obj1) != hashmanager.compute_object_hash(
        obj2
    )


# ── Database tests ──────────────────────────────────────────────────────────


def test_load_db_creates_new():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        conn = hashmanager.load_db(db_path)
        assert isinstance(conn, sqlite3.Connection)
        # Check schema
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='uploaded_objects'"
        )
        assert cursor.fetchone() is not None
        conn.close()


def test_load_db_opens_existing():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        # Create DB with data
        conn1 = hashmanager.load_db(db_path)
        conn1.execute(
            "INSERT INTO uploaded_objects (composite_key, stix_id, obj_hash) VALUES (?, ?, ?)",
            ("id1|hash1", "id1", "hash1"),
        )
        conn1.commit()
        conn1.close()
        # Reopen
        conn2 = hashmanager.load_db(db_path)
        cursor = conn2.execute("SELECT stix_id FROM uploaded_objects WHERE stix_id=?", ("id1",))
        assert cursor.fetchone()[0] == "id1"
        conn2.close()


def test_save_db():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        conn = hashmanager.load_db(db_path)
        conn.execute(
            "INSERT INTO uploaded_objects (composite_key, stix_id, obj_hash) VALUES (?, ?, ?)",
            ("id2|hash2", "id2", "hash2"),
        )
        hashmanager.save_db(conn, db_path)
        # Reopen to verify
        conn2 = hashmanager.load_db(db_path)
        cursor = conn2.execute("SELECT stix_id FROM uploaded_objects WHERE stix_id=?", ("id2",))
        assert cursor.fetchone()[0] == "id2"
        conn2.close()


# ── Filter/record tests ─────────────────────────────────────────────────────


def test_filter_new_objects_all_new():
    with tempfile.TemporaryDirectory() as td:
        conn = hashmanager.load_db(Path(td) / "test.db")
        objects = [
            {"id": "indicator--1", "name": "a"},
            {"id": "indicator--2", "name": "b"},
        ]
        new_objects, skipped = hashmanager.filter_new_objects(objects, conn)
        assert len(new_objects) == 2
        assert skipped == 0
        conn.close()


def test_filter_new_objects_some_existing():
    with tempfile.TemporaryDirectory() as td:
        conn = hashmanager.load_db(Path(td) / "test.db")
        obj1 = {"id": "indicator--1", "name": "a"}
        obj2 = {"id": "indicator--2", "name": "b"}
        # Record obj1
        hashmanager.record_uploaded_objects([obj1], conn)
        # Filter both
        new_objects, skipped = hashmanager.filter_new_objects([obj1, obj2], conn)
        assert len(new_objects) == 1
        assert new_objects[0]["id"] == "indicator--2"
        assert skipped == 1
        conn.close()


def test_filter_new_objects_modified_object_not_skipped():
    """Modified object (different hash) should NOT be skipped."""
    with tempfile.TemporaryDirectory() as td:
        conn = hashmanager.load_db(Path(td) / "test.db")
        obj_v1 = {"id": "indicator--1", "name": "old"}
        obj_v2 = {"id": "indicator--1", "name": "new"}
        # Record v1
        hashmanager.record_uploaded_objects([obj_v1], conn)
        # Filter v2 - should NOT be skipped since hash differs
        new_objects, skipped = hashmanager.filter_new_objects([obj_v2], conn)
        assert len(new_objects) == 1
        assert skipped == 0
        conn.close()


def test_record_uploaded_objects():
    with tempfile.TemporaryDirectory() as td:
        conn = hashmanager.load_db(Path(td) / "test.db")
        objects = [
            {"id": "indicator--1", "name": "a"},
            {"id": "indicator--2", "name": "b"},
        ]
        hashmanager.record_uploaded_objects(objects, conn)
        cursor = conn.execute("SELECT COUNT(*) FROM uploaded_objects")
        assert cursor.fetchone()[0] == 2
        conn.close()


def test_record_uploaded_objects_ignores_duplicates():
    with tempfile.TemporaryDirectory() as td:
        conn = hashmanager.load_db(Path(td) / "test.db")
        obj = {"id": "indicator--1", "name": "a"}
        hashmanager.record_uploaded_objects([obj], conn)
        hashmanager.record_uploaded_objects([obj], conn)  # Record again
        cursor = conn.execute("SELECT COUNT(*) FROM uploaded_objects")
        assert cursor.fetchone()[0] == 1  # Still only 1
        conn.close()


# ── Artifact download tests ─────────────────────────────────────────────────


def test_download_artifact_success(monkeypatch, tmp_path):
    import zipfile
    import io

    # Create a zip with a DB file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("stix_hashes.db", b"fake-db-content")
    zip_buffer.seek(0)

    list_resp = test_utils.FakeJSONResponse(
        {
            "artifacts": [
                {"id": 123, "archive_download_url": "https://example.com/download"}
            ]
        }
    )
    dl_resp = MagicMock()
    dl_resp.raise_for_status = MagicMock()
    dl_resp.content = zip_buffer.read()

    responses = iter([list_resp, dl_resp])
    monkeypatch.setattr(
        hashmanager.requests, "get", lambda *a, **k: next(responses)
    )

    dest = tmp_path / "downloaded.db"
    result = hashmanager.download_artifact("test-artifact", "owner/repo", "token", dest)
    assert result is True
    assert dest.exists()
    assert dest.read_bytes() == b"fake-db-content"


def test_download_artifact_no_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(
        hashmanager.requests,
        "get",
        lambda *a, **k: test_utils.FakeJSONResponse({"artifacts": []}),
    )
    dest = tmp_path / "downloaded.db"
    result = hashmanager.download_artifact("test-artifact", "owner/repo", "token", dest)
    assert result is False


def test_download_artifact_list_fails(monkeypatch, tmp_path):
    def raise_error(*a, **k):
        raise Exception("Network error")

    monkeypatch.setattr(hashmanager.requests, "get", raise_error)
    dest = tmp_path / "downloaded.db"
    result = hashmanager.download_artifact("test-artifact", "owner/repo", "token", dest)
    assert result is False


def test_download_artifact_no_db_in_zip(monkeypatch, tmp_path):
    import zipfile
    import io

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("other_file.txt", b"not-a-db")
    zip_buffer.seek(0)

    list_resp = test_utils.FakeJSONResponse(
        {
            "artifacts": [
                {"id": 123, "archive_download_url": "https://example.com/download"}
            ]
        }
    )
    dl_resp = MagicMock()
    dl_resp.raise_for_status = MagicMock()
    dl_resp.content = zip_buffer.read()

    responses = iter([list_resp, dl_resp])
    monkeypatch.setattr(
        hashmanager.requests, "get", lambda *a, **k: next(responses)
    )

    dest = tmp_path / "downloaded.db"
    result = hashmanager.download_artifact("test-artifact", "owner/repo", "token", dest)
    assert result is False


# ── Cleanup tests ───────────────────────────────────────────────────────────


def test_cleanup_old_artifacts_keeps_recent(monkeypatch):
    artifacts = [
        {"id": i, "created_at": f"2024-01-{i:02d}T00:00:00Z"}
        for i in range(1, 16)
    ]
    # Reverse to simulate newest-first
    artifacts.reverse()

    deleted_ids = []

    def mock_get(*a, **k):
        return test_utils.FakeJSONResponse({"artifacts": artifacts})

    def mock_delete(url, *a, **k):
        artifact_id = int(url.split("/")[-1])
        deleted_ids.append(artifact_id)
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        return resp

    monkeypatch.setattr(hashmanager.requests, "get", mock_get)
    monkeypatch.setattr(hashmanager.requests, "delete", mock_delete)

    hashmanager.cleanup_old_artifacts("test-artifact", "owner/repo", "token", keep_count=10)
    
    # Should delete 5 oldest (ids 1-5)
    assert len(deleted_ids) == 5
    assert set(deleted_ids) == {1, 2, 3, 4, 5}


def test_cleanup_old_artifacts_nothing_to_delete(monkeypatch):
    artifacts = [{"id": i} for i in range(1, 6)]

    monkeypatch.setattr(
        hashmanager.requests,
        "get",
        lambda *a, **k: test_utils.FakeJSONResponse({"artifacts": artifacts}),
    )

    deleted = []
    monkeypatch.setattr(
        hashmanager.requests,
        "delete",
        lambda *a, **k: deleted.append(1),
    )

    hashmanager.cleanup_old_artifacts("test-artifact", "owner/repo", "token", keep_count=10)
    assert len(deleted) == 0


def test_cleanup_old_artifacts_handles_errors(monkeypatch):
    def raise_error(*a, **k):
        raise Exception("API error")

    monkeypatch.setattr(hashmanager.requests, "get", raise_error)
    # Should not crash
    hashmanager.cleanup_old_artifacts("test-artifact", "owner/repo", "token")
