"""
hashmanager.py — Tracks uploaded STIX objects by (id, hash) to avoid re-uploading
unchanged objects.

The state is persisted in a SQLite database.  Between runs the database is
stored as a GitHub Actions artifact so it survives across workflow executions.

Public API
----------
compute_object_hash(obj)            -> str   (SHA-256 hex of canonical JSON)
filter_new_objects(objects, db)     -> (new_objects, skipped_count)
record_uploaded_objects(objects, db)
load_db(path)                       -> sqlite3.Connection
save_db(conn, path)
download_artifact(artifact_name, api_base_url, api_key, dest_path) -> bool
"""

import hashlib
import io
import json
import logging
import os
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

_TIME_PROPERTIES = frozenset({
    "created",
    "modified",
    "published",
    "valid_from",
    "valid_until",
    "first_seen",
    "last_seen",
    "first_observed",
    "last_observed",
})


def compute_object_hash(obj: dict) -> str:
    """Return the SHA-256 hex digest of the canonical (sorted-keys) JSON
    representation of *obj*, with time-related properties stripped out.

    Time properties (created, modified, valid_from, valid_until, first_seen,
    last_seen, first_observed, last_observed) are excluded so that an object
    whose only change is a timestamp update is still considered identical and
    is not re-uploaded.

    The hash is stable across Python versions because:
    - time properties are removed before serialisation
    - keys are sorted recursively via ``sort_keys=True``
    - separators are fixed (no trailing whitespace)
    """
    stripped = {k: v for k, v in obj.items() if k not in _TIME_PROPERTIES}
    canonical = json.dumps(stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS uploaded_objects (
    composite_key TEXT PRIMARY KEY,
    stix_id       TEXT NOT NULL,
    obj_hash      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_stix_id ON uploaded_objects (stix_id);
"""


def _make_db_entry(obj: dict) -> str:
    """Generate composite key: stix_id + '|' + obj_hash"""
    stix_id = obj['id']
    obj_hash = compute_object_hash(obj)
    return f"{stix_id}|{obj_hash}", stix_id, obj_hash


def load_db(path: str | os.PathLike) -> sqlite3.Connection:
    """Open (or create) the SQLite database at *path* and ensure the schema
    exists.  Returns an open ``sqlite3.Connection``."""
    conn = sqlite3.connect(str(path))
    conn.executescript(_SCHEMA)
    conn.commit()
    logger.debug("Opened hash database at %s", path)
    return conn


def save_db(conn: sqlite3.Connection, path: str | os.PathLike) -> None:
    """Flush and close *conn*, then ensure the file is present at *path*.

    If the connection was opened against a different on-disk path you can pass
    the desired destination; the file will be copied if necessary.
    """
    conn.commit()
    # Obtain the filename the connection is already backed by
    db_file = conn.execute("PRAGMA database_list").fetchone()[2]
    db_file = db_file and Path(db_file)
    conn.close()
    logger.debug("Closed hash database (backed by %s)", db_file)

    dest = Path(path)
    if db_file and db_file.resolve() != dest.resolve() and db_file.exists():
        shutil.copy2(db_file, dest)
        logger.debug("Copied database from %s to %s", db_file, dest)


# ---------------------------------------------------------------------------
# Object filtering / recording
# ---------------------------------------------------------------------------

def filter_new_objects(
    objects: list[dict], conn: sqlite3.Connection
) -> tuple[list[dict], int]:
    """Return *(new_objects, skipped_count)* where *new_objects* are the
    elements from *objects* that do NOT already exist in the database with the
    same hash (i.e. objects that must be uploaded).

    An object is considered *already uploaded* when its ``id`` AND ``hash``
    are both present in the database — this means a modified version of the
    same object (different hash) will **not** be skipped and will be
    re-uploaded.

    Uses a single query with primary key lookup for optimal performance.
    """
    if not objects:
        return [], 0
    
    # Build composite keys and prepare query parameters in one pass.
    new_objects = []
    skipped = 0
    for obj in objects:
        composite_key, _, _ = _make_db_entry(obj)
        row = conn.execute(
            "SELECT 1 FROM uploaded_objects WHERE composite_key = ?",
            (composite_key,),
        ).fetchone()
        if row:
            skipped += 1
        else:
            new_objects.append(obj)
    
    return new_objects, skipped


def record_uploaded_objects(objects: list[dict], conn: sqlite3.Connection) -> None:
    """Insert *(composite_key, stix_id, obj_hash)* rows into the database for
    every object in *objects*.  Rows that already exist are silently ignored
    (INSERT OR IGNORE)."""
    rows = [_make_db_entry(obj) for obj in objects]
    conn.executemany(
        "INSERT OR IGNORE INTO uploaded_objects (composite_key, stix_id, obj_hash) VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()
    logger.debug("Recorded %d uploaded objects in hash database", len(rows))


# ---------------------------------------------------------------------------
# GitHub Actions artifact helpers
# ---------------------------------------------------------------------------

_GH_API_BASE = "https://api.github.com"
_DB_FILENAME = "stix_hashes.db"


def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def download_artifact(
    artifact_name: str,
    repo: str,
    token: str,
    dest_path: str | os.PathLike,
) -> bool:
    """Download the most-recent GitHub Actions artifact named *artifact_name*
    from *repo* (``"owner/repo"``) and extract the SQLite database file to
    *dest_path*.

    Returns ``True`` on success, ``False`` when the artifact does not exist or
    the download fails (callers should then start with a fresh database).
    """
    list_url = f"{_GH_API_BASE}/repos/{repo}/actions/artifacts"
    params = {"name": artifact_name, "per_page": 1}
    try:
        resp = requests.get(list_url, headers=_gh_headers(token), params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("Could not list artifacts for %s: %s", artifact_name, exc)
        return False

    artifacts = data.get("artifacts", [])
    if not artifacts:
        logger.info("No existing artifact named %r found; starting with empty DB.", artifact_name)
        return False

    # The list is sorted newest-first by default.
    artifact = artifacts[0]
    download_url = artifact.get("archive_download_url")
    artifact_id = artifact.get("id")

    if not download_url:
        logger.warning("Artifact %r has no archive_download_url", artifact_name)
        return False

    logger.info(
        "Downloading artifact %r (id=%s) from %s", artifact_name, artifact_id, download_url
    )
    try:
        dl_resp = requests.get(
            download_url, headers=_gh_headers(token), stream=True, timeout=60
        )
        dl_resp.raise_for_status()
    except Exception as exc:
        logger.warning("Failed to download artifact %r: %s", artifact_name, exc)
        return False

    try:
        with zipfile.ZipFile(io.BytesIO(dl_resp.content)) as zf:
            # The zip may contain the DB directly or nested; find it by name.
            names = zf.namelist()
            db_entry = next((n for n in names if n.endswith(_DB_FILENAME)), None)
            if db_entry is None:
                logger.warning(
                    "Artifact zip does not contain %s (contents: %s)", _DB_FILENAME, names
                )
                return False
            with zf.open(db_entry) as src, open(str(dest_path), "wb") as dst:
                shutil.copyfileobj(src, dst)
        logger.info("Artifact DB extracted to %s", dest_path)
        return True
    except Exception as exc:
        logger.warning("Failed to extract artifact %r: %s", artifact_name, exc)
        return False
