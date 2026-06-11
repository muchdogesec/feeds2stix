import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from stix2 import Incident, Note
from processors.ransomlook import ransomlook
from tests.utilities import FakeJSONResponse, stix_as_dict


SOURCE_IDENTITY = ransomlook.create_ransomlook_identity()
SOURCE_MARKING = ransomlook.create_ransomlook_marking_definition()
SOURCE_IDENTITY_DICT = stix_as_dict(SOURCE_IDENTITY)
SOURCE_MARKING_DICT = stix_as_dict(SOURCE_MARKING)

GROUP_META = {
    "aliases": ["LockBit"],
    "affiliates": ["LockBitSupp"],
    "profile": ["https://www.ransomlook.io/group/lockbit5"],
    "description": "Lockbit5 group description",
    "raas": True,
    "locations": [
        {
            "slug": "https://lockbit.example.onion",
            "available": True,
            "fs": True,
            "chat": False,
            "admin": True,
        },
        {
            "slug": "https://ignored.example.onion",
            "available": False,
        },
    ],
    "notes": {
        "note-1": {"id": "note-1", "title": "Ransom note"},
    },
}

POSTS = [
    {
        "group_name": "Lockbit5",
        "post_title": "Acme Corp",
        "discovered": "2026-06-01T10:00:00Z",
        "description": "Victim post one.",
        "link": "https://www.ransomlook.io/post/acme",
        "screen": "/screens/acme.png",
        "magnet": "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    {
        "group_name": "Lockbit5",
        "post_title": "Beta Holdings",
        "discovered": "2026-06-02T11:00:00Z",
        "description": "Victim post two.",
    },
    {
        "group_name": "BlackCat",
        "post_title": "Example Org",
        "discovered": "2026-07-03T12:30:00Z",
        "description": "Victim post three.",
    },
]


@pytest.fixture(autouse=True)
def clear_caches():
    cached_functions = [
        ransomlook._crypto,
        ransomlook._notes,
        ransomlook.fetch_group_details,
        ransomlook.fetch_group_crypto,
        ransomlook._fetch_group,
        ransomlook.fetch_and_create_group_objects,
    ]
    for fn in cached_functions:
        fn.cache_clear()
    yield
    for fn in cached_functions:
        fn.cache_clear()


def test_parse_timestamp_returns_utc():
    assert ransomlook.parse_timestamp("2026-06-01T10:00:00Z") == datetime(
        2026, 6, 1, 10, 0, tzinfo=UTC
    )
    assert ransomlook.parse_timestamp("2026-06-01T10:00:00") == datetime(
        2026, 6, 1, 10, 0, tzinfo=UTC
    )


def test_resolve_date_range_uses_explicit_bounds_and_rejects_inverted_ranges():
    since = datetime(2026, 6, 1, tzinfo=UTC)
    until = datetime(2026, 6, 30, tzinfo=UTC)

    resolved_since, resolved_until = ransomlook.resolve_date_range(since, until)

    assert resolved_since == since
    assert resolved_until == until

    with pytest.raises(ValueError):
        ransomlook.resolve_date_range(until, since)


def test_iter_month_windows_splits_at_month_boundaries():
    windows = [
        (start.date(), end.date())
        for start, end in ransomlook.iter_month_windows(
            datetime(2026, 6, 15, 12, 0, tzinfo=UTC),
            datetime(2026, 8, 3, 8, 0, tzinfo=UTC),
        )
    ]

    assert windows == [
        (datetime(2026, 6, 15, tzinfo=UTC).date(), datetime(2026, 6, 30, tzinfo=UTC).date()),
        (datetime(2026, 7, 1, tzinfo=UTC).date(), datetime(2026, 7, 31, tzinfo=UTC).date()),
        (datetime(2026, 8, 1, tzinfo=UTC).date(), datetime(2026, 8, 3, tzinfo=UTC).date()),
    ]


def test_request_json_uses_optional_api_key(monkeypatch):
    monkeypatch.setenv("RANSOMLOOK_API_KEY", "test-api-key")

    with patch(
        "processors.ransomlook.ransomlook.requests.get",
        return_value=FakeJSONResponse({"posts": []}),
    ) as mock_get:
        ransomlook.request_json("https://example.test")

    assert mock_get.call_args.kwargs["headers"] == {"Authorization": "test-api-key"}


def test_request_json_without_api_key_sends_no_auth_header(monkeypatch):
    monkeypatch.delenv("RANSOMLOOK_API_KEY", raising=False)

    with patch(
        "processors.ransomlook.ransomlook.requests.get",
        return_value=FakeJSONResponse({"posts": []}),
    ) as mock_get:
        ransomlook.request_json("https://example.test")

    assert mock_get.call_args.kwargs["headers"] == {}


def test_fetch_posts_period_writes_raw_file_and_normalizes_posts(tmp_path, monkeypatch):
    monkeypatch.delenv("RANSOMLOOK_API_KEY", raising=False)
    payload = {"posts": POSTS}

    with patch(
        "processors.ransomlook.ransomlook.requests.get",
        return_value=FakeJSONResponse(payload),
    ) as mock_get:
        posts, raw_path = ransomlook.fetch_posts_period(
            tmp_path,
            datetime(2026, 6, 1, tzinfo=UTC),
            datetime(2026, 6, 30, tzinfo=UTC),
        )

    assert raw_path.name == "ransomlook_20260601_20260630.json"
    assert json.loads(raw_path.read_text()) == payload
    assert [post["post_title"] for post in posts] == [
        "Acme Corp",
        "Beta Holdings",
        "Example Org",
    ]
    assert posts[0]["discovered"] == datetime(2026, 6, 1, 10, 0, tzinfo=UTC)
    assert mock_get.call_args.args[0].endswith("/posts/period/2026-06-01/2026-06-30")


def test_fetch_group_details_adds_derived_fields():
    group_payload = [dict(GROUP_META), [{"post_title": "post-one", "discovered": "2026-06-01T00:00:00Z"}]]

    with patch(
        "processors.ransomlook.ransomlook.request_json",
        return_value=FakeJSONResponse(group_payload),
    ), patch.object(ransomlook, "group_has_crypto", return_value=True), patch.object(
        ransomlook,
        "get_note_list",
        return_value={"note-1": {"id": "note-1", "title": "Ransom note"}},
    ):
        group_meta, incidents = ransomlook.fetch_group_details("Lockbit5")

    assert incidents == group_payload[1]
    assert group_meta["has_crypto"] is True
    assert group_meta["notes"] == {"note-1": {"id": "note-1", "title": "Ransom note"}}


def test_create_intrusion_set_normalizes_aliases_and_external_references():
    created = datetime(2026, 6, 1, tzinfo=UTC)
    modified = datetime(2026, 6, 3, tzinfo=UTC)

    intrusion_set = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        created,
        modified,
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )

    assert stix_as_dict(intrusion_set) == {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
        "created_by_ref": SOURCE_IDENTITY_DICT["id"],
        "created": "2026-06-01T00:00:00.000Z",
        "modified": "2026-06-03T00:00:00.000Z",
        "first_seen": "2026-06-01T00:00:00Z",
        "last_seen": "2026-06-03T00:00:00Z",
        "name": "Lockbit5",
        "aliases": ["LockBit", "LockBitSupp"],
        "labels": ["raas"],
        "description": "Lockbit5 group description",
        "external_references": [
            {
                "source_name": "ransomlook",
                "url": "https://www.ransomlook.io/group/Lockbit5",
            },
            {
                "source_name": "ransomlook-profile",
                "url": "https://www.ransomlook.io/group/lockbit5",
            },
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_DICT["id"],
        ],
    }


def test_create_location_url_objects_creates_only_available_locations():
    group_obj = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )

    objects = ransomlook.create_location_url_objects(
        GROUP_META,
        group_obj,
    )

    assert stix_as_dict(objects) == [
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--cd381c0c-7a68-5888-a83a-d06330a73fc1",
            "value": "https://lockbit.example.onion",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--492b13a2-190c-5e64-8333-e0f45bc54f71",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "target_ref": "url--cd381c0c-7a68-5888-a83a-d06330a73fc1",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "description": "Lockbit5 uses https://lockbit.example.onion admin,fs",
        },
    ]


def test_create_wallet_objects_dedupes_wallet_addresses():
    group_obj = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    crypto_payload = {
        "by_chain": {
            "btc": [
                {"address": "bc1qexamplewallet0000000000000000000000000"},
                {"address": "bc1qexamplewallet0000000000000000000000000"},
            ],
            "eth": [{"address": "0x1111111111111111111111111111111111111111"}],
        }
    }

    objects = ransomlook.create_wallet_objects(
        "lockbit5",
        crypto_payload,
        group_obj["id"],
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )

    assert stix_as_dict(objects) == [
        {
            "type": "cryptocurrency-wallet",
            "spec_version": "2.1",
            "id": "cryptocurrency-wallet--63c69546-406d-5b56-8079-ecd9c86d38df",
            "value": "bc1qexamplewallet0000000000000000000000000",
            "extensions": {
                "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
                    "extension_type": "new-sco"
                }
            },
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--dbc863a0-6117-5eb0-85ef-66cd7c19a987",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "target_ref": "cryptocurrency-wallet--63c69546-406d-5b56-8079-ecd9c86d38df",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "description": "lockbit5 wallet on btc",
        },
        {
            "type": "cryptocurrency-wallet",
            "spec_version": "2.1",
            "id": "cryptocurrency-wallet--f0ff06db-1eba-58e1-b534-2a734208a58e",
            "value": "0x1111111111111111111111111111111111111111",
            "extensions": {
                "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
                    "extension_type": "new-sco"
                }
            },
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--3ffc05da-05d4-509f-b352-5cf1d71610cf",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "target_ref": "cryptocurrency-wallet--f0ff06db-1eba-58e1-b534-2a734208a58e",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "description": "lockbit5 wallet on eth",
        },
    ]
    assert [
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in objects
        if obj["type"] == "relationship"
    ] == [
        (
            "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "uses",
            "cryptocurrency-wallet--63c69546-406d-5b56-8079-ecd9c86d38df",
        ),
        (
            "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "uses",
            "cryptocurrency-wallet--f0ff06db-1eba-58e1-b534-2a734208a58e",
        ),
    ]


def test_create_post_objects_creates_incident_identity_and_relationships():
    group_obj = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    post = dict(POSTS[0])
    post["discovered"] = ransomlook.parse_timestamp(post["discovered"])

    incident, rel_incident, identity, rel_identity = ransomlook.create_post_objects(
        post,
        group_obj,
    )

    assert stix_as_dict(incident) == {
        "type": "incident",
        "spec_version": "2.1",
        "id": "incident--639b3793-00f2-52d4-9435-bf0877525b75",
        "created_by_ref": SOURCE_IDENTITY_DICT["id"],
        "created": "2026-06-01T10:00:00.000Z",
        "modified": "2026-06-01T10:00:00.000Z",
        "name": "Acme Corp claimed by Lockbit5",
        "description": "Victim post one.",
        "external_references": [
            {
                "source_name": "ransomlook",
                "url": "https://www.ransomlook.io/group/Lockbit5",
            },
            {
                "source_name": "path",
                "url": "https://www.ransomlook.io/post/acme",
            },
            {
                "source_name": "screenshot",
                "url": "https://www.ransomlook.io/screens/acme.png",
            },
            {
                "source_name": "path",
                "url": "https://www.ransomlook.io/post/acme",
            },
            {
                "source_name": "screenshot",
                "url": "magnet:?xt=urn:btih:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
        ],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_DICT["id"],
        ],
    }
    assert stix_as_dict(identity) == {
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--ffe8dff7-bb44-54dd-8764-9492558b5e76",
        "created_by_ref": SOURCE_IDENTITY_DICT["id"],
        "created": "2026-06-01T10:00:00.000Z",
        "modified": "2026-06-01T10:00:00.000Z",
        "name": "Acme Corp",
        "identity_class": "organization",
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_DICT["id"],
        ],
    }
    assert stix_as_dict([rel_incident, rel_identity]) == [
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--65bd2d14-aaba-529c-aa50-04143b62480e",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T10:00:00.000Z",
            "modified": "2026-06-01T10:00:00.000Z",
            "relationship_type": "attributed-to",
            "source_ref": "incident--639b3793-00f2-52d4-9435-bf0877525b75",
            "target_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "description": "Acme Corp was claimed by Lockbit5",
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/Lockbit5",
                }
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--3869f8e0-197e-533f-aced-901646c72e9c",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T10:00:00.000Z",
            "modified": "2026-06-01T10:00:00.000Z",
            "relationship_type": "targets",
            "source_ref": "identity--ffe8dff7-bb44-54dd-8764-9492558b5e76",
            "target_ref": "incident--639b3793-00f2-52d4-9435-bf0877525b75",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/Lockbit5",
                }
            ],
        },
    ]
    assert [
        (obj["source_ref"], obj["relationship_type"], obj["target_ref"])
        for obj in [rel_incident, rel_identity]
    ] == [
        (
            "incident--639b3793-00f2-52d4-9435-bf0877525b75",
            "attributed-to",
            "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
        ),
        (
            "identity--ffe8dff7-bb44-54dd-8764-9492558b5e76",
            "targets",
            "incident--639b3793-00f2-52d4-9435-bf0877525b75",
        ),
    ]


def test_fetch_and_create_note_object_uses_note_body_and_external_references():
    group_obj = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    note_payload = {
        "title": "Lockbit ransom note",
        "content": "Pay us now",
        "updated_at": "2026-06-04T09:30:00Z",
    }

    with patch(
        "processors.ransomlook.ransomlook.request_json",
        return_value=FakeJSONResponse(note_payload),
    ):
        note = ransomlook.fetch_and_create_note_object(
            {"id": "note-1", "title": "Ransom note"},
            group_obj,
            SOURCE_IDENTITY_DICT["id"],
            SOURCE_MARKING_DICT["id"],
        )

    assert stix_as_dict(note) == {
        "type": "note",
        "spec_version": "2.1",
        "id": "note--87517343-ed3c-5145-8564-4b7c98f5cc9f",
        "created_by_ref": SOURCE_IDENTITY_DICT["id"],
        "created": "2026-06-01T00:00:00.000Z",
        "modified": "2026-06-04T09:30:00.000Z",
        "abstract": "Lockbit ransom note",
        "content": "Pay us now",
        "object_refs": ["intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1"],
        "object_marking_refs": [
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_DICT["id"],
        ],
        "external_references": [
            {
                "source_name": "ransomlook",
                "url": "https://www.ransomlook.io/notes/note-1",
            },
            {
                "source_name": "ransomlook",
                "url": "https://www.ransomlook.io/group/Lockbit5",
            },
        ],
    }


def test_fetch_and_create_group_objects_assembles_group_bundle():
    group_obj = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    group_meta = dict(GROUP_META)
    note_obj = Note(
        id="note--11111111-1111-4111-8111-111111111111",
        created_by_ref=SOURCE_IDENTITY_DICT["id"],
        created=datetime(2026, 6, 1, tzinfo=UTC),
        modified=datetime(2026, 6, 1, tzinfo=UTC),
        abstract="Ransom note",
        content="pay us",
        object_refs=["intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1"],
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            SOURCE_MARKING_DICT["id"],
        ],
    )
    crypto_payload = {
        "by_chain": {"btc": [{"address": "bc1qexamplewallet0000000000000000000000000"}]}
    }

    with patch.object(
        ransomlook,
        "_fetch_group",
        return_value=(group_obj, group_meta, []),
    ), patch.object(
        ransomlook,
        "fetch_group_crypto",
        return_value=crypto_payload,
    ), patch.object(
        ransomlook,
        "fetch_and_create_note_object",
        return_value=note_obj,
    ):
        objects = ransomlook.fetch_and_create_group_objects(
            "Lockbit5",
            SOURCE_IDENTITY_DICT["id"],
            SOURCE_MARKING_DICT["id"],
        )

    assert stix_as_dict(objects) == [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
        "id": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T00:00:00.000Z",
            "modified": "2026-06-03T00:00:00.000Z",
        "first_seen": "2026-06-01T00:00:00Z",
        "last_seen": "2026-06-03T00:00:00Z",
            "name": "Lockbit5",
            "aliases": ["LockBit", "LockBitSupp"],
            "labels": ["raas"],
            "description": "Lockbit5 group description",
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/Lockbit5",
                },
                {
                    "source_name": "ransomlook-profile",
                    "url": "https://www.ransomlook.io/group/lockbit5",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
        },
        {
            "type": "url",
            "spec_version": "2.1",
            "id": "url--cd381c0c-7a68-5888-a83a-d06330a73fc1",
            "value": "https://lockbit.example.onion",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--492b13a2-190c-5e64-8333-e0f45bc54f71",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "target_ref": "url--cd381c0c-7a68-5888-a83a-d06330a73fc1",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "description": "Lockbit5 uses https://lockbit.example.onion admin,fs",
        },
        {
            "type": "cryptocurrency-wallet",
            "spec_version": "2.1",
            "id": "cryptocurrency-wallet--63c69546-406d-5b56-8079-ecd9c86d38df",
            "value": "bc1qexamplewallet0000000000000000000000000",
            "extensions": {
                "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
                    "extension_type": "new-sco"
                }
            },
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--dbc863a0-6117-5eb0-85ef-66cd7c19a987",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "target_ref": "cryptocurrency-wallet--63c69546-406d-5b56-8079-ecd9c86d38df",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "description": "Lockbit5 wallet on btc",
        },
        stix_as_dict(note_obj),
    ]


def test_create_stix_objects_for_posts_groups_posts_by_group():
    group_a = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    group_b = ransomlook.create_intrusion_set(
        "BlackCat",
        dict(GROUP_META),
        datetime(2026, 7, 1, tzinfo=UTC),
        datetime(2026, 7, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )

    def fake_fetch_and_create_group_objects(group_name, source_identity_id, source_marking_id):
        return [group_a] if group_name == "Lockbit5" else [group_b]

    def fake_create_post_objects(post, group_obj):
        incident_ids = {
            "Acme Corp": "incident--11111111-1111-4111-8111-111111111111",
            "Beta Holdings": "incident--22222222-2222-4222-8222-222222222222",
            "Example Org": "incident--33333333-3333-4333-8333-333333333333",
        }
        return [
            Incident(
                id=incident_ids[post["post_title"]],
                created=post["discovered"],
                modified=post["discovered"],
                created_by_ref=SOURCE_IDENTITY_DICT["id"],
                name=post["post_title"],
            )
        ]

    posts = [ransomlook.normalize_post_record(post) for post in POSTS]

    with patch.object(
        ransomlook,
        "fetch_and_create_group_objects",
        side_effect=fake_fetch_and_create_group_objects,
    ) as mock_group_fetch, patch.object(
        ransomlook,
        "create_post_objects",
        side_effect=fake_create_post_objects,
    ) as mock_post_objects:
        objects = ransomlook.create_stix_objects_for_posts(
            posts,
            SOURCE_IDENTITY,
            SOURCE_MARKING,
        )

    assert mock_group_fetch.call_count == 2
    assert mock_post_objects.call_count == 3
    assert stix_as_dict(objects) == [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--02a263fe-ee8a-5b45-bcb9-aad720c4fd4f",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-07-01T00:00:00.000Z",
            "modified": "2026-07-03T00:00:00.000Z",
            "first_seen": "2026-07-01T00:00:00Z",
            "last_seen": "2026-07-03T00:00:00Z",
            "name": "BlackCat",
            "aliases": ["LockBit", "LockBitSupp"],
            "labels": ["raas"],
            "description": "Lockbit5 group description",
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/BlackCat",
                },
                {
                    "source_name": "ransomlook-profile",
                    "url": "https://www.ransomlook.io/group/lockbit5",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
        },
        {
            "type": "incident",
            "spec_version": "2.1",
            "id": "incident--33333333-3333-4333-8333-333333333333",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-07-03T12:30:00.000Z",
            "modified": "2026-07-03T12:30:00.000Z",
            "name": "Example Org",
        },
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T00:00:00.000Z",
            "modified": "2026-06-03T00:00:00.000Z",
            "first_seen": "2026-06-01T00:00:00Z",
            "last_seen": "2026-06-03T00:00:00Z",
            "name": "Lockbit5",
            "aliases": ["LockBit", "LockBitSupp"],
            "labels": ["raas"],
            "description": "Lockbit5 group description",
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/Lockbit5",
                },
                {
                    "source_name": "ransomlook-profile",
                    "url": "https://www.ransomlook.io/group/lockbit5",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
        },
        {
            "type": "incident",
            "spec_version": "2.1",
            "id": "incident--11111111-1111-4111-8111-111111111111",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T10:00:00.000Z",
            "modified": "2026-06-01T10:00:00.000Z",
            "name": "Acme Corp",
        },
        {
            "type": "incident",
            "spec_version": "2.1",
            "id": "incident--22222222-2222-4222-8222-222222222222",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-02T11:00:00.000Z",
            "modified": "2026-06-02T11:00:00.000Z",
            "name": "Beta Holdings",
        },
    ]


def test_create_one_actor_creates_threat_actor_and_group_relationships():
    group_one = ransomlook.create_intrusion_set(
        "Lockbit5",
        dict(GROUP_META),
        datetime(2026, 6, 1, tzinfo=UTC),
        datetime(2026, 6, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    group_two = ransomlook.create_intrusion_set(
        "BlackCat",
        dict(GROUP_META),
        datetime(2026, 7, 1, tzinfo=UTC),
        datetime(2026, 7, 3, tzinfo=UTC),
        SOURCE_IDENTITY_DICT["id"],
        SOURCE_MARKING_DICT["id"],
    )
    actor = {
        "name": "VileActor",
        "aliases": ["Vile"],
        "relations": {"groups": ["Lockbit5", "BlackCat"]},
    }

    with patch.object(
        ransomlook,
        "_fetch_group",
        side_effect=[
            (group_one, GROUP_META, []),
            (group_two, GROUP_META, []),
        ],
    ):
        objects = ransomlook._create_one_actor(
            actor,
            SOURCE_IDENTITY_DICT["id"],
            SOURCE_MARKING_DICT["id"],
        )

    assert stix_as_dict(objects) == [
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T00:00:00.000Z",
            "modified": "2026-06-03T00:00:00.000Z",
            "first_seen": "2026-06-01T00:00:00Z",
            "last_seen": "2026-06-03T00:00:00Z",
            "name": "Lockbit5",
            "aliases": ["LockBit", "LockBitSupp"],
            "labels": ["raas"],
            "description": "Lockbit5 group description",
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/Lockbit5",
                },
                {
                    "source_name": "ransomlook-profile",
                    "url": "https://www.ransomlook.io/group/lockbit5",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
        },
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--02a263fe-ee8a-5b45-bcb9-aad720c4fd4f",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-07-01T00:00:00.000Z",
            "modified": "2026-07-03T00:00:00.000Z",
            "first_seen": "2026-07-01T00:00:00Z",
            "last_seen": "2026-07-03T00:00:00Z",
            "name": "BlackCat",
            "aliases": ["LockBit", "LockBitSupp"],
            "labels": ["raas"],
            "description": "Lockbit5 group description",
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/BlackCat",
                },
                {
                    "source_name": "ransomlook-profile",
                    "url": "https://www.ransomlook.io/group/lockbit5",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
        },
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--a6f5df75-b0c3-513a-b53c-8e5636951720",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T00:00:00.000Z",
            "modified": "2026-07-01T00:00:00.000Z",
            "name": "VileActor",
            "aliases": ["Vile"],
            "threat_actor_types": ["crime-syndicate"],
            "roles": ["affiliate", "developer", "broker", "admin"],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/actor/VileActor",
                    "external_id": "VileActor",
                }
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--8f9ac7c4-4ecf-520e-bc5e-5367a4d62a99",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T00:00:00.000Z",
            "modified": "2026-07-01T00:00:00.000Z",
            "relationship_type": "associated-with",
            "source_ref": "threat-actor--a6f5df75-b0c3-513a-b53c-8e5636951720",
            "target_ref": "intrusion-set--b6c8191c-a571-572b-bf9b-7b5c6b45d0d1",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/actor/VileActor",
                    "external_id": "VileActor",
                },
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/Lockbit5",
                },
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--5b3badbf-f511-573d-b529-c953b1978cd2",
            "created_by_ref": SOURCE_IDENTITY_DICT["id"],
            "created": "2026-06-01T00:00:00.000Z",
            "modified": "2026-07-01T00:00:00.000Z",
            "relationship_type": "associated-with",
            "source_ref": "threat-actor--a6f5df75-b0c3-513a-b53c-8e5636951720",
            "target_ref": "intrusion-set--02a263fe-ee8a-5b45-bcb9-aad720c4fd4f",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                SOURCE_MARKING_DICT["id"],
            ],
            "external_references": [
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/actor/VileActor",
                    "external_id": "VileActor",
                },
                {
                    "source_name": "ransomlook",
                    "url": "https://www.ransomlook.io/group/BlackCat",
                },
            ],
        },
    ]


def test_fetch_and_create_threat_actors_fetches_all_actors_and_dedupes(monkeypatch):
    actor_list = [{"name": "VileActor"}, {"name": "OtherActor"}]
    actor_payload = {"name": "VileActor", "aliases": [], "relations": {"groups": []}}

    def fake_request_json(url):
        if url.endswith("/actors/"):
            return FakeJSONResponse(actor_list)
        return FakeJSONResponse(actor_payload)

    with patch.object(
        ransomlook,
        "request_json",
        side_effect=fake_request_json,
    ), patch.object(
        ransomlook,
        "_create_one_actor",
        side_effect=[
            [{"id": "duplicate", "type": "threat-actor"}],
            [{"id": "duplicate", "type": "threat-actor"}],
        ],
    ) as mock_create:
        objects = ransomlook.fetch_and_create_threat_actors(
            SOURCE_IDENTITY_DICT["id"],
            SOURCE_MARKING_DICT["id"],
        )

    assert mock_create.call_count == 2
    assert objects == [{"id": "duplicate", "type": "threat-actor"}]


def test_main_creates_actor_and_monthly_bundles(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setattr(ransomlook, "BASE_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ransomlook.py",
            "--since-date",
            "2026-06-01",
            "--until-date",
            "2026-07-15",
        ],
    )
    monkeypatch.setattr(
        ransomlook,
        "fetch_external_objects",
        lambda: {
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
        },
    )
    monkeypatch.setattr(
        ransomlook,
        "fetch_and_create_threat_actors",
        lambda source_identity_id, source_marking_id: [
            {
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": "threat-actor--11111111-1111-4111-8111-111111111111",
                "name": "VileActor",
            }
        ],
    )
    monkeypatch.setattr(
        ransomlook,
        "fetch_posts_period",
        lambda data_dir, start_dt, end_dt: (
            [ransomlook.normalize_post_record(POSTS[0])],
            data_dir / f"ransomlook_{start_dt:%Y%m%d}_{end_dt:%Y%m%d}.json",
        ),
    )
    monkeypatch.setattr(
        ransomlook,
        "create_stix_objects_for_posts",
        lambda posts, source_identity, source_marking: [
            {
                "type": "note",
                "spec_version": "2.1",
                "id": "note--11111111-1111-4111-8111-111111111111",
                "content": "dummy",
                "object_refs": ["identity--11111111-1111-4111-8111-111111111111"],
            }
        ],
    )

    saved_names = []

    def fake_save_bundle_to_file(bundle, output_dir, filename, add_timestamp=True):
        saved_names.append(filename)
        return str(Path(output_dir) / f"{filename}.json")

    monkeypatch.setattr(ransomlook, "save_bundle_to_file", fake_save_bundle_to_file)

    ransomlook.main()

    assert saved_names == [
        "ransomlook_threat_actors",
        "ransomlook_20260601_20260630",
        "ransomlook_20260701_20260715",
    ]
    content = out_file.read_text()
    assert "bundle_count=3" in content
    assert "bundle_path=" in content
