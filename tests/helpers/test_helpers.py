import json
import os
from pathlib import Path
from unittest.mock import patch
import uuid

from stix2 import Bundle

from helpers import utils as h
from tests import utils as test_utils


class SerializableBundle:
    def __init__(self, data):
        self.data = data

    def serialize(self, indent=4):
        return json.dumps(self.data, indent=indent)


def test_generate_uuid5_with_default_namespace_is_deterministic():
    v1 = h.generate_uuid5("abc")
    v2 = h.generate_uuid5("abc")
    assert v1 == v2


def test_generate_uuid5_with_stix_namespace_string():
    result = h.generate_uuid5(
        "name", namespace="marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    )
    assert result == "ca113c79-d6f8-57a2-85a8-d23af2d1204b"
    assert result == h.generate_uuid5(
        "name", namespace=uuid.UUID("a1cb37d2-3bd3-5b23-8526-47a22694b7e0")
    )


def test_fetch_external_objects(monkeypatch):
    with patch(
        "helpers.utils.requests.get",
        return_value=test_utils.FakeJSONResponse(
            {"id": "marking-definition--fb965ce3-b6a7-4bde-b97a-a3497d6b334a"}
        ),
    ):
        marking = h.fetch_external_objects()
    assert marking["id"] == "marking-definition--fb965ce3-b6a7-4bde-b97a-a3497d6b334a"


def test_create_identity_object():
    identity = h.create_identity_object("n", "d", "organization", "c")
    assert identity.type == "identity"
    assert identity.name == "n"


def test_create_marking_definition_object():
    marking = h.create_marking_definition_object("origin")
    assert marking.type == "marking-definition"
    assert marking.definition["statement"] == "origin"


def test_create_bundle_with_metadata():
    source_identity = h.create_identity_object("src", "d", "system", "x")
    source_marking = h.create_marking_definition_object("origin")
    feeds2stix_identity = h.create_identity_object(
        "feeds2stix", "d", "organization", "https://example.com"
    )
    feeds2stix_marking = h.create_marking_definition_object("s")
    b = h.create_bundle_with_metadata(
        [], source_identity, source_marking, feeds2stix_marking
    )
    assert isinstance(b, Bundle)
    assert len(b.objects) == 3


def test_save_bundle_to_file(tmp_path):
    bundle = SerializableBundle({"type": "bundle", "id": "bundle--1", "objects": []})
    filepath = h.save_bundle_to_file(
        bundle, str(tmp_path), "sample", add_timestamp=False
    )
    assert filepath.endswith("sample.json")
    assert Path(filepath).exists()


def test_setup_output_directory_clean(tmp_path):
    base = tmp_path / "base"
    bundles = base / "bundles"
    bundles.mkdir(parents=True)
    (bundles / "old.txt").write_text("x")
    output_dir, data_dir = h.setup_output_directory(str(base), clean=True)
    assert os.path.exists(output_dir)
    assert os.path.exists(data_dir)
    assert output_dir == base / "bundles"
    assert data_dir == base / "data"
    assert not (Path(output_dir) / "old.txt").exists()


def test_make_relationship():
    rel = h.make_relationship(
        source_ref="indicator--11111111-1111-4111-8111-111111111111",
        target_ref="ipv4-addr--22222222-2222-4222-8222-222222222222",
        relationship_type="indicates",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
        created="2026-01-01T00:00:00.000Z",
    )
    assert rel.type == "relationship"
    assert rel.relationship_type == "indicates"
