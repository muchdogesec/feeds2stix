import json
from pathlib import Path

import pytest

from helpers import split_jsons


def test_get_file_size_kb_returns_positive_value():
    size = split_jsons.get_file_size_kb({"a": "b"})
    assert size > 0


@pytest.mark.parametrize(
    "max_size_kb,expected",
    [
        (1000, [500, 200, 100, 50, 20, 10, 5, 2, 1]),
        (500, [250, 100, 50, 25, 10, 5, 2, 1]),
        (100, [50, 20, 10, 5, 2, 1]),
        (50, [25, 10, 5, 2, 1]),
        (10, [5, 2, 1]),
        (5, [5, 2, 1]),  # same as max_kb_size=10
        (9, [5, 2, 1]),  # same as max_kb_size=10
    ],
)
def test_get_batch_sizes_returns_values_for_large_limit(max_size_kb, expected):
    sizes = split_jsons.get_batch_sizes(max_size_kb)
    print(sizes)
    assert sizes == expected, sizes


def test_save_bundle_writes_json_file(tmp_path):
    path = split_jsons.save_bundle(
        str(tmp_path),
        "bundle--1",
        "name",
        1,
        [{"type": "indicator", "id": "indicator--1"}],
    )
    assert Path(path).exists()
    data = json.loads(Path(path).read_text())
    assert data["type"] == "bundle"
    assert data["id"] == "bundle--1"


def test_split_stix_bundle_raises_for_non_bundle(tmp_path):
    input_file = tmp_path / "bad.json"
    input_file.write_text(json.dumps({"type": "indicator", "objects": []}))
    with pytest.raises(ValueError):
        split_jsons.split_stix_bundle(str(input_file), 100)


def test_split_stix_bundle_creates_multiple_files(tmp_path):
    objects = [
        {"type": "identity", "id": "identity--1"},
        {
            "type": "marking-definition",
            "id": "marking-definition--1",
            "definition_type": "statement",
            "definition": {"statement": "x"},
        },
    ]
    for i in range(8):
        objects.append(
            {
                "type": "indicator",
                "id": f"indicator--{i}",
                "name": "N" * 10000,
            }
        )
    input_bundle = {"type": "bundle", "id": "bundle--1", "objects": objects}
    input_file = tmp_path / "bundle.json"
    input_file.write_text(json.dumps(input_bundle))

    out = split_jsons.split_stix_bundle(
        str(input_file), max_size_kb=11, output_dir=str(tmp_path / "out")
    )
    assert len(out) > 1
    assert all(Path(p).exists() for p in out)


def test_split_stix_bundle_tiny_max_size_does_not_stall(tmp_path):
    objects = [
        {"type": "identity", "id": "identity--1"},
        {
            "type": "marking-definition",
            "id": "marking-definition--1",
            "definition_type": "statement",
            "definition": {"statement": "x"},
        },
        {"type": "indicator", "id": "indicator--1", "name": "N" * 2000},
    ]
    input_bundle = {"type": "bundle", "id": "bundle--1", "objects": objects}
    input_file = tmp_path / "tiny.json"
    input_file.write_text(json.dumps(input_bundle))

    out = split_jsons.split_stix_bundle(
        str(input_file), max_size_kb=1, output_dir=str(tmp_path / "out_tiny")
    )
    assert len(out) >= 1
    assert all(Path(p).exists() for p in out)
