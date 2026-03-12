import argparse
import json
import logging
import math
import os
from pathlib import Path
from types import SimpleNamespace

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def get_file_size_kb(data):
    """Calculate the size of JSON data in kilobytes"""
    json_str = json.dumps(data)
    return len(json_str.encode("utf-8")) / 1024


def get_batch_sizes(max_size_kb):
    """Calculate dynamic batch sizes based on max_size_kb"""
    size_based = []
    max_size_kb = max(max_size_kb, 10)  # Ensure we have a positive size
    size = max_size_kb
    while size > 1:
        for i in [2, 5, 10]:
            size = max(int(max_size_kb / i), 1)
            size_based.append(size)
            if size == 1:
                break
        max_size_kb = size
    return size_based


def split_stix_bundle(input_file, max_size_kb, output_dir=None):
    """
    Split a STIX bundle into multiple bundles based on max size

    Args:
        input_file: Path to input STIX bundle JSON file
        max_size_kb: Maximum size of each output file in kilobytes
        output_dir: Directory to save split bundles (defaults to same dir as input)

    Returns:
        List of output file paths
    """
    logger.info(f"Loading bundle from: {input_file}")

    with open(input_file, "r") as f:
        bundle = json.load(f)

    if bundle.get("type") != "bundle":
        raise ValueError("Input file is not a STIX bundle")

    objects = bundle.get("objects", [])
    logger.info(f"Total objects in bundle: {len(objects)}")

    if output_dir is None:
        output_dir = os.path.dirname(input_file) or "."
    os.makedirs(output_dir, exist_ok=True)

    input_path = Path(input_file)
    base_name = input_path.stem

    # Separate metadata objects (identity, marking-definition) from other objects
    metadata_objects = []
    data_objects = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type in ["identity", "marking-definition"]:
            metadata_objects.append(obj)
        else:
            data_objects.append(obj)

    logger.info(
        f"Metadata objects: {len(metadata_objects)}, Data objects: {len(data_objects)}"
    )

    # Calculate base bundle size (metadata + bundle structure)
    base_bundle = {
        "type": "bundle",
        "id": bundle.get("id", "bundle--00000000-0000-0000-0000-000000000000"),
        "objects": metadata_objects,
    }
    base_size_kb = get_file_size_kb(base_bundle)
    logger.info(f"Base bundle size (metadata): {base_size_kb:.2f} KB")

    if base_size_kb > max_size_kb:
        logger.warning(
            f"Base bundle size ({base_size_kb:.2f} KB) exceeds max size ({max_size_kb} KB)"
        )
        logger.warning(
            "Will attempt to split anyway, but some bundles may exceed max size"
        )

    # Split data objects into chunks
    output_files = []
    chunk_num = 1
    current_chunk = []
    i = 0

    # Calculate dynamic batch sizes based on max_size
    # Start with size-based estimates, then fall back to fixed sizes
    batch_sizes = get_batch_sizes(max_size_kb)

    while i < len(data_objects):

        batch_added = False

        for batch_size in batch_sizes:
            # Test adding batch_size objects
            test_chunk = current_chunk + data_objects[i : i + batch_size]
            test_bundle = {
                "type": "bundle",
                "id": bundle.get("id", "bundle--00000000-0000-0000-0000-000000000000"),
                "objects": metadata_objects + test_chunk,
            }
            test_size = get_file_size_kb(test_bundle)

            if test_size <= max_size_kb:
                # Batch fits, add it
                current_chunk = test_chunk
                i += batch_size
                batch_added = True
                break
            elif not current_chunk and batch_size == batch_sizes[-1]:
                # Even a single object doesn't fit in empty chunk - add it anyway
                logger.warning(
                    f"Single object at index {i} exceeds max size ({test_size:.2f} KB > {max_size_kb} KB)"
                )
                current_chunk = test_chunk
                i += 1
                batch_added = True
                break

        # If no batch could be added and chunk is full, save it
        if not batch_added and current_chunk:
            output_file = save_bundle(
                output_dir,
                bundle.get("id", "bundle--00000000-0000-0000-0000-000000000000"),
                base_name,
                chunk_num,
                metadata_objects + current_chunk,
            )
            output_files.append(output_file)

            current_chunk = []
            chunk_num += 1

    # Save remaining objects
    if current_chunk:
        output_file = save_bundle(
            output_dir,
            bundle.get("id", "bundle--00000000-0000-0000-0000-000000000000"),
            base_name,
            chunk_num,
            metadata_objects + current_chunk,
        )
        output_files.append(output_file)

    logger.info(f"Split complete: Created {len(output_files)} bundle(s)")
    return output_files


def save_bundle(output_dir, bundle_id, base_name, chunk_num, objects):
    output_file = os.path.join(output_dir, f"{base_name}.part_{chunk_num}.json")
    chunk_bundle = {"type": "bundle", "id": bundle_id, "objects": objects}

    with open(output_file, "w") as f:
        json.dump(chunk_bundle, f, indent=4)

    actual_size = get_file_size_kb(chunk_bundle)
    logger.info(
        f"Created {output_file} with {len(objects)} objects ({actual_size:.2f} KB)"
    )
    return output_file
