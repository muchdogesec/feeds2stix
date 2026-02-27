import uuid
import requests
import logging
import os
import shutil
from datetime import UTC, datetime
from stix2 import Identity, MarkingDefinition, Bundle, Relationship

logger = logging.getLogger(__name__)

NAMESPACE_UUID = uuid.UUID("a1cb37d2-3bd3-5b23-8526-47a22694b7e0")
FEEDS2STIX_IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"
FEEDS2STIX_MARKING_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json"


def generate_uuid5(name, namespace=NAMESPACE_UUID):
    """Generate UUIDv5 from namespace and name"""
    if isinstance(namespace, str):
        _, _, namespace_uuid = namespace.rpartition("--")
        namespace = uuid.UUID(namespace_uuid)
    return str(uuid.uuid5(namespace, name))


def fetch_external_objects():
    """Fetch external STIX identity and marking definition objects"""
    logger.info("Fetching external STIX objects...")

    identity_response = requests.get(FEEDS2STIX_IDENTITY_URL)
    identity_response.raise_for_status()
    feeds2stix_identity = identity_response.json()

    marking_response = requests.get(FEEDS2STIX_MARKING_URL)
    marking_response.raise_for_status()
    feeds2stix_marking = marking_response.json()

    return feeds2stix_identity, feeds2stix_marking


def create_identity_object(name, description, identity_class, contact_info):
    """
    Create a standardized STIX Identity object.

    Args:
        name: Name of the identity
        description: Description of the identity
        identity_class: Identity class (e.g., 'system', 'organization')
        contact_info: Contact information URL or string

    Returns:
        Identity object
    """
    identity_id = generate_uuid5(name)

    identity = Identity(
        id=f"identity--{identity_id}",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        created="2020-01-01T00:00:00.000Z",
        modified="2020-01-01T00:00:00.000Z",
        name=name,
        description=description,
        identity_class=identity_class,
        contact_information=contact_info,
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    )

    return identity


def create_marking_definition_object(statement):
    """
    Create a standardized STIX Marking Definition object.

    Args:
        statement: The statement to include in the marking definition (typically origin URL)

    Returns:
        MarkingDefinition object
    """
    marking_id = generate_uuid5(statement)

    marking = MarkingDefinition(
        id=f"marking-definition--{marking_id}",
        created_by_ref="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        created="2020-01-01T00:00:00.000Z",
        definition_type="statement",
        definition={"statement": statement},
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        ],
    )

    return marking


def create_bundle_with_metadata(
    stix_objects,
    source_identity,
    source_marking,
    feeds2stix_identity,
    feeds2stix_marking,
):
    """
    Create a STIX bundle with metadata objects and content objects.

    Args:
        stix_objects: List of STIX objects (indicators, observables, etc.)
        source_identity: Identity object for the feed source
        source_marking: Marking definition object for the feed source
        feeds2stix_identity: feeds2stix identity object
        feeds2stix_marking: feeds2stix marking definition object

    Returns:
        Bundle object
    """
    all_objects = [
        feeds2stix_identity,
        feeds2stix_marking,
        source_identity,
        source_marking,
    ] + stix_objects

    bundle = Bundle(objects=all_objects)
    return bundle


def save_bundle_to_file(bundle, output_dir, filename, add_timestamp=True):
    """
    Save a STIX bundle to a timestamped JSON file.

    Args:
        bundle: Bundle object to save
        output_dir: Directory to save the bundle in
        prefix: Filename prefix (e.g., 'cinsscore', 'ipsum', 'vxvault')
        add_timestamp: Whether to add a timestamp to the filename

    Returns:
        Filepath of saved bundle
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d")
    if add_timestamp:
        filename = f"{filename}_{timestamp}"
    filename = filename + ".json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        f.write(bundle.serialize(indent=4))

    logger.info(f"Bundle saved to: {filepath}")
    return filepath


def setup_output_directory(base_dir, clean=True):
    """
    Setup output directory for bundles, optionally cleaning existing content.

    Args:
        base_dir: Base directory path
        clean: Whether to remove existing directory contents

    Returns:
        Path to the bundles output directory
    """
    output_dir = os.path.join(base_dir, "bundles")

    if clean and os.path.exists(output_dir):
        logger.info(f"Cleaning output directory: {output_dir}")
        shutil.rmtree(output_dir)

    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def make_relationship(
    source_ref,
    target_ref,
    relationship_type,
    created_by_ref,
    marking_refs,
    created=None,
    modified=None,
):
    """Helper function to create a relationship object"""
    relationship_id = generate_uuid5(
        f"{source_ref}+{target_ref}", namespace=marking_refs[-1]
    )

    relationship = Relationship(
        type="relationship",
        id="relationship--" + relationship_id,
        created_by_ref=created_by_ref,
        created=created,
        modified=modified or created,
        relationship_type=relationship_type,
        source_ref=source_ref,
        target_ref=target_ref,
        object_marking_refs=marking_refs,
    )

    return relationship
