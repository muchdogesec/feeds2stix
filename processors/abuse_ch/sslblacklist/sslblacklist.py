import csv
import os
import requests
import uuid
import shutil
import hashlib
import logging
from stix2 import File, Indicator, Malware, Relationship, Bundle, parse
from stix2.datastore.filesystem import FileSystemStore
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# URLs for external STIX objects
marking_definition_url = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json"
identity_url = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"
csv_url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"

# Load external STIX objects
marking_definition = parse(requests.get(marking_definition_url).json())
identity = parse(requests.get(identity_url).json())

# Create base directory structure
base_output_dir = "bundles/abuse_ch/sslblacklist"
bundle_output_dir = os.path.join(base_output_dir, "bundles")
stix_objects_dir = os.path.join(base_output_dir, "stix2_objects")

# Ensure clean directories: Delete output_dir to start fresh on each run
if os.path.exists(base_output_dir):
    logger.info(f"Deleting existing directory: {base_output_dir}")
    shutil.rmtree(base_output_dir)

# Create the necessary directories
os.makedirs(bundle_output_dir, exist_ok=True)
os.makedirs(stix_objects_dir, exist_ok=True)

# Create subdirectories for each STIX object type
for stix_type in ['indicator', 'relationship', 'file', 'marking-definition', 'identity']:
    os.makedirs(os.path.join(stix_objects_dir, stix_type), exist_ok=True)

# Initialize the filesystem store
store = FileSystemStore(stix_objects_dir)

# Use a predefined namespace UUID for generating UUIDv5
namespace_uuid = uuid.UUID('a1cb37d2-3bd3-5b23-8526-47a22694b7e0')  # marking definition uuid for feed

# Function to generate UUIDv5
def generate_uuid(namespace, name):
    return str(uuid.uuid5(namespace, name))

# Function to generate bundle ID based on sorted objects
def generate_bundle_id(namespace, objects):
    md5 = hashlib.md5()
    for obj in sorted(objects, key=lambda x: x['id']):
        md5.update(obj['id'].encode('utf-8'))
    return generate_uuid(namespace, md5.hexdigest())

# Save the imported STIX objects to the filesystem store
logger.info("Saving external STIX objects (marking definition and identity) to the filesystem store.")
store.add(marking_definition)
store.add(identity)

# Download and parse the CSV data
logger.info("Downloading and parsing CSV data.")
response = requests.get(csv_url)
response.raise_for_status()
lines = response.text.splitlines()

# Extract the last update date from the header
last_update_date = None
for line in lines:
    if line.startswith('# Last updated:'):
        last_update_date = line.split('# Last updated: ')[1].split(' UTC')[0]
        break

if not last_update_date:
    raise ValueError("Last update date not found in the header.")
logger.info(f"Last update date: {last_update_date}")

# Find the header line
header_index = 0
for i, line in enumerate(lines):
    if line.startswith('# Listingdate'):
        header_index = i
        break

# Adjust the header line to remove the '#'
lines[header_index] = lines[header_index][1:].strip()

reader = csv.DictReader(lines[header_index:])  # Use the corrected header line

# Print headers to diagnose KeyError
logger.info(f"CSV Headers: {reader.fieldnames}")

# Parse CSV and create STIX objects
file_objects = {}
malware_mapping = {}

# Function to clean listing reasons
def clean_listing_reason(reason):
    if reason is None:
        return "Unknown"
    
    reason = reason.replace(" malware distribution", "")
    reason = reason.replace("Malware distribution", "Malware")
    reason = reason.replace("Cobalt C&C", "CobaltStrike C&C")
    reason = reason.replace(" C&C", "")
    return reason

# Step 1: Create File objects and map listing_reason to file objects
logger.info("Creating File objects and mapping listing reasons.")
for row in reader:
    listing_date = row['Listingdate']
    sha1 = row['SHA1']
    listing_reason = clean_listing_reason(row['Listingreason'])
    
    # Skip rows that don't match the date format (e.g., the last row)
    try:
        listing_date_dt = datetime.strptime(listing_date, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        continue

    listing_date_stix = listing_date_dt.isoformat() + "Z"
    
    # Create File object
    file_obj = File(
        hashes={"SHA-1": sha1}
    )
    file_objects[sha1] = {
        "file": file_obj,
        "listing_date": listing_date_stix
    }

    # Save File object using FileSystemStore
    store.add(file_obj)

    # Map listing_reason to file objects
    if listing_reason not in malware_mapping:
        malware_mapping[listing_reason] = {
            "files": [],
            "dates": [],
            "stix_objects": []
        }
    malware_mapping[listing_reason]["files"].append(file_obj)
    malware_mapping[listing_reason]["dates"].append(listing_date_dt)
    malware_mapping[listing_reason]["stix_objects"].append(file_obj)

# Step 2: Create Malware, Indicator, and Relationship objects for each listing_reason and generate bundles
logger.info("Creating Malware, Indicator, and Relationship objects.")
for listing_reason, data in malware_mapping.items():
    stix_objects = [
        marking_definition,
        identity
    ]
    stix_objects.extend(data["stix_objects"])
    file_refs = [file.id for file in data["files"]]
    earliest_date = min(data["dates"])
    latest_date = max(data["dates"])

    malware_obj = Malware(
        id="malware--" + generate_uuid(namespace_uuid, listing_reason),
        created_by_ref=identity.id,
        created=earliest_date.isoformat() + "Z",
        modified=latest_date.isoformat() + "Z",
        name=listing_reason,
        malware_types=["remote-access-trojan"],
        is_family=True,
        sample_refs=file_refs,
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            marking_definition.id
        ]
    )
    stix_objects.append(malware_obj)

    # Save Malware object using FileSystemStore
    store.add(malware_obj)

    # Generate the pattern in chunks to avoid recursion depth issues
    pattern_parts = []
    chunk_size = 50  # Adjust the chunk size as needed
    for i in range(0, len(data["files"]), chunk_size):
        chunk = data["files"][i:i + chunk_size]
        chunk_pattern = ' OR '.join([f"[ file:hashes.'SHA-1' = '{file.hashes['SHA-1']}' ]" for file in chunk])
        pattern_parts.append(f"({chunk_pattern})")

    pattern = ' OR '.join(pattern_parts)

    indicator_obj = Indicator(
        id=malware_obj.id.replace("malware", "indicator"),
        created_by_ref=identity.id,
        created=earliest_date.isoformat() + "Z",
        modified=latest_date.isoformat() + "Z",
        indicator_types=["malicious-activity"],
        name=listing_reason,
        pattern=pattern,
        pattern_type="stix",
        valid_from=earliest_date.isoformat() + "Z",
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            marking_definition.id
        ]
    )
    stix_objects.append(indicator_obj)

    # Save Indicator object using FileSystemStore
    store.add(indicator_obj)

    # Create Relationships between Indicator and Malware
    malware_relationship_id = generate_uuid(namespace_uuid, f"{indicator_obj.id}+{malware_obj.id}")
    malware_relationship_obj = Relationship(
        id="relationship--" + malware_relationship_id,
        created=indicator_obj.created,
        modified=indicator_obj.modified,
        created_by_ref=identity.id,
        relationship_type="detects",
        source_ref=indicator_obj.id,
        target_ref=malware_obj.id,
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            marking_definition.id
        ]
    )
    stix_objects.append(malware_relationship_obj)

    # Save Malware-Indicator Relationship using FileSystemStore
    store.add(malware_relationship_obj)

    # Create Relationships between Indicator and each File
    for file_obj in data["files"]:
        listing_date = file_objects[file_obj.hashes['SHA-1']]['listing_date']
        file_relationship_id = generate_uuid(namespace_uuid, f"{indicator_obj.id}+{file_obj.id}")
        file_relationship_obj = Relationship(
            id="relationship--" + file_relationship_id,
            created=listing_date,
            modified=listing_date,
            created_by_ref=identity.id,
            relationship_type="pattern-contains",
            source_ref=indicator_obj.id,
            target_ref=file_obj.id,
            object_marking_refs=[
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                marking_definition.id
            ]
        )
        stix_objects.append(file_relationship_obj)

        # Save Indicator-File Relationship using FileSystemStore
        store.add(file_relationship_obj)

    # Create and save the bundle for this listing_reason
    bundle_id = generate_bundle_id(namespace_uuid, stix_objects)
    bundle = Bundle(
        id="bundle--" + bundle_id,
        objects=stix_objects
    )

    # Save the bundle to a file
    name = listing_reason.replace('.', '_').replace('-', '_').replace(' ', '_').lower()
    bundle_path = os.path.join(bundle_output_dir, f"{name}.json")
    logger.info(f"Saving the bundle to {bundle_path}.")
    with open(bundle_path, 'w') as bundle_file:
        serialized_bundle = bundle.serialize(pretty=True)
        bundle_file.write(serialized_bundle)
        logger.info(f"Finished writing the bundle to {bundle_path}.")

logger.info(f"All STIX bundles and objects have been saved in the directory: {base_output_dir}")
