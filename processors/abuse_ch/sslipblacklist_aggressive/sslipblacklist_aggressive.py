import csv
import os
import requests
import uuid
import shutil
import hashlib
import logging
from stix2 import IPv4Address, NetworkTraffic, Indicator, Relationship, Bundle, parse
from stix2.datastore.filesystem import FileSystemStore
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# URLs for external STIX objects
marking_definition_url = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json"
identity_url = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"
csv_url = "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"

# Load external STIX objects
marking_definition = parse(requests.get(marking_definition_url).json())
identity = parse(requests.get(identity_url).json())

# Additional marking definition
extra_marking_definition = {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--387824ed-ce3e-43b2-9be7-b121b2b917d9",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "2020-01-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {
        "statement": "Origin data source: https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"
    },
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ]
}

# Create a filesystem store
output_dir = "bundles/abuse_ch/sslipblacklist_aggressive"
if os.path.exists(output_dir):
    shutil.rmtree(output_dir)
os.makedirs(output_dir)

store = FileSystemStore(output_dir)

# Use a predefined namespace UUID for generating UUIDv5
namespace_uuid = uuid.UUID('387824ed-ce3e-43b2-9be7-b121b2b917d9')  # marking definition uuid for feed

# Function to generate UUIDv5
def generate_uuid(namespace, name):
    return str(uuid.uuid5(namespace, name))

# Function to generate bundle ID based on sorted objects
def generate_bundle_id(namespace, objects):
    md5 = hashlib.md5()
    for obj in sorted(objects, key=lambda x: x['id']):
        md5.update(obj['id'].encode('utf-8'))
    return generate_uuid(namespace, md5.hexdigest())

# Function to determine protocols based on port
def determine_protocols(port):
    if port == '80':
        return ['http', 'tcp']
    elif port == '443':
        return ['ssl', 'tcp']
    else:
        return ['tcp']

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
    if line.startswith('# Firstseen'):
        header_index = i
        break

# Adjust the header line to remove the '#'
lines[header_index] = lines[header_index][1:].strip()

reader = csv.DictReader(lines[header_index:])  # Use the corrected header line

# Print headers to diagnose KeyError
logger.info(f"CSV Headers: {reader.fieldnames}")

# Parse CSV and create STIX objects
ipv4_objects = {}
network_traffic_objects = {}
indicator_mapping = {}

# Step 1: Create IPv4Address and NetworkTraffic objects and map them
logger.info("Creating IPv4Address and NetworkTraffic objects and mapping them.")
for row in reader:
    first_seen = row['Firstseen']
    dst_ip = row['DstIP']
    dst_port = row['DstPort']
    
    # Skip rows that don't match the date format (e.g., the last row)
    try:
        first_seen_dt = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        continue

    first_seen_stix = first_seen_dt.isoformat() + "Z"

    # Create IPv4Address object
    ipv4_obj = IPv4Address(
        value=dst_ip
    )
    ipv4_objects[dst_ip] = ipv4_obj

    # Determine protocols based on port
    protocols = determine_protocols(dst_port)

    # Create NetworkTraffic object
    network_traffic_obj = NetworkTraffic(
        dst_ref=ipv4_obj.id,
        dst_port=int(dst_port),
        protocols=protocols
    )
    network_traffic_objects[(dst_ip, dst_port)] = network_traffic_obj

    # Map indicators
    if dst_ip not in indicator_mapping:
        indicator_mapping[dst_ip] = {
            "ports": [],
            "dates": [],
            "stix_objects": []
        }
    indicator_mapping[dst_ip]["ports"].append(dst_port)
    indicator_mapping[dst_ip]["dates"].append(first_seen_dt)
    indicator_mapping[dst_ip]["stix_objects"].extend([ipv4_obj, network_traffic_obj])

# Step 2: Create Indicator and Relationship objects for each IP and generate bundles
logger.info("Creating Indicator and Relationship objects.")
bundles = {}
for dst_ip, data in indicator_mapping.items():
    stix_objects = data["stix_objects"]
    earliest_date = min(data["dates"])
    latest_date = max(data["dates"])

    pattern_parts = []
    for port in data["ports"]:
        pattern_parts.append(f"[ipv4-addr:value = '{dst_ip}' AND network-traffic:dst_port = '{port}']")
    pattern = ' OR '.join(pattern_parts)

    indicator_name = f"C&C Botnet: {dst_ip}"
    indicator_id = generate_uuid(namespace_uuid, indicator_name)

    indicator_obj = Indicator(
        id="indicator--" + indicator_id,
        created_by_ref=identity.id,
        created=earliest_date.isoformat() + "Z",
        modified=latest_date.isoformat() + "Z",
        indicator_types=["malicious-activity"],
        name=indicator_name,
        pattern=pattern,
        pattern_type="stix",
        valid_from=earliest_date.isoformat() + "Z",
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--387824ed-ce3e-43b2-9be7-b121b2b917d9",
            "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
        ]
    )
    stix_objects.append(indicator_obj)

    relationship_obj = Relationship(
        id="relationship--" + indicator_id,
        created=indicator_obj.created,
        modified=indicator_obj.modified,
        relationship_type="detects",
        source_ref=indicator_obj.id,
        target_ref=ipv4_objects[dst_ip].id,
        object_marking_refs=[
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--387824ed-ce3e-43b2-9be7-b121b2b917d9",
            "marking-definition--418465b1-2dbe-41b7-b994-19817164e793"
        ]
    )
    stix_objects.append(relationship_obj)

    year = latest_date.year
    if year not in bundles:
        bundles[year] = [
            marking_definition,
            identity,
            extra_marking_definition
        ]
    bundles[year].extend(stix_objects)

# Create and save bundles per year
for year, stix_objects in bundles.items():
    unique_stix_objects = {obj['id']: obj for obj in stix_objects}.values()
    bundle_id = generate_bundle_id(namespace_uuid, unique_stix_objects)
    bundle = Bundle(
        id="bundle--" + bundle_id,
        objects=list(unique_stix_objects)
    )

    bundle_path = os.path.join(output_dir, f"{year}.json")
    logger.info(f"Saving the bundle to {bundle_path}.")
    with open(bundle_path, 'w') as bundle_file:
        serialized_bundle = bundle.serialize(pretty=True)
        bundle_file.write(serialized_bundle)
        logger.info(f"Finished writing the bundle to {bundle_path}.")

logger.info(f"All STIX bundles have been saved in the directory: {output_dir}")
