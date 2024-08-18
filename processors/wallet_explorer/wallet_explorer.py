import os
import uuid
import gdown
import shutil
import hashlib
import requests
import json
import stix2
import pandas as pd
import time
import argparse
from stix2extensions.cryptocurrency_wallet import CryptocurrencyWallet

# Constants and Configuration
GOOGLE_SHEET_URL = "https://docs.google.com/spreadsheets/d/1hF76TV48LLjmgZ80aFl5CpWWn4geQkQM50EUcYqAQyY/export?format=csv"
DOWNLOAD_ID = "1hF76TV48LLjmgZ80aFl5CpWWn4geQkQM50EUcYqAQyY"
OUTPUT_DIR = "bundles/wallet_explorer/"
STIX_OBJECTS_DIR = "bundles/wallet_explorer/stix2_objects"
TMP_DIR = "bundles/wallet_explorer/tmp_object_store"
OASIS_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7") # oasis namespace
NAMESPACE = uuid.UUID("a1cb37d2-3bd3-5b23-8526-47a22694b7e0") # this is feed2stix uuidv4
WALLET_API = "https://www.walletexplorer.com/api/1/wallet-addresses"
MARKING_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json"
IDENTITY_OBJECT_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"
TLP_CLEAR = "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
INITIAL_DELAY = 1  # Initial delay between requests in seconds
MAX_BACKOFF_TIME = 60  # Maximum backoff time in seconds
LOCATION_LOOKUP_FILE = 'processors/wallet_explorer/lookups/locations-bundle.json'  # Path to the location lookup file

# Ensure TMP_DIR, OUTPUT_DIR, and STIX_OBJECTS_DIR exist
def ensure_directories_exist():
    for directory in [TMP_DIR, OUTPUT_DIR, STIX_OBJECTS_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)

# Delete the bundles directory at the start of the script
def clean_output_directory():
    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR)
    print(f"Cleaned up the {OUTPUT_DIR} directory.")

# Download the Google Sheet as a CSV file using gdown
def download_spreadsheet():
    print("Downloading the spreadsheet...")
    if not os.path.exists(TMP_DIR):
        os.makedirs(TMP_DIR)
    csv_url = f"https://docs.google.com/spreadsheets/d/{DOWNLOAD_ID}/export?format=csv"
    gdown.download(url=csv_url, output=f"{TMP_DIR}/wallet_explorer_sheet.csv", quiet=False)
    print("Download complete.")

# Fetch the Marking Definition and Identity Objects
def fetch_stix_objects():
    print("Fetching STIX objects (marking definition and identity)...")
    marking_definition_response = requests.get(MARKING_DEFINITION_URL)
    identity_object_response = requests.get(IDENTITY_OBJECT_URL)
    
    if marking_definition_response.status_code == 200 and identity_object_response.status_code == 200:
        marking_definition = stix2.parse(marking_definition_response.json())
        identity_object = stix2.parse(identity_object_response.json())
        return marking_definition, identity_object
    else:
        raise Exception(f"Failed to download STIX objects. Marking Definition HTTP Status: {marking_definition_response.status_code}, Identity Object HTTP Status: {identity_object_response.status_code}")

# Store each STIX object in the filesystem, organized by type
def store_stix_object(stix_object):
    object_type = stix_object['type']
    type_dir = os.path.join(STIX_OBJECTS_DIR, object_type)
    if not os.path.exists(type_dir):
        os.makedirs(type_dir)
    
    object_id = stix_object.id.replace(":", "_")
    filename = f"{object_id}.json"
    filepath = os.path.join(type_dir, filename)
    
    # Serialize the STIX object using the STIX2 library's serialize() method
    with open(filepath, "w") as f:
        f.write(stix_object.serialize(pretty=True))
    
    print(f"Stored STIX object {object_id} at {filepath}")

# Collect all STIX objects by type and create bundles
def create_stix_bundles():
    stix_objects = []

    # Traverse the directories in stix2_objects and collect all STIX objects
    for root, _, files in os.walk(STIX_OBJECTS_DIR):
        for filename in files:
            if filename.endswith(".json"):
                filepath = os.path.join(root, filename)
                with open(filepath, "r") as f:
                    stix_object = json.load(f)
                    stix_objects.append(stix2.parse(stix_object))

    # Generate the bundle ID using the serialized objects
    bundle_id = f"bundle--{uuid.uuid5(NAMESPACE, hashlib.md5(json.dumps([obj.serialize() for obj in stix_objects], sort_keys=True).encode()).hexdigest())}"
    
    # Create the STIX bundle
    bundle = stix2.Bundle(
        type="bundle",
        id=bundle_id,
        objects=stix_objects  # Directly use the original STIX objects here
    )
    
    # Write the bundle to a file
    bundle_filename = "wallet_explorer_bundle.json"
    bundle_filepath = os.path.join(OUTPUT_DIR, bundle_filename)
    with open(bundle_filepath, "w") as file:
        file.write(bundle.serialize(pretty=True))
    print(f"STIX bundle created and saved to {bundle_filepath}")

# Parse the CSV file and process exchanges into STIX objects
def process_exchanges(record_urls=None, process_wallets=False):
    print("Processing exchanges from the CSV file...")
    marking_definition, identity_object = fetch_stix_objects()

    # Read the CSV file using pandas
    df = pd.read_csv(f"{TMP_DIR}/wallet_explorer_sheet.csv")

    # Filter exchanges if --record_url is provided
    if record_urls:
        df = df[df['record_url'].isin(record_urls)]

    # Assuming the columns are: record_id, record_name, record_description, record_url, record_country
    for index, row in df.iterrows():
        record_id = row['record_id']
        record_name = row['record_name']
        record_url = row['record_url']
        record_description = row['record_description']
        record_country = row['record_country']
        record_is_active = row['record_is_active']
        record_type = row['record_type']

        print(f"Creating STIX Identity object for exchange: {record_name}")

        identity_id = f"identity--{uuid.uuid5(NAMESPACE, record_name)}"
        created_date = stix2.utils.STIXdatetime.now()

        # Create Identity object for the exchange
        identity = stix2.Identity(
            type="identity",
            spec_version="2.1",
            id=identity_id,
            created_by_ref=identity_object.id,
            created=created_date,
            modified=created_date,
            name=record_name,
            description=record_description,
            sectors=["financial-services", "technology"],
            identity_class="organization",
            contact_information=record_url,
            object_marking_refs=[
                marking_definition.id,
                TLP_CLEAR
            ],
            external_references=[
                {
                    "source_name": "feeds2stix-id",
                    "external_id": record_id

                },
                {
                    "source_name": "feeds2stix-type",
                    "external_id": record_type

                },
                {
                    "source_name": "feeds2stix-is-active",
                    "external_id": record_is_active

                }
            ]
        )

        # Store STIX objects
        store_stix_object(marking_definition)
        store_stix_object(identity_object)
        store_stix_object(identity)

        # Fetch wallets using WalletExplorer API if process_wallets is True
        if process_wallets:
            fetch_wallets(record_url, identity_id)

        # Create Location and Relationship objects
        if record_country and record_country != "Unknown":
            create_location_and_relationship(identity, record_country, marking_definition, identity_object)

    print("Finished processing exchanges.")

# Fetch wallets from WalletExplorer and create STIX objects
def fetch_wallets(record_url, identity_id):
    from_offset = 0
    delay = INITIAL_DELAY
    print(f"Fetching wallets for exchange: {record_url}")

    while True:
        response = requests.get(f"{WALLET_API}?wallet={record_url}&from={from_offset}&count=100&caller=https://github.com/muchdogesec/feeds2stix")

        # Check if the response was successful
        if response.status_code == 200:
            wallet_data = response.json()

            # Check if the 'addresses' key is present in the response
            if 'addresses' not in wallet_data:
                print(f"No addresses found for {record_url}. Response: {wallet_data}")
                break

            if not wallet_data['addresses']:
                print(f"No more addresses to fetch for {record_url}.")
                break

            print(f"Found {len(wallet_data['addresses'])} addresses for {record_url}.")

            for address in wallet_data['addresses']:
                wallet = CryptocurrencyWallet(
                    id=f"cryptocurrency-wallet--{str(uuid.uuid5(OASIS_NAMESPACE, address['address']))}",
                    address=address['address'],
                    exchange_ref=identity_id,  # Reference the exchange identity here
                    extensions={
                        "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
                            "extension_type": "new-sco"
                        }
                    }
                )
                store_stix_object(wallet)

            from_offset += 100
            print(f"Fetching next batch of addresses starting from {from_offset}...")
            delay = INITIAL_DELAY  # Reset delay after a successful request
        else:
            print(f"Failed to fetch wallets for {record_url}. HTTP Status: {response.status_code}")
            if response.status_code == 429:  # HTTP 429 Too Many Requests
                delay = min(delay * 2, MAX_BACKOFF_TIME)  # Exponential backoff
                print(f"Rate limit exceeded. Backing off for {delay} seconds.")
            else:
                break

        time.sleep(delay)

# Create Location and Relationship STIX objects
def create_location_and_relationship(identity, record_country, marking_definition, identity_object):
    print(f"Linking exchange {identity.name} with location {record_country}")
    location_lookup = load_location_data()
    location_obj = next((loc for loc in location_lookup['objects'] if loc.get('country') == record_country), None)

    if location_obj:
        # Use the location object directly from the lookup file
        location = stix2.parse(location_obj)
        store_stix_object(location)

        # Generate the UUID for the relationship using the specified format
        relationship_id = f"relationship--{uuid.uuid5(NAMESPACE, f'located-in+{identity.id}+{location.id}')}"
        
        # Create the relationship object
        relationship = stix2.Relationship(
            type="relationship",
            spec_version="2.1",
            id=relationship_id,
            created_by_ref=identity_object.id,
            created=identity.created,
            modified=identity.modified,
            relationship_type="located-in",
            source_ref=identity.id,
            target_ref=location.id,
            object_marking_refs=[
                marking_definition.id,
                TLP_CLEAR
            ]
        )
        store_stix_object(relationship)
        print(f"Created relationship object between {identity.name} and {location.name}.")
    else:
        print(f"Location not found for country code {record_country}.")

# Load location data from the JSON file
def load_location_data():
    print("Loading location data...")
    with open(LOCATION_LOOKUP_FILE, 'r') as file:
        return json.load(file)

# Print the directory structure of stix2_objects
def print_directory_structure(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        print(f"{indent}{os.path.basename(root)}/")
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print(f"{subindent}{f}")

# Main function to run the script
def main():
    parser = argparse.ArgumentParser(description='Wallet Explorer STIX Generator')
    parser.add_argument('--record_url', type=str, help='Comma-separated list of exchange URLs to process')
    parser.add_argument('--process_wallets', action='store_true', help='Process wallets for each exchange if true')
    args = parser.parse_args()

    ensure_directories_exist()  # Ensure TMP_DIR, OUTPUT_DIR, and STIX_OBJECTS_DIR exist
    clean_output_directory()  # Deletes and recreates OUTPUT_DIR
    
    download_spreadsheet()  # Download the spreadsheet after ensuring directories exist

    record_urls = args.record_url.split(',') if args.record_url else None
    process_exchanges(record_urls, process_wallets=args.process_wallets)
    
    # Create the final STIX bundle with all objects
    create_stix_bundles()

    # Print the structure of the stix2_objects directory
    print("Directory structure of stix2_objects:")
    print_directory_structure(STIX_OBJECTS_DIR)

    # Clean up TMP_DIR
    shutil.rmtree(TMP_DIR)
    print("Temporary files cleaned up. Process complete.")

if __name__ == "__main__":
    main()
