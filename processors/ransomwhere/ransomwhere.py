import os
import shutil
import requests
import uuid
import json
import logging
from datetime import datetime
from stix2 import (
    FileSystemStore,
    MarkingDefinition,
    Bundle,
    Relationship,
    CustomObservable,
    properties,
    Malware,
    ExtensionDefinition,
    Identity,
    Indicator,
)

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
RANSOMWHERE_API_URL = "https://api.ransomwhe.re/export"
# output directory
STIX_DIRECTORY = "bundles/ransomwhere/"
BUNDLE_FILE = os.path.join(STIX_DIRECTORY, "ransomwhere-bundle.json")
# Use a predefined namespace UUID for generating UUIDv5
NAMESPACE_UUID = uuid.UUID("51fe4ca9-320b-4ea8-9d3c-1f46383a5144")  # marking def id, used to generate sdos/sros
OASIS_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7") # used to generate scos
# URLs for external objects
EXTERNAL_OBJECTS_URLS = {
    "cryptocurrency_transaction_extension": "https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/scos/cryptocurrency-transaction.json",
    "cryptocurrency_wallet_extension": "https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/scos/cryptocurrency-wallet.json",
    "feeds2stix_identity": "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json",
    "feeds2stix_marking_definition": "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"
}

# Additional marking definition
extra_marking_definition = MarkingDefinition(
    type="marking-definition",
    spec_version="2.1",
    id="marking-definition--51fe4ca9-320b-4ea8-9d3c-1f46383a5144",
    created_by_ref="identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    created="2020-01-01T00:00:00.000Z",
    definition_type="statement",
    definition={
        "statement": "Origin data source: https://api.ransomwhe.re/export"
    },
    object_marking_refs=[
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ]
)

# Mapping of ransomware to ATT&CK details
attack_mapping = {
    "SynAck": {"attack_stix_id": "malware--04227b24-7817-4de1-9050-b7b1b57f5866", "attack_id": "S0242"},
    "WannaCry": {"attack_stix_id": "malware--75ecdbf1-c2bb-4afc-a3f9-c8da4de8c661", "attack_id": "S0366"},
    "NotPetya": {"attack_stix_id": "malware--5719af9d-6b16-46f9-9b28-fb019541ddbb", "attack_id": "S0368"},
    "SamSam": {"attack_stix_id": "malware--4d56e6e9-1a6d-46e3-896c-dfdf3cc96e62", "attack_id": "S0370"},
    "Ryuk": {"attack_stix_id": "malware--a020a61c-423f-4195-8c46-ba1d21abba37", "attack_id": "S0446"},
    "Netwalker (Mailto)": {"attack_stix_id": "malware--754effde-613c-4244-a83e-fb659b2a4d06", "attack_id": "S0457"},
    "REvil / Sodinokibi": {"attack_stix_id": "malware--ac61f1f9-7bb1-465e-9b8a-c2ce8e88baf5", "attack_id": "S0496"},
    "Egregor": {"attack_stix_id": "malware--cc4c1287-9c86-4447-810c-744f3880ec37", "attack_id": "S0554"},
    "Conti": {"attack_stix_id": "malware--4dea7d8e-af94-4bfb-afe4-7ff54f59308b", "attack_id": "S0575"},
    "HelloKitty": {"attack_stix_id": "malware--5d11d418-95dd-4377-b782-23160dfa17b4", "attack_id": "S0617"},
    "Cuba": {"attack_stix_id": "malware--6cd07296-14aa-403d-9229-6343d03d4752", "attack_id": "S0625"},
    "Avaddon": {"attack_stix_id": "malware--58c5a3a1-928f-4094-9e98-a5a4e56dd5f3", "attack_id": "S0640"},
    "AvosLocker": {"attack_stix_id": "malware--0945a1a5-a79a-47c8-9079-10c16cdfcb5d", "attack_id": "S1053"},
    "BlackCat": {"attack_stix_id": "malware--50c44c34-3abb-48ae-9433-a2337de5b0bc", "attack_id": "S1068"},
    "Black Basta": {"attack_stix_id": "malware--8d242fb4-9033-4f13-8a88-4b9b4bcd9a53", "attack_id": "S1070"},
    "Akira": {"attack_stix_id": "malware--6f6b2353-4b39-40ce-9d6d-d00b7a61e656", "attack_id": "S1129"}
}

# Custom STIX objects
@CustomObservable('cryptocurrency-wallet', [
    ('address', properties.StringProperty(required=True)),
])
class CryptocurrencyWallet:
    pass

@CustomObservable('cryptocurrency-transaction', [
    ('symbol', properties.StringProperty(required=True)),
    ('hash', properties.StringProperty(required=True)),
    ('execution_time', properties.TimestampProperty(required=True)),
    ('output', properties.ListProperty(properties.DictionaryProperty, required=True)),
])
class CryptocurrencyTransaction:
    pass

# Helper functions
def convert_epoch_to_datetime(epoch_time):
    return datetime.utcfromtimestamp(epoch_time).strftime('%Y-%m-%dT%H:%M:%SZ')

def generate_stix_id(object_type, name_or_hash):
    return f"{object_type}--{str(uuid.uuid5(OASIS_NAMESPACE, name_or_hash))}"

def generate_relationship_id(source_ref, target_ref):
    return f"relationship--{str(uuid.uuid5(NAMESPACE_UUID, source_ref + '+' + target_ref))}"

def generate_malware_id(name):
    return f"malware--{str(uuid.uuid5(NAMESPACE_UUID, name))}"

def get_marking_definition():
    return MarkingDefinition(
        id="marking-definition--27557362-b745-4161-96e8-ccd62ce4cb26",
        created_by_ref="identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        created="2022-01-01T00:00:00.000Z",
        definition_type="statement",
        definition={"statement": "Cable, Jack. (2022). Ransomwhere: A Crowdsourced Ransomware Payment Dataset (1.0.0) [Data set]. Zenodo. https://doi.org/10.5281/zenodo.6512123"},
        object_marking_refs=[
            "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
        ]
    )

def get_wallet_object(address):
    return CryptocurrencyWallet(
        id=generate_stix_id("cryptocurrency-wallet", address),
        address=address,
        extensions={
            "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
                "extension_type": "new-sco"
            }
        }
    )

def get_transaction_object(transaction_hash, transactions, blockchain):
    outputs = [{"address_ref": tx['wallet_id'], "amount": tx['amount'] / 100000000} for tx in transactions]  # Adjust the amount
    return CryptocurrencyTransaction(
        id=generate_stix_id("cryptocurrency-transaction", transaction_hash),
        symbol="BTC" if blockchain.lower() == "bitcoin" else blockchain,
        hash=transaction_hash,
        execution_time=convert_epoch_to_datetime(transactions[0]['time']),
        output=outputs,
        extensions={
            "extension-definition--151d042d-4dcf-5e44-843f-1024440318e5": {
                "extension_type": "new-sco"
            }
        }
    )

def get_malware_object(family, earliest_transaction_time):
    external_references = []
    if family in attack_mapping:
        attack_info = attack_mapping[family]
        external_references.append({
            "source_name": "mitre-attack",
            "url": f"https://attack.mitre.org/software/{attack_info['attack_id']}",
            "external_id": attack_info["attack_id"]
        })
    return Malware(
        id=generate_malware_id(family),
        created_by_ref="identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        created=convert_epoch_to_datetime(earliest_transaction_time),
        modified=convert_epoch_to_datetime(earliest_transaction_time),
        name=family,
        malware_types=["ransomware"],
        is_family=True,
        object_marking_refs=[
            "marking-definition--904ac99b-7539-5de7-9ffa-23186f0e07b6",
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--51fe4ca9-320b-4ea8-9d3c-1f46383a5144"
        ],
        external_references=external_references if external_references else None
    )

def get_indicator_object(malware_obj, wallet_addresses):
    max_chunk_size = 100  # Adjust this size if necessary
    patterns = []
    for i in range(0, len(wallet_addresses), max_chunk_size):
        chunk = wallet_addresses[i:i + max_chunk_size]
        pattern = " OR ".join([f"cryptocurrency-wallet:address = '{address}'" for address in chunk])
        patterns.append(f"[{pattern}]")
    complete_pattern = " OR ".join(patterns)
    logging.debug(f"Generated pattern: {complete_pattern}")
    return Indicator(
        id=f"indicator--{malware_obj.id.split('--')[1]}",
        created_by_ref="identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        created=malware_obj.created,
        modified=malware_obj.modified,
        name=f"{malware_obj.name} Cryptocurrency Wallets",
        description=f"Known Cryptocurrency Wallets associated with {malware_obj.name}",
        indicator_types=["malicious-activity"],
        pattern=complete_pattern,
        pattern_type="stix",
        valid_from=malware_obj.created,
        object_marking_refs=malware_obj.object_marking_refs
    )

def get_indicator_wallet_relationship(indicator_obj, wallet_obj):
    relationship_id = generate_relationship_id(indicator_obj.id, wallet_obj.id)
    return Relationship(
        id=relationship_id,
        created_by_ref="identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        created=indicator_obj.created,
        modified=indicator_obj.modified,
        relationship_type="pattern-contains",
        source_ref=indicator_obj.id,
        target_ref=wallet_obj.id,
        object_marking_refs=indicator_obj.object_marking_refs
    )

def get_indicator_malware_relationship(indicator_obj, malware_obj):
    relationship_id = generate_relationship_id(indicator_obj.id, malware_obj.id)
    return Relationship(
        id=relationship_id,
        created_by_ref="identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        created=malware_obj.created,
        modified=malware_obj.modified,
        relationship_type="indicates",
        source_ref=indicator_obj.id,
        target_ref=malware_obj.id,
        object_marking_refs=indicator_obj.object_marking_refs
    )

def create_stix_object_from_json(json_obj):
    stix_type = json_obj['type']
    if stix_type == 'marking-definition':
        return MarkingDefinition(**json_obj)
    elif stix_type == 'identity':
        return Identity(**json_obj)
    elif stix_type == 'extension-definition':
        return ExtensionDefinition(**json_obj)
    else:
        raise ValueError(f"Unsupported STIX object type: {stix_type}")

def download_and_store_external_objects(urls, existing_ids):
    objects = []
    for name, url in urls.items():
        response = requests.get(url)
        response.raise_for_status()
        obj = response.json()
        stix_obj = create_stix_object_from_json(obj)
        objects.append(stix_obj)
        if stix_obj.id not in existing_ids:
            fs.add(stix_obj)
            existing_ids.add(stix_obj.id)
    return objects

def generate_md5_from_list(stix_objects):
    """Generate an MD5 hash from a list of STIX objects."""
    import hashlib
    md5_hash = hashlib.md5()
    for obj in sorted(stix_objects, key=lambda x: x['id']):
        md5_hash.update(obj['id'].encode('utf-8'))
    return md5_hash.hexdigest()

def store_in_bundle(stix_objects):
    bundle_id = "bundle--" + str(uuid.uuid5(
        NAMESPACE_UUID, generate_md5_from_list(stix_objects))
    )
    bundle_of_all_objects = Bundle(id=bundle_id, objects=stix_objects, allow_custom=True)
    with open(BUNDLE_FILE, "w") as f:
        f.write(json.dumps(json.loads(bundle_of_all_objects.serialize()), indent=4))
    logging.info(f"STIX bundle created successfully at {BUNDLE_FILE}")

# Delete existing STIX directory and create a new one
if os.path.exists(STIX_DIRECTORY):
    shutil.rmtree(STIX_DIRECTORY)
os.makedirs(STIX_DIRECTORY)

# Initialize STIX filestore
fs = FileSystemStore(STIX_DIRECTORY)

# Fetch existing IDs
existing_ids = {obj['id'] for obj in fs.query()}

# Download and store external objects
external_objects = download_and_store_external_objects(EXTERNAL_OBJECTS_URLS, existing_ids)

# Add the extra marking definition to the filestore
if extra_marking_definition.id not in existing_ids:
    fs.add(extra_marking_definition)
    existing_ids.add(extra_marking_definition.id)

# Fetch data
response = requests.get(RANSOMWHERE_API_URL)
data = response.json()

# Process data
wallet_objects = {}
transaction_objects_by_hash = {}
malware_objects = {}
relationship_objects = {}
indicator_addresses = {}

for item in data['result']:
    address = item['address']
    blockchain = item['blockchain']
    family = item['family']
    transactions = item['transactions']
    
    wallet_id = generate_stix_id("cryptocurrency-wallet", address)
    wallet_objects[address] = get_wallet_object(address)
    
    if transactions:  # Ensure there is at least one transaction
        for transaction in transactions:
            transaction_hash = transaction['hash']
            transaction['wallet_id'] = wallet_id

            if transaction_hash not in transaction_objects_by_hash:
                transaction_objects_by_hash[transaction_hash] = []  # Initialize list here

            transaction_objects_by_hash[transaction_hash].append(transaction)

        if family not in malware_objects:
            malware_objects[family] = get_malware_object(family, transactions[0]['time'])
            logging.debug(f"Created malware object for family {family}")

        if family in indicator_addresses:
            indicator_addresses[family].append(address)
        else:
            indicator_addresses[family] = [address]

# Create transaction objects
transaction_objects = [
    get_transaction_object(hash, txs, blockchain)
    for hash, txs in transaction_objects_by_hash.items()
]

# Create indicator objects
indicator_objects = {}
for family, addresses in indicator_addresses.items():
    indicator_objects[family] = get_indicator_object(malware_objects[family], addresses)

# Collect all objects to be bundled
all_stix_objects = list(wallet_objects.values()) + transaction_objects + list(malware_objects.values()) + list(indicator_objects.values())

# Add relationships to bundle
for indicator in indicator_objects.values():
    malware_family = indicator.description.split("associated with ")[1]  # Extract the malware family name from the indicator description
    if malware_family in malware_objects:
        malware = malware_objects[malware_family]
        all_stix_objects.append(get_indicator_malware_relationship(indicator, malware))
    else:
        logging.error(f"Malware object for family {malware_family} not found.")
    wallet_addresses = [addr.split("'")[1] for addr in indicator.pattern[1:-1].split(" OR ")]
    for address in wallet_addresses:
        wallet = wallet_objects[address]
        all_stix_objects.append(get_indicator_wallet_relationship(indicator, wallet))

# Add external objects, extra marking definition, and the main marking definition to the bundle once
all_stix_objects = external_objects + [extra_marking_definition, get_marking_definition()] + all_stix_objects

# Log all objects before bundling
logging.debug(f"Total number of STIX objects: {len(all_stix_objects)}")
for obj in all_stix_objects:
    logging.debug(f"Object: {obj.serialize()}")

# Add objects to filestore with collision check
logging.info("Starting to add objects to the filestore.")
for obj in all_stix_objects:
    if obj.id in existing_ids:
        logging.warning(f"Collision occurred for object: {obj.id}")
    else:
        try:
            fs.add(obj)
            existing_ids.add(obj.id)
        except Exception as e:
            logging.error(f"Error adding object {obj.id}: {e}")

logging.info(f"STIX objects have been created and saved to {STIX_DIRECTORY}")

# Create and store the bundle
logging.info("Starting to create STIX bundle.")
store_in_bundle(all_stix_objects)

print("done")
