import requests
import argparse
import os
import json
import uuid
from datetime import datetime
from stix2 import (Bundle, Identity, Indicator, Malware, MarkingDefinition, IPv4Address, DomainName, URL, File, NetworkTraffic, Relationship, parse)
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# URLs to import the marking-definition and identity STIX objects
MARKING_DEFINITION_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json"
IDENTITY_URL = "https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json"

def fetch_stix_object(url):
    response = requests.get(url)
    response.raise_for_status()
    print(f"Fetched STIX object from {url}")
    return parse(response.json(), allow_custom=True)

def create_session_with_retries(retries=5, backoff_factor=0.3):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=(502, 503, 504)
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

session = create_session_with_retries()

def fetch_malware_list():
    print("Fetching malware list...")
    response = session.post(API_URL, data=json.dumps({"query": "malware_list"}), headers={'Content-Type': 'application/json'})
    print(f"Request URL: {API_URL}")
    print(f"Request Payload: {{'query': 'malware_list'}}")
    print(f"Response Status: {response.status_code}")
    response.raise_for_status()
    malware_list = response.json().get("data", {})
    print(f"Fetched {len(malware_list)} malware entries.")
    return malware_list

def fetch_malware_info(malware_name, limit=1000, skip=0):
    payload = {
        "query": "malwareinfo",
        "malware": malware_name,
        "limit": limit,
        "skip": skip
    }
    response = session.post(API_URL, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
    print(f"Request URL: {API_URL}")
    print(f"Request Payload: {json.dumps(payload, indent=2)}")
    print(f"Response Headers: {response.request.headers}")
    print(f"Response Status: {response.status_code}")
    response.raise_for_status()
    data = response.json()
    print(f"Fetched malware info for {malware_name} with {len(data.get('data', []))} records (limit: {limit}, skip: {skip}).")
    return data

def filter_records_by_date(records, first_seen_min, last_seen_max):
    print(f"Filtering records by date. First seen min: {first_seen_min}, Last seen max: {last_seen_max}")
    filtered_records = []
    for record in records:
        first_seen = datetime.strptime(record["first_seen"], '%Y-%m-%d %H:%M:%S UTC')
        last_seen = datetime.strptime(record["last_seen"], '%Y-%m-%d %H:%M:%S UTC') if record["last_seen"] else None
        if (not first_seen_min or first_seen >= first_seen_min) and (not last_seen_max or (last_seen and last_seen <= last_seen_max)):
            filtered_records.append(record)
    print(f"Filtered {len(filtered_records)} records out of {len(records)} total records.")
    return filtered_records

def create_stix_objects(records, malware_name, marking_definition, identity):
    print(f"Creating STIX objects for {malware_name}...")
    stix_objects = []
    observable_mapping = {}

    for record in records:
        if record["ioc_type"] == "ip:port":
            ip, port = record["ioc"].split(":")
            ip_obj = IPv4Address(value=ip)
            stix_objects.append(ip_obj)
            network_traffic_obj = NetworkTraffic(
                dst_ref=ip_obj.id,
                dst_port=int(port),
                protocols=["tcp"] if port not in ["80", "443"] else (["http", "tcp"] if port == "80" else ["ssl", "tcp"])
            )
            stix_objects.append(network_traffic_obj)
            observable_mapping[record["id"]] = network_traffic_obj
        elif record["ioc_type"] == "url":
            url_obj = URL(value=record["ioc"])
            stix_objects.append(url_obj)
            observable_mapping[record["id"]] = url_obj
        elif record["ioc_type"] == "domain":
            domain_obj = DomainName(value=record["ioc"])
            stix_objects.append(domain_obj)
            observable_mapping[record["id"]] = domain_obj
        elif record["ioc_type"] in ["md5_hash", "sha256_hash"]:
            file_obj = File(hashes={record["ioc_type"].split("_")[0].upper(): record["ioc"]})
            stix_objects.append(file_obj)
            observable_mapping[record["id"]] = file_obj

    print(f"Created {len(stix_objects)} STIX objects for observables.")

    # Malware object
    malware = Malware(
        id="malware--" + str(uuid.uuid5(uuid.UUID("865d4e5d-f46d-4908-b2ab-50a8f227be07"), malware_name)),
        created=datetime.utcnow().isoformat() + "Z",
        modified=datetime.utcnow().isoformat() + "Z",
        name=malware_name,
        malware_types=["unknown"],
        is_family=True,
        object_marking_refs=[marking_definition.id]
    )
    stix_objects.append(malware)

    for record in records:
        indicator = Indicator(
            id="indicator--" + str(uuid.uuid5(uuid.UUID("865d4e5d-f46d-4908-b2ab-50a8f227be07"), f"{malware_name}-{record['reporter']}-{record['id']}")),
            created_by_ref=identity.id,
            created=record["first_seen"],
            modified=record["last_seen"] if record["last_seen"] else record["first_seen"],
            name=malware_name,
            pattern_type="stix",
            pattern="[{}]".format(" OR ".join([observable_mapping[record["id"]].id for record in records if record["id"] in observable_mapping])),
            valid_from=record["first_seen"],
            labels=[malware_name],
            confidence=int(record["confidence_level"]),
            external_references=[
                {
                    "source_name": "threatfox_reporter",
                    "external_id": record["reporter"]
                },
                {
                    "source_name": "threatfox_reference",
                    "external_id": record.get("reference", "")
                }
            ],
            object_marking_refs=[marking_definition.id]
        )
        stix_objects.append(indicator)

        relationship = Relationship(
            id="relationship--" + str(uuid.uuid5(uuid.UUID("865d4e5d-f46d-4908-b2ab-50a8f227be07"), f"{indicator.id}-{malware.id}")),
            created_by_ref=identity.id,
            created=record["first_seen"],
            modified=record["last_seen"] if record["last_seen"] else record["first_seen"],
            relationship_type="indicates",
            source_ref=indicator.id,
            target_ref=malware.id,
            object_marking_refs=[marking_definition.id]
        )
        stix_objects.append(relationship)

    print(f"Created {len(stix_objects)} total STIX objects for {malware_name}.")
    return stix_objects

def save_bundle(malware_name, stix_objects):
    bundle = Bundle(objects=stix_objects)
    os.makedirs(f"bundles/abuse_ch/threatfox", exist_ok=True)
    bundle_path = f"bundles/abuse_ch/threatfox/{malware_name}.json"
    with open(bundle_path, "w") as f:
        f.write(bundle.serialize(pretty=True))
    print(f"Saved STIX bundle to {bundle_path}")

def main():
    parser = argparse.ArgumentParser(description="ThreatFox Malware STIX Bundle Creator")
    parser.add_argument("--malware", type=str, help="Specific malware name to query")
    parser.add_argument("--first_seen_min", type=str, help="Filter for earliest first_seen date (YYYY-MM-DD)")
    args = parser.parse_args()

    first_seen_min = datetime.strptime(args.first_seen_min, '%Y-%m-%d') if args.first_seen_min else None

    if args.malware:
        malware_list = {args.malware: {"malware_printable": args.malware}}
    else:
        malware_list = fetch_malware_list()

    marking_definition = fetch_stix_object(MARKING_DEFINITION_URL)
    identity = fetch_stix_object(IDENTITY_URL)

    for malware_key, malware_info in malware_list.items():
        malware_name = malware_info["malware_printable"]
        skip = 0
        all_records = []
        while True:
            response_data = fetch_malware_info(malware_name, skip=skip)
            records = response_data.get("data", [])
            if not records:
                break
            filtered_records = filter_records_by_date(records, first_seen_min, None)
            if not filtered_records:
                break
            all_records.extend(filtered_records)
            skip += 1000

        if all_records:
            stix_objects = create_stix_objects(all_records, malware_name, marking_definition, identity)
            save_bundle(malware_name, stix_objects)

if __name__ == "__main__":
    main()
