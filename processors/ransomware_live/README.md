# ransomware_live

## Overview

ransomware_live uses the [ransomware2stix](https://github.com/muchdogesec/ransomware2stix) module to convert ransomware group intelligence from the ransomware.live API into STIX 2.1 format. It generates threat intelligence objects representing ransomware groups, their victims, tools, tactics, and indicators of compromise.

**Data Source:** [ransomware.live](https://ransomware.live/) API via [ransomware2stix](https://github.com/muchdogesec/ransomware2stix/blob/api-pro-impl/docs/README.md)  
**Update Schedule:** On demand  
**Format:** Ransomware group, victim, IOC, and tool data retrieved from the ransomware.live API

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `intrusion-set`
- `vulnerability`
- `file`
- `url`
- `email-addr`
- `cryptocurrency-wallet`
- `incident`
- `tool`
- `x-mitre-tactic`
- `relationship`

**Relationships:**
- `intrusion-set` → `attack-pattern` (uses) — MITRE ATT&CK techniques
- `intrusion-set` → `vulnerability` (exploits) — CVEs extracted from group data
- `intrusion-set` → `file` (uses) — file hash IOCs
- `intrusion-set` → `url` (uses) — URL/FTP IOCs
- `intrusion-set` → `cryptocurrency-wallet` (uses) — Bitcoin wallet IOCs
- `intrusion-set` → `identity` (victim-of) — victim organisations
- `intrusion-set` → `incident` (attributed-to) — ransomware incidents
- `intrusion-set` → `tool` (uses) — tools used by the group
- `identity` → `location` (located-in) — victim country
- `tool` → `x-mitre-tactic` (uses-tactic) — tool category

## Data generation

### Installation

Install the ransomware2stix module before running this processor:

```bash
pip install https://github.com/muchdogesec/ransomware2stix/archive/refs/heads/api-pro-impl.zip
```

### Required environment variables

The following environment variables must be set before running the processor:

| Variable | Description |
|---|---|
| `CTIBUTLER_BASE_URL` | Base URL for the CTI Butler API (e.g. `http://api.ctibutler.com`) |
| `CTIBUTLER_API_KEY` | API key for CTI Butler — used to retrieve MITRE ATT&CK and Location objects |
| `VULMATCH_BASE_URL` | Base URL for the Vulmatch API (e.g. `http://api.vulmatch.com`) |
| `VULMATCH_API_KEY` | API key for Vulmatch — used to retrieve CVE/Vulnerability objects |
| `RANSOMWARE_LIVE_API_KEY` | API Pro key for the ransomware.live API (`X-API-KEY` header) |

The script will exit with an error message listing any missing variables before processing begins.

### Data source

Data is retrieved from the ransomware.live API via the ransomware2stix module. The module fetches the following endpoints in order to optimise API calls:

1. **Groups List** — all ransomware groups tracked by ransomware.live
2. **IOC Statistics** — which groups have indicators of compromise available
3. **Group Details** — description, dark web locations, tools used, TTPs, and known CVEs
4. **IOCs** — file hashes, Bitcoin addresses, URLs, and email addresses (only for groups with IOCs)
5. **Victims** — victim organisations for groups that have posted victims

Full documentation on data collection and STIX object generation is available in the [ransomware2stix documentation](https://github.com/muchdogesec/ransomware2stix/blob/api-pro-impl/docs/README.md).

### Mapping

#### Imported objects

```
https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/ransomware2stix.json
https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/ransomware2stix.json
```

#### Intrusion Set

Each ransomware group is represented as an Intrusion Set object:

```json
{
  "type": "intrusion-set",
  "spec_version": "2.1",
  "id": "intrusion-set--<UUID V5>",
  "created_by_ref": "identity--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5",
  "created": "<SCRIPT FIRST RUN TIME>",
  "modified": "<HIGHEST location.updated TIME, ELSE CREATED TIME>",
  "name": "<name>",
  "description": "<description>",
  "primary_motivation": "organizational-gain",
  "threat_actor_types": ["crime-syndicate"],
  "resource_level": "team",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5"
  ],
  "external_references": [
    {
      "source_name": "darkweb_site",
      "url": "<locations.slug>"
    }
  ]
}
```

UUIDv5 Generation: namespace `7bae962c-40ae-5817-8cdc-e1b6eb4f38f5` + `<group_name>`

#### IOC Objects

Different IOC types are converted to appropriate STIX Cyber Observable objects:

- **SHA-256, SHA-1, MD5**: Created as `file` objects with corresponding hash values in the `hashes` dictionary
- **Bitcoin addresses**: Created as `cryptocurrency-wallet` objects via crypto2stix
- **URLs/FTP**: Created as `url` objects
- **Email addresses**: Created as `email-addr` objects

Each IOC is linked to the Intrusion Set via a `uses` relationship.

#### Victim Identity Objects

Each victim organisation becomes an `identity` object:

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<UUID v5>",
  "created_by_ref": "identity--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5",
  "created": "2020-01-01T00:00:00.000Z",
  "modified": "<highest discovered date>",
  "name": "<victim>",
  "description": "<description>",
  "contact_information": "<domain>",
  "identity_class": "organization",
  "sectors": "<sector lookup>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5"
  ]
}
```

UUIDv5 Generation: namespace `7bae962c-40ae-5817-8cdc-e1b6eb4f38f5` + `<victim_name_lowercase>`

#### Incident Objects

Each victim compromise is represented as an `incident` object with a title in the format `<victim> ransomed by <group>`:

```json
{
  "type": "incident",
  "spec_version": "2.1",
  "id": "incident--<UUID v5>",
  "created_by_ref": "identity--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5",
  "created": "<attackdate>",
  "modified": "<discovered>",
  "title": "<identity name> ransomed by <group name>",
  "url": "<claim_url>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5"
  ]
}
```

UUIDv5 Generation: namespace `7bae962c-40ae-5817-8cdc-e1b6eb4f38f5` + `<incident.name>+<victim.id>`

For full details on all object mappings, see the [ransomware2stix documentation](https://github.com/muchdogesec/ransomware2stix/blob/api-pro-impl/docs/README.md).

## Usage

### Running locally

Copy `.env.example` to `ransomware_live.env`, fill in your credentials


Load the variables:

```bash
set -a; source ransomware_live.env; set +a
```

Then run the processor:

```bash
python processors/ransomware_live/ransomware_live.py [--since-date DATE] [--until-date DATE] [--groups GROUP ...]
```

### Options

* `--since-date <YYYY-MM-DD>`: Only process victims discovered on or after this date.
* `--until-date <YYYY-MM-DD>`: Only process victims discovered on or before this date.
* `--groups <group> [<group> ...]`: Only process data for the specified ransomware group(s) (case-insensitive). Default is all groups.

### Examples

Run with all available data:
```bash
python processors/ransomware_live/ransomware_live.py
```

Run for a specific date range:
```bash
python processors/ransomware_live/ransomware_live.py --since-date 2026-01-01 --until-date 2026-04-22
```

Run for specific groups only:
```bash
python processors/ransomware_live/ransomware_live.py --groups akira clop lockbit
```

### Output

The script saves generated STIX bundle files to the output directory:
* `outputs/ransomware_live/bundles/`

Each bundle contains:
* Intrusion Set objects for each ransomware group
* Identity objects for victim organisations
* Incident objects for each recorded attack
* Location objects for victim countries
* Tool and x-mitre-tactic objects for tools used by each group
* File, URL, cryptocurrency-wallet, and email-addr objects for IOCs
* Vulnerability objects for CVEs referenced in group data
* Relationship objects linking all of the above
* Auto-imported identity and marking-definition objects from ransomware2stix

## GitHub Action

The processor is linked to a GitHub action that runs on demand.

### Setup

Configure the following in your GitHub repository:

**Secrets** (Settings → Secrets and variables → Actions):
* `CTX_BASE_URL`: The base URL for your CTX instance (e.g., `https://api.cyberthreatexchange.com`)
* `CTX_API_KEY`: Your CTX API key for authentication
* `CTIBUTLER_BASE_URL`: Base URL for the CTI Butler API
* `CTIBUTLER_API_KEY`: API key for CTI Butler
* `VULMATCH_BASE_URL`: Base URL for the Vulmatch API
* `VULMATCH_API_KEY`: API key for Vulmatch
* `RANSOMWARE_LIVE_API_KEY`: Your ransomware.live API Pro key (`X-API-KEY`)

**Variables**:
* `RANSOMWARE_LIVE_FEED_ID`: The CTX feed ID where ransomware_live data should be uploaded
* `MAX_BUNDLE_SIZE_KB`: Maximum size in KB for bundle files before splitting (e.g., `5120` for 5 MB)
