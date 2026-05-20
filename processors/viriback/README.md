# viriback

## Overview

Viriback is a collaborative clearing house for data and information about phishing and malware activity on the Internet. It provides openly accessible feeds for security researchers, analysts, and threat intelligence systems.

https://www.viriback.com/

**Feed URL:** https://tracker.viriback.com/dump.php  
**Update Schedule:** Continuous updates  
**Format:** CSV

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `url`
- `ipv4-addr`
- `indicator`
- `malware`

**Relationships:**
- `indicator` → `url` (`indicates`)
- `url` → `ipv4-addr` (`related-to`)
- `indicator` → `malware` (`indicates`)
- `url` → `malware` (`related-to`)

## Data source

https://tracker.viriback.com/dump.php

## Data schema

```csv
Family,URL,IP,FirstSeen
Pony,http://officeman.tk/images/admin.php,207.180.230.128,01-06-2019
Pony,http://learn.cloudience.com/ojekwaeng/yugo/admin.php,192.145.234.108,01-06-2019
Pony,http://vman23.com/ba24/admin.php,95.213.204.53,01-06-2019
Pony,http://vman23.com/ba23/admin.php,95.213.204.53,01-06-2019
Pony,http://vman23.com/ba22/admin.php,95.213.204.53,01-06-2019
Pony,http://vman23.com/ba21/admin.php,95.213.204.53,01-06-2019
Pony,http://vman23.com/ba20/admin.php,95.213.204.53,01-06-2019
Pony,http://vman23.com/smt/admin.php,95.213.204.53,01-06-2019
Pony,http://lojalstil.mk/img/dataimage/admin.php,88.99.251.203,01-06-2019
Lokibot,http://unimasa.icu/dapper/five/PvqDq929BSx_A_D_M1n_a.php,5.253.62.205,01-06-2019
```

The CSV contains:

- `FirstSeen`: First observed date in `DD-MM-YYYY` format
- `URL`: Malicious URL
- `IP`: Associated IPv4 address
- `Family`: Malware family name

Results are not guaranteed to be sorted.

## Mapping

#### Imported objects

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json

#### Identity

An identity is hardcoded for the feed.

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<UUIDV5>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "2020-01-01T00:00:00.000Z",
  "modified": "2020-01-01T00:00:00.000Z",
  "name": "Viriback",
  "description": "Viriback is a collaborative clearing house for data and information about phishing on the Internet. Also, Viriback provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.",
  "identity_class": "system",
  "contact_information": "https://www.viriback.com/",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`.

#### Marking Definition

This is hardcoded and never changes.

```json
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--<UUIDV5>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "2020-01-01T00:00:00.000Z",
  "definition_type": "statement",
  "definition": {
    "statement": "Origin: https://tracker.viriback.com/dump.php"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### URL

For each entry, a URL SCO is created.

```json
{
  "type": "url",
  "spec_version": "2.1",
  "id": "url--<UUID>",
  "value": "<url>"
}
```

UUID generated automatically by the STIX2 library.

#### IPv4 Address

For each entry, an IPv4 Address SCO is created.

```json
{
  "type": "ipv4-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--<UUID>",
  "value": "<ip>"
}
```

UUID generated automatically by the STIX2 library.

#### Indicator

For each URL, an Indicator object is created.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<first_seen>",
  "modified": "<first_seen>",
  "valid_from": "<first_seen>",
  "indicator_types": [
    "malicious-activity"
  ],
  "name": "URL: <url>",
  "pattern": "[url:value = '<url>']",
  "pattern_type": "stix",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 is generated using namespace `<UUID OF FEED MARKING DEF>` and value `<indicator_name>`.

#### URL → IPv4 Relationship

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<first_seen>",
  "modified": "<first_seen>",
  "relationship_type": "related-to",
  "source_ref": "url--<ID>",
  "target_ref": "ipv4-addr--<ID>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`.

#### Indicator → URL Relationship

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<first_seen>",
  "modified": "<first_seen>",
  "relationship_type": "indicates",
  "source_ref": "indicator--<ID>",
  "target_ref": "url--<ID>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`.

#### Malware

A Malware object is created for each malware family.

```json
{
  "type": "malware",
  "spec_version": "2.1",
  "id": "malware--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<earliest entry timestamp>",
  "modified": "<latest entry timestamp>",
  "name": "<family>",
  "malware_types": [
    "unknown"
  ],
  "is_family": true,
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 is generated using namespace `<UUID OF FEED MARKING DEF>` and value `family`.

#### Indicator → Malware Relationship

Each indicator is linked to the malware family.

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<entry timestamp>",
  "modified": "<entry timestamp>",
  "relationship_type": "indicates",
  "source_ref": "indicator--<ID>",
  "target_ref": "malware--<ID>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`.

#### URL → Malware Relationship

Each URL is linked to the malware family.

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<entry timestamp>",
  "modified": "<entry timestamp>",
  "relationship_type": "related-to",
  "source_ref": "url--<ID>",
  "target_ref": "malware--<ID>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`.

## Usage

```bash
python processors/viriback/viriback.py [OPTIONS]
```

### Options

* `--since-date <date>`: Only include records on or after this date
* `--until-date <date>`: Only include records on or before this date

Dates support ISO format:

```text
YYYY-MM-DD
YYYY-MM-DDTHH:MM:SS
```

### Examples

Process all records:

```bash
python processors/viriback/viriback.py
```

Process records after a specific date:

```bash
python processors/viriback/viriback.py --since-date 2026-02-01
```

Process records within a date range:

```bash
python processors/viriback/viriback.py \
  --since-date 2026-02-01 \
  --until-date 2026-02-26
```

## Output

The script creates separate bundles for each malware family:

* `outputs/viriback/bundles/<family>.json`

Each bundle contains:

- URL objects
- IPv4 address objects
- Indicator objects
- Malware family objects
- Relationships connecting URLs, IPs, Indicators, and Malware

## GitHub Action

The processor is automated via GitHub Actions at [`update-viribot.yml`](../../.github/workflows/update-viribot.yml).

### Schedule

The workflow runs automatically once a day because the FirstSeen doesn't contain the time part of the datetime:

```yaml
schedule:
  - cron: '0 */2 * * *'  # Every 2 hours
```

### How It Works

1. **Fetch Last Run Time**: Uses GitHub API to retrieve the timestamp of the last successful workflow run
2. **Process Data**: Downloads the full MalwareBazaar CSV and processes only records with `FirstSeen` newer than the last run time
3. **Create STIX Bundles**: Generates separate bundles for each malware signature found
4. **Upload to CTX**: Automatically uploads all generated bundles to CyberThreat eXchange using the configured feed ID

### Manual Dispatch

The workflow can also be triggered manually with custom parameters:

- **`start_date`**: Filter records by date (YYYY-MM-DD format)
  - Set to `"auto"` (default) to use the last successful run time
  - Set to a specific date like `"2024-07-15"` to process records from that date onwards
  - Leave empty to process all records

### Configuration

Required secrets and variables:

- **Secrets**:
  - `CTX_BASE_URL`: Base URL for the CTX API
  - `CTX_API_KEY`: API key for CTX authentication

- **Variables**:
  - `VIRIBACK_FEED_ID`: The CTX feed ID to upload bundles to
  - `MAX_BUNDLE_SIZE_KB`: Maximum bundle size in KB (bundles exceeding this will be split)

### Incremental Updates

The workflow intelligently handles incremental updates:

- For scheduled runs: Automatically filters by the last successful run time
- For manual runs with `start_date="auto"`: Uses the last successful run time
- This ensures only new malware samples are processed on each run, avoiding duplicate processing
