# Phishing Army

## Overview

Phishing Army publishes a curated phishing blocklist derived from public phishing intelligence sources and updated every 6 hours.

**Feed URL:** https://phishing.army/download/phishing_army_blocklist.txt  
**Update Schedule:** Every 6 hours  
**Format:** Plain-text domain blocklist

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `attack-pattern`
- `domain-name`
- `indicator`

**Relationships:**
- `indicator` → `domain-name` (`indicates`)
- `indicator` → `attack-pattern` (`indicates`)

## Data source

The feed is a plain-text blocklist with one domain per line. Comment lines beginning with `#` are ignored.

## Mapping

#### Imported objects

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json

ATT&CK Enterprise T1566 Phishing:

`attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b`

The processor fetches the attack-pattern from CTI Butler when configured, otherwise it uses the bundled local fallback.

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
  "name": "Phishing Army",
  "description": "Phishing Army maintains a curated phishing blocklist derived from public phishing intelligence sources.",
  "identity_class": "system",
  "contact_information": "https://www.phishing.army/",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Identity `id` is generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`.

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
    "statement": "Origin: https://phishing.army/download/phishing_army_blocklist.txt"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` is generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### Domain Name

For each entry, a `domain-name` SCO is created.

```json
{
  "type": "domain-name",
  "spec_version": "2.1",
  "id": "domain-name--UUID",
  "value": "<domain>"
}
```

UUID is generated automatically by the STIX2 library.

#### Indicator

For each domain, an Indicator object is created.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<script_run_time>",
  "modified": "<script_run_time>",
  "valid_from": "<script_run_time>",
  "indicator_types": [
    "malicious-activity"
  ],
  "name": "Domain Name: <VALUE>",
  "pattern": "[domain-name:value = '<VALUE>']",
  "pattern_type": "stix",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

Indicator `id` is generated using namespace `<UUID OF FEED MARKING DEF>` and value `name`.

#### Indicator -> Domain Name Relationship

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<script_run_time>",
  "modified": "<script_run_time>",
  "relationship_type": "indicates",
  "source_ref": "indicator--<ID>",
  "target_ref": "domain-name--<ID>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`.

#### Indicator -> ATT&CK Technique Relationship

Each indicator is linked to ATT&CK Enterprise T1566 Phishing.

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<script_run_time>",
  "modified": "<script_run_time>",
  "relationship_type": "indicates",
  "description": "<domain> is known to be used for Phishing (T1566)",
  "source_ref": "indicator--<ID>",
  "target_ref": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
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
python processors/phishing_army/phishing_army.py
```

This processor has no date filters. It uses the current snapshot of the blocklist and stamps STIX objects with the script run time.

## Output

The processor creates a single STIX bundle file:

* `outputs/phishing_army/bundles/phishing_army_YYYYMMDD.json`

Each bundle contains:

* `domain-name` objects for the blocklisted domains
* `indicator` objects with patterns matching the domains
* `relationship` objects linking indicators to domains
* `relationship` objects linking indicators to ATT&CK T1566 Phishing
* ATT&CK T1566 Phishing `attack-pattern`
* identity and marking definition objects

## GitHub Action

The processor is intended to run on a 6-hour schedule and upload the current snapshot bundle to CTX.

### Required Configuration

**Secrets:**
* `CTX_BASE_URL`
* `CTX_API_KEY`

**Variables:**
* `PHISHING_ARMY_FEED_ID`
* `MAX_BUNDLE_SIZE_KB`
