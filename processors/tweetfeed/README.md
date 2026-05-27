# TweetFeed

## Overview

TweetFeed collects indicators of compromise shared by the infosec community on X/Twitter and exposes them through a public API.

**Feed URL:** https://tweetfeed.live/feeds/  
**API Base:** https://api.tweetfeed.live/v1/  
**Format:** JSON feed of IOC records

The API supports a `since`-based query model and only returns up to one year of data at a time.

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `user-account`
- `domain-name`
- `ipv4-addr`
- `file`
- `url`
- `indicator`

**Relationships:**
- `indicator` → SCO (`indicates`)

## Data source

The API returns records shaped like this:

```json
[
  {
    "date": "2026-05-01 02:47:00",
    "user": "harugasumi",
    "type": "domain",
    "value": "nedabaci.z4.web.core.windows.net",
    "tags": [],
    "tweet": "https://x.com/harugasumi/status/2050044303926505846"
  },
  {
    "date": "2026-05-01 02:47:00",
    "user": "harugasumi",
    "type": "url",
    "value": "https://nedabaci.z4.web.core.windows.net",
    "tags": [],
    "tweet": "https://x.com/harugasumi/status/2050044303926505846"
  }
]
```

Each record represents one IOC observed in a tweet, with:

- `date`: observation timestamp in `YYYY-MM-DD HH:MM:SS` format
- `user`: X/Twitter account that posted the IOC
- `type`: IOC type
- `value`: IOC value
- `tags`: feed tags attached to the IOC
- `tweet`: source tweet URL

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
  "name": "TweetFeed",
  "description": "TweetFeed collects Indicators of Compromise (IOCs) shared by the infosec community on Twitter/X.",
  "identity_class": "system",
  "contact_information": "https://tweetfeed.live/",
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
    "statement": "Origin: https://api.tweetfeed.live/v1/"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` is generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### User Account

For each record, a `user-account` SCO is created to represent the posting account.

```json
{
  "type": "user-account",
  "spec_version": "2.1",
  "id": "user-account--UUID",
  "account_type": "twitter",
  "display_name": "<user>"
}
```

UUID is generated automatically by the STIX2 library.

#### Indicator -> User account Relationship

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<date>",
  "modified": "<date>",
  "relationship_type": "indicates",
  "source_ref": "indicator--<ID>",
  "target_ref": "user-account--<ID>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`.

#### SCOs

The following input `type` values are mapped to SCOs:

- `domain` -> `domain-name`
- `ip` -> `ipv4-addr`
- `md5` -> `file` with `MD5` hash
- `sha256` -> `file` with `SHA-256` hash
- `url` -> `url`

#### Indicator

For each IOC record, an Indicator object is created.

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<date>",
  "modified": "<date>",
  "valid_from": "<date>",
  "indicator_types": [
    "malicious-activity"
  ],
  "name": "<TYPE>: <VALUE>",
  "pattern": "[<TYPE>:<KEY> = '<VALUE>']",
  "pattern_type": "stix",
  "labels": [
    "<TAGS>"
  ],
  "external_references": [
    {
      "source_name": "x_url",
      "url": "<TWEET>"
    }
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

Indicator `id` is generated using namespace `<UUID OF FEED MARKING DEF>` and value `<indicator_name>`.

#### Indicator -> SCO Relationship

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<date>",
  "modified": "<date>",
  "relationship_type": "indicates",
  "source_ref": "indicator--<ID>",
  "target_ref": "<TYPE>--<ID>",
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
python processors/tweetfeed/tweetfeed.py [--start-date YYYY-MM-DD]
```

When `--start-date` is supplied, the processor queries the TweetFeed API's `since` endpoint with that timestamp so it only pulls records from the requested point forward.

This processor is date-driven and uses the feed record timestamp to set STIX timestamps.

## Output

The processor produces STIX bundles containing:

- a `user-account` object for the posting account
- an SCO for the IOC value
- an `indicator` object that matches the IOC
- a relationship from the `indicator` to the SCO
- identity and marking definition objects

Bundles are written to `outputs/tweetfeed/bundles/tweetfeed_YYYYMMDD.json`.

## Notes

- The API only exposes a bounded lookback window of one year per query.
- The feed is best treated as a dated processor because each record includes an explicit `date`.

## GitHub Action

The processor is intended to run on a 15-minute schedule and resume from the last processed indicator timestamp when possible.

### Required Configuration

**Secrets:**
- `CTX_BASE_URL`
- `CTX_API_KEY`

**Variables:**
- `TWEETFEED_FEED_ID`
- `MAX_BUNDLE_SIZE_KB`
