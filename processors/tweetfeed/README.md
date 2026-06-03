# TweetFeed

## Overview

TweetFeed collects indicators of compromise shared by the infosec community on X/Twitter and publishes them as CSV snapshots in a git repository.

**Feed Repository:** https://github.com/0xDanielLopez/TweetFeed  
**Format:** CSV IOC snapshots in a git repository

The processor clones the TweetFeed repository and reads CSV files from the repository tree. It supports `--start-date` and `--until-date` filters and groups records into monthly bundles of up to 1000 records each.

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

The repository contains CSV files shaped like this:

```csv
date,user,type,value,tags,tweet
2026-05-01 02:47:00,harugasumi,domain,nedabaci.z4.web.core.windows.net,#phishing #CobaltStrike,https://x.com/harugasumi/status/2050044303926505846
```

Each CSV row represents one IOC observed in a tweet, with:

- `date`: observation timestamp in `YYYY-MM-DD HH:MM:SS` format
- `user`: X/Twitter account that posted the IOC
- `type`: IOC type
- `value`: IOC value
- `tags`: feed tags attached to the IOC
- `tweet`: source tweet URL

The processor reads files under `20*/*/*.csv`, filters rows by `--start-date` and `--until-date`, then groups records by month into zero-padded bundle parts such as `tweetfeed_202605p01.json` and `tweetfeed_202605p02.json`.

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
  "relationship_type": "related-to",
  "description": "Indicator was created using post by @<user>",
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


#### ATT&CK 

The following `labels` are assigned to Indicators (June 2026):

aitm, android, apt, asyncrat, booking, c2, clickfix, deimos, dprk, infostealer, kimsuky, lazarus, malware, mustangpanda, netsupport, opendir, phishing, ransomware, rat, remcos, scam, stealer, supershell, trojan, vidar, xworm

We should link Indicators containing the label `phishing` to the ATT&CK technique 
 `T1566` `attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b` using CTI Butler

Imports: `attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b` from CTI Butler

With relationship to Indicator:

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUID V5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<date>",
  "modified": "<date>",
  "relationship_type": "indicates",
  "description": "<VALUE> is known to be used for Phishing (T1566)",
  "source_ref": "indicator--<URL INDICATOR>",
  "target_ref": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ],
  "external_references": [
    {
      "source_name": "x_url",
      "url": "<TWEET>"
    }
  ]
}
```

## Usage

```bash
python processors/tweetfeed/tweetfeed.py [--start-date YYYY-MM-DD] [--until-date YYYY-MM-DD]
```

When `--start-date` is supplied, the processor only includes records on or after that timestamp.
When `--until-date` is supplied, the processor only includes records on or before that timestamp.

This processor is date-driven and uses the feed record timestamp to set STIX timestamps.

## Output

The processor produces STIX bundles containing:

- a `user-account` object for the posting account
- an SCO for the IOC value
- an `indicator` object that matches the IOC
- a relationship from the `indicator` to the SCO
- when the `phishing` label is present, an ATT&CK T1566 relationship and attack-pattern object
- identity and marking definition objects

Bundles are written to `outputs/tweetfeed/bundles/tweetfeed_YYYYMMpNN.json`.

## Notes

- The API only exposes a bounded lookback window of one year per query.
- The feed is best treated as a dated processor because each record includes an explicit `date`.
- Records are grouped into bundles of up to 1000 rows per month.

## GitHub Action

The processor is intended to run on a 15-minute schedule and resume from the last processed indicator timestamp when possible.

### Required Configuration

**Secrets:**
- `CTX_BASE_URL`
- `CTX_API_KEY`
- `CTIBUTLER_BASE_URL`: base URL for the CTI Butler API used to fetch ATT&CK objects
- `CTIBUTLER_API_KEY`: API key for CTI Butler

**Variables:**
- `TWEETFEED_FEED_ID`
- `MAX_BUNDLE_SIZE_KB`

### Workflow inputs

- `since_date`: optional lower bound for records included in a manual run
- `until_date`: optional upper bound for records included in a manual run
