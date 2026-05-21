# tweetfeed

## Overview

https://tweetfeed.live/feeds/

The data is all accessible via an API using `since` filter (you can only query a max of one year)

https://api.tweetfeed.live/v1/since/2026-05-01T00:00:00Z/

The data looks like so;

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
    },
    {
```

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
    "statement": "Origin: https://api.tweetfeed.live/v1/"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.


#### SCOs

The following `types` originate in each TweetDeck entry:

* domain -> `domain`
* ip -> `ipv4-addr`
* md5 -> `file.hash.md5`
* sha256 -> `file.hash.sha256`
* url -> `url`

For each entry, one of the SCOs types is created.

#### Indicator

For each SCO created, an Indicator object is created.

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

UUIDv5 is generated using namespace `<UUID OF FEED MARKING DEF>` and value `<indicator_name>`.

#### Indicator → SCO Relationship

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

#### User account SCO

For each record a user account to represent the Twitter account is created;

```json
{
  "type": "user-account",
  "spec_version": "2.1",
  "id": "user-account--UUID",
  "account_type": "twitter",
  "display_name": "<user>"
}
```

UUID generated automatically by the STIX2 library.
