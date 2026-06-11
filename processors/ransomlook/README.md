# RansomLook

## Overview

RansomLook is an open-source ransomware intelligence platform that publishes victim posts, group profiles, ransom notes, threat actors, infrastructure, and cryptocurrency context.

**Feed URL:** `https://www.ransomlook.io/api`  
**API Docs:** `https://www.ransomlook.io/doc/#/`  
**Update Schedule:** Daily, with CTX resume support in the workflow  
**Format:** JSON API, with optional `RANSOMLOOK_API_KEY` authentication

This processor is date-driven. It fetches posts in month-sized windows from `GET /posts/period/{start_date}/{end_date}`, then writes:

- one threat-actor bundle for the actor catalogue
- one STIX bundle per month window of posts

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `intrusion-set`
- `threat-actor`
- `incident`
- `note`
- `url`
- `cryptocurrency-wallet`
- `relationship`

**Relationships:**
- `intrusion-set` -> `url` (`uses`) for group infrastructure
- `intrusion-set` -> `cryptocurrency-wallet` (`uses`) for wallet addresses
- `incident` -> `intrusion-set` (`attributed-to`) for claimed victim posts
- `incident` -> `identity` (`targets`) for the victim organization
- `threat-actor` -> `intrusion-set` (`associated-with`) for actor-to-group links

Victim notes are modeled as STIX `note` objects with `object_refs` pointing back to the related `intrusion-set`.

## Data Source

The processor reads the public RansomLook API surface used by the rewritten module:

- `GET /posts/period/{start_date}/{end_date}` for dated victim posts
- `GET /group/{group_name}` for group metadata and group-linked posts
- `GET /crypto/` for the list of groups with wallet data
- `GET /crypto/{group_name}` for wallet details
- `GET /notes/` for the list of groups with note coverage
- `GET /notes/group/{group_name}` for note metadata
- `GET /notes/{note_id}` for note bodies and update timestamps
- `GET /actors/` for actor names
- `GET /actors/{actor_name}` for actor details and related groups

The processor accepts both `{"posts": [...]}` and raw list responses from the period endpoint. Each post is expected to include:

- `group_name`
- `post_title`
- `discovered`

It also uses these optional fields when present:

- `description`
- `link`
- `screen`
- `magnet`

Group metadata is expected to include:

- `aliases`
- `affiliates`
- `profile`
- `description`
- `raas`
- `locations`
- `notes`

The location records are filtered on `available`, and wallet data is read from `by_chain`.

## Mapping

#### Imported Objects

The processor imports the shared feeds2stix marking definition:

`https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json`

#### Source Identity

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<UUIDV5>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "2020-01-01T00:00:00.000Z",
  "modified": "2020-01-01T00:00:00.000Z",
  "name": "RansomLook",
  "description": "RansomLook is an open-source ransomware and data-extortion intelligence platform covering groups, victim posts, actors, infrastructure, ransom notes, leaks, and cryptocurrency wallets.",
  "identity_class": "organization",
  "contact_information": "https://www.ransomlook.io/",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Identity `id` is generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and the value `RansomLook`.

#### Marking Definition

```json
{
  "type": "marking-definition",
  "spec_version": "2.1",
  "id": "marking-definition--<UUIDV5>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "2020-01-01T00:00:00.000Z",
  "definition_type": "statement",
  "definition": {
    "statement": "Origin: https://www.ransomlook.io/api"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking definition `id` is generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and the origin statement.

#### Intrusion Set

Each group becomes one `intrusion-set` object.

```json
{
  "type": "intrusion-set",
  "spec_version": "2.1",
  "id": "intrusion-set--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF RANSOMLOOK IDENTITY>",
  "created": "<first post timestamp in the window>",
  "modified": "<last post timestamp in the window>",
  "first_seen": "<first post timestamp in the window>",
  "last_seen": "<last post timestamp in the window>",
  "name": "<group name>",
  "aliases": ["<alias>", "<affiliate>"],
  "labels": ["raas"],
  "description": "<group description>",
  "external_references": [
    {
      "source_name": "ransomlook",
      "url": "https://www.ransomlook.io/group/<group-name>"
    },
    {
      "source_name": "ransomlook-profile",
      "url": "<profile url>"
    }
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF RANSOMLOOK MARKING>"
  ]
}
```

The `intrusion-set` ID is deterministic and uses `generate_uuid5(group_name, source_marking_id)`.

#### Incident

Each victim post becomes one `incident` object.

```json
{
  "type": "incident",
  "spec_version": "2.1",
  "id": "incident--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF RANSOMLOOK IDENTITY>",
  "created": "<post discovered timestamp>",
  "modified": "<post discovered timestamp>",
  "name": "<victim name> claimed by <group>",
  "description": "<post description>",
  "external_references": [
    {
      "source_name": "ransomlook",
      "url": "https://www.ransomlook.io/group/<group-name>"
    }
  ]
}
```

The incident ID is deterministic and uses `generate_uuid5(f"{group.name}:{post['post_title']}", source_marking_id)`.

#### Identity

Each post also creates a victim `identity` object.

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF RANSOMLOOK IDENTITY>",
  "created": "<post discovered timestamp>",
  "modified": "<post discovered timestamp>",
  "name": "<victim name>",
  "identity_class": "organization"
}
```

The identity ID is deterministic and uses `generate_uuid5(post['post_title'], source_marking_id)`.

#### Note

Group notes are modeled as STIX `note` objects.

```json
{
  "type": "note",
  "spec_version": "2.1",
  "id": "note--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF RANSOMLOOK IDENTITY>",
  "created": "<group first_seen timestamp>",
  "modified": "<note updated_at timestamp>",
  "abstract": "<note title>",
  "content": "<note body>",
  "object_refs": [
    "intrusion-set--<UUID OF GROUP>"
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF RANSOMLOOK MARKING>"
  ],
  "external_references": [
    {
      "source_name": "ransomlook",
      "url": "https://www.ransomlook.io/notes/<note-id>"
    }
  ]
}
```

The note ID is deterministic and uses `generate_uuid5(f"note:{note_id}", source_marking_id)`.

#### URLs and Wallets

Available infrastructure locations become `url` SCOs and wallet addresses become `cryptocurrency-wallet` SCOs. Each one is linked from the group with a `uses` relationship.

#### Threat Actors

Actor records from `/actors/{name}` become `threat-actor` objects. Each actor is linked to the referenced groups with `associated-with` relationships.

## Timestamp Handling

- post `discovered` timestamps drive incident and victim identity timestamps
- group first/last seen timestamps are derived from the posts in the current month window
- note `created` uses the group first-seen timestamp
- note `modified` uses the note `updated_at` timestamp
- threat actor `created` and `modified` are derived from the grouped records they reference
- `--since-date` and `--until-date` filter on the post `discovered` timestamp after each month window is downloaded

Date-only CLI inputs are normalized with the shared parsing helpers, so `--until-date 2026-06-30` is treated as the end of that day in UTC.

## Usage

```bash
python processors/ransomlook/ransomlook.py [--since-date YYYY-MM-DD] [--until-date YYYY-MM-DD]
```

When `--since-date` is supplied, the processor only includes posts discovered on or after that timestamp.
When `--until-date` is supplied, the processor only includes posts discovered on or before that timestamp.

This processor is date-driven and uses the post `discovered` timestamp to set STIX timestamps. It fetches posts in month-sized windows from `GET /posts/period/{start_date}/{end_date}` and then filters on the full `since_date` and `until_date` values, including time.

## GitHub Action

The workflow lives at [`.github/workflows/update-ransomlook.yml`](../../.github/workflows/update-ransomlook.yml).

### Required Configuration

**Secrets:**
- `CTX_BASE_URL`
- `CTX_API_KEY`

**Variables:**
- `RANSOMLOOK_FEED_ID`
- `MAX_BUNDLE_SIZE_KB`

### Workflow inputs

- `target_environment`: choose `all`, `staging`, or `production` for manual runs
- `since_date`: optional lower bound for posts included in a manual run; use `auto` to resume from the latest note timestamp
- `until_date`: optional upper bound for posts included in a manual run
