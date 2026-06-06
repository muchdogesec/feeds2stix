# RansomLook

## Overview

RansomLook publishes open-source ransomware and data-extortion intelligence covering groups, victim posts, actors, crypto wallets, leak sites, file servers, chat infrastructure, and related ecosystem entities.

This document is a **draft STIX mapping** for a future `ransomlook` processor. It follows the design patterns used across current `feeds2stix` processors, especially [`ransomware_live`](../ransomware_live/README.md), but adapts them to RansomLook's post-centric and infrastructure-rich data model.

**Feed URL:** `https://www.ransomlook.io/api`  
**Update Schedule:** Updated live on the source platform  
**Format:** Authenticated JSON API

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `intrusion-set`
- `incident`
- `note`
- `threat-actor`
- `location`
- `url`
- `cryptocurrency-wallet`
- `relationship`

**Relationships:**
- `intrusion-set` -> `url` (`uses`) for leak, file-server, chat, admin, and relay locations
- `intrusion-set` -> `cryptocurrency-wallet` (`uses`) for ransom-payment wallets
- `intrusion-set` -> `identity` (`targets`) for victim organisations
- `incident` -> `intrusion-set` (`attributed-to`) for victim posts claimed by a group
- `incident` -> `identity` (`targets`) for the victim named in the post
- `identity` -> `location` (`located-in`) when victim country is available
- `threat-actor` -> `intrusion-set` (`associated-with`) for actor-to-group relations

Ransom notes should be modeled as STIX `note` SDOs that reference their related `intrusion-set` via `object_refs`, rather than via a separate STIX relationship object.

## Data generation

### Required environment variables

The following environment variable should be set before running the processor locally:

| Variable | Description |
|---|---|
| `RANSOMLOOK_API_KEY` | API key sent in the `Authorization` header |

### Data source

RansomLook exposes an authenticated API at `https://www.ransomlook.io/api`. The public documentation currently shows these relevant endpoints:

- `GET /posts` with `days=<n>` for recent victim posts
- `GET /group/<slug>` for a specific group's details
- `GET /search?query=<text>` for global victim-post search
- `GET /export/<db_num>` for full database export
- `GET /actor/<name>` for actor profiles
- `GET /crypto/<group>` for group wallet data

The documentation explicitly notes these export databases:

- `0` = Groups
- `2` = Posts
- `3` = Markets
- `4` = Leaks
- `5` = Actors

### Public endpoint shape validated without authentication

The following endpoint behavior has been validated against the live public API on **2026-06-06**:

- `GET /posts?days=<n>` is publicly accessible
  - response shape: `{"posts": [{"group_name": "...", "discovered": "..."}]}`
- `GET /group/<slug>` is publicly accessible
  - response shape: a JSON array with:
    - index `0`: group metadata object
    - index `1`: victim-post array
- `GET /crypto/<group>` is publicly accessible for groups with wallet data
  - response shape: `{"group": "...", "aliases": [...], "total": <int>, "by_chain": {...}}`
- `GET /export/<db_num>` requires authentication
  - unauthenticated response: HTTP `401`

The public `group` metadata object was observed to contain these keys:

- `affiliates`
- `captcha`
- `hash`
- `jabber`
- `locations`
- `mail`
- `matrix`
- `meta`
- `other`
- `pgp`
- `private`
- `profile`
- `raas`
- `ransomware_galaxy_value`
- `session`
- `telegram`
- `tox`

The public victim-post objects from `GET /group/<slug>` were observed to contain:

- `post_title`
- `discovered`
- `description`
- `link`
- `magnet`
- `screen`

The public `locations` entries from `GET /group/<slug>` were observed to contain:

- `slug`
- `fqdn`
- `timeout`
- `delay`
- `fs`
- `chat`
- `admin`
- `browser`
- `init_script`
- `private`
- `version`
- `available`
- `title`
- `updated`
- `lastscrape`
- `header`
- `fixedfile`
- `screen`
- `source`

The public wallet entries from `GET /crypto/<group>` were observed to contain:

- `address`
- `balance`
- `blockchain`
- `createdAt`
- `family`
- `updatedAt`
- `balanceUSD`
- `tx_count`
- `last_tx_time`
- `created_at`
- `updated_at`
- `imported_at`
- `source`
- `origin`
- `group`

Public ransom-note coverage was also validated:

- `/notes` publicly lists family-specific note pages such as `/notes/krybit`
- `/notes/<family>` pages expose note bodies publicly in HTML, including:
  - note filename
  - full note text inside `<pre class="note-body">`
  - a link back to the corresponding `/group/<name>` page

### Collection strategy

The recommended processor design is:

1. Discover active or relevant groups from `GET /posts?days=<n>`.
2. For each discovered group slug, call `GET /group/<slug>`.
3. Use `GET /group/<slug>` index `0` for group metadata and infrastructure locations.
4. Use `GET /group/<slug>` index `1` for victim posts.
5. Enrich each group with `GET /crypto/<group>` when wallet data is available.

This keeps the processor entirely on the public API surface we validated live, and still mirrors the `ransomware_live` pattern of creating one ransomware-group-centric bundle.

### Public-only processor design

Because RansomLook's export endpoints are private, the recommended V1 processor should avoid them completely.

The public-only implementation model is:

- seed the run from `GET /posts?days=<n>`
- deduplicate `group_name` values
- normalize each `group_name` into the group slug used by `GET /group/<slug>`
- fetch `GET /group/<slug>` for each group
- optionally fetch `GET /crypto/<group>` for the same slug

Tradeoffs of the public-only design:

- pros:
  - no private API dependency
  - sufficient data for `intrusion-set`, `incident`, `url`, and `cryptocurrency-wallet`
  - enough structure for a useful first processor
- cons:
  - no bulk historical export
  - actor coverage is likely limited or unavailable
  - structured victim country/sector/domain enrichment may be absent

### Timestamp handling

Based on the public docs and glossary:

- post discovery timestamps should drive `incident.created`
- the highest seen source timestamp for an entity should drive `modified`
- if a source object has no timestamp, fall back to processor run time

Because the public docs do not currently publish full response schemas, exact field names for some timestamps must be confirmed during implementation against authenticated payloads.

## Mapping

#### Imported objects

The processor should import the shared feeds2stix marking definition:

`https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json`

#### Source Identity

An identity should be hardcoded for the feed:

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<UUIDV5>",
  "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "created": "2020-01-01T00:00:00.000Z",
  "modified": "2020-01-01T00:00:00.000Z",
  "name": "RansomLook",
  "description": "Open-source ransomware and data-extortion intelligence covering groups, victim posts, actors, infrastructure, ransom notes, leaks, and cryptocurrency wallets.",
  "identity_class": "system",
  "contact_information": "https://www.ransomlook.io/",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Identity `id` should be generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`.

#### Marking definition

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

Marking definition `id` should be generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### Intrusion Set

Each ransomware group should be represented as an `intrusion-set`.

RansomLook's glossary defines a group as a ransomware or data-extortion collective, and group pages expose details such as description, RaaS status, affiliates, and locations. The current draft mapping is:

```json
{
  "type": "intrusion-set",
  "spec_version": "2.1",
  "id": "intrusion-set--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED IDENTITY>",
  "created": "<processor run time or earliest group timestamp>",
  "modified": "<latest group timestamp>",
  "name": "<group.name>",
  "description": "<group.description>",
  "aliases": ["<group.slug>", "<other aliases when present>"],
  "resource_level": "organization",
  "primary_motivation": "organizational-gain",
  "goals": [
    "extortion",
    "data theft",
    "ransomware deployment"
  ],
  "labels": [
    "ransomware",
    "data-extortion",
    "raas"
  ],
  "external_references": [
    {
      "source_name": "ransomlook",
      "url": "https://www.ransomlook.io/group/<group.slug>",
      "external_id": "<group.slug>"
    }
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

`intrusion-set.id` should be generated using namespace `<UUID OF FEED MARKING DEF>` and a stable group key such as `group.slug` if present, else `group.name.lower()`.

Notes:

- `labels` like `raas` should only be included when the source marks the group as RaaS.
- `goals` are a draft design choice derived from RansomLook's glossary and may be omitted if the team prefers stricter source fidelity.

#### Victim Identity

Each victim post should create or reuse an `identity` object for the targeted organisation.

```json
{
  "type": "identity",
  "spec_version": "2.1",
  "id": "identity--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED IDENTITY>",
  "created": "<post.discovered>",
  "modified": "<latest post timestamp for this victim>",
  "name": "<post.post_title or normalized victim name>",
  "identity_class": "organization",
  "sectors": ["<mapped sector when present>"],
  "contact_information": "<victim domain when present>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

`identity.id` should be generated using namespace `<UUID OF FEED MARKING DEF>` and a stable victim key. Preferred order:

1. explicit victim ID from source, if present
2. normalized victim domain
3. normalized victim name

#### Incident

Each victim post should become an `incident`.

RansomLook's glossary defines a victim/post as a single entry published by a group and associated with one group and one discovery timestamp. That maps well to one STIX `incident` per post.

```json
{
  "type": "incident",
  "spec_version": "2.1",
  "id": "incident--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED IDENTITY>",
  "created": "<post.discovered>",
  "modified": "<post.discovered or latest post update timestamp>",
  "name": "<victim name> claimed by <group name>",
  "description": "<post description or excerpt when present>",
  "first_seen": "<post.discovered>",
  "external_references": [
    {
      "source_name": "ransomlook",
      "url": "https://www.ransomlook.io/post/<post id or slug>",
      "external_id": "<post id>"
    }
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

`incident.id` should be generated using namespace `<UUID OF FEED MARKING DEF>` and a stable post key such as `<group_slug>:<post_id>` or `<group_slug>:<post_url>`.

#### URL SCO

RansomLook tracks multiple kinds of group infrastructure, including DLS, file servers, chats, admin panels, and relays. Each distinct URL should become a `url` SCO.

```json
{
  "type": "url",
  "spec_version": "2.1",
  "id": "url--<GENERATED BY STIX2 LIB>",
  "value": "<location.url>"
}
```

Recommended labeling behavior:

- keep infrastructure type on the relationship `description` or `labels`
- avoid encoding DLS/FS/chat/admin directly into the SCO beyond the URL value

#### Cryptocurrency Wallet SCO

RansomLook exposes crypto address data by group. Each address should become a `cryptocurrency-wallet` SCO.

```json
{
  "type": "cryptocurrency-wallet",
  "spec_version": "2.1",
  "id": "cryptocurrency-wallet--<UUIDV5 OR PRODUCER LOGIC>",
  "address": "<wallet.address>",
  "currency_type": "<chain or asset symbol>"
}
```

If additional enrichment is present, such as transaction counts or chain labels, it can be carried in:

- `labels`
- `external_references`
- a custom property if the team already has a preferred extension pattern

#### Threat Actor

RansomLook has a distinct actor model and actor-to-group relations. Each actor should become a `threat-actor`.

```json
{
  "type": "threat-actor",
  "spec_version": "2.1",
  "id": "threat-actor--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED IDENTITY>",
  "created": "<processor run time or actor timestamp>",
  "modified": "<latest actor timestamp>",
  "name": "<actor.name>",
  "aliases": ["<actor.aliases>"],
  "threat_actor_types": ["crime-syndicate"],
  "roles": ["affiliate", "developer", "broker", "admin"],
  "external_references": [
    {
      "source_name": "ransomlook",
      "url": "https://www.ransomlook.io/actor/<actor.slug or name>",
      "external_id": "<actor.slug or name>"
    }
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

Notes:

- `roles` should only be populated when the source clearly distinguishes them.
- if actor type is unknown, use `threat_actor_types: ["unknown"]` as done elsewhere in the repo.

#### Ransom Note

When a public `/notes/<family>` page exists, each note file on that page should become a STIX `note` SDO.

```json
{
  "type": "note",
  "spec_version": "2.1",
  "id": "note--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED IDENTITY>",
  "created": "<processor run time>",
  "modified": "<processor run time>",
  "abstract": "<filename>",
  "content": "<full ransom note text>",
  "object_refs": [
    "intrusion-set--<group id>"
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

Recommended ID strategy:

- generate `note.id` using namespace `<UUID OF FEED MARKING DEF>` and value `<group slug>:<filename>:<content hash>`

Recommended extraction behavior:

- use the note filename as `abstract`
- use the full note body as `content`
- create one `note` object per note file shown on the page
- attach the corresponding `intrusion-set` in `object_refs`
- optionally extract any onion or clearnet URLs from the note body as `url` SCOs if the team wants note-derived infrastructure pivots in V2

#### Location

When a victim country is present in post data, it should resolve to a CTI Butler `location` object using the same country-normalization pattern already used by processors like `phishunt`.

#### Relationships

##### Intrusion Set -> URL (`uses`)

Each group infrastructure URL should be linked back to the group:

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--<UUIDV5>",
  "relationship_type": "uses",
  "source_ref": "intrusion-set--<group id>",
  "target_ref": "url--<location id>",
  "description": "<location type: dls|fs|chat|admin|relay>",
  "created": "<group timestamp>",
  "modified": "<group timestamp>"
}
```

##### Intrusion Set -> Cryptocurrency Wallet (`uses`)

Each ransom wallet should be linked to the group with `uses`.

##### Incident -> Intrusion Set (`attributed-to`)

Each victim post incident should be linked to the claiming group with `attributed-to`.

##### Incident -> Identity (`targets`)

Each incident should link to the victim organization with `targets`.

##### Intrusion Set -> Identity (`targets`)

This relationship is optional but recommended for direct group-to-victim pivoting across bundles.

##### Identity -> Location (`located-in`)

When victim country is available, link victim identity to the resolved country `location`.

##### Threat Actor -> Intrusion Set (`associated-with`)

For each actor relation to a group, create an `associated-with` relationship.

## Bundle strategy

Recommended output pattern:

- one bundle per group, matching the current `ransomware_live` operational shape
- each bundle contains:
  - source identity
  - source marking definition
  - feeds2stix marking definition
  - one `intrusion-set`
  - related `incident` objects for that group
  - deduplicated victim `identity` objects
  - related `location` objects
  - group infrastructure `url` objects
  - group `cryptocurrency-wallet` objects
  - related `threat-actor` objects
  - all connecting relationships

Alternative:

- date-based bundles for very large post volumes

The group-bundle pattern is the closer fit to the current ransomware processors in this repo.

## Remaining questions before implementation

The public surface is now well enough understood to narrow these down substantially:

1. `group_name` from `GET /posts` appears to map directly to `GET /group/<slug>` when URL-encoded, with no additional slug-normalization required.
   - validated examples include:
     - `coinbase cartel` -> `/group/coinbase%20cartel`
     - `inc ransom` -> `/group/inc%20ransom`
     - `eraleign (apt73)` -> `/group/eraleign%20%28apt73%29`
   - a live check across sampled groups from `GET /posts?days=2` returned HTTP `200` for each URL-encoded `group_name`

2. Victim posts have a stable deterministic key in the public group response: the relative `link` field `/post/<hash>`.
   - the hash component is suitable as the incident source key
   - however, direct navigation to `/post/<hash>` returned HTTP `404` during validation, so the hash should be treated as a stable identifier, not necessarily a resolvable public URL

3. Victim country, sector, and domain do not appear as structured fields on the public post objects.
   - `post_title` is often a domain-like string and can often serve as the best public victim-domain hint
   - `description` frequently contains free-text country and sector clues such as "company in Turkey" or industry descriptions
   - the public group page embeds the same victim-post data in a `posts-data` JSON script block, but still without dedicated structured fields for country or sector

4. Public actor coverage is available via HTML pages, not the documented API endpoint.
   - `GET /api/actor/<name>` returned HTTP `404` in validation
   - public actor pages such as `/actor/LockBitSupp` and `/actor/bassterlord` exist
   - those pages expose useful structured HTML, including:
     - linked group relations
     - linked market/forum relations
     - optional biographical fields such as first and last name
   - this means actor support is possible in a public-only processor, but via HTML scraping rather than API JSON

5. Leaks and ransom notes are publicly reachable and parseable, while markets remain less certain.
   - leaks:
     - `/leaks` publicly lists `/leak/<id>` links
     - `/leak/1` returned compact JSON with fields like `id`, `name`, and nested `group` metadata
   - ransom notes:
     - `/notes` publicly lists family pages such as `/notes/krybit`
     - `/notes/krybit` returned public HTML containing note bodies in `<pre class="note-body">`
   - markets:
     - public actor pages link to `/market/<name>` paths
     - a dedicated market schema was not validated in this round

### Recommended V1 boundary after public validation

Recommended in V1:

- groups -> `intrusion-set`
- victim posts -> `incident`
- victims -> `identity`
- infrastructure -> `url`
- crypto -> `cryptocurrency-wallet`
- core relationships

Reasonable but optional in V1:

- actors via public HTML scraping from `/actor/<name>`
- ransom notes via public `/notes/<family>` pages

Better deferred to V2 unless explicitly needed:

- leaks
- markets/forums

The reason to defer those is not lack of public access, but scope control: the public data is there, but it adds a second collection model beyond the core group/post processor.

## Suggested V1 scope

To keep the first implementation aligned with existing design patterns, V1 should focus on:

- groups -> `intrusion-set`
- posts -> `incident`
- victims -> `identity`
- group infrastructure -> `url`
- group crypto -> `cryptocurrency-wallet`
- core relationships only

Optional only when validated from public data:

- victim country -> `location`
- actor profiles -> `threat-actor`

This keeps the processor close to `ransomware_live`, while still capturing the richer infrastructure model that makes RansomLook distinct, without depending on private API access.
