## MSRC Security Update Guide

## Overview

MSRC Security Update Guide publishes Microsoft vulnerability intelligence from the official MSRC RSS feed and converts it into STIX 2.1.

**Feed:** https://api.msrc.microsoft.com/update-guide/rss

This processor is dated and keeps an unresolved CVE list so CVEs that are not yet in Vulmatch can be retried on later runs. It only processes `Revision="1.0"` items. Higher revisions are skipped because they are usually editorial updates rather than new vulnerability records.

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `note`

**Imported objects:**
- `vulnerability` from Vulmatch

## Data source

Each RSS item looks like this:

```xml
<item Revision="1.0000000000">
  <guid isPermaLink="false">CVE-2026-26030</guid>
  <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030</link>
  <category>CVE</category>
  <title>CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable</title>
  <description>[CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) is a Remote Code Execution vulnerability. Please see [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) for more information.</description>
  <pubDate>Tue, 10 Mar 2026 07:00:00 -0700</pubDate>
</item>
```

The CVE ID is taken from `<guid>`.

The `description` field is Markdown, so Markdown links are extracted and written to the Note object as `external_references`. The plain text description is kept as the Note `content`.

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
  "name": "MSRC Security Update Guide",
  "description": "The Microsoft Security Response Center (MSRC) investigates all reports of security vulnerabilities affecting Microsoft products and services, and provides the information here as part of the ongoing effort to help you manage security risks and help keep your systems protected.",
  "identity_class": "system",
  "contact_information": "https://msrc.microsoft.com/update-guide/",
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
    "statement": "Origin: https://api.msrc.microsoft.com/update-guide/rss"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` is generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### Note

To represent the MSRC data we attach a Note to the Vulnerability, so the CVE must already exist in Vulmatch.

```json
{
  "type": "note",
  "spec_version": "2.1",
  "id": "note--<UUIDV5>",
  "created": "<pub_date>",
  "modified": "<pub_date>",
  "abstract": "<title>",
  "object_refs": ["vulnerability--<ID>"],
  "content": "<description>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ],
  "external_references": [
    {
      "source_name": "cve",
      "url": "<NVD LINK>",
      "external_id": "CVE-XXXX-YYYYY",
    }
    {
      "source_name": "msrc",
      "url": "<link>"
    },
    {
      "source_name": "msrc",
      "url": "<markdown link>"
    },
    {
      "source_name": "vulmatch",
      "url": "<vulmatch link>"
    }
  ]
}
```

## Usage

```bash
python processors/microsoft_update_guide/microsoft_update_guide.py path/to/missing_cve_list.json
```

The argument is a persistent JSON file mapping CVE IDs to the parsed RSS item that first introduced them. Each run reads the file, appends CVEs parsed from the MSRC RSS feed, fetches Vulmatch vulnerabilities in chunks of 50, removes found CVEs from the map, and writes the unresolved map back to disk.

The processor uses the MSRC RSS item `pubDate` timestamp for Note timestamps. Vulnerability objects are imported from Vulmatch and are not created from the RSS feed directly.

## Output

The processor writes STIX bundles to `outputs/microsoft_update_guide/bundles/msrc_part_NNN.json`.

The updated unresolved CVE map is written to `outputs/microsoft_update_guide/data/missing_cve_list.json` and uploaded as the `msrc-missing-cve-list` workflow artifact.

## GitHub Action

The processor is intended to run daily and resume unresolved CVEs from the latest `msrc-missing-cve-list` artifact.

### Required Configuration

**Secrets:**
- `CTX_BASE_URL`
- `CTX_API_KEY`
- `VULMATCH_BASE_URL`
- `VULMATCH_API_KEY`

**Variables:**
- `MSRC_FEED_ID`
- `MAX_BUNDLE_SIZE_KB`

### Workflow inputs

- `target_environment`: choose `all`, `staging`, or `production` for manual runs
