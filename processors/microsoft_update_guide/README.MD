## MSRC Security Update Guide

This feed posts new vulnerabilities

https://api.msrc.microsoft.com/update-guide/rss

Note entries in the feeds can be duplicates (see below)

All we need to do is create a feed from Vulmatch bundle (import ONLY `vulnerability` object).

Each record in the feed looks like

```xml
    <item
      Revision="1.0000000000">
      <guid
        isPermaLink="false">CVE-2026-26030</guid>
      <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030</link>
      <category>CVE</category>
      <title>CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable</title>
      <description>[CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) is a Remote Code Execution vulnerability that has been identified in Microsoft Semantic Kernel Python SDK, specifically within the InMemoryVectorStore filter functionality. GitHub created this CVE on their behalf. GitHub created this CVE on their behalf. This document incorporates updates in the Microsoft Semantic Kernel Repository which address this vulnerability.

Please see [CVE-2026-26030](https://www.cve.org/CVERecord?id=CVE-2026-26030) for more information.</description>
      <pubDate>Tue, 10 Mar 2026 07:00:00 -0700</pubDate>
    </item>
    <item
      Revision="1.1000000000">
      <guid
        isPermaLink="false">CVE-2026-26030</guid>
      <link>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26030</link>
      <category>CVE</category>
      <title>CVE-2026-26030 GitHub: CVE-2026-26030 Microsoft Semantic Kernel InMemoryVectorStore filter functionality vulnerable</title>
      <description>Acknowledgement added. This is an informational change only.</description>
      <pubDate>Thu, 12 Mar 2026 07:00:00 -0700</pubDate>
    </item>
```

For duplicate entries, we should make sure we limit to `Revision=1.0`, subsequent entries do not usually add any relevant info, other than to advise of an update.

Note, this feed is quite large and stores a large amount of entries. This means updates can be run once per day.

### STIX Mapping

We should include the feed data as we do with all feeds.

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
    "statement": "Origin: https://api.msrc.microsoft.com/update-guide/rss"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### Note

To represent the MSRC data we should attach a Note to the Vulnerability (thus must exist in Vulmatch)

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
      "source_name": "msrc",
      "url": "<link>"
    },
    {
      "source_name": "vulmatch",
      "url": "<vulmatch link>"
    }
  ]
}
```