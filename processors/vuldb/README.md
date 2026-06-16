## VulDB

This feed posts new vulnerabilities

https://vuldb.com/rss/recent

All we need to do is create a feed from Vulmatch bundle (import ONLY `vulnerability` object).

Each record in the feed looks like

```xml
<item>
<title>CVE-2026-11438 | theonedev up to 15.0.5 /projects project.forkedFromId improper authorization (EUVD-2026-34973)</title>
<link>https://vuldb.com/vuln/369018</link>
<guid isPermaLink="true">https://vuldb.com/vuln/369018</guid>
<pubDate>Sat, 06 Jun 2026 00:26:13 +0200</pubDate>
<dc:creator>vuldb.com</dc:creator>
<description><![CDATA[A vulnerability was found in <a href="https://vuldb.com/product/theonedev:onedev">theonedev onedev up to 15.0.5</a>. It has been classified as <a href="https://vuldb.com/kb/risk">critical</a>. Affected by this vulnerability is an unknown functionality of the file <em>/projects</em>. The manipulation of the argument <em>project.forkedFromId</em> leads to improper authorization.

This vulnerability is uniquely identified as <a href="https://vuldb.com/cve/CVE-2026-11438">CVE-2026-11438</a>. The attack is possible to be carried out remotely. No exploit exists.

Upgrading the affected component is recommended.]]></description>
<category><![CDATA[Vendor: theonedev]]></category>
<category><![CDATA[Product: onedev]]></category>
<category><![CDATA[Risk: critical]]></category>
<category><![CDATA[Physical: No]]></category>
<category><![CDATA[Local: No]]></category>
<category><![CDATA[Remote: Yes]]></category>
<category><![CDATA[Exploit: No]]></category>
<category><![CDATA[Countermeasures: Upgrade]]></category>
</item>
```

There are two challenges in the design of this

1. Need to parse the CVE ID logically. I think we can do this inside the `<title>` but needs validation
2. The harder problem is that this data usually exists before Vulmatch has it (Vulmatch published 24-48 hours later). The feed also publishes 100's of results a day, but the feed only ever contains 100 items.

### Dealing with problem 2

We need to poll the feed every hour.

We should only add records for CVEs that exist in Vulmatch (and not attempt to create them)

Which means we need to store CVEs in artefacts that do not match on Vulmatch, to be rerun on the next command.

Essentially we should keep rerunning old CVEs indexed from the feed to VM until a response is returned.

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
  "name": "VulDB",
  "description": "VulDB stands for Vulnerability Database. We are curating and documenting all security vulnerabilities that got published in electronic products. We are one of the most important sources for people responsible for handling vulnerabilities, vulnerability management, exploit analysis, cyber threat intelligence, and incident response handling.",
  "identity_class": "system",
  "contact_information": "https://vuldb.com/",
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
    "statement": "Origin: https://vuldb.com/rss/recent"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking Definition `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### Note

To represent the VulDB data we should attach a Note to the Vulnerability (thus must exist in Vulmatch)

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
  "labels": [
  	"<CATEGORY[N]"
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ],
  "external_references": [
    {
      "source_name": "cve",
      "url": "<NVD LINK>",
      "external_id": "CVE-XXXX-YYYZZ",
    },
    {
      "source_name": "vuldb",
      "url": "<link>"
    },
  ]
}
```

## Usage

```bash
python processors/vuldb/vuldb.py path/to/vuldb-cve-list.json
```

The argument is a persistent JSON file mapping CVE IDs to the parsed RSS item that first introduced them. Each run reads the file, appends CVE IDs parsed from `https://vuldb.com/rss/recent`, fetches CVEs from Vulmatch in chunks of 50, removes found CVEs from the map, and writes the unresolved map back to disk.

The processor uses the VulDB RSS item `pubDate` timestamp for VulDB `note` objects. Vulnerability objects are imported from Vulmatch and are not created from the RSS feed directly.

## Output

The processor writes STIX bundles to `outputs/vuldb/bundles/vuldb_part_NNN.json`.

The updated unresolved CVE map is written to `outputs/vuldb/data/vuldb-cve-list.json` for upload as the `vuldb-cve-list` workflow artifact.

## GitHub Action

The processor is intended to run hourly and resume unresolved CVEs from the latest `vuldb-cve-list` artifact.

### Required Configuration

**Secrets:**
- `CTX_BASE_URL`
- `CTX_API_KEY`
- `VULMATCH_BASE_URL`
- `VULMATCH_API_KEY`

**Variables:**
- `VULDB_FEED_ID`
- `MAX_BUNDLE_SIZE_KB`

### Workflow inputs

- `target_environment`: choose `all`, `staging`, or `production` for manual runs
