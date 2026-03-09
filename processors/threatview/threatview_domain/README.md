# ThreatView Domain

https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt

Not sure of update schedule.

Contains a list of domains

## Mapping

#### Imported objects

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json

#### Identity

An identity is hardcoded for the feed 

```json
{
	"type": "identity",
	"spec_version": "2.1",
	"id": "identity--<UUID>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"created": "2020-01-01T00:00:00.000Z",
	"modified": "2020-01-01T00:00:00.000Z",
	"name": "ThreatView",
	"description": "Verified threat feeds for immediate perimeter enforcement across security stacks.",
	"identity_class": "organization",
	"contact_information": "https://threatview.io/",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`

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
		"statement": "Origin: https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt"
	},
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`

#### Domain

```json
{
	"type": "domain",
	"spec_version": "2.1",
	"id": "domain--<UUID>",
	"hashes": "<VALUE>"
}
```

UUID generate by STIX2 lib.

With relationship to Indicator:

```json
{
	"type": "relationship",
	"spec_version": "2.1",
	"id": "relationship--<UUID V5>",
	"created_by_ref": "identity--<UUID OF FEED ID>",
	"created": "<SCRIPT RUN FIRST SEEN DATE>",
	"modified": "<SCRIPT RUN FIRST SEEN DATE>",
	"relationship_type": "indicates",
	"source_ref": "indicator--<UUID>",
	"target_ref": "domain--<UUID>",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
		"marking-definition--<UUID OF FEED MARKING DEF>"
	]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`

#### Indicator

```json
{
	"type": "indicator",
	"spec_version": "2.1",
	"id": "indicator--<UUID V5>",
	"created_by_ref": "identity--<UUID OF FEED ID>",
	"created": "<SCRIPT RUN FIRST SEEN DATE>",
	"modified": "<SCRIPT RUN FIRST SEEN DATE>",
	"valid_from": "<SCRIPT RUN FIRST SEEN DATE>",
	"indicator_types": [
		"malicious-activity"
	],
	"name": "Domain: <VALUE>",
	"pattern": "[domain:value='<VALUE>']",
	"pattern_type": "stix",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
		"marking-definition--<UUID OF FEED MARKING DEF>"
	]
}
```

Identity `id` generated using namespace `<UUID OF FEED MARKING DEF>` and value `name`

## Usage

```bash
python processors/threatview/threatview_domain/threatview_domain.py
```

No command-line options are available. The script downloads the live feed and creates a single STIX bundle.

TODO Fadl