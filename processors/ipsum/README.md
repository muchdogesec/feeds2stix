## IPSum

Daily feed of bad IPs (categorised by scores) https://github.com/stamparm/ipsum

Categories are between 1: lots of false positives - 8: no false positives. You can configure this setting when running the connector.

## Data generation

### Feed info

8 feeds categoriesed into levels in the format

```
https://raw.githubusercontent.com/stamparm/ipsum/master/levels/<LEVEL>.txt
```

e.g.

```
https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt
```

Updated everyday at around 0100 everyday UTC.

The command line should give an option to rule `category_score` (between `1` - `8`) which determines feed 

### Mapping

#### Imported objects

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json

#### Identity

An identity is hardcoded for the feed 

```json
{
	"type": "identity",
	"spec_version": "2.1",
	"id": "identity--9d7266e0-e0e7-529a-a840-7df15fb8fcf2",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"created": "2020-01-01T00:00:00.000Z",
	"modified": "2020-01-01T00:00:00.000Z",
	"name": "IPSum",
	"description": "IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses. All lists are automatically retrieved and parsed on a daily (every 24 hours) basis and the final result is pushed to this repository. The feed contains IP addresses plus an occurrence count (how many source lists each IP appears on). Higher counts generally mean higher confidence and fewer false positives when blocking inbound traffic. Also, list is sorted by occurrence count (highest to lowest).",
	"identity_class": "system",
	"contact_information": "https://github.com/stamparm/ipsum",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`

#### IPv4

```json
{
	"type": "ipv4-addr",
	"spec_version": "2.1",
	"id": "ipv4-addr--UUID",
	"value": "<IP IN LIST>"
}
```

#### Indicator

```json
{
	"type": "indicator",
	"spec_version": "2.1",
	"id": "indicator--<UUID V5>",
	"created_by_ref": "identity--9d7266e0-e0e7-529a-a840-7df15fb8fcf2",
	"created": "<SCRIPT RUN TIME>",
	"modified": "<SCRIPT RUN TIME>",
	"valid_from": "<SCRIPT RUN TIME>",
	"confidence": "<VALUE>",
	"indicator_types": [
		"malicious-activity"
	],
	"name": "<TYPE>: <VALUE>",
	"description": "[<PATTERN>]",
	"pattern": "<ENTIRE SIGMA RULE YAML>",
	"pattern_type": "stix",
	"external_references": [
		{
			"source_name": "IPSum",
			"url": "https://github.com/stamparm/ipsum"
		}
	],
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`

The `confidence` value depends on the feed category used * 10 (e.g. if feed 8 used, confidence will be `80`)

## Github action

The processor should also be linked to a Github action that downloads data from the feed every 24 hours (after feed update schedule)

The issue with this feed is `created` and `modified` times are not included in the feed.

To solve this we need a GitHub action that has a CTX API key to see if object exists.

If run in Github action mode, the script will do an additional check

1. see if indicator exists in feed
2. if:
	* false: normal behaviour
	* true: indicator / sco not submitted