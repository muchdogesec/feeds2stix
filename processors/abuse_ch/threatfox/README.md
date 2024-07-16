# threatfox

## tl;dr logic of the script

The script works like so

1. Downloads the data from `https://threatfox.abuse.ch/export/csv/full/`
2. reads the body of the response, only considering CLI argument values entered by user
3. for user entered malware entry or first unique malware entry identified in csv, turns the entries found in the csv into STIX objects (as described in this doc). STIX objects are stored to the filesystemstore in `bundles/abuse_ch/threatfox/stix2_objects`.
4. the created objects are packaged in a STIX 2.1 bundle
5. If no `malware` value passed to cli, script moves back to step 3 to next malware object until all malwares are covered

Note this script can handle updates to data in a graceful way. Because a copy of all STIX `bundles/abuse_ch/threatfox/stix2_objects` is stored the script does not need to process all data on each run. On update runs the script will only consider data greater than the highest `modified` time for the malware specified.

## Overview

> ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs) associated with malware with the infosec community, AV vendors and threat intelligence providers.

https://threatfox.abuse.ch/

## Data source

https://threatfox.abuse.ch/export/csv/full/

## Data schema

```
################################################################
# ThreatFox IOCs: additions - CSV format (full dump)           #
# Last updated: 2024-07-16 06:45:19 UTC                        #
#                                                              #
# Terms Of Use: https://threatfox.abuse.ch/faq/#tos            #
# For questions please contact threatfox [at] abuse.ch         #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter"
"2024-07-16 06:45:19", "1301611", "http://rocheholding.top/rudolph/five/fre.php", "url", "botnet_cc", "win.lokipws", "Burkina,Loki,LokiBot,LokiPWS", "Loki Password Stealer (PWS)", "2024-07-16 08:11:39", "75", "https://bazaar.abuse.ch/sample/d5a6b19ed0cb225a61c510bff2f2713b3a69435527f41fbb83d4e8343effaa13/", "lokibot", "0", "abuse_ch"
"2024-07-16 05:25:36", "1301610", "8.134.12.90:7777", "ip:port", "botnet_cc", "win.cobalt_strike", "Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "", "100", "None", "CobaltStrike,cs-watermark-987654321", "0", "abuse_ch"
"2024-07-16 05:25:35", "1301609", "172.245.184.135:8888", "ip:port", "botnet_cc", "win.cobalt_strike", "Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "", "100", "None", "CobaltStrike,cs-watermark-987654321", "0", "abuse_ch"
"2024-07-16 05:25:34", "1301608", "91.208.73.75:82", "ip:port", "botnet_cc", "win.cobalt_strike", "Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "", "100", "None", "CobaltStrike,cs-watermark-100000", "0", "abuse_ch"
"2024-07-16 05:25:33", "1301606", "8.223.20.63:443", "ip:port", "botnet_cc", "win.cobalt_strike", "Agentemis,BEACON,CobaltStrike,cobeacon", "Cobalt Strike", "", "100", "None", "CobaltStrike", "0", "abuse_ch"
[...more records...]
# Number of entries: 1217668
```

Where `[...more records...]` is more rows removed for brevity here.

The last row should be ignored.

The results of this file are sorted by `first_seen_utc` in descending day order. The results inside a day are not necessarily in the time order. e.g. results will always be in order `2024-07-16`, `2024-07-15`, `2024-07-14`, etc. but could be in order `2024-07-16 06:45:19`, `2024-07-16 08:11:39`, `2024-07-16 05:25:36`

## Data Normalisation

Note `last_seen_utc` does not always have a value in the input CSV, in which case it inherits `first_seen_utc`

## STIX objects

### Imported objects:

* marking-definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json
* identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json

### Generated object mappings

#### Marking Definition

This is hardcoded and never changes;

```json
{
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--865d4e5d-f46d-4908-b2ab-50a8f227be07",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "2020-01-01T00:00:00.000Z",
    "definition_type": "statement",
    "definition": {
        "statement": "Origin data source: https://threatfox.abuse.ch/export/csv/full/"
    },
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ]
}
```

#### Observables 

For each unique `ioc_value` entry, observables can be created as follows;

##### ioc_type=ip:port

If `ioc_type=ip:port` then the `ioc_value` is split at the `:` character. The left part is the `ipv4-addr` the right part is the `network-traffic` port.

```json
{
	"type": "ipv4-addr",
	"spec_version": "2.1",
	"id": "ipv4-addr--<GENERATED BY STIX2 LIB>",
	"value": "<ioc_value>"
}
```

```json
{
	"type": "network-traffic",
	"spec_version": "2.1",
	"id": "network-traffic--<GENERATED BY STIX2 LIB>",
	"dst_ref": "<CORRESPONDING IPV4 ADDR OBJECT>",
	"dst_port": "<ioc_value>",
	"protocols": [
		"<SEE DICTIONARY IN NOTES>"
	]
}
```

For `protocols`, if `DstPort` =

* `80` then = [`http`, `tcp`]
* `443` then = [`ssl`, `tcp`]
* any other value then = [`tcp`]

##### ioc_type=url

```json
{  
	"type": "url",
	"spec_version": "2.1",
	"id": "url--<GENERATED BY STIX2 LIB>",
	"value": "<ioc_value>"
}
```

##### ioc_type=domain

```json
{
	"type": "domain-name",
	"spec_version": "2.1",
	"id": "domain-name--<GENERATED BY STIX2 LIB>",
	"value": "<ioc_value>"
}
```

##### ioc_type=md5_hash

```json
{
	"type": "file",
	"spec_version": "2.1",
	"id": "file--<GENERATED BY STIX2 LIB>",
	"hashes": {
		"MD5": "<ioc_value>"
	}
}
```

##### ioc_type=sha256_hash

```json
{
	"type": "file",
	"spec_version": "2.1",
	"id": "file--<GENERATED BY STIX2 LIB>",
	"hashes": {
		"SHA-256": "<ioc_value>"
	}
}
```

#### Malware

For each unique `malware_printable` entry a Malware objects is created as follows;

```json
{
	"type": "malware",
	"spec_version": "2.1",
	"id": "malware--<UUIDV5>",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
	"created": "Earliest <first_seen_utc> for all observables linked to this malware",
	"modified": "Latest <last_seen_utc> for all observables linked to this malware",
	"name": "<malware_printable>",
	"malware_types": [
		"unknown"
	],
	"aliases": [
		"<all unique malware_alias for observables linked to this malware as a list>"
	],
	"is_family": true,
	"sample_refs": [
		"<ALL STIX FILE OBJECTS CREATED FOR MALWARE>"
	],
	"labels": [
		"all unique tags for observables linked to this malware as a list"
	],
	"external_references": [
		{
			"source_name": "threatfox_malware",
			"external_id": "<threatfox_malware>"
	    },
	],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--865d4e5d-f46d-4908-b2ab-50a8f227be07",
        "marking-definition--418465b1-2dbe-41b7-b994-19817164e793"
    ]
}
```

Note `<last_seen_utc>` might be `null` for all observables. In which case it is replaced with `first_seen_utc` so `modified` time can be populated.

UUIDv5 is generated using namespace `865d4e5d-f46d-4908-b2ab-50a8f227be07` and `name` value

#### Indicators 

Each row has a `reference` and `reporter` value. All observables with the same `malware_printable` , `reference` and `reporter` are grouped and an Indicator objects is created as follows...

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<UUIDV5>",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "Earliest <first_seen_utc> for all observables linked to this indicator",
    "modified": "Latest <last_seen_utc> for all observables linked to this indicator",
    "indicator_types": [
    	"malicious-activity"
    ],
    "name": "<malware_printable>",
    "pattern": "<STIX PATTERN FOR EACH SCO LINKED TO MALWARE AND FROM THIS REFERENCE/REPORTED JOINED WITH OR OPERATORS>",
    "pattern_type": "stix",
    "valid_from": "Same as `created` value",
    "labels": [
        "all unique tags for observables linked to this malware as a list"
    ],
	"confidence": "highest <confidence_level> for all observables linked to this indicator",
	"external_references": [
	 	{
			"source_name": "threatfox_reporter",
			"external_id": "<reporter>"
	    },
	 	{
			"source_name": "threatfox_reference",
			"external_id": "<reference[n]>"
	    }
	],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--865d4e5d-f46d-4908-b2ab-50a8f227be07",
        "marking-definition--418465b1-2dbe-41b7-b994-19817164e793"
    ]
  }
```

UUIDv5 is generated using namespace `865d4e5d-f46d-4908-b2ab-50a8f227be07` and `name` and `external_references.external_id` (where `external_references.source_name==threatfox_reporter`
 
Note `<last_seen_utc>` might be `null` for all observables returned. In which case it is replaced with `first_seen_utc` so `modified` time can be populated.

Each indicator created is then linked to the malware objects like so;

```json
{
	"type": "relationship",
	"spec_version": "2.1",
	"id": "relationship--<Indicator UUID>",
	"created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "<INDICATOR CREATED TIME>",
    "modified": "<INDICATOR MODIFIED TIME>",
    "relationship_type": "detects",
    "source_ref": "indicator--<ID>",
    "target_ref": "malware--<ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--865d4e5d-f46d-4908-b2ab-50a8f227be07",
        "marking-definition--418465b1-2dbe-41b7-b994-19817164e793"
    ]
}
```

UUIDv5 is generated using namespace `865d4e5d-f46d-4908-b2ab-50a8f227be07` and `source_ref+target_ref`

And each object listed in the pattern of the Indicator is linked to it like so;

```json
{
	"type": "relationship",
	"spec_version": "2.1",
	"id": "relationship--<UUIDV5>",
    "created": "<first_seen_utc> value for target_ref observable",
    "modified": "<last_seen_utc> value for target_ref observable",
    "relationship_type": "detects",
    "source_ref": "indicator--<ID>",
    "target_ref": "<OBJECT_ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--865d4e5d-f46d-4908-b2ab-50a8f227be07",
        "marking-definition--418465b1-2dbe-41b7-b994-19817164e793"
    ]
}
```

UUIDv5 is generated using namespace `865d4e5d-f46d-4908-b2ab-50a8f227be07` and `source_ref+target_ref`

All the generated objects are placed into STIX bundles in the directory `bundles/abuse_ch/threatfox`.

A bundle is per malware `name`;

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5>",
    "objects": [
        "ALL STIX OBJECTS CREATED"
    ]
}
```

The UUID is generated using the namespace `865d4e5d-f46d-4908-b2ab-50a8f227be07` and an md5 of all the sorted objects in the bundle.

Any `(` and `)` characters in the `name` value are removed before saving the bundle filename. All `-` characters are replaced with `_`

## Run the script

```shell
python3 processors/abuse_ch/threatfox/threatfox.py --malware "NAME" --update
```

Where:

* `malware` (optional, dictionary): the name is the `malware_printable` value to filter on
    * default is all
* `update` (optional): if passed will search for the highest `modified` time in the malware objects that match the input. The script will identify if any new data has been added since `modified` and script run time for that malware. If true, then the new observables will be added, and indicator/malware/bundle updated / added to reflect changes.

e.g. 

```shell
python3 processors/abuse_ch/threatfox/threatfox.py --malware "NjRAT"
```

Would only process results for `NjRAT`.