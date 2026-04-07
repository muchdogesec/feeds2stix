# abuse.ch threatfox

## Overview

> ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs) associated with malware with the infosec community, AV vendors and threat intelligence providers.

https://threatfox.abuse.ch/

## Data source

For first run: https://threatfox.abuse.ch/export/csv/full/
For subsequent updates: https://threatfox.abuse.ch/export/csv/recent/

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

## Mapping

#### Imported objects

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json

#### Identity

An identity is hardcoded for the feed 

```json
{
	"type": "identity",
	"spec_version": "2.1",
	"id": "identity--<UUIDV5>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"created": "2020-01-01T00:00:00.000Z",
	"modified": "2020-01-01T00:00:00.000Z",
	"name": "abuse.ch",
	"description": "abuse.ch has been effecting change on cybercrime for almost twenty years, owing to global recognition of our identified and tracked cyber threat signals. Supported by a community of 15,000 specialist researchers, abuse.ch’s independent intelligence is relied on by security researchers, network operators and law enforcement agencies.",
	"identity_class": "organization",
	"contact_information": "https://abuse.ch/",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`

#### Marking Definition

This is hardcoded and never changes;

```json
{
	"type": "marking-definition",
	"spec_version": "2.1",
	"id": "marking-definition--<UUIDV5>",
	"created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
	"created": "2020-01-01T00:00:00.000Z",
	"definition_type": "statement",
	"definition": {
		"statement": "Origin data source: https://threatfox.abuse.ch/export/csv/recent/"
	},
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`

#### Observables

Various types of observable exist;

URL
IP+Port
Domain
sha256_hash
md5_hash

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

UUID generated by STIX2 library

With relationship to Indicator (for ip+port, both objects linked to indicator):

```json
{
	"type": "relationship",
	"spec_version": "2.1",
	"id": "relationship--<UUID V5>",
	"created_by_ref": "identity--<UUID OF FEED ID>",
	"created": "<first_seen_utc>",
	"modified": "<first_seen_utc>",
	"relationship_type": "indicates",
	"source_ref": "indicator--<UUID>",
	"target_ref": "<TYPE>--<UUID>",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
		"marking-definition--<UUID OF FEED MARKING DEF>"
	]
}
```

UUIDv5 uses namespace `<UUID OF FEED MARKING DEF>` and value `source_ref+target_ref`

#### Malware

For each unique `malware_printable` entry a Malware objects is created as follows;

```json
{
	"type": "malware",
	"spec_version": "2.1",
	"id": "malware--<UUIDV5>",
    "created_by_ref": "identity--<UUID OF FEED ID>",
	"created": "Earliest <first_seen_utc> for all observables linked to this malware",
	"modified": "Latest <last_seen_utc> for all observables linked to this malware",
	"name": "<malware_printable>",
	"malware_types": [
		"remote-access-trojan <IF NAME ENDS IN RAT>"
		"adware <IF NAME STARTS WITH Adware.>",
		"ransomware <IF NAME STARTS WITH Ransomware.>",
		"worm <IF NAME STARTS WITH Worm.>",
		"unknown <IF NOT MATCHES ANY OTHER TYPE>"
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
			"source_name": "malpedia",
			"external_id": "https://malpedia.caad.fkie.fraunhofer.de/details/<fk_malware>"
	    }
	],
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
		"marking-definition--<UUID OF FEED MARKING DEF>"
    ]
}
```

Note `<last_seen_utc>` might be `null` for all observables. In which case it is replaced with `first_seen_utc` so `modified` time can be populated.

UUIDv5 is generated using namespace `<UUID OF FEED MARKING DEF>` and `name` value

#### Indicators 

For each row (aka SCO) an indicator is creted

```json
{
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<UUIDV5>",
    "created_by_ref": "identity--<UUID OF FEED ID>",
    "created": "Earliest <first_seen_utc> for all observables linked to this indicator",
    "modified": "Latest <last_seen_utc> for all observables linked to this indicator",
    "indicator_types": [
    	"malicious-activity"
    ],
    "name": "<malware_printable>",
    "pattern": "<STIX PATTERN",
    "pattern_type": "stix",
    "valid_from": "Same as `created` value",
    "confidence": "<confidence_level>",
    "labels": [
        "all unique tags for observables linked to this malware as a list"
    ],
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
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
		"marking-definition--<UUID OF FEED MARKING DEF>"
    ]
  }
```

UUIDv5 is generated using namespace `<UUID OF FEED MARKING DEF>` and `name` and `external_references.external_id` (where `external_references.source_name==threatfox_reporter`
 
Note `<last_seen_utc>` might be `null` for all observables returned. In which case it is replaced with `first_seen_utc` so `modified` time can be populated.

Each indicator created is then linked to the malware objects like so;

```json
{
	"type": "relationship",
	"spec_version": "2.1",
	"id": "relationship--<Indicator UUID>",
	"created_by_ref": "identity--<UUID OF FEED ID>",
	"created": "<MALWARE CREATED TIME>",
	"modified": "<MALWARE MODIFIED TIME>",
	"relationship_type": "indicates",
	"source_ref": "indicator--<ID>",
	"target_ref": "malware--<ID>",
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
		"marking-definition--<UUID OF FEED MARKING DEF>"
	]
}
```

UUIDv5 is generated using namespace `<UUID OF FEED MARKING DEF>` and `source_ref+target_ref`


## Run the script

Fadl todo