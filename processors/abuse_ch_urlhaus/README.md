



## Data schema

```
###############################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)      #
# Last updated: 2026-02-26 12:05:20 (UTC)                      #
#                                                              #
# Terms Of Use: https://urlhaus.abuse.ch/api/                  #
# For questions please contact urlhaus [at] abuse.ch           #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3786237","2026-02-26 12:05:20","http://182.126.120.150:58801/i","online","2026-02-26 12:05:20","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3786237/","geenensp"
"3786236","2026-02-26 11:54:17","http://222.138.150.74:43262/i","online","2026-02-26 11:54:17","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3786236/","geenensp"
"3786235","2026-02-26 11:51:29","http://117.216.147.208:50583/bin.sh","online","2026-02-26 11:51:29","malware_download","32-bit,elf,mips","https://urlhaus.abuse.ch/url/3786235/","geenensp"
"3786234","2026-02-26 11:49:11","http://222.141.137.34:50034/i","online","2026-02-26 11:49:11","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3786234/","geenensp"
"3786233","2026-02-26 11:37:20","http://27.37.27.82:43810/i","online","2026-02-26 11:37:20","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3786233/","geenensp"
"3786232","2026-02-26 11:35:21","http://59.93.18.59:55942/i","online","2026-02-26 11:35:21","malware_download","32-bit,elf,mips","https://urlhaus.abuse.ch/url/3786232/","geenensp"
"3786231","2026-02-26 11:30:24","http://113.239.221.37:48028/i","offline","","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3786231/","geenensp"
"3786230","2026-02-26 11:30:11","http://222.138.150.74:43262/bin.sh","online","2026-02-26 11:30:11","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3786230/","geenensp"
"3786229","2026-02-26 11:26:09","https://pub-462189601a584e8fad4889d4ed31f4f4.r2.dev/Zoom%20Setup.exe","online","2026-02-26 11:26:09","malware_download","None","https://urlhaus.abuse.ch/url/3786229/","juroots"
"3786228","2026-02-26 11:26:06","https://www.dropbox.com/scl/fi/xkf95lbdgtxjofs4uem8c/ZoomApp_agent_x64_s-i-__fca21db2bb0230ee251a503b021fe02d2114d1f0.msi?rlkey=zvmjseot8z5gyzj6s0eu01myp&st=h0ulds3h&dl=1","offline","","malware_download","None","https://urlhaus.abuse.ch/url/3786228/","juroots"
```

## Mapping

#### Imported objects

https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/marking-definition/feeds2stix.json
https://raw.githubusercontent.com/muchdogesec/stix4doge/refs/heads/main/objects/identity/dogesec.json

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
		"statement": "Origin data source: https://urlhaus.abuse.ch/downloads/csv_recent/"
	},
	"object_marking_refs": [
		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
	]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`