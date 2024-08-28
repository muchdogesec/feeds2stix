# Wallet Explorer

## Overview

![](processors/abuse_ch/wallet_explorer/wallet_explorer.png)

Wallet Explorer tags crypto wallets that belongs to crypto exchanges, marketplaces and other online platforms used for crypto transactions.

By tracking down the platform that handled a transaction (identified using the wallet address in a transaction), it is often possible to track it down to an individual who received the funds the transaction (by getting a court order for the exchange to release information about the person who signed up).

## Running the script

```shell
python3 processors/wallet_explorer/wallet_explorer.py \
    --record_url value1,value2 \
    --process_wallets BOOLEAN
```

where; 

* `--record_url` (optional, string): will only download data for the specific records passed. [Values can be obtained from the `record_url` column in the sheet here](https://docs.google.com/spreadsheets/d/1hF76TV48LLjmgZ80aFl5CpWWn4geQkQM50EUcYqAQyY/edit?usp=sharing).
* `--process_wallets` if this flag is passed, all wallets that belong to the exchange (known by Wallet Explorer) will be created as Cryptocurrency Wallet objects

e.g

Create all record identity/location objects

```shell
python3 processors/wallet_explorer/wallet_explorer.py
```

Create for `Bittrex.com` and `Huobi.com` identity/location objects

```shell
python3 processors/wallet_explorer/wallet_explorer.py \
    --record_url Bittrex.com,Huobi.com
```

Create for `Btc38.com` identity/location objects, and download all the wallets known to be owned by `Btc38.com`

```shell
python3 processors/wallet_explorer/wallet_explorer.py \
    --process_wallets \
    --record_url Btc38.com
```

## How it works

### Wallet Explorer data

Wallet Explorer provides a variety of API endpoints

* Get wallet addresses for an entity (e.g. exchange)
    * e.g. http://www.walletexplorer.com/api/1/wallet-addresses?wallet=Huobi.com&from=0&count=100&&caller=https://github.com/muchdogesec/feeds2stix
* Get transaction details
    * e.g. http://www.walletexplorer.com/api/1/tx?txid=99fd988bf60ff67847488ceeb76d08a8fcca7bde80bb0b06be2ef4a0055c3ba7&from=0&count=100&&caller=https://github.com/muchdogesec/feeds2stix
* Get wallet details
    * e.g. http://www.walletexplorer.com/api/1/address?address=14hSMo1zBP4JE5r8soe3mmbhowrXdjHT8J&from=0&count=100&caller=https://github.com/muchdogesec/feeds2stix

I have normalised this in the sheet:

https://docs.google.com/spreadsheets/d/1hF76TV48LLjmgZ80aFl5CpWWn4geQkQM50EUcYqAQyY/edit?usp=sharing

Which this script downloads to make API requests to wallet explorer.

### Download the data

First download the spreadsheet temporarily from


Using [gdown](https://pypi.org/project/gdown/3.3.1/)

e.g. 

```shell
gdown 1hF76TV48LLjmgZ80aFl5CpWWn4geQkQM50EUcYqAQyY
```

### Convert to STIX objects

The data in the spreadsheet then uses the STIX2 python library to create STIX objects (using the filesystem) in a directory named `stix2_objects` as follows;

At a high-level the graph of STIX objects created is as follows;

https://miro.com/app/board/uXjVKwqZNss=/

#### Automatically imported objects

* feeds2stix: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json
* feeds2stix: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json

#### Identity (for each exchange)

```json
{
	"type": "identity",
	"spec_version": "2.1",
	"id": "identity--<UUIDV5>",
	"created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
	"created": "<record_created>",
	"modified": "<record_modified>",
	"name": "<exchange_name>",
	"description": "<exchange_description>",
	"sectors": [
		"financial-services",
		"technology"
	],
  	"identity_class": "organization",
  	"contact_information": "<exchange_url>",
  	"object_marking_refs": [
  		"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
  	],

}
```

The UUIDv5 is generated using the namespace and the `name` value.

#### Location (for each exchange)

Each location has a `exchange_country` which is a two digit country code.

In `lookups/locations-bundle.json` is a list of STIX location objects ([this comes from location2stix](https://github.com/muchdogesec/location2stix/)).

That look as follows;

```json
{
    "type": "bundle",
    "id": "bundle--d8af807c-1238-5432-ba34-8bdd759f99e1",
    "objects": [
        {
            "type": "location",
            "spec_version": "2.1",
            "id": "location--e68e76c5-60f1-506e-b495-86adb8ec0a5b",
            "created_by_ref": "identity--674a16c1-8b43-5c3e-8692-b3d8935e4903",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "name": "United States of America",
            "region": "northern-america",
            "country": "US",
            "external_references": [
                {
                    "source_name": "alpha-3",
                    "external_id": "USA"
                },
                {
                    "source_name": "iso_3166-2",
                    "external_id": "ISO 3166-2:US"
                },
                {
                    "source_name": "country-code",
                    "external_id": "840"
                }
            ],
            "object_marking_refs": [
                "marking-definition--674a16c1-8b43-5c3e-8692-b3d8935e4903",
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ]
        },
```

Where the correct country object for the `exchange_country` can be found in `objects.country` property.

#### Relationship (between exchange and country)

To link the `location` to the `identity` a STIX relationship object is created as follows

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "<IDENTITY CREATED PROPERTY>",
    "modified": "<IDENTITY MODIFIED PROPERTY>",
    "relationship_type": "located-in",
    "description": "<IDENTITY OBJECT NAME> is located in <LOCATION NAME>",
    "source_ref": "identity--<IDENTITY ID>",
    "target_ref": "location-<LOCATION ID>",
    "object_marking_refs": [
    	"marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ]
}
```

The UUIDv5 is generated using the namespace and the `<relationship_type>+<source_ref>+<target_ref>` value.

#### Cryptocurrency wallet

Each `<exchange_url>` can be looked up against the Wallet Explorer API to find out what wallets are owned by the exchange. This makes it possible to identity what transactions went through an exchange (because the transaction will contain a wallet belonging to the exchange).

The requests take the format

```
http://www.walletexplorer.com/api/1/wallet-addresses?wallet=<exchange_url>&from=<FROM>&count=100&caller=https://github.com/muchdogesec/feeds2stix
```

Where;

* `<exchange_url>` is the exchange url shown in the spreadsheet
* `<FROM>` is the first record you want. This is useful where more than one page of results exists (`count=100` limits results to 100 each time). So to page through responses, you can increase this value by 100 each time.

e.g.

```
http://www.walletexplorer.com/api/1/wallet-addresses?wallet=Huobi.com&from=0&count=100&caller=https://github.com/muchdogesec/feeds2stix
```

Returns a response like;

```json
{"found":true,"label":"Huobi.com","wallet_id":"000012a55e988d91","addresses_count":29242,"addresses":[{"address":"19hx1B4pTDsBAYJJYYrj1t6bcVw1e9omuH","balance":6.420352701097727,"incoming_txs":9,"last_used_in_block":797138},{"address":"16vyeuwbuNz9PKPs4VqqGLsVRJ2G6uJj39","balance":2.5335204117000103,"incoming_txs":39,"last_used_in_block":341241},{"address":"12uuCfvuxeyGhWaEU1sHTbkCN7eWMT7qFp","balance":2.335349418222904,"incoming_txs":5,"last_used_in_block":400520},{"address":"1NMbcRqggWu75DG5AqZtin5kecdHoDVs3b","balance":2.0997000001370907,"incoming_txs":6,"last_used_in_block":326727},{"address":"1DgcQFeaCQBo41oxtzUuV3caW5TNjXvhLZ","balance":1.0000060014426708,"incoming_txs":12,"last_used_in_block":797160},{"address":"16K4VtKNxcaNkvNvDYiiWjyn1n49irJ8Ep","balance":1,"incoming_txs":4,"last_used_in_block":332425},{"address":"1FDpmBztMAUvR1Q4JJeb2FnA4VUxUAAtmd","balance":0.5384000018239021,"incoming_txs":2,"last_used_in_block":302565},{"address":"1ko9cGfFxWoUMMZ3MsxuSjRHfLDNgyjr9","balance":0.51773551851511,"incoming_txs":274,"last_used_in_block":513005},{"address":"1MnkzcBw8prYASnMiJ772ApcEsn1tFtn1A","balance":0.21000000089406967,"incoming_txs":48,"last_used_in_block":469487},{"address":"1CXrs7piiUdDXG1nT8jk43GWqCtPpbQbYu","balance":0.18304554000496864,"incoming_txs":248,"last_used_in_block":848439},{"address":"17WQqNZafGZWWa1zW4LaJ1h7S7qKKER8as","balance":0.043125029653310776,"incoming_txs":675,"last_used_in_block":500473},{"address":"14zzx8PWeXULMp11NmFdk3yuTabME6naBN","balance":0.03245963156223297,"incoming_txs":13,"last_used_in_block":306636},{"address":"1H8casG2e6keyjVGoQeh21oE2UJCtXECSL","balance":0.019999999552965164,"incoming_txs":7,"last_used_in_block":412764},{"address":"1JHsjazLvtpW6MC3AppTK8FtDU79mKeJDg","balance":0.015166301280260086,"incoming_txs":106,"last_used_in_block":323286},{"address":"18FVW8RUVnoHwBGFkRFsf9kyAHJcrcbiuS","balance":0.008999999612569809,"incoming_txs":4,"last_used_in_block":298865},{"address":"1F3GeJi6VesFMkaUF9o81vtJFkTdCs59bC","balance":0.008516181260347366,"incoming_txs":45,"last_used_in_block":397696},{"address":"1NMwkFzhkPRdK1XCH8dKxWmsCDCFFmx8Rq","balance":0.006358109414577484,"incoming_txs":45,"last_used_in_block":508325}],"updated_to_block":857064}
```

You need to keep paging until 0 `addresses` are returned. e.g.

```json
{"found":true,"label":"Huobi.com","wallet_id":"000012a55e988d91","addresses_count":29242,"addresses":[],"updated_to_block":857064}
```

You can they use [stix2extensions](https://github.com/muchdogesec/stix2extensions/) to create `cryptocurrency-wallet` objects from this data.

In the format;

```json
{
    "type": "cryptocurrency-wallet",
    "spec_version": "2.1",
    "id": "cryptocurrency-wallet--<ID GENERATED BY CODE>",
    "address": "<addresses.address>",
    "exchange_ref": "<THE IDENTITY OBJECT OF THE EXCHANGE IN SEARCH)",
    "extensions": {
        "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
            "extension_type": "new-sco"
        }
    }
}
```

Here is an example of how this can be done

```shell
pip3 install https://github.com/muchdogesec/stix2extensions/
```

```python
import uuid
import stix2
import os
import shutil

from uuid import UUID

from stix2extensions.cryptocurrency_wallet import CryptocurrencyWallet
from stix2extensions.cryptocurrency_exchange import CryptocurrencyExchange
# create the directories

tmp_directories = [
    "tmp_object_store",
]

for directory in tmp_directories:
    if not os.path.exists(directory):
        os.makedirs(directory)

# define UUID for generating UUIDv5s -- this is the OASIS namespace for SCOs https://github.com/oasis-open/cti-python-stix2/blob/master/stix2/base.py#L29

namespace=UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Create CryptocurrencyWallet SCO

example_CryptocurrencyWalletSCO = CryptocurrencyWallet(
                    id="cryptocurrency-wallet--"+ str(uuid.uuid5(namespace, f"1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY")),
                    address="1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY",
                    exchange_ref="cryptocurrency-exchange--1ee9d44a-c962-59b5-adbf-e47cb3f03b92",
                    )

print(example_CryptocurrencyWalletSCO)
```

#### Create a STIX bundle of all objects

feeds2stix also creates a STIX 2.1 Bundle JSON object containing all the other STIX 2.1 Objects created at each run. The Bundle takes the format;

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5 GENERATION LOGIC>",
    "objects": [
        "<ALL STIX JSON OBJECTS>"
    ]
}
```

The UUID is generated using the namespace and the base64 encoded value of the cli of all objects sorted in the bundle.

The bundle is named; `wallet_explorer_bundle.json`

```txt
.
└── bundles/
    └── wallet_explorer/
        ├── bundles
        │   └── wallet_explorer_bundle.json   
        └── stix2_objects
            ├── cryptocurrency-wallet
            ├── identity
            ├── location
            ├── marking-definition
            └── relationship
```

## Tools that inspired us

* [Chainabuse: Report malicious crypto activity, covers much more than just ransomware (e.g. blackmail)](https://www.chainabuse.com/)
* [ransomwatch trails the extortion sites used by ransomware groups and surfaces an aggregated feed of claims](https://ransomwatch.telemetry.ltd/#/)
* [ransomware.live Another Ransomware gang tracker, also contains ransom notes](https://www.ransomware.live/)
* [A resource containing all the tools each ransomware gangs uses](https://github.com/BushidoUK/Ransomware-Tool-Matrix)
* [Ransomwhere is the open, crowdsourced ransomware payment tracker, includes wallet and transaction info](https://ransomwhe.re/)
    * a better API for Ransomwhere: https://www.opensanctions.org/datasets/ransomwhere/

## More advance commercial alternatives

* https://platform.arkhamintelligence.com/explorer/entity/lazarus-group
* https://metasleuth.io/result/eth/0xf3701f445b6bdafedbca97d1e477357839e4120d
    * https://blocksecteam.medium.com/metasleuth-how-to-use-metasleuth-to-analyze-a-phishing-attack-b525caac14c5
    * https://github.com/blocksecteam/metasleuth_resources
    * https://docs.metasleuth.io/tutorials/crypto-tracking-starting-with-a-transaction
* https://www.ransom-db.com/

## Other good crypto intel resources

* [Ransomware power ranking (similar to Gartner style grpahs) by Halcyon](https://www.halcyon.ai/top-ransomware-groups)
* https://twitter.com/zachxbt?s=11&t=kWkJgiFyqEQ-15ldAcQtsA
* https://twitter.com/realscamsniffer?s=11&t=kWkJgiFyqEQ-15ldAcQtsA
* https://github.com/OffcierCia/Crypto-OpSec-SelfGuard-RoadMap
* https://github.com/aaarghhh/awesome_osint_criypto_web3_stuff
* https://start.me/p/RM1EKa/cryptocurrency-investigations
* https://start.me/p/onEm1Y/07-finint-cryptocurrency
* https://start.me/p/kx5DJ9/cryptocurrency-osint
* https://www.aware-online.com/en/osint-tools/cryptocurrency-tools/
* https://github.com/OffcierCia/On-Chain-Investigations-Tools-List
* https://start.me/p/QRg5ad/officercia
* https://www.web3isgoinggreat.com
* https://hacked.slowmist.io
* https://cryptopanic.com
* https://twitter.com/tayvano_
* https://twitter.com/zachxbt
* https://solidityscan.com/web3hackhub

## Thanks to...

Thanks to http://www.walletexplorer.com/ who let us use their API to link exchanges to wallets. Without this data, we'd have to use expensive services like Chainanalysis (which do have more data) for the underlying data.

## Useful supporting tools

* [Insert this date into a ArangoDB for analysis using stix2arango](https://github.com/muchdogesec/stix2arango/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)