# Wallet Explorer

## Overview

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
    * e.g. http://www.walletexplorer.com/api/1/wallet-addresses?wallet=Huobi.com&caller=https://github.com/muchdogesec/feeds2stix
* Get transaction details
    * e.g. http://www.walletexplorer.com/api/1/tx?txid=99fd988bf60ff67847488ceeb76d08a8fcca7bde80bb0b06be2ef4a0055c3ba7&caller=https://github.com/muchdogesec/feeds2stix
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

https://miro.com/app/board/uXjVKotYvUg=/

#### Automatically imported objects

* feeds2stix: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json
* feeds2stix: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json

#### Identity (for each exchange)

```json
{
	"type": "identity",
	"spec_version": "2.1",
	"id": "identity--<UUIDV5>",
	"created_by_ref": "identity--9b9c892f-bab3-5be5-b3bf-d2b5c21775b7",
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
  		"marking-definition--9b9c892f-bab3-5be5-b3bf-d2b5c21775b7"
  		"marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
  	],

}
```

The UUIDv5 is generated using the namespace `9b9c892f-bab3-5be5-b3bf-d2b5c21775b7` and the `name` value.

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
    "created_by_ref": "identity--9b9c892f-bab3-5be5-b3bf-d2b5c21775b7",
    "created": "<IDENTITY CREATED PROPERTY>",
    "modified": "<IDENTITY MODIFIED PROPERTY>",
    "relationship_type": "located-in",
    "source_ref": "identity--<IDENTITY ID>",
    "target_ref": "location-<LOCATION ID>",
    "object_marking_refs": [
    	"marking-definition--9b9c892f-bab3-5be5-b3bf-d2b5c21775b7",
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    ]
}
```

The UUIDv5 is generated using the namespace `9b9c892f-bab3-5be5-b3bf-d2b5c21775b7` and the `<relationship_type>+<source_ref>+<target_ref>` value.

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

To generate the id of the SRO, a UUIDv5 is generated using the namespace `9b9c892f-bab3-5be5-b3bf-d2b5c21775b7` and `<MD5 HASH OF THE SORTED OBJECTS PAYLOAD IN BUNDLE JSON>`.

The bundle is named; `wallet_explorer_bundle.json`

## Thanks to...

Thanks to http://www.walletexplorer.com/ who let us use their API to link exchanges to wallets. Without this data, we'd have to use expensive services like Chainanalysis (which do have more data) for the underlying data.

## Useful supporting tools

* [Insert this date into a ArangoDB for analysis using stix2arango](https://github.com/muchdogesec/stix2arango/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)