# ransomwhere2stix

## Overview

> Ransomwhere is the open, crowdsourced ransomware payment tracker. Transparency is crucially needed in assessing the spread of ransomware and the efficacy of mitigations. Fortunately, due to the transparent nature of Bitcoin, it's easy to track payments with knowledge of receipt addresses. By crowdsourcing ransomware payment addresses, we hope to provide an open resource for the security community and the public.

[ransomwhe.re](https://ransomwhe.re/#about)

The data is reported by Ransomwhere is in a custom JSON format. To ensure easy integration with downstream tooling ransomwhere2stix converts the response of Ransomwhere into STIX 2.1 Objects.

## Run the script

```shell
python3 processors/ransomwhere/ransomwhere.py \
  --family <NAME>
```

Where; 

* `family`: is the name of the malware family. Must match the family name reported by ransomwhe.re. You can obtain these on [ransomwhe.re](https://ransomwhe.re/). e.g. `BlackCat`

## The data

The data reported by Ransomwhere is available via there API:

https://api.ransomwhe.re/export

Note:

> To protect victims and prevent abuse, addresses will be made public 90 days after being submitted.

A response from the API takes the following structure;

```json
{
  "result": [
    {
      "address": "17TMc2UkVRSga2yYvuxSD9Q1XyB2EPRjTF",
      "balance": 126686348,
      "blockchain": "bitcoin",
      "createdAt": "2021-07-08T06:43:08.978Z",
      "transactions": [
        {
          "hash": "cfb39d98f66da8bfe42ad86894f116a3c1d8c6d1189456fcffae615a80623c49",
          "time": 1587839053,
          "amount": 43577930,
          "amountUSD": 3298.82142637708
        },
        {
          "hash": "81748bb90b4ca5bb4ecc643f17744adcf9d560752d632bdeef7daac49b0c8233",
          "time": 1587165185,
          "amount": 83108418,
          "amountUSD": 5897.5267344871
        }
      ],
      "updatedAt": "2021-09-22T20:53:57.424Z",
      "family": "Netwalker (Mailto)",
      "balanceUSD": 9196.34816086418
    },
    {
      "address": "1Kcwserp7KqSMYBDe6Ra5atHP6xWbQPBnD",
      "balance": 22686185461,
      "blockchain": "bitcoin",
      "createdAt": "2021-07-08T06:43:10.267Z",
      "transactions": [
        {
          "hash": "62bb9a02cbf0480a23d1384c171fc56d819558e6e2cfa7026cc991b4c89b6186",
          "time": 1595803514,
          "amount": 1039703595,
          "amountUSD": 102984.377306577
        },
        {
          "hash": "35935ceb9c6ed049b1bea7fdd6bd97b6d67ec75027371a02bbc611c0c26eeed4",
          "time": 1594799546,
          "amount": 5632831999,
          "amountUSD": 517817.059307676
        },
        {
          "hash": "8cac82f680d413c75a48936fe70104627618fd0af551cf0fdb37825965dd1150",
          "time": 1594737740,
          "amount": 4386436703,
          "amountUSD": 405447.725598874
        },
        {
          "hash": "3368057184a4875d6bf4b18fbd99289554fa92b36bb7be348d8fbcb21b4d68ce",
          "time": 1594670593,
          "amount": 3430887548,
          "amountUSD": 317138.010562875
        },
        {
          "hash": "bbfd9ba91fcc3ecf68f3972d9647319673ba167935ec697062a519a2e906752d",
          "time": 1594416504,
          "amount": 2849925680,
          "amountUSD": 264439.121074679
        },
        {
          "hash": "fbbb4d6797ee5cd9fdb748a678a05ef5dbef3c52ceaf55d08900391ec542b1cf",
          "time": 1594227769,
          "amount": 2628399936,
          "amountUSD": 247814.298748139
        },
        {
          "hash": "5c9c89a5e016bd5dbcedef96486f7e419b76cb917a277d072d5d5214c1029728",
          "time": 1594008231,
          "amount": 2718000000,
          "amountUSD": 254825.39987262
        }
      ],
      "updatedAt": "2021-09-22T20:53:59.751Z",
      "family": "Netwalker (Mailto)",
      "balanceUSD": 2110465.99247144
    },
    {
      "address": "1GuPsTqJjib8t2idTaLwa95kRLtiWhrE5A",
      "balance": 16074062261,
      "blockchain": "bitcoin",
      "createdAt": "2021-07-08T06:43:10.314Z",
      "transactions": [
        {
          "hash": "3f7184bc30444cc3d390626af1b1afe5dab8b762ee63badff19f102ad944e3c1",
          "time": 1591296250,
          "amount": 20699,
          "amountUSD": 2.02863379446581
        },
        {
          "hash": "941428d32d36d7643d6d61220490b6f48e25d4dbb26a78240d2a104021a102bd",
          "time": 1591280483,
          "amount": 16074041562,
          "amountUSD": 1575358.41955269
        }
      ],
      "updatedAt": "2021-09-22T20:54:00.070Z",
      "family": "Netwalker (Mailto)",
      "balanceUSD": 1575360.44818649
    }
  ]
}
```

[The structure of the responses can also be reviewed in the code for the site](https://github.com/cablej/ransomwhere/tree/main/backend/model).

Essentially Ransomwhere is tracking ransomware payments to wallet addresses that Malware is using when executed.

The relevant data for ransomwhere2stix:

* each `address` is associated with a `family` (the Malware family).
* each `address` has a list of transactions showing the `hash` of the transaction and the `amount` in the `blockchain` specified

### Some notes

**Malware wallet relationships**

The wallets are linked to Malware and not Actors in this database. That means many bad actors might be using a malware family specified (but we don't know what actor owns what wallet). This is where future improvements could be made to this script by looking up actors linked to a wallet and modelling actors in this graph too.

## STIX 2.1 data mapping

We model the data in STIX 2.1 as follows;

https://miro.com/app/board/uXjVKwqZNss=/

Here is the detail...

### Automatically imported objects

* Cryptocurrency Transaction Extension Definition: https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/scos/cryptocurrency-transaction.json
* Cryptocurrency Wallet Extension Definition: https://raw.githubusercontent.com/muchdogesec/stix2extensions/main/extension-definitions/scos/cryptocurrency-wallet.json
* feeds2stix_identity: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/marking-definition/feeds2stix.json
* feeds2stix_marking_definition: https://raw.githubusercontent.com/muchdogesec/stix4doge/main/objects/identity/feeds2stix.json

### Wallets

For every distinct `address` returned by the API a `cryptocurrency-wallet` is created

```json
{
    "type": "cryptocurrency-wallet",
    "spec_version": "2.1",
    "id": "cryptocurrency-wallet--<UUID V5>",
    "address": "<DISTINCT ADDRESS FROM API>",
    "extensions": {
        "extension-definition--be78509e-6958-51b1-8b26-d17ee0eba2d7": {
            "extension_type": "new-sco"
        }
    }
}
```

The UUID is generated using the namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` (OASIS STIX namespace) and the `address` value.

### Transaction

For every distinct `transaction` returned by the API a `cryptocurrency-transaction` is created

```json
{
    "type": "cryptocurrency-transaction",
    "spec_version": "2.1",
    "id": "cryptocurrency-transaction--<UUID v5>",
    "symbol": "<blockhain> CONVERTED",
    "hash": "<transactions.hash>",
    "execution_time": "<transactions.time> CONVERTED",
    "output": [
        {
            "address_ref": "cryptocurrency-wallet--<ADDRESS OF STIX WALLET OBJECT>",
            "amount": "<transactions.amount> / 100000000"
        },
        {
            "address_ref": "cryptocurrency-wallet--<ADDRESS OF STIX WALLET OBJECT>",
            "amount": "<transactions.amount> / 100000000"
        }
    ],
    "extensions": {
        "extension-definition--151d042d-4dcf-5e44-843f-1024440318e5": {
            "extension_type": "new-sco"
        }
    }
}
```

Note, 

* `<transactions.time>` needs to be converted from epoch
* `<blockhain>` needs to be converted from name to 3 digit currency identification code
    * currently `blockchain` values are always Bitcoin which are converted to `BTC`
* one or more `output`s might exist where the transaction sends money from a source wallet to one or more destination objects

The UUID is generated using the namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` (OASIS STIX namespace) and the `hash` value.

### Malware

For every distinct `family` a STIX Malware object is created

```json
{
  "type": "malware",
  "spec_version": "2.1",
  "id": "malware--<UUID V5>",
  "created_by": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
  "created": "<EARLIEST CRYPTOCURRENCY TRANSACTION RELATED TO FAMILY>",
  "modified": "<EARLIEST CRYPTOCURRENCY TRANSACTION RELATED TO FAMILY>",
  "name": "<FAMILY>",
  "malware_types": ["ransomware"],
  "is_family": true,
  "object_marking_refs": [
      "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
  ],
  "external_references": [
    {
      "source_name": "mitre-attack",
      "url": "https://attack.mitre.org/groups/<attack_id for malware name>",
      "external_id": "<attack_id for malware name>"
    }
  ]
}
```

The UUID is generated using the namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and the `name` value.

Note, not all Malware objects have `external_references`. Only the following that are linked to ATT&CK

|ransomwhere_name  |created_stix_object_id                       |attack_stix_id                               |attack_id|
|------------------|---------------------------------------------|---------------------------------------------|---------|
|SynAck            |malware--987f4ce2-d51d-55d0-a6e1-00c6d9adfe71|malware--04227b24-7817-4de1-9050-b7b1b57f5866|S0242    |
|WannaCry          |malware--9a7e0dbf-69aa-56b4-a644-03d26f464bb8|malware--75ecdbf1-c2bb-4afc-a3f9-c8da4de8c661|S0366    |
|NotPetya          |malware--05cf1494-f682-5262-8368-e9dffebd4485|malware--5719af9d-6b16-46f9-9b28-fb019541ddbb|S0368    |
|SamSam            |malware--08a2bbbe-b987-5da1-874f-92673cd06bd6|malware--4d56e6e9-1a6d-46e3-896c-dfdf3cc96e62|S0370    |
|Ryuk              |malware--b4a7bb88-4385-5073-81e5-d2010e1b116a|malware--a020a61c-423f-4195-8c46-ba1d21abba37|S0446    |
|Netwalker (Mailto)|malware--6749fd15-fb86-5cef-a222-3794a0611efb|malware--754effde-613c-4244-a83e-fb659b2a4d06|S0457    |
|REvil / Sodinokibi|malware--c65911e3-77ab-5cc0-b7eb-2a4d9872458e|malware--ac61f1f9-7bb1-465e-9b8a-c2ce8e88baf5|S0496    |
|Egregor           |malware--d67e2148-ead4-5cdf-8a25-6d3e2fbec2f0|malware--cc4c1287-9c86-4447-810c-744f3880ec37|S0554    |
|Conti             |malware--797d9ae1-1b00-5621-8ed7-b973c790e13f|malware--4dea7d8e-af94-4bfb-afe4-7ff54f59308b|S0575    |
|HelloKitty        |malware--2b1afb53-3b4e-5c0f-8f3e-3af9dca00024|malware--5d11d418-95dd-4377-b782-23160dfa17b4|S0617    |
|Cuba              |malware--16c1cf00-43c6-520b-bbc4-a3f0b0db1c57|malware--6cd07296-14aa-403d-9229-6343d03d4752|S0625    |
|Avaddon           |malware--afb07690-b99d-519a-8cba-1bd1481751c9|malware--58c5a3a1-928f-4094-9e98-a5a4e56dd5f3|S0640    |
|AvosLocker        |malware--3012ffc1-a4e4-5f6a-b384-274afb782d12|malware--0945a1a5-a79a-47c8-9079-10c16cdfcb5d|S1053    |
|BlackCat          |malware--f471ae33-97e1-5a7d-9ad6-14f5d5c429a0|malware--50c44c34-3abb-48ae-9433-a2337de5b0bc|S1068    |
|Black Basta       |malware--5fcf9972-c2c1-5cee-9d45-735af16e6736|malware--8d242fb4-9033-4f13-8a88-4b9b4bcd9a53|S1070    |
|Akira             |malware--683edbcf-fb51-5b96-a205-fa2eb5740741|malware--6f6b2353-4b39-40ce-9d6d-d00b7a61e656|S1129    |


### Indicator

For every Malware object created, a corresponding Indicator object is created

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<RELATED MALWARE UUID>",
  "created_by": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
  "created": "<MALWARE CREATED TIME>",
  "modified": "<MALWARE MODIFIED TIME>",
  "name": "<MALWARE NAME> Cryptocurrency Wallets",
  "description": "Known Cryptocurrency Wallets associated with <MALWARE NAME>",
  "indicator_types": [
      "malicious-activity"
  ],
  "pattern": "[(cryptocurrency-wallet:<HASH> OR cryptocurrency-wallet:<HASH>)]",
  "pattern_type": "stix",
  "valid_from": "<CREATED TIME>",
  "object_marking_refs": [
      "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
      "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
  ]
}
```

The `pattern` contains all the `cryptocurrency-wallet` hash values that are related to the Malware.

The UUID is the same as that used for the `malware` object.

### Relationships

To create a graph structure, STIX SROs are used to link Indicator objects to the `cryptocurrency-wallet` found in their pattern property

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "<INDICATOR CREATED PROPERTY>",
    "modified": "<INDICATOR MODIFIED PROPERTY>",
    "relationship_type": "pattern-contains",
    "description": "<INDICATOR NAME> identifies <cryptocurrency-wallet address>",
    "source_ref": "indicator--<INDICATOR ID>",
    "target_ref": "cryptocurrency-wallet-<TRANSACTION ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ]
}
```

The UUID is generated using the namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and the value `<SOURCE_REF>+<TARGET_REF>`.

Indicator objects are also linked to their corresponding Malware object like so

```json
{
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<UUIDV5 GENERATION LOGIC>",
    "created_by_ref": "identity--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "created": "<MALWARE CREATED PROPERTY>",
    "modified": "<MALWARE MODIFIED PROPERTY>",
    "relationship_type": "detects",
    "description": "<INDICATOR NAME> detects <MALWARE NAME>",
    "source_ref": "indicator--<INDICATOR ID>",
    "target_ref": "malware-<MALWARE ID>",
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
    ]
}
```

The UUID is generated using the namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and the value `<SOURCE_REF>+<TARGET_REF>`.

### Bundle

This script outputs all the objects into a single STIX 2.1 bundle `bundles/ransomwhere/ransomwhere-bundle.json`

```json
{
    "type": "bundle",
    "id": "bundle--<UUIDV5>",
    "objects": [
        "ALL STIX OBJECTS CREATED"
    ]
}
```

The UUID is generated using the namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and the md5 hash of all objects sorted in the bundle.

## Output structure

```txt
.
└── bundles/
    └── ransomwhere/
        ├── bundles
        │   └── ransomwhere-bundle.json   
        └── stix2_objects
            ├── cryptocurrency-transaction
            ├── cryptocurrency-wallet
            ├── extension-definition
            ├── identity
            ├── indicator
            ├── malware
            ├── marking-definition
            └── relationship
```

## Thanks to...

Thanks to Jack Cable who created [ransomwhe.re](https://ransomwhe.re/) and decided to keep the data open. Without this, we would have to generate our own data collection techniques.

## Useful supporting tools

* To generate STIX 2.1 Objects: [stix2 Python Lib](https://stix2.readthedocs.io/en/latest/)
* The STIX 2.1 specification: [STIX 2.1 docs](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
* [Insert this date into a ArangoDB for analysis using stix2arango](https://github.com/muchdogesec/stix2arango/)
  * also see stix2arango-notes.md for how to do this / some useful queries