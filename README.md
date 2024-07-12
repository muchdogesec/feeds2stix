# feeds2stix

## Overview

A set of scripts that take data from threat intelligence feeds and converts it into STIX 2.1 objects.

The aim of this repository is to make it easy for anyone to get structured cyber threat intelligence into downstream tools.

## Structure of this repository

The key parts of this repository are structured as follows;

```txt
.
├── processors/
│   ├── producer1/
│   │	├── README.md # describes the mapping of the feed.py files
│   │	├── feed1.py
│   │   └── feed2.py
│   └── producer2/
│    	├── README.md
│    	└── feed1.py 
└── bundles/
    ├── producer1/
    │	├── feed1
    │	│	├── bundle1.json # multiple bundles can be produced for a single feed (e.g. seperated by threat actor)
    │	│	└── bundle2.json
    │	└── feed2
    │		├── bundle1.json
    │		└── bundle2.json
    └── producer2/
     	└── feed1
    		└── bundle1.json
```

The `processors` directory contains the scripts that generate the data. These scripts output the data into the `bundles` directory.

## Adding new processors

Installing the script

To install crypto2stix;

```shell
# clone the latest code
git clone https://github.com/muchdogesec/feeds2stix
# create a venv
cd feeds2stix
python3 -m venv feeds2stix-venv
source feeds2stix-venv/bin/activate
# install requirements
pip3 install -r requirements.txt
```

## Support

[Minimal support provided via the DOGESEC community](https://community.dogesec.com/).

## Licenses

* Code: [AGPLv3](/LICENSE).
* Content: [Creative Commons Attribution 4.0 International Public License](/LICENSE-CONTENT)