# PromptIntel

## Overview

PromptIntel is a collaborative threat-intelligence platform focused on adversarial prompts, agent abuse patterns, and AI misuse detection.

**Feed URL:** https://api.promptintel.novahunting.ai/api/v1/prompts  
**Update Schedule:** Continuous API updates (workflow runs every 6 hours)  
**Format:** JSON prompt records

**Note:** This is a dated processor. `--since-date` and `--until-date` filter records using source `created_at` timestamps.

**STIX Objects Created:**
- `identity`
- `marking-definition`
- `ai-prompt`
- `indicator`
- `file`
- `threat-actor`
- `course-of-action`
- `relationship`

**Relationships:**
- `indicator` -> `ai-prompt` (`indicates`)
- `indicator` -> `file` (`indicates`)
- `indicator` -> `threat-actor` (`related-to`)
- `course-of-action` -> `indicator` (`mitigates`)
- `indicator` -> `attack-pattern` (`indicates`) for inferred ATLAS techniques

## Data generation

### Required environment variables

The following environment variable must be set before running the processor locally:

| Variable | Description |
|---|---|
| `PROMPTINTEL_API_KEY` | API key for PromptIntel API access (`Authorization: Bearer <key>`) |

### Data source

The processor calls:

- `GET https://api.promptintel.novahunting.ai/api/v1/prompts`

and converts each prompt record into STIX 2.1 objects.

### Timestamp handling

`created_at` from PromptIntel is used for:

- `indicator.created`
- `indicator.modified`
- `indicator.valid_from`
- related relationship `created` / `modified`
- `threat-actor` and `course-of-action` timestamps

Records are grouped into hourly bundles using `YYYYMMDD_HH` from source `created_at`.

### Mapping

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
  "name": "PromptIntel",
  "description": "Track, analyze, and defend against adversarial AI prompts and emerging agent threats. A collaborative threat intel platform covering prompts, agent skills, and AI abuse patterns.",
  "identity_class": "system",
  "contact_information": "https://promptintel.novahunting.ai/",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Identity `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `name`.

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
    "statement": "Origin: https://api.promptintel.novahunting.ai/api/v1"
  },
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0"
  ]
}
```

Marking definition `id` generated using namespace `a1cb37d2-3bd3-5b23-8526-47a22694b7e0` and value `definition.statement`.

#### AI Prompt SCO

```json
{
  "type": "ai-prompt",
  "spec_version": "2.1",
  "id": "ai-prompt--<UUID>",
  "value": "<prompt>",
  "models": ["<model_labels>"]
}
```

Created with `stix2extensions.AiPrompt`.

#### Indicator SDO

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<UUIDV5>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "created": "<created_at>",
  "modified": "<created_at>",
  "valid_from": "<created_at>",
  "indicator_types": ["malicious-activity"],
  "name": "<title>",
  "description": "Impact: <impact_description>",
  "pattern_type": "nova",
  "pattern": "<nova_rule>",
  "confidence": "<mapped from severity>",
  "labels": ["categories.*", "threats.*", "severity.*", "tags"],
  "external_references": [
    {
      "source_name": "promptintel",
      "description": "url",
      "url": "https://promptintel.novahunting.ai/prompt/<id>"
    }
  ],
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

Indicator `id` generated using namespace `<UUID OF FEED MARKING DEF>` and value `name`.

Severity-to-confidence mapping:

- `low` -> `25`
- `medium` -> `50`
- `high` -> `75`
- `critical` -> `90`

#### File SCO

One file SCO per `malware_hashes` entry:

```json
{
  "type": "file",
  "spec_version": "2.1",
  "id": "file--<UUID>",
  "hashes": {
    "SHA-256": "<malware_hash>"
  }
}
```

#### Threat Actor SDO

One threat actor per `threat_actors` value:

```json
{
  "type": "threat-actor",
  "spec_version": "2.1",
  "id": "threat-actor--<UUIDV5>",
  "created": "<created_at>",
  "modified": "<created_at>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "threat_actor_types": ["unknown"],
  "name": "<threat_actor>",
  "object_marking_refs": [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
    "marking-definition--<UUID OF FEED MARKING DEF>"
  ]
}
```

#### Course of Action SDO

When `mitigation_suggestions` exists:

```json
{
  "type": "course-of-action",
  "spec_version": "2.1",
  "id": "course-of-action--<UUIDV5>",
  "created": "<created_at>",
  "modified": "<created_at>",
  "created_by_ref": "identity--<UUID OF FEED ID>",
  "name": "Mitigation of <title>",
  "description": "<mitigation_suggestions>"
}
```

#### ATLAS technique links

The processor infers and links these attack patterns when matching keywords are present:

- `AML.T0054` LLM Jailbreak (`attack-pattern--9bf148ad-b901-5aeb-a029-6c0a8ce0a564`)
- `AML.T0057` LLM Data Leakage (`attack-pattern--0c8eca96-8d33-5fd4-a9c0-51db41128b89`)
- `AML.T0051` LLM Prompt Injection (`attack-pattern--6ff098e9-2864-579e-bebb-a0f1c92ec772`)

## Usage

```bash
python processors/promptintel/promptintel.py [OPTIONS]
```

### Options

- `--since-date <date>`: Only process prompts created on or after this date (`YYYY-MM-DD` or ISO datetime).
- `--until-date <date>`: Only process prompts created on or before this date (`YYYY-MM-DD` or ISO datetime).

### Examples

Process all available prompts:

```bash
python processors/promptintel/promptintel.py
```

Process prompts from a date:

```bash
python processors/promptintel/promptintel.py --since-date 2026-01-01
```

Process prompts in a range:

```bash
python processors/promptintel/promptintel.py --since-date 2026-01-01 --until-date 2026-01-15
```

### Output

The script creates STIX bundle files grouped by date and hour:

- `outputs/promptintel/bundles/promptintel_YYYYMMDD_HH.json`

Each bundle contains:

- source identity and marking definition
- imported feeds2stix marking definition
- all STIX objects produced from prompt records in that hour bucket

## GitHub Action

The processor is automated via GitHub Actions at [`update-promptintel.yml`](../../.github/workflows/update-promptintel.yml).

### Setup

Configure the following in your GitHub repository.

**Secrets** (Settings -> Secrets and variables -> Actions):

- `PROMPTINTEL_API_KEY`: API key used by the PromptIntel processor
- `CTX_BASE_URL`: base URL for your CTX instance
- `CTX_API_KEY`: API key for CTX uploads

**Variables**:

- `PROMPTINTEL_FEED_ID`: CTX feed ID for PromptIntel uploads
- `MAX_BUNDLE_SIZE_KB`: maximum bundle size for upload splitting

### Workflow behavior

- schedule: every 6 hours
- supports manual runs with optional `since_date` and `until_date`
- supports `since_date=auto` to resume from latest uploaded indicator timestamp
- uploads bundles via `helpers/upload.py`
