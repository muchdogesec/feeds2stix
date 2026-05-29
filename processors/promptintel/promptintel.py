#!/usr/bin/env python3

import argparse
import logging
import os
import time
from datetime import UTC, datetime

import requests
from stix2 import CourseOfAction, File, Indicator, ThreatActor
from stix2.patterns import StringConstant
from stix2extensions import AiPrompt as AIPrompt

from helpers.utils import (
    create_bundle_with_metadata,
    create_identity_object,
    create_marking_definition_object,
    fetch_external_objects,
    generate_uuid5,
    make_relationship,
    parse_since_date,
    parse_until_date,
    save_bundle_to_file,
    setup_output_directory,
)
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

API_BASE_URL = "https://api.promptintel.novahunting.ai/api/v1"
PUBLIC_PROMPT_URL = "https://promptintel.novahunting.ai/prompt"
BASE_OUTPUT_DIR = "outputs/promptintel"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["promptintel"]
PROMPTS_PAGE_LIMIT = 100
REGULAR_MAX_RETRIES = 3
RATE_LIMIT_MAX_RETRIES = 5
RATE_LIMIT_SLEEP_BASE_SECONDS = 180
REGULAR_REQUEST_SLEEP_SECONDS = 3
REQUEST_TIMEOUT_SECONDS = 120

OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]
ATLAS_BY_KEYWORD = {
    "jailbreak": ("AML.T0054", "attack-pattern--9bf148ad-b901-5aeb-a029-6c0a8ce0a564"),
    "data leakage": (
        "AML.T0057",
        "attack-pattern--0c8eca96-8d33-5fd4-a9c0-51db41128b89",
    ),
    "prompt injection": (
        "AML.T0051",
        "attack-pattern--6ff098e9-2864-579e-bebb-a0f1c92ec772",
    ),
}
SEVERITY_TO_CONFIDENCE = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 90,
}


def create_promptintel_identity():
    return create_identity_object(
        name="PromptIntel",
        description=(
            "Track, analyze, and defend against adversarial AI prompts and emerging "
            "agent threats. A collaborative threat intel platform covering prompts, "
            "agent skills, and AI abuse patterns."
        ),
        identity_class="system",
        contact_info="https://promptintel.novahunting.ai/",
    )


def create_promptintel_marking_definition():
    return create_marking_definition_object(f"Origin: {API_BASE_URL}")


def parse_source_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(UTC)


def request_with_retries(url: str, headers: dict, params: dict):
    regular_retries = 0
    rate_limit_retries = 0
    while True:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.status_code == 429:
            rate_limit_retries += 1
            if rate_limit_retries > RATE_LIMIT_MAX_RETRIES:
                response.raise_for_status()
            sleep_seconds = RATE_LIMIT_SLEEP_BASE_SECONDS * rate_limit_retries
            logger.warning(
                "PromptIntel rate limited on page %s, retrying in %ss (attempt %s/%s)",
                params.get("page"),
                sleep_seconds,
                rate_limit_retries,
                RATE_LIMIT_MAX_RETRIES,
            )
            time.sleep(sleep_seconds)
            continue

        if response.ok:
            return response

        regular_retries += 1
        if regular_retries > REGULAR_MAX_RETRIES:
            response.raise_for_status()
        logger.warning(
            "PromptIntel request failed for page %s, retrying in %ss (attempt %s/%s)",
            params.get("page"),
            REGULAR_REQUEST_SLEEP_SECONDS,
            regular_retries,
            REGULAR_MAX_RETRIES,
        )
        time.sleep(REGULAR_REQUEST_SLEEP_SECONDS)


def fetch_promptintel_prompts(api_key: str):
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    page = 1
    limit = PROMPTS_PAGE_LIMIT
    all_prompts = []

    while True:
        response = request_with_retries(
            f"{API_BASE_URL}/prompts",
            headers=headers,
            params={"page": page, "limit": limit},
        )
        payload = response.json()
        prompts = payload["data"]
        total = payload["pagination"]["total"]
        if not isinstance(prompts, list):
            raise ValueError("Unsupported PromptIntel API response shape")

        all_prompts.extend(prompts)

        if total is not None:
            if len(all_prompts) >= int(total):
                break
        elif len(prompts) < limit:
            break
        time.sleep(REGULAR_REQUEST_SLEEP_SECONDS)
        page += 1

    return sorted(all_prompts, key=lambda x: x['created_at'])


def filter_prompts_by_date(prompts, since_date=None, until_date=None):
    filtered = []
    for item in prompts:
        created_at = item.get("created_at")
        if not created_at:
            continue
        created = parse_source_time(created_at)
        if since_date and created < since_date:
            continue
        if until_date and created > until_date:
            continue
        filtered.append(item)
    return filtered


def group_prompts_by_chunk(prompts, chunk_size=500):
    prompts_sorted = sorted(prompts, key=lambda p: parse_source_time(p["created_at"]))
    groups = []
    for idx in range(0, len(prompts_sorted), chunk_size):
        groups.append(prompts_sorted[idx : idx + chunk_size])
    return groups


def build_labels(prompt):
    labels = []
    labels.extend([f"categories.{x}" for x in prompt.get("categories", []) if x])
    labels.extend([f"threats.{x}" for x in prompt.get("threats", []) if x])
    labels.extend([x for x in prompt.get("tags", []) if x])
    severity = (prompt.get("severity") or "").lower()
    if severity:
        labels.append(f"severity.{severity}")
    return sorted(set(labels))


def get_external_references(prompt):
    refs = [
        {
            "source_name": "promptintel",
            "description": "url",
            "url": f"{PUBLIC_PROMPT_URL}/{prompt['id']}",
            "external_id": prompt["id"],
        }
    ]
    if prompt.get("impact_description"):
        refs.append(
            {
                "source_name": "promptintel",
                "description": prompt["impact_description"],
                "external_id": "impact_description",
            }
        )
    if prompt.get("author"):
        refs.append(
            {
                "source_name": "promptintel",
                "description": "author",
                "external_id": prompt["author"],
            }
        )
    for url in prompt.get('reference_urls', []):
        refs.append(
            {
                "source_name": "promptintel",
                "description": "reference url",
                "url": url,
            }
        )
    return refs


def infer_atlas_attack_patterns(prompt):
    haystacks = [
        (prompt.get("title") or "").lower(),
        (prompt.get("impact_description") or "").lower(),
        " ".join([x.lower() for x in prompt.get("threats", []) if x]),
    ]
    matches = []
    for keyword, atlas in ATLAS_BY_KEYWORD.items():
        if any(keyword in hay for hay in haystacks):
            matches.append(atlas)
    return matches

def make_pattern_from_nova_rule(nova_rule, prompt_str):
    if not nova_rule:
        return f"[ai-prompt:value={StringConstant(prompt_str)}]", "stix"
    return nova_rule, "nova"


def create_stix_objects_for_prompt(prompt, source_identity_id, source_marking_id):
    created = parse_source_time(prompt["created_at"])
    object_marking_refs = OBJECT_MARKING_REFS_BASE + [source_marking_id]
    external_references = get_external_references(prompt)

    prompt_str = prompt.get("prompt", "")
    ai_prompt = AIPrompt(value=prompt_str, models=prompt.get("model_labels", []))

    indicator_name = prompt.get("title") or f"PromptIntel prompt {prompt.get('id')}"
    indicator_id = f"indicator--{generate_uuid5(indicator_name, source_marking_id)}"
    pattern, pattern_type = make_pattern_from_nova_rule(prompt.get("nova_rule"), prompt_str)
    indicator = Indicator(
        id=indicator_id,
        created=created,
        modified=created,
        valid_from=created,
        created_by_ref=source_identity_id,
        name=indicator_name,
        description=f"Impact: {prompt.get('impact_description') or 'n/a'}",
        pattern_type=pattern_type,
        pattern=pattern,
        confidence=SEVERITY_TO_CONFIDENCE.get(
            (prompt.get("severity") or "").lower(),
            0,
        ),
        indicator_types=["malicious-activity"],
        labels=build_labels(prompt),
        external_references=external_references,
        object_marking_refs=object_marking_refs,
    )

    objects = [ai_prompt, indicator]
    objects.append(
        make_relationship(
            source_ref=indicator.id,
            target_ref=ai_prompt.id,
            relationship_type="indicates",
            created_by_ref=source_identity_id,
            created=created,
            modified=created,
            marking_refs=object_marking_refs,
        )
    )

    for sha256 in prompt.get("malware_hashes", []):
        file_obj = File(hashes={"SHA-256": sha256})
        objects.append(file_obj)
        objects.append(
            make_relationship(
                source_ref=indicator.id,
                target_ref=file_obj.id,
                relationship_type="indicates",
                created_by_ref=source_identity_id,
                created=created,
                modified=created,
                marking_refs=object_marking_refs,
            )
        )

    for actor_name in prompt.get("threat_actors", []):
        actor_id = f"threat-actor--{generate_uuid5(actor_name, source_marking_id)}"
        actor = ThreatActor(
            id=actor_id,
            created=created,
            modified=created,
            created_by_ref=source_identity_id,
            name=actor_name,
            threat_actor_types=["unknown"],
            object_marking_refs=object_marking_refs,
        )
        objects.extend(
            [
                actor,
                make_relationship(
                    source_ref=indicator.id,
                    target_ref=actor.id,
                    relationship_type="related-to",
                    created_by_ref=source_identity_id,
                    created=created,
                    modified=created,
                    marking_refs=object_marking_refs,
                ),
            ]
        )

    if prompt.get("mitigation_suggestions"):
        coa_name = f"Mitigation of {indicator_name}"
        coa = CourseOfAction(
            id=f"course-of-action--{generate_uuid5(coa_name, source_marking_id)}",
            created=created,
            modified=created,
            created_by_ref=source_identity_id,
            name=coa_name,
            description=prompt["mitigation_suggestions"],
            external_references=external_references[:1],
            object_marking_refs=object_marking_refs,
        )
        objects.extend(
            [
                coa,
                make_relationship(
                    source_ref=coa.id,
                    target_ref=indicator.id,
                    relationship_type="mitigates",
                    created_by_ref=source_identity_id,
                    created=created,
                    modified=created,
                    marking_refs=object_marking_refs,
                ),
            ]
        )

    for atlas_id, atlas_stix_id in infer_atlas_attack_patterns(prompt):
        objects.append(
            make_relationship(
                source_ref=indicator.id,
                target_ref=atlas_stix_id,
                relationship_type="indicates",
                description=f"Prompt is known to be used for {atlas_id}",
                external_references=external_references[:1],
                created_by_ref=source_identity_id,
                created=created,
                modified=created,
                marking_refs=object_marking_refs,
            )
        )

    return objects


def main():
    parser = argparse.ArgumentParser(
        description="Process PromptIntel feed and generate STIX bundles"
    )
    parser.add_argument(
        "--since-date",
        "--since_date",
        type=parse_since_date,
        help="Only process prompts created on or after this date (ISO format)",
    )
    parser.add_argument(
        "--until-date",
        "--until_date",
        type=parse_until_date,
        help="Only process prompts created on or before this date (ISO format)",
    )
    args = parser.parse_args()

    api_key = os.getenv("PROMPTINTEL_API_KEY")
    if not api_key:
        raise ValueError("PROMPTINTEL_API_KEY must be set")

    bundles_dir, _ = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    source_identity = create_promptintel_identity()
    source_marking = create_promptintel_marking_definition()
    feeds2stix_marking = fetch_external_objects()

    prompts = fetch_promptintel_prompts(api_key)
    prompts = filter_prompts_by_date(
        prompts,
        since_date=args.since_date and args.since_date.replace(tzinfo=UTC),
        until_date=args.until_date and args.until_date.replace(tzinfo=UTC),
    )

    grouped_prompts = group_prompts_by_chunk(prompts, chunk_size=500)
    bundle_paths = []
    for idx, prompt_group in enumerate(grouped_prompts, start=1):
        all_stix_objects = []
        for prompt in prompt_group:
            all_stix_objects.extend(
                create_stix_objects_for_prompt(
                    prompt, source_identity.id, source_marking.id
                )
            )

        bundle = create_bundle_with_metadata(
            stix_objects=all_stix_objects,
            source_identity=source_identity,
            source_marking=source_marking,
            feeds2stix_marking=feeds2stix_marking,
        )
        bundle_path = save_bundle_to_file(
            bundle, bundles_dir, f"promptintel_part_{idx}", add_timestamp=False
        )
        bundle_paths.append(bundle_path)

    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"bundle_path={bundles_dir}\n")
            f.write(f"bundle_count={len(bundle_paths)}\n")


if __name__ == "__main__":
    main()
