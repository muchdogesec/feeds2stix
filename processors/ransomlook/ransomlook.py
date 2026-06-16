#!/usr/bin/env python3

import argparse
import calendar
from functools import lru_cache
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urljoin

import requests
from stix2 import (
    IntrusionSet,
    Note,
    URL,
    ThreatActor,
    Incident,
    Identity,
)
from stix2extensions import CryptocurrencyWallet

sys.path.append(os.path.join(os.path.dirname(__file__), "../.."))

from helpers.utils import (  # noqa: E402
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
    write_github_output,
)
from processors.metadata import PROCESSOR_METADATA_BY_PROCESSOR  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

API_BASE = "https://www.ransomlook.io/api"
REFERENCE_BASE_URL = "https://www.ransomlook.io"
BASE_OUTPUT_DIR = "outputs/ransomlook"
PROCESSOR_METADATA = PROCESSOR_METADATA_BY_PROCESSOR["ransomlook"]
OBJECT_MARKING_REFS_BASE = [
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
]
STATIC_DATE = datetime(2020, 1, 1, tzinfo=UTC)
DEFAULT_LOOKBACK_DAYS = 30


def create_ransomlook_identity():
    return create_identity_object(
        name="RansomLook",
        description=(
            "RansomLook is an open-source ransomware and data-extortion intelligence platform "
            "covering groups, victim posts, actors, infrastructure, ransom notes, leaks, and "
            "cryptocurrency wallets."
        ),
        identity_class="organization",
        contact_info="https://www.ransomlook.io/",
    )


def create_ransomlook_marking_definition():
    return create_marking_definition_object(f"Origin: {API_BASE}")


def parse_timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def resolve_date_range(since_date: datetime | None, until_date: datetime | None):
    end = until_date or datetime.now(UTC)
    start = since_date or (end - timedelta(days=DEFAULT_LOOKBACK_DAYS))

    if start > end:
        raise ValueError("since-date must be on or before until-date")

    return start.astimezone(UTC), end.astimezone(UTC)


def iter_month_windows(start_dt: datetime, end_dt: datetime):
    current_date = start_dt.date()
    end_date = end_dt.date()

    while current_date <= end_date:
        last_day = calendar.monthrange(current_date.year, current_date.month)[1]
        window_end_date = min(
            current_date.replace(day=last_day),
            end_date,
        )
        yield (
            datetime(
                current_date.year, current_date.month, current_date.day, tzinfo=UTC
            ),
            datetime(
                window_end_date.year,
                window_end_date.month,
                window_end_date.day,
                tzinfo=UTC,
            ),
        )
        current_date = window_end_date + timedelta(days=1)


def request_json(url: str, params: dict | None = None):
    api_key = os.getenv("RANSOMLOOK_API_KEY")
    response = requests.get(
        url,
        headers={"Authorization": api_key} if api_key else {},
        params=params or {},
        timeout=120,
    )
    response.raise_for_status()
    return response


def extract_posts(payload):
    if isinstance(payload, dict):
        if isinstance(payload.get("posts"), list):
            return payload["posts"]
        if isinstance(payload.get("results"), list):
            return payload["results"]
    if isinstance(payload, list):
        return payload
    return []


def normalize_post_record(raw_record: dict):
    discovered = raw_record.get("discovered") or raw_record.get("date")
    group_name = raw_record.get("group_name") or raw_record.get("group")
    post_title = raw_record.get("post_title") or raw_record.get("title")

    if not discovered or not group_name or not post_title:
        return None

    record = dict(raw_record)
    record["group_name"] = str(group_name).strip()
    record["post_title"] = str(post_title).strip()
    record["discovered"] = parse_timestamp(str(discovered))
    return record


def filter_posts_by_date(posts, since_date=None, until_date=None):
    filtered = []
    for post in posts:
        discovered = post["discovered"]
        if since_date and discovered < since_date:
            continue
        if until_date and discovered > until_date:
            continue
        filtered.append(post)

    filtered.sort(
        key=lambda item: (
            item["discovered"],
            item["group_name"].lower(),
            item["post_title"].lower(),
        )
    )
    return filtered


@lru_cache
def fetch_group_details(group_name: str):
    logger.info("fetching metadata for group: %s", group_name)
    url = f"{API_BASE}/group/{quote(group_name, safe='')}"
    response = request_json(url)
    group_meta, incidents = response.json()
    group_meta["has_crypto"] = group_has_crypto(group_name)
    group_meta["notes"] = get_note_list(group_name)
    return group_meta, incidents


@lru_cache
def _crypto():
    url = f"{API_BASE}/crypto/"
    return tuple(x["name"] for x in request_json(url).json())


@lru_cache
def _notes():
    url = f"{API_BASE}/notes/"
    return tuple(x["name"] for x in request_json(url).json())


def group_has_crypto(group_name):
    return group_name in _crypto()


def get_note_list(group_name):
    if group_name not in _notes():
        return {}
    url = f"{API_BASE}/notes/group/{quote(group_name, safe='')}"
    return {x["id"]: x for x in request_json(url).json()}


@lru_cache
def fetch_group_crypto(group_slug: str):
    if group_slug not in _crypto():
        return {}
    url = f"{API_BASE}/crypto/{quote(group_slug, safe='')}"
    response = request_json(url)
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def fetch_and_create_note_object(
    note, group_obj, source_identity_id, source_marking_id
):
    note_id = note["id"]
    note_title = note.get("title") or note.get("name") or note_id
    url = f"{API_BASE}/notes/{quote(note_id, safe='')}"
    logger.info("fetching note %s for group %s", note_title, group_obj.name)
    response = request_json(url)
    response.raise_for_status()
    data = response.json()
    note_stix_id = "note--" + generate_uuid5(f"note:{note_id}", source_marking_id)
    note_title = data["title"]
    return Note(
        id=note_stix_id,
        created_by_ref=source_identity_id,
        created=group_obj.created,
        modified=parse_timestamp(data["updated_at"]),
        abstract=note_title,
        content=data["content"],
        object_refs=[group_obj.id],
        object_marking_refs=OBJECT_MARKING_REFS_BASE + [source_marking_id],
        external_references=[
            {
                "source_name": "ransomlook",
                "url": "https://www.ransomlook.io/notes/" + note_id,
            },
            group_obj.external_references[0],
        ],
    )


@lru_cache
def _fetch_group(group_name, source_identity_id, source_marking_id):
    group_meta, group_incidents = fetch_group_details(group_name)
    group_posts = sorted(
        group_incidents,
        key=lambda item: (item["discovered"], item["post_title"].lower()),
    )
    if group_posts:
        first_seen = parse_timestamp(group_posts[0]["discovered"])
        last_seen = parse_timestamp(group_posts[-1]["discovered"])
    else:
        first_seen = last_seen = datetime(2020, 1, 1, tzinfo=UTC)

    group_object = create_intrusion_set(
        group_name,
        group_meta,
        first_seen,
        last_seen,
        source_identity_id,
        source_marking_id,
    )
    return group_object, group_meta, group_incidents


@lru_cache
def fetch_and_create_group_objects(group_name, source_identity_id, source_marking_id):
    objects = []
    group_object, group_meta, _ = _fetch_group(
        group_name, source_identity_id, source_marking_id
    )
    objects.append(group_object)
    for obj in create_location_url_objects(group_meta, group_object):
        objects.append(obj)

    logger.info("Fetching crypto&notes for group %s...", group_name)
    crypto_payload = fetch_group_crypto(group_name)
    for obj in create_wallet_objects(
        group_name,
        crypto_payload,
        group_object["id"],
        source_identity_id,
        source_marking_id,
    ):
        objects.append(obj)

    for note_id, note_meta in group_meta["notes"].items():
        note_obj = fetch_and_create_note_object(
            note_meta,
            group_object,
            source_identity_id,
            source_marking_id,
        )
        objects.append(note_obj)

    return objects


def _create_one_actor(actor: dict, source_identity_id, source_marking_id):
    objects = []

    for group_name in actor["relations"]["groups"]:
        group_obj, _, _ = _fetch_group(
            group_name, source_identity_id, source_marking_id
        )
        objects.append(group_obj)

    created_ts = min(obj["created"] for obj in objects)
    modified_ts = max(obj["created"] for obj in objects)
    threat_actor = ThreatActor(
        id="threat-actor--" + generate_uuid5(actor["name"], source_marking_id),
        created_by_ref=source_identity_id,
        name=actor["name"],
        aliases=actor["aliases"],
        created=created_ts,
        modified=modified_ts,
        threat_actor_types=["crime-syndicate"],
        roles=["affiliate", "developer", "broker", "admin"],
        object_marking_refs=OBJECT_MARKING_REFS_BASE + [source_marking_id],
        external_references=[
            {
                "source_name": "ransomlook",
                "url": "https://www.ransomlook.io/actor/" + actor["name"],
                "external_id": actor["name"],
            }
        ],
    )
    objects.append(threat_actor)
    for group_obj in objects:
        if group_obj.type != "intrusion-set":
            continue
        rel = make_relationship(
            threat_actor.id,
            group_obj.id,
            "associated-with",
            source_identity_id,
            threat_actor.object_marking_refs,
            created_ts,
            modified_ts,
            external_references=[
                threat_actor.external_references[0],
                group_obj.external_references[0],
            ],
        )
        objects.append(rel)
    return objects


def fetch_and_create_threat_actors(source_identity_id, source_marking_id):
    url = f"{API_BASE}/actors/"
    actors = sorted([actor["name"] for actor in request_json(url).json()])
    added_objects = set()
    objects = []
    for actor_name in actors:
        url2 = url + quote(actor_name, safe="")
        actor = request_json(url2).json()
        for obj in _create_one_actor(actor, source_identity_id, source_marking_id):
            if obj["id"] not in added_objects:
                added_objects.add(obj["id"])
                objects.append(obj)
    return objects


def fetch_posts_period(data_dir: Path, start_dt: datetime, end_dt: datetime):
    start_date = start_dt.date()
    end_date = end_dt.date()
    url = f"{API_BASE}/posts/period/{start_date.isoformat()}/{end_date.isoformat()}"
    logger.info("Fetching RansomLook posts from %s", url)
    response = request_json(url)

    payload = response.json()
    raw_path = data_dir / f"ransomlook_{start_date:%Y%m%d}_{end_date:%Y%m%d}.json"
    raw_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    logger.info("Saved raw feed to %s", raw_path)

    posts = [normalize_post_record(post) for post in extract_posts(payload)]
    posts = [post for post in posts if post is not None]
    logger.info(
        "Fetched %s RansomLook posts for %s-%s", len(posts), start_date, end_date
    )
    return posts, raw_path


def normalize_url_value(value: str | None):
    if not value:
        return None
    value = value.strip()
    if "://" not in value:
        return None
    return value


def create_intrusion_set(
    group_name,
    group_meta: dict,
    first_seen: datetime,
    last_seen: datetime,
    source_identity_id: str,
    source_marking_id: str,
):
    aliases = group_meta.get("aliases") or []
    affiliates = group_meta.get("affiliates", [])
    if isinstance(affiliates, str):
        affiliates = affiliates.split(",")
    aliases.extend(affiliates)
    aliases = sorted(set(aliases))

    external_references = [
        {
            "source_name": "ransomlook",
            "url": f"https://www.ransomlook.io/group/{quote(group_name, safe='')}",
        }
    ]
    for profile in group_meta.get("profile", []):
        external_references.append(dict(source_name="ransomlook-profile", url=profile))

    iset_id = f"intrusion-set--" + generate_uuid5(group_name, source_marking_id)
    labels = []
    if group_meta.get("raas"):
        labels.append("raas")
    return IntrusionSet(
        id=iset_id,
        created_by_ref=source_identity_id,
        created=first_seen,
        modified=last_seen,
        first_seen=first_seen,
        last_seen=last_seen,
        name=group_name,
        labels=labels,
        aliases=aliases or None,
        description=group_meta.get("description"),
        external_references=external_references,
        object_marking_refs=OBJECT_MARKING_REFS_BASE + [source_marking_id],
    )


def create_post_objects(
    post: dict,
    group: IntrusionSet,
):

    more_refs = []

    if link := post.get("link"):
        more_refs.append(dict(source_name="path", url=link))
    if screen := post.get("screen"):
        more_refs.append(
            dict(source_name="screenshot", url=urljoin(REFERENCE_BASE_URL, screen)),
        )
    if link := post.get("link"):
        more_refs.append(dict(source_name="path", url=link))
    if magnet := post.get("magnet"):
        more_refs.append(
            dict(source_name="screenshot", url=magnet),
        )

    incident_id = "incident--" + generate_uuid5(
        f"{group.name}:{post['post_title']}", group.object_marking_refs[-1]
    )
    identity_id = "identity--" + generate_uuid5(
        post["post_title"], group.object_marking_refs[-1]
    )
    identity = Identity(
        id=identity_id,
        created_by_ref=group.created_by_ref,
        object_marking_refs=group.object_marking_refs,
        created=post["discovered"],
        modified=post["discovered"],
        name=post["post_title"],
        identity_class="organization",
    )
    incident = Incident(
        id=incident_id,
        created_by_ref=group.created_by_ref,
        object_marking_refs=group.object_marking_refs,
        created=post["discovered"],
        modified=post["discovered"],
        name=f"{identity.name} claimed by {group.name}",
        description=post["description"],
        external_references=[group.external_references[0], *more_refs],
    )
    rel_incident = make_relationship(
        target_ref=group.id,
        source_ref=incident.id,
        relationship_type="attributed-to",
        created_by_ref=group.created_by_ref,
        created=incident.created,
        modified=incident.modified,
        marking_refs=group.object_marking_refs,
        description=f"{identity.name} was claimed by {group.name}",
        external_references=[
            group.external_references[0],
        ],
    )
    rel_id_incident = make_relationship(
        target_ref=incident.id,
        source_ref=identity.id,
        relationship_type="targets",
        created_by_ref=group.created_by_ref,
        created=incident.created,
        modified=incident.modified,
        marking_refs=group.object_marking_refs,
        external_references=[
            group.external_references[0],
        ],
    )
    return incident, rel_incident, identity, rel_id_incident


def create_location_url_objects(group_meta: dict, group_obj: IntrusionSet):
    group_id = group_obj.id
    objects = []
    seen = set()

    for location in group_meta.get("locations", []) or []:
        if not location.get("available"):
            continue
        url_obj = URL(value=location["slug"])
        objects.append(url_obj)
        descriptions = set()
        for k, v in location.items():
            if v and k in ["fs", "chat", "fixedFile", "admin"]:
                descriptions.add(k)
        descriptions = sorted(descriptions)
        description = f"{group_obj.name} uses {url_obj.value}"
        if descriptions:
            description += " " + ",".join(descriptions)
        objects.append(
            make_relationship(
                source_ref=group_id,
                target_ref=url_obj.id,
                relationship_type="uses",
                created_by_ref=group_obj.created_by_ref,
                created=STATIC_DATE,
                modified=STATIC_DATE,
                marking_refs=group_obj.object_marking_refs,
                description=description,
            )
        )
    return objects


def create_wallet_objects(
    group_slug: str,
    crypto_payload: dict,
    group_id: str,
    source_identity_id: str,
    source_marking_id: str,
):
    objects = []
    seen = set()
    object_marking_refs = OBJECT_MARKING_REFS_BASE + [source_marking_id]

    for chain, wallets in (crypto_payload.get("by_chain") or {}).items():
        if not isinstance(wallets, list):
            continue
        for wallet in wallets:
            if not isinstance(wallet, dict):
                continue
            address = str(wallet.get("address") or "").strip()
            if not address or address in seen:
                continue
            seen.add(address)
            wallet_obj = CryptocurrencyWallet(value=address)
            objects.append(wallet_obj)
            objects.append(
                make_relationship(
                    source_ref=group_id,
                    target_ref=wallet_obj.id,
                    relationship_type="uses",
                    created_by_ref=source_identity_id,
                    created=STATIC_DATE,
                    modified=STATIC_DATE,
                    marking_refs=object_marking_refs,
                    description=f"{group_slug} wallet on {chain}",
                )
            )
    return objects


def create_stix_objects_for_posts(posts, source_identity, source_marking):
    stix_objects = []
    seen_object_ids = set()
    seen_groups = {}

    def append_once(stix_object):
        object_id = stix_object["id"]
        if object_id in seen_object_ids:
            return
        seen_object_ids.add(object_id)
        stix_objects.append(stix_object)

    posts_by_group = defaultdict(list)
    for post in posts:
        posts_by_group[post["group_name"]].append(post)

    source_identity_id = source_identity["id"]
    source_marking_id = source_marking["id"]

    for group_name in sorted(posts_by_group):
        group_posts = sorted(
            posts_by_group[group_name],
            key=lambda item: (item["discovered"], item["post_title"].lower()),
        )
        if group_name not in seen_groups:
            group_obj, *other_group_objects = fetch_and_create_group_objects(
                group_name, source_identity_id, source_marking_id
            )
            seen_groups[group_name] = group_obj
            append_once(group_obj)
            for obj in other_group_objects:
                append_once(obj)
        else:
            group_obj = seen_groups[group_name]
        for post in group_posts:
            for obj in create_post_objects(post, group_obj):
                append_once(obj)

    return stix_objects


def main():
    parser = argparse.ArgumentParser(
        description="Process RansomLook posts and generate STIX bundles"
    )
    parser.add_argument(
        "--since-date",
        "--since_date",
        type=parse_since_date,
        help="Only process posts discovered on or after this date (YYYY-MM-DD or ISO 8601).",
    )
    parser.add_argument(
        "--until-date",
        "--until_date",
        type=parse_until_date,
        help="Only process posts discovered on or before this date (YYYY-MM-DD or ISO 8601).",
    )

    args = parser.parse_args()

    since_date, until_date = resolve_date_range(args.since_date, args.until_date)

    bundles_dir, data_dir = setup_output_directory(BASE_OUTPUT_DIR, clean=True)
    feeds2stix_marking = fetch_external_objects()
    source_identity = create_ransomlook_identity()
    source_marking = create_ransomlook_marking_definition()

    bundle_paths = []

    ## create actors bundle
    threat_actor_objects = fetch_and_create_threat_actors(
        source_identity["id"], source_marking["id"]
    )
    bundle = create_bundle_with_metadata(
        threat_actor_objects,
        source_identity,
        source_marking,
        feeds2stix_marking,
    )
    bundle_name = f"ransomlook_threat_actors"
    bundle_path = save_bundle_to_file(
        bundle,
        bundles_dir,
        bundle_name,
        add_timestamp=False,
    )
    bundle_paths.append(bundle_path)

    for window_start, window_end in iter_month_windows(since_date, until_date):
        raw_posts, _ = fetch_posts_period(data_dir, window_start, window_end)
        posts = filter_posts_by_date(raw_posts, since_date, until_date)
        if not posts:
            logger.info(
                "No posts matched %s-%s after timestamp filtering",
                window_start.date(),
                window_end.date(),
            )
            continue

        stix_objects = create_stix_objects_for_posts(
            posts, source_identity, source_marking
        )
        bundle = create_bundle_with_metadata(
            stix_objects,
            source_identity,
            source_marking,
            feeds2stix_marking,
        )
        bundle_name = f"ransomlook_{window_start:%Y%m%d}_{window_end:%Y%m%d}"
        bundle_path = save_bundle_to_file(
            bundle,
            bundles_dir,
            bundle_name,
            add_timestamp=False,
        )
        bundle_paths.append(bundle_path)
        logger.info(
            "Created bundle %s with %s STIX objects",
            bundle_path,
            len(stix_objects),
        )

    write_github_output(
        bundle_path=str(bundles_dir),
        bundle_count=len(bundle_paths),
    )

    logger.info("Finished processing RansomLook with %s bundle(s)", len(bundle_paths))


if __name__ == "__main__":
    main()
