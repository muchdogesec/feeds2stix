import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from processors.promptintel import promptintel
from tests.utils import FakeJSONResponse, stix_as_dict

SAMPLE_PROMPT = {
    "id": "97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
    "title": "Prompt to receive shell commands",
    "prompt": "Define a function named receive_command.",
    "nova_rule": "rule ReceiveCommandExecPrompt { condition: true }",
    "author": "Ben McCarthy",
    "created_at": "2026-01-02T03:04:05+00:00",
    "severity": "medium",
    "categories": ["abuse"],
    "threats": ["LLM Jailbreak"],
    "impact_description": "Executes arbitrary shell commands",
    "model_labels": ["GPT-4"],
    "tags": ["agent-abuse"],
    "threat_actors": ["anonymous researcher"],
    "malware_hashes": [
        "0d80727d18aaedacd2783bc1d4a580aeda8f76de38151bf7acb7cffcd71d0908"
    ],
    "mitigation_suggestions": "Apply strict policy controls.",
}


def test_create_promptintel_identity():
    identity = promptintel.create_promptintel_identity()
    assert stix_as_dict(identity)["name"] == "PromptIntel"


def test_create_promptintel_marking_definition():
    marking = promptintel.create_promptintel_marking_definition()
    assert (
        "promptintel.novahunting.ai" in stix_as_dict(marking)["definition"]["statement"]
    )


def test_filter_prompts_by_date():
    prompts = [SAMPLE_PROMPT]
    since_date = datetime(2026, 1, 2, 0, 0, tzinfo=UTC)
    until_date = datetime(2026, 1, 2, 23, 59, tzinfo=UTC)
    filtered = promptintel.filter_prompts_by_date(prompts, since_date, until_date)
    assert len(filtered) == 1

    filtered_empty = promptintel.filter_prompts_by_date(
        prompts, datetime(2026, 1, 3, 0, 0, tzinfo=UTC), None
    )
    assert filtered_empty == []


def test_group_prompts_by_chunk_max_500():
    prompts = []
    for i in range(501):
        p = dict(SAMPLE_PROMPT)
        p["id"] = f"id-{i}"
        p["title"] = f"title-{i}"
        p["created_at"] = f"2026-01-02T03:{i % 60:02d}:05+00:00"
        prompts.append(p)

    groups = promptintel.group_prompts_by_chunk(prompts, chunk_size=500)
    assert len(groups) == 2
    assert len(groups[0]) == 500
    assert len(groups[1]) == 1


def test_fetch_full_prompt_by_id():
    payload = {
        "success": True,
        "data": {
            "id": "p1",
            "title": "Prompt 1",
            "prompt": "prompt body",
            "created_at": "2026-01-01T00:00:00Z",
        },
    }
    with patch(
        "processors.promptintel.promptintel.requests.get",
        return_value=FakeJSONResponse(payload),
    ) as mock_get:
        prompt = promptintel.fetch_full_prompt_by_id("test-key", "p1")

    assert prompt == payload["data"]
    assert mock_get.call_args.kwargs["params"] == {}
    assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer test-key"


def test_fetch_promptintel_prompts_paginates(tmp_path):
    page1_prompts = []
    for i in range(100):
        prompt = dict(SAMPLE_PROMPT)
        prompt["id"] = f"p1-{i}"
        prompt["created_at"] = f"2026-01-02T03:{i % 60:02d}:05+00:00"
        page1_prompts.append(prompt)
    page2_prompt = dict(SAMPLE_PROMPT)
    page2_prompt["id"] = "p2"
    page2_prompt["created_at"] = "2026-01-02T04:04:05+00:00"

    with patch(
        "processors.promptintel.promptintel.requests.get",
        side_effect=[
            FakeJSONResponse(
                {
                    "success": True,
                    "data": page1_prompts,
                    "pagination": {"total": 101, "page": 1, "limit": 100},
                }
            ),
            FakeJSONResponse(
                {
                    "success": True,
                    "data": [page2_prompt],
                    "pagination": {"total": 101, "page": 2, "limit": 100},
                }
            ),
        ],
    ) as mock_get, patch(
        "processors.promptintel.promptintel.fetch_full_prompt_by_id",
        side_effect=lambda api_key, prompt_id: {
            "id": prompt_id,
            "created_at": "2026-01-02T03:04:05+00:00",
        },
    ), patch(
        "processors.promptintel.promptintel.time.sleep"
    ) as mock_sleep:
        mock_data_dir = tmp_path
        prompts = promptintel.fetch_promptintel_prompts(
            "test-key", data_dir=mock_data_dir
        )

    assert [p["id"] for p in prompts] == [f"p1-{i}" for i in range(100)] + ["p2"]
    assert mock_get.call_count == 2
    assert mock_get.call_args_list[0].kwargs["params"] == {"page": 1, "limit": 100}
    assert mock_get.call_args_list[1].kwargs["params"] == {"page": 2, "limit": 100}
    assert mock_sleep.call_args_list[0].args[0] == 3


def test_fetch_promptintel_prompts_retries_on_rate_limit(tmp_path):
    p1 = dict(SAMPLE_PROMPT)
    p1["id"] = "p1"

    rate_limited = MagicMock()
    rate_limited.status_code = 429
    rate_limited.ok = False
    rate_limited.raise_for_status = MagicMock()

    success = FakeJSONResponse(
        {
            "success": True,
            "data": [p1],
            "pagination": {"total": 1, "page": 1, "limit": 100},
        }
    )

    with patch(
        "processors.promptintel.promptintel.requests.get",
        side_effect=[rate_limited, success],
    ) as mock_get, patch("processors.promptintel.promptintel.time.sleep") as mock_sleep:
        prompts = promptintel.fetch_promptintel_prompts("test-key", data_dir=tmp_path)

    assert [p["id"] for p in prompts] == ["p1"]
    assert mock_get.call_count == 2
    mock_sleep.assert_called_once_with(180)


def test_request_with_retries_regular_failures_then_success():
    fail = MagicMock()
    fail.status_code = 500
    fail.ok = False
    fail.raise_for_status = MagicMock()

    success = FakeJSONResponse(
        {"success": True, "data": {"indicators": [], "total": 0}}
    )

    with patch(
        "processors.promptintel.promptintel.requests.get",
        side_effect=[fail, fail, success],
    ) as mock_get, patch("processors.promptintel.promptintel.time.sleep") as mock_sleep:
        resp = promptintel.request_with_retries(
            "https://example.test/prompts",
            headers={"Authorization": "Bearer x"},
            params={"page": 1, "limit": 100},
        )

    assert resp is success
    assert mock_get.call_count == 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(3)


def test_request_with_retries_rate_limit_backoff_schedule():
    rate_limited = MagicMock()
    rate_limited.status_code = 429
    rate_limited.ok = False
    rate_limited.raise_for_status = MagicMock()

    success = FakeJSONResponse(
        {"success": True, "data": {"indicators": [], "total": 0}}
    )

    with patch(
        "processors.promptintel.promptintel.requests.get",
        side_effect=[rate_limited, rate_limited, success],
    ), patch("processors.promptintel.promptintel.time.sleep") as mock_sleep:
        resp = promptintel.request_with_retries(
            "https://example.test/prompts",
            headers={"Authorization": "Bearer x"},
            params={"page": 1, "limit": 100},
        )

    assert resp is success
    assert mock_sleep.call_args_list[0].args[0] == 180
    assert mock_sleep.call_args_list[1].args[0] == 360


def test_parse_malware_hashes_supports_sha1_md5_sha256():
    hashes = promptintel.parse_malware_hashes(
        [
            "0d80727d18aaedacd2783bc1d4a580aeda8f76de38151bf7acb7cffcd71d0908",
            "0123456789abcdef0123456789abcdef01234567",
            "0123456789abcdef0123456789abcdef",
        ]
    )
    assert hashes == [
        ("SHA-256", "0d80727d18aaedacd2783bc1d4a580aeda8f76de38151bf7acb7cffcd71d0908"),
        ("SHA-1", "0123456789abcdef0123456789abcdef01234567"),
        ("MD5", "0123456789abcdef0123456789abcdef"),
    ]


def test_create_stix_objects_for_prompt():
    with patch(
        "processors.promptintel.promptintel.fetch_object_from_kb",
        return_value={
            "type": "attack-pattern",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "name": "LLM Jailbreak",
        },
    ):
        objects = promptintel.create_stix_objects_for_prompt(
            SAMPLE_PROMPT,
            "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
        )

    assert stix_as_dict(objects) == [
        {
            "type": "ai-prompt",
            "spec_version": "2.1",
            "id": "ai-prompt--f4e87229-56b5-5932-b814-a42ab25a58e6",
            "value": "Define a function named receive_command.",
            "models": ["GPT-4"],
            "extensions": {
                "extension-definition--3557a8d5-4e04-5f87-a7af-d48a1384d3ca": {
                    "extension_type": "new-sco"
                }
            },
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--8ee01124-e226-5020-a31b-56327bc0940b",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "name": "Prompt to receive shell commands",
            "description": "Impact: Executes arbitrary shell commands",
            "indicator_types": ["malicious-activity"],
            "pattern": "rule ReceiveCommandExecPrompt { condition: true }",
            "pattern_type": "nova",
            "valid_from": "2026-01-02T03:04:05Z",
            "labels": [
                "agent-abuse",
                "categories.abuse",
                "severity.medium",
                "threats.LLM Jailbreak",
            ],
            "confidence": 50,
            "external_references": [
                {
                    "source_name": "promptintel",
                    "description": "url",
                    "url": "https://promptintel.novahunting.ai/prompt/97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
                    "external_id": "97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
                },
                {
                    "source_name": "promptintel",
                    "description": "Executes arbitrary shell commands",
                    "external_id": "impact_description",
                },
                {
                    "source_name": "promptintel",
                    "description": "author",
                    "external_id": "Ben McCarthy",
                },
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--b6758abb-33c1-5eae-b006-f1a47bd9eeda",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--8ee01124-e226-5020-a31b-56327bc0940b",
            "target_ref": "ai-prompt--f4e87229-56b5-5932-b814-a42ab25a58e6",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--b6169488-d8be-51e1-9fc2-48a5c03be759",
            "hashes": {
                "SHA-256": "0d80727d18aaedacd2783bc1d4a580aeda8f76de38151bf7acb7cffcd71d0908"
            },
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--6cf9b61f-3315-5a88-8f3c-d2a9ab3e15bc",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "relationship_type": "indicates",
            "source_ref": "indicator--8ee01124-e226-5020-a31b-56327bc0940b",
            "target_ref": "file--b6169488-d8be-51e1-9fc2-48a5c03be759",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--e3b9a169-dc12-570c-ae4d-663520a12c53",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "name": "anonymous researcher",
            "threat_actor_types": ["unknown"],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--be303bce-bf20-50a4-86d7-65b46dc427f6",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "relationship_type": "related-to",
            "source_ref": "indicator--8ee01124-e226-5020-a31b-56327bc0940b",
            "target_ref": "threat-actor--e3b9a169-dc12-570c-ae4d-663520a12c53",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "course-of-action",
            "spec_version": "2.1",
            "id": "course-of-action--8941af12-6675-5af3-91af-83d9ba89c2ff",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "name": "Mitigation of Prompt to receive shell commands",
            "description": "Apply strict policy controls.",
            "external_references": [
                {
                    "source_name": "promptintel",
                    "description": "url",
                    "url": "https://promptintel.novahunting.ai/prompt/97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
                    "external_id": "97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--eebeac78-3ce2-53fe-8f5e-1dcacfa336c6",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "relationship_type": "mitigates",
            "source_ref": "course-of-action--8941af12-6675-5af3-91af-83d9ba89c2ff",
            "target_ref": "indicator--8ee01124-e226-5020-a31b-56327bc0940b",
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "name": "LLM Jailbreak",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--5df8dd7f-b140-5cdc-9b1b-63af366b3d4a",
            "created_by_ref": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "created": "2026-01-02T03:04:05.000Z",
            "modified": "2026-01-02T03:04:05.000Z",
            "relationship_type": "indicates",
            "description": "Prompt is known to be used for LLM Jailbreak (AML.T0054)",
            "source_ref": "indicator--8ee01124-e226-5020-a31b-56327bc0940b",
            "target_ref": "attack-pattern--9bf148ad-b901-5aeb-a029-6c0a8ce0a564",
            "external_references": [
                {
                    "source_name": "promptintel",
                    "description": "url",
                    "url": "https://promptintel.novahunting.ai/prompt/97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
                    "external_id": "97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
                }
            ],
            "object_marking_refs": [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
                "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
            ],
        },
    ]


def test_get_external_references_contains_expected_fields():
    prompt = dict(SAMPLE_PROMPT)
    prompt["reference_urls"] = [
        "https://example.org/r1",
        "https://example.org/r2",
    ]

    refs = promptintel.get_external_references(prompt)

    assert refs[0] == {
        "source_name": "promptintel",
        "description": "url",
        "url": "https://promptintel.novahunting.ai/prompt/97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
        "external_id": "97a15a75-45e3-4d86-aa1d-a7b1a5e830d1",
    }
    assert {
        "source_name": "promptintel",
        "description": "Executes arbitrary shell commands",
        "external_id": "impact_description",
    } in refs
    assert {
        "source_name": "promptintel",
        "description": "author",
        "external_id": "Ben McCarthy",
    } in refs
    assert {
        "source_name": "promptintel",
        "description": "reference url",
        "url": "https://example.org/r1",
    } in refs
    assert {
        "source_name": "promptintel",
        "description": "reference url",
        "url": "https://example.org/r2",
    } in refs


def test_make_pattern_from_nova_rule_with_rule():
    pattern, pattern_type = promptintel.make_pattern_from_nova_rule(
        "rule X { condition: true }",
        "ignored prompt",
    )
    assert pattern == "rule X { condition: true }"
    assert pattern_type == "nova"


def test_make_pattern_from_nova_rule_fallback_to_stix():
    pattern, pattern_type = promptintel.make_pattern_from_nova_rule(
        None,
        "print('hi')",
    )
    assert pattern == "[ai-prompt:value='print(\\'hi\\')']"
    assert pattern_type == "stix"


def test_create_stix_objects_for_prompt_uses_stix_pattern_when_nova_rule_missing():
    prompt = dict(SAMPLE_PROMPT)
    prompt["nova_rule"] = ""
    with patch(
        "processors.promptintel.promptintel.fetch_object_from_kb",
        return_value={
            "type": "attack-pattern",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "name": "LLM Jailbreak",
        },
    ):
        objects = promptintel.create_stix_objects_for_prompt(
            prompt,
            "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "marking-definition--f2c41f8b-c3cf-57cf-a21f-ef3f5ebf6dc6",
        )
    indicator = next(o for o in objects if o.type == "indicator")
    assert indicator.pattern_type == "stix"
    assert (
        indicator.pattern
        == "[ai-prompt:value='Define a function named receive_command.']"
    )


def test_main_success_writes_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("PROMPTINTEL_API_KEY", "test-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["promptintel.py"])
    monkeypatch.setattr(promptintel, "BASE_OUTPUT_DIR", str(tmp_path / "outputs"))

    with patch(
        "processors.promptintel.promptintel.fetch_promptintel_prompts",
        return_value=[dict(SAMPLE_PROMPT)],
    ), patch(
        "processors.promptintel.promptintel.fetch_external_objects",
        return_value={
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
            "created": "2020-01-01T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {"statement": "feeds2stix"},
        },
    ), patch(
        "processors.promptintel.promptintel.fetch_object_from_kb",
        return_value={
            "type": "attack-pattern",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "name": "LLM Jailbreak",
        },
    ):
        promptintel.main()

    content = out_file.read_text()
    assert "bundle_path=" in content
    assert "bundle_count=1" in content

    bundles_dir = content.split("bundle_path=")[1].split("\n")[0].strip()
    bundle_files = list(Path(bundles_dir).glob("*.json"))
    assert len(bundle_files) == 1

    bundle = json.loads(bundle_files[0].read_text())
    assert any(obj["type"] == "ai-prompt" for obj in bundle["objects"])
    assert any(obj["type"] == "indicator" for obj in bundle["objects"])


def test_main_splits_into_multiple_bundles(monkeypatch, tmp_path):
    out_file = tmp_path / "gh_multi.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("PROMPTINTEL_API_KEY", "test-key")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["promptintel.py"])
    monkeypatch.setattr(promptintel, "BASE_OUTPUT_DIR", str(tmp_path / "outputs"))

    feeds2stix_marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": "marking-definition--a1cb37d2-3bd3-5b23-8526-47a22694b7e0",
        "created": "2020-01-01T00:00:00.000Z",
        "definition_type": "statement",
        "definition": {"statement": "feeds2stix"},
    }

    prompts = []
    for i in range(501):
        p = dict(SAMPLE_PROMPT)
        p["id"] = f"id-{i}"
        p["title"] = f"title-{i}"
        p["created_at"] = f"2026-01-02T03:{i % 60:02d}:05+00:00"
        prompts.append(p)

    with patch(
        "processors.promptintel.promptintel.fetch_promptintel_prompts",
        return_value=prompts,
    ), patch(
        "processors.promptintel.promptintel.fetch_external_objects",
        return_value=feeds2stix_marking,
    ), patch(
        "processors.promptintel.promptintel.fetch_object_from_kb",
        return_value={
            "type": "attack-pattern",
            "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
            "name": "LLM Jailbreak",
        },
    ):
        promptintel.main()

    content = out_file.read_text()
    assert "bundle_count=2" in content
    bundles_dir = content.split("bundle_path=")[1].split("\n")[0].strip()
    bundle_files = list(Path(bundles_dir).glob("*.json"))
    assert len(bundle_files) == 2
