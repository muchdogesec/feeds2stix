from unittest.mock import patch

from helpers import kb_fetch


class FakeJSONResponse:
    def __init__(self, response):
        self.response = response

    def json(self):
        return self.response

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, timeout=None, params=None):
        self.calls.append({"url": url, "timeout": timeout, "params": params and params.copy()})
        return FakeJSONResponse(self.responses.pop(0))


def test_fetch_attack_pattern_from_ctibutler_uses_session_base_url():
    session = FakeSession(
        [
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b",
                        "name": "Phishing",
                    }
                ]
            }
        ]
    )

    with patch(
        "helpers.kb_fetch.ctibutler_session",
        return_value=(session, "https://api.ctibutler.com"),
    ):
        obj = kb_fetch._fetch_kb_object_from_ctibutler(
            "attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b"
        )

    assert obj["name"] == "Phishing"
    assert session.calls == [
        {
            "url": "https://api.ctibutler.com/v1/attack-enterprise/objects/attack-pattern--a62a8db3-f23a-4d8f-afd6-9dbc77e7813b/",
            "timeout": 30,
            "params": None,
        }
    ]


def test_get_all_pages_uses_initial_params_only():
    session = FakeSession(
        [
            {"objects": [{"id": "location--1"}], "page_size": 1, 'total_results_count': 2},
            {"objects": [{"id": "location--2"}], "page_size": 2, 'total_results_count': 2},
        ]
    )

    results = kb_fetch.get_all_pages(session, "https://api.ctibutler.com/")

    assert results == [{"id": "location--1"}, {"id": "location--2"}]
    assert session.calls == [
        {
            "url": "https://api.ctibutler.com/",
            "timeout": 30,
            "params": {"page": 1},
        },
        {
            "url": "https://api.ctibutler.com/",
            "timeout": 30,
            "params": {"page": 2},
        },
    ]


def test_vulmatch_session_uses_env_without_api_key(monkeypatch):
    monkeypatch.setenv("VULMATCH_BASE_URL", "https://api.vulmatch.com/")
    monkeypatch.delenv("VULMATCH_API_KEY", raising=False)

    session, base_url = kb_fetch.vulmatch_session()

    assert base_url == "https://api.vulmatch.com"
    assert "API-KEY" not in session.headers


def test_fetch_vulnerabilities_uses_vulmatch_session_and_returns_dict(monkeypatch):
    session = FakeSession([{"objects": [{"name": "CVE-2026-11438", "id": "vulnerability--1"}]}])
    calls = []

    def fake_get_all_pages(fake_session, url):
        calls.append((fake_session, url))
        return [{"name": "CVE-2026-11438", "id": "vulnerability--1"}]

    monkeypatch.setattr(kb_fetch, "vulmatch_session", lambda: (session, "https://api.vulmatch.com"))
    monkeypatch.setattr(kb_fetch, "get_all_pages", fake_get_all_pages)

    assert kb_fetch.fetch_vulnerabilities(["CVE-2026-11438"]) == {
        "CVE-2026-11438": {"name": "CVE-2026-11438", "id": "vulnerability--1"}
    }
    assert calls == [
        (
            session,
            "https://api.vulmatch.com/v1/cve/objects/?cve_id=CVE-2026-11438",
        )
    ]
