import json
import os
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import call, patch, MagicMock

import pytest
import stix2

# Set required env vars before importing modules that read them at module level.
# ransomware2stix.parser reads RANSOMWARE_LIVE_API_KEY from os.environ at import time.
os.environ.setdefault("RANSOMWARE_LIVE_API_KEY", "test-api-key")
os.environ.setdefault("CTIBUTLER_BASE_URL", "http://test.ctibutler.com")
os.environ.setdefault("CTIBUTLER_API_KEY", "test-ctibutler-key")
os.environ.setdefault("VULMATCH_BASE_URL", "http://test.vulmatch.com")
os.environ.setdefault("VULMATCH_API_KEY", "test-vulmatch-key")

from processors.ransomware_live import ransomware_live  # noqa: E402

_FAKE_IDENTITY = stix2.Identity(
    id="identity--7bae962c-40ae-5817-8cdc-e1b6eb4f38f5",
    name="ransomware2stix",
    identity_class="system",
    created="2020-01-01T00:00:00.000Z",
    modified="2020-01-01T00:00:00.000Z",
)
_FAKE_BUNDLE_1 = stix2.Bundle(objects=[_FAKE_IDENTITY])
_FAKE_BUNDLE_2 = stix2.Bundle(objects=[_FAKE_IDENTITY])

_ALL_ENV_VARS = {
    "CTIBUTLER_BASE_URL": "http://test.ctibutler.com",
    "CTIBUTLER_API_KEY": "test-ctibutler-key",
    "VULMATCH_BASE_URL": "http://test.vulmatch.com",
    "VULMATCH_API_KEY": "test-vulmatch-key",
    "RANSOMWARE_LIVE_API_KEY": "test-api-key",
}


def _fake_run(args):
    yield "clop", _FAKE_BUNDLE_1
    yield "akira", _FAKE_BUNDLE_2


def test_required_env_vars_list():
    assert set(ransomware_live.REQUIRED_ENV_VARS) == {
        "CTIBUTLER_BASE_URL",
        "CTIBUTLER_API_KEY",
        "VULMATCH_BASE_URL",
        "VULMATCH_API_KEY",
        "RANSOMWARE_LIVE_API_KEY",
    }


def test_missing_env_var_exits(monkeypatch):
    monkeypatch.delenv("CTIBUTLER_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["ransomware_live.py"])
    with pytest.raises(SystemExit) as exc_info:
        ransomware_live.main()
    assert exc_info.value.code == 2


def test_missing_env_var_error_names_the_missing_var(monkeypatch, capsys):
    monkeypatch.delenv("VULMATCH_API_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["ransomware_live.py"])
    with pytest.raises(SystemExit):
        ransomware_live.main()
    captured = capsys.readouterr()
    assert "VULMATCH_API_KEY" in captured.err


def test_main_success_writes_bundles_and_github_output(monkeypatch, tmp_path):
    out_file = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    for k, v in _ALL_ENV_VARS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(sys, "argv", ["ransomware_live.py"])
    monkeypatch.setattr(ransomware_live, "BASE_OUTPUT_DIR", str(tmp_path / "output"))

    with patch(
        "processors.ransomware_live.ransomware_live.ransomware2stix_main.run",
        side_effect=_fake_run,
    ), patch(
        "processors.ransomware_live.ransomware_live.save_bundle_to_file",
        wraps=ransomware_live.save_bundle_to_file,
    ) as mock_save:
        ransomware_live.main()

    assert mock_save.call_count == 2
    saved_filenames = [c.args[2] for c in mock_save.call_args_list]
    assert "clop" in saved_filenames
    assert "akira" in saved_filenames

    output_text = out_file.read_text()
    assert "bundle_count=2" in output_text
    assert "bundle_path=" in output_text

    bundle_dir = Path(output_text.split("bundle_path=")[1].split("\n")[0].strip())
    bundle_files = sorted(bundle_dir.glob("*.json"))
    assert len(bundle_files) == 2
    assert {f.name for f in bundle_files} == {"clop.json", "akira.json"}


def test_main_passes_date_and_group_args_to_run(monkeypatch, tmp_path):
    for k, v in _ALL_ENV_VARS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(sys, "argv", [
        "ransomware_live.py",
        "--since-date", "2026-01-01",
        "--until-date", "2026-04-01",
        "--groups", "clop", "akira",
    ])
    monkeypatch.setattr(ransomware_live, "BASE_OUTPUT_DIR", str(tmp_path / "output"))

    captured = []

    def capture_run(args):
        captured.append(args)
        yield from _fake_run(args)

    with patch(
        "processors.ransomware_live.ransomware_live.ransomware2stix_main.run",
        side_effect=capture_run,
    ):
        ransomware_live.main()

    assert len(captured) == 1
    args = captured[0]
    assert args.groups == ["clop", "akira"]
    assert args.min_discovered == datetime(2026, 1, 1)
    assert args.max_discovered == datetime(2026, 4, 1)


def test_main_no_args_passes_none_dates_and_empty_groups(monkeypatch, tmp_path):
    for k, v in _ALL_ENV_VARS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(sys, "argv", ["ransomware_live.py"])
    monkeypatch.setattr(ransomware_live, "BASE_OUTPUT_DIR", str(tmp_path / "output"))

    captured = []

    def capture_run(args):
        captured.append(args)
        return iter([])

    with patch(
        "processors.ransomware_live.ransomware_live.ransomware2stix_main.run",
        side_effect=capture_run,
    ):
        ransomware_live.main()

    assert len(captured) == 1
    args = captured[0]
    assert args.min_discovered is None
    assert args.max_discovered is None
    assert args.groups == []


def test_main_no_github_output_env_does_not_fail(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    for k, v in _ALL_ENV_VARS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(sys, "argv", ["ransomware_live.py"])
    monkeypatch.setattr(ransomware_live, "BASE_OUTPUT_DIR", str(tmp_path / "output"))

    with patch(
        "processors.ransomware_live.ransomware_live.ransomware2stix_main.run",
        side_effect=_fake_run,
    ):
        ransomware_live.main()  # should not raise
