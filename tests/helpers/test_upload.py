import builtins
import json
from pathlib import Path

import pytest

from helpers import upload
from tests import utils as test_utils


def test_poll_job_status_completed(monkeypatch):
    monkeypatch.setattr(
        upload.requests,
        "get",
        lambda *a, **k: test_utils.FakeJSONResponse({"id": "j1", "state": "completed"}),
    )
    result = upload.poll_job_status(
        "j1", "https://ctx", "k", poll_interval=0, max_wait=5
    )
    assert result["state"] == "completed"


def test_poll_job_status_timeout(monkeypatch):
    call_count = 0

    def mock_time():
        nonlocal call_count
        call_count += 1
        # First call returns 0 (start_time), subsequent calls return 10 (elapsed > max_wait)
        return 0 if call_count == 1 else 10

    monkeypatch.setattr(upload.time, "time", mock_time)
    result = upload.poll_job_status(
        "j1", "https://ctx", "k", poll_interval=0, max_wait=5
    )
    assert result["state"] == "timeout"


def test_poll_job_status_handles_pending_unknown_and_not_ok(monkeypatch):
    responses = iter(
        [
            test_utils.FakeResponse(status_code=500),
            test_utils.FakeJSONResponse({"state": "pending"}),
            test_utils.FakeJSONResponse({"state": "weird"}),
            test_utils.FakeJSONResponse({"state": "completed", "id": "j1"}),
        ]
    )
    monkeypatch.setattr(upload.requests, "get", lambda *a, **k: next(responses))
    monkeypatch.setattr(upload.time, "sleep", lambda *_: None)
    result = upload.poll_job_status(
        "j1", "https://ctx", "k", poll_interval=0, max_wait=5
    )
    assert result["state"] == "completed"


def test_upload_bundle_success(monkeypatch):
    monkeypatch.setattr(
        upload.requests,
        "post",
        lambda *a, **k: test_utils.FakeJSONResponse(
            {"id": "job-1", "state": "completed"}
        ),
    )
    result = upload.upload_bundle(
        {"objects": [{"id": "a"}]}, "https://ctx", "k", "feed"
    )
    assert result["success"] is True
    assert result["job_id"] == "job-1"


def test_upload_bundle_removes_failed_object_and_retries(monkeypatch):
    responses = [
        test_utils.FakeJSONResponse(
            {
                "id": "job-fail",
                "state": "failed",
                "errors": [{"objects": {"0": ["bad"]}}],
            }
        ),
        test_utils.FakeJSONResponse({"id": "job-ok", "state": "completed"}),
    ]
    monkeypatch.setattr(upload.requests, "post", lambda *a, **k: responses.pop(0))
    bundle = {"objects": [{"id": "bad-obj"}, {"id": "good-obj"}]}
    result = upload.upload_bundle(bundle, "https://ctx", "k", "feed", max_retries=3)
    assert result["success"] is True
    assert len(result["failed_objects"]) == 1
    assert result["submitted_objects"] == 1


def test_upload_bundle_unrecoverable_error(monkeypatch):
    monkeypatch.setattr(
        upload.requests,
        "post",
        lambda *a, **k: test_utils.FakeJSONResponse(
            {"id": "job", "state": "failed", "errors": {"oops": 1}}
        ),
    )
    result = upload.upload_bundle(
        {"objects": [{"id": "a"}]}, "https://ctx", "k", "feed"
    )
    assert result["success"] is False
    assert result["job_state"] == "error"


def test_upload_bundle_all_objects_fail_returns_success_true(monkeypatch):
    monkeypatch.setattr(
        upload.requests,
        "post",
        lambda *a, **k: test_utils.FakeJSONResponse(
            {
                "id": "job",
                "state": "failed",
                "errors": [{"objects": {"0": ["bad"]}}],
            }
        ),
    )
    result = upload.upload_bundle(
        {"objects": [{"id": "a"}]}, "https://ctx", "k", "feed", max_retries=1
    )
    assert result["success"] is True
    assert result["submitted_objects"] == 0


def test_upload_bundle_wait_for_completion(monkeypatch):
    monkeypatch.setattr(
        upload.requests,
        "post",
        lambda *a, **k: test_utils.FakeJSONResponse(
            {"id": "job-1", "state": "processing"}
        ),
    )
    monkeypatch.setattr(
        upload, "poll_job_status", lambda *a, **k: {"state": "completed", "id": "job-1"}
    )
    result = upload.upload_bundle(
        {"objects": [{"id": "a"}]}, "https://ctx", "k", "feed", wait_for_completion=True
    )
    assert result["job_state"] == "completed"
    assert result["final_job_data"]["id"] == "job-1"


def test_upload_bundle_http_error_retries_and_fails(monkeypatch):
    monkeypatch.setattr(
        upload.requests,
        "post",
        lambda *a, **k: test_utils.FakeJSONResponse({"state": "x"}, status_code=500),
    )
    result = upload.upload_bundle(
        {"objects": [{"id": "a"}]}, "https://ctx", "k", "feed", max_retries=2
    )
    assert result["success"] is False
    assert "Upload failed after 2 attempts" in result["error"]


def test_write_github_summary_single(monkeypatch, tmp_path):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    upload.write_github_summary(
        [
            {
                "success": True,
                "job_id": "job-1",
                "job_state": "completed",
                "total_objects": 2,
                "submitted_objects": 2,
                "failed_objects": [],
            }
        ]
    )
    text = summary.read_text()
    assert "CTX Bundle Upload Summary" in text
    assert "job-1" in text


def test_write_github_summary_multi(monkeypatch, tmp_path):
    summary = tmp_path / "summary_multi.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    upload.write_github_summary(
        [
            {
                "success": True,
                "job_id": "job-1",
                "bundle_file": "a.json",
                "job_state": "completed",
                "total_objects": 2,
                "submitted_objects": 2,
                "failed_objects": [],
            },
            {
                "success": False,
                "job_id": "job-2",
                "bundle_file": "b.json",
                "job_state": "failed",
                "total_objects": 3,
                "submitted_objects": 1,
                "failed_objects": [{"id": "x"}],
            },
        ],
        is_multi_bundle=True,
    )
    text = summary.read_text()
    assert "Individual Bundle Results" in text
    assert "Overall Summary" in text


def test_write_github_summary_no_env(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    upload.write_github_summary([{"success": True}], is_multi_bundle=False)


def test_write_github_summary_multi_truncates_after_50(monkeypatch, tmp_path):
    summary = tmp_path / "summary_many.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    results = []
    for i in range(55):
        results.append(
            {
                "success": True,
                "job_id": f"job-{i}",
                "bundle_file": f"b{i}.json",
                "job_state": "completed",
                "total_objects": 1,
                "submitted_objects": 1,
                "failed_objects": [],
            }
        )
    upload.write_github_summary(results, is_multi_bundle=True)
    text = summary.read_text()
    assert "and 5 more bundles" in text


def test_save_artifacts_writes_files(tmp_path):
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text("{}")
    result = {
        "req_responses": [
            {
                "request_url": "u",
                "response_json": {"ok": True},
            },
            {
                "request_url": "u",
                "response_text": "bad",
            },
        ],
        "failed_objects": [{"id": "x"}],
    }
    out_dir = upload.save_artifacts(result, str(tmp_path), "bundleA", str(bundle_file))
    assert Path(out_dir).exists()
    assert (Path(out_dir) / "requests_and_responses_1.json").exists()
    assert (Path(out_dir) / "failed_objects.json").exists()


def test_save_artifacts_handles_copy_failure(monkeypatch, tmp_path):
    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text("{}")

    real_import = builtins.__import__

    class FakeShutil:
        @staticmethod
        def copy2(*args, **kwargs):
            raise RuntimeError("copy fail")

    def fake_import(name, *args, **kwargs):
        if name == "shutil":
            return FakeShutil
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    out_dir = upload.save_artifacts(
        {"req_responses": [], "failed_objects": []},
        str(tmp_path),
        "bundleB",
        str(bundle_file),
    )
    assert Path(out_dir).exists()


def test_main_success_path(monkeypatch, tmp_path):
    bundle_file = tmp_path / "one.json"
    bundle_file.write_text(json.dumps({"type": "bundle", "objects": []}))

    monkeypatch.setattr(upload.os.path, "getsize", lambda *_: 1)
    monkeypatch.setattr(upload, "split_stix_bundle", lambda *a, **k: [])
    monkeypatch.setattr(
        upload,
        "upload_bundle",
        lambda *a, **k: {
            "success": True,
            "job_id": "j",
            "total_objects": 0,
            "submitted_objects": 0,
            "failed_objects": [],
            "job_state": "completed",
        },
    )
    monkeypatch.setattr(upload, "save_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(upload, "write_github_summary", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        upload.main([str(bundle_file)], "https://ctx", "key", "feed")
    assert exc.value.code == 0


def test_main_success_writes_github_output(monkeypatch, tmp_path):
    bundle_file = tmp_path / "one.json"
    bundle_file.write_text(json.dumps({"type": "bundle", "objects": [{"id": "indicator--1"}]}))
    gh = tmp_path / "gh.out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh))
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")

    monkeypatch.setattr(upload.os.path, "getsize", lambda *_: 1)
    monkeypatch.setattr(upload, "split_stix_bundle", lambda *a, **k: [])
    monkeypatch.setattr(
        upload,
        "upload_bundle",
        lambda *a, **k: {
            "success": True,
            "job_id": "job-x",
            "total_objects": 3,
            "submitted_objects": 3,
            "failed_objects": [],
            "job_state": "completed",
        },
    )
    monkeypatch.setattr(upload, "save_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(upload, "write_github_summary", lambda *a, **k: None)
    # Mock hashmanager
    monkeypatch.setattr(upload.hashmanager, "download_artifact", lambda *a, **k: False)
    monkeypatch.setattr(upload.hashmanager, "cleanup_old_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(upload.hashmanager, "load_db", lambda *a, **k: None)
    monkeypatch.setattr(upload.hashmanager, "filter_new_objects", lambda objs, conn: (objs, 0))
    monkeypatch.setattr(upload.hashmanager, "record_uploaded_objects", lambda *a, **k: None)
    monkeypatch.setattr(upload.hashmanager, "save_db", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        upload.main([str(bundle_file)], "https://ctx", "key", "feed")
    assert exc.value.code == 0
    text = gh.read_text()
    assert "job_id=job-x" in text
    assert "bundles_processed=1" in text


def test_main_directory_and_split_flow(monkeypatch, tmp_path):
    in_dir = tmp_path / "in"
    in_dir.mkdir()
    src1 = in_dir / "a.json"
    src2 = in_dir / "b.json"
    src1.write_text("{}")
    src2.write_text("{}")

    split1 = tmp_path / "split1.json"
    split2 = tmp_path / "split2.json"
    split1.write_text(json.dumps({"type": "bundle", "objects": []}))
    split2.write_text(json.dumps({"type": "bundle", "objects": []}))

    monkeypatch.setattr(upload.os.path, "getsize", lambda *_: 100000)
    monkeypatch.setattr(
        upload, "split_stix_bundle", lambda *a, **k: [str(split1), str(split2)]
    )
    monkeypatch.setattr(
        upload,
        "upload_bundle",
        lambda *a, **k: {
            "success": True,
            "job_id": "job-m",
            "total_objects": 0,
            "submitted_objects": 0,
            "failed_objects": [],
            "job_state": "completed",
        },
    )
    monkeypatch.setattr(upload, "save_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(upload, "write_github_summary", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        upload.main([str(in_dir)], "https://ctx", "key", "feed", max_size_kb=1)
    assert exc.value.code == 0


def test_main_catches_bundleuploadfailed(monkeypatch, tmp_path):
    bundle_file = tmp_path / "one.json"
    bundle_file.write_text(json.dumps({"type": "bundle", "objects": [{"id": "indicator--1"}]}))
    monkeypatch.setattr(upload.os.path, "getsize", lambda *_: 1)
    # Mock hashmanager
    monkeypatch.setattr(upload.hashmanager, "download_artifact", lambda *a, **k: False)
    monkeypatch.setattr(upload.hashmanager, "cleanup_old_artifacts", lambda *a, **k: None)
    monkeypatch.setattr(upload.hashmanager, "load_db", lambda *a, **k: None)
    monkeypatch.setattr(upload.hashmanager, "filter_new_objects", lambda objs, conn: (objs, 0))
    monkeypatch.setattr(upload.hashmanager, "record_uploaded_objects", lambda *a, **k: None)
    monkeypatch.setattr(upload.hashmanager, "save_db", lambda *a, **k: None)
    monkeypatch.setattr(
        upload,
        "upload_bundle",
        lambda *a, **k: (_ for _ in ()).throw(upload.BundleUploadFailed("bad")),
    )
    monkeypatch.setattr(upload, "write_github_summary", lambda *a, **k: None)
    monkeypatch.setattr(upload, "save_artifacts", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        upload.main([str(bundle_file)], "https://ctx", "key", "feed")
    assert exc.value.code == 1


def test_main_catches_generic_exception(monkeypatch, tmp_path):
    bundle_file = tmp_path / "one.json"
    bundle_file.write_text(json.dumps({"type": "bundle", "objects": []}))
    monkeypatch.setattr(
        upload.os.path,
        "getsize",
        lambda *_: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    with pytest.raises(SystemExit) as exc:
        upload.main([str(bundle_file)], "https://ctx", "key", "feed")
    assert exc.value.code == 1


def test_main_exits_nonzero_when_bundle_load_fails(monkeypatch, tmp_path):
    bad_bundle = tmp_path / "bad.json"
    bad_bundle.write_text("{not-json")

    monkeypatch.setattr(upload.os.path, "getsize", lambda *_: 1)
    monkeypatch.setattr(upload, "write_github_summary", lambda *a, **k: None)
    monkeypatch.setattr(upload, "save_artifacts", lambda *a, **k: None)

    with pytest.raises(SystemExit) as exc:
        upload.main([str(bad_bundle)], "https://ctx", "key", "feed")
    assert exc.value.code == 1
