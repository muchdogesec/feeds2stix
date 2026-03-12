# write function that takes bundle object and uploads it to cyberthreat exchange (ctx), main function takes bundle file and uploads it to ctx
import copy
import json
import logging
import os
import sys
import time
import warnings
from pathlib import Path

import requests
from split_jsons import get_file_size_kb, split_stix_bundle

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BundleUploadFailed(Exception):
    """Exception raised when bundle upload fails with unrecoverable errors."""

    pass


def poll_job_status(job_id, api_base_url, api_key, poll_interval=5, max_wait=300):
    """
    Poll job status until it's completed or failed.

    Args:
        job_id: Job ID to poll
        api_base_url: Base URL for CTX API
        api_key: API key for authentication
        poll_interval: Seconds between polls
        max_wait: Maximum seconds to wait

    Returns:
        Final job state dict
    """
    url = f"{api_base_url}/v1/jobs/{job_id}/"
    headers = {"API-KEY": api_key}

    start_time = time.time()
    while True:
        elapsed = time.time() - start_time
        if elapsed > max_wait:
            logger.warning(f"Job {job_id} polling timeout after {max_wait}s")
            return {"state": "timeout", "id": job_id}

        try:
            response = requests.get(url, headers=headers)
            if not response.ok:
                logger.warning(f"Failed to poll job {job_id}: {response.status_code}")
                time.sleep(poll_interval)
                continue

            job_data = response.json()
            state = job_data.get("state", "unknown")

            if state in ["completed", "failed"]:
                return job_data
            elif state in ["pending", "processing"]:
                logger.info(f"Job {job_id} state: {state}, waiting...")
                time.sleep(poll_interval)
            else:
                logger.warning(f"Job {job_id} unknown state: {state}")
                time.sleep(poll_interval)

        except Exception as e:
            logger.error(f"Error polling job {job_id}: {e}")
            time.sleep(poll_interval)


def upload_bundle(
    bundle, api_base_url, api_key, feed_id, max_retries=3, wait_for_completion=False
):
    """
    Upload a STIX bundle to CTX with automatic retry and error handling.

    Args:
        bundle: STIX bundle dictionary
        api_base_url: Base URL for CTX API
        api_key: API key for authentication
        feed_id: Feed ID to upload to
        max_retries: Maximum number of retry attempts
        wait_for_completion: Wait for job to complete before returning

    Returns:
        Dictionary with upload results including job_id and any failed objects
    """
    url = f"{api_base_url}/v1/feeds/{feed_id}/bundle/"
    headers = {"API-KEY": api_key, "Content-Type": "application/json"}

    original_objects = bundle.get("objects", [])
    total_objects = len(original_objects)
    logger.info(f"Uploading bundle with {total_objects} objects to feed {feed_id}")

    failed_objects = []
    current_bundle = bundle.copy()
    error_msg = "Max retries exhausted without successful upload"

    req_responses = []
    job_id = None

    for attempt in range(max_retries):
        if attempt > 0:
            logger.info(f"Retry attempt {attempt}/{max_retries - 1}")

        try:
            req_responses.append(
                {"request_url": url, "request_body": copy.deepcopy(current_bundle)}
            )
            response = requests.post(url, headers=headers, json=current_bundle)
            req_responses[-1]["response_status"] = response.status_code
            req_responses[-1]["response_text"] = response.text
            job_result = response.json()
            req_responses[-1]["response_json"] = job_result
            del req_responses[-1]["response_text"]  # Remove text to save space
            if not response.ok:
                logger.warning(
                    f"Upload attempt failed with status {response.status_code}: {response.text}"
                )
                raise Exception(f"HTTP {response.status_code}: {response.text}")

            job_id = job_result.get("id")
            if job_result["state"] == "failed":
                logger.warning(f"Some objects failed validation")
                error_data = job_result.get("errors", {})
                if (
                    not isinstance(error_data, list)
                    or not error_data
                    or "objects" not in error_data[0]
                ):
                    raise BundleUploadFailed(error_data)

                error_data = error_data[0]

                objects_removed = 0
                for index, error in reversed(error_data["objects"].items()):
                    index = int(index)
                    obj = current_bundle["objects"][index]
                    failed_objects.append(
                        {
                            "id": obj.get("id"),
                            "errors": error,
                        }
                    )
                    current_bundle["objects"].pop(index)
                    logger.debug(f"Object {index} ({obj.get('type')}) failed: {error}")
                    objects_removed += 1
                logger.info(
                    f"Removed {objects_removed} problematic objects, retrying..."
                )

                if not current_bundle.get("objects"):
                    logger.warning("All objects failed validation")
                    return {
                        "success": True,
                        "job_id": job_id,
                        "total_objects": total_objects,
                        "submitted_objects": 0,
                        "failed_objects": failed_objects,
                        "error": "All objects failed validation",
                        "req_responses": req_responses,
                        "job_state": "failed",
                    }

                continue

            else:
                logger.info(f"Successfully uploaded bundle, job_id: {job_id}")
                logger.info(f"State: {job_result.get('state')}")

                result = {
                    "success": True,
                    "job_id": job_id,
                    "total_objects": total_objects,
                    "submitted_objects": len(current_bundle.get("objects", [])),
                    "failed_objects": failed_objects,
                    "req_responses": req_responses,
                    "job_state": job_result.get("state"),
                }

                if wait_for_completion and job_id:
                    logger.info(f"Waiting for job {job_id} to complete...")
                    final_job_data = poll_job_status(job_id, api_base_url, api_key)
                    result["job_state"] = final_job_data.get("state")
                    result["final_job_data"] = final_job_data
                    logger.info(f"Job {job_id} final state: {result['job_state']}")

                return result

        except BundleUploadFailed as e:
            logger.error("Unrecoverable error during upload")
            error_msg = f"Unrecoverable error during upload: {e}"
            break

        except Exception as e:
            logger.error(f"Error during upload attempt: {e}")
            if attempt == max_retries - 1:
                error_msg = f"Upload failed after {max_retries} attempts: {e}"
                break
            continue

    return {
        "success": False,
        "job_id": job_id,
        "total_objects": total_objects,
        "submitted_objects": 0,
        "failed_objects": failed_objects,
        "error": error_msg,
        "req_responses": req_responses,
        "job_state": "error",
    }


def write_github_summary(results, is_multi_bundle=False):
    """Write GitHub Actions step summary."""
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    try:
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write("## CTX Bundle Upload Summary\n\n")

            if is_multi_bundle:
                f.write("### Individual Bundle Results\n\n")
                f.write("| Job ID | Bundle | Total | Submitted | Failed | State |\n")
                f.write("|--------|--------|-------|-----------|--------|-------|\n")

                # Limit to first 50 results to avoid step summary size limits
                results_to_show = results[:50]
                remaining_count = len(results) - len(results_to_show)

                for result in results_to_show:
                    job_id = result.get("job_id", "N/A")
                    bundle_name = Path(result.get("bundle_file", "unknown")).name
                    total = result.get("total_objects", 0)
                    submitted = result.get("submitted_objects", 0)
                    failed = len(result.get("failed_objects", []))
                    state = result.get("job_state", "unknown")
                    state_emoji = (
                        "✅"
                        if state == "completed"
                        else ("⏳" if state in ["pending", "processing"] else "❌")
                    )

                    f.write(
                        f"| `{job_id}` | `{bundle_name}` | {total} | {submitted} | {failed} | {state_emoji} {state} |\n"
                    )

                if remaining_count > 0:
                    f.write(f"\n\n*...and {remaining_count} more bundles*\n\n")

                f.write("\n### Overall Summary\n\n")
                total_bundles = len(results)
                successful = sum(1 for r in results if r.get("success"))
                total_objects = sum(r.get("total_objects", 0) for r in results)
                submitted_objects = sum(r.get("submitted_objects", 0) for r in results)
                failed_objects = sum(len(r.get("failed_objects", [])) for r in results)

                f.write(f"- **Bundles Processed:** {successful}/{total_bundles}\n")
                f.write(f"- **Total Objects:** {total_objects}\n")
                f.write(f"- **Submitted Objects:** {submitted_objects}\n")
                f.write(f"- **Failed Objects:** {failed_objects}\n")

            else:
                result = results[0] if results else {}

                if result.get("success"):
                    f.write("✅ **Status:** Upload successful\n\n")
                    if result.get("job_id"):
                        f.write(f"- **Job ID:** `{result['job_id']}`\n")
                        if result.get("job_state"):
                            f.write(f"- **Job State:** {result['job_state']}\n")
                    f.write(f"- **Total Objects:** {result.get('total_objects', 0)}\n")
                    f.write(
                        f"- **Submitted Objects:** {result.get('submitted_objects', 0)}\n"
                    )
                    f.write(
                        f"- **Failed Objects:** {len(result.get('failed_objects', []))}\n"
                    )
                else:
                    f.write("❌ **Status:** Upload failed\n\n")
                    f.write(f"- **Error:** {result.get('error', 'Unknown error')}\n")
                    f.write(f"- **Total Objects:** {result.get('total_objects', 0)}\n")
                    f.write(
                        f"- **Failed Objects:** {len(result.get('failed_objects', []))}\n"
                    )

                if result.get("bundle_file"):
                    f.write(f"- **Bundle:** `{result['bundle_file']}`\n")

            f.write("\n")
        logger.info("GitHub Actions summary written")
    except Exception as e:
        logger.error(f"Failed to write GitHub Actions summary: {e}")


def save_artifacts(result, artifacts_base_dir, bundle_name, bundle_file):
    """Save artifacts for a single bundle upload."""
    bundle_artifacts_dir = os.path.join(artifacts_base_dir, bundle_name)
    os.makedirs(bundle_artifacts_dir, exist_ok=True)

    # Copy original bundle file to artifacts directory
    if bundle_file and os.path.exists(bundle_file):
        import shutil

        bundle_copy_path = os.path.join(bundle_artifacts_dir, Path(bundle_file).name)
        try:
            shutil.copy2(bundle_file, bundle_copy_path)
            logger.debug(f"Copied bundle to {bundle_copy_path}")
        except Exception as e:
            logger.error(f"Failed to copy bundle file: {e}")

    if result.get("req_responses"):
        for idx, req_resp in enumerate(result["req_responses"], 1):
            full_file = os.path.join(
                bundle_artifacts_dir, f"requests_and_responses_{idx}.json"
            )
            try:
                with open(full_file, "w", encoding="utf-8") as f:
                    json.dump(req_resp, f, indent=2)
                logger.debug(f"Saved full request/response to {full_file}")
            except Exception as e:
                logger.error(f"Failed to save full request/response: {e}")

            response_data = req_resp.get("response_json") or req_resp.get(
                "response_text"
            )
            if response_data:
                if isinstance(response_data, dict):
                    response_file = os.path.join(
                        bundle_artifacts_dir, f"response_{idx}.json"
                    )
                    try:
                        with open(response_file, "w", encoding="utf-8") as f:
                            json.dump(response_data, f, indent=2)
                        logger.debug(f"Saved response to {response_file}")
                    except Exception as e:
                        logger.error(f"Failed to save response: {e}")
                else:
                    response_file = os.path.join(
                        bundle_artifacts_dir, f"response_{idx}.txt"
                    )
                    try:
                        with open(response_file, "w", encoding="utf-8") as f:
                            f.write(str(response_data))
                        logger.debug(f"Saved response to {response_file}")
                    except Exception as e:
                        logger.error(f"Failed to save response: {e}")

    if result.get("failed_objects"):
        failed_objects_file = os.path.join(bundle_artifacts_dir, "failed_objects.json")
        try:
            with open(failed_objects_file, "w", encoding="utf-8") as f:
                json.dump(result["failed_objects"], f, indent=2)
            logger.info(
                f"Saved {len(result['failed_objects'])} failed objects to {failed_objects_file}"
            )
        except Exception as e:
            logger.error(f"Failed to save failed objects: {e}")

    return bundle_artifacts_dir


def main(bundle_files, api_base_url, api_key, feed_id, max_size_kb=10_000):
    try:
        # Expand directories to individual files
        all_bundle_files = []
        for bundle_file in bundle_files:
            if os.path.isdir(bundle_file):
                logger.info(f"Walking directory: {bundle_file}")
                json_files = []
                for root, dirs, files in os.walk(bundle_file):
                    for file in files:
                        if file.endswith(".json"):
                            json_files.append(os.path.join(root, file))
                json_files.sort()  # Sort alphabetically
                logger.info(f"Found {len(json_files)} JSON files in directory")
                all_bundle_files.extend(json_files)
            else:
                all_bundle_files.append(bundle_file)

        # Process files and split if necessary
        processed_files = []
        for bundle_file in all_bundle_files:
            bundle_size = os.path.getsize(bundle_file) / 1024
            if bundle_size > max_size_kb:
                logger.info(
                    f"Bundle {bundle_file} ({bundle_size:.2f} KB) exceeds max size ({max_size_kb} KB), splitting..."
                )
                split_files = split_stix_bundle(bundle_file, max_size_kb)
                processed_files.extend(split_files)
                logger.info(f"Split into {len(split_files)} parts")
            else:
                logger.info(
                    f"Bundle {bundle_file} ({bundle_size:.2f} KB) is within max size, no splitting needed"
                )
                processed_files.append(bundle_file)

        is_multi_bundle = len(processed_files) > 1
        results = []

        artifacts_dir = "upload_artifacts"
        os.makedirs(artifacts_dir, exist_ok=True)

        logger.info("=" * 120)
        logger.info("=" * 120)

        for bundle_file in processed_files:
            logger.info(f"Processing bundle: {bundle_file}")

            try:
                with open(bundle_file, "r") as f:
                    bundle = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load bundle {bundle_file}: {e}")
                results.append(
                    {
                        "success": False,
                        "bundle_file": bundle_file,
                        "total_objects": 0,
                        "submitted_objects": 0,
                        "failed_objects": [],
                        "error": f"Failed to load bundle: {e}",
                        "job_id": None,
                        "job_state": "error",
                    }
                )
                continue

            result = upload_bundle(
                bundle,
                api_base_url,
                api_key,
                feed_id,
                wait_for_completion=is_multi_bundle,
            )
            result["bundle_file"] = bundle_file
            results.append(result)

            bundle_name = Path(bundle_file).stem
            save_artifacts(result, artifacts_dir, bundle_name, bundle_file)

            if is_multi_bundle:
                job_id = result.get("job_id") or "N/A"
                bundle_name_display = Path(bundle_file).name[:28]
                total = result.get("total_objects", 0)
                submitted = result.get("submitted_objects", 0)
                failed = len(result.get("failed_objects", []))
                state = result.get("job_state") or "unknown"
                logger.info(
                    str(
                        {
                            "job_id": job_id,
                            "bundle_name": bundle_name_display,
                            "total": total,
                            "submitted": submitted,
                            "failed": failed,
                            "state": state,
                        }
                    )
                )

        write_github_summary(results, is_multi_bundle)

        logger.info("=" * 120)
        if is_multi_bundle:
            total_bundles = len(results)
            successful = sum(1 for r in results if r.get("success"))
            total_objects = sum(r.get("total_objects", 0) for r in results)
            submitted_objects = sum(r.get("submitted_objects", 0) for r in results)
            failed_objects_count = sum(
                len(r.get("failed_objects", [])) for r in results
            )

            logger.info(
                f"✅ Processed {successful}/{total_bundles} bundles successfully"
            )
            logger.info(f"   Total objects: {total_objects}")
            logger.info(f"   Submitted: {submitted_objects}")
            logger.info(f"   Failed: {failed_objects_count}")
        else:
            result = results[0]
            if result.get("success"):
                logger.info("✅ Upload successful!")
                if result.get("job_id"):
                    logger.info(f"   Job ID: {result['job_id']}")
                    if result.get("job_state"):
                        logger.info(f"   Job State: {result['job_state']}")
                logger.info(
                    f"   Submitted: {result.get('submitted_objects', 0)}/{result.get('total_objects', 0)} objects"
                )
                logger.info(
                    f"   Failed: {len(result.get('failed_objects', []))} objects"
                )
            else:
                logger.error(
                    f"❌ Upload failed: {result.get('error', 'Unknown error')}"
                )
                logger.error(
                    f"   Failed objects: {len(result.get('failed_objects', []))}/{result.get('total_objects', 0)}"
                )
        logger.info("=" * 120)

        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            try:
                with open(github_output, "a", encoding="utf-8") as f:
                    all_successful = all(r.get("success") for r in results)
                    f.write(f"success={str(all_successful).lower()}\n")
                    f.write(f"bundles_processed={len(results)}\n")
                    f.write(f"artifacts_dir={artifacts_dir}\n")
                    if len(results) == 1:
                        result = results[0]
                        f.write(f"job_id={result.get('job_id', '')}\n")
                        f.write(f"total_objects={result.get('total_objects', 0)}\n")
                        f.write(
                            f"submitted_objects={result.get('submitted_objects', 0)}\n"
                        )
                        f.write(
                            f"failed_objects={len(result.get('failed_objects', []))}\n"
                        )
            except Exception as e:
                logger.error(f"Failed to write GitHub output: {e}")

        if not all(r.get("success") for r in results):
            sys.exit(1)

        sys.exit(0)

    except BundleUploadFailed as e:
        logger.error(f"Bundle upload failed with unrecoverable error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Upload STIX bundle(s) to CyberThreat eXchange (CTX)",
        epilog="""
Environment Variables:
  CTX_BASE_URL    Base URL for the CTX API
  CTX_API_KEY     API key for authentication

Example:
  export CTX_BASE_URL="https://api.cyberthreatexchange.com"
  export CTX_API_KEY="your-api-key"
  python helpers/upload.py bundles/ipsum/bundles/ipsum_level_8.json --feed_id YOUR_FEED_ID
  python helpers/upload.py bundle1.json bundle2.json bundle3.json --feed_id YOUR_FEED_ID
  python helpers/upload.py large_bundle.json --feed_id YOUR_FEED_ID --max-size 4000
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "bundle_files", nargs="+", help="Path(s) to the STIX bundle file(s)"
    )
    parser.add_argument(
        "--feed_id",
        "--feed-id",
        help="ID of the feed to upload the bundle to",
        required=True,
    )
    parser.add_argument(
        "--max-size",
        "--max_size",
        type=float,
        help="Maximum size of bundles in kilobytes (KB). Bundles larger than this will be automatically split.",
    )

    args = parser.parse_args()
    args.max_size = args.max_size or float(os.getenv("MAX_BUNDLE_SIZE_KB", 10_000))

    api_base_url = os.getenv("CTX_BASE_URL")
    if not api_base_url:
        logger.error("CTX_BASE_URL environment variable is not set")
        sys.exit(1)

    api_key = os.getenv("CTX_API_KEY")
    if not api_key:
        logger.error("CTX_API_KEY environment variable is not set")
        sys.exit(1)

    main(args.bundle_files, api_base_url, api_key, args.feed_id, args.max_size)
