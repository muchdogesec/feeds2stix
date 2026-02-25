# write function that takes bundle object and uploads it to cyberthreat exchange (ctx), main function takes bundle file and uploads it to ctx
import json
import sys
import warnings
import requests
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BundleUploadFailed(Exception):
    """Exception raised when bundle upload fails with unrecoverable errors."""

    pass


def upload_bundle(bundle, api_base_url, api_key, feed_id, max_retries=3):
    """
    Upload a STIX bundle to CTX with automatic retry and error handling.

    Args:
        bundle: STIX bundle dictionary
        api_base_url: Base URL for CTX API
        api_key: API key for authentication
        feed_id: Feed ID to upload to
        max_retries: Maximum number of retry attempts

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

    req_responses = []  # Store responses for debugging

    for attempt in range(max_retries):
        if attempt > 0:
            logger.info(f"Retry attempt {attempt}/{max_retries - 1}")

        try:
            req_responses.append({"request_body": current_bundle})
            response = requests.post(url, headers=headers, json=current_bundle)
            req_responses[-1]["response_status"] = response.status_code
            req_responses[-1]["response_text"] = response.text
            result = response.json()
            req_responses[-1]["response_json"] = result
            if not response.ok:
                logger.warning(
                    f"Upload attempt failed with status {response.status_code}: {response.text}"
                )
                raise Exception(f"HTTP {response.status_code}: {response.text}")

            if result["state"] == "failed":
                # Parse error response to identify problematic objects
                logger.warning(f"Some objects failed validation")
                error_data = response.json().get("errors", {})
                if (
                    not isinstance(error_data, list)
                    or not error_data
                    or "objects" not in error_data[0]
                ):
                    # If errors is not a list or is empty, treat as unrecoverable
                    raise BundleUploadFailed(error_data)

                error_data = error_data[0]

                # Extract failed object indices
                objects_removed = 0
                for index, error in reversed(
                    error_data["objects"].items()
                ):  # Reverse to avoid index shifting when removing
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

                # If no objects left, return early
                if not current_bundle.get("objects"):
                    logger.warning("All objects failed validation")
                    return {
                        "success": True,
                        "job_id": None,
                        "total_objects": total_objects,
                        "submitted_objects": 0,
                        "failed_objects": failed_objects,
                        "error": "All objects failed validation",
                        "req_responses": req_responses,
                    }

                # Continue to retry with cleaned bundle
                continue

            else:
                job_id = result.get("id")
                logger.info(f"Successfully uploaded bundle, job_id: {job_id}")
                logger.info(f"State: {result.get('state')}")

                return {
                    "success": True,
                    "job_id": job_id,
                    "total_objects": total_objects,
                    "submitted_objects": len(current_bundle.get("objects", [])),
                    "failed_objects": failed_objects,
                    "req_responses": req_responses,
                }

        except BundleUploadFailed as e:
            # Unrecoverable error, don't retry
            logger.error("Unrecoverable error during upload")
            error_msg = f"Unrecoverable error during upload: {e}"
            break

        except Exception as e:
            logger.error(f"Error during upload attempt: {e}")
            if attempt == max_retries - 1:
                # Last attempt failed
                error_msg = f"Upload failed after {max_retries} attempts: {e}"
                break
            continue

    # All retries exhausted
    return {
        "success": False,
        "job_id": None,
        "total_objects": total_objects,
        "submitted_objects": 0,
        "failed_objects": failed_objects,
        "error": error_msg,
        "req_responses": req_responses,
    }


def write_github_summary(result, bundle_file):
    """Write GitHub Actions step summary."""
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    try:
        with open(summary_file, "a", encoding="utf-8") as f:
            f.write("## CTX Bundle Upload Summary\n\n")

            if result["success"]:
                f.write("✅ **Status:** Upload successful\n\n")
                if result["job_id"]:
                    f.write(f"- **Job ID:** `{result['job_id']}`\n")
                f.write(f"- **Total Objects:** {result['total_objects']}\n")
                f.write(f"- **Submitted Objects:** {result['submitted_objects']}\n")
                f.write(f"- **Failed Objects:** {len(result['failed_objects'])}\n")
            else:
                f.write("❌ **Status:** Upload failed\n\n")
                f.write(f"- **Error:** {result.get('error', 'Unknown error')}\n")
                f.write(f"- **Total Objects:** {result['total_objects']}\n")
                f.write(f"- **Failed Objects:** {len(result['failed_objects'])}\n")

            f.write(f"- **Bundle:** `{bundle_file}`\n")

            if result.get("req_responses"):
                f.write(f"\n### Artifacts\n\n")
                num_requests = len(result["req_responses"])
                f.write(
                    f"- `requests_and_responses_{{1..{num_requests}}}.json` - Full request/response data\n"
                )
                f.write(
                    f"- `response_{{1..{num_requests}}}.json` - Individual responses\n"
                )
                if result["failed_objects"]:
                    f.write(
                        f"- `failed_objects.json` - {len(result['failed_objects'])} failed object(s)\n"
                    )

            f.write("\n")
        logger.info("GitHub Actions summary written")
    except Exception as e:
        logger.error(f"Failed to write GitHub Actions summary: {e}")


def main(bundle_file, api_base_url, api_key, feed_id):
    try:
        logger.info(f"Loading bundle from {bundle_file}")
        with open(bundle_file, "r") as file:
            bundle = json.load(file)

        result = upload_bundle(bundle, api_base_url, api_key, feed_id)

        # Create artifacts directory
        artifacts_dir = "upload_artifacts"
        os.makedirs(artifacts_dir, exist_ok=True)

        # Save request/response data
        if result.get("req_responses"):
            for idx, req_resp in enumerate(result["req_responses"], 1):
                # Save full request and response
                full_file = os.path.join(
                    artifacts_dir, f"requests_and_responses_{idx}.json"
                )
                try:
                    with open(full_file, "w", encoding="utf-8") as f:
                        json.dump(req_resp, f, indent=2)
                    logger.info(f"Saved full request/response to {full_file}")
                except Exception as e:
                    logger.error(f"Failed to save full request/response: {e}")

                # Save individual response
                response_data = req_resp.get("response_json") or req_resp.get(
                    "response_text"
                )
                if response_data:
                    if isinstance(response_data, dict):
                        response_file = os.path.join(
                            artifacts_dir, f"response_{idx}.json"
                        )
                        try:
                            with open(response_file, "w", encoding="utf-8") as f:
                                json.dump(response_data, f, indent=2)
                            logger.info(f"Saved response to {response_file}")
                        except Exception as e:
                            logger.error(f"Failed to save response: {e}")
                    else:
                        response_file = os.path.join(
                            artifacts_dir, f"response_{idx}.txt"
                        )
                        try:
                            with open(response_file, "w", encoding="utf-8") as f:
                                f.write(str(response_data))
                            logger.info(f"Saved response to {response_file}")
                        except Exception as e:
                            logger.error(f"Failed to save response: {e}")

        # Save failed objects as artifact if any
        failed_objects_file = None
        if result["failed_objects"]:
            failed_objects_file = os.path.join(artifacts_dir, "failed_objects.json")
            try:
                with open(failed_objects_file, "w", encoding="utf-8") as f:
                    json.dump(result["failed_objects"], f, indent=2)
                logger.info(
                    f"Saved {len(result['failed_objects'])} failed objects to {failed_objects_file}"
                )
            except Exception as e:
                logger.error(f"Failed to save failed objects: {e}")
                failed_objects_file = None

        # Write GitHub Actions summary
        write_github_summary(result, bundle_file)

        # Print results
        logger.info("=" * 60)
        if result["success"]:
            logger.info("✅ Upload successful!")
            if result["job_id"]:
                logger.info(f"   Job ID: {result['job_id']}")
            logger.info(
                f"   Submitted: {result['submitted_objects']}/{result['total_objects']} objects"
            )
            logger.info(f"   Failed: {len(result['failed_objects'])} objects")

            if failed_objects_file:
                logger.info(f"   Failed objects saved to: {failed_objects_file}")
        else:
            logger.error(f"❌ Upload failed: {result.get('error', 'Unknown error')}")
            logger.error(
                f"   Failed objects: {len(result['failed_objects'])}/{result['total_objects']}"
            )
        logger.info("=" * 60)

        # Output for GitHub Actions
        github_output = os.getenv("GITHUB_OUTPUT")
        if github_output:
            try:
                with open(github_output, "a", encoding="utf-8") as f:
                    f.write(f"success={str(result['success']).lower()}\n")
                    f.write(f"job_id={result.get('job_id', '')}\n")
                    f.write(f"total_objects={result['total_objects']}\n")
                    f.write(f"submitted_objects={result['submitted_objects']}\n")
                    f.write(f"failed_objects={len(result['failed_objects'])}\n")
                    f.write(f"artifacts_dir={artifacts_dir}\n")
            except Exception as e:
                logger.error(f"Failed to write GitHub output: {e}")

        if not result["success"]:
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
        description="Upload a STIX bundle to CyberThreat eXchange (CTX)",
        epilog="""
Environment Variables:
  CTX_BASE_URL    Base URL for the CTX API
  CTX_API_KEY     API key for authentication

Example:
  export CTX_BASE_URL="https://api.cyberthreatexchange.com"
  export CTX_API_KEY="your-api-key"
  python helpers/upload.py bundles/ipsum/bundles/ipsum_level_8.json --feed_id YOUR_FEED_ID
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("bundle_file", help="Path to the STIX bundle file")
    parser.add_argument(
        "--feed_id",
        "--feed-id",
        help="ID of the feed to upload the bundle to",
        required=True,
    )

    args = parser.parse_args()

    # Check environment variables after parsing args (allows --help to work)
    api_base_url = os.getenv("CTX_BASE_URL")
    if not api_base_url:
        logger.error("CTX_BASE_URL environment variable is not set")
        sys.exit(1)

    api_key = os.getenv("CTX_API_KEY")
    if not api_key:
        logger.error("CTX_API_KEY environment variable is not set")
        sys.exit(1)

    main(args.bundle_file, api_base_url, api_key, args.feed_id)
