#!/usr/bin/env python3
"""
clean_hashmanagers.py — Delete hashmanager artifacts from GitHub Actions

This script deletes hashmanager artifacts (deduplication databases) from 
GitHub Actions, with optional filtering by artifact name.

Usage:
    python helpers/clean_hashmanagers.py
    python helpers/clean_hashmanagers.py --name-contains staging
    python helpers/clean_hashmanagers.py --name-contains ipsum --dry-run

Examples:
    # Delete all hashmanager artifacts
    python helpers/clean_hashmanagers.py

    # Delete hashmanagers with 'staging' in the name
    python helpers/clean_hashmanagers.py --name-contains staging

    # Preview what would be deleted without actually deleting
    python helpers/clean_hashmanagers.py --name-contains production --dry-run
"""

import argparse
import logging
import os
import sys
from typing import Optional

import hashmanager, requests

logger = logging.getLogger(__name__)

GITHUB_REPO = "muchdogesec/feeds2stix"

def list_all_artifacts(token: str) -> list[dict]:
    """List all artifacts from the GitHub repository."""
    list_url = f"{hashmanager._GH_API_BASE}/repos/{GITHUB_REPO}/actions/artifacts"
    all_artifacts = []
    page = 1
    per_page = 100
    
    while True:
        params = {"per_page": per_page, "page": page}
        try:
            resp = requests.get(
                list_url, headers=hashmanager._gh_headers(token), params=params, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.error(f"Failed to list artifacts (page {page}): {exc}")
            break
        
        artifacts = data.get("artifacts", [])
        if not artifacts:
            break
        
        all_artifacts.extend(artifacts)
        
        # Check if there are more pages
        total_count = data.get("total_count", 0)
        if len(all_artifacts) >= total_count:
            break
        
        page += 1
    
    logger.info(f"Found {len(all_artifacts)} total artifacts in {GITHUB_REPO}")
    return all_artifacts


def filter_hashmanager_artifacts(
    artifacts: list[dict], 
    name_contains: Optional[str] = None,
    feeds: Optional[list[str]] = None
) -> list[dict]:
    """Filter artifacts to only include hashmanager artifacts ending with _dupedb.
    
    Args:
        artifacts: List of all artifacts
        name_contains: Optional substring to filter artifact names
        feeds: Optional list of feed IDs to filter artifact names
    Returns:
        Filtered list of hashmanager artifacts
    """
    artifacts_to_remove = []
    feeds = [feed_id.lower().replace("-", "") for feed_id in feeds] if feeds else None
    
    for artifact in artifacts:
        name = artifact.get("name", "")
        
        if not name.endswith("_dupedb"):
            continue
        
        if name_contains and name_contains not in name:
            continue
        
        if feeds and not any(feed_id in name for feed_id in feeds):
            continue
        
        artifacts_to_remove.append(artifact)
    
    filter_desc = f" (name contains '{name_contains}')" if name_contains else ""
    if feeds:
        filter_desc += f" (feeds: {', '.join(feeds)})"
    logger.info(f"Filtered to {len(artifacts_to_remove)} hashmanager artifacts{filter_desc}")
    return artifacts_to_remove


def delete_artifact(artifact_id: int, token: str) -> bool:
    """Delete a single artifact by ID. Returns True on success, False on failure."""
    delete_url = f"{hashmanager._GH_API_BASE}/repos/{GITHUB_REPO}/actions/artifacts/{artifact_id}"
    
    try:
        resp = requests.delete(
            delete_url, headers=hashmanager._gh_headers(token), timeout=30
        )
        resp.raise_for_status()
        return True
    except Exception as exc:
        logger.error(f"Failed to delete artifact {artifact_id}: {exc}")
        return False


def delete_artifacts(
    artifacts: list[dict], token: str, dry_run: bool = False
) -> tuple[int, int, list[dict]]:
    """Delete a list of artifacts. Returns (success_count, failure_count, results_list)."""
    results = []
    
    if dry_run:
        logger.info(f"DRY RUN: Would delete {len(artifacts)} artifacts")
        for artifact in artifacts:
            logger.info(
                f"  - {artifact['name']} (id={artifact['id']}, "
                f"size={artifact['size_in_bytes']:,} bytes, "
                f"created={artifact['created_at']})"
            )
            results.append({
                'name': artifact['name'],
                'status': 'would-delete',
                'size_in_bytes': artifact['size_in_bytes']
            })
        return len(artifacts), 0, results
    
    success_count = 0
    failure_count = 0
    
    for i, artifact in enumerate(artifacts, 1):
        artifact_id = artifact["id"]
        artifact_name = artifact["name"]
        
        logger.info(
            f"Deleting {i}/{len(artifacts)}: {artifact_name} (id={artifact_id})..."
        )
        
        if delete_artifact(artifact_id, token):
            success_count += 1
            logger.info(f"  ✓ Successfully deleted {artifact_name}")
            results.append({
                'name': artifact_name,
                'status': 'success',
                'size_in_bytes': artifact['size_in_bytes']
            })
        else:
            failure_count += 1
            logger.warning(f"  ✗ Failed to delete {artifact_name}")
            results.append({
                'name': artifact_name,
                'status': 'failed',
                'size_in_bytes': artifact['size_in_bytes']
            })
    
    return success_count, failure_count, results


def write_github_step_summary(
    summary_file: str,
    results: list[dict],
    dry_run: bool,
    name_contains: Optional[str] = None,
) -> None:
    """Write a GitHub Actions step summary with a table of results."""
    try:
        with open(summary_file, "w", encoding="utf-8") as f:
            f.write("## 🗑️ Hashmanager Cleanup Results\n\n")
            
            f.write("### Configuration\n\n")
            f.write(f"- **Filter**: {f'Name contains `{name_contains}`' if name_contains else 'All hashmanager artifacts'}\n")
            f.write(f"- **Mode**: {'🔍 Dry Run (Preview)' if dry_run else '🗑️ Delete'}\n\n")
            
            if not results:
                f.write("### No hashmanager artifacts found\n\n")
                return
            
            success_count = sum(1 for r in results if r['status'] in ('success', 'would-delete'))
            failed_count = sum(1 for r in results if r['status'] == 'failed')
            
            f.write("### Summary\n\n")
            f.write(f"- **Total artifacts found**: {len(results)}\n")
            if dry_run:
                f.write(f"- **Would delete**: {success_count}\n")
            else:
                f.write(f"- **Successfully deleted**: {success_count}\n")
                f.write(f"- **Failed to delete**: {failed_count}\n")
            
            total_size = sum(r['size_in_bytes'] for r in results)
            size_mb = total_size / (1024 * 1024)
            f.write(f"- **Total size**: {size_mb:.2f} MB ({total_size:,} bytes)\n\n")
            
            f.write("### Artifacts\n\n")
            f.write("| Artifact Name | Status | Size |\n")
            f.write("|---------------|--------|------|\n")
            
            for result in results:
                name = result['name']
                status = result['status']
                size_kb = result['size_in_bytes'] / 1024
                
                if status == 'success':
                    status_display = "✅ Deleted"
                elif status == 'would-delete':
                    status_display = "🔍 Would Delete"
                elif status == 'failed':
                    status_display = "❌ Failed"
                else:
                    status_display = status
                
                if size_kb < 1024:
                    size_display = f"{size_kb:.1f} KB"
                else:
                    size_display = f"{size_kb/1024:.2f} MB"
                
                f.write(f"| `{name}` | {status_display} | {size_display} |\n")
            
            f.write("\n")
            
            if dry_run:
                f.write("> ℹ️ **This was a dry run.** No artifacts were deleted. ")
                f.write("Run again without `--dry-run` to actually delete these artifacts.\n")
            elif failed_count > 0:
                f.write(f"> ⚠️ **Warning:** {failed_count} artifact(s) failed to delete. ")
                f.write("Check the logs for details.\n")
        
        logger.info(f"GitHub step summary written to {summary_file}")
    
    except Exception as exc:
        logger.warning(f"Failed to write GitHub step summary: {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="Delete hashmanager artifacts from GitHub Actions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    
    parser.add_argument(
        "--name-contains",
        help="Filter artifacts by substring in name (e.g., 'staging', 'production', 'ipsum')",
    )


    parser.add_argument(
        "--feeds",
        nargs="+",
        help="Filter artifacts by feed ids (e.g., '575680fe-10d7-42d5-b25e-13b31f899c75', '3240b259-af50-4886-b672-3b014fcdaf4b', 'dd375bdd-2920-4901-8f8f-744c7796800c')",
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be deleted without actually deleting",
    )
    
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    gh_token = os.getenv("GITHUB_TOKEN")
    if not gh_token:
        logger.error("GITHUB_TOKEN environment variable is not set")
        sys.exit(1)
    
    logger.info(f"Fetching artifacts from {GITHUB_REPO}...")
    all_artifacts = list_all_artifacts(gh_token)
    
    if not all_artifacts:
        logger.info("No artifacts found in repository")
        return
    
    logger.info(f"{'='*80}")
    logger.info(f"Cleaning hashmanagers")
    logger.info(f"Repository: {GITHUB_REPO}")
    if args.name_contains:
        logger.info(f"Filter: Name contains '{args.name_contains}'")
    else:
        logger.info("Filter: ALL hashmanager artifacts")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info(f"{'='*80}\n")
    
    hashmanager_artifacts = filter_hashmanager_artifacts(
        all_artifacts, name_contains=args.name_contains, feeds=args.feeds
    )
    
    if not hashmanager_artifacts:
        logger.info("No hashmanager artifacts found matching criteria")
        return
    
    if not args.dry_run:
        logger.warning(
            f"\n⚠️  About to delete {len(hashmanager_artifacts)} hashmanager artifacts!"
        )
        
        if sys.stdin.isatty():
            response = input("\nType 'yes' to confirm deletion: ")
            if response.lower() != "yes":
                logger.info("Deletion cancelled")
                return
        else:
            logger.info("Running in non-interactive mode, proceeding with deletion...")
    
    success_count, failure_count, results = delete_artifacts(
        hashmanager_artifacts, gh_token, dry_run=args.dry_run
    )
    
    logger.info(f"\n{'='*80}")
    logger.info("Summary:")
    logger.info(f"  Total hashmanager artifacts: {len(hashmanager_artifacts)}")
    if args.dry_run:
        logger.info(f"  Would delete: {success_count}")
    else:
        logger.info(f"  Successfully deleted: {success_count}")
        logger.info(f"  Failed to delete: {failure_count}")
    logger.info(f"{'='*80}")
    
    github_step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if github_step_summary:
        write_github_step_summary(
            github_step_summary, 
            results, 
            args.dry_run, 
            args.name_contains
        )


if __name__ == "__main__":
    main()
