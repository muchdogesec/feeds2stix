
#!/usr/bin/env python3

import logging
import os

from git import Repo

def clone_or_update_repo(repo_path, repo_url):
    """Clone the repository or pull latest changes if it already exists"""
    if os.path.exists(repo_path):
        logging.info(
            f"Repository already exists at {repo_path}, pulling latest changes..."
        )
        repo = Repo(repo_path)
        origin = repo.remotes.origin
        origin.pull()
    else:
        logging.info(f"Cloning repository from {repo_url}...")
        repo = Repo.clone_from(repo_url, repo_path)
    logging.info("Repository ready")
    logging.info("HEAD commit id: %s", repo.head.commit.hexsha)
    return repo