"""
Utility script to verify GitHub connectivity and test alert retrieval.
Can be executed to verify your .env settings against GitHub:

    python backend/check_github.py

Outputs:
- Token and repository status
- Dependabot alert count and samples
- Code scanning alert count and samples
"""

import asyncio
import sys
from pathlib import Path

# Add project root to sys.path so script can be run directly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.config import settings
from backend.app.github_client import (
    GitHubClient,
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubRateLimitError,
    GitHubResourceNotFoundError,
)


async def main():
    print("=" * 60)
    print(" GitHub Security Alert Governance POC - Client Verification")
    print("=" * 60)

    if not settings.github_token:
        print("[!] GITHUB_TOKEN is not set in .env or environment.")
        print("    Please copy .env.example to .env and configure GITHUB_TOKEN, GITHUB_OWNER, and GITHUB_REPO.")
        print("    Exiting verification check.")
        sys.exit(1)

    if not settings.github_owner or not settings.github_repo:
        print("[!] GITHUB_OWNER or GITHUB_REPO is missing in .env.")
        sys.exit(1)

    print(f"[*] Target Repository: {settings.repository_full_name}")
    print(f"[*] Base URL:          {settings.github_api_base_url}")
    print(f"[*] Token Prefix:      {settings.github_token[:4]}...{settings.github_token[-4:] if len(settings.github_token) > 8 else ''}")

    client = GitHubClient(
        token=settings.github_token,
        owner=settings.github_owner,
        repo=settings.github_repo,
        base_url=settings.github_api_base_url,
    )

    # 1. Verify Repository Access
    print("\n[1/3] Verifying repository access...")
    try:
        repo_data = await client.verify_credentials()
        print(f"      [OK] Successfully connected to repository: {repo_data.get('full_name')}")
        print(f"           Visibility: {repo_data.get('visibility', 'unknown')}")
        print(f"           Default Branch: {repo_data.get('default_branch', 'main')}")
    except GitHubAuthenticationError as e:
        print(f"      [FAILED] Authentication error: {e}")
        sys.exit(1)
    except GitHubPermissionError as e:
        print(f"      [FAILED] Permission error: {e}")
        sys.exit(1)
    except GitHubResourceNotFoundError as e:
        print(f"      [FAILED] Repository not found: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"      [FAILED] Unexpected error: {e}")
        sys.exit(1)

    # 2. Retrieve Dependabot Alerts
    print("\n[2/3] Fetching Dependabot alerts...")
    try:
        dependabot_alerts = await client.get_dependabot_alerts()
        print(f"      [OK] Retrieved {len(dependabot_alerts)} Dependabot alert(s).")
        for i, alert in enumerate(dependabot_alerts[:3], 1):
            print(f"           #{i} [{alert['severity'].upper()}] {alert['package_or_rule']}: {alert['title']}")
            print(f"               File: {alert['affected_file']} | Status: {alert['state']}")
        if len(dependabot_alerts) > 3:
            print(f"           ... and {len(dependabot_alerts) - 3} more.")
    except Exception as e:
        print(f"      [ERROR] Could not fetch Dependabot alerts: {e}")

    # 3. Retrieve Code Scanning Alerts
    print("\n[3/3] Fetching Code Scanning (CodeQL) alerts...")
    try:
        code_alerts = await client.get_code_scanning_alerts()
        print(f"      [OK] Retrieved {len(code_alerts)} Code Scanning alert(s).")
        for i, alert in enumerate(code_alerts[:3], 1):
            print(f"           #{i} [{alert['severity'].upper()}] {alert['package_or_rule']}: {alert['title']}")
            print(f"               File: {alert['affected_file']} | Status: {alert['state']}")
        if len(code_alerts) > 3:
            print(f"           ... and {len(code_alerts) - 3} more.")
    except Exception as e:
        print(f"      [ERROR] Could not fetch Code Scanning alerts: {e}")

    print("\n" + "=" * 60)
    print(" Verification complete.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
