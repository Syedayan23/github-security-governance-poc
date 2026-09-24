"""
Synchronization engine for GitHub Security Alert Governance POC.

Handles initial and on-demand synchronization:
GitHub API -> retrieve existing Dependabot alerts & Code Scanning alerts -> upsert into SQLite.
Does NOT depend on webhooks for historical alerts.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.config import settings
from backend.app.database import upsert_alerts_batch, record_governance_event
from backend.app.github_client import (
    GitHubClient,
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubResourceNotFoundError,
    GitHubRateLimitError,
)


class SyncService:
    """
    Coordinates synchronization of security alerts from GitHub REST API into SQLite.
    """
    def __init__(self, client: Optional[GitHubClient] = None, db_path: Optional[str] = None):
        self.db_path = db_path
        if client:
            self.client = client
        else:
            self.client = GitHubClient(
                token=settings.github_token,
                owner=settings.github_owner,
                repo=settings.github_repo,
                base_url=settings.github_api_base_url,
            )

    async def sync_all_alerts(self) -> Dict[str, Any]:
        """
        Executes a full synchronization of existing security alerts from GitHub REST API into SQLite.
        Returns a summary report of synced alerts and any warnings/errors.
        """
        errors: List[str] = []
        dependabot_alerts: List[Dict[str, Any]] = []
        code_scanning_alerts: List[Dict[str, Any]] = []

        # 1. Fetch Dependabot alerts
        try:
            dependabot_alerts = await self.client.get_dependabot_alerts()
            upsert_alerts_batch(dependabot_alerts, db_path=self.db_path)
        except (GitHubAuthenticationError, GitHubPermissionError, GitHubRateLimitError) as e:
            # Fatal authentication or permission error
            raise e
        except GitHubResourceNotFoundError:
            # Common if Dependabot alerts are disabled in repository settings
            errors.append(
                "Dependabot alerts endpoint returned 404. "
                "Ensure Dependabot alerts are enabled in Repository -> Settings -> Code security and analysis."
            )
        except Exception as e:
            errors.append(f"Failed to fetch Dependabot alerts: {str(e)}")

        # 2. Fetch Code Scanning alerts
        try:
            code_scanning_alerts = await self.client.get_code_scanning_alerts()
            upsert_alerts_batch(code_scanning_alerts, db_path=self.db_path)
        except (GitHubAuthenticationError, GitHubPermissionError, GitHubRateLimitError) as e:
            raise e
        except GitHubResourceNotFoundError:
            # Common if CodeQL/code scanning has not yet run or is disabled
            errors.append(
                "Code Scanning alerts endpoint returned 404. "
                "Ensure CodeQL action has executed at least once or code scanning is enabled."
            )
        except Exception as e:
            errors.append(f"Failed to fetch Code Scanning alerts: {str(e)}")

        total_synced = len(dependabot_alerts) + len(code_scanning_alerts)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Audit log the synchronization
        record_governance_event(
            event_type="SYNC_COMPLETED",
            source="REST_API",
            details=f"Synced {len(dependabot_alerts)} dependabot, {len(code_scanning_alerts)} code scanning alerts. Errors: {len(errors)}",
            db_path=self.db_path
        )

        return {
            "status": "success" if not errors else ("partial_success" if total_synced > 0 else "warning"),
            "repository": self.client.repository,
            "dependabot_synced": len(dependabot_alerts),
            "code_scanning_synced": len(code_scanning_alerts),
            "total_synced": total_synced,
            "synced_at": now_iso,
            "errors": errors
        }
