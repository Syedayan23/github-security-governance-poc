"""
Alerts and synchronization API routes.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from backend.app.config import settings
from backend.app.database import get_alerts, get_alert_by_id, get_alerts_summary
from backend.app.models import AlertResponse, SummaryResponse, SyncResponse
from backend.app.sync import SyncService
from backend.app.github_client import (
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubRateLimitError,
)

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_model=List[AlertResponse], summary="Retrieve stored security alerts")
async def list_alerts(
    scanner: Optional[str] = Query(None, description="Filter by scanner: 'dependabot' or 'code_scanning'"),
    severity: Optional[str] = Query(None, description="Filter by severity: 'critical', 'high', 'medium', 'low'"),
    state: Optional[str] = Query(None, description="Filter by state: 'open', 'fixed', 'dismissed'")
):
    """
    Returns security alerts stored in SQLite database.
    Supports filtering by scanner type, severity, and state.
    """
    return get_alerts(scanner=scanner, severity=severity, state=state)


@router.get("/alerts/summary", response_model=SummaryResponse, summary="Get alert governance metrics summary")
async def alerts_summary():
    """
    Provides aggregated metrics for the frontend dashboard:
    - Total alerts
    - Dependabot alerts count
    - Code scanning alerts count
    - Open alerts count
    - Severity breakdown
    """
    summary_data = get_alerts_summary()
    summary_data["repository"] = settings.repository_full_name
    return summary_data


@router.get("/alerts/{alert_id}", response_model=AlertResponse, summary="Get single alert by ID")
async def get_alert(alert_id: str):
    """
    Retrieves full details for a specific security alert by ID (e.g. 'dependabot-1' or 'code_scanning-42').
    """
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert with ID '{alert_id}' was not found in the database."
        )
    return alert


@router.post("/sync", response_model=SyncResponse, summary="Synchronize alerts from GitHub REST API")
async def trigger_sync():
    """
    Initiates synchronization of existing security alerts from GitHub REST API to SQLite.
    Does not rely on webhooks, allowing historical alerts to be indexed immediately.
    """
    sync_service = SyncService()
    try:
        result = await sync_service.sync_all_alerts()
        return result
    except GitHubAuthenticationError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except GitHubPermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except GitHubRateLimitError as e:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Synchronization failed: {str(e)}"
        )
