"""
Pydantic data models for GitHub Security Governance POC.
Provides request and response validation for FastAPI endpoints.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AlertResponse(BaseModel):
    id: str = Field(..., description="Unique composite alert ID (e.g. dependabot-1, code_scanning-42)")
    scanner: str = Field(..., description="Scanner source: 'dependabot' or 'code_scanning'")
    external_id: int = Field(..., description="Original GitHub alert number")
    severity: str = Field(..., description="Severity level: 'critical', 'high', 'medium', or 'low'")
    state: str = Field(..., description="Alert state: 'open', 'fixed', 'dismissed', etc.")
    repository: str = Field(..., description="GitHub repository full name (owner/repo)")
    package_or_rule: str = Field(..., description="Affected package name or CodeQL rule ID")
    affected_file: str = Field(default="", description="Manifest path or source code file and line")
    title: str = Field(default="", description="Advisory summary or rule description")
    html_url: str = Field(default="", description="GitHub browser URL for the alert")
    created_at: str = Field(..., description="Timestamp when alert was created on GitHub")
    updated_at: str = Field(..., description="Timestamp when alert was last updated on GitHub")
    first_seen_at: str = Field(..., description="Timestamp when alert was first ingested into SQLite")
    last_synced_at: str = Field(..., description="Timestamp when alert was last synced or received via webhook")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Original GitHub API alert payload")


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class SummaryResponse(BaseModel):
    repository: str
    total_alerts: int
    dependabot_alerts: int
    code_scanning_alerts: int
    open_alerts: int
    fixed_alerts: int
    dismissed_alerts: int
    by_severity: SeverityBreakdown


class SyncResponse(BaseModel):
    status: str
    repository: str
    dependabot_synced: int
    code_scanning_synced: int
    total_synced: int
    synced_at: str
    errors: List[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    repository_configured: str
    database_connected: bool
    github_token_configured: bool
    webhook_secret_configured: bool


class WebhookProcessingResult(BaseModel):
    status: str
    event: str
    action: Optional[str] = None
    alert_id: Optional[str] = None
    message: str
