"""
GitHub Webhook processing and signature verification for Security Alert Governance POC.

Verifies the cryptographic HMAC-SHA256 signature in X-Hub-Signature-256.
Processes:
- 'dependabot_alert' events
- 'code_scanning_alert' events
- 'ping' events
Updates SQLite persistence in real time.
"""

import hmac
import hashlib
from typing import Any, Dict, Optional, Tuple
from fastapi import HTTPException, status
from backend.app.config import settings
from backend.app.database import upsert_alert, record_governance_event
from backend.app.github_client import normalize_dependabot_alert, normalize_code_scanning_alert


def verify_github_signature(raw_body: bytes, signature_header: Optional[str], secret: Optional[str] = None) -> bool:
    """
    Validates HMAC-SHA256 signature provided in GitHub's X-Hub-Signature-256 header.
    Returns True if signature is valid, False otherwise.
    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    """
    configured_secret = secret if secret is not None else settings.github_webhook_secret

    # If no secret is configured on server, reject webhook calls for security
    if not configured_secret:
        return False

    if not signature_header:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected_signature = "sha256=" + hmac.new(
        key=configured_secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected_signature, signature_header)


def process_webhook_event(
    event_type: str,
    payload: Dict[str, Any],
    db_path: Optional[str] = None
) -> Tuple[str, Optional[Dict[str, Any]], str]:
    """
    Processes verified GitHub webhook payload and updates SQLite.
    Returns tuple of (status, normalized_alert_or_none, message).
    """
    # 1. Handle GitHub Ping event
    if event_type == "ping":
        record_governance_event(
            event_type="WEBHOOK_PING",
            source="WEBHOOK",
            details="Ping event received from GitHub webhook configuration.",
            db_path=db_path
        )
        return "pong", None, "GitHub webhook ping received successfully"

    repo_info = payload.get("repository") or {}
    repository = repo_info.get("full_name") or settings.repository_full_name
    action = payload.get("action", "unknown")
    alert_raw = payload.get("alert")

    if not alert_raw:
        return "ignored", None, f"Event '{event_type}' action '{action}' contained no alert object."

    # 2. Handle Dependabot alert webhook
    if event_type == "dependabot_alert":
        normalized = normalize_dependabot_alert(alert_raw, repository)
        # Webhook payload state reflects current action (created, dismissed, fixed, reopened)
        if action == "fixed":
            normalized["state"] = "fixed"
        elif action == "dismissed":
            normalized["state"] = "dismissed"
        elif action in ("created", "reopened", "reintroduced"):
            normalized["state"] = "open"

        saved = upsert_alert(normalized, db_path=db_path)
        record_governance_event(
            event_type=f"DEPENDABOT_ALERT_{action.upper()}",
            source="WEBHOOK",
            alert_id=saved["id"],
            details=f"Action: {action}, Severity: {saved['severity']}, Rule/Package: {saved['package_or_rule']}",
            db_path=db_path
        )
        return "processed", saved, f"Dependabot alert {saved['id']} processed ({action})."

    # 3. Handle Code Scanning alert webhook
    elif event_type == "code_scanning_alert":
        normalized = normalize_code_scanning_alert(alert_raw, repository)
        if action in ("fixed", "closed_by_user"):
            normalized["state"] = "fixed" if action == "fixed" else "dismissed"
        elif action in ("created", "reopened", "reopened_by_user", "appeared_in_branch"):
            normalized["state"] = "open"

        saved = upsert_alert(normalized, db_path=db_path)
        record_governance_event(
            event_type=f"CODE_SCANNING_ALERT_{action.upper()}",
            source="WEBHOOK",
            alert_id=saved["id"],
            details=f"Action: {action}, Severity: {saved['severity']}, Rule: {saved['package_or_rule']}",
            db_path=db_path
        )
        return "processed", saved, f"Code scanning alert {saved['id']} processed ({action})."

    else:
        return "ignored", None, f"Unsupported webhook event type: '{event_type}'."
