"""
GitHub Webhook receiver endpoint.
"""

import json
from fastapi import APIRouter, Request, Header, HTTPException, status
from backend.app.config import settings
from backend.app.webhook import verify_github_signature, process_webhook_event
from backend.app.models import WebhookProcessingResult

router = APIRouter(tags=["webhooks"])


@router.post("/webhooks/github", response_model=WebhookProcessingResult, summary="Receive GitHub Webhook events")
async def github_webhook_endpoint(
    request: Request,
    x_github_event: str = Header(..., alias="X-GitHub-Event"),
    x_hub_signature_256: str = Header(None, alias="X-Hub-Signature-256"),
    x_github_delivery: str = Header(None, alias="X-GitHub-Delivery"),
):
    """
    Receives GitHub webhook events for:
    - dependabot_alert
    - code_scanning_alert
    - ping
    Verifies HMAC-SHA256 signature using GITHUB_WEBHOOK_SECRET.
    Updates SQLite in real time.
    """
    # 1. Read raw body bytes for cryptographic signature verification
    raw_body = await request.body()

    # 2. Verify signature
    # In production/testing, signature verification ensures events originate genuinely from GitHub
    is_valid = verify_github_signature(raw_body, x_hub_signature_256)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Hub-Signature-256 webhook signature. "
                   "Verify that GITHUB_WEBHOOK_SECRET is set identically in .env and the GitHub webhook configuration."
        )

    # 3. Parse JSON body
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed JSON payload in webhook request: {str(e)}"
        )

    # 4. Process event
    status_str, saved_alert, message = process_webhook_event(x_github_event, payload)

    return WebhookProcessingResult(
        status=status_str,
        event=x_github_event,
        action=payload.get("action"),
        alert_id=saved_alert["id"] if saved_alert else None,
        message=message
    )
