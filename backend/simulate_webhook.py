"""
Utility script to simulate GitHub Webhook events locally.
Can be used to test webhook handling and signature verification against a running backend:

    python backend/simulate_webhook.py --event dependabot
    python backend/simulate_webhook.py --event code_scanning
    python backend/simulate_webhook.py --event ping
"""

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path
import httpx

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.config import settings


def sign_payload(secret: str, payload_bytes: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def get_mock_dependabot_payload(repo: str) -> dict:
    return {
        "action": "created",
        "repository": {"full_name": repo},
        "alert": {
            "number": 999,
            "state": "open",
            "security_advisory": {
                "ghsa_id": "GHSA-simulated-1234",
                "cve_id": "CVE-2023-99999",
                "summary": "Simulated vulnerability in urllib3 via Webhook",
                "severity": "high"
            },
            "dependency": {
                "package": {"ecosystem": "pip", "name": "urllib3"},
                "manifest_path": "sample_vulnerable_app/requirements.txt"
            },
            "html_url": f"https://github.com/{repo}/security/dependabot/999",
            "created_at": "2026-03-01T12:00:00Z",
            "updated_at": "2026-03-01T12:00:00Z"
        }
    }


def get_mock_code_scanning_payload(repo: str) -> dict:
    return {
        "action": "created",
        "repository": {"full_name": repo},
        "alert": {
            "number": 888,
            "state": "open",
            "rule": {
                "id": "py/sql-injection",
                "security_severity_level": "critical",
                "description": "Simulated SQL injection detected via CodeQL Webhook"
            },
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {
                "location": {
                    "path": "sample_vulnerable_app/vulnerable_code.py",
                    "start_line": 21
                }
            },
            "html_url": f"https://github.com/{repo}/security/code-scanning/888",
            "created_at": "2026-03-01T12:30:00Z",
            "updated_at": "2026-03-01T12:30:00Z"
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Simulate GitHub Webhook for local testing.")
    parser.add_argument("--url", default="http://localhost:8000/webhooks/github", help="Target webhook URL")
    parser.add_argument("--event", choices=["dependabot", "code_scanning", "ping"], default="dependabot", help="Event type to simulate")
    parser.add_argument("--secret", default=settings.github_webhook_secret or "poc_test_secret", help="Webhook secret for HMAC-SHA256 signature")
    args = parser.parse_args()

    repo = settings.repository_full_name or "local/test-repo"

    if args.event == "ping":
        event_name = "ping"
        payload = {"zen": "Approachable is better than simple.", "hook_id": 12345678}
    elif args.event == "dependabot":
        event_name = "dependabot_alert"
        payload = get_mock_dependabot_payload(repo)
    else:
        event_name = "code_scanning_alert"
        payload = get_mock_code_scanning_payload(repo)

    payload_bytes = json.dumps(payload).encode("utf-8")
    signature = sign_payload(args.secret, payload_bytes)

    headers = {
        "X-GitHub-Event": event_name,
        "X-Hub-Signature-256": signature,
        "X-GitHub-Delivery": "simulated-delivery-001",
        "Content-Type": "application/json"
    }

    print(f"[*] Sending simulated '{event_name}' event to {args.url}...")
    print(f"[*] Signature: {signature}")

    try:
        response = httpx.post(args.url, content=payload_bytes, headers=headers, timeout=10.0)
        print(f"[*] Response status: {response.status_code}")
        print(f"[*] Response body:   {response.text}")
    except httpx.ConnectError:
        print("[!] Could not connect to backend server. Make sure the FastAPI server is running on http://localhost:8000.")
        sys.exit(1)


if __name__ == "__main__":
    main()
