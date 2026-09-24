"""
Integration tests for FastAPI endpoints and Webhook processing.
Validates:
- GET /health
- GET /alerts
- GET /alerts/{id}
- GET /alerts/summary
- POST /sync
- POST /webhooks/github (HMAC signature verification, event handling for dependabot & code scanning)
"""

import hmac
import hashlib
import json
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.config import settings
from backend.app.database import init_db, upsert_alert, get_connection
from backend.app.webhook import verify_github_signature


TEST_SECRET = "test-secret-12345"


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Configures a temporary SQLite database and test secret for every test."""
    db_file = str(tmp_path / "test_api.db")
    monkeypatch.setattr(settings, "database_path", db_file)
    monkeypatch.setattr(settings, "github_webhook_secret", TEST_SECRET)
    monkeypatch.setattr(settings, "github_owner", "test-owner")
    monkeypatch.setattr(settings, "github_repo", "test-repo")
    monkeypatch.setattr(settings, "github_token", "test-token")
    init_db(db_file)
    return db_file


def compute_signature(secret: str, payload_bytes: bytes) -> str:
    """Computes HMAC-SHA256 signature in GitHub format."""
    digest = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def test_verify_github_signature_unit():
    payload = b'{"action": "created"}'
    valid_sig = compute_signature(TEST_SECRET, payload)
    invalid_sig = "sha256=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"

    assert verify_github_signature(payload, valid_sig, secret=TEST_SECRET) is True
    assert verify_github_signature(payload, invalid_sig, secret=TEST_SECRET) is False
    assert verify_github_signature(payload, None, secret=TEST_SECRET) is False
    assert verify_github_signature(payload, valid_sig, secret="") is False


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["database_connected"] is True
        assert data["github_token_configured"] is True
        assert data["webhook_secret_configured"] is True


@pytest.mark.asyncio
async def test_alerts_endpoints_and_filtering():
    # Insert test data into SQLite
    upsert_alert({
        "id": "dependabot-100",
        "scanner": "dependabot",
        "external_id": 100,
        "severity": "critical",
        "state": "open",
        "repository": "test-owner/test-repo",
        "package_or_rule": "urllib3",
        "affected_file": "requirements.txt",
        "title": "urllib3 bug",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    })
    upsert_alert({
        "id": "code_scanning-200",
        "scanner": "code_scanning",
        "external_id": 200,
        "severity": "medium",
        "state": "dismissed",
        "repository": "test-owner/test-repo",
        "package_or_rule": "py/clear-text-logging",
        "affected_file": "app.py:10",
        "title": "Clear text log",
        "created_at": "2026-01-02T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z",
    })

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # GET /alerts (all)
        res = await ac.get("/alerts")
        assert res.status_code == 200
        alerts = res.json()
        assert len(alerts) == 2

        # GET /alerts with filters
        res_filter = await ac.get("/alerts", params={"scanner": "dependabot"})
        assert res_filter.status_code == 200
        assert len(res_filter.json()) == 1
        assert res_filter.json()[0]["id"] == "dependabot-100"

        # GET /alerts/{id}
        res_detail = await ac.get("/alerts/dependabot-100")
        assert res_detail.status_code == 200
        assert res_detail.json()["package_or_rule"] == "urllib3"

        # GET /alerts/{id} 404
        res_404 = await ac.get("/alerts/nonexistent-id")
        assert res_404.status_code == 404

        # GET /alerts/summary
        res_sum = await ac.get("/alerts/summary")
        assert res_sum.status_code == 200
        sum_data = res_sum.json()
        assert sum_data["total_alerts"] == 2
        assert sum_data["dependabot_alerts"] == 1
        assert sum_data["code_scanning_alerts"] == 1
        assert sum_data["open_alerts"] == 1
        assert sum_data["by_severity"]["critical"] == 1


@pytest.mark.asyncio
async def test_webhook_signature_verification_failure():
    payload = json.dumps({"action": "ping"}).encode("utf-8")
    headers = {
        "X-GitHub-Event": "ping",
        "X-Hub-Signature-256": "sha256=invalidhexsignature",
        "Content-Type": "application/json"
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/webhooks/github", content=payload, headers=headers)
        assert response.status_code == 401
        assert "Invalid or missing X-Hub-Signature-256" in response.json()["detail"]


@pytest.mark.asyncio
async def test_webhook_ping_event():
    payload = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
    sig = compute_signature(TEST_SECRET, payload)
    headers = {
        "X-GitHub-Event": "ping",
        "X-Hub-Signature-256": sig,
        "Content-Type": "application/json"
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/webhooks/github", content=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pong"


@pytest.mark.asyncio
async def test_webhook_dependabot_alert_created_and_fixed():
    # 1. Simulate dependabot_alert created event
    created_payload_dict = {
        "action": "created",
        "repository": {"full_name": "test-owner/test-repo"},
        "alert": {
            "number": 55,
            "state": "open",
            "security_advisory": {"severity": "high", "summary": "Sample advisory"},
            "dependency": {"package": {"name": "requests"}, "manifest_path": "backend/requirements.txt"},
            "created_at": "2026-02-10T10:00:00Z",
            "updated_at": "2026-02-10T10:00:00Z",
            "html_url": "https://github.com/test-owner/test-repo/security/dependabot/55"
        }
    }
    payload_bytes = json.dumps(created_payload_dict).encode("utf-8")
    sig = compute_signature(TEST_SECRET, payload_bytes)
    headers = {
        "X-GitHub-Event": "dependabot_alert",
        "X-Hub-Signature-256": sig,
        "Content-Type": "application/json"
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res1 = await ac.post("/webhooks/github", content=payload_bytes, headers=headers)
        assert res1.status_code == 200
        assert res1.json()["alert_id"] == "dependabot-55"

        # Verify alert exists in database
        res_get = await ac.get("/alerts/dependabot-55")
        assert res_get.status_code == 200
        assert res_get.json()["state"] == "open"
        assert res_get.json()["package_or_rule"] == "requests"

        # 2. Simulate dependabot_alert fixed event
        fixed_payload_dict = dict(created_payload_dict)
        fixed_payload_dict["action"] = "fixed"
        fixed_payload_dict["alert"]["state"] = "fixed"
        fixed_payload_dict["alert"]["updated_at"] = "2026-02-11T12:00:00Z"

        fixed_bytes = json.dumps(fixed_payload_dict).encode("utf-8")
        fixed_sig = compute_signature(TEST_SECRET, fixed_bytes)
        headers["X-Hub-Signature-256"] = fixed_sig

        res2 = await ac.post("/webhooks/github", content=fixed_bytes, headers=headers)
        assert res2.status_code == 200

        # Verify state updated to fixed in database
        res_updated = await ac.get("/alerts/dependabot-55")
        assert res_updated.status_code == 200
        assert res_updated.json()["state"] == "fixed"


@pytest.mark.asyncio
async def test_webhook_code_scanning_alert_event():
    cs_payload = {
        "action": "created",
        "repository": {"full_name": "test-owner/test-repo"},
        "alert": {
            "number": 77,
            "state": "open",
            "rule": {
                "id": "py/sql-injection",
                "security_severity_level": "critical",
                "description": "SQL injection vulnerability"
            },
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {
                "location": {
                    "path": "sample_vulnerable_app/vulnerable_code.py",
                    "start_line": 21
                }
            },
            "created_at": "2026-02-15T08:00:00Z",
            "updated_at": "2026-02-15T08:00:00Z",
            "html_url": "https://github.com/test-owner/test-repo/security/code-scanning/77"
        }
    }
    payload_bytes = json.dumps(cs_payload).encode("utf-8")
    sig = compute_signature(TEST_SECRET, payload_bytes)
    headers = {
        "X-GitHub-Event": "code_scanning_alert",
        "X-Hub-Signature-256": sig,
        "Content-Type": "application/json"
    }

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/webhooks/github", content=payload_bytes, headers=headers)
        assert res.status_code == 200
        assert res.json()["alert_id"] == "code_scanning-77"

        # Verify in database
        res_get = await ac.get("/alerts/code_scanning-77")
        assert res_get.status_code == 200
        assert res_get.json()["severity"] == "critical"
        assert res_get.json()["affected_file"] == "sample_vulnerable_app/vulnerable_code.py:21"
