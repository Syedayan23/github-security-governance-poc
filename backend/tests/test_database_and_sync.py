"""
Unit and integration tests for SQLite persistence and SyncService.
"""

import pytest
import tempfile
from pathlib import Path
import httpx
from backend.app.database import (
    init_db,
    upsert_alert,
    upsert_alerts_batch,
    get_alerts,
    get_alert_by_id,
    get_alerts_summary,
)
from backend.app.github_client import GitHubClient
from backend.app.sync import SyncService


@pytest.fixture
def temp_db():
    """Provides a fresh isolated temporary SQLite database for each test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    try:
        Path(db_path).unlink(missing_ok=True)
    except Exception:
        pass


def test_init_and_upsert_alert(temp_db):
    alert1 = {
        "id": "dependabot-10",
        "scanner": "dependabot",
        "external_id": 10,
        "severity": "high",
        "state": "open",
        "repository": "test-org/test-repo",
        "package_or_rule": "urllib3",
        "affected_file": "backend/requirements.txt",
        "title": "Vulnerability in urllib3",
        "html_url": "https://github.com/test-org/test-repo/security/dependabot/10",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "raw_data": {"test": "payload1"}
    }

    saved = upsert_alert(alert1, db_path=temp_db)
    assert saved["id"] == "dependabot-10"
    assert saved["severity"] == "high"
    assert saved["state"] == "open"
    assert saved["first_seen_at"] is not None

    # Test update preserves first_seen_at but updates state and updated_at
    initial_first_seen = saved["first_seen_at"]
    alert1_updated = dict(alert1)
    alert1_updated["state"] = "fixed"
    alert1_updated["updated_at"] = "2026-01-02T00:00:00Z"

    updated = upsert_alert(alert1_updated, db_path=temp_db)
    assert updated["state"] == "fixed"
    assert updated["first_seen_at"] == initial_first_seen
    assert updated["updated_at"] == "2026-01-02T00:00:00Z"


def test_upsert_batch_and_filtering(temp_db):
    alerts = [
        {
            "id": "dependabot-1",
            "scanner": "dependabot",
            "external_id": 1,
            "severity": "high",
            "state": "open",
            "repository": "test-org/test-repo",
            "package_or_rule": "requests",
            "title": "requests vuln",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "raw_data": {}
        },
        {
            "id": "code_scanning-1",
            "scanner": "code_scanning",
            "external_id": 1,
            "severity": "critical",
            "state": "open",
            "repository": "test-org/test-repo",
            "package_or_rule": "py/sql-injection",
            "title": "SQL Injection",
            "created_at": "2026-01-02T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "raw_data": {}
        },
        {
            "id": "dependabot-2",
            "scanner": "dependabot",
            "external_id": 2,
            "severity": "low",
            "state": "dismissed",
            "repository": "test-org/test-repo",
            "package_or_rule": "jinja2",
            "title": "jinja2 vuln",
            "created_at": "2026-01-03T00:00:00Z",
            "updated_at": "2026-01-03T00:00:00Z",
            "raw_data": {}
        }
    ]

    count = upsert_alerts_batch(alerts, db_path=temp_db)
    assert count == 3

    # Filter by scanner
    dep_alerts = get_alerts(scanner="dependabot", db_path=temp_db)
    assert len(dep_alerts) == 2
    cs_alerts = get_alerts(scanner="code_scanning", db_path=temp_db)
    assert len(cs_alerts) == 1

    # Filter by severity
    crit_alerts = get_alerts(severity="critical", db_path=temp_db)
    assert len(crit_alerts) == 1
    assert crit_alerts[0]["id"] == "code_scanning-1"

    # Filter by state
    open_alerts = get_alerts(state="open", db_path=temp_db)
    assert len(open_alerts) == 2

    # Verify summary metrics
    summary = get_alerts_summary(db_path=temp_db)
    assert summary["total_alerts"] == 3
    assert summary["dependabot_alerts"] == 2
    assert summary["code_scanning_alerts"] == 1
    assert summary["open_alerts"] == 2
    assert summary["dismissed_alerts"] == 1
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["low"] == 1


@pytest.mark.asyncio
async def test_sync_service(temp_db):
    dep_payload = [{
        "number": 1,
        "state": "open",
        "security_advisory": {"severity": "medium", "summary": "dep vuln"},
        "dependency": {"package": {"name": "urllib3"}, "manifest_path": "requirements.txt"},
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    }]
    cs_payload = [{
        "number": 5,
        "state": "open",
        "rule": {"id": "py/path-injection", "security_severity_level": "high", "description": "path traversal"},
        "most_recent_instance": {"location": {"path": "app.py", "start_line": 10}},
        "created_at": "2026-01-02T00:00:00Z",
        "updated_at": "2026-01-02T00:00:00Z"
    }]

    def handler(request: httpx.Request):
        url_str = str(request.url)
        if "/dependabot/alerts" in url_str:
            return httpx.Response(200, json=dep_payload)
        elif "/code-scanning/alerts" in url_str:
            return httpx.Response(200, json=cs_payload)
        return httpx.Response(404, json={"message": "Not Found"})

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="mock-token", owner="test-org", repo="test-repo", transport=transport)
    sync_service = SyncService(client=client, db_path=temp_db)

    result = await sync_service.sync_all_alerts()

    assert result["status"] == "success"
    assert result["dependabot_synced"] == 1
    assert result["code_scanning_synced"] == 1
    assert result["total_synced"] == 2

    # Check database content
    alerts = get_alerts(db_path=temp_db)
    assert len(alerts) == 2
    assert get_alert_by_id("dependabot-1", db_path=temp_db) is not None
    assert get_alert_by_id("code_scanning-5", db_path=temp_db) is not None
