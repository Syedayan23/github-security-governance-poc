"""
Unit tests for GitHubClient.
Validates:
- Dependabot alert retrieval & normalization
- Code Scanning alert retrieval & normalization
- Pagination support via Link headers
- Error handling (401 Unauthorized, 403 Forbidden, 404 Not Found, Rate Limiting)
- Credential verification
"""

import pytest
import httpx
from backend.app.github_client import (
    GitHubClient,
    GitHubAuthenticationError,
    GitHubPermissionError,
    GitHubRateLimitError,
    GitHubResourceNotFoundError,
    parse_next_link,
)


def test_parse_next_link():
    link_header = (
        '<https://api.github.com/repositories/1/dependabot/alerts?page=2>; rel="next", '
        '<https://api.github.com/repositories/1/dependabot/alerts?page=4>; rel="last"'
    )
    assert parse_next_link(link_header) == "https://api.github.com/repositories/1/dependabot/alerts?page=2"
    assert parse_next_link(None) is None
    assert parse_next_link('<https://api.github.com/item>; rel="prev"') is None


@pytest.mark.asyncio
async def test_verify_credentials_success():
    def handler(request: httpx.Request):
        assert request.headers["authorization"] == "Bearer test-token"
        assert request.headers["accept"] == "application/vnd.github+json"
        assert request.url.path == "/repos/my-org/my-repo"
        return httpx.Response(200, json={"id": 12345, "full_name": "my-org/my-repo"})

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="my-repo", transport=transport)
    repo_data = await client.verify_credentials()
    assert repo_data["full_name"] == "my-org/my-repo"


@pytest.mark.asyncio
async def test_get_dependabot_alerts_single_page():
    mock_payload = [
        {
            "number": 1,
            "state": "open",
            "dependency": {
                "package": {"ecosystem": "pip", "name": "urllib3"},
                "manifest_path": "backend/requirements.txt",
                "scope": "runtime"
            },
            "security_advisory": {
                "ghsa_id": "GHSA-1234",
                "cve_id": "CVE-2023-45803",
                "summary": "urllib3 HTTP request body vulnerability",
                "severity": "high"
            },
            "url": "https://api.github.com/repos/my-org/my-repo/dependabot/alerts/1",
            "html_url": "https://github.com/my-org/my-repo/security/dependabot/1",
            "created_at": "2026-01-15T10:00:00Z",
            "updated_at": "2026-01-15T10:00:00Z"
        }
    ]

    def handler(request: httpx.Request):
        assert "/dependabot/alerts" in str(request.url)
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="my-repo", transport=transport)
    alerts = await client.get_dependabot_alerts()

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["id"] == "dependabot-1"
    assert alert["scanner"] == "dependabot"
    assert alert["severity"] == "high"
    assert alert["state"] == "open"
    assert alert["package_or_rule"] == "urllib3"
    assert alert["affected_file"] == "backend/requirements.txt"
    assert alert["title"] == "urllib3 HTTP request body vulnerability"
    assert alert["html_url"] == "https://github.com/my-org/my-repo/security/dependabot/1"


@pytest.mark.asyncio
async def test_get_code_scanning_alerts_single_page():
    mock_payload = [
        {
            "number": 42,
            "state": "open",
            "created_at": "2026-02-01T12:00:00Z",
            "updated_at": "2026-02-01T12:00:00Z",
            "url": "https://api.github.com/repos/my-org/my-repo/code-scanning/alerts/42",
            "html_url": "https://github.com/my-org/my-repo/security/code-scanning/42",
            "rule": {
                "id": "py/sql-injection",
                "severity": "error",
                "security_severity_level": "critical",
                "description": "SQL query built from user-controlled sources",
                "name": "SQL query built from user-controlled sources"
            },
            "tool": {
                "name": "CodeQL"
            },
            "most_recent_instance": {
                "location": {
                    "path": "sample_vulnerable_app/vulnerable_code.py",
                    "start_line": 21,
                    "end_line": 21
                }
            }
        }
    ]

    def handler(request: httpx.Request):
        assert "/code-scanning/alerts" in str(request.url)
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="my-repo", transport=transport)
    alerts = await client.get_code_scanning_alerts()

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["id"] == "code_scanning-42"
    assert alert["scanner"] == "code_scanning"
    assert alert["severity"] == "critical"
    assert alert["state"] == "open"
    assert alert["package_or_rule"] == "py/sql-injection"
    assert alert["affected_file"] == "sample_vulnerable_app/vulnerable_code.py:21"
    assert alert["title"] == "SQL query built from user-controlled sources"


@pytest.mark.asyncio
async def test_pagination_handling():
    page1 = [{"number": 1, "security_advisory": {"severity": "low"}, "dependency": {"package": {"name": "pkg-a"}}}]
    page2 = [{"number": 2, "security_advisory": {"severity": "medium"}, "dependency": {"package": {"name": "pkg-b"}}}]

    def handler(request: httpx.Request):
        if "page=2" in str(request.url):
            return httpx.Response(200, json=page2)
        else:
            headers = {
                "Link": '<https://api.github.com/repos/my-org/my-repo/dependabot/alerts?page=2>; rel="next"'
            }
            return httpx.Response(200, json=page1, headers=headers)

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="my-repo", transport=transport)
    alerts = await client.get_dependabot_alerts()

    assert len(alerts) == 2
    assert alerts[0]["external_id"] == 1
    assert alerts[1]["external_id"] == 2


@pytest.mark.asyncio
async def test_authentication_error_401():
    def handler(request: httpx.Request):
        return httpx.Response(401, json={"message": "Bad credentials"})

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="bad-token", owner="my-org", repo="my-repo", transport=transport)

    with pytest.raises(GitHubAuthenticationError) as exc_info:
        await client.verify_credentials()
    assert "Authentication failed (HTTP 401)" in str(exc_info.value)


@pytest.mark.asyncio
async def test_permission_error_403():
    def handler(request: httpx.Request):
        return httpx.Response(403, json={"message": "Resource not accessible by personal access token"})

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="my-repo", transport=transport)

    with pytest.raises(GitHubPermissionError) as exc_info:
        await client.get_dependabot_alerts()
    assert "access forbidden (HTTP 403)" in str(exc_info.value)


@pytest.mark.asyncio
async def test_rate_limit_error_403_with_header():
    def handler(request: httpx.Request):
        headers = {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1800000000"
        }
        return httpx.Response(403, headers=headers, json={"message": "API rate limit exceeded"})

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="my-repo", transport=transport)

    with pytest.raises(GitHubRateLimitError) as exc_info:
        await client.get_dependabot_alerts()
    assert "rate limit exceeded" in str(exc_info.value)


@pytest.mark.asyncio
async def test_not_found_error_404():
    def handler(request: httpx.Request):
        return httpx.Response(404, json={"message": "Not Found"})

    transport = httpx.MockTransport(handler)
    client = GitHubClient(token="test-token", owner="my-org", repo="nonexistent-repo", transport=transport)

    with pytest.raises(GitHubResourceNotFoundError) as exc_info:
        await client.get_dependabot_alerts()
    assert "resource not found (HTTP 404)" in str(exc_info.value)
