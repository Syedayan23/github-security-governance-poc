"""
GitHub REST API client for Security Alert Governance POC.

Fetches Dependabot and Code Scanning (CodeQL) alerts using the official GitHub REST API.
Handles:
- Authentication with GitHub PAT (Personal Access Token)
- Pagination (Link header and page iteration)
- Rate limiting detection and errors
- Informative error handling for 401, 403, 404
- Normalization into a unified alert schema
"""

from typing import Any, Dict, List, Optional, Tuple
import re
import httpx
from datetime import datetime, timezone


class GitHubAPIError(Exception):
    """Base exception for GitHub API errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class GitHubAuthenticationError(GitHubAPIError):
    """Raised when GitHub token is missing, invalid, or expired (HTTP 401)."""
    pass


class GitHubPermissionError(GitHubAPIError):
    """Raised when token lacks required permissions/scopes (HTTP 403)."""
    pass


class GitHubRateLimitError(GitHubAPIError):
    """Raised when GitHub API rate limit is exceeded (HTTP 403/429 with rate limit)."""
    def __init__(self, message: str, reset_timestamp: Optional[int] = None):
        super().__init__(message, status_code=403)
        self.reset_timestamp = reset_timestamp


class GitHubResourceNotFoundError(GitHubAPIError):
    """Raised when repository or feature is not found (HTTP 404)."""
    pass


def parse_next_link(link_header: Optional[str]) -> Optional[str]:
    """
    Parses standard RFC 5988 Link header for rel="next" URL.
    Example: <https://api.github.com/repositories/123/alerts?page=2>; rel="next"
    """
    if not link_header:
        return None
    matches = re.findall(r'<([^>]+)>;\s*rel="([^"]+)"', link_header)
    for url, rel in matches:
        if rel == "next":
            return url
    return None


def normalize_dependabot_alert(alert_data: Dict[str, Any], repository: str) -> Dict[str, Any]:
    """
    Normalizes a Dependabot alert JSON object into a unified governance alert dictionary.
    """
    number = alert_data.get("number")
    advisory = alert_data.get("security_advisory") or {}
    dependency = alert_data.get("dependency") or {}
    package = dependency.get("package") or {}
    manifest_path = dependency.get("manifest_path") or ""

    # Dependabot severity is in security_advisory.severity (low, medium, high, critical)
    severity = (advisory.get("severity") or "unknown").lower()
    state = (alert_data.get("state") or "open").lower()

    return {
        "id": f"dependabot-{number}",
        "scanner": "dependabot",
        "external_id": number,
        "severity": severity,
        "state": state,
        "repository": repository,
        "title": advisory.get("summary") or f"Vulnerability in {package.get('name', 'package')}",
        "package_or_rule": package.get("name") or "unknown",
        "affected_file": manifest_path,
        "created_at": alert_data.get("created_at"),
        "updated_at": alert_data.get("updated_at") or alert_data.get("created_at"),
        "html_url": alert_data.get("html_url") or "",
        "raw_data": alert_data,
    }


def normalize_code_scanning_alert(alert_data: Dict[str, Any], repository: str) -> Dict[str, Any]:
    """
    Normalizes a Code Scanning (CodeQL) alert JSON object into a unified governance alert dictionary.
    """
    number = alert_data.get("number")
    rule = alert_data.get("rule") or {}
    most_recent = alert_data.get("most_recent_instance") or {}
    location = most_recent.get("location") or {}

    # Code scanning severity can be in rule.security_severity_level (critical, high, medium, low)
    # or fallback to rule.severity (error, warning, note, none)
    sec_level = rule.get("security_severity_level")
    if sec_level:
        severity = sec_level.lower()
    else:
        rule_sev = (rule.get("severity") or "warning").lower()
        mapping = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
        severity = mapping.get(rule_sev, "medium")

    state = (alert_data.get("state") or "open").lower()

    # Determine affected file location
    file_path = location.get("path") or ""
    start_line = location.get("start_line")
    if file_path and start_line:
        affected_file = f"{file_path}:{start_line}"
    else:
        affected_file = file_path

    tool_name = (alert_data.get("tool") or {}).get("name", "CodeQL")

    return {
        "id": f"code_scanning-{number}",
        "scanner": "code_scanning",
        "external_id": number,
        "severity": severity,
        "state": state,
        "repository": repository,
        "title": rule.get("description") or rule.get("name") or f"CodeQL Alert #{number}",
        "package_or_rule": rule.get("id") or tool_name,
        "affected_file": affected_file,
        "created_at": alert_data.get("created_at"),
        "updated_at": alert_data.get("updated_at") or alert_data.get("created_at"),
        "html_url": alert_data.get("html_url") or "",
        "raw_data": alert_data,
    }


class GitHubClient:
    """
    Asynchronous client for interacting with GitHub Security APIs.
    """
    def __init__(
        self,
        token: str,
        owner: str,
        repo: str,
        base_url: str = "https://api.github.com",
        api_version: str = "2022-11-28",
        timeout: float = 30.0,
        transport: Optional[httpx.AsyncBaseTransport] = None
    ):
        self.token = token.strip()
        self.owner = owner.strip()
        self.repo = repo.strip()
        self.base_url = base_url.rstrip("/")
        self.api_version = api_version
        self.timeout = timeout
        self.transport = transport

    @property
    def repository(self) -> str:
        return f"{self.owner}/{self.repo}"

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.api_version,
            "User-Agent": "GitHub-Security-Governance-POC/1.0"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _handle_response_error(self, response: httpx.Response) -> None:
        """Translates HTTP error status codes into informative custom exceptions."""
        if response.is_success:
            return

        status = response.status_code
        # Check rate limits
        remaining = response.headers.get("x-ratelimit-remaining")
        reset_time = response.headers.get("x-ratelimit-reset")
        reset_int = int(reset_time) if reset_time and reset_time.isdigit() else None

        if remaining == "0" or status == 429:
            reset_msg = ""
            if reset_int:
                dt = datetime.fromtimestamp(reset_int, tz=timezone.utc)
                reset_msg = f" Rate limit resets at {dt.isoformat()} UTC."
            raise GitHubRateLimitError(
                f"GitHub API rate limit exceeded.{reset_msg}",
                reset_timestamp=reset_int
            )

        if status == 401:
            raise GitHubAuthenticationError(
                "GitHub API Authentication failed (HTTP 401). "
                "Please verify your GITHUB_TOKEN is valid and has not expired.",
                status_code=401,
                response_body=response.text
            )
        elif status == 403:
            raise GitHubPermissionError(
                f"GitHub API access forbidden (HTTP 403) for repository '{self.repository}'. "
                "Ensure your token has the necessary permissions (e.g. read access to 'Dependabot alerts' "
                "and 'Code scanning alerts' or 'security_events' scope). Details: " + response.text,
                status_code=403,
                response_body=response.text
            )
        elif status == 404:
            raise GitHubResourceNotFoundError(
                f"GitHub resource not found (HTTP 404) for repository '{self.repository}'. "
                "Verify the repository exists, is accessible to your token, and that security scanning features are enabled.",
                status_code=404,
                response_body=response.text
            )
        else:
            raise GitHubAPIError(
                f"GitHub API error (HTTP {status}): {response.text}",
                status_code=status,
                response_body=response.text
            )

    async def verify_credentials(self) -> Dict[str, Any]:
        """
        Validates GitHub credentials and repository accessibility.
        Returns the repository metadata dict on success.
        """
        url = f"{self.base_url}/repos/{self.owner}/{self.repo}"
        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            response = await client.get(url, headers=self._get_headers())
            self._handle_response_error(response)
            return response.json()

    async def _fetch_paginated_endpoint(
        self,
        endpoint_url: str,
        params: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Helper to fetch all pages of a GitHub security alerts endpoint.
        Handles both Link header rel="next" navigation and page numbering.
        """
        results: List[Dict[str, Any]] = []
        current_params = dict(params or {})
        current_params.setdefault("per_page", 100)
        current_params.setdefault("page", 1)

        next_url: Optional[str] = endpoint_url

        async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
            while next_url:
                # If next_url already includes query params from Link header, don't pass current_params
                req_params = current_params if next_url == endpoint_url else None
                response = await client.get(next_url, headers=self._get_headers(), params=req_params)
                self._handle_response_error(response)

                page_items = response.json()
                if not isinstance(page_items, list):
                    break

                results.extend(page_items)

                # Check Link header for next page
                link_header = response.headers.get("link")
                parsed_next = parse_next_link(link_header)

                if parsed_next:
                    next_url = parsed_next
                elif len(page_items) == current_params["per_page"] and next_url == endpoint_url:
                    # Fallback pagination when Link header is absent but full page was returned
                    current_params["page"] += 1
                else:
                    # No more pages
                    break

        return results

    async def get_dependabot_alerts(
        self,
        state: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves Dependabot security alerts for the repository.
        Reference: GET /repos/{owner}/{repo}/dependabot/alerts
        """
        endpoint = f"{self.base_url}/repos/{self.owner}/{self.repo}/dependabot/alerts"
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        if severity:
            params["severity"] = severity

        raw_alerts = await self._fetch_paginated_endpoint(endpoint, params=params)
        return [normalize_dependabot_alert(alert, self.repository) for alert in raw_alerts]

    async def get_code_scanning_alerts(
        self,
        state: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieves Code Scanning (CodeQL) security alerts for the repository.
        Reference: GET /repos/{owner}/{repo}/code-scanning/alerts
        """
        endpoint = f"{self.base_url}/repos/{self.owner}/{self.repo}/code-scanning/alerts"
        params: Dict[str, Any] = {}
        if state:
            params["state"] = state
        if severity:
            params["severity"] = severity

        raw_alerts = await self._fetch_paginated_endpoint(endpoint, params=params)
        return [normalize_code_scanning_alert(alert, self.repository) for alert in raw_alerts]

    async def get_all_alerts(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Retrieves both Dependabot and Code Scanning alerts in one call.
        Returns a tuple of (dependabot_alerts, code_scanning_alerts).
        """
        dependabot_alerts = await self.get_dependabot_alerts()
        code_scanning_alerts = await self.get_code_scanning_alerts()
        return dependabot_alerts, code_scanning_alerts
