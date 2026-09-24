"""
Configuration settings for GitHub Security Alert Governance POC.
Loads environment variables safely using Pydantic Settings and dotenv.
"""

from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


# Locate root directory containing .env
BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE = BASE_DIR / ".env"


class Settings(BaseSettings):
    # GitHub Credentials & Settings
    # Token should have permissions to read dependabot and code-scanning alerts
    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    github_owner: str = Field(default="", alias="GITHUB_OWNER")
    github_repo: str = Field(default="github-security-governance-poc", alias="GITHUB_REPO")
    github_webhook_secret: str = Field(default="", alias="GITHUB_WEBHOOK_SECRET")

    # GitHub REST API configuration
    github_api_base_url: str = Field(default="https://api.github.com", alias="GITHUB_API_BASE_URL")
    github_api_version: str = Field(default="2022-11-28", alias="GITHUB_API_VERSION")

    # Local persistence configuration (SQLite)
    database_path: str = Field(default="governance_security.db", alias="DATABASE_PATH")

    # Server configuration
    host: str = Field(default="0.0.0.0", alias="HOST")
    port: int = Field(default=8000, alias="PORT")

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def repository_full_name(self) -> str:
        """Returns owner/repo format if owner is configured."""
        if self.github_owner and self.github_repo:
            return f"{self.github_owner}/{self.github_repo}"
        return self.github_repo


# Singleton instance
settings = Settings()
