# GitHub Security Governance POC

Proof of concept for ingesting GitHub security alerts into an application.

## Security Scanners

- Dependabot
- CodeQL / Code Scanning

## Purpose

This repository is a dedicated test repository used to generate security
findings and test GitHub API and webhook-based alert ingestion.

## Test Components

- Python application (`app.py`)
- Dependency manifest (`requirements.txt`)
- MCP test configuration (`mcp.json`)
- YAML configuration (`config.yaml`)
- CodeQL test fixtures

No real credentials or production secrets should be stored in this repository.

---

## Architecture

```text
              YOUR TEST REPOSITORY
                       │
          ┌────────────┴────────────┐
          ↓                         ↓
     requirements.txt            app.py
          ↓                         ↓
      Dependabot                  CodeQL
          ↓                         ↓
     Security Alert           Code Scanning Alert
          │                         │
          └────────────┬────────────┘
                       ↓
                 GitHub Security
                       ↓
            Your FastAPI (backend/)
                       ↓
             React UI (frontend/)
```

---

## Test Fixture Details

### 1. Dependabot Test Dependencies (`requirements.txt`)
Contains intentionally outdated Python packages with published GitHub Security Advisories:
* `urllib3==1.26.4` (CVE-2023-43804, CVE-2023-45803, CVE-2021-33503)
* `jinja2==2.11.2` (CVE-2024-22195, CVE-2020-28493)
* `requests==2.20.0` (CVE-2023-32681, CVE-2018-18074)

### 2. CodeQL Test Fixtures (`app.py`)
Harmless, isolated test functions designed to trigger built-in CodeQL Python queries:
* **py/weak-cryptographic-hash**: MD5 hashing for password fields (CWE-327)
* **py/disabled-cert-validation**: Disabling TLS certificate verification with `verify=False` (CWE-295)
* **py/unsafe-deserialization**: Deserializing data with Python's standard `pickle.loads` (CWE-502)
* **py/command-line-injection**: Direct string formatting into `subprocess.run(..., shell=True)` (CWE-78)
* **py/clear-text-logging-sensitive-data**: Clear-text logging of sensitive variables (token, password) (CWE-312)
* **py/flask-debug**: Flask application instantiated with debug mode enabled (CWE-489)

---

## CodeQL Workflow Details

File: `.github/workflows/codeql.yml`

* **When it runs automatically**:
  1. On every **push** to the `main` or `master` branch.
  2. On every **pull request** targeting `main` or `master`.
  3. On a weekly **cron schedule** (Mondays at 12:00 UTC).
* **How to trigger it manually**:
  1. Go to your GitHub repository in your web browser.
  2. Click the **Actions** tab.
  3. In the left sidebar, click **CodeQL Analysis**.
  4. Click the **Run workflow** dropdown on the right and select the `main` branch.
  5. Click the green **Run workflow** button.
  6. Once complete, findings will appear under **Security** > **Code scanning**.

---

## Quick Start: Connecting to GitHub & Ingestion

### 1. Configure Credentials
Copy `.env.example` to `.env` and set your credentials:
```dotenv
GITHUB_TOKEN=ghp_your_token_here
GITHUB_OWNER=your_github_username
GITHUB_REPO=github-security-governance-poc
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
```

### 2. Run the Governance Platform
* **Backend**:
  ```powershell
  .venv\Scripts\uvicorn.exe backend.app.main:app --port 8000
  ```
* **Frontend**:
  ```powershell
  cd frontend
  npm.cmd run dev
  ```
  Visit [http://localhost:5173](http://localhost:5173) and click **"Sync GitHub Alerts"**.
