"""
==============================================================================
GitHub Security Governance POC - Test Application
SECURITY TEST FIXTURES FOR GITHUB CODEQL CODE SCANNING
==============================================================================

PURPOSE:
This file contains intentionally insecure but completely harmless test code
patterns designed specifically to trigger GitHub CodeQL alerts.

SAFETY NOTICE:
- Contains NO real credentials, tokens, API keys, or production secrets.
- Performs NO destructive operations or malicious actions.
- All sensitive strings are artificial test placeholders.
- Intended strictly for verification of CodeQL code scanning alert governance.
==============================================================================
"""

import hashlib
import logging
import pickle
import subprocess
import requests
from flask import Flask, request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("governance-poc-test")

app = Flask(__name__)


# ------------------------------------------------------------------------------
# 1. Weak Cryptographic Hashing
# CodeQL Query ID: py/weak-cryptographic-hash
# CWE-327: Use of a Broken or Risky Cryptographic Algorithm
# ------------------------------------------------------------------------------
def hash_password_weak(test_password: str) -> str:
    """
    Test fixture: Uses MD5 for sensitive password hashing.
    CodeQL flags MD5 as a cryptographically broken hash function.
    """
    hasher = hashlib.md5()
    hasher.update(test_password.encode("utf-8"))
    return hasher.hexdigest()


# ------------------------------------------------------------------------------
# 2. Insecure HTTP Request Configuration (Disabled SSL/TLS Verification)
# CodeQL Query ID: py/disabled-cert-validation
# CWE-295: Improper Certificate Validation
# ------------------------------------------------------------------------------
def fetch_external_report_insecure(target_url: str):
    """
    Test fixture: Disables TLS certificate validation (verify=False).
    CodeQL flags this as an insecure HTTP client configuration prone to MITM.
    """
    # Safe test endpoint with disabled TLS certificate check
    return requests.get(target_url, verify=False, timeout=5)


# ------------------------------------------------------------------------------
# 3. Unsafe Deserialization
# CodeQL Query ID: py/unsafe-deserialization
# CWE-502: Deserialization of Untrusted Data
# ------------------------------------------------------------------------------
def deserialize_user_payload(raw_pickle_bytes: bytes):
    """
    Test fixture: Uses Python's standard `pickle.loads` on unverified data.
    CodeQL flags arbitrary object deserialization as dangerous.
    """
    return pickle.loads(raw_pickle_bytes)


# ------------------------------------------------------------------------------
# 4. Unsafe Shell Command Construction
# CodeQL Query ID: py/command-line-injection
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# ------------------------------------------------------------------------------
def run_diagnostic_ping(user_host: str):
    """
    Test fixture: Formats user input directly into a shell command with shell=True.
    CodeQL flags OS command injection patterns.
    """
    # Safe test command constructed insecurely
    cmd = f"echo pinging {user_host}"
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)


# ------------------------------------------------------------------------------
# 5. Clear-Text Logging of Sensitive-Looking Test Data
# CodeQL Query ID: py/clear-text-logging-sensitive-data
# CWE-312: Cleartext Storage of Sensitive Information
# ------------------------------------------------------------------------------
def authenticate_test_user(username: str, test_auth_token: str, test_password: str):
    """
    Test fixture: Logs sensitive parameter names directly to console/file.
    CodeQL flags logging variables named password, token, or secret.
    """
    logger.info("Attempting login for user: %s with token: %s and password: %s",
                username, test_auth_token, test_password)
    return username == "test_admin"


# ------------------------------------------------------------------------------
# 6. Flask Debug Mode Enabled in Production Context
# CodeQL Query ID: py/flask-debug
# CWE-489: Active Debug Code in Production
# ------------------------------------------------------------------------------
@app.route("/")
def index():
    return {
        "status": "online",
        "service": "GitHub Security Governance POC - Test Fixture",
        "scanner_target": "CodeQL"
    }


def start_flask_debug():
    """
    Test fixture: Launches Flask server with debug mode set to True.
    CodeQL flags this because debug mode enables the Werkzeug interactive debugger.
    """
    app.run(debug=True, host="127.0.0.1", port=5001)


if __name__ == "__main__":
    print("[*] GitHub Security Governance POC - Test Application Fixtures Loaded.")
    print("    This file contains intentional CodeQL test fixtures for alert governance.")
