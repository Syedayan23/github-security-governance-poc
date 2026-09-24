"""
Sample educational application containing intentional vulnerability patterns
to demonstrate GitHub Code Scanning (CodeQL) alert governance.

DO NOT USE IN PRODUCTION ENVIRONMENTS.
"""

import sqlite3
import pickle
import base64


def query_user_insecure(username: str):
    """
    Intentionally vulnerable SQL query via raw string formatting.
    CodeQL will detect CWE-89 (SQL Injection).
    """
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, username TEXT, role TEXT)")
    
    # Vulnerable to SQL injection: direct string interpolation
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return cursor.execute(query).fetchall()


def deserialize_payload_insecure(payload: str):
    """
    Intentionally vulnerable insecure deserialization using pickle.
    CodeQL will detect CWE-502 (Deserialization of Untrusted Data).
    """
    raw_data = base64.b64decode(payload)
    # Vulnerable to arbitrary code execution
    return pickle.loads(raw_data)


if __name__ == "__main__":
    print("Sample application for GitHub CodeQL scanner demonstration.")
