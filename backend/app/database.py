"""
SQLite database module for GitHub Security Alert Governance POC.

Provides persistence for Dependabot and Code Scanning alerts, allowing them
to coexist in a unified schema with full historical and raw metadata tracking.
"""

import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from backend.app.config import settings


def get_db_path(custom_path: Optional[str] = None) -> str:
    """Resolves SQLite database file path."""
    raw_path = custom_path or settings.database_path
    if raw_path.startswith("sqlite:///"):
        raw_path = raw_path.replace("sqlite:///", "")
    return raw_path


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured SQLite connection with row factory and WAL mode."""
    path = get_db_path(db_path)
    # Ensure parent directory exists
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes the database schema if tables do not exist."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id TEXT PRIMARY KEY,
                scanner TEXT NOT NULL,
                external_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                state TEXT NOT NULL,
                repository TEXT NOT NULL,
                package_or_rule TEXT NOT NULL,
                affected_file TEXT DEFAULT '',
                title TEXT DEFAULT '',
                html_url TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                raw_data TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_synced_at TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_scanner ON security_alerts(scanner);
            """)
            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_state ON security_alerts(state);
            """)
            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
            """)
            conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_repo ON security_alerts(repository);
            """)

            # Audit log table for sync and webhook events
            conn.execute("""
            CREATE TABLE IF NOT EXISTS governance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                alert_id TEXT,
                details TEXT,
                created_at TEXT NOT NULL
            );
            """)
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Converts a database Row to a JSON-serializable dictionary."""
    data = dict(row)
    if "raw_data" in data and isinstance(data["raw_data"], str):
        try:
            data["raw_data"] = json.loads(data["raw_data"])
        except Exception:
            pass
    return data


def upsert_alert(alert: Dict[str, Any], db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Inserts or updates a security alert in SQLite.
    Preserves `first_seen_at` on update while updating `last_synced_at`.
    """
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_json = json.dumps(alert.get("raw_data", {}))

    try:
        with conn:
            cursor = conn.cursor()
            # Check existing first_seen_at
            cursor.execute("SELECT first_seen_at FROM security_alerts WHERE id = ?", (alert["id"],))
            existing = cursor.fetchone()
            first_seen = existing["first_seen_at"] if existing else now_iso

            cursor.execute("""
            INSERT INTO security_alerts (
                id, scanner, external_id, severity, state, repository,
                package_or_rule, affected_file, title, html_url,
                created_at, updated_at, raw_data, first_seen_at, last_synced_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                severity = excluded.severity,
                state = excluded.state,
                package_or_rule = excluded.package_or_rule,
                affected_file = excluded.affected_file,
                title = excluded.title,
                html_url = excluded.html_url,
                updated_at = excluded.updated_at,
                raw_data = excluded.raw_data,
                last_synced_at = excluded.last_synced_at;
            """, (
                alert["id"],
                alert["scanner"],
                alert["external_id"],
                alert["severity"],
                alert["state"],
                alert["repository"],
                alert.get("package_or_rule", ""),
                alert.get("affected_file", ""),
                alert.get("title", ""),
                alert.get("html_url", ""),
                alert.get("created_at") or now_iso,
                alert.get("updated_at") or now_iso,
                raw_json,
                first_seen,
                now_iso
            ))
            cursor.execute("SELECT * FROM security_alerts WHERE id = ?", (alert["id"],))
            return row_to_dict(cursor.fetchone())
    finally:
        conn.close()


def upsert_alerts_batch(alerts: List[Dict[str, Any]], db_path: Optional[str] = None) -> int:
    """Inserts or updates a batch of alerts in a single transaction."""
    if not alerts:
        return 0
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    count = 0
    try:
        with conn:
            cursor = conn.cursor()
            for alert in alerts:
                cursor.execute("SELECT first_seen_at FROM security_alerts WHERE id = ?", (alert["id"],))
                existing = cursor.fetchone()
                first_seen = existing["first_seen_at"] if existing else now_iso
                raw_json = json.dumps(alert.get("raw_data", {}))

                cursor.execute("""
                INSERT INTO security_alerts (
                    id, scanner, external_id, severity, state, repository,
                    package_or_rule, affected_file, title, html_url,
                    created_at, updated_at, raw_data, first_seen_at, last_synced_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    severity = excluded.severity,
                    state = excluded.state,
                    package_or_rule = excluded.package_or_rule,
                    affected_file = excluded.affected_file,
                    title = excluded.title,
                    html_url = excluded.html_url,
                    updated_at = excluded.updated_at,
                    raw_data = excluded.raw_data,
                    last_synced_at = excluded.last_synced_at;
                """, (
                    alert["id"],
                    alert["scanner"],
                    alert["external_id"],
                    alert["severity"],
                    alert["state"],
                    alert["repository"],
                    alert.get("package_or_rule", ""),
                    alert.get("affected_file", ""),
                    alert.get("title", ""),
                    alert.get("html_url", ""),
                    alert.get("created_at") or now_iso,
                    alert.get("updated_at") or now_iso,
                    raw_json,
                    first_seen,
                    now_iso
                ))
                count += 1
        return count
    finally:
        conn.close()


def get_alerts(
    scanner: Optional[str] = None,
    severity: Optional[str] = None,
    state: Optional[str] = None,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves filtered list of security alerts sorted by updated_at descending."""
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params: List[Any] = []

        if scanner:
            query += " AND scanner = ?"
            params.append(scanner.lower())
        if severity:
            query += " AND severity = ?"
            params.append(severity.lower())
        if state:
            query += " AND state = ?"
            params.append(state.lower())

        query += " ORDER BY updated_at DESC"

        cursor = conn.cursor()
        cursor.execute(query, params)
        return [row_to_dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_alert_by_id(alert_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a single alert by its unique composite id."""
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM security_alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        return row_to_dict(row) if row else None
    finally:
        conn.close()


def get_alerts_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Computes summary metrics for the governance dashboard:
    - total_alerts
    - dependabot_alerts
    - code_scanning_alerts
    - open_alerts
    - fixed_alerts
    - dismissed_alerts
    - severity_breakdown (critical, high, medium, low)
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN scanner = 'dependabot' THEN 1 ELSE 0 END) as dependabot,
            SUM(CASE WHEN scanner = 'code_scanning' THEN 1 ELSE 0 END) as code_scanning,
            SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open,
            SUM(CASE WHEN state = 'fixed' THEN 1 ELSE 0 END) as fixed,
            SUM(CASE WHEN state = 'dismissed' THEN 1 ELSE 0 END) as dismissed,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
        FROM security_alerts;
        """)
        row = cursor.fetchone()
        return {
            "total_alerts": row["total"] or 0,
            "dependabot_alerts": row["dependabot"] or 0,
            "code_scanning_alerts": row["code_scanning"] or 0,
            "open_alerts": row["open"] or 0,
            "fixed_alerts": row["fixed"] or 0,
            "dismissed_alerts": row["dismissed"] or 0,
            "by_severity": {
                "critical": row["critical"] or 0,
                "high": row["high"] or 0,
                "medium": row["medium"] or 0,
                "low": row["low"] or 0,
            }
        }
    finally:
        conn.close()


def record_governance_event(
    event_type: str,
    source: str,
    alert_id: Optional[str] = None,
    details: Optional[str] = None,
    db_path: Optional[str] = None
) -> None:
    """Records an audit log entry for synchronization or webhook events."""
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute("""
            INSERT INTO governance_events (event_type, source, alert_id, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (event_type, source, alert_id, details, now_iso))
    finally:
        conn.close()
