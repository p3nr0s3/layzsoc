"""SQLite caching and history layer for Slothery."""

import sqlite3
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from core.config import CACHE_DB_FILE, CACHE_TTL_HOURS


def utc_now() -> datetime:
    """Helper to return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(CACHE_DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables in the SQLite database."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc_value TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                overall_verdict TEXT NOT NULL,
                vt_data TEXT,
                abuse_data TEXT,
                hit_count INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_iocs INTEGER NOT NULL,
                malicious INTEGER NOT NULL,
                suspicious INTEGER NOT NULL,
                clean INTEGER NOT NULL,
                unknown INTEGER NOT NULL
            )
            """
        )
        conn.commit()


# Initialize on import
init_db()


def get_cached_ioc(ioc_value: str) -> Optional[Dict[str, Any]]:
    """Fetches valid, non-expired cache record for an IoC."""
    val = ioc_value.lower().strip()
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM ioc_cache 
            WHERE ioc_value = ? AND expires_at > ?
            """,
            (val, now_str),
        )
        row = cursor.fetchone()
        if not row:
            return None

        # Increment hit counter
        cursor.execute(
            "UPDATE ioc_cache SET hit_count = hit_count + 1 WHERE ioc_value = ?",
            (val,),
        )
        conn.commit()

        vt_parsed = json.loads(row["vt_data"]) if row["vt_data"] else None
        abuse_parsed = json.loads(row["abuse_data"]) if row["abuse_data"] else None

        return {
            "ioc_value": row["ioc_value"],
            "ioc_type": row["ioc_type"],
            "verdict": row["overall_verdict"],
            "vt_data": vt_parsed,
            "abuse_data": abuse_parsed,
            "hit_count": row["hit_count"],
            "updated_at": row["updated_at"],
            "expires_at": row["expires_at"],
            "is_cached": True,
        }


def save_cached_ioc(
    ioc_value: str,
    ioc_type: str,
    verdict: str,
    vt_data: Optional[Dict],
    abuse_data: Optional[Dict],
    ttl_hours: int = CACHE_TTL_HOURS,
):
    """Saves or updates an IoC result in the cache."""
    val = ioc_value.lower().strip()
    now = utc_now()
    expires = now + timedelta(hours=ttl_hours)
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

    vt_json = json.dumps(vt_data) if vt_data else None
    abuse_json = json.dumps(abuse_data) if abuse_data else None

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO ioc_cache (ioc_value, ioc_type, overall_verdict, vt_data, abuse_data, hit_count, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(ioc_value) DO UPDATE SET
                overall_verdict = excluded.overall_verdict,
                vt_data = excluded.vt_data,
                abuse_data = excluded.abuse_data,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at
            """,
            (val, ioc_type, verdict, vt_json, abuse_json, now_str, expires_str),
        )
        conn.commit()


def get_all_cached_iocs(limit: int = 500) -> List[Dict[str, Any]]:
    """Returns list of cached IoCs for management view."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT ioc_value, ioc_type, overall_verdict, hit_count, updated_at, expires_at
            FROM ioc_cache
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]


def clear_cache() -> int:
    """Purges all cached IoCs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ioc_cache")
        count = cursor.rowcount
        conn.commit()
        return count


def delete_cache_entry(ioc_value: str) -> bool:
    """Deletes a specific entry from the cache."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ioc_cache WHERE ioc_value = ?", (ioc_value.lower().strip(),))
        deleted = cursor.rowcount > 0
        conn.commit()
        return deleted


def get_cache_stats() -> Dict[str, int]:
    """Returns count of active and expired entries."""
    now_str = utc_now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ioc_cache WHERE expires_at > ?", (now_str,))
        active_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ioc_cache WHERE expires_at <= ?", (now_str,))
        expired_count = cursor.fetchone()[0]

        return {"active": active_count, "expired": expired_count, "total": active_count + expired_count}


def log_scan(total: int, mal: int, susp: int, clean: int, unk: int):
    """Logs a completed batch scan to the audit history."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_history (total_iocs, malicious, suspicious, clean, unknown)
            VALUES (?, ?, ?, ?, ?)
            """,
            (total, mal, susp, clean, unk),
        )
        conn.commit()


def get_scan_history(limit: int = 20) -> List[Dict[str, Any]]:
    """Returns recent scan history logs."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scan_history
            ORDER BY scan_timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
