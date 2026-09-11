import os
import sqlite3
from pathlib import Path


DEFAULT_DATABASE_FILE = Path(__file__).parent / "sentinelx.db"


def get_database_path():
    override = os.getenv("SENTINELX_DB_PATH")
    if override:
        return Path(override)
    return DEFAULT_DATABASE_FILE


# Preserve DATABASE_FILE for backwards compatibility
DATABASE_FILE = DEFAULT_DATABASE_FILE


def get_connection(db_path=None):
    target_path = Path(db_path) if db_path else get_database_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(target_path, timeout=10.0)
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
    return connection


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            message TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("[+] SentinelX database initialized.")


def insert_alert(alert):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            threat_type,
            severity,
            source_ip,
            destination_ip,
            protocol,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["threat_type"],
        alert["severity"],
        alert.get("source_ip"),
        alert.get("destination_ip"),
        alert.get("protocol"),
        alert.get("message")
    ))

    connection.commit()
    connection.close()

    print("[+] Alert stored in database.")


if __name__ == "__main__":
    initialize_database()