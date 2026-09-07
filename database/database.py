import sqlite3
from pathlib import Path


DATABASE_FILE = Path(__file__).parent / "sentinelx.db"


def get_connection():
    return sqlite3.connect(DATABASE_FILE)


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