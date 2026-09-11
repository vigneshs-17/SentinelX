from flask import Flask, jsonify, send_from_directory
from database.database import get_connection
from pathlib import Path
from config.settings import THREAT_TYPE_PORT_SCAN, THREAT_TYPE_HIGH_TRAFFIC


app = Flask(__name__)

DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"


@app.route("/")
def home():
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/alerts")
def get_alerts():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            threat_type,
            severity,
            source_ip,
            destination_ip,
            protocol,
            message
        FROM alerts
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    connection.close()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row[0],
            "timestamp": row[1],
            "threat_type": row[2],
            "severity": row[3],
            "source_ip": row[4],
            "destination_ip": row[5],
            "protocol": row[6],
            "message": row[7]
        })

    return jsonify(alerts)


@app.route("/api/stats")
def get_stats():
    connection = get_connection()
    cursor = connection.cursor()

    # Total alerts
    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    # High severity alerts
    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
    """)
    high_severity = cursor.fetchone()[0]

    # Port scan alerts (canonical PORT_SCAN detection events)
    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE threat_type = ?
    """, (THREAT_TYPE_PORT_SCAN,))
    port_scans = cursor.fetchone()[0]

    # High traffic alerts (canonical HIGH_TRAFFIC detection events)
    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE threat_type = ?
    """, (THREAT_TYPE_HIGH_TRAFFIC,))
    high_traffic = cursor.fetchone()[0]

    connection.close()

    return jsonify({
        "total_alerts": total_alerts,
        "high_severity": high_severity,
        "port_scans": port_scans,
        "high_traffic": high_traffic
    })


if __name__ == "__main__":
    app.run(debug=True)