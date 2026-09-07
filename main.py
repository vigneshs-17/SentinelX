import threading
import time

from backend.api import app
from capture.packet_capture import start_capture


def start_dashboard():
    print("[*] Starting SentinelX dashboard...")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )


def main():
    print("=" * 60)
    print("        SENTINELX")
    print("        Network Intrusion Detection &")
    print("        Threat Monitoring System")
    print("=" * 60)

    print("\n[*] Starting SentinelX components...\n")

    # Start Flask dashboard in background
    dashboard_thread = threading.Thread(
        target=start_dashboard,
        daemon=True
    )

    dashboard_thread.start()

    # Give Flask a moment to start
    time.sleep(2)

    print("[+] Dashboard available at:")
    print("[+] http://127.0.0.1:5000/\n")

    # Start packet capture
    print("[*] Starting network monitoring...\n")

    start_capture()


if __name__ == "__main__":
    main()