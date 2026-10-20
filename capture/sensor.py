"""
The sensor process: capture (or PCAP replay) -> bounded queue -> engine -> alert sinks -> alerts.db.

No HTTP lives here. Besides the packet path it runs two housekeeping threads:
  * a heartbeat that writes a sensor_status row every SENSOR_STATUS_INTERVAL seconds (read by the API), and
  * retention: a prune of alerts ingested more than RETENTION_DAYS ago at start and then daily (live capture only, never replay), plus pruning of old heartbeats.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from capture.packet_capture import start_capture
from capture.pcap_replay import replay_pcap
from capture.pipeline import PacketPipeline
from capture.processor import PacketProcessor
from config.settings import (
    QUEUE_MAXSIZE,
    RETENTION_DAYS,
    RETENTION_INTERVAL_SECONDS,
    SENSOR_ID,
    SENSOR_STATUS_INTERVAL,
    SENSOR_STATUS_RETENTION_HOURS,
)
from database.database import (
    close_database,
    initialize_database,
    insert_sensor_status,
    prune_alerts,
    prune_sensor_status,
)
from logs.sinks import CompositeSink, build_sink_from_env

logger = logging.getLogger("sentinelx.sensor")


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


class Sensor:
    def __init__(
        self,
        sensor_id: str = SENSOR_ID,
        sink: CompositeSink | None = None,
        status_interval: float = SENSOR_STATUS_INTERVAL,
        retention_days: int = RETENTION_DAYS,
        retention_interval: float = RETENTION_INTERVAL_SECONDS,
        queue_maxsize: int = QUEUE_MAXSIZE,
        utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.sensor_id = sensor_id
        self.sink = sink or build_sink_from_env()
        self.pipeline = PacketPipeline(maxsize=queue_maxsize)
        self.processor = PacketProcessor(alert_sink=self.sink, sensor_id=sensor_id)
        self.pipeline.set_processor(self.processor)
        self.status_interval = status_interval
        self.retention_days = retention_days
        self.retention_interval = retention_interval
        self._utcnow = utcnow
        self._monotonic = monotonic
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._last_processed = 0
        self._last_tick = monotonic()

    # -- status ------------------------------------------------------------------------------------

    def collect_status(self) -> dict[str, Any]:
        snap = self.pipeline.get_snapshot()
        partitions = self.processor.engine.get_metrics()["partitions"]
        now = self._monotonic()
        elapsed = now - self._last_tick
        pps = (snap["packets_processed"] - self._last_processed) / elapsed if elapsed > 0 else 0.0
        self._last_processed, self._last_tick = snap["packets_processed"], now
        return {
            "sensor_id": self.sensor_id,
            "last_seen": _iso(self._utcnow()),
            "received": snap["packets_received"],
            "dropped": snap["packets_dropped"],
            "queue_depth": snap["current_queue_size"],
            "pps_10s": round(pps, 2),
            "state_size": sum(p["size"] for p in partitions.values()),
            "evictions": sum(p["evictions"] for p in partitions.values()),
            "webhook_failures": self.sink.webhook_failures,
        }

    def write_status(self) -> dict[str, Any]:
        status = self.collect_status()
        insert_sensor_status(status)
        return status

    # -- retention ---------------------------------------------------------------------------------

    def prune_now(self) -> int:
        """Prune old heartbeats always, and alerts when retention is enabled. Returns alerts deleted."""
        now = self._utcnow()
        prune_sensor_status(_iso(now - timedelta(hours=SENSOR_STATUS_RETENTION_HOURS)))
        if self.retention_days <= 0:
            return 0
        deleted = prune_alerts(_iso(now - timedelta(days=self.retention_days)))
        if deleted:
            logger.info("Retention: deleted %d alerts older than %d days", deleted, self.retention_days)
        return deleted

    # -- lifecycle ---------------------------------------------------------------------------------

    def _loop(self, interval: float, action: Callable[[], Any], name: str) -> None:
        while not self._stop.is_set():
            try:
                action()
            except Exception as exc:
                logger.error("Sensor %s task failed: %s", name, exc)
            if self._stop.wait(interval):
                break

    def start(self, retention: bool = True) -> None:
        """
        Create/upgrade alerts.db (D2) and start the heartbeat thread and, unless retention is False, the retention
        thread. Replay passes retention=False: an offline replay must never delete anything (N1).
        """
        initialize_database()
        self._stop.clear()
        tasks: list[tuple[str, float, Callable[[], object]]] = [("heartbeat", self.status_interval, self.write_status)]
        if retention:
            tasks.append(("retention", self.retention_interval, self.prune_now))
        for name, interval, action in tasks:
            t = threading.Thread(target=self._loop, args=(interval, action, name), name=f"Sensor-{name}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5.0)
        self._threads.clear()
        try:
            self.write_status()
        except Exception as exc:
            logger.error("Final sensor status write failed: %s", exc)
        self.sink.close()
        close_database()

    def run_capture(self, interface: str | None = None) -> None:
        self.start()
        try:
            start_capture(iface=interface, pipeline_instance=self.pipeline)
        finally:
            self.stop()

    def run_replay(self, pcap_path: str) -> dict[str, Any]:
        self.start(retention=False)
        try:
            return replay_pcap(pcap_path, pipeline_instance=self.pipeline)
        finally:
            self.stop()
