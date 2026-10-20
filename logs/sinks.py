"""
Alert sinks behind one interface: JSONL, SQLite, Webhook.

A sink receives a normalized alert record (see logs.alert_logger.normalize_alert) and must not mutate it.
CompositeSink fans out to several sinks and isolates failures: one broken sink never stops the others and
never raises into the engine thread. WebhookSink never blocks the caller: it enqueues on a bounded queue and a
background thread delivers with retries and exponential backoff.

The webhook URL is a secret. It is held only in a private attribute, excluded from repr(), and never logged.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from config.settings import (
    WEBHOOK_BACKOFF_SECONDS,
    WEBHOOK_COOLDOWN,
    WEBHOOK_MODE,
    WEBHOOK_QUEUE_MAXSIZE,
    WEBHOOK_RETRIES,
    WEBHOOK_TIMEOUT_SECONDS,
    WEBHOOK_URL_ENV,
)
from database.database import insert_alert
from detection.state_store import BoundedStateStore
from logs.alert_logger import append_jsonl, normalize_alert

logger = logging.getLogger("sentinelx.sinks")

DEDUP_KEYS_MAX = 4096
DISCORD_MAX_CHARS = 2000


class AlertSink(ABC):
    """One destination for alerts."""

    @abstractmethod
    def emit(self, record: dict[str, Any]) -> None:
        """Deliver one normalized alert record. May raise; CompositeSink isolates failures."""

    def close(self) -> None:  # noqa: B027 - optional hook, most sinks hold no resources
        """Release resources (threads, files). Default: nothing to do."""


class JsonlSink(AlertSink):
    def emit(self, record: dict[str, Any]) -> None:
        append_jsonl(record)


class SqliteSink(AlertSink):
    def emit(self, record: dict[str, Any]) -> None:
        insert_alert(record)


def webhook_payload(record: dict[str, Any], mode: str) -> dict[str, Any]:
    """Build the JSON body for generic | slack | discord."""
    if mode == "generic":
        return dict(record)
    text = (
        f"[{record.get('severity', '?')}] {record.get('threat_type', '?')} from {record.get('source_ip')} "
        f"to {record.get('destination_ip')}: {record.get('message', '')}"
    )
    if mode == "slack":
        return {"text": text}
    if mode == "discord":
        return {"content": text[:DISCORD_MAX_CHARS]}
    raise ValueError(f"unknown webhook mode: {mode}")


def _http_post(url: str, body: bytes, timeout: float) -> None:
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        response.read(1024)


class WebhookSink(AlertSink):
    """Background-thread webhook delivery with bounded queue, dedup, retries and backoff."""

    def __init__(
        self,
        url: str,
        mode: str = WEBHOOK_MODE,
        cooldown: float = WEBHOOK_COOLDOWN,
        queue_max: int = WEBHOOK_QUEUE_MAXSIZE,
        retries: int = WEBHOOK_RETRIES,
        backoff: float = WEBHOOK_BACKOFF_SECONDS,
        timeout: float = WEBHOOK_TIMEOUT_SECONDS,
        post: Callable[[str, bytes, float], None] = _http_post,
        sleep: Callable[[float], bool] | None = None,
    ) -> None:
        if urlsplit(url).scheme not in ("http", "https"):
            raise ValueError("webhook URL must use http or https")
        if mode not in ("generic", "slack", "discord"):
            raise ValueError("webhook mode must be generic, slack or discord")
        self._url = url  # secret
        self.mode, self.cooldown, self.retries, self.backoff, self.timeout = mode, cooldown, retries, backoff, timeout
        self._post = post
        self._stop = threading.Event()
        self._sleep = sleep or self._stop.wait
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=queue_max)
        self._last_sent: BoundedStateStore[float] = BoundedStateStore("webhook_dedup", DEDUP_KEYS_MAX)
        self._lock = threading.Lock()
        self.failures = 0
        self.sent = 0
        self.suppressed = 0
        self._thread = threading.Thread(target=self._run, name="WebhookSink", daemon=True)
        self._thread.start()

    def __repr__(self) -> str:
        return f"<WebhookSink mode={self.mode} sent={self.sent} failures={self.failures}>"

    def emit(self, record: dict[str, Any]) -> None:
        """Never blocks: dedup in event time, enqueue or count a failure when the queue is full."""
        key = (record.get("threat_type"), record.get("source_ip"))
        event_ts = float(record.get("last_seen") or 0.0)
        last = self._last_sent.get(key)
        if last is not None and event_ts - last < self.cooldown:
            with self._lock:
                self.suppressed += 1
            return
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self.failures += 1
            logger.warning("Webhook queue full; alert dropped (failures=%d)", self.failures)
            return
        self._last_sent.put(key, event_ts)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                record = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            body = json.dumps(webhook_payload(record, self.mode), ensure_ascii=False).encode("utf-8")
            if self._deliver(body):
                with self._lock:
                    self.sent += 1
            else:
                with self._lock:
                    self.failures += 1
                logger.error("Webhook delivery failed after %d retries", self.retries)

    def _deliver(self, body: bytes) -> bool:
        for attempt in range(self.retries + 1):
            try:
                self._post(self._url, body, self.timeout)
                return True
            except (OSError, urllib.error.URLError, ValueError) as exc:
                # Log the exception type only: messages from urllib can echo request details.
                logger.warning("Webhook attempt %d failed (%s)", attempt + 1, type(exc).__name__)
                if attempt < self.retries and self._sleep(self.backoff * (2**attempt)):
                    return False  # stop requested during backoff
        return False

    def close(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._thread.join(timeout=timeout)


class CompositeSink(AlertSink):
    """Fan-out to several sinks; a failing sink is logged and counted, never raised."""

    def __init__(self, sinks: list[AlertSink]) -> None:
        self.sinks = sinks
        self.sink_errors = 0

    @property
    def webhook_failures(self) -> int:
        return sum(s.failures for s in self.sinks if isinstance(s, WebhookSink))

    def emit(self, record: dict[str, Any]) -> None:
        for sink in self.sinks:
            try:
                sink.emit(record)
            except Exception as exc:
                self.sink_errors += 1
                logger.error("Alert sink %s failed: %s", type(sink).__name__, type(exc).__name__)

    def __call__(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Processor-compatible entry point: normalize once, then fan out."""
        record = normalize_alert(alert)
        self.emit(record)
        return record

    def close(self) -> None:
        for sink in self.sinks:
            sink.close()


def build_sink_from_env() -> CompositeSink:
    """JSONL + SQLite always; webhook only when SENTINELX_WEBHOOK_URL is set."""
    sinks: list[AlertSink] = [JsonlSink(), SqliteSink()]
    url = os.environ.get(WEBHOOK_URL_ENV, "").strip()
    if url:
        sinks.append(WebhookSink(url))
    return CompositeSink(sinks)
