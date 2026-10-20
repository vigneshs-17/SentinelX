"""
Decoupled Producer-Consumer packet processing pipeline for SentinelX.

The producer (Scapy sniff or PCAP replay) puts raw packets into a
bounded thread-safe queue. A single consumer worker thread consumes packets
and executes parsing, rule detection, ML inference, and alert persistence (Correction 8).
Emits periodic pipeline throughput and health summaries at INFO level.
"""

import logging
import queue
import threading
import time
from collections.abc import Callable
from typing import Any

from capture.metrics import PipelineMetrics
from config.settings import QUEUE_MAXSIZE, QUEUE_TIMEOUT, STATS_INTERVAL

logger = logging.getLogger("sentinelx.pipeline")

STOP_TOKEN = object()


class PacketPipeline:
    """
    Decoupled Producer-Consumer packet processing pipeline for SentinelX.
    Uses a single dedicated consumer worker thread for ordered, deterministic processing.
    """

    def __init__(
        self,
        maxsize: int = QUEUE_MAXSIZE,
        processor: Callable | None = None,
        stats_interval: float = STATS_INTERVAL,
    ):
        self.maxsize = maxsize
        self.queue: queue.Queue[Any] = queue.Queue(maxsize=self.maxsize)
        self.metrics = PipelineMetrics()
        self.stats_interval = stats_interval
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self._stats_thread: threading.Thread | None = None
        self._last_drop_log_time = 0.0
        self._drop_warning_interval = 2.0  # seconds between warnings

        self.processor: Callable[[Any], Any]
        self.set_processor(processor)

    def set_processor(self, processor: Any) -> None:
        """Set or update the packet processor function or PacketProcessor instance."""
        if processor is None:
            from capture.processor import PacketProcessor

            proc = PacketProcessor(metrics=self.metrics)
            self.processor = proc.process
        elif hasattr(processor, "metrics"):
            # PacketProcessor instance
            processor.metrics = self.metrics
            self.processor = getattr(processor, "process", processor)
        else:
            if getattr(processor, "__name__", "") == "process_packet":
                from capture.processor import PacketProcessor

                proc = PacketProcessor(metrics=self.metrics)
                self.processor = proc.process
            else:
                self.processor = processor

    def enqueue(self, packet: Any) -> bool:
        """
        Producer interface. Fast and non-blocking.
        Enqueues packet or records drop if queue is saturated.
        """
        self.metrics.record_received()

        try:
            self.queue.put_nowait(packet)
            self.metrics.record_queued()
            return True
        except queue.Full:
            self.metrics.record_dropped()
            current_time = time.time()
            if current_time - self._last_drop_log_time >= self._drop_warning_interval:
                logger.warning(
                    "[PIPELINE WARNING] Queue is full (maxsize=%d). Dropping incoming packets. Total dropped: %d",
                    self.maxsize,
                    self.metrics.packets_dropped,
                )
                self._last_drop_log_time = current_time
            return False

    def _worker_loop(self, worker_id: int) -> None:
        """Consumer worker loop processing items from the bounded queue."""
        while not self.stop_event.is_set() or not self.queue.empty():
            try:
                item = self.queue.get(timeout=QUEUE_TIMEOUT)
            except queue.Empty:
                continue

            if item is STOP_TOKEN:
                self.queue.task_done()
                break

            try:
                self.processor(item)
                self.metrics.record_processed()
            except Exception as exc:
                self.metrics.record_error()
                logger.error("[PIPELINE ERROR] Worker %d failed to process packet: %s", worker_id, exc)
            finally:
                self.queue.task_done()

    def _stats_monitor_loop(self) -> None:
        """Periodically reports pipeline throughput and buffer statistics at INFO level."""
        last_time = time.time()
        last_processed = self.metrics.packets_processed

        while not self.stop_event.wait(timeout=self.stats_interval):
            current_time = time.time()
            elapsed = current_time - last_time
            current_processed = self.metrics.packets_processed
            pps = (current_processed - last_processed) / elapsed if elapsed > 0 else 0.0

            last_time = current_time
            last_processed = current_processed

            logger.info(
                "Pipeline stats: %.1f pps | Queue depth: %d | Dropped: %d | Alerts: %d",
                pps,
                self.queue.qsize(),
                self.metrics.packets_dropped,
                self.metrics.alerts_generated,
            )

    def start(self) -> None:
        """Start single consumer worker thread and background periodic stats reporter."""
        self.stop_event.clear()
        self.worker = threading.Thread(
            target=self._worker_loop,
            args=(1,),
            name="PacketWorker-1",
            daemon=True,
        )
        self.worker.start()

        if self.stats_interval > 0:
            self._stats_thread = threading.Thread(
                target=self._stats_monitor_loop,
                name="PipelineStatsMonitor",
                daemon=True,
            )
            self._stats_thread.start()

    def stop(self, drain: bool = True, timeout: float = 5.0) -> None:
        """
        Stop consumer worker thread cleanly.
        If drain is True, waits for remaining queued packets to finish processing.
        """
        if drain:
            try:
                drain_deadline = time.time() + timeout
                while not self.queue.empty() and time.time() < drain_deadline:
                    time.sleep(0.05)
            except Exception as exc:
                logger.debug("Exception while draining queue during pipeline stop: %s", exc)

        self.stop_event.set()

        # Enqueue stop token to unblock worker
        if self.worker and self.worker.is_alive():
            try:
                self.queue.put_nowait(STOP_TOKEN)
            except queue.Full:
                pass

            join_deadline = time.time() + timeout
            remaining = max(0.1, join_deadline - time.time())
            self.worker.join(timeout=remaining)
            self.worker = None

        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=0.5)
            self._stats_thread = None

    def get_snapshot(self) -> dict[str, Any]:
        """Return current metrics snapshot including current queue depth."""
        return self.metrics.get_snapshot(self.queue)
