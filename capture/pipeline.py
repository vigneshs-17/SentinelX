import logging
import queue
import threading
import time
from typing import Callable, Optional

from capture.metrics import PipelineMetrics
from config.settings import QUEUE_MAXSIZE, WORKER_COUNT, QUEUE_TIMEOUT


logger = logging.getLogger("sentinelx.pipeline")

STOP_TOKEN = object()


class PacketPipeline:
    """
    Decoupled Producer-Consumer packet processing pipeline for SentinelX.
    
    The producer (Scapy sniff or PCAP replay) puts raw packets into a
    bounded thread-safe queue. One or more worker threads consume packets
    and run parsing, rule detection, ML inference, and alert persistence.
    """

    def __init__(
        self,
        maxsize: int = QUEUE_MAXSIZE,
        worker_count: int = WORKER_COUNT,
        processor: Optional[Callable] = None,
    ):
        self.maxsize = maxsize
        self.worker_count = max(1, worker_count)
        self.queue = queue.Queue(maxsize=self.maxsize)
        self.metrics = PipelineMetrics()
        self.processor = processor
        self.stop_event = threading.Event()
        self.workers = []
        self._last_drop_log_time = 0.0
        self._drop_warning_interval = 2.0  # seconds between warnings

    def set_processor(self, processor: Callable):
        """Set or update the packet processor function."""
        self.processor = processor

    def enqueue(self, packet) -> bool:
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
                    f"[PIPELINE WARNING] Queue is full (maxsize={self.maxsize}). "
                    f"Dropping incoming packets. Total dropped: {self.metrics.packets_dropped}"
                )
                self._last_drop_log_time = current_time
            return False

    def _worker_loop(self, worker_id: int):
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
                if self.processor is not None:
                    self.processor(item)
                self.metrics.record_processed()
            except Exception as error:
                self.metrics.record_error()
                logger.error(f"[WORKER-{worker_id} ERROR] Failed to process packet: {error}")
            finally:
                self.queue.task_done()

    def start(self):
        """Start worker threads."""
        self.stop_event.clear()
        self.workers = []
        for i in range(self.worker_count):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(i + 1,),
                name=f"PacketWorker-{i + 1}",
                daemon=True,
            )
            worker.start()
            self.workers.append(worker)

    def stop(self, drain: bool = True, timeout: float = 5.0):
        """
        Stop worker threads cleanly.
        If drain is True, waits for remaining queued packets to finish processing.
        """
        if drain:
            try:
                # Wait for queued tasks to finish up to timeout
                drain_deadline = time.time() + timeout
                while not self.queue.empty() and time.time() < drain_deadline:
                    time.sleep(0.05)
            except Exception:
                pass

        self.stop_event.set()

        # Enqueue stop tokens to unblock any waiting workers
        for _ in self.workers:
            try:
                self.queue.put_nowait(STOP_TOKEN)
            except queue.Full:
                pass

        # Join worker threads
        join_deadline = time.time() + timeout
        for worker in self.workers:
            remaining = max(0.1, join_deadline - time.time())
            worker.join(timeout=remaining)

        self.workers = []

    def get_snapshot(self) -> dict:
        """Return current metrics snapshot including current queue depth."""
        return self.metrics.get_snapshot(self.queue)
