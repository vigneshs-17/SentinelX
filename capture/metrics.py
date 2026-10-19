import threading


class PipelineMetrics:
    """
    Thread-safe metrics tracker for the SentinelX packet ingestion
    and processing pipeline.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.packets_received = 0
        self.packets_queued = 0
        self.packets_processed = 0
        self.packets_dropped = 0
        self.processing_errors = 0
        self.parse_errors = 0
        self.alerts_generated = 0

    def record_received(self, count: int = 1):
        with self._lock:
            self.packets_received += count

    def record_queued(self, count: int = 1):
        with self._lock:
            self.packets_queued += count

    def record_processed(self, count: int = 1):
        with self._lock:
            self.packets_processed += count

    def record_dropped(self, count: int = 1):
        with self._lock:
            self.packets_dropped += count

    def record_error(self, count: int = 1):
        with self._lock:
            self.processing_errors += count

    def record_parse_error(self, count: int = 1):
        with self._lock:
            self.parse_errors += count

    def record_alert(self, count: int = 1):
        with self._lock:
            self.alerts_generated += count

    def reset(self):
        """Reset all counters to zero."""
        with self._lock:
            self.packets_received = 0
            self.packets_queued = 0
            self.packets_processed = 0
            self.packets_dropped = 0
            self.processing_errors = 0
            self.parse_errors = 0
            self.alerts_generated = 0

    def get_snapshot(self, queue=None) -> dict:
        """
        Return an atomic snapshot of the current pipeline metrics,
        optionally sampling the current queue depth.
        """
        with self._lock:
            current_queue_size = queue.qsize() if queue is not None else 0
            return {
                "packets_received": self.packets_received,
                "packets_queued": self.packets_queued,
                "packets_processed": self.packets_processed,
                "packets_dropped": self.packets_dropped,
                "processing_errors": self.processing_errors,
                "parse_errors": self.parse_errors,
                "alerts_generated": self.alerts_generated,
                "current_queue_size": current_queue_size,
            }

    def __repr__(self):
        snap = self.get_snapshot()
        return (
            f"<PipelineMetrics received={snap['packets_received']} "
            f"queued={snap['packets_queued']} "
            f"processed={snap['packets_processed']} "
            f"dropped={snap['packets_dropped']} "
            f"errors={snap['processing_errors']} "
            f"parse_errors={snap['parse_errors']} "
            f"alerts={snap['alerts_generated']}>"
        )
