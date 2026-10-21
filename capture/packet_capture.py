"""
Network packet capture entry points and runner logic for SentinelX.

Coordinates capture loops with the bounded producer-consumer PacketPipeline.
All prints in the packet path are replaced by structured logging.
"""

import logging
from collections.abc import Callable
from typing import Any

from scapy.all import sniff

from capture.pipeline import PacketPipeline
from capture.processor import PacketProcessor
from config.settings import CAPTURE_INTERFACE

logger = logging.getLogger("sentinelx.capture")

# Default processor instance for backward compatibility with isolated tests
_default_processor = PacketProcessor()


def process_packet(packet: Any) -> list[dict[str, Any]]:
    """
    Backward-compatible packet processing function.
    Delegates to the default PacketProcessor.
    """
    return _default_processor.process(packet)


def _quiet_enqueue(pipeline: PacketPipeline) -> Callable[[Any], None]:
    """
    Scapy prints whatever the prn callback returns, and PacketPipeline.enqueue returns a bool, so passing it
    directly printed "True" for every captured packet. This wrapper always returns None.
    """

    def callback(packet: Any) -> None:
        pipeline.enqueue(packet)

    return callback


def start_capture(iface: str | None = None, pipeline_instance: PacketPipeline | None = None) -> None:
    """
    Start packet capture using the decoupled producer-consumer pipeline.
    """
    active_pipeline = pipeline_instance or PacketPipeline()
    interface = iface or CAPTURE_INTERFACE

    print("[*] SentinelX IDS started...")
    print(f"[*] Mode: Producer-Consumer (Queue size: {active_pipeline.maxsize}, Workers: 1)")
    if interface:
        print(f"[*] Interface: {interface}")
    print("[*] Monitoring network traffic...")
    print("[*] Press Ctrl+C to stop.\n")

    active_pipeline.start()

    try:
        sniff_kwargs: dict[str, Any] = {
            "prn": _quiet_enqueue(active_pipeline),
            "store": False,
        }
        if interface:
            sniff_kwargs["iface"] = interface

        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    finally:
        active_pipeline.stop(drain=True)
        snapshot = active_pipeline.get_snapshot()
        print("\n[+] Final Pipeline Metrics:")
        for k, v in snapshot.items():
            print(f"    {k}: {v}")


if __name__ == "__main__":
    start_capture()
