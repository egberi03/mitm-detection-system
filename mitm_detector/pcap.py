"""Safe offline PCAP/PCAPNG input helpers."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Iterable


def read_capture(path: str | Path) -> list[Any]:
    """Read a local capture with Scapy. Raises actionable errors for bad input."""
    try:
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Install requirements.txt first.") from exc
    capture = Path(path)
    if not capture.is_file() or capture.stat().st_size == 0:
        raise ValueError("Capture file does not exist or is empty.")
    packets = []
    try:
        with PcapReader(str(capture)) as reader:
            for packet in reader:
                packets.append(packet)
    except Exception as exc:
        raise ValueError(f"Could not parse capture: {exc}") from exc
    if not packets:
        raise ValueError("The capture contains no readable packets.")
    return packets


def features_from_capture(path: str | Path, window_seconds: int = 10):
    from .features import packets_to_features
    return packets_to_features(read_capture(path), window_seconds)


def features_from_packets(packets: Iterable[Any], window_seconds: int = 10):
    from .features import packets_to_features
    return packets_to_features(packets, window_seconds)
