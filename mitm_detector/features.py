"""Packet feature extraction shared by offline and live analysis."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, Any
import math

import pandas as pd

FEATURE_COLUMNS = [
    "arp_request_count", "arp_reply_count", "arp_unsolicited_reply_count",
    "arp_conflicting_ip_count", "arp_mapping_change_count", "arp_packets_per_second",
    "packet_count", "average_packet_size", "ipv4_fraction", "ipv6_fraction",
    "tcp_fraction", "udp_fraction", "icmp_fraction", "dns_fraction",
    "other_fraction", "unique_source_macs", "unique_destination_macs",
]
METADATA_COLUMNS = ["window_start", "source_summary", "destination_summary"]


def _has(packet: Any, layer: str) -> bool:
    try:
        return packet.haslayer(layer)
    except Exception:
        return False


def packets_to_features(packets: Iterable[Any], window_seconds: int = 10) -> pd.DataFrame:
    """Aggregate Scapy packets into fixed, capture-relative time windows.

    This is a behavioural feature extractor, not an attack proof. Mapping changes
    and replies without an earlier matching request are indicators only.
    """
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")
    windows: dict[int, dict[str, Any]] = {}
    prior_ip_mac: dict[str, str] = {}
    requests_seen: set[str] = set()

    for packet in packets:
        try:
            timestamp = float(packet.time)
            if not math.isfinite(timestamp):
                continue
            bucket = int(timestamp // window_seconds)
            row = windows.setdefault(bucket, {
                "packets": 0, "sizes": 0, "arp_req": 0, "arp_reply": 0,
                "unsolicited": 0, "mapping_changes": 0, "arp_ips": defaultdict(set),
                "src_macs": set(), "dst_macs": set(), "srcs": [], "dsts": [],
                "protocols": defaultdict(int),
            })
            row["packets"] += 1
            try:
                size = int(len(packet))
            except Exception:
                size = 0
            row["sizes"] += max(0, size)
            src_mac = dst_mac = ""
            if _has(packet, "Ether"):
                src_mac = str(packet["Ether"].src or "").lower()
                dst_mac = str(packet["Ether"].dst or "").lower()
                if src_mac: row["src_macs"].add(src_mac)
                if dst_mac: row["dst_macs"].add(dst_mac)
            if _has(packet, "ARP"):
                arp = packet["ARP"]
                op = int(getattr(arp, "op", 0) or 0)
                psrc = str(getattr(arp, "psrc", "") or "")
                pdst = str(getattr(arp, "pdst", "") or "")
                hwsrc = str(getattr(arp, "hwsrc", "") or src_mac).lower()
                row["protocols"]["arp"] += 1
                if op == 1:
                    row["arp_req"] += 1
                    if pdst:
                        requests_seen.add(pdst)
                elif op == 2:
                    row["arp_reply"] += 1
                    if psrc and psrc not in requests_seen:
                        row["unsolicited"] += 1
                if psrc and hwsrc:
                    row["arp_ips"][psrc].add(hwsrc)
                    old = prior_ip_mac.get(psrc)
                    if old is not None and old != hwsrc:
                        row["mapping_changes"] += 1
                    prior_ip_mac[psrc] = hwsrc
            elif _has(packet, "IPv6"):
                row["protocols"]["ipv6"] += 1
            elif _has(packet, "IP"):
                row["protocols"]["ipv4"] += 1
            else:
                row["protocols"]["other"] += 1
            if _has(packet, "TCP"): row["protocols"]["tcp"] += 1
            if _has(packet, "UDP"): row["protocols"]["udp"] += 1
            if _has(packet, "ICMP"): row["protocols"]["icmp"] += 1
            if _has(packet, "DNS"): row["protocols"]["dns"] += 1
            if src_mac and src_mac not in row["srcs"]: row["srcs"].append(src_mac)
            if dst_mac and dst_mac not in row["dsts"]: row["dsts"].append(dst_mac)
        except (AttributeError, TypeError, ValueError, OverflowError):
            # Skip malformed individual records and continue with the capture.
            continue

    output = []
    for bucket in sorted(windows):
        item = windows[bucket]
        count = item["packets"]
        arp_count = item["arp_req"] + item["arp_reply"]
        row = {
            "window_start": datetime.fromtimestamp(bucket * window_seconds, tz=timezone.utc).isoformat(),
            "source_summary": ", ".join(item["srcs"][:5]),
            "destination_summary": ", ".join(item["dsts"][:5]),
            "arp_request_count": item["arp_req"],
            "arp_reply_count": item["arp_reply"],
            "arp_unsolicited_reply_count": item["unsolicited"],
            "arp_conflicting_ip_count": sum(1 for macs in item["arp_ips"].values() if len(macs) > 1),
            "arp_mapping_change_count": item["mapping_changes"],
            "arp_packets_per_second": arp_count / window_seconds,
            "packet_count": count,
            "average_packet_size": item["sizes"] / count if count else 0.0,
            "unique_source_macs": len(item["src_macs"]),
            "unique_destination_macs": len(item["dst_macs"]),
        }
        protocol_map = {"ipv4": "ipv4_fraction", "ipv6": "ipv6_fraction", "tcp": "tcp_fraction",
                        "udp": "udp_fraction", "icmp": "icmp_fraction", "dns": "dns_fraction"}
        for proto, column in protocol_map.items():
            row[column] = item["protocols"].get(proto, 0) / count if count else 0.0
        row["other_fraction"] = max(0.0, 1.0 - sum(row[c] for c in protocol_map.values()))
        output.append(row)
    return pd.DataFrame(output, columns=METADATA_COLUMNS + FEATURE_COLUMNS)
