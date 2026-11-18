import pandas as pd
import pytest
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from mitm_detector.features import FEATURE_COLUMNS, packets_to_features
from mitm_detector.models import classify, load_model, train_models
from mitm_detector.reports import summary_report


def pkt(ts, op, ip, mac, pdst="192.168.1.1"):
    p = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=op, psrc=ip, hwsrc=mac, pdst=pdst)
    p.time = ts
    return p


def test_arp_feature_extraction_counts_and_conflict():
    packets = [pkt(100, 1, "192.168.1.2", "00:00:00:00:00:01", "192.168.1.1"),
               pkt(101, 2, "192.168.1.1", "00:00:00:00:00:02"),
               pkt(102, 2, "192.168.1.1", "00:00:00:00:00:03")]
    df = packets_to_features(packets, 10)
    assert len(df) == 1
    assert df.iloc[0].arp_request_count == 1
    assert df.iloc[0].arp_reply_count == 2
    assert df.iloc[0].arp_unsolicited_reply_count == 0
    assert df.iloc[0].arp_conflicting_ip_count == 1
    assert set(FEATURE_COLUMNS).issubset(df.columns)


def test_unsolicited_reply_and_protocol_features():
    p = pkt(10, 2, "10.0.0.1", "00:00:00:00:00:01")
    df = packets_to_features([p], 10)
    assert df.iloc[0].arp_unsolicited_reply_count == 1
    ip_pkt = Ether() / IP(dst="1.1.1.1") / UDP(dport=53) / Raw(load=b"x")
    ip_pkt.time = 10
    row = packets_to_features([ip_pkt]).iloc[0]
    assert row.ipv4_fraction == 1
    assert row.udp_fraction == 1


def test_empty_or_malformed_records_are_handled():
    class Bad:
        @property
        def time(self): raise ValueError("bad timestamp")
    assert packets_to_features([]).empty
    assert packets_to_features([Bad()]).empty


def test_pcap_import_valid_and_invalid(tmp_path):
    from scapy.utils import wrpcap
    from mitm_detector.pcap import read_capture, features_from_capture
    capture = tmp_path / "sample.pcap"
    wrpcap(str(capture), [pkt(100, 1, "10.0.0.1", "00:00:00:00:00:01")])
    assert len(read_capture(capture)) == 1
    assert len(features_from_capture(capture)) == 1
    with pytest.raises(ValueError): read_capture(tmp_path / "missing.pcap")


def test_training_persistence_classification_and_report(tmp_path):
    rows = []
    for label in (0, 1):
        for i in range(30):
            row = {c: float((i % 4) + (label * 3 if c.startswith("arp_") else label)) for c in FEATURE_COLUMNS}
            row["label"] = label
            row["capture_session"] = f"{'normal' if label == 0 else 'mitm'}-{i // 5}"
            rows.append(row)
    data = pd.DataFrame(rows)
    report = train_models(data, tmp_path)
    assert report["partition_counts"]["test"] > 0
    artifact = load_model("Random Forest", tmp_path)
    predictions = classify(data[FEATURE_COLUMNS], artifact)
    assert set(predictions.prediction.unique()).issubset({0, 1})
    assert "test" in report["models"]["Random Forest"]
    text = summary_report(predictions, "Random Forest", "test input")
    assert "not proof" in text


def test_invalid_training_input_rejected():
    with pytest.raises(ValueError): train_models(pd.DataFrame({"label": [0, 1]}), "models")
