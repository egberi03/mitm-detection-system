# User manual

## Start the application

Follow the Windows setup in the repository README. Launch with `streamlit run app.py`; the app opens in a local browser. Stop it with Ctrl+C in the terminal.

## Navigation

- **Dashboard:** counts current windows and classification summaries.
- **Traffic Capture and Upload:** import a PCAP/PCAPNG or optionally make a short, explicitly authorised live capture.
- **Traffic Analysis:** inspect and download extracted features; compatible feature CSVs can also be loaded.
- **MITM Detection:** classify loaded windows with a locally saved model.
- **Model Training:** upload labelled feature data and train all three algorithms.
- **Model Evaluation:** inspect held-out test metrics, confusion matrices, inference time and model size.
- **Alerts and Reports:** inspect potential alerts and export CSV/text reports.
- **System Information:** local-use and ethical limitations.

## Capture preparation

Use Wireshark/TShark or another authorised capture tool. Save a PCAP or PCAPNG file. Avoid unrelated traffic and credentials. A capture should document time, lab topology, interfaces, experiment conditions and ground-truth label in an external experiment log. File names and label columns are not model features.

For live capture, select only a permitted interface, acknowledge authorisation and choose a brief duration. Live capture can fail without Npcap, appropriate interface support, or permission; PCAP upload is the supported fallback.

## Feature CSV format

A training file must contain these numeric features and a `label` column:

`arp_request_count`, `arp_reply_count`, `arp_unsolicited_reply_count`, `arp_conflicting_ip_count`, `arp_mapping_change_count`, `arp_packets_per_second`, `packet_count`, `average_packet_size`, `ipv4_fraction`, `ipv6_fraction`, `tcp_fraction`, `udp_fraction`, `icmp_fraction`, `dns_fraction`, `other_fraction`, `unique_source_macs`, `unique_destination_macs`.

Use label `0` / `Normal` or `1` / `MITM-associated`. Optionally include `capture_session` to request grouped splitting by independent capture. The label and session ID are not features. Do not combine feature CSVs with different feature definitions without conversion and documentation.

## Interpreting output

The model's class is **Normal** or **Potentially MITM-associated**. Confidence is shown only when the classifier exposes probability estimates; it is not a calibrated probability of a real attack. Indicator notes list selected ARP cues, not model explanations. Check the original traffic and lab context. A lack of alerts does not prove a network is safe.

Metrics are computed from the uploaded labelled data. Review class counts, partition sizes and split method. Record-level splits can overestimate performance when related windows from the same capture appear across partitions. Prefer many independent capture sessions and grouped splits. Synthetic demonstration rows are only for verifying the interface.

## Troubleshooting

- **Scapy import error:** activate the project virtual environment and reinstall `requirements.txt`.
- **Malformed/empty capture:** confirm the file is a supported PCAP/PCAPNG and opens in Wireshark.
- **Live capture unavailable:** use file-based analysis; check Npcap, interface names and OS privileges.
- **No saved model:** train from a labelled feature CSV first. Models are written under `models/` and are local generated artifacts.
- **Insufficient data for training:** provide both classes with enough observations to make all three partitions; independent capture sessions are strongly preferred.
- **Suspicious feature count but no alert:** features are combined by the learned model; thresholds are not a guarantee. Review training data and model evaluation.
