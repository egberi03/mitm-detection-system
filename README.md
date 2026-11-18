# MITM Traffic Detector — local academic prototype

A defensive, local-only Streamlit application that extracts windowed traffic features from PCAP/PCAPNG captures and compares Random Forest, Decision Tree and SVM models. Its focus is **detecting indicators associated with ARP-spoofing-based MITM activity** in traffic the operator is authorised to inspect. It does not generate attacks, block hosts, or change network settings.

> Alerts are indicators for investigation, not proof of an attack. Demonstration data is synthetic and is not experimental evidence.

## Features

- PCAP/PCAPNG import through Scapy; live capture is optional and permission-dependent.
- Shared windowed packet feature extraction for offline and live traffic.
- Three supervised classifiers; SVM uses a training-fitted scaler in a Pipeline.
- Train/validation/test partitions; when capture-session identifiers permit, grouped splitting avoids placing one capture session in multiple partitions.
- Held-out metrics: accuracy, precision, recall, F1, false-positive rate, confusion matrix, inference time and serialized model size.
- Local Joblib model storage, classification, alert table, CSV export and text summary.
- Unit tests for extraction, parsing, invalid inputs, model persistence, classification and reporting.

## Windows 11 setup

1. Install Python 3.10+ and VS Code. During Python setup, enable **Add Python to PATH**.
2. Install Npcap only if live capture or Wireshark capture is needed. Use the official Npcap installer and select WinPcap API-compatible mode if required by your environment. Wireshark/TShark are optional for inspecting captures; the app reads PCAP/PCAPNG with Scapy.
3. In PowerShell, from the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local address printed by Streamlit (normally `http://localhost:8501`). Processing stays on the computer. Do not expose Streamlit to an untrusted network.

## Using captures

- Capture traffic using Wireshark on a permitted interface: choose **Capture → Start**, reproduce only benign/approved lab traffic, stop capture, and save as PCAPNG or PCAP.
- In **Traffic Capture and Upload**, select the file and process it. Choose a window duration (default 10 seconds). The result is a row per time window.
- Optional live capture is bounded to 60 seconds and requires explicit authorisation acknowledgement. On Windows, Npcap and suitable privileges may be needed. If unavailable, use file import.
- Packet capture is not a MITM test by itself. Use a documented, isolated VirtualBox internal/host-only lab and separately record the experiment labels and capture sessions. This software never launches an attack.

## Train and evaluate

Prepare a CSV with all columns listed in the **Traffic Analysis** page plus `label`. Labels are `0`/`Normal` or `1`/`MITM-associated`. The app ignores metadata, labels, filenames, and any extra columns when fitting. Include a `capture_session` column with an independent session identifier for grouped split preference. Use multiple independent normal and controlled-lab capture sessions; do not label solely from a filename. In **Model Training**, upload the CSV and train all models. **Model Evaluation** reports metrics on a held-out test partition and shows partition counts/splitting method. The validation partition is separate; this starter implementation does not tune hyperparameters.

A minimum of 10 rows is recommended, but meaningful evaluation needs substantially more independent sessions and examples of both classes. If there are too few independent sessions to represent both classes, the application reports and uses a stratified record-level split; this is weaker evidence and must be disclosed. Do not report synthetic demo metrics as research findings.

## Synthetic demonstration data

`data/demo_features.csv` contains explicitly synthetic, hand-created feature rows for interface smoke-testing only. It is not packet-derived, not representative, and not suitable for claims of detection performance.

## Tests

```powershell
pytest -q
```

Tests use generated in-memory Scapy packets and temporary local files; they do not send packets or require a network interface.

## Project layout

```text
app.py                     Streamlit UI
mitm_detector/features.py  Shared packet/window feature extraction
mitm_detector/pcap.py      Offline capture loading
mitm_detector/models.py    Splitting, training, metrics, persistence, inference
mitm_detector/reports.py   Text report generation
config.json                Sample local configuration
models/                    Local generated models (not committed)
data/                      Clearly labelled demonstration data
tests/                     Automated tests
docs/                      User and developer manuals
```

## Limitations

ARP behaviours vary in normal networks; replies without an observed request can occur legitimately, and packet loss/partial captures affect the features. Features are aggregated and do not establish causal relationships. Dataset shift, class imbalance, capture-session leakage, label quality and small sample sizes can invalidate results. The prototype is not an inline IDS, packet blocker, forensic chain-of-custody tool, or production security control.
