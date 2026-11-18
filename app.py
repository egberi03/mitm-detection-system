import json
from pathlib import Path
import tempfile

import pandas as pd
import streamlit as st

from mitm_detector.features import FEATURE_COLUMNS
from mitm_detector.models import MODELS, classify, load_model, train_models
from mitm_detector.pcap import features_from_capture, features_from_packets
from mitm_detector.reports import summary_report

st.set_page_config(page_title="Local MITM Traffic Detector", page_icon="🛡️", layout="wide")
CONFIG = json.loads(Path("config.json").read_text(encoding="utf-8"))
MODEL_DIR = Path(CONFIG.get("model_directory", "models"))

st.title("🛡️ Local MITM Traffic Detector")
st.caption("Academic defensive prototype · ARP-spoofing indicators · All processing remains on this computer")

pages = ["Dashboard", "Traffic Capture and Upload", "Traffic Analysis", "MITM Detection", "Model Training", "Model Evaluation", "Alerts and Reports", "System Information"]
page = st.sidebar.radio("Navigation", pages)
st.sidebar.info("Detection alerts are indicators, not proof. Only analyse captures and interfaces you are authorised to monitor.")
selected_model = st.sidebar.selectbox("Model selected", MODELS)

if "features" not in st.session_state: st.session_state.features = pd.DataFrame()
if "results" not in st.session_state: st.session_state.results = pd.DataFrame()
if "source" not in st.session_state: st.session_state.source = "No input loaded"


def ready_model():
    try:
        return load_model(selected_model, MODEL_DIR)
    except (FileNotFoundError, ValueError) as exc:
        st.warning(str(exc))
        return None


def run_detection():
    if st.session_state.features.empty:
        st.warning("Load a capture or feature CSV first.")
        return
    artifact = ready_model()
    if artifact:
        st.session_state.results = classify(st.session_state.features, artifact)
        st.success(f"Classified {len(st.session_state.results)} traffic windows using {selected_model}.")

if page == "Dashboard":
    st.subheader("Analysis overview")
    result = st.session_state.results
    total = len(result) if not result.empty else len(st.session_state.features)
    normal = int((result.get("prediction", pd.Series(dtype=int)) == 0).sum()) if not result.empty else 0
    suspicious = int((result.get("prediction", pd.Series(dtype=int)) == 1).sum()) if not result.empty else 0
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Traffic windows", total); c2.metric("Normal", normal); c3.metric("Potentially suspicious", suspicious)
    c4.metric("Detection percentage", f"{(100*suspicious/len(result)):.1f}%" if not result.empty else "—")
    if not st.session_state.features.empty:
        d = st.session_state.features
        arp_req = int(d["arp_request_count"].sum()); arp_rep = int(d["arp_reply_count"].sum())
        conflicts = int(d["arp_conflicting_ip_count"].sum())
        a, b, c = st.columns(3); a.metric("ARP requests", arp_req); b.metric("ARP replies", arp_rep); c.metric("Windows with mapping conflicts", conflicts)
        st.caption(f"Input: {st.session_state.source}")
    else:
        st.info("No traffic loaded yet. Visit Traffic Capture and Upload to analyse a local capture.")
    if not result.empty:
        st.markdown("#### Recent detection alerts")
        st.dataframe(result[result.prediction == 1].tail(10), use_container_width=True)
    st.write(f"Currently selected model: **{selected_model}**")

elif page == "Traffic Capture and Upload":
    st.subheader("Import capture or inspect an authorised interface")
    uploaded = st.file_uploader("Upload PCAP or PCAPNG", type=["pcap", "pcapng", "cap"])
    window = st.number_input("Aggregation window (seconds)", min_value=1, max_value=300, value=int(CONFIG.get("window_seconds", 10)))
    if uploaded and st.button("Process capture file"):
        suffix = Path(uploaded.name).suffix or ".pcap"
        try:
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as handle:
                handle.write(uploaded.getvalue()); temp_path = handle.name
            try:
                features = features_from_capture(temp_path, int(window))
            finally:
                Path(temp_path).unlink(missing_ok=True)
            st.session_state.features = features
            st.session_state.results = pd.DataFrame()
            st.session_state.source = f"Uploaded capture: {uploaded.name}"
            st.success(f"Parsed capture into {len(features)} traffic windows.")
        except Exception as exc:
            st.error(f"Capture processing failed: {exc}")
    st.markdown("#### Live capture (optional)")
    st.warning("Live capture may require Npcap and elevated permissions on Windows. Capture only an interface and traffic you are authorised to monitor. No traffic is transmitted or modified by this application.")
    consent = st.checkbox("I am authorised to monitor this interface and understand this captures traffic locally.")
    try:
        from scapy.all import get_if_list, sniff
        interfaces = get_if_list()
    except Exception:
        interfaces = []
    interface = st.selectbox("Network interface", interfaces) if interfaces else None
    duration = st.number_input("Capture duration (seconds)", min_value=1, max_value=60, value=10)
    if st.button("Start bounded live capture", disabled=not (consent and interface)):
        try:
            from scapy.all import sniff
            with st.spinner(f"Capturing on {interface} for up to {duration} seconds…"):
                packets = sniff(iface=interface, timeout=int(duration), store=True)
            live_features = features_from_packets(packets, int(window))
            st.session_state.features = live_features
            st.session_state.results = pd.DataFrame()
            st.session_state.source = f"Live interface capture: {interface}"
            st.success(f"Captured {len(packets)} packets; aggregated into {len(live_features)} windows.")
        except Exception as exc:
            st.error(f"Live capture unavailable: {exc}. Use PCAP upload instead.")

elif page == "Traffic Analysis":
    st.subheader("Extracted traffic observations")
    st.caption("Features are aggregated into fixed windows. Mapping conflicts and unsolicited replies are heuristics, not definitive attack labels.")
    if not st.session_state.features.empty:
        st.dataframe(st.session_state.features, use_container_width=True)
        st.download_button("Download extracted features (CSV)", st.session_state.features.to_csv(index=False), "traffic_features.csv", "text/csv")
    st.markdown("#### Import labelled or compatible feature CSV")
    csv_file = st.file_uploader("Feature CSV (required columns are listed below)", type=["csv"], key="feature_csv")
    st.code(", ".join(FEATURE_COLUMNS), language="text")
    if csv_file and st.button("Load feature CSV"):
        try:
            loaded = pd.read_csv(csv_file)
            missing = [c for c in FEATURE_COLUMNS if c not in loaded.columns]
            if missing: raise ValueError("Missing feature columns: " + ", ".join(missing))
            st.session_state.features = loaded
            st.session_state.results = pd.DataFrame()
            st.session_state.source = f"Feature CSV: {csv_file.name}"
            st.success(f"Loaded {len(loaded)} observations.")
        except Exception as exc: st.error(str(exc))

elif page == "MITM Detection":
    st.subheader("Classify loaded traffic")
    st.write("Every prediction is advisory. Investigate the original capture and context before drawing conclusions.")
    if st.button("Run detection"): run_detection()
    if not st.session_state.results.empty: st.dataframe(st.session_state.results, use_container_width=True)

elif page == "Model Training":
    st.subheader("Train and save the three classifiers")
    st.markdown("Provide labelled feature rows with `label` values 0 (Normal) or 1 (MITM-associated). Add `capture_session` to prefer splitting independent capture sessions. Filenames and labels are never model features.")
    training_file = st.file_uploader("Upload labelled feature dataset CSV", type=["csv"], key="training_csv")
    if training_file:
        try:
            training_data = pd.read_csv(training_file)
            st.write(f"Rows: {len(training_data)} · Columns: {len(training_data.columns)}")
            if "label" in training_data: st.write("Label counts", training_data.label.astype(str).value_counts().rename_axis("label").to_frame("count"))
            if st.button("Train Random Forest, Decision Tree, and SVM"):
                with st.spinner("Training and evaluating on held-out partitions…"):
                    report = train_models(training_data, MODEL_DIR)
                st.session_state.training_report = report
                st.success("All models trained and saved locally. Test metrics use the held-out test partition.")
        except Exception as exc: st.error(f"Training failed: {exc}")
    if "training_report" in st.session_state:
        rep = st.session_state.training_report
        st.write("Split strategy:", rep["split_method"])
        st.write("Partition counts:", rep["partition_counts"])
        st.dataframe(pd.DataFrame({name: {"Test accuracy": info["test"]["accuracy"], "Test precision": info["test"]["precision"], "Test recall": info["test"]["recall"], "Test F1": info["test"]["f1"]} for name, info in rep["models"].items()}).T)

elif page == "Model Evaluation":
    st.subheader("Held-out model comparison")
    report = st.session_state.get("training_report")
    if report:
        rows = []
        for name, info in report["models"].items():
            m = info["test"]
            rows.append({"Model": name, "Accuracy": m["accuracy"], "Precision": m["precision"], "Recall": m["recall"], "F1": m["f1"], "False-positive rate": m["false_positive_rate"], "Inference sec/row": m["inference_seconds_per_observation"], "Size (bytes)": info["model_size_bytes"]})
        metrics = pd.DataFrame(rows).set_index("Model")
        st.dataframe(metrics.style.format("{:.4f}"), use_container_width=True)
        st.bar_chart(metrics[["Accuracy", "Precision", "Recall", "F1", "False-positive rate"]])
        for name, info in report["models"].items():
            with st.expander(f"{name} — confusion matrix (test)"):
                st.write("Rows = actual [Normal, MITM-associated], columns = predicted [Normal, MITM-associated]")
                st.dataframe(pd.DataFrame(info["test"]["confusion_matrix"], index=["Actual normal", "Actual MITM"], columns=["Predicted normal", "Predicted MITM"]))
                st.caption(f"Training time: {info['training_seconds']:.4f}s · Model size: {info['model_size_bytes']} bytes")
        st.caption(f"Partition method: {report['split_method']}. Results are calculated from the uploaded labelled data; do not treat demonstration data as experimental evidence.")
    else: st.info("Train models on a labelled dataset to calculate actual evaluation metrics.")

elif page == "Alerts and Reports":
    st.subheader("Alerts and export")
    results = st.session_state.results
    if not results.empty:
        alerts = results[results.prediction == 1]
        st.metric("Potentially suspicious windows", len(alerts))
        st.dataframe(alerts, use_container_width=True)
        st.download_button("Export all classifications to CSV", results.to_csv(index=False), "mitm_analysis_results.csv", "text/csv")
        try: report_text = summary_report(results, selected_model, st.session_state.source)
        except ValueError as exc: st.error(str(exc))
        else: st.download_button("Download summary report", report_text, "analysis_report.txt", "text/plain")
    else: st.info("Run detection to populate alerts and reports.")

else:
    st.subheader("System information and ethical use")
    st.write("This is a local academic detection prototype for analysing authorised traffic, with a focus on ARP-spoofing-associated indicators.")
    st.write(f"Python: {__import__('sys').version.split()[0]} · Model directory: `{MODEL_DIR}` · Window: {CONFIG.get('window_seconds', 10)} seconds")
    st.markdown("- No cloud service or remote API is used.\n- No attack traffic is generated.\n- No packets are blocked and no network settings are changed.\n- Do not capture unrelated private traffic.\n- A model alert is not conclusive proof of an attack.")
    st.markdown("For architecture, installation, Windows Npcap guidance, experimental procedure, and limitations, see `README.md`, `docs/USER_MANUAL.md`, and `docs/DEVELOPER.md`.")
