# Developer notes

## Architecture

`app.py` is the Streamlit presentation layer. Both uploaded files and optional bounded live capture pass Scapy packet objects to `mitm_detector.features.packets_to_features`. The resulting fixed schema is shared by training and inference. `pcap.py` streams capture records via Scapy's `PcapReader` then invokes that extractor. `models.py` owns label validation, feature selection, splitting, estimators, metrics, Joblib artifacts and inference. `reports.py` builds export text.

The fixed features are counts/rates and selected protocol proportions per time window, plus metadata summaries. Model input is restricted to `FEATURE_COLUMNS`; timestamps, source/destination summaries, labels, session identifiers and filenames are excluded. SVM is a Scikit-learn Pipeline with `StandardScaler` fitted only during `.fit()` on the training partition.

## Algorithms and evaluation

- Random Forest: 150 trees, balanced class weighting, fixed random seed.
- Decision Tree: balanced class weighting and fixed random seed.
- SVM: RBF kernel, scaled features, probability estimation and balanced class weighting.

No model is presumed best and no hyperparameter search is performed. Every estimator is evaluated on validation and test partitions, but only test metrics should be cited as held-out performance. Session grouping is preferred if `capture_session` has sufficient independent groups and every partition can contain both classes. Otherwise the transparent fallback is stratified row splitting. The training report stores partition counts and method.

False-positive rate is FP/(FP+TN). Confusion matrices use label order 0, 1. Inference timing includes prediction for the partition in the current process and should be interpreted as a simple measurement, not a benchmark. Serialized artifact size is reported in bytes.

## Feature semantics and caveats

Unsolicited ARP reply means the sender protocol address was not previously observed as a request target in the processed capture. This approximation is sensitive to truncated captures, request/reply ordering and ARP cache activity. Mapping change compares observed sender IP/MAC pairs within one capture. A conflict is multiple sender MACs for one sender IP within one window. None alone implies malicious activity. Protocol fractions overlap because transport and network layers are counted independently; `other_fraction` is a residual and does not mean mutually exclusive protocol buckets.

## Local development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
streamlit run app.py
```

Generated models are runtime artifacts under `models/`; do not commit real packet captures, sensitive traffic, or trained artifacts that embed sensitive data. Test fixtures generate packets in memory and do not transmit.

## Research validity

For an undergraduate evaluation, maintain a capture manifest with session IDs, date, topology, capture location, label source, packet/capture quality and any exclusions. Keep session IDs disjoint across partitions. Ideally collect multiple independent sessions per class and use a final untouched test set. Report class balance, split method, limitations and false positives. Do not present synthetic rows or a demo run as experimental results.
