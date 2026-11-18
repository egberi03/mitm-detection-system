"""Training, evaluation, persistence, and inference for labelled features."""
from __future__ import annotations
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from .features import FEATURE_COLUMNS

MODELS = ("Random Forest", "Decision Tree", "SVM")
MODEL_FILES = {"Random Forest": "random_forest.joblib", "Decision Tree": "decision_tree.joblib", "SVM": "svm.joblib"}
LABEL_MAP = {"0": 0, "normal": 0, "normal traffic": 0, "1": 1,
             "mitm": 1, "mitm-associated": 1, "potentially mitm-associated": 1, "attack": 1}


def normalize_labels(values: pd.Series) -> pd.Series:
    def convert(value: Any) -> int:
        key = str(value).strip().lower()
        if key not in LABEL_MAP:
            raise ValueError(f"Unsupported label {value!r}; use Normal/0 or MITM-associated/1.")
        return LABEL_MAP[key]
    return values.map(convert).astype(int)


def _split_data(X, y, groups=None):
    """Create train/validation/test splits; prefer independent capture groups."""
    if groups is not None and pd.Series(groups).nunique() >= 3:
        groups = np.asarray(groups)
        for seed in range(30):
            try:
                outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
                train_val_idx, test_idx = next(outer.split(X, y, groups))
                inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 100)
                relative_train, relative_val = next(inner.split(X.iloc[train_val_idx], y.iloc[train_val_idx], groups[train_val_idx]))
                train_idx, val_idx = train_val_idx[relative_train], train_val_idx[relative_val]
                if all(set(y.iloc[idx].unique()) == {0, 1} for idx in (train_idx, val_idx, test_idx)):
                    return train_idx, val_idx, test_idx, "capture-session grouped split"
            except (ValueError, StopIteration):
                pass
        # When sessions cannot represent both labels independently, fall back
        # transparently to a stratified record split and report the limitation.
    try:
        train_val_idx, test_idx = train_test_split(np.arange(len(y)), test_size=0.2, random_state=42, stratify=y)
        train_idx, val_idx = train_test_split(train_val_idx, test_size=0.25, random_state=43, stratify=y.iloc[train_val_idx])
    except ValueError as exc:
        raise ValueError("Need enough examples of both labels to create stratified train/validation/test partitions (at least 10 rows recommended).") from exc
    return np.asarray(train_idx), np.asarray(val_idx), np.asarray(test_idx), "stratified record split (no adequate independent session split)"


def _metrics(model, X, y):
    started = time.perf_counter()
    prediction = model.predict(X)
    elapsed = time.perf_counter() - started
    tn, fp, fn, tp = confusion_matrix(y, prediction, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, prediction)),
        "precision": float(precision_score(y, prediction, zero_division=0)),
        "recall": float(recall_score(y, prediction, zero_division=0)),
        "f1": float(f1_score(y, prediction, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "inference_seconds": float(elapsed),
        "inference_seconds_per_observation": float(elapsed / max(1, len(y))),
    }


def train_models(data: pd.DataFrame, model_dir: str | Path = "models") -> dict[str, Any]:
    """Train all three models; report validation and held-out test results."""
    if "label" not in data.columns:
        raise ValueError("Training CSV must include a 'label' column (0/1 or supported text label).")
    missing = [c for c in FEATURE_COLUMNS if c not in data.columns]
    if missing:
        raise ValueError("Missing required feature columns: " + ", ".join(missing))
    clean = data[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    labels = normalize_labels(data["label"])
    valid = clean.replace([np.inf, -np.inf], np.nan).notna().all(axis=1)
    clean, labels = clean.loc[valid].reset_index(drop=True), labels.loc[valid].reset_index(drop=True)
    if labels.nunique() != 2:
        raise ValueError("Training data must contain both Normal (0) and MITM-associated (1) labels.")
    groups = data.loc[valid, "capture_session"].reset_index(drop=True) if "capture_session" in data.columns else None
    train_idx, val_idx, test_idx, split_method = _split_data(clean, labels, groups)
    X_train, y_train = clean.iloc[train_idx], labels.iloc[train_idx]
    X_val, y_val = clean.iloc[val_idx], labels.iloc[val_idx]
    X_test, y_test = clean.iloc[test_idx], labels.iloc[test_idx]

    factories = {
        "Random Forest": lambda: RandomForestClassifier(n_estimators=150, random_state=42, class_weight="balanced"),
        "Decision Tree": lambda: DecisionTreeClassifier(random_state=42, class_weight="balanced"),
        "SVM": lambda: Pipeline([("scaler", StandardScaler()), ("classifier", SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=42))]),
    }
    directory = Path(model_dir)
    directory.mkdir(parents=True, exist_ok=True)
    results = {}
    for name in MODELS:
        model = factories[name]()
        started = time.perf_counter()
        model.fit(X_train, y_train)
        training_seconds = time.perf_counter() - started
        validation_metrics = _metrics(model, X_val, y_val)
        test_metrics = _metrics(model, X_test, y_test)
        artifact = {"model": model, "model_name": name, "feature_columns": FEATURE_COLUMNS,
                    "trained_at": pd.Timestamp.now(tz="UTC").isoformat(), "split_method": split_method}
        path = directory / MODEL_FILES[name]
        joblib.dump(artifact, path)
        results[name] = {"validation": validation_metrics, "test": test_metrics,
                         "training_seconds": training_seconds, "model_size_bytes": path.stat().st_size,
                         "model_path": str(path)}
    return {"models": results, "split_method": split_method,
            "partition_counts": {"train": len(train_idx), "validation": len(val_idx), "test": len(test_idx)},
            "total_rows": len(clean), "invalid_rows_dropped": int(len(data) - len(clean))}


def load_model(name: str, model_dir: str | Path = "models") -> dict[str, Any]:
    if name not in MODEL_FILES:
        raise ValueError(f"Unknown model: {name}")
    path = Path(model_dir) / MODEL_FILES[name]
    if not path.is_file():
        raise FileNotFoundError(f"Trained model not found: {path}. Train models first.")
    artifact = joblib.load(path)
    if artifact.get("feature_columns") != FEATURE_COLUMNS:
        raise ValueError("Model feature schema does not match this application version.")
    return artifact


def classify(data: pd.DataFrame, artifact: dict[str, Any]) -> pd.DataFrame:
    missing = [c for c in FEATURE_COLUMNS if c not in data.columns]
    if missing:
        raise ValueError("Missing required features: " + ", ".join(missing))
    X = data[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)
    model = artifact["model"]
    output = data.copy()
    output["prediction"] = model.predict(X).astype(int)
    output["classification"] = output["prediction"].map({0: "Normal", 1: "Potentially MITM-associated"})
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)
        output["confidence"] = probabilities.max(axis=1)
    else:
        output["confidence"] = np.nan
    def explain(row):
        cues = []
        for col, label in (("arp_unsolicited_reply_count", "ARP reply without an earlier matching request"),
                           ("arp_conflicting_ip_count", "conflicting IP-to-MAC mapping"),
                           ("arp_mapping_change_count", "IP-to-MAC mapping change")):
            try:
                if float(row.get(col, 0) or 0) > 0: cues.append(label)
            except (TypeError, ValueError): pass
        return "; ".join(cues) if cues else "No listed ARP heuristic triggered; model uses combined traffic features."
    output["indicator_notes"] = output.apply(explain, axis=1)
    return output
