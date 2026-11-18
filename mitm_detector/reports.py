"""CSV and plain-text report helpers."""
from __future__ import annotations
from datetime import datetime, timezone
import pandas as pd


def summary_report(results: pd.DataFrame, model_name: str, source: str) -> str:
    if results.empty:
        raise ValueError("There are no analysis results to report.")
    suspicious = int((results.get("prediction", pd.Series(dtype=int)) == 1).sum())
    normal = int((results.get("prediction", pd.Series(dtype=int)) == 0).sum())
    return "\n".join([
        "MITM Traffic Analysis — Academic Prototype Report",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"Input source: {source}", f"Selected model: {model_name}",
        f"Traffic windows analysed: {len(results)}", f"Normal classifications: {normal}",
        f"Potentially MITM-associated classifications: {suspicious}",
        "Interpretation: alerts are indicators for investigation, not proof of an attack.",
        "This report contains model predictions only; it is not an independent experiment result."
    ])
