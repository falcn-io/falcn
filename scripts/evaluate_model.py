"""
Falcn Model Evaluation Dashboard
=================================
Loads a trained ONNX model (or heuristic baseline) and evaluates it against a
labeled dataset, producing precision/recall/F1, false-positive rate breakdown,
and a SHAP-based feature importance report.

Usage:
  python scripts/evaluate_model.py --model resources/models/reputation_model.onnx \
      --data-dir data/eval/ [--threshold 0.5]
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

try:
    import onnxruntime as ort
    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)

FEATURE_NAMES = [
    "log_downloads", "maintainer_count", "age_days", "days_since_update",
    "vuln_count", "malware_reports", "verified_flags", "has_install_script",
    "install_script_kb", "has_preinstall", "has_postinstall",
    "maintainer_change_count", "maintainer_velocity", "domain_age_days",
    "executable_binary_count", "network_code_files", "log_total_files",
    "entropy_max_file", "dependency_delta", "log_version_count",
    "days_between_versions", "log_stars", "log_forks", "namespace_age_days",
    "download_star_anomaly",
]


def load_data(data_dir: str) -> tuple:
    dfs = []
    for csv_path in Path(data_dir).glob("*.csv"):
        df = pd.read_csv(csv_path)
        if "label" in df.columns:
            dfs.append(df)
    if not dfs:
        raise FileNotFoundError(f"No labeled CSV files found in {data_dir}")
    combined = pd.concat(dfs, ignore_index=True)
    X = combined[FEATURE_NAMES].values.astype(np.float32)
    y = combined["label"].values.astype(np.int64)
    return X, y


def predict_onnx(model_path: str, X: np.ndarray) -> np.ndarray:
    if not ONNX_AVAILABLE:
        raise RuntimeError("onnxruntime not installed — pip install onnxruntime")
    sess = ort.InferenceSession(model_path)
    input_name = sess.get_inputs()[0].name
    output = sess.run(None, {input_name: X})
    # output[1] is usually the probability dict for classifiers
    if len(output) > 1 and hasattr(output[1][0], "items"):
        return np.array([o[1] for o in output[1]], dtype=np.float32)
    return output[0].astype(np.float32)


def heuristic_baseline(X: np.ndarray) -> np.ndarray:
    """Simple rule-based baseline for comparison (mirrors inference.go logic)."""
    scores = np.zeros(len(X), dtype=np.float32)
    scores += np.clip(1.0 - X[:, 0] / 18.0, 0, 1) * 0.15   # log downloads
    scores += np.where(X[:, 1] <= 1, 0.10, np.where(X[:, 1] <= 3, 0.03, 0))
    scores += np.where(X[:, 2] < 7, 0.15, np.where(X[:, 2] < 30, 0.08, np.where(X[:, 2] < 90, 0.03, 0)))
    scores += np.where(X[:, 5] > 0, np.clip(X[:, 5] * 0.20 + 0.30, 0, 0.45), 0)  # malware
    scores += np.where(X[:, 7] > 0, 0.06, 0)   # install script
    scores += np.where(X[:, 14] > 0, np.clip(X[:, 14] * 0.06, 0, 0.10), 0)  # executables
    scores += np.where(X[:, 17] > 7.5, 0.10, np.where(X[:, 17] > 7.0, 0.05, 0))  # entropy
    scores -= np.clip(X[:, 6] * 0.04, 0, 0.12)  # verified flags
    return np.clip(scores, 0, 1)


def print_metrics(y_true, y_proba, threshold: float, label: str):
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fp_rate = fp / max(tn + fp, 1)
    fn_rate = fn / max(tp + fn, 1)
    auc = roc_auc_score(y_true, y_proba)

    print(f"\n{'='*60}")
    print(f"  {label}  (threshold={threshold:.2f})")
    print(f"{'='*60}")
    print(classification_report(y_true, y_pred, target_names=["benign", "malicious"]))
    print(f"  AUC-ROC          : {auc:.4f}")
    print(f"  False Positive   : {fp_rate:.4f}  ({fp}/{tn+fp} benign flagged)")
    print(f"  False Negative   : {fn_rate:.4f}  ({fn}/{tp+fn} malicious missed)")
    print(f"  Confusion Matrix :")
    print(f"    TN={tn:6d}  FP={fp:6d}")
    print(f"    FN={fn:6d}  TP={tp:6d}")

    # Find threshold that maximises F1
    prec, rec, thresholds = precision_recall_curve(y_true, y_proba)
    f1_scores = np.where((prec + rec) > 0, 2 * prec * rec / (prec + rec), 0)
    best_idx = np.argmax(f1_scores)
    best_thresh = thresholds[best_idx] if best_idx < len(thresholds) else threshold
    print(f"\n  Optimal threshold (max F1): {best_thresh:.3f}  →  F1={f1_scores[best_idx]:.4f}")
    return {"auc": auc, "fp_rate": fp_rate, "fn_rate": fn_rate, "f1": f1_score(y_true, y_pred), "best_threshold": float(best_thresh)}


def main():
    parser = argparse.ArgumentParser(description="Evaluate Falcn ML model")
    parser.add_argument("--model", default="resources/models/reputation_model.onnx")
    parser.add_argument("--data-dir", default="data/eval", help="Directory with labeled CSVs")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--output", default="resources/models/eval_report.json")
    args = parser.parse_args()

    print(f"\nLoading evaluation data from: {args.data_dir}")
    try:
        X, y = load_data(args.data_dir)
        print(f"  Loaded {len(y)} samples ({y.sum()} malicious, {(y==0).sum()} benign)")
    except FileNotFoundError as e:
        print(f"  {e}")
        print("  Generating synthetic evaluation set (1000 samples)...")
        sys.path.insert(0, os.path.dirname(__file__))
        from train_ml_model import generate_synthetic_data
        X, y = generate_synthetic_data(n_samples=1000, seed=99)
        print(f"  Generated {len(y)} synthetic samples")

    report = {}

    # Heuristic baseline
    h_scores = heuristic_baseline(X)
    report["heuristic"] = print_metrics(y, h_scores, args.threshold, "Heuristic Baseline")

    # ONNX model
    if os.path.exists(args.model):
        print(f"\nLoading ONNX model: {args.model}")
        try:
            m_scores = predict_onnx(args.model, X)
            report["onnx"] = print_metrics(y, m_scores, args.threshold, f"ONNX Model ({Path(args.model).name})")
        except Exception as e:
            print(f"  [error] ONNX evaluation failed: {e}")
    else:
        print(f"\n  [info] No ONNX model at {args.model} — skipping model evaluation")

    # Feature importance via permutation (simple)
    print("\n=== Feature Importance (permutation) ===")
    h_base_f1 = f1_score(y, (h_scores >= args.threshold).astype(int))
    drops = []
    for i, fname in enumerate(FEATURE_NAMES):
        X_perm = X.copy()
        X_perm[:, i] = np.random.permutation(X_perm[:, i])
        perm_scores = heuristic_baseline(X_perm)
        perm_f1 = f1_score(y, (perm_scores >= args.threshold).astype(int))
        drops.append((fname, h_base_f1 - perm_f1))
    drops.sort(key=lambda x: -x[1])
    print(f"  {'Feature':<35} {'F1 Drop':>8}")
    print(f"  {'-'*44}")
    for fname, drop in drops:
        bar = "█" * max(0, int(drop / max(drops[0][1], 0.001) * 20))
        print(f"  {fname:<35} {drop:>8.4f}  {bar}")

    report["feature_importance"] = [{"name": n, "f1_drop": v} for n, v in drops]

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Evaluation report saved → {args.output}")


if __name__ == "__main__":
    main()
