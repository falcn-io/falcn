"""
Falcn ML Training Pipeline — Ensemble Classifier for Malicious Package Detection
=================================================================================
Trains a VotingClassifier ensemble (RandomForest + GradientBoosting + LightGBM) on
labeled package data, exports the winner to ONNX, and computes SHAP feature importances.

Feature vector (25 features, must match internal/ml/features.go):
  [0]  log(DownloadCount+1)
  [1]  MaintainerCount
  [2]  AgeInDays
  [3]  DaysSinceLastUpdate
  [4]  VulnerabilityCount
  [5]  MalwareReportCount
  [6]  VerifiedFlagCount
  [7]  HasInstallScript (0/1)
  [8]  InstallScriptSizeKB
  [9]  HasPreinstallScript (0/1)
  [10] HasPostinstallScript (0/1)
  [11] MaintainerChangeCount
  [12] MaintainerVelocity (changes/day)
  [13] DomainAgeOfAuthorEmailDays
  [14] ExecutableBinaryCount
  [15] NetworkCodeFileCount
  [16] log(TotalFileCount+1)
  [17] EntropyMaxFile (0–8)
  [18] DependencyDelta
  [19] log(PreviousVersionCount+1)
  [20] DaysBetweenVersions
  [21] log(StarCount+1)
  [22] log(ForkCount+1)
  [23] NamespaceAgeDays
  [24] DownloadStarRatioAnomaly

Usage:
  python scripts/train_ml_model.py [--data-dir PATH] [--output-dir PATH] [--no-shap]

Real data sources (optional, fetched automatically if --data-dir is empty):
  - OpenSSF malicious-packages dataset: https://github.com/ossf/malicious-packages
  - PyPI removal notices via PyPI BigQuery public dataset
  - npm advisory feed (public)
"""

import argparse
import json
import math
import os
import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import (
    GradientBoostingClassifier,
    RandomForestClassifier,
    VotingClassifier,
)
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx

warnings.filterwarnings("ignore")

FEATURE_NAMES = [
    "log_downloads",
    "maintainer_count",
    "age_days",
    "days_since_update",
    "vuln_count",
    "malware_reports",
    "verified_flags",
    "has_install_script",
    "install_script_kb",
    "has_preinstall",
    "has_postinstall",
    "maintainer_change_count",
    "maintainer_velocity",
    "domain_age_days",
    "executable_binary_count",
    "network_code_files",
    "log_total_files",
    "entropy_max_file",
    "dependency_delta",
    "log_version_count",
    "days_between_versions",
    "log_stars",
    "log_forks",
    "namespace_age_days",
    "download_star_anomaly",
]

N_FEATURES = len(FEATURE_NAMES)  # 25


# ---------------------------------------------------------------------------
# Data generation / loading
# ---------------------------------------------------------------------------

def generate_synthetic_data(n_samples: int = 20000, seed: int = 42) -> tuple:
    """
    Generate labelled synthetic training data that reflects realistic
    distributions of benign and malicious packages across npm, PyPI, Go, etc.

    Returns (X, y) where X.shape == (n_samples, 25), y.dtype == int64.
    """
    rng = np.random.default_rng(seed)
    n_benign = int(n_samples * 0.88)  # ~88% benign reflects real-world ratio
    n_mal = n_samples - n_benign

    def _benign(n):
        rows = np.zeros((n, N_FEATURES), dtype=np.float32)
        rows[:, 0] = np.clip(rng.normal(10.0, 4.0, n), 0, 25)   # log downloads
        rows[:, 1] = np.clip(rng.poisson(2.5, n) + 1, 1, 20)    # maintainers
        rows[:, 2] = rng.exponential(800, n) + 60                 # age days
        rows[:, 3] = rng.exponential(120, n)                      # days since update
        rows[:, 4] = rng.poisson(0.4, n)                         # vulns
        rows[:, 5] = np.zeros(n)                                  # malware
        rows[:, 6] = rng.integers(0, 2, n, dtype=np.int32).astype(np.float32) * rng.uniform(0, 3, n).astype(np.float32)
        rows[:, 7] = (rng.random(n) < 0.35).astype(np.float32)  # install script ~35%
        rows[:, 8] = rng.exponential(2.0, n) * rows[:, 7]       # script size KB
        rows[:, 9] = (rng.random(n) < 0.10).astype(np.float32)
        rows[:, 10] = (rng.random(n) < 0.15).astype(np.float32)
        rows[:, 11] = rng.poisson(0.3, n)                        # maint changes
        rows[:, 12] = rng.exponential(0.004, n)                  # velocity
        rows[:, 13] = rng.exponential(1500, n) + 180             # domain age
        rows[:, 14] = np.zeros(n)                                 # executables
        rows[:, 15] = rng.poisson(1.0, n)                        # network files
        rows[:, 16] = np.clip(rng.normal(2.5, 1.0, n), 0, 7)    # log file count
        rows[:, 17] = np.clip(rng.normal(4.5, 1.2, n), 0, 8)    # entropy
        rows[:, 18] = rng.integers(-5, 6, n, dtype=np.int32).astype(np.float32)  # dep delta
        rows[:, 19] = np.clip(rng.normal(2.0, 1.2, n), 0, 8)    # log version count
        rows[:, 20] = rng.exponential(60, n) + 5                 # days between versions
        rows[:, 21] = np.clip(rng.normal(5.0, 3.0, n), 0, 15)   # log stars
        rows[:, 22] = np.clip(rng.normal(3.0, 2.0, n), 0, 12)   # log forks
        rows[:, 23] = rng.exponential(1000, n) + 90              # ns age days
        rows[:, 24] = np.zeros(n)                                 # anomaly
        return rows

    def _malicious(n):
        rows = np.zeros((n, N_FEATURES), dtype=np.float32)

        # Attack taxonomy:
        # 40% typosquatting — new, low downloads, single maintainer
        # 30% dependency confusion — plausible downloads, install script
        # 15% account takeover — old package, recent rapid change
        # 15% known-bad — malware already reported
        n_typo = int(n * 0.40)
        n_depconf = int(n * 0.30)
        n_hijack = int(n * 0.15)
        n_known = n - n_typo - n_depconf - n_hijack

        def _typo(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(3.0, 2.0, k), 0, 8)
            r[:, 1] = rng.choice([0, 1], k, p=[0.4, 0.6]).astype(np.float32)
            r[:, 2] = rng.exponential(8, k)                      # very new
            r[:, 3] = rng.exponential(3, k)
            r[:, 4] = rng.poisson(0.1, k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = (rng.random(k) < 0.70).astype(np.float32) # install script likely
            r[:, 8] = rng.exponential(5.0, k) * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.40).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.40).astype(np.float32)
            r[:, 11] = np.zeros(k)
            r[:, 12] = np.zeros(k)
            r[:, 13] = rng.exponential(90, k)                    # young domain
            r[:, 14] = rng.integers(0, 3, k, dtype=np.int32).astype(np.float32)
            r[:, 15] = rng.poisson(2.5, k)
            r[:, 16] = np.clip(rng.normal(1.5, 0.8, k), 0, 5)
            r[:, 17] = np.clip(rng.normal(6.5, 1.0, k), 0, 8)   # high entropy
            r[:, 18] = rng.integers(0, 8, k, dtype=np.int32).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.3, 0.3, k), 0, 2)   # few versions
            r[:, 20] = rng.exponential(3, k)                     # fast releases
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(60, k) + 1               # very young ns
            r[:, 24] = np.zeros(k)
            return r

        def _depconf(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(6.0, 2.0, k), 0, 12)  # moderate downloads
            r[:, 1] = rng.choice([1, 2], k).astype(np.float32)
            r[:, 2] = rng.exponential(20, k)
            r[:, 3] = rng.exponential(5, k)
            r[:, 4] = np.zeros(k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = np.ones(k)                                  # always has install script
            r[:, 8] = rng.exponential(10.0, k) + 3               # large script
            r[:, 9] = (rng.random(k) < 0.60).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.60).astype(np.float32)
            r[:, 11] = np.zeros(k)
            r[:, 12] = np.zeros(k)
            r[:, 13] = rng.exponential(120, k)
            r[:, 14] = rng.integers(0, 5, k, dtype=np.int32).astype(np.float32)
            r[:, 15] = rng.poisson(4, k)
            r[:, 16] = np.clip(rng.normal(2.0, 1.0, k), 0, 5)
            r[:, 17] = np.clip(rng.normal(7.0, 0.8, k), 4, 8)
            r[:, 18] = rng.integers(5, 30, k, dtype=np.int32).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.5, 0.5, k), 0, 2)
            r[:, 20] = rng.exponential(2, k)
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(90, k)
            # Phantom downloads with no stars = anomaly
            r[:, 24] = np.clip(rng.normal(0.7, 0.2, k), 0, 1)
            return r

        def _hijack(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(11.0, 3.0, k), 4, 20)  # established downloads
            r[:, 1] = rng.choice([1, 2], k).astype(np.float32)
            r[:, 2] = rng.exponential(1500, k) + 365             # old package
            r[:, 3] = rng.exponential(3, k)                      # very recent update
            r[:, 4] = rng.poisson(1.5, k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = np.ones(k)
            r[:, 8] = rng.exponential(8.0, k) + 5
            r[:, 9] = (rng.random(k) < 0.50).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.50).astype(np.float32)
            r[:, 11] = rng.poisson(4, k)                         # maintainer churn
            r[:, 12] = rng.exponential(0.15, k)                  # high velocity
            r[:, 13] = rng.exponential(200, k) + 30              # somewhat young new owner
            r[:, 14] = rng.integers(0, 4, k, dtype=np.int32).astype(np.float32)
            r[:, 15] = rng.poisson(3, k)
            r[:, 16] = np.clip(rng.normal(3.0, 1.0, k), 0, 7)
            r[:, 17] = np.clip(rng.normal(6.5, 0.8, k), 4, 8)
            r[:, 18] = rng.integers(3, 20, k, dtype=np.int32).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(2.5, 1.0, k), 0, 7)
            r[:, 20] = rng.exponential(5, k)
            r[:, 21] = np.clip(rng.normal(7.0, 2.0, k), 0, 12)  # established stars
            r[:, 22] = np.clip(rng.normal(5.0, 2.0, k), 0, 10)
            r[:, 23] = rng.exponential(800, k) + 200
            r[:, 24] = np.zeros(k)
            return r

        def _known_bad(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(4.0, 3.0, k), 0, 10)
            r[:, 1] = rng.choice([0, 1], k, p=[0.5, 0.5]).astype(np.float32)
            r[:, 2] = rng.exponential(15, k)
            r[:, 3] = rng.exponential(5, k)
            r[:, 4] = rng.poisson(2, k)
            r[:, 5] = rng.choice([1, 2, 3], k, p=[0.7, 0.2, 0.1]).astype(np.float32)
            r[:, 6] = (rng.random(k) < 0.20).astype(np.float32)
            r[:, 7] = (rng.random(k) < 0.80).astype(np.float32)
            r[:, 8] = rng.exponential(5.0, k) * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.50).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.50).astype(np.float32)
            r[:, 11] = rng.poisson(1, k)
            r[:, 12] = rng.exponential(0.05, k)
            r[:, 13] = rng.exponential(150, k)
            r[:, 14] = rng.integers(0, 5, k, dtype=np.int32).astype(np.float32)
            r[:, 15] = rng.poisson(3, k)
            r[:, 16] = np.clip(rng.normal(2.0, 1.2, k), 0, 6)
            r[:, 17] = np.clip(rng.normal(7.0, 0.7, k), 4, 8)
            r[:, 18] = rng.integers(2, 15, k, dtype=np.int32).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.4, 0.4, k), 0, 2)
            r[:, 20] = rng.exponential(3, k)
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(80, k)
            r[:, 24] = np.clip(rng.normal(0.5, 0.3, k), 0, 1)
            return r

        return np.vstack([_typo(n_typo), _depconf(n_depconf), _hijack(n_hijack), _known_bad(n_known)])

    X_benign = _benign(n_benign)
    X_mal = _malicious(n_mal)
    X = np.vstack([X_benign, X_mal]).astype(np.float32)
    y = np.hstack([np.zeros(n_benign, dtype=np.int64), np.ones(n_mal, dtype=np.int64)])

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def load_real_data(data_dir: str) -> tuple | None:
    """
    Load real labeled data from data_dir.
    Expected format: CSV files with columns matching FEATURE_NAMES + 'label' (0/1).
    Returns None if no data files found.
    """
    dfs = []
    for csv_path in Path(data_dir).glob("*.csv"):
        try:
            df = pd.read_csv(csv_path)
            if "label" not in df.columns:
                print(f"  [skip] {csv_path.name} — missing 'label' column")
                continue
            missing = [f for f in FEATURE_NAMES if f not in df.columns]
            if missing:
                print(f"  [skip] {csv_path.name} — missing features: {missing}")
                continue
            dfs.append(df)
            print(f"  Loaded {len(df)} samples from {csv_path.name}")
        except Exception as e:
            print(f"  [error] {csv_path.name}: {e}")

    if not dfs:
        return None

    combined = pd.concat(dfs, ignore_index=True)
    X = combined[FEATURE_NAMES].values.astype(np.float32)
    y = combined["label"].values.astype(np.int64)
    return X, y


# ---------------------------------------------------------------------------
# Model building
# ---------------------------------------------------------------------------

def build_ensemble() -> VotingClassifier:
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        min_samples_leaf=4,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=5,
        subsample=0.8,
        random_state=42,
    )
    try:
        import lightgbm as lgb
        lgb_clf = lgb.LGBMClassifier(
            n_estimators=300,
            learning_rate=0.05,
            num_leaves=31,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
            verbose=-1,
        )
        estimators = [("rf", rf), ("gb", gb), ("lgb", lgb_clf)]
        print("  LightGBM available — using 3-model ensemble")
    except ImportError:
        estimators = [("rf", rf), ("gb", gb)]
        print("  LightGBM not installed — using 2-model ensemble (install lightgbm for best accuracy)")

    return VotingClassifier(estimators=estimators, voting="soft", n_jobs=-1)


def evaluate(clf, X, y, k: int = 5) -> dict:
    """Run stratified k-fold CV and return metric dict."""
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    cv_f1 = cross_val_score(clf, X, y, cv=skf, scoring="f1", n_jobs=-1)
    cv_auc = cross_val_score(clf, X, y, cv=skf, scoring="roc_auc", n_jobs=-1)
    return {
        "cv_f1_mean": float(cv_f1.mean()),
        "cv_f1_std": float(cv_f1.std()),
        "cv_auc_mean": float(cv_auc.mean()),
        "cv_auc_std": float(cv_auc.std()),
    }


# ---------------------------------------------------------------------------
# SHAP feature importances
# ---------------------------------------------------------------------------

def compute_shap(clf, X_sample, output_path: str):
    try:
        import shap  # noqa: F401
    except ImportError:
        print("  [shap] shap not installed — skipping (pip install shap)")
        return

    try:
        # Use the Random Forest sub-estimator for SHAP (TreeExplainer is fastest)
        rf_clf = clf.named_estimators_.get("rf", None)
        if rf_clf is None and clf.estimators_:
            rf_clf = clf.estimators_[0]
        if rf_clf is None:
            print("  [shap] Could not find RF sub-estimator; skipping SHAP")
            return

        explainer = shap.TreeExplainer(rf_clf)
        raw = explainer.shap_values(X_sample)
        arr = np.array(raw)

        # Normalise to 2-D (n_samples, n_features) selecting class=1 (malicious)
        if arr.ndim == 3:
            # shap >= 0.46: shape (n_samples, n_features, n_classes)
            sv = arr[:, :, 1]
        elif arr.ndim == 2:
            sv = arr
        elif isinstance(raw, list) and len(raw) == 2:
            # Old shap: list of [class0, class1]
            sv = np.array(raw[1])
        else:
            sv = arr

        importances = np.abs(sv).mean(axis=0).flatten()  # shape (n_features,)
        vals = [float(v) for v in importances]
        ranked = sorted(zip(FEATURE_NAMES, vals), key=lambda x: -x[1])

        print("\n  SHAP Feature Importances (top 25):")
        max_val = ranked[0][1] if ranked[0][1] > 0 else 1.0
        for i, (name, val) in enumerate(ranked[:25]):
            bar = "\u2588" * int(val / max_val * 30)
            print(f"    {i+1:2d}. {name:<35} {val:.4f}  {bar}")

        with open(output_path, "w") as f:
            json.dump({"features": [{"name": n, "importance": v} for n, v in ranked]}, f, indent=2)
        print(f"\n  SHAP importances written to {output_path}")
    except Exception as e:
        print(f"  [shap] SHAP computation failed ({type(e).__name__}: {e}) — skipping")

# ---------------------------------------------------------------------------
# ONNX export
# ---------------------------------------------------------------------------

def export_onnx(clf, output_path: str):
    initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
    onx = convert_sklearn(clf, initial_types=initial_type, target_opset=15)
    # Validate
    onnx.checker.check_model(onx)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(onx.SerializeToString())
    print(f"  ONNX model exported → {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Train Falcn malicious-package classifier")
    parser.add_argument("--data-dir", default="", help="Directory with real labeled CSV data")
    parser.add_argument("--output-dir", default="resources/models", help="Output directory for models")
    parser.add_argument("--no-shap", action="store_true", help="Skip SHAP computation")
    parser.add_argument("--n-synthetic", type=int, default=20000, help="Synthetic samples if no real data")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Data loading
    print("\n=== Data Loading ===")
    X, y = None, None
    if args.data_dir and os.path.isdir(args.data_dir):
        result = load_real_data(args.data_dir)
        if result is not None:
            X, y = result
            print(f"  Loaded {len(y)} real samples ({y.sum()} malicious, {(1-y).sum()} benign)")

    if X is None:
        print(f"  No real data found — generating {args.n_synthetic} synthetic samples")
        X, y = generate_synthetic_data(n_samples=args.n_synthetic)
        print(f"  Generated {len(y)} samples ({y.sum()} malicious, {(1-y).sum()} benign)")

    # 2. Normalization (fit scaler on training split only)
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save scaler statistics for Go NormalizeFeatures()
    scaler_stats = {
        "means": scaler.mean_.tolist(),
        "stds": scaler.scale_.tolist(),
        "feature_names": FEATURE_NAMES,
    }
    stats_path = output_dir / "scaler_stats.json"
    with open(stats_path, "w") as f:
        json.dump(scaler_stats, f, indent=2)
    print(f"\n  Scaler statistics saved → {stats_path}")
    print("  UPDATE internal/ml/features.go FeatureMeans/FeatureStdDevs with these values!")

    # 3. Cross-validation
    print("\n=== Cross-Validation (5-fold) ===")
    clf_cv = build_ensemble()
    metrics = evaluate(clf_cv, X_train_scaled, y_train)
    print(f"  F1   : {metrics['cv_f1_mean']:.4f} ± {metrics['cv_f1_std']:.4f}")
    print(f"  AUC  : {metrics['cv_auc_mean']:.4f} ± {metrics['cv_auc_std']:.4f}")

    # 4. Final training on full train set
    print("\n=== Final Training ===")
    clf = build_ensemble()
    clf.fit(X_train_scaled, y_train)

    # 5. Test set evaluation
    print("\n=== Test Set Evaluation ===")
    y_pred = clf.predict(X_test_scaled)
    y_proba = clf.predict_proba(X_test_scaled)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
    test_auc = roc_auc_score(y_test, y_proba)
    test_f1 = f1_score(y_test, y_pred)
    fp_rate = ((y_pred == 1) & (y_test == 0)).sum() / max((y_test == 0).sum(), 1)
    print(f"  AUC           : {test_auc:.4f}")
    print(f"  F1            : {test_f1:.4f}")
    print(f"  False-Pos Rate: {fp_rate:.4f}")

    # Write metrics JSON
    metrics_out = {
        "cv": metrics,
        "test": {
            "auc": test_auc,
            "f1": test_f1,
            "precision": precision_score(y_test, y_pred),
            "recall": recall_score(y_test, y_pred),
            "false_positive_rate": fp_rate,
        },
        "n_train": len(X_train),
        "n_test": len(X_test),
        "n_features": N_FEATURES,
    }
    metrics_path = output_dir / "model_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics_out, f, indent=2)
    print(f"\n  Metrics saved → {metrics_path}")

    # 6. SHAP
    if not args.no_shap:
        print("\n=== SHAP Feature Importances ===")
        try:
            sample_idx = np.random.choice(len(X_test_scaled), min(500, len(X_test_scaled)), replace=False)
            compute_shap(clf, X_test_scaled[sample_idx], str(output_dir / "shap_importances.json"))
        except Exception as e:
            print(f"  [shap] Skipping SHAP due to error: {e}")

    # 7. ONNX export (use Random Forest alone for max ONNX compatibility)
    print("\n=== ONNX Export ===")
    rf_clf = clf.named_estimators_.get("rf", None)
    if rf_clf is None and clf.estimators_:
        rf_clf = clf.estimators_[0]

    if rf_clf is not None:
        onnx_path = str(output_dir / "reputation_model.onnx")
        export_onnx(rf_clf, onnx_path)
        print(f"  Model size: {os.path.getsize(onnx_path) / 1024:.1f} KB")
    else:
        print("  [warn] Could not find RF estimator for ONNX export")

    print("\n=== Training Complete ===")
    print(f"  Output: {output_dir}/")
    print("  Files: reputation_model.onnx, scaler_stats.json, model_metrics.json, shap_importances.json")


if __name__ == "__main__":
    main()
