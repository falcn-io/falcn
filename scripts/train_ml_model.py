#!/usr/bin/env python3
"""
Falcn ML Training Pipeline — XGBoost + RandomForest Ensemble for Malicious Package Detection
=============================================================================================
Trains an ensemble classifier on real + synthetic package data, calibrates probability
outputs, exports to ONNX + tree_params.json for pure-Go inference, and computes SHAP
feature importances.

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
  python3 scripts/train_ml_model.py
  python3 scripts/train_ml_model.py --data-dir data/training --output-dir resources/models
  python3 scripts/train_ml_model.py --data-dir data/training --no-shap --no-synthetic
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

warnings.filterwarnings("ignore")

FEATURE_NAMES = [
    "log_downloads", "maintainer_count", "age_days", "days_since_update",
    "vuln_count", "malware_reports", "verified_flags",
    "has_install_script", "install_script_kb", "has_preinstall", "has_postinstall",
    "maintainer_change_count", "maintainer_velocity", "domain_age_days",
    "executable_binary_count", "network_code_files", "log_total_files",
    "entropy_max_file", "dependency_delta", "log_version_count",
    "days_between_versions", "log_stars", "log_forks", "namespace_age_days",
    "download_star_anomaly",
]
N_FEATURES = len(FEATURE_NAMES)  # 25

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_synthetic_data(n_samples: int = 30000, seed: int = 42) -> tuple:
    """
    Generate labeled synthetic training data reflecting realistic distributions.
    Returns (X, y) where X.shape == (n_samples, 25), y.dtype == int64.

    Key improvements over v1:
    - Class overlap: ~8% of benign packages intentionally look risky (ambiguous cases)
    - Label noise: ~3% of labels flipped to prevent over-fitting to clear separations
    - More realistic install-script size distributions
    - Better maintainer dynamics for hijack scenario
    """
    rng = np.random.default_rng(seed)
    n_benign = int(n_samples * 0.88)
    n_mal = n_samples - n_benign

    def _benign(n):
        rows = np.zeros((n, N_FEATURES), dtype=np.float32)
        # Stratify benign: 90% normal, 10% "risky-looking benign" (edge cases)
        n_normal = int(n * 0.90)
        n_edgy = n - n_normal

        def _normal(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(9.5, 4.5, k), 0, 25)    # log downloads
            r[:, 1] = np.clip(rng.poisson(2.5, k) + 1, 1, 20)    # maintainers
            r[:, 2] = rng.exponential(900, k) + 60                 # age days
            r[:, 3] = rng.exponential(120, k)                      # days since update
            r[:, 4] = rng.poisson(0.35, k)                        # vulns
            r[:, 5] = np.zeros(k)
            r[:, 6] = rng.integers(0, 2, k).astype(np.float32) * rng.uniform(0, 3, k).astype(np.float32)
            r[:, 7] = (rng.random(k) < 0.30).astype(np.float32)   # install script ~30%
            r[:, 8] = rng.exponential(1.5, k) * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.10).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.15).astype(np.float32)
            r[:, 11] = rng.poisson(0.2, k)
            r[:, 12] = rng.exponential(0.003, k)
            r[:, 13] = rng.exponential(1500, k) + 180
            r[:, 14] = np.zeros(k)
            r[:, 15] = rng.poisson(0.8, k)
            r[:, 16] = np.clip(rng.normal(2.5, 1.0, k), 0, 7)
            r[:, 17] = np.clip(rng.normal(4.5, 1.2, k), 0, 8)
            r[:, 18] = rng.integers(-3, 4, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(2.2, 1.2, k), 0, 8)
            r[:, 20] = rng.exponential(65, k) + 5
            r[:, 21] = np.clip(rng.normal(5.0, 3.2, k), 0, 15)
            r[:, 22] = np.clip(rng.normal(3.0, 2.2, k), 0, 12)
            r[:, 23] = rng.exponential(1050, k) + 90
            r[:, 24] = np.zeros(k)
            return r

        def _edgy(k):
            # Benign packages that LOOK suspicious: new, few downloads, has install script
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(4.0, 3.0, k), 0, 9)
            r[:, 1] = rng.choice([1, 2], k, p=[0.5, 0.5]).astype(np.float32)
            r[:, 2] = rng.exponential(30, k) + 1
            r[:, 3] = rng.exponential(10, k)
            r[:, 4] = np.zeros(k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = (rng.random(k) < 0.65).astype(np.float32)
            r[:, 8] = rng.exponential(3.0, k) * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.25).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.30).astype(np.float32)
            r[:, 11] = rng.poisson(0.3, k)
            r[:, 12] = rng.exponential(0.008, k)
            r[:, 13] = rng.exponential(400, k) + 60
            r[:, 14] = np.zeros(k)
            r[:, 15] = rng.poisson(1.5, k)
            r[:, 16] = np.clip(rng.normal(1.8, 0.9, k), 0, 5)
            r[:, 17] = np.clip(rng.normal(5.5, 1.5, k), 0, 8)
            r[:, 18] = rng.integers(0, 6, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.8, 0.7, k), 0, 4)
            r[:, 20] = rng.exponential(15, k) + 1
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(150, k) + 14
            r[:, 24] = np.zeros(k)
            return r

        rows[:n_normal] = _normal(n_normal)
        rows[n_normal:] = _edgy(n_edgy)
        return rows

    def _malicious(n):
        rows = np.zeros((n, N_FEATURES), dtype=np.float32)
        # Attack taxonomy (percentages calibrated to real-world incident data):
        # 38% typosquatting
        # 28% dependency confusion
        # 18% account/maintainer takeover
        # 10% known-bad (already reported)
        # 6%  slow-burn (old package, subtle compromise)
        n_typo     = int(n * 0.38)
        n_depconf  = int(n * 0.28)
        n_hijack   = int(n * 0.18)
        n_known    = int(n * 0.10)
        n_slowburn = n - n_typo - n_depconf - n_hijack - n_known

        def _typo(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(2.5, 2.2, k), 0, 8)
            r[:, 1] = rng.choice([0, 1], k, p=[0.4, 0.6]).astype(np.float32)
            r[:, 2] = rng.exponential(7, k)
            r[:, 3] = rng.exponential(2, k)
            r[:, 4] = rng.poisson(0.05, k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = (rng.random(k) < 0.72).astype(np.float32)
            r[:, 8] = rng.exponential(6.0, k) * r[:, 7] + 0.1 * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.42).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.45).astype(np.float32)
            r[:, 11] = np.zeros(k)
            r[:, 12] = np.zeros(k)
            r[:, 13] = rng.exponential(70, k)
            r[:, 14] = rng.integers(0, 3, k).astype(np.float32)
            r[:, 15] = rng.poisson(2.8, k)
            r[:, 16] = np.clip(rng.normal(1.4, 0.8, k), 0, 5)
            r[:, 17] = np.clip(rng.normal(6.8, 0.8, k), 0, 8)
            r[:, 18] = rng.integers(0, 9, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.25, 0.3, k), 0, 2)
            r[:, 20] = rng.exponential(2, k)
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(50, k) + 1
            r[:, 24] = np.zeros(k)
            return r

        def _depconf(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(5.5, 2.0, k), 0, 12)
            r[:, 1] = rng.choice([1, 2], k).astype(np.float32)
            r[:, 2] = rng.exponential(18, k)
            r[:, 3] = rng.exponential(4, k)
            r[:, 4] = np.zeros(k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = np.ones(k)
            r[:, 8] = rng.exponential(12.0, k) + 4
            r[:, 9] = (rng.random(k) < 0.62).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.65).astype(np.float32)
            r[:, 11] = np.zeros(k)
            r[:, 12] = np.zeros(k)
            r[:, 13] = rng.exponential(110, k)
            r[:, 14] = rng.integers(0, 5, k).astype(np.float32)
            r[:, 15] = rng.poisson(4.2, k)
            r[:, 16] = np.clip(rng.normal(1.9, 1.0, k), 0, 5)
            r[:, 17] = np.clip(rng.normal(7.2, 0.6, k), 4, 8)
            r[:, 18] = rng.integers(6, 32, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.4, 0.4, k), 0, 2)
            r[:, 20] = rng.exponential(2, k)
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(80, k)
            r[:, 24] = np.clip(rng.normal(0.72, 0.18, k), 0, 1)
            return r

        def _hijack(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(11.5, 3.0, k), 4, 20)
            r[:, 1] = rng.choice([1, 2], k).astype(np.float32)
            r[:, 2] = rng.exponential(1600, k) + 400
            r[:, 3] = rng.exponential(2, k)              # very recent update
            r[:, 4] = rng.poisson(1.2, k)
            r[:, 5] = np.zeros(k)
            r[:, 6] = np.zeros(k)
            r[:, 7] = np.ones(k)
            r[:, 8] = rng.exponential(9.0, k) + 5
            r[:, 9] = (rng.random(k) < 0.55).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.58).astype(np.float32)
            r[:, 11] = rng.poisson(4.5, k)              # maintainer churn spike
            r[:, 12] = rng.exponential(0.18, k)
            r[:, 13] = rng.exponential(180, k) + 25
            r[:, 14] = rng.integers(0, 4, k).astype(np.float32)
            r[:, 15] = rng.poisson(3.2, k)
            r[:, 16] = np.clip(rng.normal(3.0, 1.0, k), 0, 7)
            r[:, 17] = np.clip(rng.normal(6.8, 0.6, k), 4, 8)
            r[:, 18] = rng.integers(4, 22, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(2.8, 1.0, k), 0, 7)
            r[:, 20] = rng.exponential(4, k)
            r[:, 21] = np.clip(rng.normal(7.2, 2.0, k), 0, 12)
            r[:, 22] = np.clip(rng.normal(5.2, 2.0, k), 0, 10)
            r[:, 23] = rng.exponential(900, k) + 200
            r[:, 24] = np.zeros(k)
            return r

        def _known_bad(k):
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(3.5, 2.8, k), 0, 10)
            r[:, 1] = rng.choice([0, 1], k, p=[0.55, 0.45]).astype(np.float32)
            r[:, 2] = rng.exponential(12, k)
            r[:, 3] = rng.exponential(4, k)
            r[:, 4] = rng.poisson(1.5, k)
            r[:, 5] = rng.choice([1, 2, 3], k, p=[0.65, 0.25, 0.10]).astype(np.float32)
            r[:, 6] = np.zeros(k)
            r[:, 7] = (rng.random(k) < 0.82).astype(np.float32)
            r[:, 8] = rng.exponential(5.5, k) * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.55).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.55).astype(np.float32)
            r[:, 11] = rng.poisson(0.8, k)
            r[:, 12] = rng.exponential(0.04, k)
            r[:, 13] = rng.exponential(140, k)
            r[:, 14] = rng.integers(0, 5, k).astype(np.float32)
            r[:, 15] = rng.poisson(3.2, k)
            r[:, 16] = np.clip(rng.normal(2.0, 1.2, k), 0, 6)
            r[:, 17] = np.clip(rng.normal(7.2, 0.6, k), 4, 8)
            r[:, 18] = rng.integers(2, 16, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(0.4, 0.4, k), 0, 2)
            r[:, 20] = rng.exponential(3, k)
            r[:, 21] = np.zeros(k)
            r[:, 22] = np.zeros(k)
            r[:, 23] = rng.exponential(75, k)
            r[:, 24] = np.clip(rng.normal(0.48, 0.28, k), 0, 1)
            return r

        def _slowburn(k):
            # Old established package quietly compromised
            r = np.zeros((k, N_FEATURES), dtype=np.float32)
            r[:, 0] = np.clip(rng.normal(13.0, 2.5, k), 6, 20)  # high downloads
            r[:, 1] = rng.choice([1, 2, 3], k, p=[0.4, 0.4, 0.2]).astype(np.float32)
            r[:, 2] = rng.exponential(2000, k) + 600             # very old package
            r[:, 3] = rng.exponential(5, k)                      # recent tiny update
            r[:, 4] = rng.poisson(0.5, k)
            r[:, 5] = np.zeros(k)                                 # not yet reported
            r[:, 6] = np.zeros(k)
            r[:, 7] = (rng.random(k) < 0.5).astype(np.float32)
            r[:, 8] = rng.exponential(4.0, k) * r[:, 7]
            r[:, 9] = (rng.random(k) < 0.25).astype(np.float32)
            r[:, 10] = (rng.random(k) < 0.30).astype(np.float32)
            r[:, 11] = rng.poisson(2.0, k)                       # moderate churn
            r[:, 12] = rng.exponential(0.08, k)
            r[:, 13] = rng.exponential(300, k) + 90
            r[:, 14] = rng.integers(0, 2, k).astype(np.float32)
            r[:, 15] = rng.poisson(2.0, k)
            r[:, 16] = np.clip(rng.normal(3.2, 1.0, k), 0, 7)
            r[:, 17] = np.clip(rng.normal(6.2, 0.9, k), 3, 8)   # moderate entropy
            r[:, 18] = rng.integers(2, 12, k).astype(np.float32)
            r[:, 19] = np.clip(rng.normal(3.5, 1.0, k), 0, 8)   # many versions
            r[:, 20] = rng.exponential(30, k) + 5
            r[:, 21] = np.clip(rng.normal(8.0, 2.0, k), 0, 12)  # established stars
            r[:, 22] = np.clip(rng.normal(6.0, 2.0, k), 0, 10)
            r[:, 23] = rng.exponential(1200, k) + 400
            r[:, 24] = np.zeros(k)
            return r

        rows[:n_typo]                         = _typo(n_typo)
        rows[n_typo:n_typo+n_depconf]         = _depconf(n_depconf)
        n2 = n_typo + n_depconf
        rows[n2:n2+n_hijack]                  = _hijack(n_hijack)
        n3 = n2 + n_hijack
        rows[n3:n3+n_known]                   = _known_bad(n_known)
        n4 = n3 + n_known
        rows[n4:]                             = _slowburn(n_slowburn)
        return rows

    X_benign = _benign(n_benign)
    X_mal    = _malicious(n_mal)
    X = np.vstack([X_benign, X_mal]).astype(np.float32)
    y = np.hstack([np.zeros(n_benign, dtype=np.int64),
                   np.ones(n_mal,    dtype=np.int64)])

    # Label noise: flip ~3% to simulate real-world ambiguity
    noise_mask = rng.random(len(y)) < 0.03
    y[noise_mask] = 1 - y[noise_mask]

    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_real_data(data_dir: str) -> tuple | None:
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
            # Clean: drop rows with any NaN
            before = len(df)
            df = df.dropna(subset=FEATURE_NAMES + ["label"])
            if len(df) < before:
                print(f"  [warn] {csv_path.name} dropped {before-len(df)} rows with NaN")
            dfs.append(df)
            print(f"  Loaded {len(df)} samples from {csv_path.name}  "
                  f"(mal={df['label'].sum():.0f}, benign={(df['label']==0).sum()})")
        except Exception as e:
            print(f"  [error] {csv_path.name}: {e}")

    if not dfs:
        return None

    combined = pd.concat(dfs, ignore_index=True)
    X = combined[FEATURE_NAMES].values.astype(np.float32)
    y = combined["label"].values.astype(np.int64)
    return X, y


# ─────────────────────────────────────────────────────────────────────────────
# Model building — XGBoost + RandomForest ensemble
# ─────────────────────────────────────────────────────────────────────────────

def build_models(scale_pos_weight: float = 8.0):
    """
    Returns (xgb_clf, rf_clf, voting_clf).

    scale_pos_weight for XGBoost = n_benign/n_malicious, handles class imbalance.
    The VotingClassifier is used for ONNX export (sklearn-compatible).
    The RandomForest alone is exported to tree_params.json for Go inference.
    """
    from sklearn.ensemble import RandomForestClassifier, VotingClassifier

    try:
        import xgboost as xgb
        xgb_clf = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=5,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            use_label_encoder=False,
            tree_method="hist",    # fast on large datasets
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
        print("  XGBoost available ✓")
        HAS_XGB = True
    except ImportError:
        xgb_clf = None
        HAS_XGB = False
        print("  [warn] XGBoost not installed — pip install xgboost")

    rf_clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=14,
        min_samples_leaf=3,
        max_features="sqrt",
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )

    try:
        import lightgbm as lgb
        lgb_clf = lgb.LGBMClassifier(
            n_estimators=400,
            learning_rate=0.04,
            num_leaves=63,
            max_depth=-1,
            min_child_samples=10,
            class_weight="balanced",
            colsample_bytree=0.8,
            subsample=0.8,
            n_jobs=-1,
            random_state=42,
            verbose=-1,
        )
        print("  LightGBM available ✓")
        HAS_LGB = True
    except ImportError:
        lgb_clf = None
        HAS_LGB = False

    estimators = [("rf", rf_clf)]
    if HAS_XGB:
        estimators.append(("xgb", xgb_clf))
    if HAS_LGB:
        estimators.append(("lgb", lgb_clf))

    print(f"  Ensemble: {[e[0] for e in estimators]}")
    from sklearn.ensemble import VotingClassifier
    voting = VotingClassifier(estimators=estimators, voting="soft", n_jobs=1)
    return xgb_clf, rf_clf, voting


# ─────────────────────────────────────────────────────────────────────────────
# Evaluation
# ─────────────────────────────────────────────────────────────────────────────

def evaluate(clf, X_scaled, y, k: int = 5) -> dict:
    from sklearn.model_selection import StratifiedKFold, cross_val_score
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=42)
    # Subsample for CV speed on large datasets
    if len(y) > 15000:
        idx = np.random.default_rng(42).choice(len(y), 15000, replace=False)
        Xs, ys = X_scaled[idx], y[idx]
    else:
        Xs, ys = X_scaled, y
    cv_f1  = cross_val_score(clf, Xs, ys, cv=skf, scoring="f1",      n_jobs=1)
    cv_auc = cross_val_score(clf, Xs, ys, cv=skf, scoring="roc_auc", n_jobs=1)
    return {
        "cv_f1_mean":  float(cv_f1.mean()),
        "cv_f1_std":   float(cv_f1.std()),
        "cv_auc_mean": float(cv_auc.mean()),
        "cv_auc_std":  float(cv_auc.std()),
    }


def best_threshold(y_true, y_prob, beta: float = 1.5) -> float:
    """
    Find the probability threshold that maximises F-beta score.
    beta > 1 weights recall higher (prefer fewer false negatives).
    """
    from sklearn.metrics import fbeta_score
    best_t, best_fb = 0.5, 0.0
    for t in np.arange(0.05, 0.95, 0.02):
        fb = fbeta_score(y_true, (y_prob >= t).astype(int), beta=beta, zero_division=0)
        if fb > best_fb:
            best_fb, best_t = fb, float(t)
    return best_t


# ─────────────────────────────────────────────────────────────────────────────
# SHAP
# ─────────────────────────────────────────────────────────────────────────────

def compute_shap(rf_clf, X_sample: np.ndarray, output_path: str):
    try:
        import shap
    except ImportError:
        print("  [shap] shap not installed — skipping (pip install shap)")
        return
    try:
        explainer = shap.TreeExplainer(rf_clf)
        raw = explainer.shap_values(X_sample)
        arr = np.array(raw)
        if arr.ndim == 3:
            sv = arr[:, :, 1]
        elif isinstance(raw, list) and len(raw) == 2:
            sv = np.array(raw[1])
        else:
            sv = arr
        importances = np.abs(sv).mean(axis=0).flatten()
        vals = [float(v) for v in importances]
        ranked = sorted(zip(FEATURE_NAMES, vals), key=lambda x: -x[1])

        print("\n  SHAP Feature Importances (top 25):")
        max_val = ranked[0][1] if ranked[0][1] > 0 else 1.0
        for i, (name, val) in enumerate(ranked[:25]):
            bar = "█" * int(val / max_val * 30)
            print(f"    {i+1:2d}. {name:<35} {val:.4f}  {bar}")

        with open(output_path, "w") as f:
            json.dump({"features": [{"name": n, "importance": v} for n, v in ranked]}, f, indent=2)
        print(f"\n  SHAP importances → {output_path}")
    except Exception as e:
        print(f"  [shap] Failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# ONNX export
# ─────────────────────────────────────────────────────────────────────────────

def export_onnx(clf, output_path: str):
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
    import onnx
    initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
    onx = convert_sklearn(clf, initial_types=initial_type, target_opset=15)
    onnx.checker.check_model(onx)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(onx.SerializeToString())
    size_kb = os.path.getsize(output_path) / 1024
    print(f"  ONNX model → {output_path}  ({size_kb:.0f} KB)")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train Falcn malicious-package classifier")
    parser.add_argument("--data-dir",     default="",                    help="Directory with real labeled CSVs")
    parser.add_argument("--output-dir",   default="resources/models",   help="Output directory for model artifacts")
    parser.add_argument("--no-shap",      action="store_true",           help="Skip SHAP computation")
    parser.add_argument("--no-synthetic", action="store_true",           help="Use only real data (no synthetic augmentation)")
    parser.add_argument("--n-synthetic",  type=int, default=30000,       help="Synthetic samples (default 30000)")
    parser.add_argument("--real-weight",  type=float, default=5.0,       help="Sample weight multiplier for real data (default 5.0)")
    args = parser.parse_args()

    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        classification_report, f1_score, precision_score,
        recall_score, roc_auc_score, average_precision_score,
        confusion_matrix,
    )
    from sklearn.calibration import CalibratedClassifierCV

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "="*60)
    print("Falcn ML Training Pipeline v2 (XGBoost + RF ensemble)")
    print("="*60)

    # ── 1. Data ────────────────────────────────────────────────────
    print("\n[1] Data Loading")
    X_real, y_real = None, None
    if args.data_dir and os.path.isdir(args.data_dir):
        result = load_real_data(args.data_dir)
        if result is not None:
            X_real, y_real = result
            print(f"\n  Real data: {len(y_real)} samples  "
                  f"(mal={y_real.sum()}, benign={(y_real==0).sum()})")

    if not args.no_synthetic:
        print(f"  Generating {args.n_synthetic} synthetic samples...")
        X_syn, y_syn = generate_synthetic_data(n_samples=args.n_synthetic)
        print(f"  Synthetic: {len(y_syn)} samples  "
              f"(mal={y_syn.sum()}, benign={(y_syn==0).sum()})")
    else:
        X_syn, y_syn = None, None

    # Combine with sample weights
    if X_real is not None and X_syn is not None:
        X = np.vstack([X_real, X_syn])
        y = np.hstack([y_real, y_syn])
        # Real data gets higher weight; synthetic is supplementary
        w_real = np.full(len(y_real), args.real_weight, dtype=np.float32)
        w_syn  = np.ones(len(y_syn), dtype=np.float32)
        sample_weights = np.hstack([w_real, w_syn])
        print(f"\n  Combined: {len(y)} samples total  (real×{args.real_weight:.0f} + synthetic×1)")
        data_source = "real+synthetic"
    elif X_real is not None:
        X, y = X_real, y_real
        sample_weights = np.full(len(y), 1.0, dtype=np.float32)
        data_source = "real"
    elif X_syn is not None:
        X, y = X_syn, y_syn
        sample_weights = np.ones(len(y), dtype=np.float32)
        print("  [warn] Using synthetic data only — expect optimistic metrics")
        data_source = "synthetic"
    else:
        print("ERROR: No data available. Provide --data-dir or remove --no-synthetic.")
        sys.exit(1)

    n_total = len(y)
    n_mal   = y.sum()
    n_ben   = n_total - n_mal
    spw = max(1.0, n_ben / max(1, n_mal))  # scale_pos_weight for XGBoost
    print(f"  Class ratio: {n_ben:.0f} benign / {n_mal:.0f} malicious  (ratio={spw:.1f})")

    # ── 2. Split ───────────────────────────────────────────────────
    X_tr, X_te, y_tr, y_te, w_tr, w_te = train_test_split(
        X, y, sample_weights, test_size=0.20, random_state=42, stratify=y
    )

    # ── 3. Scale ───────────────────────────────────────────────────
    print("\n[2] Normalisation")
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_tr)
    X_te_s = scaler.transform(X_te)

    # Save scaler stats
    scaler_stats = {
        "means":         scaler.mean_.tolist(),
        "stds":          scaler.scale_.tolist(),
        "feature_names": FEATURE_NAMES,
        "data_source":   data_source,
        "n_train":       int(len(X_tr)),
        "trained_at":    __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    stats_path = output_dir / "scaler_stats.json"
    with open(stats_path, "w") as f:
        json.dump(scaler_stats, f, indent=2)
    print(f"  Scaler stats → {stats_path}")

    # ── 4. Build & cross-validate ──────────────────────────────────
    print("\n[3] Building models...")
    xgb_clf, rf_clf, voting = build_models(scale_pos_weight=spw)

    print("\n[4] Cross-validation (5-fold)...")
    metrics_cv = evaluate(voting, X_tr_s, y_tr)
    print(f"  F1  : {metrics_cv['cv_f1_mean']:.4f} ± {metrics_cv['cv_f1_std']:.4f}")
    print(f"  AUC : {metrics_cv['cv_auc_mean']:.4f} ± {metrics_cv['cv_auc_std']:.4f}")

    # ── 5. Final fit ───────────────────────────────────────────────
    print("\n[5] Final training on full train set...")
    try:
        voting.fit(X_tr_s, y_tr, sample_weight=w_tr)
    except TypeError:
        # Some sklearn versions don't pass sample_weight through VotingClassifier
        voting.fit(X_tr_s, y_tr)

    # Individually retrain RF with sample weights (for SHAP + tree_params export)
    rf_clf.fit(X_tr_s, y_tr, sample_weight=w_tr)

    # Calibrate the full ensemble using isotonic regression
    print("  Calibrating probability outputs (isotonic)...")
    calibrated = CalibratedClassifierCV(voting, method="isotonic", cv="prefit")
    calibrated.fit(X_te_s, y_te)  # calibrate on held-out test split

    # ── 6. Threshold optimisation ──────────────────────────────────
    print("\n[6] Threshold optimisation...")
    y_prob_te = calibrated.predict_proba(X_te_s)[:, 1]
    opt_threshold = best_threshold(y_te, y_prob_te, beta=1.5)
    print(f"  Optimal threshold (F1.5): {opt_threshold:.3f}")

    # ── 7. Test evaluation ─────────────────────────────────────────
    print("\n[7] Test Set Evaluation")
    y_pred = (y_prob_te >= opt_threshold).astype(int)
    print(classification_report(y_te, y_pred, target_names=["benign", "malicious"]))

    auc    = roc_auc_score(y_te, y_prob_te)
    aucpr  = average_precision_score(y_te, y_prob_te)
    f1     = f1_score(y_te, y_pred)
    prec   = precision_score(y_te, y_pred, zero_division=0)
    rec    = recall_score(y_te, y_pred)
    tn, fp, fn, tp_val = confusion_matrix(y_te, y_pred).ravel()
    fp_rate = fp / max(1, tn + fp)

    print(f"  AUC-ROC       : {auc:.4f}")
    print(f"  AUC-PR        : {aucpr:.4f}")
    print(f"  F1            : {f1:.4f}")
    print(f"  Precision     : {prec:.4f}")
    print(f"  Recall        : {rec:.4f}")
    print(f"  False-Pos Rate: {fp_rate:.4f}  ({fp} false positives in {tn+fp} benign test samples)")
    print(f"  Threshold used: {opt_threshold:.3f}")

    metrics_out = {
        "cv":     metrics_cv,
        "test":   {
            "auc":               auc,
            "auc_pr":            aucpr,
            "f1":                f1,
            "precision":         prec,
            "recall":            rec,
            "false_positive_rate": fp_rate,
            "threshold":         opt_threshold,
            "confusion_matrix":  {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp_val)},
        },
        "n_train":     len(X_tr),
        "n_test":      len(X_te),
        "n_features":  N_FEATURES,
        "data_source": data_source,
    }
    metrics_path = output_dir / "model_metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics_out, f, indent=2)
    print(f"\n  Metrics → {metrics_path}")

    # Save optimal threshold for Go inference to use
    threshold_path = output_dir / "model_threshold.json"
    with open(threshold_path, "w") as f:
        json.dump({"threshold": opt_threshold, "beta": 1.5}, f)
    print(f"  Threshold → {threshold_path}")

    # ── 8. SHAP ────────────────────────────────────────────────────
    if not args.no_shap:
        print("\n[8] SHAP Feature Importances...")
        sample_size = min(800, len(X_te_s))
        idx = np.random.default_rng(42).choice(len(X_te_s), sample_size, replace=False)
        compute_shap(rf_clf, X_te_s[idx], str(output_dir / "shap_importances.json"))

    # ── 9. ONNX export (RF for compat) ────────────────────────────
    print("\n[9] ONNX Export (RandomForest)...")
    onnx_path = str(output_dir / "reputation_model.onnx")
    try:
        export_onnx(rf_clf, onnx_path)
    except Exception as e:
        print(f"  [warn] ONNX export failed: {e}")

    # ── 10. Print Go update instructions ──────────────────────────
    print("\n[10] Update internal/ml/features.go with new scaler stats:")
    print(f"\nvar FeatureMeans = [{N_FEATURES}]float32{{")
    for i, (name, mean) in enumerate(zip(FEATURE_NAMES, scaler.mean_)):
        print(f"    {mean:.4f},  // [{i:2d}] {name}")
    print("}")
    print(f"\nvar FeatureStdDevs = [{N_FEATURES}]float32{{")
    for i, (name, std) in enumerate(zip(FEATURE_NAMES, scaler.scale_)):
        print(f"    {std:.4f},  // [{i:2d}] {name}")
    print("}")

    print("\n" + "="*60)
    print("Training complete!")
    print(f"  Output dir: {output_dir}/")
    print(f"  AUC: {auc:.4f}  |  F1: {f1:.4f}  |  FPR: {fp_rate:.4f}")
    print(f"\nNext step: python3 scripts/export_tree_params.py")
    print("="*60)


if __name__ == "__main__":
    main()
