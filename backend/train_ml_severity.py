"""
Training script for the SecureCode AI Machine Learning Severity Classifier.

Usage:
    python train_ml_severity.py --dataset path/to/vulnerabilities.csv

Requires a CSV file with columns:
    cwe, has_source, has_sink, is_flow_confirmed, sanitization,
    evidence_count, affected_lines_count, confidence, exploitability,
    code_lines, severity

This script trains a Random Forest classifier using scikit-learn and persists
the trained artifact to ml_model.joblib for production inference.
"""

import argparse
import sys
from pathlib import Path

try:
    import joblib
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score, train_test_split
    from sklearn.metrics import classification_report
except ImportError:
    print("[ERROR] scikit-learn and joblib are required for training. Please run: pip install scikit-learn joblib")
    sys.exit(1)

OUTPUT_MODEL_PATH = Path(__file__).parent / "ml_model.joblib"


def train_model(dataset_path: Path):
    if not dataset_path.exists():
        print(f"[ERROR] Dataset file '{dataset_path}' not found.")
        print("To train a real ML severity model, please provide a CSV dataset of verified vulnerability findings with true severity labels.")
        sys.exit(1)

    import csv
    X = []
    y = []

    with open(dataset_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                features = [
                    float(row.get("base_cwe_weight", 0.65)),
                    float(row.get("has_source", 0.0)),
                    float(row.get("has_sink", 0.0)),
                    float(row.get("is_flow_confirmed", 0.0)),
                    float(row.get("sanitization", 0.0)),
                    float(row.get("evidence_count", 1.0)),
                    float(row.get("affected_lines_count", 1.0)),
                    float(row.get("norm_conf", 0.8)),
                    float(row.get("exploit_val", 0.55)),
                    float(row.get("code_lines", 0.1)),
                ]
                label = row["severity"].strip().upper()
                if label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    X.append(features)
                    y.append(label)
            except Exception as e:
                continue

    if len(X) < 20:
        print(f"[ERROR] Dataset has only {len(X)} valid samples. A minimum of 20 samples is required to train a reliable classifier.")
        sys.exit(1)

    print(f"[TRAIN] Loaded {len(X)} verified samples. Training Random Forest classifier...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    clf.fit(X_train, y_train)

    cv_scores = cross_val_score(clf, X, y, cv=min(5, len(X) // 5))
    print(f"[TRAIN] Cross-Validation Accuracy: {np.mean(cv_scores):.4f} (+/- {np.std(cv_scores):.4f})")

    y_pred = clf.predict(X_test)
    print("\n[EVALUATION REPORT]")
    print(classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(clf, OUTPUT_MODEL_PATH)
    print(f"[TRAIN] Successfully saved model to: {OUTPUT_MODEL_PATH}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SecureCode AI ML Severity Model")
    parser.add_argument("--dataset", type=str, required=False, help="Path to verified training CSV dataset")
    args = parser.parse_args()

    if not args.dataset:
        print("SecureCode AI - ML Severity Model Training Utility")
        print("=" * 60)
        print("STATUS: Model not trained yet / deterministic fallback active.")
        print("To train a genuine supervised model, run:")
        print("    python train_ml_severity.py --dataset <path_to_labeled_data.csv>")
        print("\nNote: We do NOT generate fake training data. The engine operates in explainable deterministic fallback mode until a real labeled dataset is supplied.")
    else:
        train_model(Path(args.dataset))
