"""Offline EMBER 2018 Random Forest training and test-set evaluation.

TRAINING happens here, not inside FastAPI. After a successful run, FastAPI
loads models/ember_rf.joblib once at process startup for inference.

This script:
1. Loads labeled EMBER training data via the existing loader.
2. Loads the official labeled test split (untouched until evaluation).
3. Fits sklearn.ensemble.RandomForestClassifier on X_train/y_train only.
4. Evaluates accuracy, precision, recall, F1, FPR, confusion matrix, ROC-AUC.
5. Writes Joblib + metadata only after training/evaluation succeed.

It does not fabricate metrics or write an empty model if the dataset is missing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.data.ember_loader import EmberDatasetError
from app.training.rf_config import RandomForestConfig
from app.training.trainer import run_offline_training


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train and evaluate the EMBER 2018 Random Forest offline."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Extracted EMBER 2018 directory (default: ML_EMBER_DATA_DIR / data/ember2018).",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=None,
        help="Joblib output path (default: models/ember_rf.joblib).",
    )
    parser.add_argument(
        "--metadata-path",
        type=Path,
        default=None,
        help="JSON metadata output path (default: models/ember_rf_metadata.json).",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of trees (default: 100).",
    )
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="Parallel jobs for sklearn (default: -1, all CPUs).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = RandomForestConfig(n_estimators=args.n_estimators, n_jobs=args.n_jobs, random_state=42)

    print("== CipherGuard AI offline EMBER Random Forest training ==")
    print("Inference remains in FastAPI; this process never serves HTTP.")
    print()

    try:
        result = run_offline_training(
            data_dir=args.data_dir,
            model_path=args.model_path,
            metadata_path=args.metadata_path,
            config=config,
            require_official_dim=True,
            persist=True,
        )
    except EmberDatasetError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        print(
            "No Joblib artifact was written. Do not start FastAPI inference until "
            "offline training succeeds.",
            file=sys.stderr,
        )
        return 1

    print()
    print(
        "Offline training finished. Restart FastAPI so the lifespan hook loads "
        f"{result.model_path} once per worker."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
