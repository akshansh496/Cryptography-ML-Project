"""Inspect a local EMBER 2018 dataset before offline training.

Usage (from ml-service/):

    python scripts/inspect_ember.py
    python scripts/inspect_ember.py --data-dir data/ember2018
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.data import format_dataset_report, inspect_ember_dataset


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect local EMBER 2018 dataset files.")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Path to the extracted EMBER 2018 directory (default: ML_EMBER_DATA_DIR / data/ember2018).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    info = inspect_ember_dataset(args.data_dir)
    print(format_dataset_report(info))
    if not info.dataset_present or info.format is None:
        return 1
    if info.n_train_samples == 0:
        print(
            "\nReal Random Forest training cannot run until supervised EMBER "
            "training samples are available.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
