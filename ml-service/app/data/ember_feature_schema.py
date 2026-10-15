"""Official EMBER 2018 (feature version 2) schema constants.

Feature group sizes and ordering match elastic/ember PEFeatureExtractor with
feature_version=2 (2381-dimensional static PE vectors).
"""

from __future__ import annotations

from typing import Final

# Supervised labels used by EMBER. Unlabeled samples must be excluded from training.
LABEL_BENIGN: Final[int] = 0
LABEL_MALICIOUS: Final[int] = 1
LABEL_UNLABELED: Final[int] = -1
SUPERVISED_LABELS: Final[frozenset[int]] = frozenset({LABEL_BENIGN, LABEL_MALICIOUS})

# EMBER 2018 uses feature_version=2 (includes data directories).
EMBER_FEATURE_VERSION: Final[int] = 2

# Group dimensions in PEFeatureExtractor(feature_version=2) concatenation order.
EMBER_FEATURE_GROUPS: Final[tuple[tuple[str, int], ...]] = (
    ("histogram", 256),
    ("byteentropy", 256),
    ("strings", 104),  # 1+1+1+96+1+1+1+1+1
    ("general", 10),
    ("header", 62),
    ("section", 255),  # 5 + 5*50
    ("imports", 1280),
    ("exports", 128),
    ("datadirectories", 30),  # 15 * 2
)

EMBER_FEATURE_DIM: Final[int] = sum(dim for _, dim in EMBER_FEATURE_GROUPS)

assert EMBER_FEATURE_DIM == 2381, "EMBER 2018 feature_version=2 must be 2381-D"


def build_ember_feature_names() -> list[str]:
    """Return deterministic feature names aligned with the official vector order."""

    names: list[str] = []
    for group, dim in EMBER_FEATURE_GROUPS:
        names.extend(f"{group}_{i}" for i in range(dim))
    return names


EMBER_FEATURE_NAMES: Final[list[str]] = build_ember_feature_names()
