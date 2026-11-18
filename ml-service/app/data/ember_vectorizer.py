"""Vectorize official EMBER 2018 raw JSON feature objects into 2381-D float vectors.

This module implements only ``process_raw_features`` for feature_version=2.
It mirrors the hashing and concatenation order from elastic/ember so JSONL
records become sklearn-ready matrices without inventing a new schema.

LIEF / PE parsing is intentionally not included here; that belongs in the
PE extractor used by FastAPI inference.
"""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.feature_extraction import FeatureHasher

from app.data.ember_feature_schema import EMBER_FEATURE_DIM

# Reuse hasher instances. Creating a new FeatureHasher per sample is too slow
# for the 800k-row EMBER JSONL corpus and does not change the hash mapping.
_HASHER_STR_10 = FeatureHasher(10, input_type="string")
_HASHER_STR_50 = FeatureHasher(50, input_type="string")
_HASHER_PAIR_50 = FeatureHasher(50, input_type="pair")
_HASHER_STR_256 = FeatureHasher(256, input_type="string")
_HASHER_STR_1024 = FeatureHasher(1024, input_type="string")
_HASHER_STR_128 = FeatureHasher(128, input_type="string")


def _require_key(raw_obj: dict[str, Any], key: str) -> Any:
    if key not in raw_obj:
        raise ValueError(f"EMBER raw feature object is missing required key '{key}'.")
    return raw_obj[key]


def _histogram(raw_obj: list[Any]) -> np.ndarray:
    counts = np.asarray(raw_obj, dtype=np.float32)
    if counts.shape != (256,):
        raise ValueError(f"histogram must have length 256, got shape {counts.shape}.")
    total = float(counts.sum())
    if total == 0.0:
        return counts
    return counts / total


def _byteentropy(raw_obj: list[Any]) -> np.ndarray:
    counts = np.asarray(raw_obj, dtype=np.float32)
    if counts.shape != (256,):
        raise ValueError(f"byteentropy must have length 256, got shape {counts.shape}.")
    total = float(counts.sum())
    if total == 0.0:
        return counts
    return counts / total


def _strings(raw_obj: dict[str, Any]) -> np.ndarray:
    required = (
        "numstrings",
        "avlength",
        "printables",
        "printabledist",
        "entropy",
        "paths",
        "urls",
        "registry",
        "MZ",
    )
    for key in required:
        if key not in raw_obj:
            raise ValueError(f"strings feature object is missing '{key}'.")
    hist = np.asarray(raw_obj["printabledist"], dtype=np.float32)
    if hist.shape != (96,):
        raise ValueError(f"strings.printabledist must have length 96, got {hist.shape}.")
    hist_divisor = float(raw_obj["printables"]) if float(raw_obj["printables"]) > 0 else 1.0
    return np.hstack(
        [
            float(raw_obj["numstrings"]),
            float(raw_obj["avlength"]),
            float(raw_obj["printables"]),
            hist / hist_divisor,
            float(raw_obj["entropy"]),
            float(raw_obj["paths"]),
            float(raw_obj["urls"]),
            float(raw_obj["registry"]),
            float(raw_obj["MZ"]),
        ]
    ).astype(np.float32)


def _general(raw_obj: dict[str, Any]) -> np.ndarray:
    keys = (
        "size",
        "vsize",
        "has_debug",
        "exports",
        "imports",
        "has_relocations",
        "has_resources",
        "has_signature",
        "has_tls",
        "symbols",
    )
    for key in keys:
        if key not in raw_obj:
            raise ValueError(f"general feature object is missing '{key}'.")
    return np.asarray([float(raw_obj[k]) for k in keys], dtype=np.float32)


def _header(raw_obj: dict[str, Any]) -> np.ndarray:
    if "coff" not in raw_obj or "optional" not in raw_obj:
        raise ValueError("header feature object must contain 'coff' and 'optional'.")
    coff = raw_obj["coff"]
    optional = raw_obj["optional"]
    return np.hstack(
        [
            float(coff["timestamp"]),
            _HASHER_STR_10.transform([[coff["machine"]]]).toarray()[0],
            _HASHER_STR_10.transform([list(coff["characteristics"])]).toarray()[0],
            _HASHER_STR_10.transform([[optional["subsystem"]]]).toarray()[0],
            _HASHER_STR_10.transform([list(optional["dll_characteristics"])]).toarray()[0],
            _HASHER_STR_10.transform([[optional["magic"]]]).toarray()[0],
            float(optional["major_image_version"]),
            float(optional["minor_image_version"]),
            float(optional["major_linker_version"]),
            float(optional["minor_linker_version"]),
            float(optional["major_operating_system_version"]),
            float(optional["minor_operating_system_version"]),
            float(optional["major_subsystem_version"]),
            float(optional["minor_subsystem_version"]),
            float(optional["sizeof_code"]),
            float(optional["sizeof_headers"]),
            float(optional["sizeof_heap_commit"]),
        ]
    ).astype(np.float32)


def _section(raw_obj: dict[str, Any]) -> np.ndarray:
    if "entry" not in raw_obj or "sections" not in raw_obj:
        raise ValueError("section feature object must contain 'entry' and 'sections'.")
    sections = list(raw_obj["sections"])
    general = [
        len(sections),
        sum(1 for s in sections if s.get("size", 0) == 0),
        sum(1 for s in sections if s.get("name", "") == ""),
        sum(
            1
            for s in sections
            if "MEM_READ" in s.get("props", []) and "MEM_EXECUTE" in s.get("props", [])
        ),
        sum(1 for s in sections if "MEM_WRITE" in s.get("props", [])),
    ]
    section_sizes = [(s.get("name", ""), float(s.get("size", 0))) for s in sections]
    section_entropy = [(s.get("name", ""), float(s.get("entropy", 0.0))) for s in sections]
    section_vsize = [(s.get("name", ""), float(s.get("vsize", 0))) for s in sections]
    entry = raw_obj.get("entry", "")
    characteristics = [
        p for s in sections for p in s.get("props", []) if s.get("name", "") == entry
    ]
    return np.hstack(
        [
            general,
            _HASHER_PAIR_50.transform([section_sizes]).toarray()[0],
            _HASHER_PAIR_50.transform([section_entropy]).toarray()[0],
            _HASHER_PAIR_50.transform([section_vsize]).toarray()[0],
            # Official EMBER hashed the entry name by iterating its characters.
            # Modern scikit-learn rejects a bare string sample, so pass list(entry).
            _HASHER_STR_50.transform([list(entry)]).toarray()[0],
            _HASHER_STR_50.transform([characteristics]).toarray()[0],
        ]
    ).astype(np.float32)


def _imports(raw_obj: dict[str, Any]) -> np.ndarray:
    libraries = list({lib.lower() for lib in raw_obj.keys()})
    libraries_hashed = _HASHER_STR_256.transform([libraries]).toarray()[0]
    imports = [f"{lib.lower()}:{entry}" for lib, entries in raw_obj.items() for entry in entries]
    imports_hashed = _HASHER_STR_1024.transform([imports]).toarray()[0]
    return np.hstack([libraries_hashed, imports_hashed]).astype(np.float32)


def _exports(raw_obj: list[Any]) -> np.ndarray:
    exports_hashed = _HASHER_STR_128.transform([list(raw_obj)]).toarray()[0]
    return exports_hashed.astype(np.float32)


def _datadirectories(raw_obj: list[Any]) -> np.ndarray:
    name_order = [
        "EXPORT_TABLE",
        "IMPORT_TABLE",
        "RESOURCE_TABLE",
        "EXCEPTION_TABLE",
        "CERTIFICATE_TABLE",
        "BASE_RELOCATION_TABLE",
        "DEBUG",
        "ARCHITECTURE",
        "GLOBAL_PTR",
        "TLS_TABLE",
        "LOAD_CONFIG_TABLE",
        "BOUND_IMPORT",
        "IAT",
        "DELAY_IMPORT_DESCRIPTOR",
        "CLR_RUNTIME_HEADER",
    ]
    features = np.zeros(2 * len(name_order), dtype=np.float32)
    # Official EMBER process_raw_features indexes by position for the first 15 entries.
    for i in range(len(name_order)):
        if i < len(raw_obj):
            features[2 * i] = float(raw_obj[i].get("size", 0))
            features[2 * i + 1] = float(raw_obj[i].get("virtual_address", 0))
    return features


def vectorize_raw_features(raw_obj: dict[str, Any]) -> np.ndarray:
    """Convert one EMBER JSONL raw-feature object into a 2381-D float32 vector."""

    if not isinstance(raw_obj, dict):
        raise ValueError("Each EMBER sample must be a JSON object.")

    parts = [
        _histogram(_require_key(raw_obj, "histogram")),
        _byteentropy(_require_key(raw_obj, "byteentropy")),
        _strings(_require_key(raw_obj, "strings")),
        _general(_require_key(raw_obj, "general")),
        _header(_require_key(raw_obj, "header")),
        _section(_require_key(raw_obj, "section")),
        _imports(_require_key(raw_obj, "imports")),
        _exports(_require_key(raw_obj, "exports")),
        _datadirectories(_require_key(raw_obj, "datadirectories")),
    ]
    vector = np.hstack(parts).astype(np.float32, copy=False)
    if vector.shape != (EMBER_FEATURE_DIM,):
        raise ValueError(
            f"Vectorized sample has shape {vector.shape}, expected ({EMBER_FEATURE_DIM},)."
        )
    return vector
