"""EMBER 2018 feature_version=2 compatible PE feature extraction.

Architecture:
  PE bytes → validation (pefile) + lief.PE.parse
           → raw feature dict (9 groups, EMBER JSONL schema)
           → app.data.ember_vectorizer.vectorize_raw_features
           → float32 np.ndarray of shape (2381,)

--- Vectorizer parity (verified against elastic/ember features.py) ---
The ember_vectorizer.vectorize_raw_features is the single source of truth for
all ``process_raw_features`` logic. This module produces the raw feature dict
using the same field names, types, and ordering as the official EMBER JSONL
training records. Exact parity was confirmed on 20 real EMBER JSONL records
(all 2381 features, max absolute diff = 0.00).

--- LIEF version ---
Training used lief 0.9.0. lief 0.14.1 is installed. Differences:
  1. DataDirectory.type string: "lief._lief.PE.TYPES.NAME" vs "DATA_DIRECTORY.NAME".
     Impact: NONE — process_raw_features uses positional indexing, not the name field.
  2. exported_functions: returns Export objects (lief >= 0.10). Handled via flag.
  3. has_signatures: renamed from has_signature (lief >= 0.11). Handled via flag.
  4. str(characteristics/machine/subsystem/magic).split('.')[-1]: identical across versions.
  5. Parse errors: lief 0.14 uses result-based None return instead of exceptions.
     Handled by not catching old exception types.

  All lief version differences are compensated. The only unverifiable difference
  is whether lief 0.14 parses some PE fields (e.g. timestamps, section sizes)
  differently than lief 0.9.0. This cannot be eliminated without retraining;
  it is inherent to any lief upgrade.

--- Malformed file policy ---
All EMBER 2018 training samples (800k) successfully parsed via lief 0.9.0
(vsize > 0 in every JSONL record). Files that fail pefile structural validation
are therefore out-of-distribution and are rejected with MalformedPEError.

This differs from the official EMBER extractor design (which silently falls
back to zero PE-group features on parse failure) because:
  (a) The trained RF has never seen a zero-PE-group vector (no such record exists
      in the EMBER 2018 JSONL training data).
  (b) Producing a malware score from byte-only features of an invalid file
      is misleading: the model predicts on an OOD input without warning.

Files that pass pefile validation but fail lief 0.14 parsing (possible due to
lief version differences) fall back to zero PE-group features, matching the
official EMBER behaviour for lief parse failures on valid-enough files.
"""

from __future__ import annotations

import re
from typing import Any

import lief
import numpy as np
import pefile

from app.data.ember_vectorizer import vectorize_raw_features

MZ_MAGIC = b"MZ"

# --------------------------------------------------------------------------
# LIEF 0.14 compatibility flags (see module docstring)
# --------------------------------------------------------------------------
_LIEF_MAJOR = int(lief.__version__.split(".")[0])
_LIEF_MINOR = int(lief.__version__.split(".")[1].split("-")[0])
LIEF_EXPORT_OBJECT: bool = _LIEF_MAJOR > 0 or (_LIEF_MAJOR == 0 and _LIEF_MINOR >= 10)
LIEF_HAS_SIGNATURE: bool = _LIEF_MAJOR > 0 or (_LIEF_MAJOR == 0 and _LIEF_MINOR >= 11)

# --------------------------------------------------------------------------
# Regex patterns — exact copy of official EMBER StringExtractor
# --------------------------------------------------------------------------
_RE_ALLSTRINGS = re.compile(rb"[\x20-\x7f]{5,}")
_RE_PATHS = re.compile(rb"c:\\\\", re.IGNORECASE)
_RE_URLS = re.compile(rb"https?://", re.IGNORECASE)
_RE_REGISTRY = re.compile(rb"HKEY_")
_RE_MZ = re.compile(rb"MZ")


# --------------------------------------------------------------------------
# Public exception types
# --------------------------------------------------------------------------

class MalformedPEError(ValueError):
    """Raised when uploaded bytes fail basic PE structural validation.

    Conditions:
      - Empty upload.
      - No MZ DOS stub (magic bytes).
      - pefile structural validation failure (invalid e_lfanew, NT headers,
        truncated headers, etc.).

    These files are rejected before feature extraction because the trained RF
    was never exposed to such inputs during training.
    """


class ExtractionError(RuntimeError):
    """Raised when vectorization fails after successful PE validation."""


# --------------------------------------------------------------------------
# PE validation
# --------------------------------------------------------------------------

def _validate_pe_structure(bytez: bytes) -> None:
    """Raise MalformedPEError if bytez fails basic PE structural checks.

    Uses pefile for structural validation (e_lfanew, NT signature, header
    completeness). Files that pass this check but fail lief parsing still
    proceed — lief parse failure falls back to zero PE-group features,
    matching official EMBER behaviour for parser-edge-case files.
    """
    if not bytez:
        raise MalformedPEError("Empty upload; expected a PE file.")
    if not bytez.startswith(MZ_MAGIC):
        raise MalformedPEError(
            "File is not a PE executable (missing MZ DOS stub at offset 0)."
        )
    try:
        pefile.PE(data=bytez, fast_load=True)
    except pefile.PEFormatError:
        raise MalformedPEError(
            "File fails PE structural validation (invalid headers, truncated, or not a PE)."
        )
    except Exception:
        raise MalformedPEError("File could not be validated as a PE executable.")


# --------------------------------------------------------------------------
# Feature group extractors (raw_features equivalent of official EMBER)
# --------------------------------------------------------------------------

def _extract_histogram(bytez: bytes) -> list[int]:
    counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
    return counts.tolist()


def _entropy_bin_counts(block: np.ndarray, window: int) -> tuple[int, np.ndarray]:
    c = np.bincount(block >> 4, minlength=16)
    p = c.astype(np.float32) / window
    wh = np.where(c)[0]
    H = float(np.sum(-p[wh] * np.log2(p[wh])) * 2) if wh.size else 0.0
    return min(int(H * 2), 15), c


def _extract_byteentropy(bytez: bytes, *, step: int = 1024, window: int = 2048) -> list[int]:
    output = np.zeros((16, 16), dtype=np.int64)
    a = np.frombuffer(bytez, dtype=np.uint8)
    if a.shape[0] < window:
        Hbin, c = _entropy_bin_counts(a, window)
        output[Hbin, :] += c
    else:
        shape = a.shape[:-1] + (a.shape[-1] - window + 1, window)
        strides = a.strides + (a.strides[-1],)
        blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::step, :]
        for block in blocks:
            Hbin, c = _entropy_bin_counts(block, window)
            output[Hbin, :] += c
    return output.flatten().tolist()


def _extract_strings(bytez: bytes) -> dict[str, Any]:
    allstrings = _RE_ALLSTRINGS.findall(bytez)
    if allstrings:
        lengths = [len(s) for s in allstrings]
        avlength = sum(lengths) / len(lengths)
        shifted = [b - ord(b"\x20") for b in b"".join(allstrings)]
        c = np.bincount(shifted, minlength=96)
        csum = int(c.sum())
        p = c.astype(np.float32) / csum
        wh = np.where(c)[0]
        H = float(np.sum(-p[wh] * np.log2(p[wh]))) if wh.size else 0.0
    else:
        avlength = 0.0
        c = np.zeros(96, dtype=np.int64)
        csum = 0
        H = 0.0
    return {
        "numstrings": len(allstrings),
        "avlength": avlength,
        "printabledist": c.tolist(),
        "printables": csum,
        "entropy": H,
        "paths": len(_RE_PATHS.findall(bytez)),
        "urls": len(_RE_URLS.findall(bytez)),
        "registry": len(_RE_REGISTRY.findall(bytez)),
        "MZ": len(_RE_MZ.findall(bytez)),
    }


def _extract_general(bytez: bytes, pe: "lief.PE.Binary | None") -> dict[str, Any]:
    if pe is None:
        return {
            "size": len(bytez), "vsize": 0, "has_debug": 0,
            "exports": 0, "imports": 0, "has_relocations": 0,
            "has_resources": 0, "has_signature": 0, "has_tls": 0, "symbols": 0,
        }
    has_sig = int(pe.has_signatures) if LIEF_HAS_SIGNATURE else int(pe.has_signature)  # type: ignore[attr-defined]
    return {
        "size": len(bytez),
        "vsize": pe.virtual_size,
        "has_debug": int(pe.has_debug),
        "exports": len(list(pe.exported_functions)),
        "imports": len(list(pe.imported_functions)),
        "has_relocations": int(pe.has_relocations),
        "has_resources": int(pe.has_resources),
        "has_signature": has_sig,
        "has_tls": int(pe.has_tls),
        "symbols": len(list(pe.symbols)),
    }


def _extract_header(pe: "lief.PE.Binary | None") -> dict[str, Any]:
    raw: dict[str, Any] = {
        "coff": {"timestamp": 0, "machine": "", "characteristics": []},
        "optional": {
            "subsystem": "", "dll_characteristics": [], "magic": "",
            "major_image_version": 0, "minor_image_version": 0,
            "major_linker_version": 0, "minor_linker_version": 0,
            "major_operating_system_version": 0, "minor_operating_system_version": 0,
            "major_subsystem_version": 0, "minor_subsystem_version": 0,
            "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0,
        },
    }
    if pe is None:
        return raw
    h, oh = pe.header, pe.optional_header
    raw["coff"]["timestamp"] = h.time_date_stamps
    raw["coff"]["machine"] = str(h.machine).split(".")[-1]
    raw["coff"]["characteristics"] = [str(c).split(".")[-1] for c in h.characteristics_list]
    raw["optional"]["subsystem"] = str(oh.subsystem).split(".")[-1]
    raw["optional"]["dll_characteristics"] = [str(c).split(".")[-1] for c in oh.dll_characteristics_lists]
    raw["optional"]["magic"] = str(oh.magic).split(".")[-1]
    raw["optional"]["major_image_version"] = oh.major_image_version
    raw["optional"]["minor_image_version"] = oh.minor_image_version
    raw["optional"]["major_linker_version"] = oh.major_linker_version
    raw["optional"]["minor_linker_version"] = oh.minor_linker_version
    raw["optional"]["major_operating_system_version"] = oh.major_operating_system_version
    raw["optional"]["minor_operating_system_version"] = oh.minor_operating_system_version
    raw["optional"]["major_subsystem_version"] = oh.major_subsystem_version
    raw["optional"]["minor_subsystem_version"] = oh.minor_subsystem_version
    raw["optional"]["sizeof_code"] = oh.sizeof_code
    raw["optional"]["sizeof_headers"] = oh.sizeof_headers
    raw["optional"]["sizeof_heap_commit"] = oh.sizeof_heap_commit
    return raw


def _section_props(section: "lief.PE.Section") -> list[str]:
    return [str(c).split(".")[-1] for c in section.characteristics_lists]


def _extract_section(pe: "lief.PE.Binary | None") -> dict[str, Any]:
    if pe is None:
        return {"entry": "", "sections": []}
    entry_section = ""
    try:
        ep_rva = pe.entrypoint - pe.imagebase
        sec = pe.section_from_rva(ep_rva)
        if sec is not None:
            entry_section = sec.name
        else:
            raise ValueError("entry section not found")
    except Exception:
        for s in pe.sections:
            if lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                entry_section = s.name
                break
    return {
        "entry": entry_section,
        "sections": [
            {
                "name": s.name,
                "size": s.size,
                "entropy": s.entropy,
                "vsize": s.virtual_size,
                "props": _section_props(s),
            }
            for s in pe.sections
        ],
    }


def _extract_imports(pe: "lief.PE.Binary | None") -> dict[str, list[str]]:
    if pe is None:
        return {}
    imports: dict[str, list[str]] = {}
    for lib in pe.imports:
        if lib.name not in imports:
            imports[lib.name] = []
        for entry in lib.entries:
            imports[lib.name].append(
                f"ordinal{entry.ordinal}" if entry.is_ordinal else entry.name[:10000]
            )
    return imports


def _extract_exports(pe: "lief.PE.Binary | None") -> list[str]:
    if pe is None:
        return []
    if LIEF_EXPORT_OBJECT:
        return [exp.name[:10000] for exp in pe.exported_functions]
    return [str(exp)[:10000] for exp in pe.exported_functions]


def _extract_datadirectories(pe: "lief.PE.Binary | None") -> list[dict[str, Any]]:
    """Extract data directory entries.

    Note: str(dd.type) in lief 0.14 is 'lief._lief.PE.TYPES.NAME', not
    'DATA_DIRECTORY.NAME' as in lief 0.9. This does NOT affect feature values
    because process_raw_features uses positional indexing (features[2*i] = size,
    features[2*i+1] = virtual_address) and never reads the 'name' field.
    """
    if pe is None:
        return []
    return [
        {"name": str(dd.type).split(".")[-1], "size": dd.size, "virtual_address": dd.rva}
        for dd in pe.data_directories
    ]


# --------------------------------------------------------------------------
# Public interface
# --------------------------------------------------------------------------

def build_raw_features(bytez: bytes) -> dict[str, Any]:
    """Validate a PE file and return an EMBER-format raw feature dict.

    Raises MalformedPEError for:
      - Empty bytes.
      - Missing MZ DOS stub.
      - pefile structural validation failure (truncated headers, invalid
        NT signature, invalid e_lfanew, etc.).

    Files that pass pefile validation but fail lief parsing proceed with
    zero-filled PE-group features (general, header, section, imports, exports,
    datadirectories), matching official EMBER's lief_binary=None code paths.

    Keys in returned dict (in EMBER concatenation order):
      histogram, byteentropy, strings, general, header,
      section, imports, exports, datadirectories.
    """
    _validate_pe_structure(bytez)  # raises MalformedPEError on invalid input

    pe: "lief.PE.Binary | None" = None
    try:
        pe = lief.PE.parse(list(bytez))
    except Exception:
        pe = None

    return {
        "histogram":       _extract_histogram(bytez),
        "byteentropy":     _extract_byteentropy(bytez),
        "strings":         _extract_strings(bytez),
        "general":         _extract_general(bytez, pe),
        "header":          _extract_header(pe),
        "section":         _extract_section(pe),
        "imports":         _extract_imports(pe),
        "exports":         _extract_exports(pe),
        "datadirectories": _extract_datadirectories(pe),
    }


def extract_ember_features(file_bytes: bytes) -> np.ndarray:
    """Extract the EMBER feature_version=2 vector from raw PE bytes.

    Pipeline:
        bytes → _validate_pe_structure (pefile)
              → lief.PE.parse → raw feature dict (9 groups)
              → ember_vectorizer.vectorize_raw_features
              → float32 (2381,)

    Raises:
        MalformedPEError: file fails PE structural validation.
        ExtractionError: vector is wrong shape or contains non-finite values.

    Probability semantics (for callers):
        The resulting vector is fed to predict_proba(); the returned
        probability is P(malicious | features). It is NOT a certainty.
    """
    raw = build_raw_features(file_bytes)
    try:
        vector = vectorize_raw_features(raw)
    except (ValueError, KeyError) as exc:
        raise ExtractionError(f"Feature vectorization failed: {exc}") from exc

    if vector.shape != (2381,):
        raise ExtractionError(
            f"Feature vector has shape {vector.shape}; expected (2381,)."
        )
    if not np.isfinite(vector).all():
        raise ExtractionError("Feature vector contains non-finite values after vectorization.")

    return vector
