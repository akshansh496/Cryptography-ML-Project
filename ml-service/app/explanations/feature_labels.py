"""Maps EMBER 2018-style feature names to analyst-facing descriptions.

Labels below are documentation for the future explainer. They are not used to
invent predictions. The live explainer will rank features from the loaded model.
"""

from __future__ import annotations

from app.schemas import TopFeature

FEATURE_LABELS: dict[str, str] = {
    "section_entropy_text": "Entropy of the .text section; high values can indicate packing or obfuscation.",
    "histogram": "Byte-value histogram statistics over the raw file.",
    "byteentropy": "Byte-entropy histogram capturing local randomness in the binary.",
    "strings_numstrings": "Count of printable strings extracted from the file.",
    "general_imports": "Number of imported functions listed in the PE import table.",
    "header_coff_timestamp": "COFF header timestamp field from the PE header.",
    "imports": "Imported libraries and APIs used by the binary.",
    "exports": "Exported symbols, if the file is a DLL or similar module.",
    "datadirectories": "PE data-directory entries (imports, resources, relocations, and related tables).",
}


def describe_feature(feature_name: str) -> str:
    return FEATURE_LABELS.get(
        feature_name,
        f"EMBER feature '{feature_name}' contributed to the static assessment.",
    )


def explain_top_features(
    feature_names: list[str],
    importances: list[float],
    *,
    limit: int = 5,
) -> list[TopFeature]:
    """Build the top-N explanation payload once real importances exist."""

    ranked = sorted(
        zip(feature_names, importances, strict=False),
        key=lambda item: item[1],
        reverse=True,
    )[:limit]
    return [
        TopFeature(feature=name, importance=float(score), description=describe_feature(name))
        for name, score in ranked
    ]
