"""
entropy.py — Shannon Entropy Engine
====================================
Implements §2.4.1 of the project report:
  H(X) = -∑ p(xᵢ) × log₂(p(xᵢ))

DGA (Domain Generation Algorithm) detection: machine-generated domains
exhibit high character-level entropy because pseudo-random algorithms
distribute characters uniformly, whereas human-chosen names follow
natural-language phonological rules (low entropy).

Thresholds (Mamun et al., 2016):
  Legitimate domains: 2.5 – 3.5 bits
  DGA domains:        > 3.5 bits  (flagged as suspicious)
  Definite DGA:       > 4.0 bits  (high confidence)
"""

from __future__ import annotations
import math
import re
from dataclasses import dataclass


# ── Thresholds ────────────────────────────────────────────────────────────────
ENTROPY_SAFE      = 3.2   # below → probably human-chosen
ENTROPY_WARN      = 3.55   # above → likely DGA
MIN_LABEL_LEN     = 6     # short labels (e.g. "io", "api") are excluded


@dataclass
class EntropyResult:
    label: str          # SLD analysed
    entropy: float      # Shannon entropy value (bits per char)
    is_dga: bool        # True if entropy exceeds warning threshold
    is_suspicious: bool # True if entropy in the "suspicious" band
    confidence: str     # "low" | "medium" | "high"


def _shannon(s: str) -> float:
    """Compute Shannon entropy of string s in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _clean_label(label: str) -> str:
    """Strip hyphens and digits for a conservative entropy check (false-positive guard)."""
    return re.sub(r"[\d\-]", "", label.lower())


def dga_score(sld: str) -> EntropyResult:
    """
    Analyse the Second-Level Domain (SLD) for DGA patterns.

    Args:
        sld: the second-level domain string, e.g. "paypal" from paypal.com
             or "x7z9q2mwpb" from x7z9q2mwpb.ru

    Returns:
        EntropyResult with entropy value, DGA flag, and confidence level.
    """
    label = sld.lower().strip()

    # Too short to be meaningful
    if len(label) < MIN_LABEL_LEN:
        return EntropyResult(
            label=label, entropy=0.0,
            is_dga=False, is_suspicious=False, confidence="low"
        )

    h = _shannon(label)

    # Compute entropy on the letters-only version as a secondary check.
    # Real DGA domains remain high-entropy even when digits/hyphens removed.
    h_letters = _shannon(_clean_label(label)) if len(_clean_label(label)) >= 4 else h

    is_suspicious = h >= ENTROPY_SAFE
    is_dga        = h >= ENTROPY_WARN and h_letters >= ENTROPY_SAFE

    if is_dga:
        confidence = "high"
    elif is_suspicious:
        confidence = "medium"
    else:
        confidence = "low"

    return EntropyResult(
        label=label,
        entropy=round(h, 4),
        is_dga=is_dga,
        is_suspicious=is_suspicious,
        confidence=confidence,
    )
