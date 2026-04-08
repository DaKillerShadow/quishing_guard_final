"""
entropy.py — Shannon Entropy Engine
====================================
Implements §2.4.1 of the project report:
  H(X) = -∑ p(xᵢ) × log₂(p(xᵢ))

DGA (Domain Generation Algorithm) detection: machine-generated domains
exhibit high character-level entropy because pseudo-random algorithms
distribute characters uniformly, whereas human-chosen names follow
natural-language phonological rules (low entropy).

Upgraded to use Normalized Entropy (H / H_max) to accurately detect 
DGA patterns.
"""

from __future__ import annotations
import math
import re
import collections
from dataclasses import dataclass


# ── Thresholds ────────────────────────────────────────────────────────────────
MIN_LABEL_LEN = 6     # short labels (e.g. "io", "api") are excluded
NORM_SAFE     = 0.85  # below → human-chosen
NORM_WARN     = 0.92  # above → likely DGA


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
    
    n = len(s)
    # Optimized frequency counting using CPython's built-in Counter
    freq = collections.Counter(s)
    
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
    # Fallback to prevent AttributeError if upstream parser passes None
    if not sld:
        return EntropyResult(
            label="", entropy=0.0,
            is_dga=False, is_suspicious=False, confidence="low"
        )

    label = sld.lower().strip()

    # Too short to be meaningful
    if len(label) < MIN_LABEL_LEN:
        return EntropyResult(
            label=label, entropy=0.0,
            is_dga=False, is_suspicious=False, confidence="low"
        )

    # Calculate raw entropy
    h = _shannon(label)
    
    # Calculate normalized entropy
    h_max = math.log2(len(set(label))) if len(set(label)) > 1 else 1.0
    h_norm = h / h_max  # Normalized: 0.0 (one char repeated) → 1.0 (perfectly random)

    # Compute entropy on the letters-only version as a secondary check.
    # Real DGA domains remain high-entropy even when digits/hyphens removed.
    cleaned_label = _clean_label(label)
    h_letters = _shannon(cleaned_label) if len(cleaned_label) >= 4 else h

    # ✅ FIXED: Using only the normalized logic, removed the old raw entropy overrides
    is_suspicious = h_norm >= NORM_SAFE
    is_dga        = h_norm >= NORM_WARN and (h_letters / h_max) >= NORM_SAFE

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