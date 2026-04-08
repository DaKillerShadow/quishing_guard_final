"""
entropy.py — Shannon Entropy Engine
====================================
Implements §2.4.1 of the project report:
  H(X) = -∑ p(xᵢ) × log₂(p(xᵢ))

Upgraded to use Normalized Entropy (H / H_max) to accurately detect 
DGA patterns in short domains (< 12 characters) that are mathematically 
bounded by log2(N).
"""

from __future__ import annotations
import math
import re
import collections
from dataclasses import dataclass

# ── Thresholds ────────────────────────────────────────────────────────────────
# Using ratios (0.0 to 1.0) makes the engine length-agnostic.
# 0.85 means the string is 85% as random as mathematically possible for its length.
ENTROPY_RATIO_SAFE = 0.75   
ENTROPY_RATIO_WARN = 0.85   
MIN_LABEL_LEN      = 6     

@dataclass
class EntropyResult:
    label: str          
    entropy: float      # Raw Shannon entropy (kept for scorer.py UI metrics)
    normalized: float   # Ratio of (entropy / max_possible_entropy)
    is_dga: bool        # The definitive boolean for the heuristics engine
    is_suspicious: bool 
    confidence: str     

def _shannon_data(s: str) -> tuple[float, float]:
    """
    Computes both raw Shannon entropy and the normalized entropy ratio.
    Returns: (raw_entropy, normalized_ratio)
    """
    if not s:
        return 0.0, 0.0
    
    n = len(s)
    freq = collections.Counter(s)
    
    raw_entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
    
    # Maximum possible entropy for a string of length N is log2(N)
    # E.g., for a 10 char string, max entropy is ~3.32
    max_entropy = math.log2(n) if n > 1 else 1.0
    
    normalized = raw_entropy / max_entropy if max_entropy > 0 else 0.0
    
    return raw_entropy, normalized

def _clean_label(label: str) -> str:
    """Strip hyphens and digits for a conservative entropy check (false-positive guard)."""
    return re.sub(r"[\d\-]", "", label.lower())

def dga_score(sld: str) -> EntropyResult:
    """
    Analyse the Second-Level Domain (SLD) for DGA patterns using Normalized Entropy.
    """
    if not sld:
        return EntropyResult(label="", entropy=0.0, normalized=0.0, is_dga=False, is_suspicious=False, confidence="low")

    label = sld.lower().strip()

    if len(label) < MIN_LABEL_LEN:
        return EntropyResult(label=label, entropy=0.0, normalized=0.0, is_dga=False, is_suspicious=False, confidence="low")

    # Get raw and normalized entropy for the full SLD
    raw_h, norm_h = _shannon_data(label)

    # Secondary check on cleaned label to prevent false positives on numbers
    cleaned_label = _clean_label(label)
    if len(cleaned_label) >= 4:
        _, norm_h_letters = _shannon_data(cleaned_label)
    else:
        norm_h_letters = norm_h

    # Use the normalized ratio for thresholding instead of raw bits
    is_suspicious = norm_h >= ENTROPY_RATIO_SAFE
    is_dga        = norm_h >= ENTROPY_RATIO_WARN and norm_h_letters >= ENTROPY_RATIO_SAFE

    if is_dga:
        confidence = "high"
    elif is_suspicious:
        confidence = "medium"
    else:
        confidence = "low"

    return EntropyResult(
        label=label,
        entropy=round(raw_h, 4),
        normalized=round(norm_h, 4),
        is_dga=is_dga,
        is_suspicious=is_suspicious,
        confidence=confidence,
    )

