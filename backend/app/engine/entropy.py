"""
entropy.py — Shannon Entropy Engine
====================================
Implements §2.4.1 of the project report:
  H(X) = -∑ p(xᵢ) × log₂(p(xᵢ))

DGA (Domain Generation Algorithm) detection: machine-generated domains
exhibit high character-level entropy because pseudo-random algorithms
distribute characters uniformly, whereas human-chosen names follow
natural-language phonological rules (low entropy).

Upgraded to use Smart Thresholds, Digit-Ratios, and Normalized 
Entropy (H / H_max) to accurately detect complex DGA patterns.
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
    is_dga: bool        # True if entropy/ratio exceeds DGA thresholds
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
    Analyse the Second-Level Domain (SLD) for DGA patterns using 
    Absolute Entropy, Normalized Entropy, and Alphanumeric Ratios.
    """
    # Fallback to prevent AttributeError if upstream parser passes None
    if not sld:
        return EntropyResult(label="", entropy=0.0, is_dga=False, is_suspicious=False, confidence="low")

    label = sld.lower().strip()
    domain_length = len(label)

    # Too short to be meaningful
    if domain_length < MIN_LABEL_LEN:
        return EntropyResult(label=label, entropy=0.0, is_dga=False, is_suspicious=False, confidence="low")

    # Calculate raw entropy
    entropy = _shannon(label)
    
    # Calculate normalized entropy (Theoretical max for this string length)
    h_max = math.log2(domain_length) if domain_length > 1 else 1.0
    h_norm = entropy / h_max  

    is_dga = False
    is_suspicious = False

    # --- THE FIX: Smarter Evaluation ---
    
    # Check 1: Absolute high entropy (catches long random strings)
    if entropy > 3.5:
        is_dga = True
        
    # Check 2: Maxed-out entropy for short strings (Catches x7z9q2mwpb)
    elif domain_length >= 8 and entropy >= 3.2:
        is_dga = True
        
    # Check 3: High digit/consonant ratio (Catches typical DGA behavior)
    digits = sum(c.isdigit() for c in label)
    if domain_length > 0 and (digits / domain_length) > 0.3: # If more than 30% numbers
        is_dga = True

    # Check 4: Normalized baseline (Fallback for weird edge cases)
    if h_norm >= NORM_WARN:
        is_dga = True
    elif h_norm >= NORM_SAFE:
        is_suspicious = True

    # Assign confidence based on flags
    if is_dga:
        is_suspicious = True
        confidence = "high"
    elif is_suspicious:
        confidence = "medium"
    else:
        confidence = "low"

    return EntropyResult(
        label=label,
        entropy=round(entropy, 4),
        is_dga=is_dga,
        is_suspicious=is_suspicious,
        confidence=confidence,
    )