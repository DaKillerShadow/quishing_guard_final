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
    
    # FIX C-2: Replace length-based H_max with the correct alphabet-size constant.
    # The theoretical maximum Shannon entropy is log2(alphabet_size), NOT log2(string_length).
    # Using string_length caused h_norm = 1.0 for any domain with all-unique characters
    # (e.g. "github", "instagram"), producing confirmed false-positive DGA flags.
    _ALPHABET_SIZE = 36          # a-z (26) + 0-9 (10) — full domain-label character set
    H_MAX_ABSOLUTE = math.log2(_ALPHABET_SIZE)  # ≈ 5.170 bits — constant, not length-dependent
    h_norm = entropy / H_MAX_ABSOLUTE            # FIX C-2: correct normalisation

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
    # FIX M-3: Digit ratio alone is not sufficient — require elevated entropy too.
    # Without the entropy guard, "365.com", "mp3.com", "123rf.com" are incorrectly flagged.
    if domain_length > 0 and (digits / domain_length) > 0.3 and entropy > 2.8:  # FIX M-3
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
