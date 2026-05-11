"""
checker.py — Entropy-Based Password Strength Analyser
Scores passwords using Shannon entropy, character variety, and pattern penalties.
"""

import math
import re
from dataclasses import dataclass, field
from enum import Enum

class StrengthLevel(Enum):
    VERY_WEAK  = 0
    WEAK       = 1
    FAIR       = 2
    STRONG     = 3
    VERY_STRONG= 4
    LEGENDARY  = 5

LEVEL_META = {
    StrengthLevel.VERY_WEAK:   {"label": "Very Weak",   "color": "red",          "icon": "💀"},
    StrengthLevel.WEAK:        {"label": "Weak",        "color": "bright_red",   "icon": "🔴"},
    StrengthLevel.FAIR:        {"label": "Fair",        "color": "yellow",       "icon": "🟡"},
    StrengthLevel.STRONG:      {"label": "Strong",      "color": "green",        "icon": "🟢"},
    StrengthLevel.VERY_STRONG: {"label": "Very Strong", "color": "bright_green", "icon": "💪"},
    StrengthLevel.LEGENDARY:   {"label": "Legendary",   "color": "bright_cyan",  "icon": "🛡️ "},
}

@dataclass
class StrengthReport:
    password:         str
    score:            int          # 0–100
    level:            StrengthLevel
    entropy_bits:     float
    charset_size:     int
    length:           int
    has_upper:        bool
    has_lower:        bool
    has_digit:        bool
    has_symbol:       bool
    penalties:        list = field(default_factory=list)
    suggestions:      list = field(default_factory=list)
    crack_time_label: str  = ""

    @property
    def label(self) -> str:
        return LEVEL_META[self.level]["label"]

    @property
    def icon(self) -> str:
        return LEVEL_META[self.level]["icon"]

    @property
    def color(self) -> str:
        return LEVEL_META[self.level]["color"]

    @property
    def bar(self) -> str:
        filled = round(self.score / 5)
        return "█" * filled + "░" * (20 - filled)


class StrengthChecker:
    """
    Analyses password strength using:
      - Shannon entropy (bits)
      - Character class variety bonuses
      - Pattern-based penalties (repeats, sequences, common words)
      - Estimated crack time at 10^12 guesses/sec
    """

    COMMON_PASSWORDS = {
        "password","123456","password1","qwerty","abc123","letmein",
        "monkey","master","dragon","111111","baseball","iloveyou",
        "trustno1","sunshine","princess","welcome","shadow","superman",
        "michael","football","charlie","donald","password123","admin",
    }

    def check(self, password: str) -> StrengthReport:
        length      = len(password)
        has_upper   = bool(re.search(r'[A-Z]', password))
        has_lower   = bool(re.search(r'[a-z]', password))
        has_digit   = bool(re.search(r'\d',    password))
        has_symbol  = bool(re.search(r'[^A-Za-z0-9]', password))

        charset_size = self._calc_charset_size(has_upper, has_lower, has_digit, has_symbol)
        entropy      = length * math.log2(charset_size) if charset_size > 1 else 0.0

        penalties    = []
        suggestions  = []
        score        = self._base_score(entropy)

        # ── Penalties ────────────────────────────────────────────────────────
        if password.lower() in self.COMMON_PASSWORDS:
            score -= 40
            penalties.append("Common password detected")

        if re.search(r'(.)\1{2,}', password):
            score -= 15
            penalties.append("Repeated characters (e.g. 'aaa')")

        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij)', password.lower()):
            score -= 10
            penalties.append("Sequential pattern detected")

        if re.search(r'(qwerty|asdf|zxcv|qazwsx)', password.lower()):
            score -= 10
            penalties.append("Keyboard walk pattern detected")

        if re.search(r'\b(19|20)\d{2}\b', password):
            score -= 5
            penalties.append("Year pattern (e.g. 2023)")

        # ── Suggestions ──────────────────────────────────────────────────────
        if length < 12:
            suggestions.append(f"Increase length to at least 12 (currently {length})")
        if not has_upper:
            suggestions.append("Add uppercase letters (A–Z)")
        if not has_lower:
            suggestions.append("Add lowercase letters (a–z)")
        if not has_digit:
            suggestions.append("Add numbers (0–9)")
        if not has_symbol:
            suggestions.append("Add symbols (!@#$...)")

        score = max(0, min(100, score))
        level = self._score_to_level(score)
        crack = self._crack_time_label(entropy)

        return StrengthReport(
            password=password, score=score, level=level,
            entropy_bits=round(entropy, 2), charset_size=charset_size,
            length=length, has_upper=has_upper, has_lower=has_lower,
            has_digit=has_digit, has_symbol=has_symbol,
            penalties=penalties, suggestions=suggestions,
            crack_time_label=crack,
        )

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _calc_charset_size(upper, lower, digit, symbol) -> int:
        size = 0
        if upper:  size += 26
        if lower:  size += 26
        if digit:  size += 10
        if symbol: size += 32
        return size or 26

    @staticmethod
    def _base_score(entropy: float) -> int:
        if entropy < 28:  return 10
        if entropy < 36:  return 25
        if entropy < 60:  return 50
        if entropy < 80:  return 70
        if entropy < 100: return 85
        if entropy < 128: return 93
        return 100

    @staticmethod
    def _score_to_level(score: int) -> StrengthLevel:
        if score < 20:  return StrengthLevel.VERY_WEAK
        if score < 40:  return StrengthLevel.WEAK
        if score < 60:  return StrengthLevel.FAIR
        if score < 75:  return StrengthLevel.STRONG
        if score < 90:  return StrengthLevel.VERY_STRONG
        return StrengthLevel.LEGENDARY

    @staticmethod
    def _crack_time_label(entropy: float) -> str:
        """Estimate crack time assuming 10^12 guesses/second (high-end GPU cluster)."""
        guesses  = 2 ** entropy
        per_sec  = 1e12
        seconds  = guesses / per_sec
        if seconds < 1:       return "Instant"
        if seconds < 60:      return f"{seconds:.0f} seconds"
        if seconds < 3600:    return f"{seconds/60:.0f} minutes"
        if seconds < 86400:   return f"{seconds/3600:.1f} hours"
        if seconds < 2592000: return f"{seconds/86400:.0f} days"
        if seconds < 3.15e7:  return f"{seconds/2592000:.0f} months"
        if seconds < 3.15e9:  return f"{seconds/3.15e7:.0f} years"
        if seconds < 3.15e12: return f"{seconds/3.15e9:.0f} thousand years"
        if seconds < 3.15e15: return f"{seconds/3.15e12:.0f} million years"
        return "Billions of years ♾️"