"""
validator.py — Regex Pattern Validation & Complexity Enforcement
Validates passwords against configurable policy rules.
"""

import re
from dataclasses import dataclass, field


@dataclass
class PolicyRule:
    name:             str
    pattern:          str          # regex pattern
    description:      str
    required:         bool = True
    invert:           bool = False # True = pattern must NOT match
    case_insensitive: bool = False


@dataclass
class ValidationResult:
    passed:        bool
    violations:    list = field(default_factory=list)
    passed_rules:  list = field(default_factory=list)
    failed_rules:  list = field(default_factory=list)


class PasswordPolicy:
    """
    Enforces password complexity rules using compiled regex patterns.
    Supports custom rule sets for different security contexts.
    """

    # ── Built-in Policies ────────────────────────────────────────────────────

    STANDARD = [
        PolicyRule("min_length",    r'^.{8,}$',           "Minimum 8 characters"),
        PolicyRule("has_uppercase",  r'[A-Z]',             "At least one uppercase letter"),
        PolicyRule("has_lowercase",  r'[a-z]',             "At least one lowercase letter"),
        PolicyRule("has_digit",      r'\d',                "At least one digit"),
    ]

    STRONG = STANDARD + [
        PolicyRule("min_length_12",  r'^.{12,}$',          "Minimum 12 characters"),
        PolicyRule("has_symbol",     r'[^A-Za-z0-9]',      "At least one symbol"),
        PolicyRule("no_spaces",      r'\s',                 "No whitespace", invert=True),
    ]

    PARANOID = STRONG + [
        PolicyRule("min_length_20",  r'^.{20,}$',          "Minimum 20 characters"),
        PolicyRule("no_repeats",     r'(.)\1{2,}',         "No 3+ repeated chars", invert=True),
        PolicyRule("no_sequences",   r'(012|123|234|345|456|567|678|789|abc|bcd)',
                   "No sequential patterns", invert=True),
        PolicyRule("multi_upper",    r'[A-Z].*[A-Z]',      "At least two uppercase letters"),
        PolicyRule("multi_digit",    r'\d.*\d.*\d',        "At least three digits"),
        PolicyRule("multi_symbol",   r'[^A-Za-z0-9].*[^A-Za-z0-9]', "At least two symbols"),
    ]

    ENTERPRISE = [
        PolicyRule("min_length",    r'^.{14,}$',           "Minimum 14 characters"),
        PolicyRule("has_uppercase",  r'[A-Z]',             "Uppercase letter required"),
        PolicyRule("has_lowercase",  r'[a-z]',             "Lowercase letter required"),
        PolicyRule("has_digit",      r'\d',                "Digit required"),
        PolicyRule("has_symbol",     r'[!@#$%^&*\-_=+]',  "Safe symbol required"),
        PolicyRule("no_common_word", r'(?i)(password|admin|login|user|welcome)',
                   "No common words", invert=True),
        PolicyRule("no_spaces",      r'\s',                "No whitespace", invert=True),
    ]

    def __init__(self, rules: list = None, policy_name: str = "custom"):
        self.rules       = rules if rules is not None else self.STRONG
        self.policy_name = policy_name
        self._compiled = [
            (r, re.compile(r.pattern, re.IGNORECASE if r.case_insensitive else 0))
            for r in self.rules
        ]

    # ── Public API ───────────────────────────────────────────────────────────

    def validate(self, password: str) -> ValidationResult:
        violations, passed_rules, failed_rules = [], [], []

        for rule, compiled_re in self._compiled:
            match = bool(compiled_re.search(password))
            passed_this = (not match) if rule.invert else match

            if passed_this:
                passed_rules.append(rule)
            else:
                failed_rules.append(rule)
                if rule.required:
                    violations.append(f"✗ {rule.description}")

        return ValidationResult(
            passed       = len(violations) == 0,
            violations   = violations,
            passed_rules = passed_rules,
            failed_rules = failed_rules,
        )

    @classmethod
    def from_preset(cls, preset: str) -> "PasswordPolicy":
        presets = {
            "standard":   (cls.STANDARD,   "Standard"),
            "strong":     (cls.STRONG,     "Strong"),
            "paranoid":   (cls.PARANOID,   "Paranoid"),
            "enterprise": (cls.ENTERPRISE, "Enterprise"),
        }
        if preset not in presets:
            raise ValueError(f"Unknown preset '{preset}'. Choose from: {list(presets)}")
        rules, name = presets[preset]
        return cls(rules=rules, policy_name=name)