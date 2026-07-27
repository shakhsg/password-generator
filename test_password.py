"""Tests for the Password Generator, Checker, and Validator."""

import pytest
from generator import PasswordGenerator, GeneratorConfig
from checker import StrengthChecker
from validator import PasswordPolicy


# ─── Generator ────────────────────────────────────────────────────────


class TestPasswordGenerator:
    def setup_method(self):
        self.gen = PasswordGenerator()

    def test_generate_default_length(self):
        cfg = GeneratorConfig(length=16, use_symbols=True)
        result = self.gen.generate(cfg)
        assert len(result.password) == 16
        assert result.length == 16

    def test_generate_custom_length(self):
        cfg = GeneratorConfig(length=32, use_symbols=True)
        result = self.gen.generate(cfg)
        assert len(result.password) == 32

    def test_generate_no_symbols(self):
        cfg = GeneratorConfig(length=20, use_symbols=False)
        result = self.gen.generate(cfg)
        # Should contain only letters and digits
        assert all(c.isalnum() for c in result.password)

    def test_generate_exclude_ambiguous(self):
        cfg = GeneratorConfig(
            length=100, use_symbols=False, exclude_ambiguous=True
        )
        result = self.gen.generate(cfg)
        ambiguous = set("O0Il1")
        assert not any(c in ambiguous for c in result.password)

    def test_generate_batch(self):
        cfg = GeneratorConfig(length=12, use_symbols=True)
        results = self.gen.generate_batch(5, cfg)
        assert len(results) == 5
        # All unique (extremely high probability with length 12)
        passwords = [r.password for r in results]
        assert len(set(passwords)) == 5

    def test_entropy_calculation(self):
        cfg = GeneratorConfig(length=16, use_symbols=True)
        result = self.gen.generate(cfg)
        # Charset should be ~94 (26+26+10+32)
        assert result.charset_size >= 62
        assert result.entropy_bits > 80  # 16 * log2(94) ≈ 104

    def test_passphrase_generation(self):
        phrase = self.gen.generate_passphrase(words=4, separator="-")
        parts = phrase.split("-")
        assert len(parts) == 4
        assert all(len(p) > 0 for p in parts)


# ─── Checker ──────────────────────────────────────────────────────────


class TestStrengthChecker:
    def setup_method(self):
        self.checker = StrengthChecker()

    def test_weak_password(self):
        report = self.checker.check("abc")
        assert report.score < 30
        assert report.length == 3

    def test_strong_password(self):
        report = self.checker.check("Tr0ub4dor&3Cr3at!on")
        assert report.score > 60
        assert report.has_upper
        assert report.has_lower
        assert report.has_digit
        assert report.has_symbol

    def test_medium_password(self):
        report = self.checker.check("correcthorsebatterystaple")
        assert report.length == 25
        # Long but no digits or symbols
        assert not report.has_digit

    def test_empty_password(self):
        report = self.checker.check("")
        assert report.length == 0
        assert report.entropy_bits == 0.0

    def test_entropy_consistent(self):
        """Verify that 'aaaa' has low entropy due to charset=26 (lowercase only)."""
        report = self.checker.check("aaaa")
        # 4 chars × log2(26) ≈ 18.8 bits = very low
        assert report.entropy_bits < 30

    def test_crack_time_present(self):
        report = self.checker.check("Str0ng!Pass")
        assert len(report.crack_time_label) > 0
        assert len(report.label) > 0


# ─── Validator ────────────────────────────────────────────────────────


class TestPasswordPolicy:
    def test_standard_policy_pass(self):
        policy = PasswordPolicy.from_preset("standard")
        result = policy.validate("Secure1!")
        assert result.passed is True
        assert len(result.violations) == 0

    def test_standard_policy_fail_too_short(self):
        policy = PasswordPolicy.from_preset("standard")
        result = policy.validate("Ab1!")
        assert result.passed is False

    def test_strong_policy_pass(self):
        policy = PasswordPolicy.from_preset("strong")
        result = policy.validate("C0mpl3x!Passw0rd#Secure")
        assert result.passed is True

    def test_paranoid_policy_pass(self):
        policy = PasswordPolicy.from_preset("paranoid")
        result = policy.validate("S3cure!VeryL0ng#P@ssword2024")
        assert result.passed is True

    def test_paranoid_policy_fail(self):
        policy = PasswordPolicy.from_preset("paranoid")
        result = policy.validate("short")
        assert result.passed is False
        assert len(result.violations) > 0

    def test_enterprise_policy(self):
        policy = PasswordPolicy.from_preset("enterprise")
        result = policy.validate("Enterpr1se!Pass#2024")
        assert result.passed is True