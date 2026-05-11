"""
generator.py — Secure Password Generation Engine
Uses Python's `secrets` module (CSPRNG) for cryptographic randomness.
"""

import secrets
import string
import math
from dataclasses import dataclass
from typing import Optional

PASSPHRASE_POOL = [
    "apple","bridge","canyon","dragon","eagle","forest","glacier","harbor",
    "island","jungle","kernel","lemon","maple","nebula","ocean","parrot",
    "quartz","river","sunset","tiger","umbrella","valley","walrus","xenon",
    "amber","bronze","cobalt","denim","ember","fable","gravel","honey",
    "jade","karma","lime","mango","navy","olive","pearl","ruby","sage",
    "teal","venom","wheat","azure","blaze","crisp","echo","fizzy","nimble",
    "orbit","puzzle","quirky","rustic","stormy","vivid","wistful","bold",
    "crystal","delta","granite","heron","iron","jasper","lava","meteor",
    "nova","opal","prism","raven","sphinx","topaz","vortex","cipher",
    "daemon","flux","hash","loop","module","node","proxy","queue","stack",
]

CHARSETS = {
    "uppercase":    string.ascii_uppercase,
    "lowercase":    string.ascii_lowercase,
    "digits":       string.digits,
    "symbols":      string.punctuation,
    "ambiguous":    "O0Il1",
    "safe_symbols": "!@#$%^&*-_=+",
}

@dataclass
class GeneratorConfig:
    length:            int  = 16
    use_uppercase:     bool = True
    use_lowercase:     bool = True
    use_digits:        bool = True
    use_symbols:       bool = True
    use_safe_symbols:  bool = False
    exclude_ambiguous: bool = False
    custom_exclude:    str  = ""
    min_uppercase:     int  = 1
    min_lowercase:     int  = 1
    min_digits:        int  = 1
    min_symbols:       int  = 1
    custom_charset:    Optional[str] = None

@dataclass
class GeneratedPassword:
    password:       str
    charset_size:   int
    entropy_bits:   float
    length:         int
    charset_used:   str
    meets_minimums: bool = True

class PasswordGenerator:
    """
    Cryptographically secure password generator.
    Guarantees minimum character-class requirements via secure Fisher-Yates shuffle.
    """
    def __init__(self, config: Optional[GeneratorConfig] = None):
        self.config = config or GeneratorConfig()

    def generate(self, config: Optional[GeneratorConfig] = None) -> GeneratedPassword:
        cfg     = config or self.config
        charset = self._build_charset(cfg)
        if not charset:
            raise ValueError("No characters available — check configuration.")
        if cfg.length < 4:
            raise ValueError("Password length must be at least 4.")
        password = self._generate_with_minimums(charset, cfg)
        entropy  = cfg.length * math.log2(len(charset)) if len(charset) > 1 else 0.0
        return GeneratedPassword(
            password=password, charset_size=len(charset),
            entropy_bits=entropy, length=cfg.length,
            charset_used=charset, meets_minimums=True,
        )

    def generate_batch(self, count: int = 5,
                       config: Optional[GeneratorConfig] = None) -> list:
        return [self.generate(config) for _ in range(count)]

    def generate_passphrase(self, words: int = 4,
                             separator: str = "-",
                             capitalize: bool = True) -> str:
        chosen = [secrets.choice(PASSPHRASE_POOL) for _ in range(words)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]
        return separator.join(chosen)

    def _build_charset(self, cfg: GeneratorConfig) -> str:
        if cfg.custom_charset:
            return cfg.custom_charset
        pool = ""
        if cfg.use_uppercase: pool += CHARSETS["uppercase"]
        if cfg.use_lowercase: pool += CHARSETS["lowercase"]
        if cfg.use_digits:    pool += CHARSETS["digits"]
        if cfg.use_symbols:
            pool += CHARSETS["safe_symbols"] if cfg.use_safe_symbols else CHARSETS["symbols"]
        if cfg.exclude_ambiguous:
            pool = "".join(c for c in pool if c not in CHARSETS["ambiguous"])
        if cfg.custom_exclude:
            pool = "".join(c for c in pool if c not in cfg.custom_exclude)
        seen, unique = set(), []
        for ch in pool:
            if ch not in seen:
                seen.add(ch)
                unique.append(ch)
        return "".join(unique)

    def _generate_with_minimums(self, charset: str, cfg: GeneratorConfig) -> str:
        mandatory = []
        def pick_min(cls_chars: str, minimum: int):
            available = [c for c in cls_chars if c in charset]
            if available:
                mandatory.extend(secrets.choice(available) for _ in range(minimum))
        if not cfg.custom_charset:
            if cfg.use_uppercase: pick_min(CHARSETS["uppercase"], cfg.min_uppercase)
            if cfg.use_lowercase: pick_min(CHARSETS["lowercase"], cfg.min_lowercase)
            if cfg.use_digits:    pick_min(CHARSETS["digits"],    cfg.min_digits)
            if cfg.use_symbols:
                sym = CHARSETS["safe_symbols"] if cfg.use_safe_symbols else CHARSETS["symbols"]
                pick_min(sym, cfg.min_symbols)
        remaining = max(cfg.length - len(mandatory), 0)
        filler    = [secrets.choice(charset) for _ in range(remaining)]
        combined  = (mandatory + filler)[:cfg.length]
        for i in range(len(combined) - 1, 0, -1):   # Secure Fisher-Yates
            j = secrets.randbelow(i + 1)
            combined[i], combined[j] = combined[j], combined[i]
        return "".join(combined)