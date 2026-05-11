# 🔐 Password Guardian

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Security: secrets](https://img.shields.io/badge/RNG-secrets%20CSPRNG-critical)](https://docs.python.org/3/library/secrets.html)

> **Cryptographically secure password generation + entropy-based strength analysis + regex policy enforcement** — all in a single Python CLI.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔒 **CSPRNG generation** | Uses Python's `secrets` module — OS-level entropy, not `random` |
| 📊 **Entropy scoring** | Shannon entropy in bits, crack-time estimate at 10¹² guesses/sec |
| ✅ **Regex validation** | Standard / Strong / Paranoid / Enterprise policy presets |
| 🎨 **Rich terminal UI** | Full-color interface with strength meter, icons, and tables |
| 🔤 **Passphrase mode** | Memorable multi-word passphrases with configurable separator |
| ⚙️  **Customisable** | Length, charset, exclude ambiguous chars, safe symbols, batch mode |
| 🏗️  **Modular design** | `generator`, `checker`, `validator` — import into your own project |

---

## 📁 Project Structure

```
password-guardian/
├── main.py          CLI entry point + interactive UI
├── generator.py     Secure password generation engine
├── checker.py       Entropy + strength analysis
├── validator.py     Regex-based policy enforcement
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/shakhsg/password-generator.git
cd password-generator

# Install (rich is optional but makes it pretty)
pip install -r requirements.txt

# Run interactive mode
python main.py

# Quick generate a 24-char password
python main.py --generate -l 24

# Check strength of an existing password
python main.py --check

# Generate 10 passwords, safe symbols, no ambiguous chars
python main.py --batch 10 -l 20 --safe-symbols --no-ambiguous

# Generate a 5-word passphrase
python main.py --passphrase -w 5
```

---

## 🧠 How It Works

### Entropy Calculation
```
H = L × log₂(N)

H = entropy in bits
L = password length
N = charset size (26 upper + 26 lower + 10 digits + 32 symbols = 94 max)
```

| Entropy | Strength | Crack time (10¹² /sec) |
|---|---|---|
| < 36 bits | Weak | Seconds–minutes |
| 36–60 bits | Fair | Hours–months |
| 60–80 bits | Strong | Years–centuries |
| 80–100 bits | Very Strong | Millions of years |
| 100+ bits | Legendary | Billions of years |

### Strength Penalties
- Common passwords (built-in blocklist of most-used passwords)
- Repeated characters (`aaa`, `111`)
- Sequential patterns (`123`, `abc`, `qwerty`)
- Keyboard walks (`qazwsx`, `asdfgh`)
- Year patterns (`1999`, `2024`)

### Secure Generation
Uses a **cryptographically secure Fisher-Yates shuffle** over characters drawn from `secrets.choice()`:
1. Pick minimum required chars from each class (`min_upper`, `min_lower`, `min_digit`, `min_symbol`)
2. Fill remaining slots with random chars from the full charset
3. Shuffle the combined list securely
4. Result: every permutation is equally likely

---

## 🔧 Use as a Library

```python
from generator import PasswordGenerator, GeneratorConfig
from checker   import StrengthChecker
from validator import PasswordPolicy

# Generate
gen    = PasswordGenerator()
result = gen.generate(GeneratorConfig(length=20, use_safe_symbols=True))
print(result.password)        # e.g. Xk#9mP!vQn@2rLwY#8dT
print(result.entropy_bits)    # e.g. 131.1

# Check
checker = StrengthChecker()
report  = checker.check(result.password)
print(report.label)           # Very Strong
print(report.crack_time_label)# Millions of years

# Validate
policy = PasswordPolicy.from_preset("enterprise")
result = policy.validate(result.password)
print(result.passed)          # True / False
print(result.violations)      # List of failed rules
```

---

## 📋 CLI Reference

```
python main.py [OPTIONS]

Options:
  --generate          Quick generate mode
  --check             Check an existing password's strength
  --passphrase        Generate a passphrase
  --batch N           Generate N passwords at once
  -l, --length N      Password length (default: 16)
  --no-symbols        Exclude all symbols
  --safe-symbols      Use safe symbols only (!@#$%^&*-_=+)
  --no-ambiguous      Exclude O, 0, I, l, 1
  -w, --words N       Number of words in passphrase (default: 4)
```

---

## 🔒 Security Notes

- **Never** uses Python's `random` module — `secrets` is used exclusively
- Passwords are never logged, stored, or transmitted
- Minimum entropy target: **80 bits** (Very Strong) for sensitive accounts
- Passphrase entropy: ~6.4 bits/word × 4 words ≈ 25.5 bits (use 6+ words for secrets)

---

## 📜 License

MIT © 2024 [shakhsg](https://github.com/shakhsg) — free to use, modify, and distribute.