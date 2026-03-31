<div align="center">

# 🔒 secretsweep

**Find leaked secrets before they leak.**

Fast. Smart. Written in Rust.

[![Release](https://img.shields.io/github/v/release/sn01mukangai/secretsweep?color=green)](https://github.com/sn01mukangai/secretsweep/releases)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue?logo=github)](https://github.com/marketplace/actions/secretsweep)
[![Rust](https://img.shields.io/badge/Rust-1.94+-orange?logo=rust)](https://rust-lang.org)

</div>

---

**secretsweep** scans your codebase for leaked API keys, passwords, tokens, and credentials — before they hit production.

## ⚡ Why secretsweep?

| Feature | secretsweep | truffleHog | gitleaks |
|---------|------------|------------|----------|
| **Language** | Rust 🦀 | Python/Go | Go |
| **Binary size** | 2.3 MB | ~50 MB | ~15 MB |
| **False positives** | Low (quote-aware) | High | Medium |
| **Entropy detection** | ✅ Shannon entropy | ✅ | ❌ |
| **Git diff mode** | ✅ | ✅ | ✅ |
| **Zero dependencies** | ✅ Single binary | ❌ | ✅ |
| **Speed** | ⚡ Fast | 🐌 Slow | ⚡ Fast |

## 🚀 Install

### Pre-built binary

```bash
# Linux x86_64
curl -sSL https://github.com/sn01mukangai/secretsweep/releases/latest/download/secretsweep-x86_64-unknown-linux-gnu.zip -o secretsweep.zip
unzip secretsweep.zip
chmod +x secretsweep
sudo mv secretsweep /usr/local/bin/

# macOS (Intel)
curl -sSL https://github.com/sn01mukangai/secretsweep/releases/latest/download/secretsweep-x86_64-apple-darwin.zip -o secretsweep.zip

# macOS (Apple Silicon)
curl -sSL https://github.com/sn01mukangai/secretsweep/releases/latest/download/secretsweep-aarch64-apple-darwin.zip -o secretsweep.zip
```

### Build from source

```bash
git clone https://github.com/sn01mukangai/secretsweep.git
cd secretsweep
cargo build --release
cp target/release/secretsweep /usr/local/bin/
```

## 📖 Usage

### Scan a project

```bash
secretsweep ./src
```

### Output formats

```bash
secretsweep . --format text      # Human-readable (default)
secretsweep . --format json      # JSON for automation
secretsweep . --format github    # GitHub Actions annotations
```

### Filter by severity

```bash
secretsweep . --severity high    # Only high severity
secretsweep . --severity medium  # Medium and above
secretsweep . --severity all     # Everything (default)
```

### Scan git changes (perfect for CI)

```bash
secretsweep --diff               # Scan only changed lines
```

### Entropy detection

```bash
secretsweep . --entropy 4.5      # Minimum Shannon entropy (default: 4.5)
secretsweep . --no-entropy       # Disable entropy detection
```

### Scan from stdin

```bash
cat file.py | secretsweep --stdin
git diff | secretsweep --stdin
```

## 🤖 GitHub Action

Add to your workflow:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  secretsweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sn01mukangai/secretsweep@v2
        with:
          path: '.'
          severity: 'high'
          format: 'github'
```

## 📊 What It Detects

| Category | Examples | Patterns |
|----------|----------|----------|
| **Cloud** | AWS keys, Google API keys, Firebase | 6 |
| **Payments** | Stripe, OpenAI | 2 |
| **Code Hosting** | GitHub PAT, OAuth, App tokens | 3 |
| **Communication** | Slack, Discord, Telegram | 5 |
| **Email** | SendGrid, Mailgun | 2 |
| **Databases** | MongoDB, MySQL, PostgreSQL, Redis | 4 |
| **Private Keys** | RSA, EC, Generic | 3 |
| **JWT** | JSON Web Tokens | 1 |
| **Generic** | API keys, passwords, tokens | 4 |
| **Entropy** | Unknown secrets (high entropy strings) | ✨ |

**Total: 30+ named patterns + entropy detection**

## 🧠 How It Works

### Pattern Matching
Each secret type has a carefully crafted regex pattern. Patterns are tested against every line of every file.

### Entropy Detection
Strings in quotes with high [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) (≥ 4.5 bits/char) are flagged as potential secrets — even if they don't match a known pattern.

### False Positive Reduction
- **Quote-aware filtering** — regex patterns in source code are ignored
- **Comment skipping** — lines starting with `#`, `//`, `*` are skipped
- **Known FP database** — common false positives (example.com, placeholder, etc.)
- **Binary file skipping** — images, archives, executables are skipped

## 🔧 Exit Codes

- `0` — No high-severity secrets found
- `1` — High-severity secrets detected

Use in CI to block merges:

```bash
secretsweep . --severity high || echo "❌ Secrets found — merge blocked"
```

## 📦 Integrations

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secretsweep
        name: secretsweep
        entry: secretsweep --severity high
        language: system
        types: [file]
```

### Git pre-push hook

```bash
#!/bin/bash
# .git/hooks/pre-push
secretsweep . --severity high --no-entropy
if [ $? -ne 0 ]; then
  echo "❌ High-severity secrets found — push blocked"
  exit 1
fi
```

### VS Code Task

```json
{
  "label": "Secret Sweep",
  "type": "shell",
  "command": "secretsweep",
  "args": ["${workspaceFolder}", "--format", "text"],
  "problemMatcher": []
}
```

## 📋 JSON Output Schema

```json
{
  "tool": "secretsweep",
  "version": "2.1.0",
  "target": "./src",
  "timestamp": "2026-03-31",
  "files_scanned": 42,
  "summary": {
    "total": 3,
    "high": 2,
    "medium": 1
  },
  "findings": [
    {
      "file": "./src/config.py",
      "line": 42,
      "pattern": "AWS Access Key",
      "severity": "high",
      "description": "AWS access key",
      "match": "AKIAIOSFODNN7EXAMPLE"
    }
  ]
}
```

## 🗺️ Roadmap

- [x] Core secret scanning
- [x] Entropy detection
- [x] False positive reduction
- [x] GitHub Action
- [x] Cross-platform binaries
- [x] JSON/text/GitHub output
- [ ] Custom pattern file (`.secretsweep.toml`)
- [ ] Ignore file (`.secretsweepignore`)
- [ ] SARIF output (GitHub Code Scanning)
- [ ] VS Code extension
- [ ] Pre-commit hook package

## 🛡️ Powered by CipherShield

secretsweep is built by [CipherShield Security](https://github.com/sn01mukangai) — making security accessible for every developer.

Need a full security audit? [Contact us](mailto:security@ciphershield.co.ke).

## 📄 License

MIT — free to use, modify, and distribute.
