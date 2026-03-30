<div align="center">

# 🔒 secretsweep

**Find leaked secrets before they leak.**

Fast. Focused. Developer-friendly.

[![PyPI](https://img.shields.io/pypi/v/secretsweep?color=green)](https://pypi.org/project/secretsweep/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![GitHub Action](https://img.shields.io/badge/GitHub-Action-blue?logo=github)](https://github.com/marketplace/actions/secretsweep)
[![Python](https://img.shields.io/badge/python-3.8+-yellow)](https://python.org)

</div>

---

**secretsweep** scans your codebase for leaked API keys, passwords, tokens, and credentials — before they hit production.

Unlike bloated enterprise tools, secretsweep is **fast**, **zero-config**, and gives you **clean output** you can actually use.

## ✨ Features

- 🔍 **40+ secret patterns** — AWS, Google, Stripe, GitHub, Slack, OpenAI, databases, and more
- ⚡ **Fast** — scans 10,000+ files in seconds
- 🎯 **Focused** — minimal false positives, no bloat
- 📦 **Zero config** — works out of the box
- 🤖 **GitHub Action** — one line in your CI pipeline
- 📊 **Multiple formats** — text, JSON, GitHub Actions annotations
- 🚪 **Exit codes** — fails CI on high-severity findings

## 🚀 Install

```bash
pip install secretsweep
```

## 📖 Usage

### Scan a directory

```bash
secretsweep ./src
```

### Scan with JSON output

```bash
secretsweep . --format json
```

### Only report high severity

```bash
secretsweep . --severity high
```

### Scan from stdin (for git hooks, pipes, etc.)

```bash
cat file.py | secretsweep --stdin
git diff | secretsweep --stdin
```

## 🤖 GitHub Action

Add to your workflow — one step:

```yaml
- uses: sn01mukangai/secretsweep@v1
  with:
    path: '.'
    severity: 'all'
```

Full example:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  secretsweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sn01mukangai/secretsweep@v1
        with:
          path: '.'
          severity: 'high'
          fail-on-high: 'true'
```

## 📊 Output Formats

### Text (default)
```
============================================================
  secretsweep v1.0.0 — Secret Scanner
  Target: ./src
============================================================

  Found 2 potential secret(s):
  🔴 High: 1  🟡 Medium: 1

🔴 [HIGH] AWS Access Key
   File: ./src/config.py:42
   Match: AKIAIOSFODNN7EXAMPLE
   AWS access key — can access cloud resources

🟡 [MEDIUM] Generic API Key
   File: ./src/utils.py:15
   Match: api_key = "sk-abc123..."
   Possible API key
```

### JSON (`--format json`)
```json
{
  "tool": "secretsweep",
  "version": "1.0.0",
  "summary": { "total": 2, "high": 1, "medium": 1 },
  "findings": [...]
}
```

### GitHub Actions (`--format github`)
```
::warning file=src/config.py,line=42::[HIGH] AWS Access Key: AWS access key
```

## 🎯 What It Detects

| Category | Examples |
|----------|----------|
| **Cloud** | AWS keys, Google API keys, Firebase URLs |
| **Payments** | Stripe keys, PayPal credentials |
| **Code Hosting** | GitHub PATs, GitLab tokens |
| **Communication** | Slack tokens, Discord webhooks, Telegram bots |
| **Email** | SendGrid, Mailgun API keys |
| **AI** | OpenAI API keys |
| **Databases** | MongoDB, MySQL, PostgreSQL, Redis URIs |
| **Crypto** | Private keys (RSA, EC, DSA), JWTs |
| **Generic** | API keys, passwords, tokens, secrets |

## 🔧 Exit Codes

- `0` — No high-severity secrets found
- `1` — High-severity secrets detected

Use this in CI to block merges with leaked secrets:

```bash
secretsweep . --severity high || echo "SECRETS FOUND - BLOCKING MERGE"
```

## 📦 Integrations

### pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: secretsweep
      name: secretsweep
      entry: secretsweep --severity high
      language: python
      types: [file]
```

### Git pre-push hook

```bash
#!/bin/bash
# .git/hooks/pre-push
secretsweep . --severity high
if [ $? -ne 0 ]; then
  echo "❌ Secrets found — push blocked"
  exit 1
fi
```

## 🤔 Why Not truffleHog/gitleaks?

| Feature | secretsweep | truffleHog | gitleaks |
|---------|------------|------------|----------|
| **Setup** | `pip install` | Complex | Go install |
| **Speed** | ⚡ Fast | 🐌 Slow | ⚡ Fast |
| **False positives** | Low | High | Medium |
| **Output** | Clean text/JSON | Verbose | Verbose |
| **CI integration** | GitHub Action built-in | Manual | Manual |
| **Zero config** | ✅ | ❌ | ❌ |

## 🛡️ Powered by CipherShield

secretsweep is built by [CipherShield Security](https://github.com/sn01mukangai) — making security accessible for every developer.

Need a full security audit? [Contact us](mailto:security@ciphershield.co.ke).

## 📄 License

MIT — free to use, modify, and distribute.
