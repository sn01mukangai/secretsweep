#!/usr/bin/env python3
"""
secretsweep — Find leaked secrets before they leak.
Fast, focused, developer-friendly secret scanner.

Usage:
    secretsweep [path] [--format json|text|github] [--severity high|medium|all]
    secretsweep --stdin < file.txt
    secretsweep --diff < git diff output>
"""

import re
import sys
import os
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

__version__ = "1.0.0"
__author__ = "CipherShield"

# ─── Secret Patterns ───
# Each pattern: (name, regex, severity, description)
PATTERNS = [
    # Cloud Providers
    ("AWS Access Key", r'AKIA[0-9A-Z]{16}', "high", "AWS access key — can access cloud resources"),
    ("AWS Secret Key", r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "high", "AWS secret key"),
    ("AWS MWS Key", r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "high", "Amazon MWS key"),

    # Google
    ("Google API Key", r'AIza[0-9A-Za-z_-]{35}', "high", "Google API key — can access GCP services"),
    ("Google OAuth Token", r'ya29\.[0-9A-Za-z_-]+', "high", "Google OAuth token"),

    # OpenAI
    ("OpenAI API Key", r'sk-[a-zA-Z0-9]{20,}', "high", "OpenAI/Stripe secret key"),

    # GitHub
    ("GitHub PAT", r'ghp_[A-Za-z0-9]{36}', "high", "GitHub personal access token"),
    ("GitHub OAuth", r'gho_[A-Za-z0-9]{36}', "high", "GitHub OAuth token"),
    ("GitHub App Token", r'(ghu|ghs)_[A-Za-z0-9]{36}', "high", "GitHub App token"),

    # Slack
    ("Slack Token", r'xox[bpoas]-[A-Za-z0-9-]+', "high", "Slack workspace/bot token"),
    ("Slack Webhook", r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', "medium", "Slack webhook URL"),

    # Stripe
    ("Stripe Key", r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}', "high", "Stripe API key"),
    ("Stripe Restricted Key", r'rk_(?:live|test)_[A-Za-z0-9]{20,}', "high", "Stripe restricted key"),

    # Twilio
    ("Twilio API Key", r'SK[a-f0-9]{32}', "high", "Twilio API key"),

    # SendGrid
    ("SendGrid API Key", r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "high", "SendGrid API key"),

    # Mailgun
    ("Mailgun API Key", r'key-[0-9a-zA-Z]{32}', "high", "Mailgun API key"),

    # Firebase
    ("Firebase URL", r'https://[a-z0-9-]+\.firebaseio\.com', "medium", "Firebase Realtime Database URL"),
    ("Firebase API Key", r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}', "high", "Firebase Cloud Messaging key"),

    # Database Connections
    ("MongoDB URI", r'mongodb(\+srv)?://[^\s\'\"<>]+', "high", "MongoDB connection string with credentials"),
    ("MySQL URI", r'mysql://[^\s\'\"<>]+', "high", "MySQL connection string"),
    ("PostgreSQL URI", r'postgres(ql)?://[^\s\'\"<>]+', "high", "PostgreSQL connection string"),
    ("Redis URI", r'redis://[^\s\'\"<>]+', "high", "Redis connection string"),

    # Private Keys
    ("RSA Private Key", r'-----BEGIN RSA PRIVATE KEY-----', "high", "RSA private key"),
    ("EC Private Key", r'-----BEGIN EC PRIVATE KEY-----', "high", "EC private key"),
    ("Private Key (Generic)", r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "high", "Private key"),

    # JWT
    ("JWT Token", r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', "medium", "JSON Web Token"),

    # Generic Patterns
    ("Generic API Key", r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?', "medium", "Possible API key"),
    ("Generic Password", r'(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s\'\"<>]{8,}["\']?', "medium", "Possible hardcoded password"),
    ("Generic Secret", r'(?:secret|token|auth)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?', "medium", "Possible secret/token"),

    # Telegram
    ("Telegram Bot Token", r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}', "high", "Telegram bot token"),

    # Discord
    ("Discord Token", r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}', "high", "Discord bot token"),
    ("Discord Webhook", r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+', "medium", "Discord webhook"),
]

# Directories/files to skip
SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', '__pycache__', '.venv', 'venv',
    'env', '.env', '.tox', '.mypy_cache', '.pytest_cache', 'dist',
    'build', '.next', '.nuxt', 'target', 'bin', 'obj',
}

SKIP_EXTENSIONS = {
    '.min.js', '.min.css', '.map', '.lock', '.log',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.exe', '.dll', '.so', '.dylib',
    '.pyc', '.pyo', '.class', '.o',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.mp3', '.mp4', '.avi', '.mov',
}

# Known false positive patterns
FALSE_POSITIVES = [
    r'example\.com',
    r'your[_-]?api[_-]?key',
    r'your[_-]?secret',
    r'xxx+',
    r'changeme',
    r'placeholder',
    r'test[_-]?key',
    r'dummy',
    r'sample',
    r'REPLACE_ME',
    r'INSERT_.*_HERE',
    r'<.*>',  # XML/HTML tags
]


class Finding:
    """A single secret finding."""

    def __init__(self, file: str, line_num: int, line: str, match: str,
                 pattern_name: str, severity: str, description: str):
        self.file = file
        self.line_num = line_num
        self.line = line.strip()
        self.match = match
        self.pattern_name = pattern_name
        self.severity = severity
        self.description = description
        self.hash = hashlib.md5(f"{file}:{line_num}:{match}".encode()).hexdigest()[:8]

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line_num,
            "pattern": self.pattern_name,
            "severity": self.severity,
            "description": self.description,
            "match": self.match[:20] + "..." if len(self.match) > 20 else self.match,
            "hash": self.hash,
        }

    def to_text(self) -> str:
        sev_icon = {"high": "🔴", "medium": "🟡", "low": "⚪"}.get(self.severity, "❓")
        return (
            f"{sev_icon} [{self.severity.upper()}] {self.pattern_name}\n"
            f"   File: {self.file}:{self.line_num}\n"
            f"   Match: {self.match[:40]}{'...' if len(self.match) > 40 else ''}\n"
            f"   {self.description}\n"
        )

    def to_github(self) -> str:
        return f"::warning file={self.file},line={self.line_num}::[{self.severity.upper()}] {self.pattern_name}: {self.description}"


def is_false_positive(match: str) -> bool:
    """Check if a match is a known false positive."""
    for fp in FALSE_POSITIVES:
        if re.search(fp, match, re.IGNORECASE):
            return True
    return False


def should_skip_file(filepath: str) -> bool:
    """Check if a file should be skipped."""
    path = Path(filepath)
    # Skip hidden dirs
    for part in path.parts:
        if part.startswith('.') and part not in ('.', '..'):
            if part in SKIP_DIRS:
                return True
    # Skip binary extensions
    if path.suffix in SKIP_EXTENSIONS:
        return True
    # Skip if any part of path contains skip dirs
    for skip in SKIP_DIRS:
        if skip in str(path):
            return True
    return False


def scan_file(filepath: str, severity_filter: str = "all") -> List[Finding]:
    """Scan a single file for secrets."""
    findings = []

    if should_skip_file(filepath):
        return findings

    try:
        with open(filepath, 'r', errors='ignore') as f:
            lines = f.readlines()
    except (IOError, OSError):
        return findings

    for line_num, line in enumerate(lines, 1):
        # Skip comments (rough heuristic)
        stripped = line.strip()
        if stripped.startswith(('#', '//', '*', '<!--')):
            continue

        for name, pattern, severity, desc in PATTERNS:
            if severity_filter != "all" and severity != severity_filter:
                continue

            matches = re.finditer(pattern, line)
            for m in matches:
                match_str = m.group(0)
                if not is_false_positive(match_str):
                    findings.append(Finding(
                        file=filepath,
                        line_num=line_num,
                        line=line,
                        match=match_str,
                        pattern_name=name,
                        severity=severity,
                        description=desc,
                    ))

    return findings


def scan_directory(path: str, severity_filter: str = "all") -> List[Finding]:
    """Recursively scan a directory for secrets."""
    all_findings = []
    root = Path(path)

    if root.is_file():
        return scan_file(str(root), severity_filter)

    for filepath in root.rglob('*'):
        if filepath.is_file() and not should_skip_file(str(filepath)):
            findings = scan_file(str(filepath), severity_filter)
            all_findings.extend(findings)

    return all_findings


def scan_stdin(severity_filter: str = "all") -> List[Finding]:
    """Scan stdin for secrets."""
    content = sys.stdin.read()
    findings = []

    for line_num, line in enumerate(content.split('\n'), 1):
        for name, pattern, severity, desc in PATTERNS:
            if severity_filter != "all" and severity != severity_filter:
                continue

            matches = re.finditer(pattern, line)
            for m in matches:
                match_str = m.group(0)
                if not is_false_positive(match_str):
                    findings.append(Finding(
                        file="<stdin>",
                        line_num=line_num,
                        line=line,
                        match=match_str,
                        pattern_name=name,
                        severity=severity,
                        description=desc,
                    ))

    return findings


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings based on hash."""
    seen = set()
    unique = []
    for f in findings:
        if f.hash not in seen:
            seen.add(f.hash)
            unique.append(f)
    return unique


def print_text_report(findings: List[Finding], path: str):
    """Print findings as human-readable text."""
    high = [f for f in findings if f.severity == "high"]
    medium = [f for f in findings if f.severity == "medium"]

    print(f"\n{'='*60}")
    print(f"  secretsweep v{__version__} — Secret Scanner")
    print(f"  Target: {path}")
    print(f"  Time: {datetime.utcnow().isoformat()}Z")
    print(f"{'='*60}\n")

    if not findings:
        print("  ✅ No secrets found! Your code looks clean.\n")
        return

    print(f"  Found {len(findings)} potential secret(s):")
    print(f"  🔴 High: {len(high)}  🟡 Medium: {len(medium)}\n")

    for f in findings:
        print(f.to_text())

    print(f"{'='*60}")
    print(f"  Total: {len(findings)} finding(s)")
    if high:
        print(f"  ⚠️  {len(high)} HIGH severity issue(s) need immediate attention!")
    print(f"{'='*60}\n")


def print_json_report(findings: List[Finding], path: str):
    """Print findings as JSON."""
    report = {
        "tool": "secretsweep",
        "version": __version__,
        "target": path,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total": len(findings),
            "high": len([f for f in findings if f.severity == "high"]),
            "medium": len([f for f in findings if f.severity == "medium"]),
        },
        "findings": [f.to_dict() for f in findings],
    }
    print(json.dumps(report, indent=2))


def print_github_report(findings: List[Finding]):
    """Print findings as GitHub Actions annotations."""
    for f in findings:
        print(f.to_github())


def main():
    parser = argparse.ArgumentParser(
        prog="secretsweep",
        description="Find leaked secrets before they leak. 🔒",
        epilog="Example: secretsweep ./src --format json --severity high",
    )
    parser.add_argument("path", nargs="?", default=".",
                        help="File or directory to scan (default: current directory)")
    parser.add_argument("--format", "-f", choices=["text", "json", "github"],
                        default="text", help="Output format (default: text)")
    parser.add_argument("--severity", "-s", choices=["high", "medium", "all"],
                        default="all", help="Minimum severity to report (default: all)")
    parser.add_argument("--stdin", action="store_true",
                        help="Read from stdin instead of scanning files")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--version", "-v", action="version",
                        version=f"secretsweep {__version__}")

    args = parser.parse_args()

    # Scan
    if args.stdin:
        findings = scan_stdin(args.severity)
    else:
        target = args.path
        if not os.path.exists(target):
            print(f"Error: '{target}' does not exist", file=sys.stderr)
            sys.exit(1)
        findings = scan_directory(target, args.severity)

    # Deduplicate
    findings = deduplicate(findings)

    # Sort by severity (high first)
    findings.sort(key=lambda f: (0 if f.severity == "high" else 1, f.file, f.line_num))

    # Output
    if args.format == "json":
        print_json_report(findings, args.path)
    elif args.format == "github":
        print_github_report(findings)
    else:
        print_text_report(findings, args.path)

    # Exit code: 1 if high severity found, 0 otherwise
    has_high = any(f.severity == "high" for f in findings)
    sys.exit(1 if has_high else 0)


if __name__ == "__main__":
    main()
