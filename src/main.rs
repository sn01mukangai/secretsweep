use clap::Parser;
use colored::*;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use walkdir::WalkDir;

const VERSION: &str = "2.1.0";

#[derive(Parser)]
#[command(name = "secretsweep", version = VERSION, about = "Find leaked secrets before they leak. 🔒")]
struct Cli {
    /// Path to scan (file or directory)
    #[arg(default_value = ".")]
    path: String,

    /// Output format
    #[arg(short, long, default_value = "text", value_parser = ["text", "json", "github"])]
    format: String,

    /// Minimum severity to report
    #[arg(short, long, default_value = "all", value_parser = ["high", "medium", "all"])]
    severity: String,

    /// Read from stdin
    #[arg(long)]
    stdin: bool,

    /// Scan only git diff (changed lines)
    #[arg(long)]
    diff: bool,

    /// Minimum entropy threshold for generic detection (0.0-8.0, default 4.5)
    #[arg(long, default_value = "4.5")]
    entropy: f64,

    /// Skip entropy-based detection
    #[arg(long)]
    no_entropy: bool,
}

#[derive(Clone, Serialize)]
struct Finding {
    file: String,
    line: usize,
    pattern: String,
    severity: String,
    description: String,
    #[serde(rename = "match")]
    matched: String,
}

struct SecretPattern {
    name: &'static str,
    pattern: &'static str,
    severity: &'static str,
    description: &'static str,
    /// If true, skip when match is inside quotes (likely a pattern, not a secret)
    skip_in_patterns: bool,
}

fn patterns() -> Vec<SecretPattern> {
    vec![
        // Cloud — high confidence, never skip
        SecretPattern { name: "AWS Access Key", pattern: r"AKIA[0-9A-Z]{16}", severity: "high", description: "AWS access key", skip_in_patterns: false },
        SecretPattern { name: "Google API Key", pattern: r"AIza[0-9A-Za-z_-]{35}", severity: "high", description: "Google API key", skip_in_patterns: false },
        SecretPattern { name: "Google OAuth", pattern: r"ya29\.[0-9A-Za-z_-]+", severity: "high", description: "Google OAuth token", skip_in_patterns: false },
        // Payments
        SecretPattern { name: "Stripe Key", pattern: r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}", severity: "high", description: "Stripe API key", skip_in_patterns: false },
        SecretPattern { name: "OpenAI/Stripe Secret", pattern: r"sk-[a-zA-Z0-9]{20,}", severity: "high", description: "OpenAI/Stripe secret key", skip_in_patterns: false },
        // Code Hosting
        SecretPattern { name: "GitHub PAT", pattern: r"ghp_[A-Za-z0-9]{36}", severity: "high", description: "GitHub personal access token", skip_in_patterns: false },
        SecretPattern { name: "GitHub OAuth", pattern: r"gho_[A-Za-z0-9]{36}", severity: "high", description: "GitHub OAuth token", skip_in_patterns: false },
        SecretPattern { name: "GitHub App", pattern: r"(?:ghu|ghs)_[A-Za-z0-9]{36}", severity: "high", description: "GitHub App token", skip_in_patterns: false },
        // Communication
        SecretPattern { name: "Slack Token", pattern: r"xox[bpoas]-[A-Za-z0-9-]+", severity: "high", description: "Slack workspace/bot token", skip_in_patterns: false },
        SecretPattern { name: "Slack Webhook", pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", severity: "medium", description: "Slack webhook URL", skip_in_patterns: false },
        SecretPattern { name: "Discord Token", pattern: r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}", severity: "high", description: "Discord bot token", skip_in_patterns: false },
        SecretPattern { name: "Discord Webhook", pattern: r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", severity: "medium", description: "Discord webhook", skip_in_patterns: false },
        SecretPattern { name: "Telegram Bot", pattern: r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", severity: "high", description: "Telegram bot token", skip_in_patterns: false },
        // Email
        SecretPattern { name: "SendGrid", pattern: r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", severity: "high", description: "SendGrid API key", skip_in_patterns: false },
        SecretPattern { name: "Mailgun", pattern: r"key-[0-9a-zA-Z]{32}", severity: "high", description: "Mailgun API key", skip_in_patterns: false },
        // Twilio
        SecretPattern { name: "Twilio", pattern: r"SK[a-f0-9]{32}", severity: "high", description: "Twilio API key", skip_in_patterns: false },
        // Firebase
        SecretPattern { name: "Firebase URL", pattern: r"https://[a-z0-9-]+\.firebaseio\.com", severity: "medium", description: "Firebase Realtime Database", skip_in_patterns: false },
        SecretPattern { name: "Firebase FCM", pattern: r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}", severity: "high", description: "Firebase Cloud Messaging key", skip_in_patterns: false },
        // Database — skip when inside quotes (often regex patterns)
        SecretPattern { name: "MongoDB URI", pattern: r"mongodb(\+srv)?://\S+", severity: "high", description: "MongoDB connection string", skip_in_patterns: true },
        SecretPattern { name: "MySQL URI", pattern: r"mysql://\S+", severity: "high", description: "MySQL connection string", skip_in_patterns: true },
        SecretPattern { name: "PostgreSQL URI", pattern: r"postgres(ql)?://\S+", severity: "high", description: "PostgreSQL connection string", skip_in_patterns: true },
        SecretPattern { name: "Redis URI", pattern: r"redis://\S+", severity: "high", description: "Redis connection string", skip_in_patterns: true },
        // Keys
        SecretPattern { name: "RSA Private Key", pattern: r"-----BEGIN RSA PRIVATE KEY-----", severity: "high", description: "RSA private key", skip_in_patterns: false },
        SecretPattern { name: "EC Private Key", pattern: r"-----BEGIN EC PRIVATE KEY-----", severity: "high", description: "EC private key", skip_in_patterns: false },
        SecretPattern { name: "Private Key", pattern: r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", severity: "high", description: "Private key", skip_in_patterns: false },
        // JWT
        SecretPattern { name: "JWT Token", pattern: r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}", severity: "medium", description: "JSON Web Token", skip_in_patterns: false },
        // Generic — skip when inside quotes
        SecretPattern { name: "Generic API Key", pattern: r"[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[=:]\s*[A-Za-z0-9_\-]{16,}", severity: "medium", description: "Possible API key", skip_in_patterns: true },
        SecretPattern { name: "Generic Password", pattern: r"[Pp]assword\s*[=:]\s*[^\s<>]{8,}", severity: "medium", description: "Possible hardcoded password", skip_in_patterns: true },
        SecretPattern { name: "Generic Secret", pattern: r"[Ss]ecret\s*[=:]\s*[A-Za-z0-9_\-]{16,}", severity: "medium", description: "Possible secret", skip_in_patterns: true },
        SecretPattern { name: "Generic Token", pattern: r"[Tt]oken\s*[=:]\s*[A-Za-z0-9_\-]{16,}", severity: "medium", description: "Possible token", skip_in_patterns: true },
    ]
}

const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "target", "bin", "obj", ".cargo",
    "go/pkg/mod", ".npm",
];

const SKIP_EXTS: &[&str] = &[
    ".min.js", ".min.css", ".map", ".lock", ".log",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class", ".o",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".mp3", ".mp4", ".avi", ".mov",
];

const FALSE_POSITIVES: &[&str] = &[
    "example\\.com", "your[_-]?api[_-]?key", "your[_-]?secret",
    "xxx+", "changeme", "placeholder", "test[_-]?key",
    "dummy", "sample", "REPLACE_ME", "INSERT_.*_HERE",
];

/// Calculate Shannon entropy of a string
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn should_skip(path: &str) -> bool {
    let p = Path::new(path);
    if let Some(ext) = p.extension() {
        let ext_str = format!(".{}", ext.to_string_lossy());
        if SKIP_EXTS.iter().any(|e| ext_str.ends_with(e)) {
            return true;
        }
    }
    for comp in p.components() {
        let s = comp.as_os_str().to_string_lossy();
        if s.starts_with('.') && s.len() > 1 {
            return true;
        }
        if SKIP_DIRS.iter().any(|d| s.contains(d)) {
            return true;
        }
    }
    false
}

fn is_false_positive(m: &str) -> bool {
    let fps: Vec<Regex> = FALSE_POSITIVES.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();
    fps.iter().any(|re| re.is_match(m))
}

/// Check if a match is inside quotes on the line (likely a regex pattern or example)
fn is_inside_quotes(line: &str, matched: &str) -> bool {
    if let Some(pos) = line.find(matched) {
        let before = &line[..pos];
        let after = &line[pos + matched.len()..];
        // Check for quote pairs
        let single_quotes_before = before.matches('\'').count();
        let double_quotes_before = before.matches('"').count();
        let single_quotes_after = after.matches('\'').count();
        let double_quotes_after = after.matches('"').count();
        // If odd number of quotes before and after, we're inside quotes
        if (single_quotes_before % 2 == 1 && single_quotes_after % 2 == 1) ||
           (double_quotes_before % 2 == 1 && double_quotes_after % 2 == 1) {
            return true;
        }
    }
    false
}

fn scan_content(content: &str, file: &str, severity_filter: &str, compiled: &[Regex], min_entropy: f64, no_entropy: bool) -> Vec<Finding> {
    let pats = patterns();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Skip comments
        if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("<!--") {
            continue;
        }

        // Pattern-based detection
        for (i, pat) in pats.iter().enumerate() {
            if severity_filter != "all" && pat.severity != severity_filter {
                continue;
            }
            for m in compiled[i].find_iter(line) {
                let matched = m.as_str();
                if is_false_positive(matched) {
                    continue;
                }
                // Skip if pattern is meant to be inside quotes and it is
                if pat.skip_in_patterns && is_inside_quotes(line, matched) {
                    continue;
                }
                // Also skip if line looks like a grep/search pattern (contains \S, \s, etc.)
                if pat.skip_in_patterns && (matched.contains(r"\S") || matched.contains(r"\s") || matched.contains("[^")) {
                    continue;
                }
                let key = format!("{}:{}:{}", file, line_num + 1, matched);
                if seen.insert(key) {
                    findings.push(Finding {
                        file: file.to_string(),
                        line: line_num + 1,
                        pattern: pat.name.to_string(),
                        severity: pat.severity.to_string(),
                        description: pat.description.to_string(),
                        matched: if matched.len() > 40 {
                            format!("{}...", &matched[..37])
                        } else {
                            matched.to_string()
                        },
                    });
                }
            }
        }

        // Entropy-based detection (high-entropy strings that look like secrets)
        if !no_entropy {
            // Look for quoted strings with high entropy
            for cap in Regex::new(r#"['"]([A-Za-z0-9+/=_\-]{20,})['"]"#).unwrap().captures_iter(line) {
                if let Some(m) = cap.get(1) {
                    let candidate = m.as_str();
                    let ent = shannon_entropy(candidate);
                    if ent >= min_entropy && candidate.len() >= 20 {
                        // Skip common non-secret patterns
                        if candidate.starts_with("http") || candidate.contains("example") || candidate.contains("test") {
                            continue;
                        }
                        let key = format!("{}:{}:entropy:{}", file, line_num + 1, candidate);
                        if seen.insert(key) {
                            findings.push(Finding {
                                file: file.to_string(),
                                line: line_num + 1,
                                pattern: format!("High-Entropy String ({:.1} bits)", ent),
                                severity: "medium".to_string(),
                                description: format!("Possible secret (entropy: {:.1}, length: {})", ent, candidate.len()),
                                matched: if candidate.len() > 40 {
                                    format!("{}...", &candidate[..37])
                                } else {
                                    candidate.to_string()
                                },
                            });
                        }
                    }
                }
            }
        }
    }
    findings
}

fn compile_patterns() -> Vec<Regex> {
    patterns().iter()
        .filter_map(|p| Regex::new(p.pattern).ok())
        .collect()
}

fn get_timestamp() -> String {
    // Use a simple approach without chrono
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    // Convert to approximate date (good enough for display)
    let days = secs / 86400;
    let year = 1970 + days / 365;
    let day_of_year = days % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn print_text(findings: &[Finding], target: &str, files_scanned: usize) {
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();

    println!();
    println!("{}", "=".repeat(60));
    println!("  secretsweep v{} — Secret Scanner", VERSION);
    println!("  Target: {}", target);
    println!("  Files scanned: {}", files_scanned);
    println!("{}", "=".repeat(60));
    println!();

    if findings.is_empty() {
        println!("  ✅ No secrets found! Your code looks clean.");
        println!();
        return;
    }

    println!("  Found {} potential secret(s):", findings.len());
    println!("  🔴 High: {}  🟡 Medium: {}", high, medium);
    println!();

    for f in findings {
        let icon = match f.severity.as_str() {
            "high" => "🔴",
            "medium" => "🟡",
            _ => "⚪",
        };
        println!("{} [{}] {}", icon, f.severity.to_uppercase(), f.pattern.bright_red().bold());
        println!("   File: {}:{}", f.file, f.line);
        println!("   Match: {}", f.matched);
        println!("   {}", f.description.dimmed());
        println!();
    }

    println!("{}", "=".repeat(60));
    println!("  Total: {} finding(s) across {} file(s)", findings.len(), files_scanned);
    if high > 0 {
        println!("  ⚠️  {} HIGH severity issue(s) need immediate attention!", high);
    }
    println!("{}", "=".repeat(60));
    println!();
}

#[derive(Serialize)]
struct JsonReport {
    tool: &'static str,
    version: &'static str,
    target: String,
    timestamp: String,
    files_scanned: usize,
    summary: JsonSummary,
    findings: Vec<Finding>,
}

#[derive(Serialize)]
struct JsonSummary {
    total: usize,
    high: usize,
    medium: usize,
}

fn print_json(findings: &[Finding], target: &str, files_scanned: usize) {
    let report = JsonReport {
        tool: "secretsweep",
        version: VERSION,
        target: target.to_string(),
        timestamp: get_timestamp(),
        files_scanned,
        summary: JsonSummary {
            total: findings.len(),
            high: findings.iter().filter(|f| f.severity == "high").count(),
            medium: findings.iter().filter(|f| f.severity == "medium").count(),
        },
        findings: findings.to_vec(),
    };
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}

fn print_github(findings: &[Finding]) {
    for f in findings {
        println!("::warning file={},line={}::[{}] {}: {}", f.file, f.line, f.severity.to_uppercase(), f.pattern, f.description);
    }
}

fn get_git_diff_lines() -> Vec<String> {
    let output = std::process::Command::new("git")
        .args(["diff", "-U0", "HEAD~1"])
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                .map(|l| l[1..].to_string())
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

fn main() {
    let cli = Cli::parse();
    let compiled = compile_patterns();

    let (mut findings, files_scanned) = if cli.stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input).unwrap();
        let f = scan_content(&input, "<stdin>", &cli.severity, &compiled, cli.entropy, cli.no_entropy);
        (f, 1)
    } else if cli.diff {
        let lines = get_git_diff_lines();
        let content = lines.join("\n");
        let f = scan_content(&content, "<git-diff>", &cli.severity, &compiled, cli.entropy, cli.no_entropy);
        (f, 1)
    } else {
        let target = &cli.path;
        if !Path::new(target).exists() {
            eprintln!("Error: '{}' does not exist", target);
            std::process::exit(1);
        }

        if Path::new(target).is_file() {
            match fs::read_to_string(target) {
                Ok(content) => {
                    let f = scan_content(&content, target, &cli.severity, &compiled, cli.entropy, cli.no_entropy);
                    (f, 1)
                }
                Err(_) => (Vec::new(), 0),
            }
        } else {
            let mut all = Vec::new();
            let mut count = 0usize;
            for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && !should_skip(&path.to_string_lossy()) {
                    count += 1;
                    if let Ok(content) = fs::read_to_string(path) {
                        let mut found = scan_content(&content, &path.to_string_lossy(), &cli.severity, &compiled, cli.entropy, cli.no_entropy);
                        all.append(&mut found);
                    }
                }
            }
            (all, count)
        }
    };

    // Sort: high first, then by file
    findings.sort_by(|a, b| {
        let sev_a = if a.severity == "high" { 0 } else { 1 };
        let sev_b = if b.severity == "high" { 0 } else { 1 };
        sev_a.cmp(&sev_b).then(a.file.cmp(&b.file)).then(a.line.cmp(&b.line))
    });

    match cli.format.as_str() {
        "json" => print_json(&findings, &cli.path, files_scanned),
        "github" => print_github(&findings),
        _ => print_text(&findings, &cli.path, files_scanned),
    }

    // Exit 1 if high severity found
    if findings.iter().any(|f| f.severity == "high") {
        std::process::exit(1);
    }
}
