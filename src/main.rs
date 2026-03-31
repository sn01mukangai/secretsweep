use clap::Parser;
use colored::*;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use walkdir::WalkDir;

const VERSION: &str = "2.0.0";

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
}

fn patterns() -> Vec<SecretPattern> {
    vec![
        // Cloud
        SecretPattern { name: "AWS Access Key", pattern: r"AKIA[0-9A-Z]{16}", severity: "high", description: "AWS access key" },
        SecretPattern { name: "Google API Key", pattern: r"AIza[0-9A-Za-z_-]{35}", severity: "high", description: "Google API key" },
        SecretPattern { name: "Google OAuth", pattern: r"ya29\.[0-9A-Za-z_-]+", severity: "high", description: "Google OAuth token" },
        // Payments
        SecretPattern { name: "Stripe Key", pattern: r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}", severity: "high", description: "Stripe API key" },
        SecretPattern { name: "OpenAI/Stripe Secret", pattern: r"sk-[a-zA-Z0-9]{20,}", severity: "high", description: "OpenAI/Stripe secret key" },
        // Code Hosting
        SecretPattern { name: "GitHub PAT", pattern: r"ghp_[A-Za-z0-9]{36}", severity: "high", description: "GitHub personal access token" },
        SecretPattern { name: "GitHub OAuth", pattern: r"gho_[A-Za-z0-9]{36}", severity: "high", description: "GitHub OAuth token" },
        SecretPattern { name: "GitHub App", pattern: r"(?:ghu|ghs)_[A-Za-z0-9]{36}", severity: "high", description: "GitHub App token" },
        // Communication
        SecretPattern { name: "Slack Token", pattern: r"xox[bpoas]-[A-Za-z0-9-]+", severity: "high", description: "Slack workspace/bot token" },
        SecretPattern { name: "Slack Webhook", pattern: r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}", severity: "medium", description: "Slack webhook URL" },
        SecretPattern { name: "Discord Token", pattern: r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}", severity: "high", description: "Discord bot token" },
        SecretPattern { name: "Discord Webhook", pattern: r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", severity: "medium", description: "Discord webhook" },
        SecretPattern { name: "Telegram Bot", pattern: r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", severity: "high", description: "Telegram bot token" },
        // Email
        SecretPattern { name: "SendGrid", pattern: r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", severity: "high", description: "SendGrid API key" },
        SecretPattern { name: "Mailgun", pattern: r"key-[0-9a-zA-Z]{32}", severity: "high", description: "Mailgun API key" },
        // Twilio
        SecretPattern { name: "Twilio", pattern: r"SK[a-f0-9]{32}", severity: "high", description: "Twilio API key" },
        // Firebase
        SecretPattern { name: "Firebase URL", pattern: r"https://[a-z0-9-]+\.firebaseio\.com", severity: "medium", description: "Firebase Realtime Database" },
        SecretPattern { name: "Firebase FCM", pattern: r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}", severity: "high", description: "Firebase Cloud Messaging key" },
        // Database
        SecretPattern { name: "MongoDB URI", pattern: r"mongodb(\+srv)?://\S+", severity: "high", description: "MongoDB connection string" },
        SecretPattern { name: "MySQL URI", pattern: r"mysql://\S+", severity: "high", description: "MySQL connection string" },
        SecretPattern { name: "PostgreSQL URI", pattern: r"postgres(ql)?://\S+", severity: "high", description: "PostgreSQL connection string" },
        SecretPattern { name: "Redis URI", pattern: r"redis://\S+", severity: "high", description: "Redis connection string" },
        // Keys
        SecretPattern { name: "RSA Private Key", pattern: r"-----BEGIN RSA PRIVATE KEY-----", severity: "high", description: "RSA private key" },
        SecretPattern { name: "EC Private Key", pattern: r"-----BEGIN EC PRIVATE KEY-----", severity: "high", description: "EC private key" },
        SecretPattern { name: "Private Key", pattern: r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", severity: "high", description: "Private key" },
        // JWT
        SecretPattern { name: "JWT Token", pattern: r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", severity: "medium", description: "JSON Web Token" },
        // Generic (case-insensitive via separate patterns)
        SecretPattern { name: "Generic API Key", pattern: r"[Aa][Pp][Ii][_\-]?[Kk][Ee][Yy]\s*[=:]\s*[A-Za-z0-9_\-]{16,}", severity: "medium", description: "Possible API key" },
        SecretPattern { name: "Generic Password", pattern: r"[Pp]assword\s*[=:]\s*[^\s<>]{8,}", severity: "medium", description: "Possible hardcoded password" },
        SecretPattern { name: "Generic Secret", pattern: r"[Ss]ecret\s*[=:]\s*[A-Za-z0-9_\-]{16,}", severity: "medium", description: "Possible secret" },
        SecretPattern { name: "Generic Token", pattern: r"[Tt]oken\s*[=:]\s*[A-Za-z0-9_\-]{16,}", severity: "medium", description: "Possible token" },
    ]
}

const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "env", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
    ".next", ".nuxt", "target", "bin", "obj",
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

fn should_skip(path: &str) -> bool {
    let p = Path::new(path);
    // Skip by extension
    if let Some(ext) = p.extension() {
        let ext_str = format!(".{}", ext.to_string_lossy());
        if SKIP_EXTS.iter().any(|e| ext_str.ends_with(e)) {
            return true;
        }
    }
    // Skip by directory component
    for comp in p.components() {
        let s = comp.as_os_str().to_string_lossy();
        if s.starts_with('.') && s.len() > 1 {
            return true;
        }
        if SKIP_DIRS.contains(&s.as_ref()) {
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

fn scan_content(content: &str, file: &str, severity_filter: &str, compiled: &[Regex]) -> Vec<Finding> {
    let pats = patterns();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for (line_num, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("<!--") {
            continue;
        }

        for (i, pat) in pats.iter().enumerate() {
            if severity_filter != "all" && pat.severity != severity_filter {
                continue;
            }
            for m in compiled[i].find_iter(line) {
                let matched = m.as_str();
                if !is_false_positive(matched) {
                    let key = format!("{}:{}:{}", file, line_num + 1, matched);
                    if seen.insert(key) {
                        findings.push(Finding {
                            file: file.to_string(),
                            line: line_num + 1,
                            pattern: pat.name.to_string(),
                            severity: pat.severity.to_string(),
                            description: pat.description.to_string(),
                            matched: if matched.len() > 30 {
                                format!("{}...", &matched[..27])
                            } else {
                                matched.to_string()
                            },
                        });
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

fn print_text(findings: &[Finding], target: &str) {
    let high = findings.iter().filter(|f| f.severity == "high").count();
    let medium = findings.iter().filter(|f| f.severity == "medium").count();

    println!();
    println!("{}", "=".repeat(60));
    println!("  secretsweep v{} — Secret Scanner", VERSION);
    println!("  Target: {}", target);
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
    println!("  Total: {} finding(s)", findings.len());
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
    summary: JsonSummary,
    findings: Vec<Finding>,
}

#[derive(Serialize)]
struct JsonSummary {
    total: usize,
    high: usize,
    medium: usize,
}

fn print_json(findings: &[Finding], target: &str) {
    let report = JsonReport {
        tool: "secretsweep",
        version: VERSION,
        target: target.to_string(),
        timestamp: chrono_now(),
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

fn chrono_now() -> String {
    // Simple timestamp without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{}s", dur.as_secs())
}

fn main() {
    let cli = Cli::parse();
    let compiled = compile_patterns();

    let mut findings = if cli.stdin {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input).unwrap();
        scan_content(&input, "<stdin>", &cli.severity, &compiled)
    } else {
        let target = &cli.path;
        if !Path::new(target).exists() {
            eprintln!("Error: '{}' does not exist", target);
            std::process::exit(1);
        }

        if Path::new(target).is_file() {
            match fs::read_to_string(target) {
                Ok(content) => scan_content(&content, target, &cli.severity, &compiled),
                Err(_) => Vec::new(),
            }
        } else {
            let mut all = Vec::new();
            for entry in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() && !should_skip(&path.to_string_lossy()) {
                    if let Ok(content) = fs::read_to_string(path) {
                        let mut found = scan_content(&content, &path.to_string_lossy(), &cli.severity, &compiled);
                        all.append(&mut found);
                    }
                }
            }
            all
        }
    };

    // Sort: high first, then by file
    findings.sort_by(|a, b| {
        let sev_a = if a.severity == "high" { 0 } else { 1 };
        let sev_b = if b.severity == "high" { 0 } else { 1 };
        sev_a.cmp(&sev_b).then(a.file.cmp(&b.file)).then(a.line.cmp(&b.line))
    });

    match cli.format.as_str() {
        "json" => print_json(&findings, &cli.path),
        "github" => print_github(&findings),
        _ => print_text(&findings, &cli.path),
    }

    // Exit 1 if high severity found
    if findings.iter().any(|f| f.severity == "high") {
        std::process::exit(1);
    }
}
