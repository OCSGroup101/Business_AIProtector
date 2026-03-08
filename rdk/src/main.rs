// Copyright 2026 Omni Cyber Solutions LLC. Apache License 2.0.
//
// openclaw-rdk — Rule Development Kit CLI
//
// Subcommands:
//   validate <file.toml>          Validate a single rule file
//   test <file.toml> --fixture <events.json>   Run rule against fixture events
//   lint <dir/>                   Validate all .toml files; detect duplicate IDs

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};

mod harness;
mod validator;

#[derive(Parser)]
#[command(
    name = "openclaw-rdk",
    about = "OpenClaw Rule Development Kit — validate, test, and lint detection rules",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a single TOML rule file
    Validate {
        /// Path to the .toml rule file
        file: PathBuf,
    },
    /// Run a rule against a fixture event set
    Test {
        /// Path to the .toml rule file
        file: PathBuf,
        /// Path to a JSON fixture file with "events" array
        #[arg(long)]
        fixture: PathBuf,
    },
    /// Validate all .toml files in a directory; detect duplicate rule IDs
    Lint {
        /// Directory to scan recursively
        dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { file } => cmd_validate(&file),
        Commands::Test { file, fixture } => cmd_test(&file, &fixture),
        Commands::Lint { dir } => cmd_lint(&dir),
    }
}

fn cmd_validate(file: &Path) -> Result<()> {
    let content = std::fs::read_to_string(file)?;
    let errors = validator::validate_toml(&content, &file.display().to_string());

    if errors.is_empty() {
        println!("OK: {}", file.display());
        Ok(())
    } else {
        for (id, err) in &errors {
            eprintln!("ERROR [{id}]: {err}");
        }
        anyhow::bail!(
            "{} validation error(s) in {}",
            errors.len(),
            file.display()
        )
    }
}

fn cmd_test(file: &Path, fixture_path: &Path) -> Result<()> {
    use openclaw_agent::detection::rule_loader::RuleFile;

    let rule_content = std::fs::read_to_string(file)?;
    let rule_file: RuleFile = toml::from_str(&rule_content)?;
    let events = harness::load_fixture(fixture_path)?;

    let mut any_error = false;
    for rule in &rule_file.rules {
        match harness::run_test(rule, &events) {
            Ok(report) => {
                println!(
                    "Rule {}: {}/{} events matched",
                    report.rule_id,
                    report.hits.len(),
                    report.total_events
                );
                if !report.hits.is_empty() {
                    println!("  Hit indices: {:?}", report.hits);
                }
            }
            Err(e) => {
                eprintln!("ERROR [{}]: {}", rule.id, e);
                any_error = true;
            }
        }
    }

    if any_error {
        anyhow::bail!("One or more test rules failed")
    }
    Ok(())
}

fn cmd_lint(dir: &Path) -> Result<()> {
    use std::collections::HashMap;

    let toml_files = collect_toml_files(dir);
    if toml_files.is_empty() {
        println!("No .toml files found in {}", dir.display());
        return Ok(());
    }

    let mut all_errors: Vec<(PathBuf, String, String)> = Vec::new();
    let mut id_map: HashMap<String, PathBuf> = HashMap::new();

    for path in &toml_files {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                all_errors.push((path.clone(), path.display().to_string(), e.to_string()));
                continue;
            }
        };

        // Validation errors
        let errors = validator::validate_toml(&content, &path.display().to_string());
        for (id, err) in errors {
            all_errors.push((path.clone(), id, err));
        }

        // Duplicate ID detection
        #[derive(serde::Deserialize)]
        struct IdOnly {
            #[serde(default)]
            rules: Vec<IdOnlyRule>,
        }
        #[derive(serde::Deserialize)]
        struct IdOnlyRule {
            id: String,
        }
        if let Ok(parsed) = toml::from_str::<IdOnly>(&content) {
            for rule in parsed.rules {
                if let Some(existing) = id_map.get(&rule.id) {
                    all_errors.push((
                        path.clone(),
                        rule.id.clone(),
                        format!("Duplicate rule ID — also defined in {}", existing.display()),
                    ));
                } else {
                    id_map.insert(rule.id, path.clone());
                }
            }
        }
    }

    if all_errors.is_empty() {
        println!(
            "OK: {} files, {} unique rule IDs — no issues",
            toml_files.len(),
            id_map.len()
        );
        Ok(())
    } else {
        for (path, id, err) in &all_errors {
            eprintln!("ERROR [{}] in {}: {}", id, path.display(), err);
        }
        anyhow::bail!("{} lint error(s) across {} files", all_errors.len(), toml_files.len())
    }
}

fn collect_toml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(collect_toml_files(&path));
            } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                files.push(path);
            }
        }
    }
    files
}
