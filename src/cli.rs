use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;
use std::path::PathBuf;

use crate::config::Config;
use crate::reporting::{OutputFormat, Reporter};
use crate::rules::RulesEngine;
use crate::sbom::SbomGenerator;
use crate::scanner::Scanner;

#[derive(Parser)]
#[command(name = "ansiblesec")]
#[command(version, about = "Security scanning and policy enforcement for Ansible playbooks", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan Ansible playbooks for security issues
    Scan {
        /// Path to playbook or directory to scan
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Path to configuration file
        #[arg(short = 'c', long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Path to secrets detection rules file
        #[arg(long, value_name = "FILE")]
        secrets_rules: Option<PathBuf>,

        /// Path to policy rules file
        #[arg(long, value_name = "FILE")]
        policy_rules: Option<PathBuf>,

        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format (text, json, sarif)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Disable caching
        #[arg(long)]
        no_cache: bool,

        /// CI mode (stricter exit codes)
        #[arg(long)]
        ci_mode: bool,

        /// Fail on any findings
        #[arg(long)]
        fail_on_findings: bool,

        /// Number of threads for scanning
        #[arg(short, long, default_value = "0")]
        threads: usize,

        /// Verbosity level (-v, -vv, -vvv)
        #[arg(short, long, action = clap::ArgAction::Count)]
        verbose: u8,
    },

    /// Lint Ansible playbooks for quality and security
    Lint {
        /// Path to playbook or directory to lint
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Path to custom rules file
        #[arg(short, long, value_name = "FILE")]
        rules: Option<PathBuf>,

        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format (text, json)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// CI mode
        #[arg(long)]
        ci_mode: bool,
    },

    /// Generate Software Bill of Materials (SBOM)
    Sbom {
        /// Path to playbook or directory
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output file path
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// SBOM format (cyclonedx, spdx)
        #[arg(short, long, default_value = "cyclonedx")]
        format: String,

        /// Include CVE lookups (requires network)
        #[arg(long)]
        include_cve: bool,
    },

    /// Validate and test custom rules
    Rules {
        #[command(subcommand)]
        command: RulesCommands,
    },
}

#[derive(Subcommand)]
enum RulesCommands {
    /// Validate rules file syntax and structure
    Validate {
        /// Path to rules file
        #[arg(value_name = "FILE")]
        rules_file: PathBuf,
    },

    /// List all available rules
    List {
        /// Path to rules file
        #[arg(value_name = "FILE")]
        rules_file: Option<PathBuf>,
    },
}

impl Cli {
    pub fn execute(&self) -> Result<()> {
        match &self.command {
            Commands::Scan {
                path,
                config: config_file,
                secrets_rules,
                policy_rules,
                output,
                format,
                no_cache,
                ci_mode,
                fail_on_findings,
                threads,
                verbose: _verbose,
            } => {
                info!("Starting security scan on: {:?}", path);

                let mut config = Config::load(config_file.clone())?;

                // Override with command-line options if provided
                if let Some(ref secrets_file) = secrets_rules {
                    config.secrets.rules_file = Some(secrets_file.to_string_lossy().to_string());
                }
                if let Some(ref policy_file) = policy_rules {
                    config.policies.rules_file = Some(policy_file.to_string_lossy().to_string());
                }

                let enable_cache = !no_cache && config.general.cache_enabled;
                let scanner = Scanner::new(config, *threads, enable_cache);
                let findings = scanner.scan(path)?;

                let output_format = OutputFormat::from_str(format)?;
                let reporter = Reporter::new(output_format);

                reporter.report(&findings, output.as_deref())?;

                // Exit code handling
                let exit_code = if *ci_mode || *fail_on_findings {
                    if findings.has_critical() {
                        2
                    } else if findings.has_high() {
                        1
                    } else {
                        0
                    }
                } else {
                    0
                };

                if exit_code != 0 {
                    std::process::exit(exit_code);
                }

                Ok(())
            }

            Commands::Lint {
                path,
                rules,
                output,
                format,
                ci_mode,
            } => {
                info!("Starting linting on: {:?}", path);

                let config = Config::load(rules.clone())?;
                let scanner = Scanner::new(config, 0, false);
                let findings = scanner.lint(path)?;

                let output_format = OutputFormat::from_str(format)?;
                let reporter = Reporter::new(output_format);

                reporter.report(&findings, output.as_deref())?;

                if *ci_mode && findings.has_errors() {
                    std::process::exit(1);
                }

                Ok(())
            }

            Commands::Sbom {
                path,
                output,
                format,
                include_cve,
            } => {
                info!("Generating SBOM for: {:?}", path);

                let generator = SbomGenerator::new(*include_cve);
                let sbom = generator.generate(path, format)?;

                if let Some(output_path) = output {
                    std::fs::write(output_path, sbom)?;
                    println!("SBOM written to: {:?}", output_path);
                } else {
                    println!("{}", sbom);
                }

                Ok(())
            }

            Commands::Rules { command } => match command {
                RulesCommands::Validate { rules_file } => {
                    info!("Validating rules file: {:?}", rules_file);

                    let rules_engine = RulesEngine::load(rules_file)?;
                    rules_engine.validate()?;

                    println!("✓ Rules file is valid");
                    Ok(())
                }

                RulesCommands::List { rules_file } => {
                    let rules_engine = if let Some(file) = rules_file {
                        RulesEngine::load(file)?
                    } else {
                        RulesEngine::default()
                    };

                    rules_engine.list_rules();
                    Ok(())
                }
            },
        }
    }
}
