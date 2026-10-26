use anyhow::Context;
use clap::{Parser, ValueEnum};
use fallback_lint::{audit, parse_config, parse_scenarios, render_text};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Strict TOML fallback policy and topology.
    #[arg(long)]
    config: PathBuf,

    /// Optional strict JSONL outage scenarios.
    #[arg(long)]
    scenarios: Option<PathBuf>,

    /// Report format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() {
    match run() {
        Ok(clean) => std::process::exit(if clean { 0 } else { 2 }),
        Err(error) => {
            eprintln!("fallback-lint: ERROR: {error:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> anyhow::Result<bool> {
    let cli = Cli::parse();
    let config_bytes = std::fs::read(&cli.config)
        .with_context(|| format!("failed to read config {}", cli.config.display()))?;
    let config_text = std::str::from_utf8(&config_bytes).context("config is not valid UTF-8")?;
    let config = parse_config(config_text)?;

    let scenario_bytes = match &cli.scenarios {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("failed to read scenarios {}", path.display()))?,
        None => Vec::new(),
    };
    let scenario_text =
        std::str::from_utf8(&scenario_bytes).context("scenarios file is not valid UTF-8")?;
    let scenarios = parse_scenarios(scenario_text)?;
    let report = audit(&config, &scenarios, &config_bytes, &scenario_bytes);

    let rendered = match cli.format {
        Format::Text => render_text(&report),
        Format::Json => format!("{}\n", serde_json::to_string_pretty(&report)?),
    };
    if let Some(path) = &cli.output {
        std::fs::write(path, rendered)
            .with_context(|| format!("failed to write report {}", path.display()))?;
    } else {
        print!("{rendered}");
    }
    Ok(report.clean)
}
