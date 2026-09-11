mod api_styles;
mod frontend;
mod models;
mod rbac;
mod risk;
mod routes;
mod secrets;
mod stack_detect;
mod taint;
mod scan;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rynix-scan", about = "Rynix static security analyzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Analyze {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long, default_value = "json")]
        format: String,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze { repo, format, profile, config } => {
            if !repo.is_dir() {
                eprintln!(r#"{{"error":{{"code":"INVALID_REPO","message":"repo path not found"}}}}"#);
                std::process::exit(1);
            }
            let scan_config = if let Some(cfg_path) = config {
                let raw = std::fs::read_to_string(&cfg_path).unwrap_or_else(|e| {
                    eprintln!(r#"{{"error":{{"code":"CONFIG_READ","message":"{}"}}}}"#, e);
                    std::process::exit(1);
                });
                serde_json::from_str(&raw).unwrap_or_else(|e| {
                    eprintln!(r#"{{"error":{{"code":"CONFIG_PARSE","message":"{}"}}}}"#, e);
                    std::process::exit(1);
                })
            } else {
                models::ScanConfig::default()
            };
            let result = scan::analyze_repo(&repo, scan_config, profile);
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            } else {
                eprintln!("unsupported format: {}", format);
                std::process::exit(1);
            }
        }
        Commands::Version => {
            println!("rynix-scan 0.1.0");
        }
    }
}
