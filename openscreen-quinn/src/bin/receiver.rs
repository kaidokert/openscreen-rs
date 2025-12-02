// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OpenScreen Receiver - Testing Server
//!
//! Acts as an OpenScreen receiver, accepting incoming QUIC connections
//! and authenticating clients using SPAKE2.

#![allow(
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::large_futures
)]

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use openscreen_quinn::QuinnServer;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "openscreen-receiver")]
#[command(about = "OpenScreen receiver for testing", long_about = None)]
struct Cli {
    /// Port to listen on
    #[arg(short, long, default_value_t = 4433)]
    port: u16,

    /// The Pre-Shared Key (PSK) for authentication. If not provided, you will be prompted.
    #[arg(long)]
    psk: Option<String>,

    /// Friendly name for this receiver
    #[arg(long, default_value = "OpenScreen Test Receiver")]
    name: String,

    /// Increase logging verbosity (-v, -vv, -vvv)
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing subscriber
    // Priority: RUST_LOG env var > CLI -v flags > default (INFO)
    use tracing_subscriber::EnvFilter;

    // Check if RUST_LOG is set
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        // Use RUST_LOG if set
        EnvFilter::from_default_env()
    } else {
        // Fall back to CLI verbosity flags
        use tracing::Level;
        let log_level = match cli.verbose.log_level_filter() {
            clap_verbosity_flag::LevelFilter::Off => Level::ERROR,
            clap_verbosity_flag::LevelFilter::Error => Level::ERROR,
            clap_verbosity_flag::LevelFilter::Warn => Level::WARN,
            clap_verbosity_flag::LevelFilter::Info => Level::INFO,
            clap_verbosity_flag::LevelFilter::Debug => Level::DEBUG,
            clap_verbosity_flag::LevelFilter::Trace => Level::TRACE,
        };
        EnvFilter::new(log_level.as_str())
    };

    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::default())
        .with_target(false)
        .with_env_filter(env_filter)
        .init();

    // Display banner
    println!("{}", "OpenScreen Receiver".bright_cyan().bold());
    println!("{}: {}", "Name".bright_green(), cli.name.bright_white());
    println!();

    // Get PSK (prompt if not provided)
    let psk = match cli.psk {
        Some(p) => p,
        None => {
            print!("{}", "Enter PSK (password): ".bright_yellow());
            std::io::Write::flush(&mut std::io::stdout())?;
            rpassword::read_password()?
        }
    };

    if psk.is_empty() {
        anyhow::bail!("PSK cannot be empty");
    }

    // Start receiver
    println!("{} on port {}", "Listening".bright_green(), cli.port);
    println!();

    match run_receiver(cli.port, &psk).await {
        Ok(()) => {
            println!();
            println!("{}", "✓ Receiver stopped".bright_green().bold());
            Ok(())
        }
        Err(e) => {
            println!();
            error!("Receiver failed: {:?}", e);
            println!("{} {:?}", "✗ Receiver failed:".bright_red().bold(), e);
            std::process::exit(1)
        }
    }
}

/// Run the OpenScreen receiver using QuinnServer
async fn run_receiver(port: u16, psk: &str) -> Result<()> {
    let bind_addr = format!("0.0.0.0:{port}").parse::<std::net::SocketAddr>()?;

    println!("WAIT: Initializing server...");
    let server = QuinnServer::bind(bind_addr, psk).await?;

    println!("{}", "Waiting for connections...".bright_cyan());
    println!();

    // Accept and handle connections
    while let Some(result) = server.accept().await {
        match result {
            Ok(connection) => {
                let remote_addr = connection.remote_address();
                println!(
                    "{} from {}",
                    "New connection".bright_cyan(),
                    remote_addr.to_string().bright_white()
                );
                println!("  {} Client authenticated!", "✓".bright_green().bold());
                info!("Client {} authenticated", remote_addr);

                // Spawn handler for this connection
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(connection).await {
                        error!("Connection handler failed: {:?}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to authenticate connection: {:?}", e);
                println!("  {} Auth failed: {:?}", "✗".bright_red(), e);
            }
        }
    }

    Ok(())
}

/// Handle an authenticated connection
async fn handle_connection(connection: openscreen_quinn::AuthenticatedConnection) -> Result<()> {
    let remote_addr = connection.remote_address();
    info!("Handling connection from {}", remote_addr);

    // For now, just keep connection alive
    // Future: Handle application messages here
    loop {
        if connection.is_closed() {
            info!("Connection from {} closed", remote_addr);
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}
