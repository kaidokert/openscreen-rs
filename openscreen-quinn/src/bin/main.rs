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

//! OpenScreen QUIC Client - Testing Tool
//!
//! Command-line tool for testing connectivity and authentication with
//! OpenScreen receivers over QUIC.

#![allow(clippy::items_after_statements, clippy::large_futures)]

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use openscreen_crypto_rustcrypto::RustCryptoCryptoProvider;
use openscreen_quinn::QuinnClient;
use std::net::ToSocketAddrs;
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "openscreen-test")]
#[command(about = "Test OpenScreen QUIC connectivity and authentication", long_about = None)]
struct Cli {
    /// The hostname or IP address of the OpenScreen receiver
    #[arg(short = 'H', long)]
    host: String,

    /// The port of the OpenScreen receiver
    #[arg(short, long, default_value_t = 4433)]
    port: u16,

    /// The Pre-Shared Key (PSK) for authentication. If not provided, you will be prompted.
    #[arg(long)]
    psk: Option<String>,

    /// Optional authentication token from mDNS
    #[arg(long)]
    auth_token: Option<String>,

    /// Authentication timeout in seconds
    #[arg(short, long, default_value_t = 5)]
    timeout: u64,

    /// Increase logging verbosity (-v, -vv, -vvv)
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing subscriber with verbosity level
    // Respect both RUST_LOG environment variable AND -v flags
    // If RUST_LOG is set, use EnvFilter (more flexible, module-specific)
    // Otherwise, use -v flags for simple global level

    if std::env::var("RUST_LOG").is_ok() {
        // RUST_LOG is set - use EnvFilter for module-specific control
        tracing_subscriber::fmt()
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::default())
            .with_target(true) // Show module paths when using RUST_LOG
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        // RUST_LOG not set - use -v flags for global level
        use tracing::Level;
        let log_level = match cli.verbose.log_level_filter() {
            clap_verbosity_flag::LevelFilter::Off => None,
            clap_verbosity_flag::LevelFilter::Error => Some(Level::ERROR),
            clap_verbosity_flag::LevelFilter::Warn => Some(Level::WARN),
            clap_verbosity_flag::LevelFilter::Info => Some(Level::INFO),
            clap_verbosity_flag::LevelFilter::Debug => Some(Level::DEBUG),
            clap_verbosity_flag::LevelFilter::Trace => Some(Level::TRACE),
        };

        let subscriber = tracing_subscriber::fmt()
            .with_timer(tracing_subscriber::fmt::time::ChronoUtc::default())
            .with_target(false);

        if let Some(level) = log_level {
            subscriber.with_max_level(level).init();
        } else {
            subscriber.init();
        }
    }

    // Display banner
    println!(
        "{}",
        "OpenScreen QUIC Client Test Tool".bright_cyan().bold()
    );
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

    // Display connection info
    println!(
        "{} {}:{}",
        "Connecting to".bright_green(),
        cli.host.bright_white().bold(),
        cli.port.to_string().bright_white().bold()
    );
    if let Some(ref token) = cli.auth_token {
        println!("{} {}", "Auth token:".bright_green(), token.bright_white());
    }
    println!();

    // Run the connection test
    match run_connection_test(&cli.host, cli.port, &psk, cli.auth_token.as_deref()).await {
        Ok(()) => {
            println!();
            println!("{}", "✓ Test completed successfully!".bright_green().bold());
            Ok(())
        }
        Err(e) => {
            println!();
            // Use error! for logging, but also print to stderr for CLI visibility
            error!("Test failed: {:?}", e);
            println!("{} {:?}", "✗ Test failed:".bright_red().bold(), e);
            std::process::exit(1);
        }
    }
}

/// Run a connection test to an OpenScreen receiver
async fn run_connection_test(
    host: &str,
    port: u16,
    psk: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    // Step 1: Resolve hostname
    print!("{}", "WAIT: Resolving hostname... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    let addr_string = format!("{host}:{port}");
    let mut addrs = addr_string
        .to_socket_addrs()
        .context("Failed to resolve hostname")?;

    let server_addr = addrs.next().context("No addresses found for hostname")?;

    println!("{} {}", "✓".bright_green(), server_addr);
    info!("Resolved {} to {}", addr_string, server_addr);

    // Step 2: Prepare dummy fingerprint (insecure - for testing only!)
    warn!("WARN:  Using dummy fingerprint - Connection is vulnerable to MITM attacks!");
    let dummy_fingerprint = [0u8; 32];

    // Step 3: Create Quinn client with expected fingerprint
    print!("{}", "WAIT: Initializing QUIC client... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    let crypto_provider = RustCryptoCryptoProvider::new();
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let mut client = QuinnClient::new(
        crypto_provider,
        bind_addr,
        dummy_fingerprint,
        "openscreen-client",
    )
    .context("Failed to create Quinn client")?;

    println!("{}", "✓".bright_green());
    debug!(
        "Quinn client initialized with bind address {} (dummy fingerprint)",
        bind_addr
    );

    // Step 4: Configure PSK and auth token
    print!("{}", "WAIT: Configuring authentication... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    client
        .set_psk(psk.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to set PSK: {e:?}"))?;

    if let Some(token) = auth_token {
        client
            .set_auth_token(token.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to set auth token: {e:?}"))?;
    }

    println!("{}", "✓".bright_green());
    debug!("PSK and auth token configured");

    // Step 5: Attempt connection
    // Fingerprint verification now happens during TLS handshake
    print!(
        "{}",
        "WAIT: Connecting to receiver (QUIC + TLS)... ".bright_yellow()
    );
    std::io::Write::flush(&mut std::io::stdout())?;

    match client.connect(server_addr, host).await {
        Ok(()) => {
            println!("{}", "✓".bright_green());
            info!("QUIC connection established");
        }
        Err(e) => {
            println!("{}", "✗".bright_red());
            warn!("Connection failed: {:?}", e);
            return Err(anyhow::anyhow!("QUIC connection failed: {e:?}"));
        }
    }

    // Step 6: Check authentication status
    // Note: The connect() method already handles authentication,
    // but we check the final state here for display purposes
    print!("{}", "WAIT: Authenticating... ".bright_yellow());
    std::io::Write::flush(&mut std::io::stdout())?;

    if client.is_authenticated() {
        println!("{}", "✓".bright_green());
        info!("Authentication successful");
    } else {
        println!("{}", "⚠".bright_yellow());
        warn!("Authentication did not complete - check receiver logs");
    }

    // Display authentication state
    println!();
    println!(
        "{} {}",
        "Authenticated:".bright_cyan(),
        if client.is_authenticated() {
            "Yes"
        } else {
            "No"
        }
    );

    Ok(())
}
