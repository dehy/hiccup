// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup`: the command-line interface to Hiccup.

mod ca;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{ArgAction, Args, Parser, Subcommand};
use hiccup_proxy::{HostPattern, Proxy, ProxyConfig};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// Open source web security testing toolkit.
#[derive(Debug, Parser)]
#[command(
    name = "hiccup",
    version,
    subcommand_required = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Increase log verbosity (-v: debug, -vv: trace). `RUST_LOG` overrides it.
    #[arg(short, long, action = ArgAction::Count, global = true)]
    verbose: u8,

    /// Directory holding Hiccup's data, such as the CA. Defaults to the
    /// per-user data directory (e.g. `~/.local/share/hiccup` on Linux).
    #[arg(long, value_name = "DIR", env = "HICCUP_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Intercepting proxy.
    #[command(subcommand)]
    Proxy(ProxyCommand),
    /// Local certificate authority for HTTPS interception.
    #[command(subcommand)]
    Ca(ca::CaCommand),
}

#[derive(Debug, Subcommand)]
enum ProxyCommand {
    /// Start the proxy.
    Start(StartArgs),
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Run an embedded proxy in this terminal until Ctrl+C.
    ///
    /// Without it, the proxy would start in a running Hiccup instance, which
    /// needs the control API (not implemented yet).
    #[arg(long)]
    foreground: bool,

    /// Address to listen on. Repeat to listen on several addresses.
    #[arg(long = "listen", value_name = "ADDR", default_value = "127.0.0.1:8080")]
    listen: Vec<SocketAddr>,

    /// Relay HTTPS to matching hosts without intercepting it, e.g. for clients
    /// that pin certificates. `*.example.com` matches subdomains, `*` every
    /// host. Repeat for several patterns.
    #[arg(long, value_name = "PATTERN")]
    tls_passthrough: Vec<HostPattern>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match cli.command {
        Command::Proxy(ProxyCommand::Start(args)) => match data_dir(cli.data_dir) {
            Some(dir) => proxy_start(args, &dir),
            None => ExitCode::FAILURE,
        },
        Command::Ca(command) => match data_dir(cli.data_dir) {
            Some(dir) => ca::run(command, &dir),
            None => ExitCode::FAILURE,
        },
    }
}

/// `--data-dir`, `HICCUP_DATA_DIR`, or the per-user data directory.
fn data_dir(explicit: Option<PathBuf>) -> Option<PathBuf> {
    let dir = explicit.or_else(|| dirs::data_dir().map(|d| d.join("hiccup")));
    if dir.is_none() {
        eprintln!("hiccup: cannot determine the user data directory; use --data-dir");
    }
    dir
}

fn init_logging(verbose: u8) {
    let default = match verbose {
        0 => "warn,hiccup_proxy=info,hiccup_cli=info",
        1 => "info,hiccup_proxy=debug,hiccup_cli=debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
}

fn proxy_start(args: StartArgs, data_dir: &std::path::Path) -> ExitCode {
    if !args.foreground {
        eprintln!(
            "hiccup: starting the proxy in a running instance needs the control API, which is \
             not implemented yet (https://github.com/dehy/hiccup/issues/15).\n\
             Use `hiccup proxy start --foreground` to run it in this terminal."
        );
        return ExitCode::from(2);
    }

    let Some(ca) = ca::load(data_dir) else {
        return ExitCode::FAILURE;
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("hiccup: cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let config = ProxyConfig {
            listen: args.listen,
            tls_passthrough: args.tls_passthrough,
            ..ProxyConfig::default()
        };
        let proxy = match Proxy::bind(config)
            .await
            .map_err(|e| e.to_string())
            .and_then(|p| p.intercept_tls(Arc::new(ca)).map_err(|e| e.to_string()))
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("hiccup: {e}");
                return ExitCode::FAILURE;
            }
        };
        for addr in proxy.local_addrs() {
            eprintln!("Hiccup proxy listening on http://{addr}");
        }
        eprintln!(
            "HTTPS is intercepted with the Hiccup CA ({}). Upstream certificates are not \
             verified.",
            ca::INSTALL_GUIDE
        );
        eprintln!("Press Ctrl+C to stop.");

        let shutdown = CancellationToken::new();
        let on_signal = shutdown.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                eprintln!("Stopping...");
            }
            on_signal.cancel();
        });
        proxy.serve(shutdown).await;
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
