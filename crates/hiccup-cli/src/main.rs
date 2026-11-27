// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup`: the command-line interface to Hiccup.

mod ca;
mod instance;
mod intercept;
mod proxy;
mod scope;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser, Subcommand};
use hiccup_control::Registry;
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

    /// Print results as JSON, for scripts.
    #[arg(long, global = true)]
    json: bool,

    /// The instance to control, or the name of the one to start (`serve`,
    /// `proxy start --foreground`). Defaults to the only running instance,
    /// or "default" when starting one.
    #[arg(long, value_name = "NAME", env = "HICCUP_INSTANCE", global = true)]
    instance: Option<String>,

    /// Directory holding Hiccup's data, such as the CA. Defaults to the
    /// per-user data directory (e.g. `~/.local/share/hiccup` on Linux).
    #[arg(long, value_name = "DIR", env = "HICCUP_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,

    /// Directory of the registry of running instances. Defaults to
    /// `$XDG_RUNTIME_DIR/hiccup`, or `hiccup/run` in the local data directory.
    ///
    /// It must be private to you: on Unix, Hiccup refuses one that other
    /// users can access; on Windows, protect it yourself.
    #[arg(long, value_name = "DIR", env = "HICCUP_RUNTIME_DIR", global = true)]
    runtime_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a Hiccup instance without a window, until Ctrl+C.
    ///
    /// Other `hiccup` commands control it, e.g. `hiccup proxy start`.
    Serve,
    /// Intercepting proxy.
    #[command(subcommand)]
    Proxy(proxy::ProxyCommand),
    /// Hold requests and responses to inspect, edit, forward or drop them.
    #[command(subcommand)]
    Intercept(intercept::InterceptCommand),
    /// Which URLs are being tested.
    #[command(subcommand)]
    Scope(scope::ScopeCommand),
    /// Running Hiccup instances.
    #[command(subcommand)]
    Instance(instance::InstanceCommand),
    /// Local certificate authority for HTTPS interception.
    #[command(subcommand)]
    Ca(ca::CaCommand),
}

/// Options shared by every command.
pub struct Globals {
    json: bool,
    instance: Option<String>,
    data_dir: Option<PathBuf>,
    runtime_dir: Option<PathBuf>,
}

impl Globals {
    /// `--data-dir`, `HICCUP_DATA_DIR`, or the per-user data directory.
    fn data_dir(&self) -> Option<PathBuf> {
        let dir = self
            .data_dir
            .clone()
            .or_else(|| dirs::data_dir().map(|d| d.join("hiccup")));
        if dir.is_none() {
            eprintln!("hiccup: cannot determine the user data directory; use --data-dir");
        }
        dir
    }

    /// The instance registry.
    fn registry(&self) -> Option<Registry> {
        let dir = self.runtime_dir.clone().or_else(Registry::default_dir);
        if dir.is_none() {
            eprintln!("hiccup: cannot determine the runtime directory; use --runtime-dir");
        }
        dir.map(Registry::new)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    let globals = Globals {
        json: cli.json,
        instance: cli.instance,
        data_dir: cli.data_dir,
        runtime_dir: cli.runtime_dir,
    };
    match cli.command {
        Command::Serve => instance::serve(&globals),
        Command::Proxy(command) => proxy::run(command, &globals),
        Command::Intercept(command) => intercept::run(command, &globals),
        Command::Scope(command) => scope::run(command, &globals),
        Command::Instance(command) => instance::run(command, &globals),
        Command::Ca(command) => match globals.data_dir() {
            Some(dir) => ca::run(command, &dir, globals.json),
            None => ExitCode::FAILURE,
        },
    }
}

/// A multi-threaded Tokio runtime. Errors are printed.
fn runtime() -> Option<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new()
        .map_err(|e| eprintln!("hiccup: cannot start the async runtime: {e}"))
        .ok()
}

/// Prints a JSON value on standard output.
fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON values serialize")
    );
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

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
