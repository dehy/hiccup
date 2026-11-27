// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup`: the command-line interface to Hiccup.

mod ca;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{ArgAction, Args, Parser, Subcommand};
use std::net::IpAddr;
use std::time::Duration;

use hiccup_proxy::{ClientCert, HostPattern, Proxy, ProxyConfig, TlsVersion, UpstreamConfig};
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

    /// Verify upstream server certificates against the OS trust store.
    ///
    /// Off by default, so that targets with self-signed or invalid
    /// certificates can be tested.
    #[arg(long, help_heading = "Upstream")]
    verify_upstream: bool,

    /// Lowest TLS version offered to servers: 1.2 or 1.3.
    #[arg(
        long,
        value_name = "VERSION",
        default_value = "1.2",
        help_heading = "Upstream"
    )]
    upstream_tls_min: TlsVersion,

    /// Highest TLS version offered to servers: 1.2 or 1.3.
    #[arg(
        long,
        value_name = "VERSION",
        default_value = "1.3",
        help_heading = "Upstream"
    )]
    upstream_tls_max: TlsVersion,

    /// Send NAME as SNI (and verify against it) for matching hosts.
    ///
    /// HOST is a pattern like in --tls-passthrough. Repeat for several hosts;
    /// the first match applies.
    #[arg(long, value_name = "HOST=NAME", value_parser = parse_sni, help_heading = "Upstream")]
    upstream_sni: Vec<(HostPattern, String)>,

    /// Connect to IP instead of resolving matching hosts. Repeatable.
    #[arg(long, value_name = "HOST=IP", value_parser = parse_resolve, help_heading = "Upstream")]
    resolve: Vec<(HostPattern, IpAddr)>,

    /// Present a client certificate to matching hosts. Repeatable.
    ///
    /// CERT is a PEM chain, leaf first. KEY is a PEM private key; without
    /// it, the key is read from CERT.
    #[arg(
        long,
        value_name = "HOST=CERT[,KEY]",
        value_parser = parse_client_cert,
        help_heading = "Upstream"
    )]
    client_cert: Vec<(HostPattern, ClientCert)>,

    /// Seconds to wait for an upstream connection, including its TLS
    /// handshake.
    #[arg(long, value_name = "SECONDS", default_value = "10", value_parser = parse_seconds, help_heading = "Upstream")]
    connect_timeout: Duration,

    /// Seconds to wait for data while a message is being received, from
    /// the client or a server.
    #[arg(long, value_name = "SECONDS", default_value = "60", value_parser = parse_seconds)]
    read_timeout: Duration,
}

/// Splits `HOST=VALUE` and parses the host pattern.
fn split_rule(s: &str) -> Result<(HostPattern, &str), String> {
    let (host, value) = s
        .split_once('=')
        .ok_or_else(|| format!("expected HOST=VALUE, got {s:?}"))?;
    Ok((host.parse()?, value))
}

fn parse_sni(s: &str) -> Result<(HostPattern, String), String> {
    let (host, name) = split_rule(s)?;
    if name.is_empty() {
        return Err("the server name is empty".to_owned());
    }
    Ok((host, name.to_owned()))
}

fn parse_resolve(s: &str) -> Result<(HostPattern, IpAddr), String> {
    let (host, ip) = split_rule(s)?;
    let ip = ip
        .trim_matches(|c| c == '[' || c == ']')
        .parse()
        .map_err(|_| format!("invalid IP address {ip:?}"))?;
    Ok((host, ip))
}

fn parse_client_cert(s: &str) -> Result<(HostPattern, ClientCert), String> {
    let (host, files) = split_rule(s)?;
    let (cert_path, key_path) = files.split_once(',').unwrap_or((files, files));
    let read = |path: &str| std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"));
    let cert = ClientCert::from_pem(&read(cert_path)?, &read(key_path)?)
        .map_err(|e| format!("{files}: {e}"))?;
    Ok((host, cert))
}

fn parse_seconds(s: &str) -> Result<Duration, String> {
    s.parse::<f64>()
        .ok()
        .filter(|secs| secs.is_finite() && *secs > 0.0)
        .map(Duration::from_secs_f64)
        .ok_or_else(|| format!("expected a positive number of seconds, got {s:?}"))
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
    let verification = if args.verify_upstream {
        "Upstream certificates are verified against the OS trust store."
    } else {
        "WARNING: upstream certificates are not verified (use --verify-upstream)."
    };
    runtime.block_on(async {
        let config = ProxyConfig {
            listen: args.listen,
            tls_passthrough: args.tls_passthrough,
            connect_timeout: args.connect_timeout,
            read_timeout: args.read_timeout,
            upstream: UpstreamConfig {
                verify: args.verify_upstream,
                tls_min: args.upstream_tls_min,
                tls_max: args.upstream_tls_max,
                sni: args.upstream_sni,
                resolve: args.resolve,
                client_certs: args.client_cert,
            },
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
            "HTTPS is intercepted with the Hiccup CA ({}).",
            ca::INSTALL_GUIDE
        );
        eprintln!("{verification}");
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
