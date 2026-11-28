// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup proxy`: start, stop and inspect the proxy of an instance.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand};
use hiccup_control::api::{
    ClientCertRule, HostRule, ProxyStartParams, ProxyStartResult, ProxyStatus, method,
};
use hiccup_proxy::{ClientCert, HostPattern, ProxyConfig, TlsVersion};

use crate::Globals;
use crate::config::Config;
use crate::instance::{self, Hosted};

#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Start the proxy in the running instance, or in this terminal with
    /// --foreground.
    Start(StartArgs),
    /// Stop the proxy of the running instance.
    Stop,
    /// Show the proxy of the running instance.
    Status,
}

#[derive(Debug, Args)]
pub struct StartArgs {
    /// Run an instance with the proxy in this terminal until Ctrl+C.
    ///
    /// Other `hiccup` commands can control it while it runs.
    #[arg(long)]
    foreground: bool,

    /// Address to listen on. Repeat to listen on several addresses.
    /// Default: `proxy.listen` (see `hiccup config`), or 127.0.0.1:8080.
    #[arg(long = "listen", value_name = "ADDR")]
    listen: Vec<SocketAddr>,

    /// Relay HTTPS to matching hosts without intercepting it, e.g. for clients
    /// that pin certificates. `*.example.com` matches subdomains, `*` every
    /// host. Repeat for several patterns.
    #[arg(long, value_name = "PATTERN")]
    tls_passthrough: Vec<HostPattern>,

    /// Verify upstream server certificates against the OS trust store.
    ///
    /// Off by default, so that targets with self-signed or invalid
    /// certificates can be tested; `proxy.verify-upstream` (see
    /// `hiccup config`) changes the default.
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
    client_cert: Vec<ClientCertRule>,

    /// Seconds to wait for an upstream connection, including its TLS
    /// handshake.
    #[arg(long, value_name = "SECONDS", default_value = "10", value_parser = parse_seconds, help_heading = "Upstream")]
    connect_timeout: Duration,

    /// Seconds to wait for data while a message is being received, from
    /// the client or a server.
    #[arg(long, value_name = "SECONDS", default_value = "60", value_parser = parse_seconds)]
    read_timeout: Duration,
}

impl StartArgs {
    /// The parameters, with unset flags taken from `config`.
    fn params(&self, config: &Config) -> ProxyStartParams {
        let millis = |d: Duration| Some(u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let rule = |(host, value): &(HostPattern, String)| HostRule {
            host: host.to_string(),
            value: value.clone(),
        };
        ProxyStartParams {
            listen: match (self.listen.as_slice(), config.listen()) {
                ([], saved) if saved.is_empty() => vec![ProxyConfig::DEFAULT_LISTEN.to_string()],
                ([], saved) => saved.iter().map(ToString::to_string).collect(),
                (given, _) => given.iter().map(ToString::to_string).collect(),
            },
            tls_passthrough: self
                .tls_passthrough
                .iter()
                .map(ToString::to_string)
                .collect(),
            verify_upstream: self.verify_upstream || config.verify_upstream(),
            upstream_tls_min: Some(self.upstream_tls_min.to_string()),
            upstream_tls_max: Some(self.upstream_tls_max.to_string()),
            upstream_sni: self.upstream_sni.iter().map(rule).collect(),
            resolve: self
                .resolve
                .iter()
                .map(|(host, ip)| rule(&(host.clone(), ip.to_string())))
                .collect(),
            client_certs: self.client_cert.clone(),
            connect_timeout_ms: millis(self.connect_timeout),
            read_timeout_ms: millis(self.read_timeout),
        }
    }
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

/// Checks the files now, for an early error, and sends absolute paths: the
/// instance may run in another directory.
fn parse_client_cert(s: &str) -> Result<ClientCertRule, String> {
    let (host, files) = split_rule(s)?;
    let (cert_path, key_path) = match files.split_once(',') {
        Some((cert, key)) => (cert, Some(key)),
        None => (files, None),
    };
    let read = |path: &str| std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"));
    let cert = read(cert_path)?;
    let key = key_path.map(read).transpose()?;
    ClientCert::from_pem(&cert, key.as_deref().unwrap_or(&cert))
        .map_err(|e| format!("{files}: {e}"))?;
    let absolute = |path: &str| {
        std::path::absolute(PathBuf::from(path))
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(|e| format!("{path}: {e}"))
    };
    Ok(ClientCertRule {
        host: host.to_string(),
        cert: absolute(cert_path)?,
        key: key_path.map(absolute).transpose()?,
    })
}

fn parse_seconds(s: &str) -> Result<Duration, String> {
    s.parse::<f64>()
        .ok()
        .filter(|secs| secs.is_finite() && *secs > 0.0)
        .map(Duration::from_secs_f64)
        .ok_or_else(|| format!("expected a positive number of seconds, got {s:?}"))
}

pub fn run(command: ProxyCommand, globals: &Globals) -> ExitCode {
    match command {
        ProxyCommand::Start(args) if args.foreground => foreground(&args, globals),
        ProxyCommand::Start(args) => {
            let Some(config) = globals.config() else {
                return ExitCode::FAILURE;
            };
            start(globals, args.params(&config))
        }
        ProxyCommand::Stop => instance::call(globals, |client| {
            Box::pin(async move { client.call_value(method::PROXY_STOP, ()).await })
        })
        .map_or(ExitCode::FAILURE, |value| {
            if globals.json {
                crate::print_json(&value);
            } else {
                println!("Proxy stopped.");
            }
            ExitCode::SUCCESS
        }),
        ProxyCommand::Status => instance::call(globals, |client| {
            Box::pin(async move { client.call_value(method::PROXY_STATUS, ()).await })
        })
        .map_or(ExitCode::FAILURE, |value| {
            if globals.json {
                crate::print_json(&value);
            } else {
                let status: ProxyStatus = serde_json::from_value(value).expect("typed");
                print_status(&status);
            }
            ExitCode::SUCCESS
        }),
    }
}

fn print_started(result: &ProxyStartResult) {
    for addr in &result.proxy.listen {
        // The first line is parsed by scripts and tests: keep it stable.
        eprintln!("Hiccup proxy listening on http://{addr}");
    }
    let exposed = result.proxy.listen.iter().any(|a| {
        a.parse::<std::net::SocketAddr>()
            .is_ok_and(|a| !a.ip().is_loopback())
    });
    if exposed {
        eprintln!(
            "WARNING: the proxy is reachable from other machines, without authentication. \
             Anyone who can reach it can use it, reach services on this machine, and have \
             HTTPS decrypted with your CA."
        );
    }
    if result.ca_generated {
        eprintln!(
            "Generated a new CA (SHA-256 {}). Install it to intercept HTTPS: {}",
            result.ca_sha256,
            crate::ca::INSTALL_GUIDE
        );
    } else {
        eprintln!(
            "HTTPS is intercepted with the Hiccup CA ({}).",
            crate::ca::INSTALL_GUIDE
        );
    }
    if result.proxy.verify_upstream {
        eprintln!("Upstream certificates are verified against the OS trust store.");
    } else {
        eprintln!("WARNING: upstream certificates are not verified (use --verify-upstream).");
    }
}

fn print_status(status: &ProxyStatus) {
    if !status.running {
        println!("Proxy:        stopped");
        return;
    }
    println!("Proxy:        running");
    for addr in &status.listen {
        println!("Listening:    http://{addr}");
    }
    println!(
        "Verification: {}",
        if status.verify_upstream { "on" } else { "off" }
    );
    println!("Exchanges:    {}", status.exchanges);
}

/// `proxy start`: start the proxy of the running instance.
fn start(globals: &Globals, params: ProxyStartParams) -> ExitCode {
    instance::call(globals, |client| {
        Box::pin(async move {
            let result: ProxyStartResult = client.call(method::PROXY_START, params).await?;
            Ok(serde_json::to_value(result).expect("serializes"))
        })
    })
    .map_or(ExitCode::FAILURE, |value| {
        if globals.json {
            crate::print_json(&value);
        } else {
            let result: ProxyStartResult = serde_json::from_value(value).expect("typed");
            print_started(&result);
        }
        ExitCode::SUCCESS
    })
}

/// `proxy start --foreground`: host an instance, start its proxy, and run
/// until Ctrl+C, `hiccup proxy stop` or `hiccup instance stop`.
fn foreground(args: &StartArgs, globals: &Globals) -> ExitCode {
    let Some(config) = globals.config() else {
        return ExitCode::FAILURE;
    };
    let params = args.params(&config);
    instance::host(globals, |hosted: Hosted| {
        Box::pin(async move {
            let result = match hosted.instance.start_proxy(params).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("hiccup: {}", e.message);
                    return ExitCode::FAILURE;
                }
            };
            print_started(&result);
            eprintln!("Press Ctrl+C to stop.");
            let mut running = hosted.instance.proxy_running();
            let shutdown = hosted.instance.shutdown_token();
            tokio::select! {
                r = tokio::signal::ctrl_c() => {
                    if r.is_ok() {
                        eprintln!("Stopping...");
                    }
                }
                () = shutdown.cancelled() => {}
                _ = running.wait_for(|running| !running) => eprintln!("The proxy was stopped."),
            }
            hosted.instance.shutdown().await;
            ExitCode::SUCCESS
        })
    })
}
