// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosting an instance (`hiccup serve`, `proxy start --foreground`) and
//! talking to one (every other command), plus `hiccup instance`.

use std::future::Future;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Subcommand;
use hiccup_control::api::method;
use hiccup_control::{BoxFuture, Client, ClientError, Handler, InstanceRecord};
use hiccup_core::Instance;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::Globals;

/// The default instance name.
pub const DEFAULT_NAME: &str = "default";

#[derive(Debug, Subcommand)]
pub enum InstanceCommand {
    /// List the running instances.
    List,
    /// Stop the running instance, and its proxy.
    Stop,
}

/// An instance hosted by this process.
pub struct Hosted {
    pub instance: Arc<Instance>,
    pub record: InstanceRecord,
}

/// Registers and serves an instance while `body` runs. The control endpoint
/// closes, and the instance unregisters, when `body` returns.
pub fn host<F, Fut>(globals: &Globals, body: F) -> ExitCode
where
    F: FnOnce(Hosted) -> Fut,
    Fut: Future<Output = ExitCode>,
{
    let (Some(data_dir), Some(registry)) = (globals.data_dir(), globals.registry()) else {
        return ExitCode::FAILURE;
    };
    let name = globals
        .instance
        .as_deref()
        .unwrap_or(DEFAULT_NAME)
        .to_owned();
    let Some(runtime) = crate::runtime() else {
        return ExitCode::FAILURE;
    };
    runtime.block_on(async {
        let mut registration = match registry.register(&name).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("hiccup: {e}");
                return ExitCode::FAILURE;
            }
        };
        let record = registration.record().clone();
        let Some(config) = globals.config() else {
            return ExitCode::FAILURE;
        };
        let instance = Instance::new(name, data_dir);
        if let Some(project) = &globals.project.clone().or_else(|| config.project()) {
            if let Err(e) = instance.open_project(project) {
                eprintln!("hiccup: cannot open the project {}: {e}", project.display());
                return ExitCode::FAILURE;
            }
            eprintln!("Recording history in {}.", project.display());
        }
        let handler: Arc<dyn Handler> = instance.clone();
        let stop_server = CancellationToken::new();
        let server = hiccup_control::serve(
            &mut registration,
            handler,
            instance.notifier(),
            stop_server.clone(),
        );
        let body = async {
            let code = body(Hosted { instance, record }).await;
            stop_server.cancel();
            code
        };
        let (served, code) = tokio::join!(server, body);
        if let Err(e) = served {
            eprintln!("hiccup: control endpoint failed: {e}");
            return ExitCode::FAILURE;
        }
        code
    })
}

/// Connects to the selected instance and runs `f`. Errors are printed.
pub fn call<F>(globals: &Globals, f: F) -> Option<Value>
where
    F: for<'c> FnOnce(&'c mut Client) -> BoxFuture<'c, Result<Value, ClientError>>,
{
    let registry = globals.registry()?;
    let runtime = crate::runtime()?;
    runtime.block_on(async {
        let record = registry
            .select(globals.instance.as_deref())
            .await
            .map_err(|e| eprintln!("hiccup: {e}"))
            .ok()?;
        let result = async {
            let mut client = Client::connect(&record).await?;
            f(&mut client).await
        }
        .await;
        result.map_err(|e| eprintln!("hiccup: {e}")).ok()
    })
}

pub fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("API types serialize")
}

/// Calls `method`; prints the result with `human`, or as JSON.
pub fn call_method(
    globals: &Globals,
    method: &'static str,
    params: Value,
    human: impl FnOnce(Value),
) -> ExitCode {
    let Some(result) = request(globals, method, params) else {
        return ExitCode::FAILURE;
    };
    if globals.json {
        crate::print_json(&result);
    } else {
        human(result);
    }
    ExitCode::SUCCESS
}

pub fn request(globals: &Globals, method: &'static str, params: Value) -> Option<Value> {
    call(globals, move |client| {
        Box::pin(async move { client.call_value(method, params).await })
    })
}

/// `hiccup serve`: run an instance until Ctrl+C or `hiccup instance stop`.
pub fn serve(globals: &Globals) -> ExitCode {
    host(globals, |hosted: Hosted| async move {
        eprintln!(
            "Hiccup instance {:?} is running (control endpoint: {}).",
            hosted.record.name, hosted.record.endpoint
        );
        eprintln!("Start the proxy with `hiccup proxy start`. Press Ctrl+C to stop.");
        let shutdown = hosted.instance.shutdown_token();
        tokio::select! {
            r = tokio::signal::ctrl_c() => {
                if r.is_ok() {
                    eprintln!("Stopping...");
                }
            }
            () = shutdown.cancelled() => eprintln!("Stopping on request..."),
        }
        hosted.instance.shutdown().await;
        ExitCode::SUCCESS
    })
}

pub fn run(command: InstanceCommand, globals: &Globals) -> ExitCode {
    match command {
        InstanceCommand::List => list(globals),
        InstanceCommand::Stop => call(globals, |client| {
            Box::pin(async move { client.call_value(method::INSTANCE_SHUTDOWN, ()).await })
        })
        .map_or(ExitCode::FAILURE, |value| {
            if globals.json {
                crate::print_json(&value);
            } else {
                println!("The instance is stopping.");
            }
            ExitCode::SUCCESS
        }),
    }
}

fn list(globals: &Globals) -> ExitCode {
    let (Some(registry), Some(runtime)) = (globals.registry(), crate::runtime()) else {
        return ExitCode::FAILURE;
    };
    let live = match runtime.block_on(registry.live()) {
        Ok(live) => live,
        Err(e) => {
            eprintln!("hiccup: cannot read the instance registry: {e}");
            return ExitCode::FAILURE;
        }
    };
    if globals.json {
        crate::print_json(&serde_json::to_value(&live).expect("serializes"));
    } else if live.is_empty() {
        println!("No running instance. Start one with `hiccup serve`.");
    } else {
        println!("{:<16} {:>8}  {:<10} ENDPOINT", "NAME", "PID", "VERSION");
        for r in &live {
            println!(
                "{:<16} {:>8}  {:<10} {}",
                r.name, r.pid, r.version, r.endpoint
            );
        }
    }
    ExitCode::SUCCESS
}
