// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup events`: stream what the instance does, live.

use std::io::Write;
use std::process::ExitCode;

use clap::Args;
use hiccup_control::api::{method, notification};
use serde_json::{Value, json};

use crate::Globals;
use crate::instance;
use crate::intercept::escape;

#[derive(Debug, Args)]
pub struct EventsArgs {
    /// Only events whose name starts with this, e.g. `exchange` or
    /// `intercept.pending`. Repeatable.
    #[arg(long, value_name = "PREFIX")]
    filter: Vec<String>,
}

pub fn run(args: &EventsArgs, globals: &Globals) -> ExitCode {
    loop {
        let filter = args.filter.clone();
        let json = globals.json;
        let ended = instance::call(globals, move |client| {
            Box::pin(async move {
                client.call_value(method::EVENTS_SUBSCRIBE, ()).await?;
                eprintln!("Streaming events (Ctrl+C to stop).");
                loop {
                    let n = client.next_notification().await?;
                    match n.method.as_str() {
                        notification::INSTANCE_STOPPING => return Ok(json!("done")),
                        notification::EVENTS_LAGGED => return Ok(n.params),
                        _ => {}
                    }
                    if !filter.is_empty() && !filter.iter().any(|f| n.method.starts_with(f)) {
                        continue;
                    }
                    let line = if json {
                        json!({ "event": n.method, "data": n.params }).to_string()
                    } else {
                        describe(&n.method, &n.params)
                    };
                    let mut out = std::io::stdout().lock();
                    if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
                        return Ok(json!("done"));
                    }
                }
            })
        });
        // `events.lagged` data, or "done" (the instance stopped, or stdout
        // closed, e.g. `| head`).
        match ended {
            None => return ExitCode::FAILURE,
            Some(Value::Object(lagged)) => {
                let missed = lagged.get("missed").and_then(Value::as_u64).unwrap_or(0);
                eprintln!("hiccup: fell behind and missed {missed} event(s); subscribing again");
            }
            Some(_) => return ExitCode::SUCCESS,
        }
    }
}

/// The URL of a request to `upstream` with this target; an absolute-form
/// target already names the scheme and host.
pub(crate) fn url(tls: bool, upstream: &str, target: &str) -> String {
    if target.starts_with('/') {
        let scheme = if tls { "https" } else { "http" };
        format!("{scheme}://{upstream}{target}")
    } else {
        target.to_owned()
    }
}

/// One line per event. Text from traffic is escaped: it must not drive the
/// terminal.
fn describe(event: &str, data: &Value) -> String {
    let text = |key: &str| escape(data[key].as_str().unwrap_or_default().as_bytes());
    let id = &data["id"];
    match event {
        notification::EXCHANGE_REQUEST => {
            let url = url(data["tls"] == true, &text("upstream"), &text("target"));
            format!("#{id} {} {url}", text("method"))
        }
        notification::EXCHANGE_RESPONSE => match data["error"].as_str() {
            Some(error) => format!("#{id} failed: {}", escape(error.as_bytes())),
            None => format!(
                "#{id} {} {} B {} ms",
                data["status"], data["size"], data["duration_ms"]
            ),
        },
        notification::INTERCEPT_PENDING => format!(
            "held {id}: {} {} {} ({})",
            text("direction"),
            text("method"),
            text("target"),
            text("upstream")
        ),
        notification::INTERCEPT_RESOLVED => format!("resolved {id}: {}", text("outcome")),
        notification::PROXY_STATE if data["running"] == true => {
            let listen: Vec<_> = data["listen"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            format!("proxy running on {}", listen.join(", "))
        }
        notification::PROXY_STATE => "proxy stopped".to_owned(),
        _ => format!("{event} {data}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_per_event() {
        let request = json!({
            "id": 3, "method": "GET", "upstream": "a.test:443", "tls": true, "target": "/x",
        });
        assert_eq!(
            describe(notification::EXCHANGE_REQUEST, &request),
            "#3 GET https://a.test:443/x"
        );
        let proxied = json!({
            "id": 4, "method": "GET", "upstream": "a.test:80", "tls": false,
            "target": "http://a.test/y",
        });
        assert_eq!(
            describe(notification::EXCHANGE_REQUEST, &proxied),
            "#4 GET http://a.test/y"
        );
        let done = json!({ "id": 3, "status": 200, "size": 12, "duration_ms": 5 });
        assert_eq!(
            describe(notification::EXCHANGE_RESPONSE, &done),
            "#3 200 12 B 5 ms"
        );
        let failed = json!({ "id": 3, "duration_ms": 5, "error": "refused" });
        assert_eq!(
            describe(notification::EXCHANGE_RESPONSE, &failed),
            "#3 failed: refused"
        );
        // A target that tries to drive the terminal is escaped.
        let hostile = json!({
            "id": 5, "method": "GET", "upstream": "a:80", "tls": false,
            "target": "/\u{1b}]52;c;aGk=\u{7}",
        });
        assert_eq!(
            describe(notification::EXCHANGE_REQUEST, &hostile),
            "#5 GET http://a:80/\\x1b]52;c;aGk=\\x07"
        );
        assert_eq!(
            describe(notification::PROXY_STATE, &json!({ "running": false })),
            "proxy stopped"
        );
    }
}
