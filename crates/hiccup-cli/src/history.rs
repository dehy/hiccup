// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup history`: the exchanges an instance recorded in its project.

use std::io::Write;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use hiccup_control::api::{
    HistoryItem, HistoryListParams, HistoryPage, HistorySummary, ItemParams, method,
};
use serde_json::Value;

use crate::Globals;
use crate::events::url;
use crate::instance::{self, call_method, to_value};
use crate::intercept::{escape, for_stdout};

#[derive(Debug, Subcommand)]
pub enum HistoryCommand {
    /// List recorded exchanges, newest first.
    List(ListArgs),
    /// Show a recorded exchange: its request and response as received.
    Show(ShowArgs),
    /// Write every matching exchange with its messages, as one JSON object
    /// per line (messages base64-encoded, as `history.show` returns them).
    Export(FilterArgs),
}

#[derive(Debug, Args)]
pub struct FilterArgs {
    /// Only this host (exactly, ignoring case).
    #[arg(long)]
    host: Option<String>,
    /// Only this request method.
    #[arg(long)]
    method: Option<String>,
    /// Only this response status.
    #[arg(long)]
    status: Option<u16>,
    /// Only responses whose media type starts with this, e.g. `image/`.
    #[arg(long, value_name = "PREFIX")]
    mime: Option<String>,
    /// Only exchanges whose request or response contains this text.
    #[arg(long, value_name = "TEXT")]
    search: Option<String>,
    /// Only what is in scope (see `hiccup scope`).
    #[arg(long)]
    in_scope: bool,
}

impl FilterArgs {
    fn params(&self, before: Option<u64>, limit: u32) -> HistoryListParams {
        HistoryListParams {
            host: self.host.clone(),
            method: self.method.clone(),
            status: self.status,
            mime: self.mime.clone(),
            search: self.search.clone(),
            in_scope: self.in_scope,
            before,
            limit: Some(limit),
        }
    }
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[command(flatten)]
    filter: FilterArgs,
    /// At most this many (at most 1000).
    #[arg(long, default_value_t = 50)]
    limit: u32,
    /// Only exchanges older than this ID, for the next page.
    #[arg(long, value_name = "ID")]
    before: Option<u64>,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The exchange ID, from `hiccup history list`.
    id: u64,
    /// Write only the request, exactly as received.
    #[arg(long, conflicts_with = "response")]
    request: bool,
    /// Write only the response, exactly as received.
    #[arg(long)]
    response: bool,
}

pub fn run(command: HistoryCommand, globals: &Globals) -> ExitCode {
    match command {
        HistoryCommand::List(args) => {
            let params = to_value(&args.filter.params(args.before, args.limit));
            call_method(globals, method::HISTORY_LIST, params, |page| {
                print_page(page, args.limit);
            })
        }
        HistoryCommand::Show(args) => show(&args, globals),
        HistoryCommand::Export(filter) => export(&filter, globals),
    }
}

fn print_page(value: Value, limit: u32) {
    let page: HistoryPage = serde_json::from_value(value).expect("typed");
    if page.items.is_empty() {
        println!("No recorded exchange.");
        return;
    }
    println!(
        "{:>6}  {:<7}  {:>6}  {:>9}  {:>7}  URL",
        "ID", "METHOD", "STATUS", "SIZE", "TIME"
    );
    for s in &page.items {
        let status = match (&s.error, s.status) {
            (Some(_), _) => "error".to_owned(),
            (None, Some(status)) => status.to_string(),
            (None, None) => "-".to_owned(),
        };
        let size = s
            .response_size
            .map_or_else(|| "-".to_owned(), |n| format!("{n} B"));
        println!(
            "{:>6}  {:<7}  {:>6}  {:>9}  {:>5}ms  {}",
            s.id,
            escape(s.method.as_bytes()),
            status,
            size,
            s.duration_ms,
            describe_url(s)
        );
    }
    // A full page: there may be more.
    if page.items.len() == limit as usize {
        let last = page.items.last().expect("not empty").id;
        eprintln!("Older: hiccup history list --before {last}");
    }
}

fn describe_url(s: &HistorySummary) -> String {
    let (upstream, target) = (escape(s.upstream.as_bytes()), escape(s.target.as_bytes()));
    url(s.tls, &upstream, &target)
}

fn decode(field: &str) -> Vec<u8> {
    data_encoding::BASE64
        .decode(field.as_bytes())
        .unwrap_or_else(|e| panic!("the instance sent invalid base64: {e}"))
}

fn show(args: &ShowArgs, globals: &Globals) -> ExitCode {
    let params = to_value(&ItemParams { id: args.id });
    if globals.json {
        return call_method(globals, method::HISTORY_SHOW, params, |_| {});
    }
    let Some(value) = instance::request(globals, method::HISTORY_SHOW, params) else {
        return ExitCode::FAILURE;
    };
    let item: HistoryItem = serde_json::from_value(value).expect("typed");
    let response = item.response.as_deref().map(decode);
    let out = if args.request {
        for_stdout(decode(&item.received), true)
    } else if args.response {
        let Some(response) = response else {
            eprintln!("hiccup: exchange {} has no response", args.id);
            return ExitCode::FAILURE;
        };
        for_stdout(response, true)
    } else {
        let s = &item.summary;
        let mut out = format!(
            "# {} {} {}",
            s.id,
            escape(s.method.as_bytes()),
            describe_url(s)
        );
        if let Some(error) = &s.error {
            out.push_str(&format!(" (failed: {})", escape(error.as_bytes())));
        }
        let mut out = format!("{out}\n").into_bytes();
        out.extend(for_stdout(decode(&item.received), false));
        if let Some(response) = response {
            out.extend_from_slice(b"\n");
            out.extend(for_stdout(response, false));
        }
        out
    };
    let mut stdout = std::io::stdout().lock();
    if stdout
        .write_all(&out)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Pages through the list, newest first, and writes each exchange in full,
/// on one connection.
fn export(filter: &FilterArgs, globals: &Globals) -> ExitCode {
    let params = filter.params(None, 1000);
    let done = instance::call(globals, move |client| {
        Box::pin(async move {
            let mut before = None;
            loop {
                let page = HistoryListParams {
                    before,
                    ..params.clone()
                };
                let page: HistoryPage = client.call(method::HISTORY_LIST, page).await?;
                let Some(last) = page.items.last() else {
                    return Ok(Value::Null);
                };
                before = Some(last.id);
                for summary in &page.items {
                    let item: Value = client
                        .call_value(method::HISTORY_SHOW, ItemParams { id: summary.id })
                        .await?;
                    let mut stdout = std::io::stdout().lock();
                    if writeln!(stdout, "{item}").is_err() {
                        return Ok(Value::Null); // Stdout closed, e.g. `| head`.
                    }
                }
            }
        })
    });
    done.map_or(ExitCode::FAILURE, |_| ExitCode::SUCCESS)
}
