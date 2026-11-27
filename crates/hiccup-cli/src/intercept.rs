// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup intercept`: hold, inspect, edit, forward and drop messages.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Subcommand, ValueEnum};
use hiccup_control::api::{
    ForwardAllResult, ForwardParams, InterceptRulesParams, InterceptStatus, ItemParams,
    PendingItem, PendingSummary, method,
};
use serde_json::Value;

use crate::Globals;
use crate::instance;

#[derive(Debug, Subcommand)]
pub enum InterceptCommand {
    /// Start holding matching messages (requests by default).
    On(OnArgs),
    /// Stop holding messages, and forward the held ones.
    Off(DirectionArgs),
    /// Show the intercept settings.
    Status,
    /// List held messages.
    List,
    /// Show a held message.
    Show(ShowArgs),
    /// Forward a held message unchanged, or all with --all.
    Forward(ForwardArgs),
    /// Drop a held message: the client gets a 502 response from Hiccup.
    Drop(IdArgs),
    /// Forward a held message after editing it. The new bytes are sent
    /// exactly as given.
    ///
    /// The bytes come from --file, from standard input when it is not a
    /// terminal, or else from $VISUAL / $EDITOR, opened on the message.
    Edit(EditArgs),
}

#[derive(Debug, Args)]
pub struct DirectionArgs {
    /// Requests.
    #[arg(long)]
    requests: bool,
    /// Responses.
    #[arg(long)]
    responses: bool,
}

impl DirectionArgs {
    /// `(requests, responses)`; neither flag means `default`.
    fn select(&self, default: (bool, bool)) -> (bool, bool) {
        if self.requests || self.responses {
            (self.requests, self.responses)
        } else {
            default
        }
    }
}

#[derive(Debug, Args)]
pub struct OnArgs {
    #[command(flatten)]
    directions: DirectionArgs,
    /// Only for these hosts (`example.com`, `*.example.com`). Repeatable.
    #[arg(long, value_name = "PATTERN")]
    host: Vec<String>,
    /// Only for these methods. Repeatable, or comma-separated.
    #[arg(long, value_name = "METHOD", value_delimiter = ',')]
    method: Vec<String>,
    /// Only for request targets matching this regular expression.
    #[arg(long, value_name = "REGEX")]
    path: Option<String>,
    /// Seconds a message may wait before --on-timeout applies. Default:
    /// forever.
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<f64>,
    /// What happens on timeout.
    #[arg(long, value_enum, default_value_t = OnTimeout::Forward, requires = "timeout")]
    on_timeout: OnTimeout,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OnTimeout {
    Forward,
    Drop,
}

#[derive(Debug, Args)]
pub struct IdArgs {
    /// The message ID, from `hiccup intercept list`.
    id: u64,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    /// The message ID, from `hiccup intercept list`.
    id: u64,
    /// Write only the exact bytes, e.g. to edit them in a file.
    #[arg(long)]
    raw: bool,
}

#[derive(Debug, Args)]
pub struct ForwardArgs {
    /// The message ID, from `hiccup intercept list`.
    #[arg(required_unless_present = "all", conflicts_with = "all")]
    id: Option<u64>,
    /// Forward every held message.
    #[arg(long)]
    all: bool,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// The message ID, from `hiccup intercept list`.
    id: u64,
    /// Read the new message from this file.
    #[arg(long, value_name = "FILE")]
    file: Option<PathBuf>,
}

pub fn run(command: InterceptCommand, globals: &Globals) -> ExitCode {
    match command {
        InterceptCommand::On(args) => on(&args, globals),
        InterceptCommand::Off(args) => off(&args, globals),
        InterceptCommand::Status => {
            call(globals, method::INTERCEPT_STATUS, Value::Null, print_status)
        }
        InterceptCommand::List => call(globals, method::INTERCEPT_LIST, Value::Null, print_list),
        InterceptCommand::Show(args) => show(&args, globals),
        InterceptCommand::Forward(ForwardArgs { all: true, .. }) => {
            call(globals, method::INTERCEPT_FORWARD_ALL, Value::Null, |v| {
                let r: ForwardAllResult = serde_json::from_value(v).expect("typed");
                println!("Forwarded {} message(s).", r.forwarded);
            })
        }
        InterceptCommand::Forward(ForwardArgs { id, .. }) => {
            let params = ForwardParams {
                id: id.expect("required by clap"),
                raw: None,
            };
            call(
                globals,
                method::INTERCEPT_FORWARD,
                to_value(&params),
                |_| {
                    println!("Forwarded.");
                },
            )
        }
        InterceptCommand::Drop(IdArgs { id }) => call(
            globals,
            method::INTERCEPT_DROP,
            to_value(&ItemParams { id }),
            |_| {
                println!("Dropped.");
            },
        ),
        InterceptCommand::Edit(args) => edit(&args, globals),
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("API types serialize")
}

/// Calls `method`; prints the result with `human`, or as JSON.
fn call(
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

fn request(globals: &Globals, method: &'static str, params: Value) -> Option<Value> {
    instance::call(globals, move |client| {
        Box::pin(async move { client.call_value(method, params).await })
    })
}

fn status(globals: &Globals) -> Option<InterceptStatus> {
    request(globals, method::INTERCEPT_STATUS, Value::Null)
        .map(|v| serde_json::from_value(v).expect("typed"))
}

fn on(args: &OnArgs, globals: &Globals) -> ExitCode {
    let Some(mut settings) = status(globals).map(|s| s.settings) else {
        return ExitCode::FAILURE;
    };
    let rules = InterceptRulesParams {
        hosts: args.host.clone(),
        methods: args.method.clone(),
        path: args.path.clone(),
    };
    let (requests, responses) = args.directions.select((true, false));
    if requests {
        settings.requests = Some(rules.clone());
    }
    if responses {
        settings.responses = Some(rules);
    }
    if let Some(secs) = args.timeout {
        if !(secs.is_finite() && secs > 0.0) {
            eprintln!("hiccup: --timeout must be a positive number of seconds");
            return ExitCode::from(2);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // Positive, finite.
        let millis = (secs * 1000.0).round().max(1.0) as u64;
        settings.timeout_ms = Some(millis);
        settings.on_timeout = Some(
            match args.on_timeout {
                OnTimeout::Forward => "forward",
                OnTimeout::Drop => "drop",
            }
            .to_owned(),
        );
    }
    call(
        globals,
        method::INTERCEPT_SET,
        to_value(&settings),
        print_status,
    )
}

fn off(args: &DirectionArgs, globals: &Globals) -> ExitCode {
    let Some(mut settings) = status(globals).map(|s| s.settings) else {
        return ExitCode::FAILURE;
    };
    let (requests, responses) = args.select((true, true));
    if requests {
        settings.requests = None;
    }
    if responses {
        settings.responses = None;
    }
    call(
        globals,
        method::INTERCEPT_SET,
        to_value(&settings),
        print_status,
    )
}

fn print_status(value: Value) {
    let status: InterceptStatus = serde_json::from_value(value).expect("typed");
    let describe = |rules: &Option<InterceptRulesParams>| match rules {
        None => "off".to_owned(),
        Some(r) => {
            let mut parts = Vec::new();
            if !r.hosts.is_empty() {
                parts.push(format!("hosts {}", r.hosts.join(", ")));
            }
            if !r.methods.is_empty() {
                parts.push(format!("methods {}", r.methods.join(", ")));
            }
            if let Some(path) = &r.path {
                parts.push(format!("path /{path}/"));
            }
            if parts.is_empty() {
                "on (all)".to_owned()
            } else {
                format!("on ({})", parts.join("; "))
            }
        }
    };
    println!("Requests:  {}", describe(&status.settings.requests));
    println!("Responses: {}", describe(&status.settings.responses));
    match status.settings.timeout_ms {
        Some(ms) => println!(
            "Timeout:   {:.1}s, then {}",
            Duration::from_millis(ms).as_secs_f64(),
            status.settings.on_timeout.as_deref().unwrap_or("forward")
        ),
        None => println!("Timeout:   none"),
    }
    println!("Held:      {}", status.pending);
}

fn print_list(value: Value) {
    let items: Vec<PendingSummary> = serde_json::from_value(value).expect("typed");
    if items.is_empty() {
        println!("No held message.");
        return;
    }
    println!(
        "{:>6}  {:<8}  {:<7}  {:>6}  {:>7}  TARGET",
        "ID", "DIR", "METHOD", "STATUS", "AGE"
    );
    for i in items {
        let scheme = if i.tls { "https" } else { "http" };
        println!(
            "{:>6}  {:<8}  {:<7}  {:>6}  {:>6.1}s  {scheme}://{}{}",
            i.id,
            i.direction,
            escape(i.method.as_bytes()),
            i.status.map_or_else(|| "-".to_owned(), |s| s.to_string()),
            Duration::from_millis(i.age_ms).as_secs_f64(),
            escape(i.upstream.as_bytes()),
            escape(i.target.as_bytes())
        );
    }
}

fn fetch(globals: &Globals, id: u64) -> Option<(PendingItem, Vec<u8>)> {
    let value = request(
        globals,
        method::INTERCEPT_SHOW,
        to_value(&ItemParams { id }),
    )?;
    let item: PendingItem = serde_json::from_value(value).expect("typed");
    match data_encoding::BASE64.decode(item.raw.as_bytes()) {
        Ok(raw) => Some((item, raw)),
        Err(e) => {
            eprintln!("hiccup: the instance sent invalid base64: {e}");
            None
        }
    }
}

fn show(args: &ShowArgs, globals: &Globals) -> ExitCode {
    if globals.json {
        let params = to_value(&ItemParams { id: args.id });
        return call(globals, method::INTERCEPT_SHOW, params, |_| {});
    }
    let Some((item, raw)) = fetch(globals, args.id) else {
        return ExitCode::FAILURE;
    };
    let mut stdout = std::io::stdout().lock();
    if !args.raw {
        let s = &item.summary;
        let _ = writeln!(
            stdout,
            "# {} {} {} {}{} ({} bytes)",
            s.id,
            s.direction,
            escape(s.method.as_bytes()),
            escape(s.upstream.as_bytes()),
            escape(s.target.as_bytes()),
            s.size
        );
    }
    // The bytes come from the client or the server: never let them drive
    // the terminal (escape sequences can rewrite the screen or set the
    // clipboard). Redirected, they are written exactly.
    let raw = if std::io::stdout().is_terminal() {
        let escaped = escape(&raw);
        if args.raw && escaped.as_bytes() != raw.as_slice() {
            eprintln!(
                "Note: control characters are escaped; redirect the output for the exact bytes."
            );
        }
        escaped.into_bytes()
    } else {
        raw
    };
    if stdout
        .write_all(&raw)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn edit(args: &EditArgs, globals: &Globals) -> ExitCode {
    let edited = if let Some(path) = &args.file {
        match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("hiccup: cannot read {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    } else if !std::io::stdin().is_terminal() {
        let mut bytes = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut bytes) {
            eprintln!("hiccup: cannot read standard input: {e}");
            return ExitCode::FAILURE;
        }
        bytes
    } else {
        let Some((_, original)) = fetch(globals, args.id) else {
            return ExitCode::FAILURE;
        };
        match edit_in_editor(&original, &editor()) {
            Ok(bytes) if bytes == original => {
                eprintln!("Unchanged: forwarding the original message.");
                let params = ForwardParams {
                    id: args.id,
                    raw: None,
                };
                return call(
                    globals,
                    method::INTERCEPT_FORWARD,
                    to_value(&params),
                    |_| {
                        println!("Forwarded.");
                    },
                );
            }
            Ok(bytes) => {
                if introduces_bare_lf(&original, &bytes) {
                    eprintln!(
                        "Note: the edited head has bare LF line endings (the original used \
                         CRLF). They are sent as is."
                    );
                }
                bytes
            }
            Err(e) => {
                eprintln!("hiccup: {e}; the message is still held");
                return ExitCode::FAILURE;
            }
        }
    };
    if edited.is_empty() {
        eprintln!("hiccup: the edited message is empty; use `hiccup intercept drop` to drop it");
        return ExitCode::FAILURE;
    }
    let params = ForwardParams {
        id: args.id,
        raw: Some(data_encoding::BASE64.encode(&edited)),
    };
    call(
        globals,
        method::INTERCEPT_FORWARD,
        to_value(&params),
        |_| {
            println!("Forwarded the edited message ({} bytes).", edited.len());
        },
    )
}

/// `$VISUAL`, else `$EDITOR`, else the platform's default editor.
fn editor() -> String {
    std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| if cfg!(windows) { "notepad" } else { "vi" }.to_owned())
}

/// Opens `editor` (a program and its arguments) on a private temporary copy
/// of `original`, and returns what it saved.
fn edit_in_editor(original: &[u8], editor: &str) -> Result<Vec<u8>, String> {
    let mut words = editor.split_whitespace();
    let program = words.next().ok_or("$EDITOR is empty")?;
    // Created readable by the user only: messages can hold credentials.
    let mut file = tempfile::Builder::new()
        .prefix("hiccup-intercept-")
        .suffix(".http")
        .tempfile()
        .map_err(|e| format!("cannot create a temporary file: {e}"))?;
    file.write_all(original)
        .and_then(|()| file.flush())
        .map_err(|e| format!("cannot write the temporary file: {e}"))?;
    let status = std::process::Command::new(program)
        .args(words)
        .arg(file.path())
        .status()
        .map_err(|e| format!("cannot run {program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program} exited with {status}"));
    }
    std::fs::read(file.path()).map_err(|e| format!("cannot read the edited file: {e}"))
}

/// Whether the edit turned the head's CRLF line endings into bare LF, as
/// editors often do. The bytes are still sent exactly, but servers may
/// reject them.
fn introduces_bare_lf(original: &[u8], edited: &[u8]) -> bool {
    let head = |b: &[u8]| {
        let end = b
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .or_else(|| b.windows(2).position(|w| w == b"\n\n"))
            .unwrap_or(b.len());
        b[..end].to_vec()
    };
    let bare_lf = |b: &[u8]| {
        b.iter()
            .enumerate()
            .any(|(i, &c)| c == b'\n' && (i == 0 || b[i - 1] != b'\r'))
    };
    !bare_lf(&head(original)) && bare_lf(&head(edited))
}

/// Text safe to print to a terminal: control characters other than tab, LF
/// and CRLF, and invalid UTF-8, are shown as `\xNN` or `\u{NN}`. A bare CR
/// is escaped too: it would let the message overwrite what is printed.
fn escape(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        let mut chars = chunk.valid().chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\r' if chars.peek() == Some(&'\n') => out.push(c),
                '\t' | '\n' => out.push(c),
                c if c.is_control() && c.is_ascii() => {
                    let _ = write!(out, "\\x{:02x}", u32::from(c));
                }
                c if c.is_control() => {
                    let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
                }
                c => out.push(c),
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{escape, introduces_bare_lf};

    #[test]
    fn bare_lf_is_noticed_in_the_head_only() {
        let crlf = b"GET / HTTP/1.1\r\nA: b\r\n\r\nbody\n";
        assert!(!introduces_bare_lf(crlf, crlf));
        assert!(introduces_bare_lf(crlf, b"GET / HTTP/1.1\nA: b\n\n"));
        assert!(!introduces_bare_lf(b"GET /\nA: b\n\n", b"GET /x\nA: b\n\n"));
    }

    #[cfg(unix)]
    #[test]
    fn the_editor_edits_a_temporary_copy() {
        use super::edit_in_editor;
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("editor");
        // Arguments are passed through; the file comes last.
        std::fs::write(&script, "#!/bin/sh\nprintf '%s' \"$1\" >> \"$2\"\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let editor = format!("{} -edited", script.display());
        assert_eq!(
            edit_in_editor(b"GET / HTTP/1.1\r\n\r\n", &editor).unwrap(),
            b"GET / HTTP/1.1\r\n\r\n-edited"
        );

        let err = edit_in_editor(b"x", "false").unwrap_err();
        assert!(err.starts_with("false exited with"), "{err}");
        let err = edit_in_editor(b"x", "/nonexistent/editor").unwrap_err();
        assert!(err.starts_with("cannot run /nonexistent/editor"), "{err}");
        assert_eq!(edit_in_editor(b"x", " ").unwrap_err(), "$EDITOR is empty");
    }

    #[test]
    fn escape_neutralises_terminal_controls() {
        assert_eq!(
            escape(b"GET / HTTP/1.1\r\n\tx\n"),
            "GET / HTTP/1.1\r\n\tx\n"
        );
        assert_eq!(escape("caf\u{e9}".as_bytes()), "caf\u{e9}");
        // OSC 52 (set the clipboard), CSI, DEL, a C1 CSI and a raw 0x9b byte.
        assert_eq!(
            escape(b"\x1b]52;c;aGk=\x07\x1b[2J\x7f"),
            "\\x1b]52;c;aGk=\\x07\\x1b[2J\\x7f"
        );
        assert_eq!(escape("\u{9b}".as_bytes()), "\\u{9b}");
        assert_eq!(escape(b"a\x9bb"), "a\\x9bb");
        // A bare CR could hide what precedes it on the line.
        assert_eq!(
            escape(b"Host: evil\rHost: good\r\n"),
            "Host: evil\\x0dHost: good\r\n"
        );
        assert_eq!(escape(b"end\r"), "end\\x0d");
    }
}
