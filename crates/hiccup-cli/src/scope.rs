// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup scope`: which URLs are being tested.

use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use hiccup_control::api::{
    ScopeRemoveParams, ScopeRuleParams, ScopeRules, ScopeTestParams, ScopeTestResult, method,
};
use serde_json::Value;

use crate::Globals;
use crate::instance::{call_method, to_value};

#[derive(Debug, Subcommand)]
pub enum ScopeCommand {
    /// Add a rule. In scope is what matches an include rule and no exclude
    /// rule; with no include rule, everything not excluded is in scope.
    Add(AddArgs),
    /// Remove a rule, by its number in `hiccup scope list`.
    Remove {
        /// The rule's number.
        number: usize,
    },
    /// List the rules.
    List,
    /// Tell whether a URL is in scope.
    Test {
        /// An `http://` or `https://` URL.
        url: String,
    },
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Exclude what the rule matches, instead of including it.
    #[arg(long)]
    exclude: bool,
    /// Only this protocol.
    #[arg(long, value_enum)]
    protocol: Option<Protocol>,
    /// Only this host (`example.com`, `*.example.com`).
    #[arg(long, value_name = "PATTERN")]
    host: Option<String>,
    /// Only this port.
    #[arg(long)]
    port: Option<u16>,
    /// Only paths (and queries) matching this regular expression.
    #[arg(long, value_name = "REGEX")]
    path: Option<String>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Protocol {
    Http,
    Https,
}

pub fn run(command: ScopeCommand, globals: &Globals) -> ExitCode {
    match command {
        ScopeCommand::Add(args) => {
            let rule = ScopeRuleParams {
                exclude: args.exclude,
                protocol: args.protocol.map(|p| {
                    match p {
                        Protocol::Http => "http",
                        Protocol::Https => "https",
                    }
                    .to_owned()
                }),
                host: args.host,
                port: args.port,
                path: args.path,
            };
            call_method(globals, method::SCOPE_ADD, to_value(&rule), print_rules)
        }
        ScopeCommand::Remove { number } => {
            let Some(index) = number.checked_sub(1) else {
                eprintln!("hiccup: rules are numbered from 1");
                return ExitCode::from(2);
            };
            let params = to_value(&ScopeRemoveParams { index });
            call_method(globals, method::SCOPE_REMOVE, params, print_rules)
        }
        ScopeCommand::List => call_method(globals, method::SCOPE_LIST, Value::Null, print_rules),
        ScopeCommand::Test { url } => {
            let params = to_value(&ScopeTestParams { url: url.clone() });
            call_method(globals, method::SCOPE_TEST, params, |v| {
                let r: ScopeTestResult = serde_json::from_value(v).expect("typed");
                let verdict = if r.in_scope {
                    "in scope"
                } else {
                    "out of scope"
                };
                println!("{url} is {verdict}.");
            })
        }
    }
}

fn print_rules(value: Value) {
    let ScopeRules { rules } = serde_json::from_value(value).expect("typed");
    if rules.is_empty() {
        println!("No rule: everything is in scope.");
        return;
    }
    for (i, r) in rules.iter().enumerate() {
        println!("{:>3}  {}", i + 1, describe(r));
    }
}

/// One line per rule, e.g. `include https://*.example.com:443 path /^\/api/`.
fn describe(rule: &ScopeRuleParams) -> String {
    let mut line = format!(
        "{} {}://{}",
        if rule.exclude { "exclude" } else { "include" },
        rule.protocol.as_deref().unwrap_or("*"),
        rule.host.as_deref().unwrap_or("*"),
    );
    if let Some(port) = rule.port {
        line.push_str(&format!(":{port}"));
    }
    if let Some(path) = &rule.path {
        line.push_str(&format!(" path /{path}/"));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_read_as_one_line() {
        assert_eq!(describe(&ScopeRuleParams::default()), "include *://*");
        let rule = ScopeRuleParams {
            exclude: true,
            protocol: Some("https".into()),
            host: Some("*.example.com".into()),
            port: Some(8443),
            path: Some("^/logout".into()),
        };
        assert_eq!(
            describe(&rule),
            "exclude https://*.example.com:8443 path /^/logout/"
        );
    }
}
