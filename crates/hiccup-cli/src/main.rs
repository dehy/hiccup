// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup`: the command-line interface to Hiccup.

use clap::Parser;

/// Open source web security testing toolkit.
#[derive(Debug, Parser)]
#[command(name = "hiccup", version, about)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
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
