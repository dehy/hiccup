// SPDX-License-Identifier: AGPL-3.0-or-later

//! `hiccup ca`: the local certificate authority.

use std::fmt::Write as _;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand, ValueEnum};
use hiccup_proxy::ca::{CERT_FILE, KEY_FILE};
use hiccup_proxy::{CaError, CertificateAuthority};

const INSTALL_GUIDE: &str = "https://github.com/dehy/hiccup/blob/main/docs/ca.md";

#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Show the CA certificate's location, subject, validity and fingerprint.
    ///
    /// Generates the CA if there is none yet.
    Info,
    /// Write the CA certificate, to install it in a browser or trust store.
    ///
    /// Generates the CA if there is none yet. The private key is never
    /// exported.
    Export(ExportArgs),
    /// Replace the CA with a new one.
    ///
    /// Clients that trust the current CA will reject Hiccup until the new
    /// certificate is installed. Remove the old one from trust stores.
    Regenerate(RegenerateArgs),
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Certificate encoding.
    #[arg(long, value_enum, default_value_t = Format::Pem)]
    format: Format,

    /// Output file. Defaults to standard output.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Format {
    /// Base64 text (`.pem`, `.crt`): Linux, macOS, Firefox, curl.
    Pem,
    /// Binary (`.der`, `.cer`): Windows, Android.
    Der,
}

#[derive(Debug, Args)]
pub struct RegenerateArgs {
    /// Confirm that the current CA should be replaced.
    #[arg(long)]
    yes: bool,
}

pub fn run(command: CaCommand, data_dir: &Path) -> ExitCode {
    match command {
        CaCommand::Info => load(data_dir).map_or(ExitCode::FAILURE, |ca| {
            print!("{}", describe(&ca, data_dir));
            ExitCode::SUCCESS
        }),
        CaCommand::Export(args) => {
            load(data_dir).map_or(ExitCode::FAILURE, |ca| export(&ca, &args))
        }
        CaCommand::Regenerate(args) => regenerate(&args, data_dir),
    }
}

/// Loads the CA, generating it on first use.
fn load(data_dir: &Path) -> Option<CertificateAuthority> {
    match CertificateAuthority::load_or_generate(data_dir) {
        Ok((ca, created)) => {
            if created {
                eprintln!("Generated a new CA in {}.", data_dir.display());
            }
            Some(ca)
        }
        Err(e) => {
            eprintln!("hiccup: {e}");
            if !matches!(e, CaError::Io { .. }) {
                eprintln!("To replace it with a new CA, run `hiccup ca regenerate --yes`.");
            }
            None
        }
    }
}

fn export(ca: &CertificateAuthority, args: &ExportArgs) -> ExitCode {
    let bytes = match args.format {
        Format::Pem => ca.cert_pem().as_bytes(),
        Format::Der => ca.cert_der(),
    };
    let result = match &args.output {
        Some(path) => {
            std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
        }
        None if matches!(args.format, Format::Der) && std::io::stdout().is_terminal() => {
            Err("refusing to write binary DER to a terminal; use --output FILE".to_owned())
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(bytes)
                .and_then(|()| stdout.flush())
                .map_err(|e| format!("cannot write to standard output: {e}"))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hiccup: {e}");
            ExitCode::FAILURE
        }
    }
}

fn regenerate(args: &RegenerateArgs, data_dir: &Path) -> ExitCode {
    if !args.yes {
        eprintln!(
            "hiccup: this replaces the CA in {}.\n\
             Browsers and systems that trust the current CA will reject Hiccup's \
             certificates until you install the new one.\n\
             Run `hiccup ca regenerate --yes` to confirm.",
            data_dir.display()
        );
        return ExitCode::from(2);
    }
    let saved = CertificateAuthority::generate().and_then(|ca| ca.save(data_dir).map(|()| ca));
    match saved {
        Ok(ca) => {
            eprintln!(
                "Generated a new CA. Remove the previous \"Hiccup CA\" from your trust \
                 stores and install this one."
            );
            print!("{}", describe(&ca, data_dir));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hiccup: {e}");
            ExitCode::FAILURE
        }
    }
}

fn describe(ca: &CertificateAuthority, data_dir: &Path) -> String {
    let info = ca.info();
    let fingerprint = info
        .sha256
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut out = String::new();
    let _ = writeln!(out, "Certificate: {}", data_dir.join(CERT_FILE).display());
    let _ = writeln!(out, "Private key: {}", data_dir.join(KEY_FILE).display());
    let _ = writeln!(out, "Subject:     {}", info.subject);
    let _ = writeln!(
        out,
        "Valid:       {} to {} (UTC)",
        info.not_before.date(),
        info.not_after.date()
    );
    let _ = writeln!(out, "SHA-256:     {fingerprint}");
    let _ = writeln!(out, "Install it:  {INSTALL_GUIDE}");
    out
}
