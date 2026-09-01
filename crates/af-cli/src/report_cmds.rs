//! The `report` sub-command: the false-positive report path.
//!
//! A false positive is a real bug of this product
//! ([docs/PRODUCT.md](https://github.com/opinicus-ai/opinicus/blob/main/docs/PRODUCT.md) §5),
//! and a report needs evidence. A raw trace is not evidence a user can
//! post: it holds command lines, paths and environment values. The command
//! validates a trace, scrubs it with the redaction machinery of the
//! telemetry crate, and writes one bundle file that the user can attach to
//! the false-positive issue template. Nothing is sent anywhere: the file is
//! written next to the user and stays there.

use std::path::PathBuf;

use af_telemetry::{build_report, write_report};
use anyhow::{bail, Context, Result};

use crate::cli::ReportArgs;
/// Runs the `report` sub-command and returns the exit code.
pub fn report(args: ReportArgs) -> Result<i32> {
    // The validation is the read itself: `read_trace` stops at the first
    // broken line and names it, so a damaged trace never becomes a report
    // that quietly lies about a session.
    let events = af_recorder::read_trace(&args.trace)
        .with_context(|| format!("{} holds no valid trace", args.trace.display()))?;
    if events.is_empty() {
        bail!(
            "{} holds no event, so there is nothing to report",
            args.trace.display()
        );
    }

    let bundle = build_report(&events);
    let out = args.out.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(bundle.default_file_name())
    });
    write_report(&out, &bundle)
        .with_context(|| format!("cannot write the report to {}", out.display()))?;

    let rules = if bundle.rules.is_empty() {
        "no rule named".to_string()
    } else {
        bundle.rules.join(", ")
    };
    println!("report: {}", out.display());
    println!(
        "{} event(s) of session {}, rule(s): {}",
        bundle.events, bundle.session, rules
    );
    println!(
        "secrets are <redacted>, content is <omitted>, identifiers are pseudonymized — \
         read it before you post it"
    );
    println!(
        "attach it to the false-positive template: \
         .github/ISSUE_TEMPLATE/false-positive.md (INCIDENTS.md explains the path)"
    );
    println!("nothing is sent anywhere; the file stays on this machine");
    Ok(0)
}
