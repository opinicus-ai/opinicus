//! The `telemetry` sub-commands: consent, samples, inspection, destruction.

use std::path::{Path, PathBuf};

use af_telemetry::{
    default_outbox_path, list_samples, write_sample, Consent, Options, Sample, Scope,
};
use anyhow::{bail, Context, Result};

use crate::cli::{
    TelemetryCommand, TelemetryDestroyArgs, TelemetryInspectArgs, TelemetryOffArgs,
    TelemetryOnArgs, TelemetrySampleArgs, TelemetryStatusArgs,
};

/// The disclosure that every telemetry command prints.
///
/// The alpha is not a production security boundary, and no sample ever
/// leaves the machine on its own. Saying both, every time, is the point of
/// the command family.
const LOCAL_ONLY: &str =
    "nothing is sent anywhere: samples stay in the outbox until you destroy them";

/// Returns the consent file of a command, or the default one.
fn config_path(path: &Option<PathBuf>) -> PathBuf {
    path.clone().unwrap_or_else(Consent::default_path)
}

/// Returns the outbox of a command, or the default one.
fn outbox_path(path: &Option<PathBuf>) -> PathBuf {
    path.clone().unwrap_or_else(default_outbox_path)
}

/// Reads the scopes of a `--scope` list, or every scope for `all`.
fn parse_scopes(words: &[String]) -> Result<Vec<Scope>> {
    let mut scopes = Vec::new();
    for word in words {
        if word == "all" {
            scopes.extend(Scope::ALL.iter().copied());
            continue;
        }
        let Some(scope) = Scope::parse(word) else {
            bail!(
                "`--scope` accepts tree, actions, content, env, identity or all, \
                 but it got `{word}`"
            );
        };
        scopes.push(scope);
    }
    if scopes.is_empty() {
        bail!("name at least one scope: tree, actions, content, env, identity, or all");
    }
    Ok(scopes)
}

/// Runs a `telemetry` sub-command and returns the exit code.
pub fn dispatch(command: TelemetryCommand) -> Result<i32> {
    match command {
        TelemetryCommand::Status(args) => status(args),
        TelemetryCommand::On(args) => on(args),
        TelemetryCommand::Off(args) => off(args),
        TelemetryCommand::Sample(args) => sample(args),
        TelemetryCommand::Inspect(args) => inspect(args),
        TelemetryCommand::Destroy(args) => destroy(args),
    }
}

/// Shows the consent state, the outbox and the disclosure.
pub fn status(args: TelemetryStatusArgs) -> Result<i32> {
    let config = config_path(&args.config);
    let outbox = outbox_path(&args.outbox);
    let consent = Consent::load(&config)
        .with_context(|| format!("cannot read the consent file {}", config.display()))?;

    if consent.is_off() {
        println!("telemetry: off (the default; the product is complete without it)");
    } else {
        let granted: Vec<&str> = consent.granted().iter().map(|s| s.label()).collect();
        println!("telemetry: on ({})", granted.join(", "));
    }
    println!("consent file: {}", config.display());
    let count = list_samples(&outbox)
        .map(|samples| samples.len())
        .unwrap_or(0);
    println!("outbox: {} ({} sample(s))", outbox.display(), count);
    println!("scopes: tree, actions, content, env, identity");
    println!("{LOCAL_ONLY}");
    println!("docs/TELEMETRY.md holds the full packaging spec");
    Ok(0)
}

/// Grants consent for one or more scopes.
pub fn on(args: TelemetryOnArgs) -> Result<i32> {
    let scopes = parse_scopes(&args.scope)?;
    let config = config_path(&args.config);
    let mut consent = Consent::load(&config)
        .with_context(|| format!("cannot read the consent file {}", config.display()))?;
    for scope in &scopes {
        consent.grant(*scope);
    }
    consent
        .save(&config)
        .with_context(|| format!("cannot write the consent file {}", config.display()))?;

    for scope in &scopes {
        println!("granted: {scope} — {}", scope.description());
    }
    let granted: Vec<&str> = consent.granted().iter().map(|s| s.label()).collect();
    println!("telemetry: on ({})", granted.join(", "));
    println!("{LOCAL_ONLY}");
    Ok(0)
}

/// Revokes consent for one scope or for all of them.
pub fn off(args: TelemetryOffArgs) -> Result<i32> {
    let config = config_path(&args.config);
    let mut consent = Consent::load(&config)
        .with_context(|| format!("cannot read the consent file {}", config.display()))?;
    if args.scope.is_empty() {
        consent.revoke_all();
        consent
            .save(&config)
            .with_context(|| format!("cannot write the consent file {}", config.display()))?;
        println!("telemetry: off — every scope revoked");
        return Ok(0);
    }

    // `off` takes plain scope names; `all` clears everything.
    let scopes = parse_scopes(&args.scope)?;
    for scope in &scopes {
        consent.revoke(*scope);
    }
    consent
        .save(&config)
        .with_context(|| format!("cannot write the consent file {}", config.display()))?;
    if consent.is_off() {
        println!("telemetry: off");
    } else {
        let granted: Vec<&str> = consent.granted().iter().map(|s| s.label()).collect();
        println!("telemetry: on ({})", granted.join(", "));
    }
    Ok(0)
}

/// Builds redacted samples from a recorded trace into the outbox.
pub fn sample(args: TelemetrySampleArgs) -> Result<i32> {
    let config = config_path(&args.config);
    let outbox = outbox_path(&args.outbox);
    let consent = Consent::load(&config)
        .with_context(|| format!("cannot read the consent file {}", config.display()))?;
    if consent.is_off() {
        println!(
            "telemetry is off, so nothing was written; grant a scope with \
             `agent-firewall telemetry on --scope …` first"
        );
        return Ok(0);
    }

    let events = af_recorder::read_trace(&args.trace)
        .with_context(|| format!("cannot read {}", args.trace.display()))?;
    let options = Options::from_environment();
    let samples = af_telemetry::build_samples(&events, &consent, &options);
    if samples.is_empty() {
        println!(
            "no suspicious event in {}, so no sample was made",
            args.trace.display()
        );
        return Ok(0);
    }

    let mut paths = Vec::new();
    for sample in &samples {
        let path = write_sample(&outbox, sample)
            .with_context(|| format!("cannot write into the outbox {}", outbox.display()))?;
        paths.push(path);
    }
    for path in &paths {
        println!("sample: {}", path.display());
    }
    let granted: Vec<&str> = consent.granted().iter().map(|s| s.label()).collect();
    println!(
        "{} sample(s) packaged with the scopes {} into {}",
        paths.len(),
        granted.join(", "),
        outbox.display()
    );
    println!("inspect them with `agent-firewall telemetry inspect <file>`");
    println!("{LOCAL_ONLY}");
    Ok(0)
}

/// Prints sample files, so a text terminal is a complete inspector.
pub fn inspect(args: TelemetryInspectArgs) -> Result<i32> {
    for path in &args.sample {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        let sample: Sample = serde_json::from_str(&text)
            .with_context(|| format!("{} holds no valid sample", path.display()))?;
        let rules = sample.rules().join(", ");
        let why = if rules.is_empty() {
            "sensed facts".to_string()
        } else {
            rules
        };
        let tree = if sample.tree.is_empty() {
            ", no tree (scope not granted)".to_string()
        } else {
            format!(", {} process(es) in the tree", sample.tree.len())
        };
        println!(
            "# sample of session {} — {} reason(s) ({}), {} event(s){}",
            sample.session,
            sample.reasons.len(),
            why,
            sample.events.len(),
            tree
        );
        println!("{text}");
    }
    Ok(0)
}

/// Deletes sample files: one, many, or the whole outbox.
pub fn destroy(args: TelemetryDestroyArgs) -> Result<i32> {
    if args.all {
        let outbox = outbox_path(&args.outbox);
        let samples = list_samples(&outbox)
            .with_context(|| format!("cannot read the outbox {}", outbox.display()))?;
        for path in &samples {
            std::fs::remove_file(path)
                .with_context(|| format!("cannot delete {}", path.display()))?;
        }
        println!(
            "destroyed {} sample(s) in {}",
            samples.len(),
            outbox.display()
        );
        return Ok(0);
    }
    if args.sample.is_empty() {
        bail!("name the samples to destroy, or pass --all for the whole outbox");
    }
    for path in &args.sample {
        std::fs::remove_file(path).with_context(|| format!("cannot delete {}", path.display()))?;
        println!("destroyed {}", path.display());
    }
    Ok(0)
}

/// Packages the samples of one finished session for `run --telemetry`.
///
/// The session is over when this runs, so the packaging can add no question
/// and no delay that matters. A failure to package is a warning on standard
/// error and never a failure of the session itself.
pub fn finish_session(
    config: &Option<PathBuf>,
    outbox: &Option<PathBuf>,
    events: &[af_core::Event],
) {
    let config = config_path(config);
    let outbox = outbox_path(outbox);
    let consent = match Consent::load(&config) {
        Ok(consent) => consent,
        Err(error) => {
            eprintln!("agent-firewall: telemetry: cannot read the consent file: {error}");
            return;
        }
    };
    if consent.is_off() {
        eprintln!(
            "agent-firewall: telemetry is off, so no sample was written; \
             `agent-firewall telemetry on --scope …` grants it"
        );
        return;
    }
    let options = Options::from_environment();
    let samples = af_telemetry::build_samples(events, &consent, &options);
    if samples.is_empty() {
        return;
    }
    match write_each(&outbox, &samples) {
        Ok(count) => eprintln!(
            "agent-firewall: telemetry: {count} sample(s) written to {} — inspect them, \
             then destroy them; nothing is sent anywhere",
            outbox.display()
        ),
        Err(error) => eprintln!("agent-firewall: telemetry: cannot write the samples: {error}"),
    }
}

/// Writes every sample and returns how many were written.
fn write_each(outbox: &Path, samples: &[Sample]) -> Result<usize> {
    for sample in samples {
        write_sample(outbox, sample)
            .with_context(|| format!("cannot write into the outbox {}", outbox.display()))?;
    }
    Ok(samples.len())
}
