//! The no-network dependency contract of `af-telemetry`, enforced by
//! `cargo test` instead of by review memory.
//!
//! [TELEMETRY.md §4](https://github.com/opinicus-ai/opinicus/blob/main/docs/TELEMETRY.md)
//! states the as-built claim: `cargo tree -p af-telemetry` holds `af-core`,
//! `serde` and `serde_json`, with no socket library anywhere below them, and
//! no code in the workspace opens a network connection for telemetry. This
//! file turns that sentence into four checks:
//!
//! 1. the direct dependencies are exactly `af-core`, `serde`, `serde_json`;
//! 2. the dev-dependencies are exactly `tempfile` (test-only, never shipped);
//! 3. the shipped transitive closure is pinned crate-by-crate;
//! 4. no network-capable crate appears anywhere in the graph, including
//!    dev-dependencies.
//!
//! If a dependency change breaks one of these, the change is either wrong or
//! deliberate: wrong fixes the code, deliberate updates this file (and the
//! claim in TELEMETRY.md) in the same commit, so the documented contract and
//! the enforced one cannot drift apart.
//!
//! Scope, stated honestly: this is a **dependency-graph** check. It proves no
//! network stack rides in through Cargo; it is not a capability sandbox, and
//! `std::net` in any dependency would not be caught by crate names. The
//! runtime boundary is Landlock; this test is the supply-chain tripwire.

use std::collections::BTreeSet;
use std::process::Command;

/// The name of the crate under contract.
const SELF_CRATE: &str = "af-telemetry";

/// Direct, shipped dependencies — the set TELEMETRY.md §4 names.
const DIRECT: &[&str] = &["af-core", "serde", "serde_json"];

/// Direct dev-dependencies. Test-only; `tempfile` and its closure appear in
/// the dev graph of check 4 but never in a shipped artifact.
const DEV_DIRECT: &[&str] = &["tempfile"];

/// The pinned shipped closure (edges: normal + build) as resolved for the
/// linux target — the platform the product and CI enforce. Pinned on
/// purpose: a new crate below `serde` or `af-core` should stop the gate and
/// be looked at, not slide through. Update this constant together with the
/// claim in TELEMETRY.md §4 when a bump is deliberate.
const SHIPPED_CLOSURE: &[&str] = &[
    "af-core",
    "itoa",
    "memchr",
    "proc-macro2",
    "quote",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "syn",
    "thiserror",
    "thiserror-impl",
    "unicode-ident",
    "zmij",
];

/// Crates that would hand this crate a network stack. Mirrors the `[bans]`
/// deny list of the root `deny.toml`; repeated here so `cargo test -p
/// af-telemetry` alone reports the breach against this crate's contract.
const NETWORK_CRATES: &[&str] = &[
    "actix-rt",
    "actix-web",
    "attohttpc",
    "curl",
    "curl-sys",
    "h2",
    "http",
    "hyper",
    "hyper-util",
    "isahc",
    "minreq",
    "mio",
    "reqwest",
    "surf",
    "tokio",
    "tungstenite",
    "ureq",
    "websocket",
];

/// Makes a `BTreeSet<String>` out of a name slice.
fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

/// Runs `cargo tree` for this crate and returns the set of crate names.
///
/// `--offline` keeps the test itself from touching the network; everything
/// it needs is already in the local cache because `cargo test` compiled the
/// crate first.
fn tree(edges: &str, depth: &str) -> BTreeSet<String> {
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let output = Command::new("cargo")
        .args([
            "tree",
            "--manifest-path",
            manifest,
            "-p",
            SELF_CRATE,
            "-e",
            edges,
            "--depth",
            depth,
            "--prefix",
            "none",
            "--no-dedupe",
            "--offline",
        ])
        .output()
        .expect("cargo tree: spawn cargo");
    if !output.status.success() {
        panic!(
            "cargo tree -p {SELF_CRATE} -e {edges} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
        .filter(|name| name != SELF_CRATE)
        .collect()
}

#[test]
fn direct_dependencies_are_exactly_af_core_serde_and_serde_json() {
    let got = tree("normal,build", "1");
    let want = set(DIRECT);
    assert_eq!(
        got, want,
        "af-telemetry's direct dependencies changed; TELEMETRY.md §4 and this contract must \
         change together, deliberately"
    );
}

#[test]
fn dev_dependencies_are_exactly_tempfile() {
    let got = tree("dev", "1");
    let want = set(DEV_DIRECT);
    assert_eq!(
        got, want,
        "af-telemetry's dev-dependencies changed; they are test-only, keep the set minimal"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn shipped_dependency_closure_is_pinned() {
    let got = tree("normal,build", "999");
    let want = set(SHIPPED_CLOSURE);
    assert_eq!(
        got, want,
        "af-telemetry's shipped dependency closure changed; if the new crate is deliberate, \
         pin it here and in TELEMETRY.md §4 in the same commit"
    );
}

#[test]
fn dependency_graph_holds_no_network_crate() {
    let graph = tree("normal,build,dev", "999");
    let banned = set(NETWORK_CRATES);
    let breach: Vec<_> = banned.intersection(&graph).collect();
    assert!(
        breach.is_empty(),
        "af-telemetry's dependency graph would pull {breach:?}; this crate has no network \
         code by design (TELEMETRY.md §4) and deny.toml bans these crates"
    );
}
