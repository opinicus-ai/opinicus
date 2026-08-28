//! The rule pack that ships inside the binary.
//!
//! The files come from the `policies/` directory of the source tree.
//! `include_str!` puts them in the program, so the firewall protects a
//! machine that has no rule file on disk and no network.

/// Every built-in rule file, with the name that messages use.
///
/// The order decides the load order. It does not change a verdict, because
/// the verdict takes the strongest decision of every rule that matched.
pub(crate) const FILES: &[(&str, &str)] = &[
    (
        "builtin:filesystem.yaml",
        include_str!("../../../policies/filesystem.yaml"),
    ),
    (
        "builtin:git.yaml",
        include_str!("../../../policies/git.yaml"),
    ),
    (
        "builtin:database.yaml",
        include_str!("../../../policies/database.yaml"),
    ),
    (
        "builtin:cloud.yaml",
        include_str!("../../../policies/cloud.yaml"),
    ),
    (
        "builtin:network.yaml",
        include_str!("../../../policies/network.yaml"),
    ),
    (
        "builtin:process.yaml",
        include_str!("../../../policies/process.yaml"),
    ),
    (
        "builtin:memory.yaml",
        include_str!("../../../policies/memory.yaml"),
    ),
    (
        "builtin:allowlist.yaml",
        include_str!("../../../policies/allowlist.yaml"),
    ),
];
