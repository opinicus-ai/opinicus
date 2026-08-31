//! Core contract of the Agent Firewall.
//!
//! This crate holds the types that all other crates share:
//!
//! * the normalized event schema ([`event`]);
//! * process and provenance types ([`process`]);
//! * policy decisions and verdicts ([`decision`]);
//! * the memory that the engine keeps for one session ([`memory`]);
//! * session and agent metadata ([`session`]);
//! * the traits that connect the layers ([`traits`]).
//!
//! No crate in this workspace may depend on a platform detail of another
//! crate. All crates communicate through the types below.

pub mod decision;
pub mod display;
pub mod error;
pub mod event;
pub mod identity;
pub mod memory;
pub mod process;
pub mod session;
pub mod traits;

pub use decision::{Decision, RiskLevel, RuleInfo, RuleMatch, Verdict};
pub use error::{Error, Result};
pub use event::{Event, EventKind, InputStream, KernelDeniedPath, MonitorCapability};
pub use identity::{
    AgentLink, AgentTag, Assessment, DetectionInput, DetectionSignal, Detector, DetectorRegistry,
    IdentifiedAgent, SessionDetach, TAG_THRESHOLD,
};
pub use memory::{MarkScope, MemoryEffect, SessionMemory};
pub use process::{Action, DiscrepancyKind, InputSource, ProcessInfo, ProcessKey, TamperKind};
pub use session::{AgentKind, AgentMeta, SensorMeta, SessionId, SessionMeta};
pub use traits::{
    ApprovalOutcome, ApprovalRequest, Approver, EvalContext, EventSink, PolicyEngine,
    ProvenanceView,
};

/// Process identifier. Signed, because that is what Linux and `nix` use.
pub type Pid = i32;

/// Wall-clock time of an event, in nanoseconds since the Unix epoch.
///
/// A plain integer is used instead of `SystemTime` so that a recorded trace
/// keeps the same value after a round trip through JSON.
pub type TimestampNanos = u64;

/// Returns the current wall-clock time in nanoseconds since the Unix epoch.
pub fn now_nanos() -> TimestampNanos {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Version of the normalized event schema.
///
/// Increase this number when a change breaks trace replay.
pub const EVENT_SCHEMA_VERSION: u32 = 1;
