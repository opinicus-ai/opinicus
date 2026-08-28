//! The traits that connect the layers of the firewall.

use serde::{Deserialize, Serialize};

use crate::{
    decision::{RuleInfo, Verdict},
    error::Result,
    event::Event,
    memory::{MemoryEffect, SessionMemory},
    process::{Action, ProcessInfo},
    session::{AgentMeta, SessionMeta},
    Pid, TimestampNanos,
};

/// Everything the policy engine needs to evaluate one action.
///
/// The context holds facts only. A rule never reads the operating system.
#[derive(Debug, Clone, Copy)]
pub struct EvalContext<'a> {
    /// Metadata of the session.
    pub session: &'a SessionMeta,
    /// The action to evaluate.
    pub action: &'a Action,
    /// The process that performs the action.
    pub process: &'a ProcessInfo,
    /// Ancestry of the process, nearest parent first and session root last.
    pub ancestry: &'a [ProcessInfo],
    /// What an agent log adapter added, when one is available.
    pub agent: Option<&'a AgentMeta>,
    /// Time of the event that produced the action.
    ///
    /// A rule with a window compares against this value and never against a
    /// clock, so a replay of a trace gives the same answer as the live
    /// session.
    pub ts: TimestampNanos,
    /// What the session remembers, when the caller keeps a memory.
    ///
    /// A rule that asks about an earlier action stays quiet while this is
    /// `None`, so a caller that keeps no memory sees the old behaviour.
    pub memory: Option<&'a SessionMemory>,
}

impl<'a> EvalContext<'a> {
    /// Makes a context.
    pub fn new(
        session: &'a SessionMeta,
        action: &'a Action,
        process: &'a ProcessInfo,
        ancestry: &'a [ProcessInfo],
    ) -> Self {
        Self {
            session,
            action,
            process,
            ancestry,
            agent: None,
            ts: 0,
            memory: None,
        }
    }

    /// Sets the time of the event that produced the action.
    pub fn at(mut self, ts: TimestampNanos) -> Self {
        self.ts = ts;
        self
    }

    /// Gives the context a read view of the session memory.
    pub fn with_memory(mut self, memory: &'a SessionMemory) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Returns true when a program with this name is anywhere in the ancestry.
    pub fn has_ancestor(&self, program: &str) -> bool {
        self.ancestry.iter().any(|p| p.program_name() == program)
    }

    /// Returns the nearest parent process, when there is one.
    pub fn parent(&self) -> Option<&ProcessInfo> {
        self.ancestry.first()
    }

    /// Returns the root of the process subtree that performs the action.
    ///
    /// The value is the process under the root of the session, so every
    /// process of one agent task gets the same answer. A mark with the scope
    /// `subtree` uses it, so a credential read in one task cannot arm a rule
    /// in another task.
    pub fn subtree_root(&self) -> Pid {
        let root = self.session.root_pid;
        for parent in self.ancestry.iter().rev() {
            if parent.pid != root {
                return parent.pid;
            }
        }
        self.process.pid
    }
}

/// A destination for normalized events.
///
/// The recorder writes events to storage. Other sinks can print events or
/// send them to a control plane.
pub trait EventSink: Send {
    /// Records one event. The sink sets the sequence number.
    fn record(&mut self, event: &Event) -> Result<()>;

    /// Writes everything that is still in memory.
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A set of deterministic rules.
pub trait PolicyEngine: Send + Sync {
    /// Evaluates one action and returns the verdict.
    ///
    /// The engine must be deterministic. The same context always gives the
    /// same verdict. The call has no side effect.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Verdict;

    /// Evaluates one action against the memory of the session.
    ///
    /// The engine reads the memory and returns what the session must write
    /// down, but it never writes itself. **The caller applies the effects, in
    /// event order.** That keeps the evaluation free of side effects, so a
    /// replay of a trace gives the same verdicts as the live session.
    ///
    /// The default implementation calls [`PolicyEngine::evaluate`] and asks
    /// for nothing, which is right for an engine with no memory.
    fn evaluate_with_memory(
        &self,
        ctx: &EvalContext<'_>,
        memory: &SessionMemory,
    ) -> (Verdict, Vec<MemoryEffect>) {
        let _ = memory;
        (self.evaluate(ctx), Vec::new())
    }

    /// Returns a description of every loaded rule.
    fn rules(&self) -> Vec<RuleInfo>;
}

/// A view of the provenance graph.
pub trait ProvenanceView {
    /// Returns the ancestry of a process, nearest parent first.
    fn ancestry(&self, pid: Pid) -> Vec<ProcessInfo>;

    /// Returns the facts of one process, when the graph knows it.
    fn process(&self, pid: Pid) -> Option<ProcessInfo>;
}

/// The answer of the user to one question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// Let this action continue one time.
    Allow,
    /// Let this action and equal actions continue for the rest of the session.
    AllowForSession,
    /// Stop this action, but let the process continue.
    Deny,
    /// Stop the action and end the whole session.
    TerminateSession,
}

impl ApprovalOutcome {
    /// Returns true when the action may continue.
    pub fn is_allow(&self) -> bool {
        matches!(
            self,
            ApprovalOutcome::Allow | ApprovalOutcome::AllowForSession
        )
    }

    /// Returns a short label for logs and the user interface.
    pub fn label(&self) -> &'static str {
        match self {
            ApprovalOutcome::Allow => "allow",
            ApprovalOutcome::AllowForSession => "allow-for-session",
            ApprovalOutcome::Deny => "deny",
            ApprovalOutcome::TerminateSession => "terminate-session",
        }
    }
}

/// One question for the user.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalRequest<'a> {
    /// Metadata of the session.
    pub session: &'a SessionMeta,
    /// The action that waits for a decision.
    pub action: &'a Action,
    /// The process that performs the action.
    pub process: &'a ProcessInfo,
    /// Ancestry of the process, nearest parent first.
    pub ancestry: &'a [ProcessInfo],
    /// The verdict that caused the question.
    pub verdict: &'a Verdict,
}

/// Something that can answer a question about a held action.
pub trait Approver: Send {
    /// Asks for a decision and returns the answer.
    ///
    /// The implementation must always return. A monitored process waits while
    /// this call runs, so an implementation that cannot ask must return a safe
    /// default instead of waiting forever.
    fn request(&mut self, req: &ApprovalRequest<'_>) -> ApprovalOutcome;
}
