//! The causal process graph of one session.

use std::collections::{BTreeMap, BTreeSet};

use af_core::{
    AgentLink, AgentTag, Decision, Event, EventKind, Pid, ProcessInfo, ProcessKey, ProvenanceView,
    SessionDetach, SessionId, SessionMeta, Verdict,
};

use crate::node::{ExitStatus, Node};

/// How many steps [`ProcessGraph::ancestry`] walks upwards at most.
///
/// The limit protects the caller against damaged data. A real session never
/// reaches it.
const MAX_DEPTH: usize = 1024;

/// The processes of one session and the links between them.
///
/// The graph answers the question "where did this action come from?". It
/// keeps every process that the session created, also after the process
/// ended, because the chain of a live process often runs through a dead
/// parent.
///
/// The graph keys the nodes on [`af_core::ProcessKey`], which holds the
/// process identifier and the start time. Linux gives the same identifier to
/// a new process later. The start time keeps the two processes apart.
///
/// # Example
///
/// ```
/// use af_core::{Event, EventKind, ProcessInfo, SessionMeta};
/// use af_provenance::ProcessGraph;
///
/// let mut session = SessionMeta::new(vec!["bash".to_string()], "/tmp".to_string());
/// session.root_pid = 100;
/// let mut graph = ProcessGraph::new(&session);
/// graph.apply(&Event::new(
///     session.session_id.clone(),
///     100,
///     EventKind::ProcessExec {
///         process: Box::new(ProcessInfo {
///             pid: 100,
///             comm: "bash".to_string(),
///             argv: vec!["bash".to_string()],
///             ..Default::default()
///         }),
///     },
/// ));
/// assert_eq!(graph.len(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct ProcessGraph {
    /// Metadata of the session that owns the graph.
    session: SessionMeta,
    /// Every node, in creation order.
    nodes: Vec<Node>,
    /// Position of the node with this identity.
    by_key: BTreeMap<ProcessKey, usize>,
    /// Position of the node that runs under this identifier now.
    live: BTreeMap<Pid, usize>,
    /// Position of the newest node with this identifier, also after the exit.
    latest: BTreeMap<Pid, usize>,
    /// How many times the graph did not know the parent of a process.
    gaps: usize,
    /// Session identifier of the session root, when the graph learned it.
    ///
    /// The root's own `ProcessInfo` carries it, which arrives with the first
    /// exec event of the root.
    root_sid: Option<Pid>,
    /// Processes the graph flagged as unlinked, in flag order.
    ///
    /// The graph pushes a process here one time. The caller drains the queue
    /// with [`ProcessGraph::take_unlinked`] and reports each flag as an
    /// event, so a replay of the trace re-derives the same flags from the
    /// same events and never reads the queue.
    pending_unlinked: Vec<(Pid, SessionDetach)>,
}

impl ProcessGraph {
    /// Makes an empty graph for one session.
    pub fn new(session: &SessionMeta) -> Self {
        Self {
            session: session.clone(),
            nodes: Vec::new(),
            by_key: BTreeMap::new(),
            live: BTreeMap::new(),
            latest: BTreeMap::new(),
            gaps: 0,
            root_sid: None,
            pending_unlinked: Vec::new(),
        }
    }

    /// Updates the graph from one normalized event.
    ///
    /// The graph uses these events:
    ///
    /// * `SessionStart` gives the metadata. It also adds the root process
    ///   when the metadata names it.
    /// * `ProcessFork` adds a child. A fork always makes a new node, because
    ///   a fork always makes a new process. A fork that only makes a thread
    ///   adds nothing.
    /// * `ProcessExec` updates the node of the process. The process keeps its
    ///   identity when it replaces its program.
    /// * `ProcessExit` marks the node as ended. The graph keeps the node.
    /// * `PolicyDecision` stores the strongest verdict of the process. It
    ///   also adds the processes of its ancestry when the graph misses them.
    /// * `SessionEnd` marks every open process as ended.
    ///
    /// The graph ignores the other events, because they do not change the
    /// process tree.
    pub fn apply(&mut self, event: &Event) {
        match &event.kind {
            EventKind::SessionStart { meta, .. } => {
                self.session = (**meta).clone();
                self.add_root_process();
            }
            EventKind::ProcessFork {
                child_pid,
                is_thread,
            } => {
                if *is_thread {
                    return;
                }
                self.on_fork(event.pid, *child_pid);
            }
            EventKind::ProcessExec { process } => {
                self.on_exec(event.pid, (**process).clone());
            }
            EventKind::ProcessExit { code, signal, sid } => {
                self.on_exit(event.pid, *code, *signal, *sid)
            }
            EventKind::PolicyDecision {
                verdict, ancestry, ..
            } => {
                let index = self.ensure_process(event.pid, ancestry);
                self.record_verdict(index, verdict);
            }
            EventKind::SessionEnd { .. } => self.end_all(),
            EventKind::ProcessUnlinked { .. } => {
                // The event reports a flag that `apply` itself derived, so a
                // replay of a trace re-derives the flag from the process
                // facts and must not count the report twice.
            }
            EventKind::FileOpen { .. }
            | EventKind::NetworkConnect { .. }
            | EventKind::FileRead { .. }
            | EventKind::FileDelete { .. }
            | EventKind::FileRename { .. }
            | EventKind::LibraryLoad { .. }
            | EventKind::EnvChange { .. }
            | EventKind::StdinWrite { .. }
            | EventKind::ApprovalRequested { .. }
            | EventKind::ApprovalResolved { .. }
            | EventKind::MonitorWarning { .. } => {}
        }
    }

    /// Rebuilds a graph from a recorded trace.
    ///
    /// The function reads the session metadata from the first `SessionStart`
    /// event. When the trace holds no such event, the graph uses the session
    /// identifier of the first event and an empty command.
    ///
    /// The function applies the events in the order of the slice, which is
    /// the order that the recorder writes them.
    pub fn from_trace(events: &[Event]) -> Self {
        let session = events
            .iter()
            .find_map(|event| match &event.kind {
                EventKind::SessionStart { meta, .. } => Some((**meta).clone()),
                _ => None,
            })
            .unwrap_or_else(|| {
                let id = events
                    .first()
                    .map(|event| event.session_id.clone())
                    .unwrap_or_else(|| SessionId::from("afw-unknown"));
                empty_session(id)
            });
        let mut graph = Self::new(&session);
        for event in events {
            graph.apply(event);
        }
        graph
    }

    /// Returns the ancestry of a process, nearest parent first and session
    /// root last.
    ///
    /// The result does not hold the process itself. It is empty when the
    /// graph does not know the process. The walk stops when it sees a node
    /// twice, so damaged data cannot make an endless loop.
    pub fn ancestry(&self, pid: Pid) -> Vec<ProcessInfo> {
        let Some(start) = self.index_of(pid) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        seen.insert(start);
        let mut next = self.nodes[start].parent;
        while let Some(index) = next {
            if !seen.insert(index) || out.len() >= MAX_DEPTH {
                break;
            }
            out.push(self.nodes[index].info.clone());
            next = self.nodes[index].parent;
        }
        out
    }

    /// Returns the facts of one process.
    ///
    /// The graph answers for a live process and for a process that ended. It
    /// answers for the newest process when an identifier was used twice.
    pub fn process(&self, pid: Pid) -> Option<ProcessInfo> {
        self.index_of(pid)
            .map(|index| self.nodes[index].info.clone())
    }

    /// Returns the facts of the process with this exact identity.
    ///
    /// Use this call when the caller holds a key, because the key stays
    /// correct after the operating system uses the identifier again.
    pub fn process_by_key(&self, key: &ProcessKey) -> Option<ProcessInfo> {
        self.by_key
            .get(key)
            .map(|index| self.nodes[*index].info.clone())
    }

    /// Returns how many processes the session created.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true when the session created no process.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns every process of the session in creation order.
    pub fn processes(&self) -> Vec<ProcessInfo> {
        self.nodes.iter().map(|node| node.info.clone()).collect()
    }

    /// Returns the metadata of the session.
    pub fn session(&self) -> &SessionMeta {
        &self.session
    }

    /// Returns the identifier of the session.
    pub fn session_id(&self) -> &SessionId {
        &self.session.session_id
    }

    /// Returns how many times the graph did not know the parent of a process.
    ///
    /// The graph attaches such a process to the session root. A high number
    /// tells the user that the monitor missed events.
    pub fn gap_count(&self) -> usize {
        self.gaps
    }

    /// Returns true when the process is gone.
    ///
    /// The answer is also true when the graph never saw an exit event but the
    /// operating system gave the identifier to a new process.
    pub fn has_ended(&self, pid: Pid) -> bool {
        self.index_of(pid)
            .map(|index| self.nodes[index].ended)
            .unwrap_or(false)
    }

    /// Returns how a process ended, when the graph saw the exit event.
    pub fn exit_status(&self, pid: Pid) -> Option<ExitStatus> {
        self.index_of(pid).and_then(|index| self.nodes[index].exit)
    }

    /// Returns the strongest verdict that the session recorded for a process.
    pub fn verdict(&self, pid: Pid) -> Option<&Verdict> {
        self.index_of(pid)
            .and_then(|index| self.nodes[index].verdict.as_ref())
    }

    /// Returns the agent identity that the session carries, when it carries
    /// one.
    ///
    /// The identity is a fact of the root of the session: the launcher
    /// assessed the root command once, and the assessment travels inside the
    /// session metadata. A process that the graph cannot link to the root
    /// keeps the identity and says so in its [`AgentTag::link`] — unlinked,
    /// never foreign.
    pub fn agent_tag(&self, pid: Pid) -> Option<AgentTag> {
        let detection = self.session.detection.as_ref()?;
        Some(AgentTag {
            name: detection.name.clone(),
            confidence: detection.confidence,
            link: self.link_of(pid),
        })
    }

    /// Returns whether the graph links a process to the session root.
    ///
    /// A process the graph never saw is `Linked`, because the absence of a
    /// node is no claim at all. A session whose metadata carries no root —
    /// every trace an older version wrote — can prove nothing, so it stays
    /// `Linked` as well.
    pub fn link_of(&self, pid: Pid) -> AgentLink {
        match self.index_of(pid) {
            Some(index) if self.nodes[index].unlink.is_some() => AgentLink::Unlinked,
            _ => AgentLink::Linked,
        }
    }

    /// Returns the processes the graph flagged as unlinked since the last
    /// call, with the fact that flagged each one.
    ///
    /// The caller reports each flag as one event. The graph raised the flag
    /// from the facts of an event it already applied, so the queue adds no
    /// new information that a replay could not derive.
    pub fn take_unlinked(&mut self) -> Vec<(Pid, SessionDetach)> {
        std::mem::take(&mut self.pending_unlinked)
    }

    /// Returns the program names that a process used before the current one.
    ///
    /// A shell script that runs `exec` keeps its identifier. The history
    /// shows the earlier program, so the tree can draw `bash -> migrate.sh`.
    pub fn history(&self, pid: Pid) -> Vec<String> {
        self.index_of(pid)
            .map(|index| self.nodes[index].history.clone())
            .unwrap_or_default()
    }

    /// Returns true when a program with this name is anywhere above the
    /// process.
    ///
    /// The check reads the current program name of every process above, and
    /// also the earlier names of those processes. A rule that asks for `bash`
    /// therefore still matches when the shell replaced its program.
    ///
    /// The check does not read the process itself.
    pub fn has_ancestor_program(&self, pid: Pid, program: &str) -> bool {
        let Some(start) = self.index_of(pid) else {
            return false;
        };
        let mut seen = BTreeSet::new();
        seen.insert(start);
        let mut next = self.nodes[start].parent;
        let mut steps = 0;
        while let Some(index) = next {
            if !seen.insert(index) || steps >= MAX_DEPTH {
                break;
            }
            steps += 1;
            let node = &self.nodes[index];
            if node.info.program_name() == program
                || node.history.iter().any(|name| name == program)
            {
                return true;
            }
            next = node.parent;
        }
        false
    }

    /// Returns the position of the node of a process.
    ///
    /// The graph looks at the live processes first. It looks at the ended
    /// processes after that, so a chain still works when a parent is gone.
    fn index_of(&self, pid: Pid) -> Option<usize> {
        self.live
            .get(&pid)
            .or_else(|| self.latest.get(&pid))
            .copied()
    }

    /// Returns the node positions in the order that [`Self::render_tree`]
    /// needs.
    pub(crate) fn sorted_children(&self, index: usize) -> Vec<usize> {
        let mut children = self.nodes[index].children.clone();
        children.sort_by_key(|child| (self.nodes[*child].order, self.nodes[*child].info.pid));
        children
    }

    /// Returns the processes that hang directly under the session root.
    pub(crate) fn root_indexes(&self) -> Vec<usize> {
        let mut roots: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.parent.is_none())
            .map(|(index, _)| index)
            .collect();
        roots.sort_by_key(|index| (self.nodes[*index].order, self.nodes[*index].info.pid));
        roots
    }

    /// Returns one node for the renderer.
    pub(crate) fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }

    /// Adds the root process of the session, when the metadata names it.
    fn add_root_process(&mut self) {
        let pid = self.session.root_pid;
        if pid <= 0 || self.live.contains_key(&pid) {
            return;
        }
        let program = self
            .session
            .command
            .first()
            .map(|word| word.rsplit('/').next().unwrap_or(word).to_string())
            .unwrap_or_default();
        let info = ProcessInfo {
            pid,
            comm: program,
            argv: self.session.command.clone(),
            cwd: Some(self.session.cwd.clone()),
            ..Default::default()
        };
        let index = self.insert(info, None);
        self.check_link(index);
    }

    /// Handles a fork event.
    fn on_fork(&mut self, parent_pid: Pid, child_pid: Pid) {
        let parent = self.resolve_parent(Some(parent_pid), child_pid);
        // A fork always announces a new process. When the graph still holds a
        // live node for this identifier, that node belongs to an older
        // process that the monitor did not see end.
        self.retire(child_pid);
        let info = ProcessInfo {
            pid: child_pid,
            ppid: Some(parent_pid),
            ..Default::default()
        };
        let index = self.insert(info, parent);
        self.check_link(index);
    }

    /// Handles an exec event.
    fn on_exec(&mut self, event_pid: Pid, mut info: ProcessInfo) {
        if info.pid == 0 {
            info.pid = event_pid;
        }
        let pid = info.pid;
        match self.live.get(&pid).copied() {
            Some(index) if same_process(self.nodes[index].key.start_ticks, info.start_ticks) => {
                self.update_exec(index, info);
            }
            Some(index) => {
                // The operating system gave the identifier to a new process.
                self.retire_index(index, pid);
                let parent = self.resolve_parent(info.ppid, pid);
                let index = self.insert(info, parent);
                self.check_link(index);
            }
            None => {
                let parent = self.resolve_parent(info.ppid, pid);
                let index = self.insert(info, parent);
                self.check_link(index);
            }
        }
    }

    /// Handles an exit event.
    ///
    /// The event can carry the session identifier of the process at its end.
    /// A daemon that called `setsid` and never ran another program carries
    /// its detachment nowhere else, so the graph compares the value here,
    /// after the fact of the exit and before it lets the process go.
    fn on_exit(&mut self, pid: Pid, code: Option<i32>, signal: Option<i32>, sid: Option<Pid>) {
        let Some(index) = self.live.remove(&pid) else {
            return;
        };
        if sid.is_some() {
            self.nodes[index].info.sid = sid;
        }
        self.check_link(index);
        self.nodes[index].ended = true;
        self.nodes[index].exit = Some(ExitStatus { code, signal });
    }

    /// Marks every process that is still open as ended.
    fn end_all(&mut self) {
        for index in std::mem::take(&mut self.live).into_values() {
            self.nodes[index].ended = true;
        }
    }

    /// Stores the strongest verdict of a process.
    fn record_verdict(&mut self, index: usize, verdict: &Verdict) {
        let stronger = match &self.nodes[index].verdict {
            Some(old) => rank(verdict) > rank(old),
            None => true,
        };
        if stronger {
            self.nodes[index].verdict = Some(verdict.clone());
        }
    }

    /// Returns the node of a process and makes it when the graph misses it.
    ///
    /// A recorded trace can hold a decision without the exec events of the
    /// chain, because retention drops events. The decision carries its own
    /// ancestry, so the graph rebuilds the missing chain from it.
    fn ensure_process(&mut self, pid: Pid, ancestry: &[ProcessInfo]) -> usize {
        if let Some(index) = self.index_of(pid) {
            return index;
        }
        let mut parent: Option<usize> = None;
        for info in ancestry.iter().rev() {
            match self.index_of(info.pid) {
                Some(index) => parent = Some(index),
                None => {
                    let mut info = info.clone();
                    // The chain of the decision wins. The parent identifier of
                    // the process helps when the chain does not reach further.
                    let above = match parent {
                        Some(index) => Some(index),
                        None => info.ppid.and_then(|ppid| self.index_of(ppid)),
                    };
                    if info.ppid.is_none() {
                        info.ppid = above.map(|index| self.nodes[index].info.pid);
                    }
                    self.count_gap(above, info.pid);
                    parent = Some(self.insert(info, above));
                }
            }
        }
        self.count_gap(parent, pid);
        let info = ProcessInfo {
            pid,
            ppid: parent.map(|index| self.nodes[index].info.pid),
            ..Default::default()
        };
        let index = self.insert(info, parent);
        self.check_link(index);
        index
    }

    /// Updates a node after the process replaced its program.
    ///
    /// The node keeps its position in the tree, because the process keeps its
    /// identity.
    fn update_exec(&mut self, index: usize, mut info: ProcessInfo) {
        let old_name = self.nodes[index].info.program_name().to_string();
        let new_name = info.program_name().to_string();
        if !old_name.is_empty() && old_name != new_name {
            self.nodes[index].push_history(old_name);
        }
        if info.ppid.is_none() {
            info.ppid = self.nodes[index].info.ppid;
        }
        if info.start_ticks == 0 {
            info.start_ticks = self.nodes[index].key.start_ticks;
        }
        let old_key = self.nodes[index].key;
        let new_key = info.key();
        self.nodes[index].info = info;
        if new_key != old_key {
            self.by_key.remove(&old_key);
            self.by_key.insert(new_key, index);
            self.nodes[index].key = new_key;
        }
        if self.nodes[index].parent.is_none() {
            self.attach_late(index);
        }
        self.check_link(index);
    }

    /// Attaches a node to its parent when the graph learns the parent later.
    fn attach_late(&mut self, index: usize) {
        let Some(ppid) = self.nodes[index].info.ppid else {
            return;
        };
        let Some(parent) = self.index_of(ppid) else {
            return;
        };
        if parent == index || self.reaches(parent, index) {
            return;
        }
        self.nodes[index].parent = Some(parent);
        self.nodes[parent].children.push(index);
    }

    /// Returns true when `start` reaches `target` through the parent links.
    ///
    /// The renderer must draw a tree, so the graph never makes a loop.
    fn reaches(&self, start: usize, target: usize) -> bool {
        let mut seen = BTreeSet::new();
        let mut next = Some(start);
        while let Some(index) = next {
            if index == target {
                return true;
            }
            if !seen.insert(index) {
                return false;
            }
            next = self.nodes[index].parent;
        }
        false
    }

    /// Assesses whether a process still sits in the session of the session
    /// root, and flags it when it does not.
    ///
    /// Every process of a session shares the session identifier of the root
    /// until one of them calls `setsid`. A process whose identifier differs
    /// from the root's therefore detached from the session — it called
    /// `setsid` or a process above it did — which is the B.6 liveness fact:
    /// such a process can outlive the session.
    ///
    /// The comparison is quiet by construction. A process whose session
    /// identifier the monitor could not read makes no claim, a session whose
    /// root identifier is still unknown makes no claim, and the root itself
    /// defines the reference. A gap in the parent chain is **not** this
    /// flag: the graph counts gaps, attaches the process under the session
    /// root and reports too much rather than too little, as it always did.
    fn check_link(&mut self, index: usize) {
        if self.nodes[index].unlink.is_some() {
            return;
        }
        let pid = self.nodes[index].info.pid;
        let sid = self.nodes[index].info.sid;
        if pid == self.session.root_pid {
            if let Some(sid) = sid {
                self.root_sid = Some(sid);
            }
            return;
        }
        if let (Some(root_sid), Some(sid)) = (self.root_sid, sid) {
            if sid != root_sid {
                self.flag(index, SessionDetach { sid, root_sid });
            }
        }
    }

    /// Flags a process as unlinked and queues the flag for the caller.
    fn flag(&mut self, index: usize, detach: SessionDetach) {
        self.nodes[index].unlink = Some(detach);
        self.pending_unlinked
            .push((self.nodes[index].info.pid, detach));
    }

    /// Returns the node of the parent process, or `None` for the session root.
    ///
    /// The graph counts a gap when it does not know the parent, because that
    /// tells the user that the monitor missed events.
    fn resolve_parent(&mut self, ppid: Option<Pid>, pid: Pid) -> Option<usize> {
        if let Some(parent_pid) = ppid {
            if parent_pid != pid && parent_pid > 0 {
                if let Some(index) = self.index_of(parent_pid) {
                    return Some(index);
                }
            }
        }
        self.count_gap(None, pid);
        None
    }

    /// Counts one gap when a process has no known parent.
    fn count_gap(&mut self, parent: Option<usize>, pid: Pid) {
        if parent.is_none() && pid != self.session.root_pid {
            self.gaps += 1;
        }
    }

    /// Moves the node of an older process aside, so a new process can use the
    /// identifier.
    fn retire(&mut self, pid: Pid) {
        if let Some(index) = self.live.get(&pid).copied() {
            self.retire_index(index, pid);
        }
    }

    /// Moves one node aside. The node stays in the graph.
    fn retire_index(&mut self, index: usize, pid: Pid) {
        self.nodes[index].ended = true;
        self.live.remove(&pid);
    }

    /// Adds a node and links it to its parent.
    fn insert(&mut self, info: ProcessInfo, parent: Option<usize>) -> usize {
        let index = self.nodes.len();
        let pid = info.pid;
        let node = Node::new(info, parent, index);
        let key = node.key;
        self.nodes.push(node);
        if let Some(parent) = parent {
            self.nodes[parent].children.push(index);
        }
        self.by_key.insert(key, index);
        self.live.insert(pid, index);
        self.latest.insert(pid, index);
        index
    }
}

impl ProvenanceView for ProcessGraph {
    fn ancestry(&self, pid: Pid) -> Vec<ProcessInfo> {
        ProcessGraph::ancestry(self, pid)
    }

    fn process(&self, pid: Pid) -> Option<ProcessInfo> {
        ProcessGraph::process(self, pid)
    }
}

/// Returns true when two start times can belong to the same process.
///
/// The monitor cannot always read the start time. A start time of `0` means
/// "not known", and an unknown time never proves that a process is new.
fn same_process(known: u64, observed: u64) -> bool {
    known == observed || known == 0 || observed == 0
}

/// Returns the strength of a verdict, so the graph can keep the strongest.
fn rank(verdict: &Verdict) -> (Decision, af_core::RiskLevel) {
    (verdict.decision, verdict.risk)
}

/// Makes session metadata for a trace without a `SessionStart` event.
fn empty_session(session_id: SessionId) -> SessionMeta {
    SessionMeta {
        session_id,
        started_at: 0,
        root_pid: 0,
        command: Vec::new(),
        cwd: String::new(),
        agent: af_core::AgentMeta::from_program(""),
        schema_version: af_core::EVENT_SCHEMA_VERSION,
        baseline: Default::default(),
        detection: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> SessionMeta {
        let mut meta = SessionMeta::new(vec!["bash".to_string()], "/work".to_string());
        meta.session_id = SessionId::from("afw-cycle");
        meta.root_pid = 0;
        meta
    }

    fn info(pid: Pid, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            comm: name.to_string(),
            argv: vec![name.to_string()],
            ..Default::default()
        }
    }

    /// Damaged data must never make an endless walk.
    #[test]
    fn ancestry_terminates_on_a_cycle() {
        let mut graph = ProcessGraph::new(&session());
        let first = graph.insert(info(10, "a"), None);
        let second = graph.insert(info(11, "b"), Some(first));
        let third = graph.insert(info(12, "c"), Some(second));
        // Make a loop that no event stream can produce.
        graph.nodes[first].parent = Some(third);

        let chain = graph.ancestry(12);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].pid, 11);
        assert_eq!(chain[1].pid, 10);
        assert!(graph.has_ancestor_program(12, "a"));
        assert!(!graph.has_ancestor_program(12, "psql"));
    }

    /// A tree drawing must also end when the data holds a loop.
    #[test]
    fn render_terminates_on_a_cycle() {
        let mut graph = ProcessGraph::new(&session());
        let first = graph.insert(info(10, "a"), None);
        let second = graph.insert(info(11, "b"), Some(first));
        // Make a loop in the child links that no event stream can produce.
        graph.nodes[second].children.push(first);

        let tree = graph.render_tree();
        assert_eq!(tree.lines().count(), 3);
    }

    /// An unknown start time never proves that a process is new.
    #[test]
    fn unknown_start_time_keeps_the_process() {
        assert!(same_process(0, 500));
        assert!(same_process(500, 0));
        assert!(same_process(500, 500));
        assert!(!same_process(500, 501));
    }
}
