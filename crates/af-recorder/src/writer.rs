//! Writing of a trace as JSON Lines.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use af_core::{Event, EventSink, Pid, Result};

use crate::retention::{decides_about, is_held_action, named_processes, Retention};

/// How many exec events wait at most for a decision that names them.
///
/// Tracing makes a lot of data, so the queue must stay bounded. The writer
/// drops the oldest event when the queue is full.
const MAX_PENDING: usize = 4096;

/// How many events the writer kept and how many it dropped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterStats {
    /// How many events the writer wrote to storage.
    pub kept: u64,
    /// How many events the writer did not write.
    pub dropped: u64,
}

/// Writes a trace as JSON Lines.
///
/// The writer puts one event on one line, so a reader can read a large trace
/// line by line, and a broken line never damages the next event.
///
/// The writer gives every event that it keeps a sequence number, from 1
/// upwards. A trace file therefore holds the numbers 1, 2, 3 and so on,
/// without a hole and without a repeat.
///
/// [`Retention`] decides which events go to the file.
/// [`Retention::EvidenceOnly`] holds an exec event back until a decision
/// names the process. [`Retention::Balanced`] holds a file open and a
/// connection back for exactly one event, and writes it when the decision of
/// that action names at least one rule. Such an event counts as dropped while
/// it waits, so `kept + dropped` always equals the number of events that the
/// writer saw.
///
/// The writer flushes after every event that is evidence and after every
/// event that is durable — the events that name the processes of the
/// session, which are the record of who ran when — and it flushes when it
/// goes away. A session that ends badly, and a monitor that an attack
/// kills, therefore still leave usable evidence.
pub struct TraceWriter {
    /// Where the lines go.
    out: Box<dyn Write + Send>,
    /// Which events go to storage.
    retention: Retention,
    /// Sequence number of the last event that the writer wrote.
    seq: u64,
    /// How many events the writer kept and dropped.
    stats: WriterStats,
    /// Exec events that wait for a decision, with their arrival order.
    pending: BTreeMap<Pid, (u64, Event)>,
    /// Arrival counter of the waiting events.
    arrivals: u64,
    /// The file open or the connection that waits for its own decision.
    ///
    /// [`Retention::Balanced`] uses it. Only one event ever waits: the
    /// firewall emits the decision of an action directly after the action, so
    /// the next event answers the question, and any other next event ends the
    /// wait with a drop.
    held: Option<Event>,
}

impl TraceWriter {
    /// Makes a writer for a new trace file.
    ///
    /// The function makes the directory of the file when it is missing, so
    /// that a caller can point at a fresh session directory.
    pub fn create(path: &Path, retention: Retention) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = File::create(path)?;
        Ok(Self::to_writer(BufWriter::new(file), retention))
    }

    /// Makes a writer that puts the lines into any destination.
    pub fn to_writer<W: Write + Send + 'static>(writer: W, retention: Retention) -> Self {
        Self {
            out: Box::new(writer),
            retention,
            seq: 0,
            stats: WriterStats::default(),
            pending: BTreeMap::new(),
            arrivals: 0,
            held: None,
        }
    }

    /// Returns how many events the writer kept and how many it dropped.
    pub fn stats(&self) -> WriterStats {
        self.stats
    }

    /// Returns which events this writer keeps.
    pub fn retention(&self) -> Retention {
        self.retention
    }

    /// Writes one event and gives it the next sequence number.
    fn write(&mut self, event: &Event) -> Result<()> {
        self.seq += 1;
        let mut line = event.clone();
        line.seq = self.seq;
        serde_json::to_writer(&mut self.out, &line)?;
        self.out.write_all(b"\n")?;
        self.stats.kept += 1;
        if line.kind.is_durable() {
            // Evidence, and the process events that name who ran when, must
            // survive a hard stop of the session — also a `SIGKILL` of the
            // monitor itself, which takes no cleanup path with it. The write
            // reaches the kernel here; the file system makes it visible to
            // the next reader even if this process dies on the next line.
            self.out.flush()?;
        }
        Ok(())
    }

    /// Holds an exec event back until a decision names the process.
    fn defer(&mut self, event: &Event) {
        self.stats.dropped += 1;
        self.arrivals += 1;
        self.pending
            .insert(event.pid, (self.arrivals, event.clone()));
        while self.pending.len() > MAX_PENDING {
            let oldest = self
                .pending
                .iter()
                .min_by_key(|(_, (arrival, _))| *arrival)
                .map(|(pid, _)| *pid);
            match oldest {
                Some(pid) => {
                    self.pending.remove(&pid);
                }
                None => break,
            }
        }
    }

    /// Writes the exec events of the processes that a kept event names.
    ///
    /// The events go out in their arrival order, so a parent still comes
    /// before its child.
    fn release(&mut self, event: &Event) -> Result<()> {
        let mut ready: Vec<(u64, Event)> = named_processes(event)
            .into_iter()
            .filter_map(|pid| self.pending.remove(&pid))
            .collect();
        ready.sort_by_key(|(arrival, _)| *arrival);
        for (_, held) in ready {
            self.stats.dropped -= 1;
            self.write(&held)?;
        }
        Ok(())
    }
}

impl TraceWriter {
    /// Holds a file open or a connection until its own decision arrives.
    ///
    /// The event counts as dropped while it waits, exactly like a deferred
    /// exec event, so the two counters always add up to what the writer saw.
    fn hold(&mut self, event: &Event) -> Result<()> {
        self.release_held(None)?;
        self.stats.dropped += 1;
        self.held = Some(event.clone());
        Ok(())
    }

    /// Ends the wait of the held action.
    ///
    /// The event goes to storage when `decision` is its own decision and names
    /// at least one rule. In every other case it stays dropped: an action that
    /// no rule matched cannot change a verdict of a replay.
    fn release_held(&mut self, decision: Option<&Event>) -> Result<()> {
        let Some(held) = self.held.take() else {
            return Ok(());
        };
        if decision.is_some_and(|decision| decides_about(&held, decision)) {
            self.stats.dropped -= 1;
            self.write(&held)?;
        }
        Ok(())
    }
}

impl EventSink for TraceWriter {
    fn record(&mut self, event: &Event) -> Result<()> {
        if self.retention == Retention::Balanced {
            if is_held_action(event) {
                return self.hold(event);
            }
            self.release_held(Some(event))?;
        }
        if self.retention.should_keep(event) {
            if self.retention == Retention::EvidenceOnly {
                self.release(event)?;
            }
            return self.write(event);
        }
        if self.retention == Retention::EvidenceOnly
            && matches!(event.kind, af_core::EventKind::ProcessExec { .. })
        {
            self.defer(event);
            return Ok(());
        }
        self.stats.dropped += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        // A held action that never got its decision stays dropped. It is an
        // action that no rule matched.
        self.release_held(None)?;
        self.out.flush()?;
        Ok(())
    }
}

impl Drop for TraceWriter {
    /// Writes everything that is still in memory.
    ///
    /// A session can end badly. The evidence of the session must still reach
    /// the file.
    fn drop(&mut self) {
        self.pending.clear();
        self.held = None;
        let _ = self.out.flush();
    }
}

impl std::fmt::Debug for TraceWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceWriter")
            .field("retention", &self.retention)
            .field("seq", &self.seq)
            .field("stats", &self.stats)
            .field("waiting", &self.pending.len())
            .finish()
    }
}
