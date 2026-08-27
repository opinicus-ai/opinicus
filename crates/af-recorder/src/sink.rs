//! Sinks that keep, copy or print events.

use std::io::Write;

use af_core::{Error, Event, EventSink, Result};

use crate::human;

/// Keeps events in memory.
///
/// Use it in tests, and use it during a run to build the process tree at the
/// end of the session.
#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    /// Every event that the sink received, in order.
    events: Vec<Event>,
}

impl MemorySink {
    /// Makes an empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every event that the sink holds.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Returns the events and uses the sink up.
    pub fn take(self) -> Vec<Event> {
        self.events
    }
}

impl EventSink for MemorySink {
    /// Keeps one event and gives it the next sequence number.
    fn record(&mut self, event: &Event) -> Result<()> {
        let mut copy = event.clone();
        copy.seq = self.events.len() as u64 + 1;
        self.events.push(copy);
        Ok(())
    }
}

/// Sends every event to several sinks.
///
/// A session normally writes a trace file and prints the events at the same
/// time. Every sink gives its own sequence numbers, because a sink can keep
/// other events than its neighbour.
#[derive(Default)]
pub struct FanoutSink {
    /// The destinations, in the order that the caller added them.
    sinks: Vec<Box<dyn EventSink>>,
}

impl FanoutSink {
    /// Makes a fanout without a destination.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one destination.
    pub fn add(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    /// Makes a fanout from a list of destinations.
    pub fn with(sinks: Vec<Box<dyn EventSink>>) -> Self {
        Self { sinks }
    }

    /// Returns how many destinations the fanout holds.
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Returns true when the fanout holds no destination.
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl EventSink for FanoutSink {
    /// Sends one event to every destination.
    ///
    /// A destination that fails does not stop the other destinations. The
    /// call returns the first failure after every destination saw the event,
    /// because a lost trace file must not also stop the screen output.
    fn record(&mut self, event: &Event) -> Result<()> {
        let mut first: Option<Error> = None;
        for sink in &mut self.sinks {
            if let Err(error) = sink.record(event) {
                first.get_or_insert(error);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Flushes every destination.
    fn flush(&mut self) -> Result<()> {
        let mut first: Option<Error> = None;
        for sink in &mut self.sinks {
            if let Err(error) = sink.flush() {
                first.get_or_insert(error);
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl std::fmt::Debug for FanoutSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FanoutSink")
            .field("sinks", &self.sinks.len())
            .finish()
    }
}

/// Which form the stream sink prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// One short line for a person.
    Human,
    /// One JSON object for another program.
    Json,
}

/// Prints events for a person or as JSON.
///
/// The human form prints one line for every event. It prints the full
/// explanation under a decision that holds an action, because every block
/// must be explainable.
///
/// The sink removes every control character from the human form, so a
/// monitored program cannot write escape sequences into the terminal of the
/// user.
pub struct StreamSink {
    /// Where the text goes.
    out: Box<dyn Write + Send>,
    /// Which form the sink prints.
    format: Format,
    /// Sequence number of the last event.
    seq: u64,
}

impl StreamSink {
    /// Makes a sink that prints one line for every event.
    pub fn human<W: Write + Send + 'static>(w: W) -> Self {
        Self {
            out: Box::new(w),
            format: Format::Human,
            seq: 0,
        }
    }

    /// Makes a sink that prints one JSON object for every event.
    pub fn json<W: Write + Send + 'static>(w: W) -> Self {
        Self {
            out: Box::new(w),
            format: Format::Json,
            seq: 0,
        }
    }
}

impl EventSink for StreamSink {
    /// Prints one event and gives it the next sequence number.
    fn record(&mut self, event: &Event) -> Result<()> {
        self.seq += 1;
        let mut copy = event.clone();
        copy.seq = self.seq;
        match self.format {
            Format::Human => {
                writeln!(self.out, "{}", human::line(&copy))?;
                if let Some(detail) = human::detail(&copy) {
                    for line in detail.lines() {
                        writeln!(self.out, "        {line}")?;
                    }
                }
            }
            Format::Json => {
                serde_json::to_writer(&mut self.out, &copy)?;
                self.out.write_all(b"\n")?;
            }
        }
        self.out.flush()?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
        Ok(())
    }
}

impl std::fmt::Debug for StreamSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSink")
            .field("format", &self.format)
            .field("seq", &self.seq)
            .finish()
    }
}
