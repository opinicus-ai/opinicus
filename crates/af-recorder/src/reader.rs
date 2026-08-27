//! Reading of a recorded trace.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use af_core::{Error, Event, EventKind, Result, SessionMeta};

/// Reads a recorded trace.
///
/// The function stops at the first broken line and returns
/// [`af_core::Error::Trace`] with the name of the file and the number of the
/// line. Use [`TraceReader`] when the caller wants to read over a damaged
/// line, or when the file is too large for the memory.
///
/// # Example
///
/// ```no_run
/// # fn main() -> af_core::Result<()> {
/// let events = af_recorder::read_trace(std::path::Path::new("session.jsonl"))?;
/// println!("{} events", events.len());
/// # Ok(())
/// # }
/// ```
pub fn read_trace(path: &Path) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    for item in TraceReader::open(path)? {
        events.push(item?);
    }
    Ok(events)
}

/// Reads a trace one event at a time, so a large file does not fill the
/// memory.
///
/// The reader gives one item for every line. A broken line gives
/// [`af_core::Error::Trace`], and the reader continues with the next line. A
/// damaged line therefore never hides the evidence that comes after it.
///
/// The reader skips an empty line, because an empty line holds no event.
pub struct TraceReader {
    /// The lines of the trace.
    lines: Box<dyn Iterator<Item = std::io::Result<String>> + Send>,
    /// Name of the file, for the error messages.
    source: String,
    /// Number of the last line that the reader read.
    line_no: u64,
    /// The first item, which [`TraceReader::open`] already read.
    first: Option<Result<Event>>,
    /// Metadata of the session, from the `SessionStart` event.
    session: Option<SessionMeta>,
    /// True when the file itself failed. The reader then stops.
    failed: bool,
}

impl TraceReader {
    /// Opens a trace file.
    ///
    /// The reader reads the first line at once, so that
    /// [`TraceReader::session_meta`] can answer before the caller reads an
    /// event. The iterator still gives that first event.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let name = path.display().to_string();
        Ok(Self::from_reader(BufReader::new(file), name))
    }

    /// Makes a reader for any source of lines.
    pub fn from_reader<R: BufRead + Send + 'static>(reader: R, source: impl Into<String>) -> Self {
        let mut reader = Self {
            lines: Box::new(reader.lines()),
            source: source.into(),
            line_no: 0,
            first: None,
            session: None,
            failed: false,
        };
        let first = reader.read_next();
        reader.first = first;
        reader
    }

    /// Returns the metadata of the session, when the trace names it.
    pub fn session_meta(&self) -> Option<&SessionMeta> {
        self.session.as_ref()
    }

    /// Returns the name of the trace, for messages to the user.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Reads the next event from the file.
    fn read_next(&mut self) -> Option<Result<Event>> {
        if self.failed {
            return None;
        }
        loop {
            let line = match self.lines.next() {
                Some(Ok(line)) => line,
                Some(Err(error)) => {
                    self.failed = true;
                    return Some(Err(Error::Io(error)));
                }
                None => return None,
            };
            self.line_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            return Some(match serde_json::from_str::<Event>(&line) {
                Ok(event) => {
                    if let EventKind::SessionStart { meta, .. } = &event.kind {
                        if self.session.is_none() {
                            self.session = Some((**meta).clone());
                        }
                    }
                    Ok(event)
                }
                Err(error) => Err(Error::trace(format!(
                    "{}:{}: {error}",
                    self.source, self.line_no
                ))),
            });
        }
    }
}

impl Iterator for TraceReader {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(first) = self.first.take() {
            return Some(first);
        }
        self.read_next()
    }
}

impl std::fmt::Debug for TraceReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceReader")
            .field("source", &self.source)
            .field("line", &self.line_no)
            .finish()
    }
}
