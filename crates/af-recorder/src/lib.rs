//! Storage and replay of normalized events.
//!
//! The firewall must explain every block and every question later, but it
//! must not keep every low-level event of every session. This crate stores
//! the events of one session as JSON Lines and reads them back:
//!
//! * [`Retention`] decides which events go to storage. Storage depends on
//!   risk, so a blocked action keeps full evidence and normal development
//!   activity goes away.
//! * [`TraceWriter`] writes one event on one line and gives every event a
//!   sequence number.
//! * [`MemorySink`], [`FanoutSink`] and [`StreamSink`] keep, copy and print
//!   the same events.
//! * [`read_trace`] and [`TraceReader`] read a trace back.
//!
//! A trace that comes back is equal to the trace that went out. A policy test
//! therefore sees the same events as the live session, and a replay builds
//! the same process tree.
//!
//! # Example
//!
//! ```
//! use af_core::{Event, EventKind, EventSink, SessionId};
//! use af_recorder::{MemorySink, Retention, TraceWriter};
//!
//! let mut sink = TraceWriter::to_writer(Vec::new(), Retention::All);
//! let event = Event::new(SessionId::from("afw-1a2b"), 1000, EventKind::ProcessFork {
//!     child_pid: 1001,
//!     is_thread: false,
//! });
//! sink.record(&event).expect("record");
//! assert_eq!(sink.stats().kept, 1);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod human;
mod reader;
mod retention;
mod sink;
mod writer;

pub use reader::{read_trace, TraceReader};
pub use retention::Retention;
pub use sink::{FanoutSink, MemorySink, StreamSink};
pub use writer::{TraceWriter, WriterStats};
