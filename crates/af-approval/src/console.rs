//! Input and output on the terminal of the user.
//!
//! The monitored agent owns the standard input of the terminal. The firewall
//! must never read that stream, because it then takes the keystrokes of the
//! user away from the agent. The firewall opens `/dev/tty` instead. This is a
//! second, independent path to the same terminal.
//!
//! The [`Console`] trait keeps all reading and writing in one place. The
//! approver holds a console and does not know if the console is a real
//! terminal or a test double.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

/// Path of the controlling terminal of the process.
const TTY_PATH: &str = "/dev/tty";

/// Largest number of bytes that the console keeps from one answer.
///
/// A hostile program can write many bytes into the terminal. The console
/// drops everything after this limit, so the memory stays small.
const MAX_ANSWER_BYTES: usize = 256;

/// The result of one read from the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The user wrote a line. The text holds no end-of-line character.
    Line(String),
    /// The time ran out before the user answered.
    TimedOut,
    /// The terminal closed, or the read failed.
    Ended,
}

/// A terminal that the approver reads and writes.
///
/// The trait has no error type. A failure of the terminal is never a reason
/// to stop the firewall, so every method reports a failure as [`Answer::Ended`]
/// or does nothing.
pub(crate) trait Console: Send {
    /// Writes text to the terminal.
    fn write_text(&mut self, text: &str);

    /// Reads one line from the terminal.
    ///
    /// `timeout` limits the wait. `None` waits without a limit.
    fn read_line(&mut self, timeout: Option<Duration>) -> Answer;
}

/// Returns true when the process can open the controlling terminal.
///
/// A continuous-integration job and a pipeline have no controlling terminal.
/// The open then fails, and the firewall must not ask a question.
pub(crate) fn terminal_is_available() -> bool {
    open_tty().is_ok()
}

/// Opens the controlling terminal for reading and writing.
fn open_tty() -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).open(TTY_PATH)
}

/// The real terminal of the user, behind `/dev/tty`.
pub(crate) struct TtyConsole {
    /// The open terminal. The approver reads and writes this file.
    file: File,
}

impl TtyConsole {
    /// Opens the controlling terminal.
    ///
    /// The call fails when the process has no terminal.
    pub(crate) fn open() -> std::io::Result<Self> {
        Ok(Self { file: open_tty()? })
    }
}

impl Console for TtyConsole {
    fn write_text(&mut self, text: &str) {
        let _ = self.file.write_all(text.as_bytes());
        let _ = self.file.flush();
    }

    fn read_line(&mut self, timeout: Option<Duration>) -> Answer {
        let deadline = timeout.map(|limit| Instant::now() + limit);
        let mut line: Vec<u8> = Vec::new();
        loop {
            match wait_for_input(self.file.as_raw_fd(), deadline) {
                Wait::Ready => {}
                Wait::TimedOut => return Answer::TimedOut,
                Wait::Failed => return end_of_input(line),
            }
            let mut byte = [0u8; 1];
            match self.file.read(&mut byte) {
                Ok(0) => return end_of_input(line),
                Ok(_) => match byte[0] {
                    // The user pressed Enter. In a raw terminal this is a
                    // carriage return, and in a normal terminal a line feed.
                    b'\n' | b'\r' => return Answer::Line(text_of(&line)),
                    // The user pressed Ctrl-C or Ctrl-D. Both end the answer.
                    0x03 | 0x04 => return Answer::Ended,
                    // The user pressed Backspace or Delete.
                    0x08 | 0x7f => {
                        line.pop();
                    }
                    value => {
                        if line.len() < MAX_ANSWER_BYTES {
                            line.push(value);
                        }
                    }
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return end_of_input(line),
            }
        }
    }
}

/// Makes the answer for a terminal that closed.
///
/// Text that the user wrote before the close is still an answer. An empty
/// buffer means that the terminal gave nothing.
fn end_of_input(line: Vec<u8>) -> Answer {
    if line.is_empty() {
        Answer::Ended
    } else {
        Answer::Line(text_of(&line))
    }
}

/// Converts the bytes of one answer into text.
///
/// A hostile program can write bytes that are not valid text. The conversion
/// replaces them, so the approver always gets valid text.
fn text_of(line: &[u8]) -> String {
    String::from_utf8_lossy(line).to_string()
}

/// The result of one wait for input.
enum Wait {
    /// The terminal has data.
    Ready,
    /// The time ran out.
    TimedOut,
    /// The wait failed.
    Failed,
}

/// Waits until the terminal has data, or until the deadline passes.
///
/// The function uses `poll`, because a plain read blocks the thread. A
/// monitored process waits while the approver asks, so the approver must be
/// able to stop the wait.
fn wait_for_input(fd: RawFd, deadline: Option<Instant>) -> Wait {
    loop {
        let milliseconds: libc::c_int = match deadline {
            None => -1,
            Some(end) => {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Wait::TimedOut;
                }
                left.as_millis().min(libc::c_int::MAX as u128) as libc::c_int
            }
        };
        let mut watched = [libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        }];
        // The call needs one valid descriptor and one entry in the array.
        // Both conditions hold here.
        let result = unsafe { libc::poll(watched.as_mut_ptr(), 1, milliseconds) };
        if result > 0 {
            if watched[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Wait::Failed;
            }
            return Wait::Ready;
        }
        if result == 0 {
            return Wait::TimedOut;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Wait::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closed_terminal_with_text_still_gives_the_line() {
        assert_eq!(
            end_of_input(b"allow".to_vec()),
            Answer::Line("allow".into())
        );
        assert_eq!(end_of_input(Vec::new()), Answer::Ended);
    }

    #[test]
    fn invalid_bytes_become_valid_text() {
        assert_eq!(text_of(&[b'a', 0xff]), "a\u{fffd}");
    }
}
