//! The text of the question that the user reads.
//!
//! The firewall holds a dangerous action while the user reads this text. The
//! text must therefore answer four questions at one look: which agent started
//! the action, what the action does, which rule matched, and what the user
//! can answer.

use std::time::Duration;

use af_core::{display, ApprovalRequest, RiskLevel};

/// Left part of the top border.
const HEADER_LEFT: &str = "┌─ Agent Firewall ─ ";

/// Left part of the bottom border. It holds the answers of the user.
const FOOTER_LEFT: &str = "└─ [a]llow once  [s]ession  [d]eny  [t]erminate ";

/// Smallest width of the box, in characters.
const MIN_WIDTH: usize = 56;

/// Largest width of one line inside the box, in characters.
///
/// A longer line goes to the next line. The box therefore keeps its shape,
/// also with a very long command line.
const MAX_CONTENT: usize = 88;

/// Indent of a line that continues the line above it.
const CONTINUATION: &str = "    ";

/// Escape code that starts yellow text.
const YELLOW: &str = "\u{1b}[33m";

/// Escape code that starts red text.
const RED: &str = "\u{1b}[31m";

/// Escape code that ends every colour.
const RESET: &str = "\u{1b}[0m";

/// Draws the question for the user.
///
/// The text holds a header with the risk level, the identifier of the
/// session, the working directory of the process, the provenance chain, the
/// operation, the rule, the risk, the decision and the answers. The body
/// comes from [`af_core::display::explain`], so a held action and a recorded
/// trace look the same.
///
/// `color` switches the colour of the risk level on. The function writes no
/// colour when `color` is false, so a log file stays clean.
///
/// `countdown` is the answer time that remains at the moment of the render.
/// The prompt then says how long the user has, and that the firewall denies
/// after it ([`countdown_line`]). The number is a fact of the render, not a
/// clock: the approver re-renders the line each time it asks again, and the
/// deadline itself is enforced by the read, where a timeout still denies.
/// Rendering can never turn a timeout into an allow.
///
/// The function removes every control character from the text of the
/// process. A hostile program can write escape codes into its command line,
/// and those codes must never reach the terminal of the user.
pub fn render_prompt(
    req: &ApprovalRequest<'_>,
    color: bool,
    countdown: Option<Duration>,
) -> String {
    let risk = req.verdict.risk;
    let mut lines: Vec<Line> = Vec::new();

    add_line(
        &mut lines,
        format!(
            "session {}  ·  {}",
            display::sanitize(req.session.session_id.as_str()),
            display::sanitize(req.session.agent.kind.label())
        ),
        None,
        color,
    );
    add_line(
        &mut lines,
        format!("cwd {}", display::sanitize(working_directory(req))),
        None,
        color,
    );
    if let Some(left) = countdown {
        add_line(&mut lines, countdown_line(left), None, color);
    }

    let explanation = display::explain(req.ancestry, req.process, req.action, req.verdict);
    let mut after_risk_label = false;
    for raw in explanation.lines() {
        let clean = display::sanitize(raw);
        let paint = if after_risk_label { Some(risk) } else { None };
        after_risk_label = clean.trim() == "Risk:";
        add_line(&mut lines, clean, paint, color);
    }

    let title = title_of(risk);
    let width = box_width(&lines, &title);

    let mut out = String::new();
    out.push_str(&border(
        HEADER_LEFT,
        &paint(&title, Some(risk), color),
        title.chars().count(),
        width,
    ));
    for line in &lines {
        out.push_str("│ ");
        out.push_str(&line.shown);
        out.push('\n');
    }
    out.push_str(&border(FOOTER_LEFT, "", 0, width));
    out
}

/// One line inside the box.
struct Line {
    /// The line without colour. The width of the box uses this text.
    plain: String,
    /// The line as the terminal shows it. It can hold escape codes.
    shown: String,
}

/// Returns the working directory of the process that acts.
///
/// The monitor cannot always read the directory of a process. The directory
/// of the session is then the best answer.
fn working_directory<'a>(req: &'a ApprovalRequest<'a>) -> &'a str {
    req.process
        .cwd
        .as_deref()
        .unwrap_or(req.session.cwd.as_str())
}

/// Adds one line to the box and breaks it when it is too long.
fn add_line(lines: &mut Vec<Line>, text: String, risk: Option<RiskLevel>, color: bool) {
    let parts = wrap(&text);
    let single = parts.len() == 1;
    for part in parts {
        let shown = if single {
            paint_value(&part, risk, color)
        } else {
            part.clone()
        };
        lines.push(Line { plain: part, shown });
    }
}

/// Breaks one long line into a group of short lines.
fn wrap(text: &str) -> Vec<String> {
    let characters: Vec<char> = text.chars().collect();
    if characters.len() <= MAX_CONTENT {
        return vec![text.to_string()];
    }
    let rest_width = MAX_CONTENT
        .saturating_sub(CONTINUATION.chars().count())
        .max(1);
    let mut parts = Vec::new();
    let mut start = 0;
    let mut width = MAX_CONTENT;
    while start < characters.len() {
        let end = (start + width).min(characters.len());
        let chunk: String = characters[start..end].iter().collect();
        if parts.is_empty() {
            parts.push(chunk);
        } else {
            parts.push(format!("{CONTINUATION}{chunk}"));
        }
        start = end;
        width = rest_width;
    }
    parts
}

/// Returns the line that says how much answer time remains.
///
/// A fraction of a second still names the second it belongs to, so the line
/// never says `0s` while an answer could still arrive within the limit. The
/// line names the consequence, because the consequence is the point: no
/// answer denies.
pub fn countdown_line(left: Duration) -> String {
    let seconds = left.as_secs().max(1);
    format!("{seconds}s left to answer, then the firewall denies")
}

/// Returns the title of the box, for example `approval required`.
fn title_of(risk: RiskLevel) -> String {
    risk.label().replace('-', " ")
}

/// Returns the width of the box in characters.
fn box_width(lines: &[Line], title: &str) -> usize {
    let content = lines
        .iter()
        .map(|line| line.plain.chars().count() + 2)
        .max()
        .unwrap_or(0);
    let header = HEADER_LEFT.chars().count() + title.chars().count() + 5;
    let footer = FOOTER_LEFT.chars().count() + 4;
    content.max(header).max(footer).max(MIN_WIDTH)
}

/// Draws a border line and fills the rest of the width with a line character.
///
/// `visible` is the width of `value` without escape codes. The fill uses that
/// number, so a colour never changes the shape of the box.
fn border(left: &str, value: &str, visible: usize, width: usize) -> String {
    let mut out = String::from(left);
    if !value.is_empty() {
        out.push_str(value);
        out.push(' ');
    }
    let used = left.chars().count() + visible + if value.is_empty() { 0 } else { 1 };
    for _ in used..width {
        out.push('─');
    }
    out.push('\n');
    out
}

/// Colours the value of a line and keeps the indent of the line.
fn paint_value(text: &str, risk: Option<RiskLevel>, color: bool) -> String {
    let value = text.trim_start();
    if value.is_empty() {
        return text.to_string();
    }
    let indent = &text[..text.len() - value.len()];
    format!("{indent}{}", paint(value, risk, color))
}

/// Puts the colour of a risk level around text.
///
/// The colour is yellow for a suspicious action and red for an action that
/// needs approval or that the firewall blocks. A lower level gets no colour,
/// because the firewall must stay quiet for normal work.
fn paint(text: &str, risk: Option<RiskLevel>, color: bool) -> String {
    let code = match (color, risk) {
        (true, Some(RiskLevel::Suspicious)) => YELLOW,
        (true, Some(RiskLevel::ApprovalRequired)) | (true, Some(RiskLevel::Blocked)) => RED,
        _ => return text.to_string(),
    };
    format!("{code}{text}{RESET}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Fixture;

    #[test]
    fn the_prompt_holds_the_chain_the_rule_the_operation_and_the_answers() {
        let fixture = Fixture::psql("DROP DATABASE customer_prod");
        let text = render_prompt(&fixture.request(), false, None);

        assert!(
            text.contains("┌─ Agent Firewall ─ approval required"),
            "{text}"
        );
        assert!(text.contains("claude"), "{text}");
        assert!(text.contains("-> bash"), "{text}");
        assert!(text.contains("-> migrate.sh"), "{text}");
        assert!(text.contains("-> psql"), "{text}");
        assert!(text.contains("Attempted operation:"), "{text}");
        assert!(text.contains("DROP DATABASE customer_prod"), "{text}");
        assert!(text.contains("Policy:"), "{text}");
        assert!(
            text.contains("database.destructive.drop-database"),
            "{text}"
        );
        assert!(text.contains("Decision:"), "{text}");
        assert!(
            text.contains("└─ [a]llow once  [s]ession  [d]eny  [t]erminate"),
            "{text}"
        );
    }

    #[test]
    fn the_prompt_holds_the_session_and_the_working_directory() {
        let fixture = Fixture::psql("DROP DATABASE customer_prod");
        let text = render_prompt(&fixture.request(), false, None);
        assert!(text.contains("session afw-test-session"), "{text}");
        assert!(text.contains("Claude Code"), "{text}");
        assert!(text.contains("cwd /home/dev/project"), "{text}");
    }

    #[test]
    fn the_prompt_removes_terminal_escape_codes() {
        let hostile = "DROP DATABASE prod\u{1b}[2J\u{1b}[1;31mSAFE\u{7}";
        let fixture = Fixture::psql(hostile);
        let text = render_prompt(&fixture.request(), false, None);

        assert!(!text.contains('\u{1b}'), "{text}");
        assert!(!text.contains('\u{7}'), "{text}");
        assert!(text.contains("DROP DATABASE prod·[2J"), "{text}");
    }

    #[test]
    fn a_hostile_working_directory_cannot_write_escape_codes() {
        let mut fixture = Fixture::psql("DROP DATABASE prod");
        fixture.process.cwd = Some("/home/dev/\u{1b}[2Jgone".to_string());
        let text = render_prompt(&fixture.request(), false, None);
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[test]
    fn colour_marks_the_risk_level() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let text = render_prompt(&fixture.request(), true, None);
        assert!(
            text.contains(&format!("{RED}approval required{RESET}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{RED}approval-required{RESET}")),
            "{text}"
        );
    }

    #[test]
    fn a_suspicious_action_is_yellow() {
        let mut fixture = Fixture::psql("DROP DATABASE prod");
        fixture.set_risk(RiskLevel::Suspicious);
        let text = render_prompt(&fixture.request(), true, None);
        assert!(
            text.contains(&format!("{YELLOW}suspicious{RESET}")),
            "{text}"
        );
        assert!(!text.contains(RED), "{text}");
    }

    #[test]
    fn a_low_risk_action_gets_no_colour() {
        let mut fixture = Fixture::psql("DROP DATABASE prod");
        fixture.set_risk(RiskLevel::Low);
        let text = render_prompt(&fixture.request(), true, None);
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[test]
    fn no_colour_means_no_escape_code() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let text = render_prompt(&fixture.request(), false, None);
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    #[test]
    fn every_line_of_the_box_has_a_border() {
        let fixture = Fixture::psql("DROP DATABASE customer_prod");
        let text = render_prompt(&fixture.request(), false, None);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with('┌'));
        assert!(lines[lines.len() - 1].starts_with('└'));
        for line in &lines[1..lines.len() - 1] {
            assert!(line.starts_with("│ "), "line: {line}");
        }
    }

    #[test]
    fn the_borders_have_the_same_width() {
        let fixture = Fixture::psql("DROP DATABASE customer_prod");
        let text = render_prompt(&fixture.request(), false, None);
        let lines: Vec<&str> = text.lines().collect();
        let first = lines[0].chars().count();
        let last = lines[lines.len() - 1].chars().count();
        assert_eq!(first, last);
        assert!(first >= MIN_WIDTH);
    }

    #[test]
    fn a_long_command_line_goes_to_the_next_line() {
        let long = "DROP DATABASE ".to_string() + &"x".repeat(400);
        let fixture = Fixture::psql(&long);
        let text = render_prompt(&fixture.request(), false, None);
        for line in text.lines() {
            assert!(
                line.chars().count() <= MAX_CONTENT + 2,
                "line too long: {} characters",
                line.chars().count()
            );
        }
    }

    #[test]
    fn a_request_without_a_rule_still_gets_a_prompt() {
        let mut fixture = Fixture::psql("DROP DATABASE prod");
        fixture.verdict.matches.clear();
        let text = render_prompt(&fixture.request(), false, None);
        assert!(text.contains("(no rule matched)"), "{text}");
    }

    #[test]
    fn the_prompt_names_the_answer_time_when_a_deadline_exists() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let text = render_prompt(&fixture.request(), false, Some(Duration::from_secs(118)));
        assert!(
            text.contains("118s left to answer, then the firewall denies"),
            "{text}"
        );
    }

    #[test]
    fn the_countdown_never_names_zero_seconds_while_an_answer_can_arrive() {
        assert_eq!(
            countdown_line(Duration::from_secs(30)),
            "30s left to answer, then the firewall denies"
        );
        // A fraction of a second still belongs to its second, so the line
        // never claims that no time is left while the read still waits.
        assert_eq!(
            countdown_line(Duration::from_millis(200)),
            "1s left to answer, then the firewall denies"
        );
    }

    #[test]
    fn a_prompt_without_a_deadline_names_no_time() {
        let fixture = Fixture::psql("DROP DATABASE prod");
        let text = render_prompt(&fixture.request(), false, None);
        assert!(!text.contains("left to answer"), "{text}");
    }
}
