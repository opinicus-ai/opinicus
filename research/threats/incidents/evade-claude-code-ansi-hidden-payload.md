# ANSI terminal escape codes hid attacker instructions from Claude Code users

- Date: 2025-04 | Agent/tool: Claude Code 0.2.76 (MCP tool descriptions and tool output) | Axis: evade

## What happened

Trail of Bits published research in April 2025 showing that ANSI terminal escape codes could hide malicious payloads inside MCP tool descriptions and tool output in Claude Code. In testing, Claude Code did no filtering or sanitization of these escape sequences. The terminal rendered them, so the human saw harmless text, while the model still read the hidden instructions and acted on them. The researchers demonstrated hidden instructions that pushed the user toward downloading Python from an attacker-controlled server. They also showed cursor-overwrite, screen-clearing, and spoofed hyperlink variants. The result is a gap between what the user approves and what the model executes.

## How it went wrong

An MCP tool returned normal-looking environment notes. One sentence was wrapped in the SGR sequence `ESC[38;5;231;49m`, which sets foreground and background to the same color. The instruction inside, for example that the user's Python downloads come from a specific IP, became invisible on screen but stayed fully readable to the model. Other variants moved the cursor up and overwrote the malicious lines with fake "scan complete" output, cleared the screen after planting instructions, or used the OSC 8 hyperlink escape so the visible link text pointed to a legitimate site while the actual URL was an attacker's. The user reviewing the terminal sees a clean transcript. The model sees the raw text and follows it. Any command the agent runs because of the hidden text looks like the agent's own choice.

## What the firewall should learn

The agent's own output channel became a hiding place, so review of terminal text cannot be trusted. The firewall sees the raw bytes before display: the `input` observable (script and command text) and exec argv carry the escape bytes. Rule ideas: approval_required when a command string or captured script contains raw ESC bytes (0x1B) or zero-width Unicode (U+200B, U+200C, U+200D, U+2060, U+FEFF), because legitimate shell commands almost never need them; strip the escapes first, then re-run pattern matching on the cleaned text so split payloads still match; report exec argv that contains control characters. This turns invisible text into a visible approval decision.

## Sources

- [Trail of Bits: Deceiving users with ANSI terminal codes in MCP](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/)
- [Trail of Bits: Jumping the Line — How MCP servers can attack you before you ever use them](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/)
- [Bright Security: Detecting ANSI Escape Sequence Injection in MCP Servers](https://brightsec.com/research/detecting-ansi-escape-sequence-injection-in-mcp-servers-with-dast/)
