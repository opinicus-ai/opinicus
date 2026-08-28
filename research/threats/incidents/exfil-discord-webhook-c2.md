# Discord webhooks became free exfiltration infrastructure across npm, PyPI and RubyGems

- Date: 2025-10-11 (Socket research round-up; packages published through 2025) | Agent/tool: malicious packages `mysql-dumpdiscord`, `nodejs.discord`, `malinssx`/`malicus`/`maliinn`, `sqlcommenter_rails` | Axis: exfil

## What happened

Socket's Threat Research Team documented a wave of malicious packages on npm, PyPI and RubyGems.org that use Discord webhooks as their exfiltration endpoint instead of attacker-run servers. The npm package `mysql-dumpdiscord` reads a project's `config.json`, `config.js`, `.env` and `ayarlar.*` files on `require()` and POSTs their contents into an attacker's Discord channel. The RubyGems package `sqlcommenter_rails` collects `/etc/passwd`, DNS servers, hostname, username, directories and the machine's public IP (via `api.ipify.org`) and posts the whole dossier the same way. PyPI packages `malinssx`, `malicus` and `maliinn` fire a webhook POST from a `setup.py` install hook during `pip install`. Socket notes the same channel is already used via Telegram, Slack and GitHub webhooks, and maps the campaign to MITRE T1567 (Exfiltration Over Web Service).

## How it went wrong

A Discord webhook is just an HTTPS URL containing a numeric ID and a secret token; whoever holds the URL can post into the channel, and posts are write-only — no authentication, no server to host, nothing to take down. A developer (or CI runner) installs the package; the package's install hook or module-load code runs inside the normal interpreter process, reads credential files with ordinary file APIs (`fs.readFileSync('.env')`, `File.read('/etc/passwd')`), and sends the data with the language's built-in HTTP client (`fetch`, `urllib.request`, `Net::HTTP`) as a plain JSON POST to `https://discord.com/api/webhooks/...`. There is no curl exec, no raw IP, no unusual port, no DNS anomaly — the destination is a popular SaaS domain that most firewalls allow by default, and the payload looks like ordinary JSON API traffic. At the OS level the whole chain hides inside one interpreter process: exec of `pip`/`npm`/`gem` (or the app importing the package), then file reads, then a single HTTPS connection to a legitimate host.

## What the firewall should learn

The current network pack's exfil rules key on curl/wget argv and collector hostnames (transfer.sh, webhook.site) — none of which appear here. The honest signal is the connection, not the command: `network_connect` to `discord.com/api/webhooks/`, `hooks.slack.com/services/`, `api.telegram.org/bot...` (and equivalents) from package-manager lifecycle ancestry or from any agent-ancestry process is an approval-worthy egress event, and pairs with `file_open` reads of `.env`/credential paths in the same session for a deny-grade chain rule. At exec level, an argv/input rule can still catch hand-run variants: a POST/upload flag aimed at a chat-webhook URL. The lesson generalizes: the collector list is a moving target, so the durable rule is channel-shaped (chat-platform webhook paths), not domain-shaped.

## Sources

- [Socket: Weaponizing Discord for Command and Control Across npm, PyPI, and RubyGems.org](https://socket.dev/blog/weaponizing-discord-for-command-and-control)
- [The Hacker News: npm, PyPI, and RubyGems Packages Found Sending Developer Data to Discord](https://thehackernews.com/2025/10/npm-pypi-and-rubygems-packages-found.html)
