# GlassWorm hid in Open VSX extensions and moved stolen credentials over blockchain-driven egress

- Date: 2025-10 | Agent/tool: VS Code / Open VSX editor extensions (extension host) | Axis: exfil

## What happened

Koi Security reported GlassWorm in late September and October 2025: malicious extensions on the Open VSX marketplace hid their code inside invisible Unicode characters. The worm stole developer credentials and spread to further extensions and repositories using them. Its command channel fetched the current C2 address from Solana blockchain transaction memos, with Google Calendar as a backup. The payload servers held stolen credentials, and Koi found a victim list spanning many countries. Koi estimated about 35,800 affected installs. The Eclipse Foundation first called the incident contained; new infected extensions and fresh blockchain C2 transactions appeared weeks later.

## How it went wrong

The user installs a normal-looking editor extension. The extension host (a `node` process) executes the hidden code. It queries a Solana RPC endpoint, reads the memo field of transactions from a hardcoded wallet, and decodes a base64 C2 URL such as `http://217.69.3.218/...`. It downloads an encrypted payload from that address, takes the decryption key from response headers, and evals the JavaScript. The payload reads browser cookie stores, keychain and Git credential material from disk, and sends it to attacker servers. Later it uses those credentials to push infected code into more packages. At the OS level: exec of `node` (extension host ancestry), a network_connect to a blockchain RPC host and then to a raw-IP C2 server, file_open reads of browser profiles and keychain files, and outbound HTTPS carrying the stolen data.

## What the firewall should learn

Two signals stand out. First, the payload fetch-and-eval is already the shape of the builtin `process.eval.downloaded-string` rule — a downloaded string that gets executed needs approval. Second, the egress pattern: an extension-host process connecting to blockchain RPC endpoints or raw IP addresses, plus reads of credential stores followed by HTTPS egress, is not part of any editor task. Rule ideas: approval_required for `network_connect` to crypto RPC hosts from any process under the agent or extension host; deny when credential-store reads (`file_open` on keychain/cookie/credential paths) are followed in the same ancestry by a `network_connect` to an external host.

## Sources

- [Koi Security: GlassWorm — First Self-Propagating Worm Using Invisible Code Hits OpenVSX Marketplace](https://www.koi.ai/blog/glassworm-first-self-propagating-worm-using-invisible-code-hits-openvsx-marketplace)
- [Koi Security: GlassWorm Goes Mac — Fresh Infrastructure, New Tricks](https://www.koi.ai/blog/glassworm-goes-mac-fresh-infrastructure-new-tricks)
- [Dark Reading: GlassWorm Returns, Slices Back into VS Code Extensions](https://www.darkreading.com/cyberattacks-data-breaches/glassworm-returns-vs-code-extensions)
- [Eclipse Foundation: Open VSX Security Update (October 2025)](https://blogs.eclipse.org/post/mika%C3%ABl-barbero/open-vsx-security-update-october-2025)
