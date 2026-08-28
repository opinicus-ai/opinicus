# CastleRAT abused the trusted Deno developer runtime to run fileless malware

- Date: 2026-03 | Agent/tool: Deno JavaScript runtime (CastleRAT campaign, Windows) | Axis: evade

## What happened

ThreatDown reported in March 2026 the first documented malware campaign that abused the Deno JavaScript runtime to evade endpoint security. The attack started with ClickFix social engineering: a fake CAPTCHA page told the victim to paste a command into the Run dialog or a terminal. Instead of downloading malware, the command installed Deno, a legitimate, code-signed JavaScript runtime that developers use and antivirus tools trust. The obfuscated payload then ran inside the trusted Deno process. It fetched a portable Python environment renamed to look like a system component ("Petuhon") and an image file, `CFBAT.jpg`, that really held the encrypted final payload. A PyArmor-obfuscated Python script decoded the image in memory and reflectively loaded CastleRAT, a RAT with keylogging, clipboard theft, browser credential, crypto wallet and SSH key theft, and webcam access. No executable file ever touched the disk for the final payload.

## How it went wrong

Every stage hid from file-based checks. The installer used only legitimate, signed tools. Deno, being trusted and signed, ran the loader JavaScript without alarms; the malicious code inherited the trust of the runtime process. The final payload was encrypted inside a JPEG and assembled only in memory through reflective PE loading, so disk scanners saw a picture, not a program. The Python interpreter was renamed to a Windows-looking name to fool casual process review. Persistence came through a scheduled task pointing back at the obfuscated loader. ThreatDown's detection relied on behavior, not files: a Deno process doing in-memory injection is not something Deno ever does in normal development.

## What the firewall should learn

A trusted interpreter is the perfect proxy: everything it does looks like the interpreter, and one exec event can carry a whole attack inside its argv or a script file. The observable signals are the process chain and its arguments. Rule ideas: approval_required when an interpreter (deno, node, python, bun) is exec'd with flags that run code from strings, URLs, or eval-style arguments (`deno eval`, `deno run` of a remote URL, `python -c`) rather than a project file; approval_required when an interpreter execs with a program name that was recently renamed or installed during the same session; deny when an interpreter process performs file_open reads of image or data files followed by exec of an unmapped memory region (loader pattern) or when its exec exe path is not on disk in a standard location. The renamed interpreter ("Petuhon") is caught by comparing argv[0]/exe to known install locations.

## Sources

- [ThreatDown: CastleRAT attack first to abuse Deno JavaScript runtime to evade enterprise security](https://www.threatdown.com/blog/castlerat-cyber-attack-is-the-first-to-abuse-deno-javascript-runtime-to-evade-enterprise-security/)
- [Security Brief: Attackers abuse Deno runtime to deploy fileless malware](https://www.securitybrief.news/story/attackers-abuse-deno-runtime-to-deploy-fileless-malware)
