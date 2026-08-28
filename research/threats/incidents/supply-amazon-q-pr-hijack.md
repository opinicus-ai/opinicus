# Amazon Q Developer extension poisoned via a crafted pull request and an over-scoped CI token

- Date: 2025-07-23 | Agent/tool: Amazon Q Developer for VS Code extension v1.84.0, CodeBuild CI | Axis: supply

## What happened

In July 2025 AWS disclosed (security bulletin AWS-2025-015, published July 23, CVE-2025-8217) that version 1.84.0 of the Amazon Q Developer VS Code extension shipped with attacker-committed code. During the investigation of a related CodeBuild incident (AWS-2025-016), AWS found the extension's CodeBuild configuration carried an inappropriately scoped GitHub token; a threat actor obtained repository credentials (reported to have been extracted via a memory dump in the build environment) and used them to commit malicious code into the extension's open-source repository — press coverage describes the payload arriving through a pull request from an account with no prior access — where the build pipeline automatically swept it into the 1.84.0 release. The embedded code was a hijack prompt aimed at the Q agent itself, instructing it to "clean" the developer's system to a near-factory state: delete files, erase configurations, and strip AWS resources including logs. The attack failed only because the payload contained a syntax error and never executed. AWS revoked the credentials, removed the code, pulled 1.84.0 from distribution and shipped 1.85.0, and added CodeBuild hardening such as unprivileged build modes that block memory dumps.

## How it went wrong

The chain abused the trust gradient that agentic tools create. The developer machine trusted the extension because the marketplace release pipeline produced it; the release pipeline trusted the repository; and the repository's CI held a GitHub token broad enough to let an outside contribution reach a release without a human ever reading the diff. The payload itself never ran as malware in the classic sense — it was instructions, waiting for the AI agent on ~a million installed machines to read them and act with its full tool permissions (AWS CLI, file operations). In other words, the deliverable was not a binary exploit but a prompt: the attack surface was the agent's own obedience. A single syntax error — pure luck, not a control — stood between the incident and mass simultaneous deletion of local and cloud resources.

## What the firewall should learn

The developer-side lesson is that a coding agent's inputs arrive from its tools' supply chain too, and the destructive instructions were sitting in plain files on disk waiting to be read. Observable signals and rule ideas: (1) the destructive payload, once an agent acts on it, becomes classic agent behavior — mass `file_open` deletes outside the work tree, `aws` resource-deletion commands, log wiping — which the filesystem and cloud packs already gate; the supply-specific addition is gating *file writes into the tool's own installation/repo directory* from an agent session (an agent or its descendants editing the extension's source or `.github`/CI config should be `approval_required`); (2) build-pipeline hygiene is upstream of the monitor, but the monitor can catch the local half of the same shape: exec ancestry rooted at a build tool (CodeBuild-equivalents: make, npm run build, cargo build) reaching for credential stores or `git push` to the tool's own repo; (3) `terminate`-grade escalation when deletion commands and cloud-destroy commands fire in the same session window — the near-factory-reset signature that this incident would have produced. The uncomfortable takeaway: had the syntax error not intervened, the incident would have looked exactly like the filesystem/catalog destructive-agent scenarios, just at fleet scale.

## Sources

- [AWS Security Bulletin AWS-2025-015: Security Update for Amazon Q Developer Extension for VS Code (Version #1.84)](https://aws.amazon.com/security/security-bulletins/AWS-2025-015/)
- [ReversingLabs: How AWS averted an AI supply chain disaster](https://www.reversinglabs.com/blog/aws-amazonq-ai-incident)
- [GitHub advisory GHSA-7g7f-ff96-5gcw (aws-toolkit-vscode)](https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw)
