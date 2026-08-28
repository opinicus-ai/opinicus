# GitHub's Copilot client retry loop amplified a capacity outage tenfold and held recovery open

- Date: 2026-08-17 | Agent/tool: GitHub Copilot client (VS Code extension) token-request retry loop | Axis: behavior

## What happened

GitHub's worst outage of the year began on August 17, 2026, when a
capacity component in the Central US data center failed to scale with a
traffic peak; authentication pressure spread into github.com, Actions,
APIs, pull requests, issues and Copilot. The outage ran 7 hours and 47
minutes with roughly 20% error rates on web and API traffic. The
amplifier that kept recovery from closing was not the original
saturation: GitHub's CTO writes that "errors in those services triggered
a client-side retry loop that increased traffic during recovery", and
that GitHub "had to mitigate that behavior before we could safely
restore traffic". Per GitHub's follow-up status reporting, the loop was
the Copilot client re-requesting authentication tokens without pausing
when the token service was slow or failing; traffic to the Copilot Token
Service rose from a normal 7,000–9,000 requests per second to
70,000–100,000, about a tenfold amplification. GitHub's escape was to
cut gateway retries in a code change and block inbound Copilot token
requests with 403s — it had to refuse its own AI assistant's traffic to
get the platform back.

## How it went wrong

Every client had a per-request retry limit and none had a per-client
retry budget: each of the fleet of Copilot clients independently decided
that a slow or failing token response deserved another request,
immediately and without backoff. Human developers retry a few times and
give up; the client population had silently changed from people to
loops, and the platform's capacity assumptions did not survive the
change. The failing component was an AI coding assistant's own client
process — the same class of process a local monitor supervises —
re-issuing network requests in a tight loop against an exhausted
service, turning a brownout into a platform-wide outage.

## What the firewall should learn

A retry storm is a rate, not a command, and it is visible from the
outside: the monitor sees every connect attempt even when the payload is
opaque TLS. Rule: per session root, a network_connect rate toward a
single API host that grows far above the session's baseline — or a
sustained connect rate above a threshold with the same
program+argv signature re-executing — is a retry storm in progress;
escalate approval_required → terminate, because every additional second
extends the damage. Count per session root, not per process: the storm
may be spread across many client processes of one tree, as it was across
every Copilot install. This is the fleet-scale sibling of the Claude
Code 429 storm, and the first documented case of a retry loop
prolonging the outage of the very service it was retrying into.

## Sources

- [GitHub (CTO Vlad Fedorov): The August 17 outage and the work ahead](https://github.blog/news-insights/company-news/the-august-17-outage-and-the-work-ahead/)
- [GitHub status: August 17 incident root cause analysis](https://www.githubstatus.com/incidents/zkxwbgr0cnmx)
- [BERI: Copilot Retried Into GitHub's Outage. Cap Your Agents.](https://www.beri.net/article/github-august-17-outage-copilot-retry-loop-agent-retry-budgets)
