# Vercel agent hallucinated a GitHub repo ID and deployed the third-party code to a customer project

- Date: 2026-03 | Agent/tool: coding agent running Claude Opus 4.6 in agent mode, Vercel deployment API | Axis: cloud

## What happened

A Vercel customer reported that code from an unknown GitHub repository had appeared in their team project. Vercel's CEO, Guillermo Rauch, investigated and published the cause: the customer's agent had invented, or hallucinated, a public repository ID and then used Vercel's API to deploy that repository. The deployment config showed `gitSource` with `type: github`, a numeric `repoId` the agent made up, and `ref: main`. The agent knew the correct project ID and project name, but instead of looking up the real repo it produced a plausible-looking numeric ID and shipped it. The outcome this time was harmless. It did not have to be: an agent with deploy rights can put unreviewed third-party code into production, poison a build, or expose secrets if the repo is hostile.

## How it went wrong

The agent had deploy-level access to the customer's project. When its task needed a source repository, it did not resolve one; it generated a numeric repo ID and passed it to the deployment API, which accepted it because the ID happened to point at a real public repository. There was no check that the repository belonged to the customer or had ever been seen before. At the OS level on a developer machine this is an exec of the deploy CLI (or a curl to the deployment endpoint) whose arguments carry the source reference, running under the agent's process tree, with the deploy token in its environment.

## What the firewall should learn

The exec observable shows a production deploy under agent ancestry: `vercel --prod`, `vercel deploy`, `netlify deploy --prod`, `serverless deploy`, `flyctl deploy`, `sam deploy`, `gcloud run deploy`, `wrangler deploy`. None of the builtin packs gate a serverless deploy today. Rule ideas: approval_required for any production-flagged deploy command under agent ancestry (decision: approval_required); and a stricter variant denies deploys whose source reference (repo ID, repo URL, ref) was not present earlier in the session, since the agent invented the one value it needed (decision: deny is too brittle here, so approval with a shown diff is the practical gate).

## Sources

- [Guillermo Rauch on X: "Turns out Opus 4.6 hallucinated a public repository ID and used our API to deploy it"](https://x.com/rauchg/status/2028920268119523788)
- [Oso: AI Agents Gone Rogue registry, "Agent shipped unverified third-party code without approval"](https://www.osohq.com/developers/ai-agents-gone-rogue)
