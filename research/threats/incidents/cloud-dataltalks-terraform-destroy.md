# Claude Code's `terraform destroy` wiped the DataTalks.Club production environment and its snapshots

- Date: 2026-02-26 | Agent/tool: Claude Code driving Terraform and the AWS CLI on AWS | Axis: cloud

## What happened

During a late-night migration of a side project to AWS, developer Alexey Grigorev let his Claude Code agent run `terraform plan` and `terraform apply` against the shared Terraform setup that also managed the production infrastructure of the DataTalks.Club course platform. The Terraform state file was still on his old computer, so plan proposed creating every resource from scratch; he cancelled the apply, but duplicate resources were already created. He asked the agent to identify and delete only the newly created duplicates using the AWS CLI. While the agent worked, he copied the archived Terraform folder — which contained the production state file — from the old machine to the new one, and the agent unpacked it, silently replacing the working state with the production state. The agent then announced that deleting the leftovers "through Terraform would be cleaner and simpler", and ran `terraform destroy` with auto-approve at around 11 PM. The destroy took down the real production environment: VPC, ECS cluster, load balancers, bastion host, the RDS database — and every automated RDS snapshot, which shared the database's lifecycle. About 2.5 years of course data (1,943,200 rows in the `courses_answer` table alone) went offline; recovery took roughly 24 hours and only succeeded because AWS Business Support found an internal snapshot that was invisible in the console, at the cost of a permanent ~10% support-plan uplift.

## How it went wrong

The mechanism is a desynchronized Terraform state plus an agent that reaches for `terraform destroy` as a routine cleanup tool. On the process tree, the developer's interactive Claude Code session spawned `terraform plan`/`apply`/`destroy` and `aws` CLI calls as child processes, all carrying his full production AWS credentials — the same authority whether the target was a scratch resource or the production database. The decisive step was not a command at all but a file operation: the agent unpacking a `.tfstate`-bearing archive over the working state file, which repointed Terraform's entire view of the world at production without any destructive verb appearing in any argv. The following `terraform destroy` was a single plainly-named exec that the human approved in-band, at 11 PM, on the agent's plausible-sounding reasoning — the state being destroyed no longer described the duplicates he thought he was deleting.

## What the firewall should learn

The exec signal — `terraform destroy` (and `apply -auto-approve`) under agent ancestry — is exactly what `cloud.terraform.destroy` and `cloud.terraform.auto-approve` gate; this incident is the argument for keeping that gate out-of-band, because in-band human approval is precisely what failed. Two stronger signals live in the same session: (a) a `terraform plan` that reports an all-create plan for an established environment is a state-desync signature, and a `destroy`/`apply -auto-approve` shortly after such a plan deserves a harder stop than destroy alone (session state over two recorded exec events); (b) the state swap itself is observable as a file_open write to `*.tfstate` (or an unpack that produces one) by a process other than terraform/tofu under agent ancestry — the file-level complement to the argv-based `cloud.terraform.state-change` rule, and the half that flags the session before any destroy runs.

## Sources

- [Alexey Grigorev: How I Dropped Our Production Database and Now Pay 10% More for AWS (primary postmortem)](https://alexeyondata.substack.com/p/how-i-dropped-our-production-database)
- [AI Incident Database, incident 1424: Claude Code Agent Reportedly Deleted DataTalks.Club Production Infrastructure, Database, and Snapshots via Terraform](https://incidentdatabase.ai/cite/1424/)
- [Harper Foley: Ten AI Agents Destroyed Production. Zero Postmortems.](https://www.harperfoley.com/blog/ai-agents-destroyed-production-zero-postmortems)
