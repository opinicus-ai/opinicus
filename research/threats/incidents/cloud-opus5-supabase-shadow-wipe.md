# Opus 5 pointed Prisma's `--shadow-database-url` at production and wiped the Supabase database

- Date: late July 2026 | Agent/tool: Claude Code (Claude Opus 5, "ultracode" mode) running Prisma against Supabase | Axis: cloud

## What happened

A developer connected Claude Code, running Anthropic's then-new Opus 5 model in the agent's broad-autonomy "ultracode" mode, to the live Supabase database of a personal project and asked it to analyze the repository and autonomously fix schema and content issues. Roughly ten minutes into the run, the agent executed `prisma migrate diff --shadow-database-url=$DATABASE_URL_UNPOOLED`. The unpooled variable holds Supabase's direct connection string — the one Supabase's own documentation recommends for migrations — and it pointed at the production database. Prisma's shadow-database semantics say the tool resets whatever database that flag points at, then replays the local migration history into the empty target; it did exactly that. All 22 tables were wiped: 130 tool records, 21 comparisons, users, reviews, likes. Because the repository's `prisma/migrations` folder was stale, the `BlogPost` and `ApiKey` tables had no migration file, so they were dropped and never recreated. The agent caught the damage itself and reported it unprompted — "The database has been wiped. This is my fault and I need to tell you immediately" — and the developer restored everything within hours through a DIY mix of backups and page recovery. The reset-destroys-the-shadow behavior is documented Prisma behavior with an open GitHub issue about exactly this footgun since 2023.

## How it went wrong

The command line contains no destructive token: `migrate diff` reads as a read-only comparison and "shadow database" reads as a disposable scratch target. The destruction lives in the flag's documented side effect — Prisma drops everything at the `--shadow-database-url` address before replaying migrations — and the address came from the environment, where the direct production credential happened to sit next to the agent. On the process tree this is one hop: the Claude Code session spawned the `prisma` process with the developer's full shell environment, so the same env that made the wipe possible also supplied its target. Two failures stacked: the agent held production credentials with write autonomy, and a routine migration command carried a hidden reset aimed at a URL chosen from that environment. Neither a `DROP` statement nor a reset subcommand ever appeared in argv, so the command looks benign to any check that scans for destructive vocabulary.

## What the firewall should learn

The observable is exec + env, and the signal is a conjunction: exec(prisma/npx) under agent ancestry with argv carrying `--shadow-database-url` (or the `migrate diff`/`migrate dev` pair) joined with the URL or host that flag's value — or its source variable's value — resolving to a production-shaped target or to the same host as the application's `DATABASE_URL`. The flag family extends beyond Prisma: `pg_restore --clean` and `mongorestore --drop` are the same shape, documented drop-before-build semantics that no SQL keyword ever exposes (native dump formats carry no SQL text at all, so input capture cannot see them either). A rule that gates "reset-side-effect flags whose target looks production-grade" would have stopped this incident at the argv, one approval prompt ahead of the wipe — catalog scenario cloud-22.

## Sources

- [Reddit r/Anthropic: "and just like that Opus 5 ultracode wipes the entire database" (primary report by the developer)](https://www.reddit.com/r/Anthropic/comments/1v9iurd/and_just_like_that_opus_5_ultracode_wipes_the/)
- [Tokenstead: What went wrong — Opus 5 ultracode wiped a production database (postmortem)](https://tokenstead.ai/guides/opus-5-ultracode-database-wipe-postmortem)
- [IT-Connect: Claude Opus 5 Wipes a Production Database — and It Wasn't Its Fault](https://www.it-connect.tech/claude-opus-5-wipes-a-production-database-and-it-wasnt-its-fault/)
- [Adversa AI: Nine AI coding agent incidents that ended with deleted data (roundup, incident 9)](https://adversa.ai/blog/ai-coding-agent-incidents/)
