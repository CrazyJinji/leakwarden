# LeakWarden

Find leaked API keys, tokens and passwords in your code and in your git history before you deploy. One Python file, standard library only, runs on your machine.

It is built for projects made with Claude Code, Cursor and Lovable, where a key often lands in a commit before anyone notices. Deleting the key from the file does not help if it is still in an old commit, so LeakWarden reads the history too.

This is the free edition, MIT licensed. [LeakWarden Pro](https://leakwarden.dev) adds checks for mistakes that are specific to AI-built apps (see the end of this page).

## Run it

```
curl -O https://leakwarden.dev/download/leakwarden.py
python3 leakwarden.py /path/to/your/project
```

You need Python 3.8 or newer. The history scan needs `git`. The SHA-256 of the current file is on [leakwarden.dev](https://leakwarden.dev#free) if you want to check the download.

## What it finds

- API keys and tokens: OpenAI, Anthropic, OpenRouter, Stripe, GitHub, Slack, SendGrid, AWS, Google, Polar, Supabase secret and `service_role` keys, private key blocks.
- Hard-coded passwords and secret-looking values, and database URLs with a password in them.
- Keys that were committed and later deleted. It reads the added lines of the last 500 commits by default.
- `.env` files that are tracked by git, or present and not covered by `.gitignore`. A committed `.env` that only holds browser-public values (`VITE_SUPABASE_URL`, `..._ANON_KEY`) is reported as low.

Keys that are public by design, such as the Supabase anon key and Stripe publishable keys, are not reported.

## Example

```
leakwarden 0.2.0 (free edition)  ./my-app

Coverage
  - secrets (working tree): checked 12 text files
  - secrets (git history): checked 2 commit(s) (limit 500), added lines only
  ...

Findings: 4 high, 1 medium, 0 low, 0 info

[HIGH] Stripe live secret key  (secret.stripe_live)
    .env:1
    > STRIPE_SECRET_KEY=[REDACTED:redacted]
    Fix: Rotate this credential now, then load it from an environment variable or a secret manager.

[HIGH] GitHub token (in git history)  (secret.github)  [history 4b9b722b]
    config.js:1
    > export const githubToken = '[REDACTED:redacted]'
    Fix: Rotate this credential now. Rewriting history (git filter-repo) only helps after the key is rotated.

...
```

The report also lists the areas it did not check, so a quiet report is not mistaken for a safe one.

## Options

```
--format text|json|markdown   report format (default: text)
--output FILE                 write the report to a file
--min-severity LEVEL          hide findings below info, low, medium or high (default: low)
--fail-on LEVEL               exit with status 1 at or above this level, or never (default: high)
--no-history                  skip the git history scan
--max-commits N               how many commits to read (default: 500)
--history-range BASE..HEAD    read only these commits, for example in CI on a pull request
```

Exit status is 0 when nothing reaches `--fail-on`, 1 when something does, and 2 on a usage error.

## Ignoring a finding

Put `leakwarden:ignore` anywhere on a line to skip it, in the working tree and in history.

Or add a `.leakwardenignore` file at the project root. One entry per line: a path glob, a rule filter, or both.

```
examples/*
rule:secret.stripe_test
rule:secret.generic src/fixtures/*
```

## What it does not do

- It never prints a secret value. Every report format redacts them.
- It does not run the project's code, and it runs `git` with hooks and fsmonitor turned off, so it is safe to point at a repository you do not trust.
- It makes no network requests.

It is a heuristic scanner. A clean report does not prove a project is secure, and it will miss secrets in formats it has no rule for. It does not check dependencies for known vulnerabilities.

## LeakWarden Pro

Pro adds the checks that matter for apps built with AI coding tools:

- Supabase row level security in your migrations: tables without RLS, policies that allow everything, views that bypass RLS
- Webhook handlers with no signature check, prices taken from the client, paywalls decided in the browser
- Secret keys exposed to the browser through `NEXT_PUBLIC_` or `VITE_` variables, and the service role key in client code
- CORS, Django settings, committed databases and risky code (`eval`, raw HTML, SQL built from strings)
- A Claude Code skill that reads the report and helps you fix each finding
- A GitHub Actions workflow that checks every pull request and annotates the lines

$29 one-time at [leakwarden.dev](https://leakwarden.dev).

## License

MIT, see [LICENSE](LICENSE).
