# Quick Start Guide

A short, practical guide to running the tool. For full details on detection logic and every flag, see the [README](README.md).

## What this tool does

It scans every repository in one or more GitHub organizations and adds a small `veracode.yml` file to repos where some Veracode scans do not apply. For example:

- A documentation repo gets SAST and SCA turned off (nothing to scan).
- An infrastructure repo with no code gets SAST turned off.
- A .NET Framework repo gets its build moved to a Windows runner.

Result: fewer failed scans and fewer blocked pull requests. Repos where every scan applies are left untouched.

By default, changes are proposed as **pull requests**, so nothing is merged without your review.

-----

## 1. Prerequisites

| Requirement | Details |
|---|---|
| Python 3.9 or newer | Check with `python3 --version`. No `pip install` needed. |
| GitHub CLI (`gh`) | Install from [cli.github.com](https://cli.github.com). Check with `gh --version`. |
| GitHub access | A token or `gh` login with access to your organization (see step 2). |
| Veracode GitHub Workflow Integration | Already set up in your org (the central `veracode` repo). |

-----

## 2. Authenticate to GitHub

Create a **classic Personal Access Token** with these scopes:

- `repo`
- `workflow`
- `read:org`
- `read:enterprise` (only if you use `--enterprise`)

If your orgs use SAML SSO, click **Configure SSO** on the token and authorize it for **each** org you want to process. Orgs the token is not authorized for are reported and skipped.

Then pick **one** of these options:

**Option A: environment variable**

```bash
# macOS / Linux
export GITHUB_TOKEN=ghp_your_token_here

# Windows PowerShell
$env:GITHUB_TOKEN="ghp_your_token_here"
```

**Option B: log in once with the GitHub CLI**

```bash
gh auth login
```

Verify it works:

```bash
gh auth status
```

> Note: if `GH_TOKEN` is set, it takes priority over `GITHUB_TOKEN`.

-----

## 3. Run it (3 steps)

Replace `my-org` with your GitHub organization name. To cover several orgs, use any of these in place of `--org my-org`:

| Target | Flag |
|---|---|
| A few orgs | `--org org-a org-b org-c` |
| A list in a file (one org per line) | `--orgs-file orgs.txt` |
| Every org in your enterprise | `--enterprise my-enterprise-slug` |
| Only some orgs of the enterprise | `--enterprise my-enterprise-slug --orgs-file pilot.txt` |

> On Windows, use `python` instead of `python3` if `python3` is not recognized.

### Step 1: Preview (no changes made)

```bash
python3 script.py --org my-org --dry-run --report audit.json
```

This only reads your repos. It produces:

- `dry_run_report.csv`: one row per repo, open it in Excel or Google Sheets to review
- `audit.json`: full details of every decision

Review the CSV. The `sast`, `sca`, and `iac` columns show which scans stay on (`True`) or get turned off (`False`), and the `*_reason` columns explain why.

### Step 2: Pilot on a few repos

```bash
python3 script.py --org my-org --include 'team-*'
```

This opens pull requests only for repos matching the pattern. Review and merge a few PRs to confirm the results look right.

### Step 3: Roll out to the whole org

```bash
python3 script.py --org my-org --report run1.json
```

This opens a pull request in each repo that needs a change.

-----

## 4. If the run stops partway

Large orgs can take a while. If the run is interrupted (Ctrl+C, network drop, laptop sleeps), resume it without redoing finished repos:

```bash
python3 script.py --org my-org --resume-from run1.json --report run2.json
```

-----

## Common options

| I want to... | Add this |
|---|---|
| Preview only, change nothing | `--dry-run` |
| Target specific repos | `--include 'api-*' 'web-*'` |
| Skip specific repos | `--exclude 'sandbox-*' 'archive-*'` |
| Commit directly instead of opening PRs | `--direct-commit` |
| Use a self-hosted Windows runner | `--windows-runner '[self-hosted, windows]'` |
| See detailed logs | `-v` |
| See every option | `--help` |

-----

## Good to know

- **Safe by default.** Default mode opens PRs; nothing is merged automatically.
- **Your own files are protected.** If a repo already has a hand-written `veracode.yml`, it is skipped (unless you pass `--force`).
- **Safe to re-run.** Repos already correct are skipped, and existing PRs are reused instead of duplicated.
- **The central `veracode` repo is always excluded** (`--central-repo NAME` if yours is named differently), and so is any repo that looks like a central integration repo.
- **Archived repos and forks are skipped** unless you add `--include-archived` or `--include-forks`.
- **Platform policy/sandbox scans are not affected.** Only pipeline scan triggers are changed.

-----

## Troubleshooting

| Error message | Fix |
|---|---|
| `gh CLI not available or not authenticated` | Install `gh`, then run `gh auth login` or set `GITHUB_TOKEN`. |
| `[my-org] cannot access org, skipping this org` | Check the org name spelling, token scopes (`repo`, `read:org`), and SSO authorization for that org. Other orgs still run. |
| `N enterprise org(s) are hidden from this token` | Authorize the token for SSO on those orgs, then re-run. |
| `Enterprise '...' is not readable with this token` | Check the enterprise slug and the `read:enterprise` scope. |
| Run is slow or pauses | Normal. The tool waits automatically to stay within GitHub rate limits. |
| Some repos show `failed` | Re-run with `--resume-from` to retry only those repos. |

-----

## Need help?

This tool is a companion to Veracode's GitHub Workflow Integration and is not officially supported by Veracode. When asking for help, share:

- The `--report` JSON file
- The exact command you ran
