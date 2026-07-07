# Workflow App per Language Scan/Runner Scoping for GitHub

Provisions per-repository `veracode.yml` override files across a GitHub organization for the [Veracode GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning) . Detects each repo's languages, dependency manifests, and IaC artifacts, then disables the scan triggers that do not apply, so an IaC repo does not fail SAST, a docs repo does not fail SCA, and gating on scan results does not block PRs.

-----

## How It Works

For each repository the script:

1. Reads languages (GitHub Linguist API) and the full file tree via the GitHub CLI
1. Decides, per scan type, whether it is relevant:
   - **SAST** - language must be one the workflow integration's autopackager actually builds
   - **SCA** - ecosystem must be agent-supported *and* a resolvable manifest/lockfile must exist
   - **IaC/secrets** - Terraform, Dockerfiles, Helm/K8s manifests, and related artifacts
1. Writes a minimal `veracode.yml` at the repo root disabling only the irrelevant scans' `push`/`pull_request` triggers. Repos where all three scans are relevant get no file at all.
1. Opens a PR with the change (or commits directly with `--direct-commit`)

All operations are idempotent. If the generated file is byte-identical to what already exists in the repo (compared via git blob SHA, computed locally with no extra API call), the repo is skipped.

> **Scan trigger semantics.** The static `push`/`pull_request` triggers control **pipeline** scans only. Platform sandbox and policy scans are governed by `analysis_on_platform` and are never touched unless `--platform-analysis` is passed explicitly. SCA and IaC scans are fully controlled by their triggers, so disabling them here fully prevents those runs.

-----

## Detection Basis

**SAST policy: pipeline-first.** Static scans stay enabled for every Pipeline Scan supported language (.NET, Java, JS/TS, Kotlin, Python, Go, Ruby, Scala, PHP, Apex, ColdFusion, Apple platforms, C/C++, COBOL, Groovy, and the mobile/hybrid frameworks). The autopackager's supported list grows over time, so repos are deliberately not opted out based on what is autopackageable today. Only languages with no pipeline support at all (Perl, PL/SQL, T-SQL, Classic ASP, RPG, VB6, Dart - platform Upload and Scan only) disable static. If packaging failures do become PR-blocking for a specific ecosystem in your org, two empty config tiers (`SAST_PIPELINE_NOT_AUTOPACKAGED`, `SAST_COMPILED_ONLY`) let you move languages out per client via `--config`, with the reason recorded in the file header, PR body, and report.

**SCA policy.** Follows the integration table's SCA column: .NET, Go, Java, JavaScript/TypeScript, Kotlin, PHP, Python, Scala, always paired with a resolvable manifest/lockfile. Ruby, Android, and React Native have no SCA support in the integration (React Native repos still match via JavaScript).

**IaC/secrets policy: secrets-first.** The IaC/secrets scan is enabled by default for every repo, including those with no IaC artifacts. The scan does two things: it scans container and infrastructure manifests (Terraform, Dockerfiles, Helm/K8s, CloudFormation) when present, and it detects hardcoded secrets in all repo contents. Since secret detection is universally valuable and the scan rarely fails, repos are not opted out based on detected artifact presence. Pass `--no-iac` to disable it org-wide (rare). The presence of IaC artifacts is noted in the reasons logged and reported, but does not change the default on.

### Runner selection

The central default runner is `ubuntu-latest`. When a build-based scan (SAST or SCA) is enabled and the repo's build is Windows-bound, the override sets:

```yaml
default:
  runs_on: windows-latest
```

Detection is tiered to avoid both false positives (a MAUI app forced onto Windows) and false negatives (a Framework app left on Linux where msbuild is absent):

| Tier | Signals | Effect |
|---|---|---|
| Strong | `packages.config`, `Global.asax`, `*.aspx`/`*.ascx`/`*.asax`/`*.master`/`*.asmx` (WebForms), `*.vcxproj`/`*.vcproj` (MSVC) | Windows, directly. These artifacts have no portable counterpart. |
| Weak | `*.xaml`, `web.config`, `*.vbproj`, `*.fsproj` | Never force Windows alone. Each has a Linux-buildable counterpart (MAUI/Avalonia XAML, ASP.NET Core IIS configs, SDK-style VB/F#). They automatically trigger project-file inspection. |
| Project markers | Inside `.csproj`/`.vbproj`/`.fsproj` contents: `<TargetFrameworkVersion>`, `ToolsVersion`, the msbuild/2003 xmlns (old-style projects), `<UseWPF>`, `<UseWindowsForms>`, `net4x` and `*-windows` target frameworks | Windows when found. Inspection runs automatically for weak-signal repos (up to 5 files, shallowest first, 1 API call each). |

Plain `.cs`, `.csproj`, and `.sln` are deliberately not signals: SDK-style .NET builds on the default Linux runner. `--deep-dotnet` extends project-file inspection to every repo containing project files, catching the zero-surface-signal case of an SDK-style project targeting `net48` or `net8.0-windows`. `--runner off` disables the feature entirely. On truncated trees the runner reason is annotated as best-effort. All three signal tiers are `--config` keys (`WINDOWS_FILE_NAMES`, `WINDOWS_FILE_SUFFIXES`, `WINDOWS_WEAK_FILE_NAMES`, `WINDOWS_WEAK_FILE_SUFFIXES`, `WINDOWS_PROJECT_MARKERS`), so org-specific conventions can be added without code changes. The runner decision and its reasoning appear in the generated file header, the PR body, the per-repo log line, and the `--report` JSON.

-----

## Prerequisites

- `gh` CLI installed and authenticated (`gh auth login`) with `repo` and `read:org` scope
- Python 3.9+, standard library only, no pip install required

-----

## Modes

| Mode | Flag | Behavior |
|---|---|---|
| Dry-run | `--dry-run` | Read-only. Prints every decision and the generated YAML, changes nothing. |
| PR (default) | *(none)* | Opens a branch and PR per repo that needs an override. |
| Direct commit | `--direct-commit` | Commits straight to the default branch instead of opening a PR. |

-----

## Quickstart

```bash
gh auth login

# Phase 1 - see what would change, review before touching anything
python3 script.py --org my-org --dry-run --report audit.json

# Phase 2 - roll out via PR
python3 script.py --org my-org

# Phase 3 - pilot on a subset first if preferred
python3 script.py --org my-org --include 'team-*'
```

-----

## Command-Line Reference

### Scope

| Flag | Default | Description |
|---|---|---|
| `--org ORG` | *(required)* | GitHub organization |
| `--include PATTERN [...]` | `*` | Glob patterns of repos to include |
| `--exclude PATTERN [...]` | `veracode` | Glob patterns of repos to skip (central repo excluded by default) |
| `--include-archived` | off | Otherwise archived repos are skipped |
| `--include-forks` | off | Otherwise forks are skipped |

Empty and disabled repos are always skipped.

### Delivery

| Flag | Default | Description |
|---|---|---|
| `--dry-run` | off | Print decisions and YAML, write nothing |
| `--direct-commit` | off | Commit to the default branch instead of opening a PR |
| `--branch-name NAME` | `chore/veracode-scan-scoping` | Branch used for the PR flow |
| `--force` | off | Overwrite an existing `veracode.yml` whose content differs from the generated one |

### Detection Tuning

| Flag | Default | Description |
|---|---|---|
| `--no-iac` | off | Disable the IaC/secrets scan for all repos. By default IaC is enabled for secret detection even without IaC artifacts. |
| `--deep-iac` | off | Download a few ambiguous root YAML/JSON files and check for CloudFormation/Kubernetes markers before confirming IaC relevance (extra API calls) |
| `--runner {auto,off}` | `auto` | `auto` writes `default: runs_on: windows-latest` on confirmed Windows build signals when a build-based scan is enabled; weak signals auto-trigger project-file inspection; `off` never writes `runs_on` |
| `--deep-dotnet` | off | Extend project-file inspection to every repo with `.csproj`/`.vbproj`/`.fsproj`, catching SDK-style projects targeting `net4x` or `*-windows` TFMs with no surface signal (extra API calls, up to 5 per repo) |
| `--platform-analysis {true,false}` | unset | Also pin `analysis_on_platform` for SAST-relevant repos. Left untouched by default. |
| `--config FILE` | built-in | JSON file overriding any detection matrix (language lists, manifest names, IaC patterns) without editing the script |

### Rate Limiting

| Flag | Default | Description |
|---|---|---|
| `--min-interval SECONDS` | `0.25` | Minimum delay between GitHub API calls |
| `--min-remaining N` | `100` | Sleep until reset when the core rate limit budget drops below this |

The script checks `/rate_limit` every 50 calls, sleeps until reset when the budget runs low, and backs off exponentially with jitter on secondary rate limit responses. Roughly 2 API calls per repo (languages + recursive tree); existing `veracode.yml` presence and its SHA are read from the same tree call.

### Output

| Flag | Default | Description |
|---|---|---|
| `--report FILE` | none | Write a JSON audit report: per-repo languages, decisions, reasons, and whether an override was written |
| `-v`, `--verbose` | off | Debug-level logging, including the per-scan-type reasoning for every repo |

-----

## Overriding Detection Matrices

Pass `--config matrices.json` with any subset of these keys to override the defaults without touching the script:

```json
{
  "SAST_LANGUAGES": ["Java", "Python", "Go", "Kotlin", "Scala", "JavaScript", "TypeScript"],
  "SCA_MANIFEST_NAMES": ["pom.xml", "package.json", "requirements.txt"],
  "IAC_DIR_HINTS": ["terraform/", "infra/", "k8s/"]
}
```

Unknown keys are rejected at startup with the list of valid keys. Use this to, for example, enable SAST for PHP or .NET repos that run a custom scan workflow instead of the integration's autopackager.

-----

## Output

### Generated `veracode.yml`

Only the disabled sections are written; everything else inherits the central config. Each file carries a comment header with the detection reasoning:

```yaml
# Detection: SAST=True (languages=['C#'])
#            SCA=True (manifests=['packages.config'], ecosystems=['C#'])
#            IaC=True (no artifacts detected, kept enabled for secret scanning)
#            Runner=windows-latest (windows signals=['global.asax', 'packages.config'])

default:
  runs_on: windows-latest
```

And a docs-only repo example (override needed only for SAST and SCA, IaC is on by default):

```yaml
# Detection: SAST=False (no supported language)
#            SCA=False (no supported manifest/ecosystem pair)
#            IaC=True (no artifacts detected, kept enabled for secret scanning)
#            Runner=default (portable ecosystem, central default (linux))

veracode_static_scan:
  push:
    trigger: false
  pull_request:
    trigger: false

veracode_sca_scan:
  push:
    trigger: false
  pull_request:
    trigger: false
```

### Summary

Printed at the end of every run:

```
========== SUMMARY ==========
Scoped (override written/PR): 41
No change needed: 12
Already correct (identical file): 3
Skipped: 6
Failed: 0
Total GitHub API calls: 187
```

### `--report` JSON

```json
{
  "org": "my-org",
  "generated": "2026-07-07T00:00:00Z",
  "api_calls": 187,
  "repos": [
    {
      "repo": "payments-api",
      "default_branch": "main",
      "languages": {"Java": 128000},
      "tree_truncated": false,
      "decision": {
        "sast": true, "sca": true, "iac": false,
        "reasons": {"sast": "languages=['Java']", "sca": "manifests=['pom.xml'], ecosystems=['Java']", "iac": "no IaC/container artifacts"}
      },
      "override_written": false
    }
  ]
}
```

-----

## Large Repos and Truncated Trees

GitHub's recursive tree API truncates on very large repos. When this happens the script merges in a guaranteed non-recursive root listing (manifests and most IaC entry points live at root) and defaults SAST/SCA/IaC to **enabled** rather than guessing them off, since a false negative here silently disables a scan while a false positive only costs one avoidable pipeline run.

-----

## Security Notes

- Uses the `gh` CLI's own authenticated session; no credentials are read, stored, or logged by the script
- Default mode opens a PR for review; no repo is changed without either explicit review or `--direct-commit`
- One repo failing never halts an org-wide run; failures are collected and reported at the end
- Existing open PRs on the scoping branch are detected and reused instead of duplicated

-----

## Support

This is a companion tool to Veracode's GitHub Workflow Integration and is not officially supported by Veracode. For issues, provide the `--report` JSON output, the `--org` used, and the command run.
