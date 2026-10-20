# Workflow App per Language Scan/Runner Scoping for GitHub

> **Start with the [Quick Start Guide](QUICKSTART.md)** for prerequisites and the commands you need, in a few minutes.

Provisions per-repository `veracode.yml` override files across one or more GitHub organizations (an explicit list, a file, or every org in an enterprise) for the [Veracode GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning). Detects each repo's languages, dependency manifests, and IaC artifacts, then disables the scan triggers that do not apply, so an IaC repo does not fail SAST, a docs repo does not fail SCA, and gating on scan results does not block PRs.

-----

## How It Works

For each repository the script:

1. Reads languages (GitHub Linguist API) and the full file tree via the GitHub CLI
2. Decides, per scan type, whether it is relevant:
   - **SAST** - language must be one the integration can package and scan in a pipeline
   - **SCA** - a resolvable manifest/lockfile from an integration-supported ecosystem must exist
   - **IaC/secrets** - on everywhere by default for secret detection (configurable)
3. Writes a minimal `veracode.yml` at the repo root disabling only the irrelevant scans' `push`/`pull_request`/`issues` triggers, plus a Windows build runner when the build is Windows-bound. Repos where all three scans are relevant get no file at all.
4. Opens a PR with the change (or commits directly with `--direct-commit`)

**Managed files.** Every generated file starts with `# managed-by: veracode-scan-scoping`. The tool owns those files (and files from earlier versions that start with `# Detection:`): it updates them when a decision changes and removes them, via PR, once every scan type is relevant again (for example a docs repo that gained code). Hand-written `veracode.yml` files are never modified unless `--force` is passed, and are left alone entirely when no override is needed.

**Idempotent.** A repo is skipped when its existing file already has the same settings. Settings are compared with comments stripped, so a changed reason in the header (a new file in a list, a truncation note) never causes churn or a PR on its own. Open scoping PRs are reused, a scoping PR the repo owners closed is not reopened on every run, and an open scoping PR that a fresh scan no longer justifies is closed.

> **Scan trigger semantics.** The static `push`/`pull_request` triggers control **pipeline** scans only. Platform sandbox and policy scans are governed by `analysis_on_platform` and are independent of these triggers; they are never touched unless `--platform-analysis` is passed explicitly. SCA and IaC scans are fully controlled by their triggers, so disabling them here fully prevents those runs.

-----

## Detection Basis

**SAST policy: pipeline-first, build-aware.** Static scans stay enabled for every Pipeline Scan supported language the integration can actually package: .NET, Java, JS/TS, Kotlin, Python, Go, Ruby, Scala, PHP, Apex, ColdFusion, Groovy, and C/C++ with a build system. Languages with no pipeline support at all (Perl, PL/SQL, T-SQL, Classic ASP, RPG, VB6, Dart) disable static. Three languages Pipeline Scan supports are disabled by default because the integration's own build cannot produce an artifact for them, each recorded with its reason in the file header, PR body, and report:

| Tier | Languages | Why |
|---|---|---|
| `SAST_PIPELINE_NOT_AUTOPACKAGED` | COBOL | The integration's pipeline build runs `veracode package ... --skip-packagers sql,cobol` and its upload step fails when no artifact is produced |
| `SAST_NO_SUPPORTED_RUNNER` | Swift, Objective-C | Apple packaging requires Xcode (macOS); the integration's build has Linux and Windows jobs only |
| `SAST_COMPILED_ONLY` | *(empty)* | Available for org-specific use |

C and C++ count only with a build system present (`SAST_BUILD_EVIDENCE`: Makefile, CMakeLists.txt, meson.build, build.ninja, configure(.ac), SConstruct, `.vcxproj`, `.mk`, `.bb`), since C/C++ autopackaging needs make/ninja/bitbake and a successful compile. Truncated trees fail open. Move languages between tiers with `--config` (`"+SAST_COMPILED_ONLY": ["Kotlin"]` is enough; a tier always wins over `SAST_LANGUAGES`).

**SCA policy: supported manifest required.** SCA is enabled when at least one manifest from an ecosystem in the integration's SCA column (.NET, Go, Java/Kotlin/Scala, JavaScript/TypeScript, PHP, Python) exists. The ecosystem is taken from the manifest itself, so a notebook repo with `requirements.txt` (Linguist reports "Jupyter Notebook", not Python) is scanned, and a stray `pom.xml` in a Python repo is still scanned fail-open with an "unpaired" note. Three kinds of files are detected and reported but never enable SCA on their own, because the agent would fail with "no build system found" and, with `break_build_on_error`, block the PR:

- **Unsupported ecosystems:** `Gemfile`, `Podfile`, `Makefile` (Ruby, CocoaPods, and Make have no SCA support in the integration)
- **Supporting files:** `global.json`, `Directory.Build.props`, `Directory.Packages.props`, `gradlew`, `mvnw`, `libs.versions.toml`, `setup.cfg`, `pnpm-workspace.yaml`, `go.work.sum`, `.sln`
- **Tool wrappers:** `gradle-wrapper.jar`, `maven-wrapper.jar` are not dependency evidence

Manifest detection is otherwise comprehensive: standard lockfiles, Gradle catalogs, .NET central package management, `requirements*.txt` variants, `.sbt` files, and vendored `.jar`/`.dll` hash scanning. To scan an ecosystem outside the integration (e.g. Ruby with your own agent run), add a group to `SCA_ECOSYSTEM_MAP` and its language to `SCA_LANGUAGES`.

**IaC/secrets policy: secrets-first.** `--iac always` (default) keeps the IaC/secrets scan on for every repo: it scans container and infrastructure manifests (Terraform, Dockerfiles, Helm/K8s, CloudFormation) when present and detects hardcoded secrets in all repo contents. `--iac artifacts` disables it where no IaC/container artifacts are found (fail-open on truncated trees; `--deep-iac` confirms ambiguous root YAML/JSON by content). `--iac off` disables it org-wide (`--no-iac` is kept as an alias).

### Runner selection

The central default runner is `ubuntu-latest`. When a build-based scan (SAST or SCA) is enabled and the repo's build is Windows-bound, the override moves **only the build** of the enabled scans to Windows, using the documented per-scan key:

```yaml
actions:
  veracode_static_scan:
    build:
      runs_on: windows-latest
  veracode_sca_scan:
    build:
      runs_on: windows-latest
```

`--runner-scope all` writes `default: runs_on` instead. In the integration's workflows that moves every job (check run, cleanup, IaC/secrets, SCA) onto the Windows runner, which costs more minutes. `--windows-runner LABEL` sets the label for self-hosted runners, e.g. `--windows-runner '[self-hosted, windows]'` (validated before it is written).

Detection is tiered to avoid both false positives (a MAUI app forced onto Windows) and false negatives (a Framework app left on Linux where msbuild is absent):

| Tier | Signals | Effect |
|---|---|---|
| Strong | `packages.config`, `Global.asax`, `*.aspx`/`*.ascx`/`*.asax`/`*.master`/`*.asmx` (WebForms), `*.vcxproj`/`*.vcproj` (MSVC), `.sqlproj`, `.wixproj` | Windows, when the repo also shows .NET/C++ evidence. These artifacts have no portable counterpart. |
| Weak | `*.xaml`, `web.config`, `app.config`, `*.vbproj`, `*.fsproj` | Never force Windows alone. Each has a Linux-buildable counterpart (MAUI/Avalonia XAML, ASP.NET Core IIS configs, SDK-style VB/F#). They automatically trigger project-file inspection. |
| Project markers | Inside `.csproj`/`.vbproj`/`.fsproj` contents: `<TargetFrameworkVersion>`, `ToolsVersion`, the msbuild/2003 xmlns (old-style projects), `<UseWPF>`, `<UseWindowsForms>`, `net4x` and `*-windows` target frameworks | Windows when found. Inspection runs automatically for weak-signal repos (up to `--max-project-files`, nearest to the weak signal first, 1 API call each). |

Plain `.cs`, `.csproj`, and `.sln` are deliberately not signals: SDK-style .NET builds on the default Linux runner. `--deep-dotnet` extends project-file inspection to every repo containing project files, catching the zero-surface-signal case of an SDK-style project targeting `net48` or `net8.0-windows`. `--runner off` disables the feature entirely. On truncated trees the runner reason is annotated as best-effort. All signal tiers are `--config` keys, so org-specific conventions can be added without code changes.

-----

## Detection Robustness

Every safeguard below is active by default and tunable via `--config`.

**Vendored and generated content is invisible to detection.** Committed `node_modules/`, `vendor/`, `bower_components/`, build output (`dist/`, `build/`, `target/`, `bin/`, `obj/`, `out/`), virtualenvs, `Pods/`, `.terraform/`, coverage output, minified bundles (`*.min.js`, `*.bundle.js`), and generated sources (`*.pb.go`, `*_pb2.py`, `*.designer.cs`) are excluded from language, manifest, IaC, and Windows-signal scanning (`VENDORED_PATH_SEGMENTS`, `GENERATED_FILE_SUFFIXES`). `packages/` is deliberately not excluded (legitimate JS monorepo layout), and Go repos with `vendor/` are still fully detected via their root `go.mod`.

**Build-tool configs do not classify a repo, including in Linguist data.** Linguist counts `webpack.config.js`, `tailwind.config.js`, `jest.config.ts` and the rest of the tooling zoo as real code. Their tree sizes are subtracted from the Linguist byte counts, and a language whose only files are tooling configs is dropped, so a docs or Python repo with frontend tooling is not a JavaScript project. If a real `package.json` exists, SCA still triggers, correctly.

**Framework scaffolding does not classify a repo.** When `pubspec.yaml` is at the root, the generated platform runners under `android/`, `ios/`, `linux/`, `macos/`, `windows/`, `web/` are excluded from classification, manifest detection, and Windows signals (`FRAMEWORK_PLATFORM_DIRS`). A `flutter create` app otherwise shows ~20 KB of C++, Swift, Kotlin, and a Gradle build that needs the Flutter SDK.

**Linguist aliases are folded.** `TSX`, `Objective-C++`, `ColdFusion CFC`, and `Java Server Pages` count as TypeScript, Objective-C, ColdFusion, and Java (`LANGUAGE_ALIASES`).

**Ambiguous extensions require corroboration.** `.m` only counts with Apple project evidence; `.cls`/`.trigger` only count with Salesforce evidence; a lone `.h` is not a C project. The Linguist API disambiguates these itself; corroboration applies to the extension fallback.

**Trivial stubs do not enable scans.** Languages below `MIN_LANGUAGE_BYTES` (default 200) are ignored for scan enablement. The union of the Linguist API and the extension fallback still catches repos where the API returns nothing or lags behind pushes. Language data is fetched ordered by size, so the dominant language is never cut off.

**Structural resilience.** Default-branch trees are fetched via `HEAD`, immune to branch names with slashes or unicode. A tree that cannot be read (HTTP 404) fails the repo instead of being treated as "no files". Truncated trees on huge repos merge in a non-recursive root listing and keep scans enabled rather than guessing them off. Submodule-only repos get the explanation recorded in the SAST reason. Repos that are empty, archived, disabled, or forks are filtered before any API spend.

**Fail-open philosophy.** Every ambiguity resolves toward keeping a scan enabled: SAST stays on for packageable languages, IaC/secrets is on everywhere by default, and truncated trees never disable anything. The overrides this tool writes only remove scans that would fail or scan nothing, never scans that might work.

-----

## Prerequisites

- `gh` CLI installed and on `PATH` (the script shells out to it for every GitHub API call)
- An authenticated `gh`: `GH_TOKEN`, then `GITHUB_TOKEN`, then stored `gh auth login` credentials, in `gh`'s own order of precedence (`GH_HOST` / `GH_ENTERPRISE_TOKEN` for GitHub Enterprise Server). The script logs which source is in use and checks access to each org before processing it. One token serves every org in the run, so it needs access to all of them (same account model as the bulk enterprise integration script).
- Python 3.9+, standard library only, no pip install required

### GitHub Personal Access Token Setup

Create a classic Personal Access Token (PAT) with the following scopes:

| Scope | Purpose |
|---|---|
| `repo` | Full control of private repositories (needed for reading repo contents and creating/updating files) |
| `workflow` | Update GitHub Actions workflows (required by the integration scope) |
| `read:org` | Read organization data (needed for listing repos and reading org settings) |
| `read:enterprise` | Only with `--enterprise`: list every org in the enterprise |

For SAML SSO organizations, authorize the token for **every** target org. With `--enterprise`, orgs the token is not SSO-authorized for are hidden by GitHub; the script warns with the count and does not process them. An org that cannot be read is recorded in the report and skipped; the other orgs continue. Then either:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
python3 script.py --org my-org --dry-run
```

or use `gh auth login` once and run the script with no token variable set. If `GH_TOKEN` is set it takes precedence over `GITHUB_TOKEN`.

-----

## Modes

| Mode | Flag | Behavior |
|---|---|---|
| Dry-run | `--dry-run` | Read-only. Prints every decision and the generated YAML, changes nothing. |
| PR (default) | *(none)* | Opens a branch and PR per repo that needs an override, update, or removal. |
| Direct commit | `--direct-commit` | Commits straight to the default branch instead of opening a PR. |

-----

## Quickstart

```bash
# Phase 1 - see what would change, review before touching anything
python3 script.py --org my-org --dry-run --report audit.json

# Several orgs, a file of orgs, or a whole enterprise
python3 script.py --org org-a org-b org-c --dry-run --report audit.json
python3 script.py --orgs-file orgs.txt --dry-run --report audit.json
python3 script.py --enterprise my-ent --dry-run --report audit.json
python3 script.py --enterprise my-ent --orgs-file pilot.txt   # only these enterprise orgs

# Phase 2 - pilot on a subset (include at least one Windows-bound .NET repo)
python3 script.py --org my-org --include 'team-*'

# Phase 3 - roll out via PR
python3 script.py --org my-org --report run1.json

# Resume after an interruption; reports stay cumulative across resumes
python3 script.py --org my-org --resume-from run1.json --report run2.json
```

-----

## Command-Line Reference

### Scope

| Flag | Default | Description |
|---|---|---|
| `--org ORG [ORG ...]` | none | One or more GitHub organizations |
| `--orgs-file FILE` | none | One org login per line, `#` comments allowed. Combined with `--org`. Same format as the bulk enterprise integration script. |
| `--enterprise SLUG` | none | Every org in this Enterprise Cloud enterprise (GraphQL, needs `read:enterprise`). Combined with `--org`/`--orgs-file`, only the listed orgs that belong to the enterprise are processed; others are logged and skipped. |

At least one of `--org`, `--orgs-file`, `--enterprise` is required. Org names are matched case-insensitively and de-duplicated. Orgs are processed one after another with one shared rate limiter and write budget, since GitHub applies those limits per token, not per org.
| `--include PATTERN [...]` | `*` | Glob patterns of repos to include (case-insensitive, applied in every org) |
| `--exclude PATTERN [...]` | `veracode` | Glob patterns of repos to skip. The central `veracode` repo is always excluded in every org. |
| `--include-archived` | off | Otherwise archived repos are skipped |
| `--include-forks` | off | Otherwise forks are skipped |

Empty and disabled repos are always skipped.

### Delivery

| Flag | Default | Description |
|---|---|---|
| `--dry-run` | off | Print decisions and YAML, write nothing |
| `--direct-commit` | off | Commit to the default branch instead of opening a PR |
| `--branch-name NAME` | `chore/veracode-scan-scoping` | Branch used for the PR flow. A leftover branch with no open PR is reset to the default branch head before reuse. |
| `--force` | off | Overwrite a hand-written (unmanaged) `veracode.yml`. Managed files are updated without it. |
| `--reopen-declined` | off | Open a new PR even where a previous scoping PR was closed and the default branch has no managed file. Without it such repos are reported as `pr_declined`. |

### Detection Tuning

| Flag | Default | Description |
|---|---|---|
| `--keep-issue-triggers` | off | Do not write `issues: trigger: false` for disabled scans. Use when the central config never enables issue triggers and you want to avoid the one-time update PRs described under Upgrading. |
| `--iac {always,artifacts,off}` | `always` | `always`: IaC/secrets on everywhere. `artifacts`: only where IaC/container artifacts exist. `off`: disabled org-wide. `--no-iac` is an alias for `off`. |
| `--deep-iac` | off | With `--iac artifacts`: download a few ambiguous root YAML/JSON files and check for CloudFormation/Kubernetes markers (extra API calls). Ignored, with a warning, in other modes. |
| `--runner {auto,off}` | `auto` | `auto` sets a Windows runner on confirmed Windows build signals when a build-based scan is enabled; weak signals auto-trigger project-file inspection. `off` never writes a runner. |
| `--runner-scope {build,all}` | `build` | `build` writes `actions: <scan>: build: runs_on` for the enabled SAST/SCA scans only. `all` writes `default: runs_on` (every job on Windows). |
| `--windows-runner LABEL` | `windows-latest` | Runner label for Windows-bound builds, or a flow list such as `'[self-hosted, windows]'` |
| `--deep-dotnet` | off | Extend project-file inspection to every repo with `.csproj`/`.vbproj`/`.fsproj` (extra API calls, up to `--max-project-files` per repo) |
| `--max-project-files N` | `5` | Cap on .NET project files downloaded per repo during Windows-marker inspection |
| `--platform-analysis {true,false}` | unset | Also pin `analysis_on_platform` for SAST-relevant repos. Left untouched by default. |
| `--config FILE` | built-in | JSON file overriding detection matrices (see below). Values are shape-checked against the defaults at startup. |

### Rate Limiting and Reliability

| Flag | Default | Description |
|---|---|---|
| `--min-interval SECONDS` | `0.25` | Minimum delay between GitHub API calls |
| `--min-remaining N` | `100` | Sleep until reset when the core rate limit budget drops below this |
| `--write-interval SECONDS` | `1.0` | Minimum delay between write requests (branches, commits, PRs), under GitHub's ~80 content-creating requests per minute |
| `--max-writes-per-hour N` | `450` | Rolling hourly cap on write requests, under GitHub's ~500 per hour secondary limit. `0` disables. |
| `--gh-timeout SECONDS` | `120` | A single `gh` call that exceeds this is abandoned and retried, so one stalled connection cannot hang an org-wide run |

The script checks `/rate_limit` every 50 calls, sleeps until reset when the budget runs low, and backs off exponentially with jitter on secondary rate limit responses and transient errors (5xx, timeouts, resets). Every write path is idempotent on retry: a branch, commit, deletion, or PR that succeeded server-side but failed client-side is recognized as done instead of marking the repo failed. PR mode makes up to 3 writes per repo, so the default hourly cap processes roughly 150 changed repos per hour; unchanged repos cost no writes.

Language data is prefetched in batches of 40 repos per GraphQL call (disable with `--no-graphql`); any repo missing from a batch, and every repo when the GraphQL endpoint is unhealthy, falls back to its own REST call. Cost is roughly 1 API call per repo (recursive tree) plus 1 per 40 repos (languages), plus 1 when a `veracode.yml` already exists (to read it) and 1 search query per run to find outdated scoping PRs.

### Output

| Flag | Default | Description |
|---|---|---|
| `--report FILE` | none | Write a JSON audit report: per-repo languages, decisions, reasons, full detection evidence, action, and outcome. Written even when the run is interrupted (Ctrl-C) or crashes, with an `interrupted` flag. Failed repos are included with their error. |
| `--resume-from FILE` | none | Skip repos (matched by org and repo name) that already reached a terminal outcome (`no_change`, `already_correct`, `committed`, `pr_opened`, `skipped_existing_file`, `pr_declined`) in a prior `--report` JSON. Their entries are carried into the new report (`carried_over: true`), so chained resumes stay cumulative. Failed and dry-run outcomes are retried. Reports from the earlier single-org version are accepted. |
| `--no-graphql` | off | Disable batched GraphQL language prefetching and use one REST call per repo instead |
| `--csv FILE` | `dry_run_report.csv` on `--dry-run`, off otherwise | Write a flat CSV: one row per repo with outcome, action, scan decisions, reasons, runner, languages, PR URL, and error. |
| `-v`, `--verbose` | off | Debug-level logging, including the per-scan-type reasoning for every repo |

-----

## Overriding Detection Matrices

Pass `--config matrices.json` to change any of the 37 detection keys without touching the script. Prefix a key with `+` to add to the default and `-` to remove from it; a bare key replaces the default entirely, which is rarely what you want for detection lists (replacing `SCA_MANIFEST_NAMES` with three names disables SCA for every other ecosystem).

```json
{
  "+VENDORED_PATH_SEGMENTS": ["generated", "third_party_libs"],
  "+TOOLING_CONFIG_BASENAMES": ["storybook.config.js"],
  "+SAST_COMPILED_ONLY": ["Kotlin"],
  "-SAST_NO_SUPPORTED_RUNNER": ["Swift"],
  "+SCA_LANGUAGES": ["Ruby"],
  "+SCA_ECOSYSTEM_MAP": {
    "ruby": {"languages": ["Ruby"], "names": ["gemfile", "gemfile.lock"]}
  }
}
```

`+`/`-` apply to lists and objects (`-` takes a list of items or object keys, case-insensitive). Unknown keys, wrong types, unknown fields in nested objects, and invalid regexes are rejected at startup with a clear message.

Keys: `APPLE_CORROBORATION_NAMES`, `APPLE_CORROBORATION_SUFFIXES`, `CLASSIFICATION_VENDORED_SEGMENTS`, `CODE_EXTENSIONS`, `FRAMEWORK_PLATFORM_DIRS`, `GENERATED_FILE_SUFFIXES`, `IAC_DIR_HINTS`, `IAC_FILE_NAMES`, `IAC_FILE_SUFFIXES`, `IAC_LANGUAGES`, `IAC_NAME_PREFIXES`, `LANGUAGE_ALIASES`, `MIN_LANGUAGE_BYTES`, `SALESFORCE_CORROBORATION_NAMES`, `SALESFORCE_CORROBORATION_SEGMENTS`, `SAST_BUILD_EVIDENCE`, `SAST_COMPILED_ONLY`, `SAST_LANGUAGES`, `SAST_NO_SUPPORTED_RUNNER`, `SAST_PIPELINE_NOT_AUTOPACKAGED`, `SCA_ECOSYSTEM_MAP`, `SCA_IGNORED_NAMES`, `SCA_LANGUAGES`, `SCA_MANIFEST_NAMES`, `SCA_MANIFEST_SUFFIXES`, `SCA_SUPPORTING_NAMES`, `SCA_SUPPORTING_SUFFIXES`, `TOOLING_CONFIG_BASENAMES`, `TOOLING_CONFIG_STEMS`, `VENDORED_PATH_SEGMENTS`, `WINDOWS_CORROBORATION_LANGUAGES`, `WINDOWS_FILE_NAMES`, `WINDOWS_FILE_SUFFIXES`, `WINDOWS_PROJECT_MARKERS`, `WINDOWS_TFM_REGEX`, `WINDOWS_WEAK_FILE_NAMES`, `WINDOWS_WEAK_FILE_SUFFIXES`.

-----

## Output

### Generated `veracode.yml`

Only the disabled sections (and a Windows build runner, when detected) are written; everything else inherits the central config. Each file carries the managed marker and a comment header with the detection reasoning.

A Windows-bound .NET Framework repo:

```yaml
# managed-by: veracode-scan-scoping (settings below are regenerated; edit the tool's --config instead)
# Detection: SAST=True (languages=['C#'])
#            SCA=True (manifests=['packages.config', 'web.csproj'], ecosystems=['dotnet']; paired=['dotnet'])
#            IaC=True (no artifacts detected, kept enabled for secret scanning)
#            Runner=windows-latest (build scope) (windows signals=['global.asax', 'packages.config'])

actions:
  veracode_static_scan:
    build:
      runs_on: windows-latest
  veracode_sca_scan:
    build:
      runs_on: windows-latest
```

A docs-only repo (IaC stays on by default for secret scanning):

```yaml
# managed-by: veracode-scan-scoping (settings below are regenerated; edit the tool's --config instead)
# Detection: SAST=False (no supported language (found: ['Markdown']))
#            SCA=False (no integration-supported dependency manifest)
#            IaC=True (no artifacts detected, kept enabled for secret scanning)
#            Runner=default (portable ecosystem, central default (linux))

veracode_static_scan:
  push:
    trigger: false
  pull_request:
    trigger: false
  issues:
    trigger: false

veracode_sca_scan:
  push:
    trigger: false
  pull_request:
    trigger: false
  issues:
    trigger: false
```

`issues.trigger` is disabled too: the reference central config has an issue-comment trigger per scan, and an org that enables it would otherwise still run the irrelevant scan on demand. `--keep-issue-triggers` omits it.

When a file's settings are already correct, it is not rewritten just to refresh the comment header, so the header reflects the detection at the time the settings last changed. The `--report`/`--csv` output always carries the current reasons.

### Summary

Printed at the end of every run (repos are shown as `org/repo`):

```
========== SUMMARY ==========
Orgs: 3 (0 not accessible)
Scoped (override written/PR): 41
No change needed: 12
Already correct (identical settings): 3
Skipped: 6
Failed: 0
Total GitHub API calls: 187 (96 writes)
```

### `--report` JSON

```json
{
  "org": "my-org",
  "orgs": ["my-org"],
  "generated": "2026-09-28T00:00:00Z",
  "api_calls": 187,
  "write_calls": 96,
  "interrupted": false,
  "org_errors": [],
  "repos": [
    {
      "org": "my-org",
      "repo": "payments-api",
      "default_branch": "main",
      "languages": {"Java": 128000},
      "tree_truncated": false,
      "decision": {
        "sast": true, "sca": true, "iac": true, "runner": null,
        "reasons": {
          "sast": "languages=['Java']",
          "sca": "manifests=['pom.xml'], ecosystems=['java']; paired=['java']",
          "iac": "artifacts present",
          "runner": "portable ecosystem, central default (linux)"
        },
        "evidence": {"...": "full, untruncated detection evidence"}
      },
      "runner_scope": "build",
      "override_written": false,
      "existing_file": null,
      "action": null,
      "outcome": "no_change"
    }
  ]
}
```

`org` is set only when a single org was processed (kept for compatibility); `orgs` always lists them all. `org_errors` lists orgs that could not be read or listed (`{"org", "error"}`).

`existing_file` is `managed`, `unmanaged`, or `null`. `action` is `write`, `delete`, or `null`.

`outcome` values: `no_change`, `already_correct`, `would_write` / `would_delete` (dry run), `committed`, `pr_opened` (with `pr_reused` when an open PR was updated), `skipped_existing_file` (hand-written file), `pr_declined`, `failed_branch_creation`, `failed` (with `error`).

### `--csv` report

Written automatically to `dry_run_report.csv` on every `--dry-run` (pass `--csv FILE` to name it explicitly, or to also get one on an apply run). One row per repo, flattened for review in Excel/Sheets before anything touches GitHub. Columns: `org, repo, default_branch, tree_truncated, outcome, action, existing_file, override_written, sast, sast_reason, sca, sca_reason, iac, iac_reason, runner, runner_reason, languages, pr_url, error, carried_over`.

-----

## Security Notes

- Uses the `gh` CLI's own authentication; no credentials are read, stored, or logged by the script
- Default mode opens a PR for review; no repo is changed without either explicit review or `--direct-commit`
- Hand-written `veracode.yml` files are never overwritten without `--force`
- Repo-derived strings are stripped of control characters before they reach YAML comments, logs, or PR bodies, and are rendered as inline code in PR bodies (no @mentions or markdown injection). Runner labels are validated before being written.
- One repo or one inaccessible org never halts a run; failures are collected, reported, and retried on `--resume-from`

-----

## Support

This is a companion tool to Veracode's GitHub Workflow Integration and is not officially supported by Veracode. For issues, provide the `--report` JSON output and the exact command run.
