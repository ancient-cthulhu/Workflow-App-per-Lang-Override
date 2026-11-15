# GitHub Veracode Scan Scoping

> See [QUICKSTART.md](QUICKSTART.md) for the fastest setup path.

This tool creates or updates per-repository `veracode.yml` overrides for the [Veracode GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning). It scans repository languages, dependency manifests, and IaC files, then disables only scan triggers that do not apply. This prevents irrelevant SAST/SCA runs from failing builds while keeping secret scanning enabled by default.

Supports one or more organizations, organization lists, or every organization in a GitHub Enterprise Cloud enterprise.

## How it works

For each eligible repository, the tool:

1. Gets GitHub Linguist language data and the repository file tree.
2. Determines whether SAST, SCA, and IaC/secrets scanning apply.
3. Writes a minimal root `veracode.yml` only when an override is needed. It disables irrelevant `push`, `pull_request`, and (by default) `issues` triggers, and can select a Windows build runner.
4. Opens or updates a PR by default, or commits directly with `--direct-commit`.

Repositories where every scan is relevant need no override. Generated files contain `# managed-by: veracode-scan-scoping` (older files beginning with `# Detection:` are also recognized). The tool updates or removes its own files as repository contents change. Hand-written `veracode.yml` files are left untouched unless `--force` is used.

**Repeatable runs:** Existing settings are compared without comments, so changes to detection explanations do not create unnecessary PRs. Open scoping PRs are reused. PRs closed without merging are not reopened unless `--reopen-declined` is set. If a fresh scan no longer justifies an open PR, the tool closes it with a comment.

> **Trigger behavior:** `push` and `pull_request` control Pipeline scans. Platform sandbox/policy scans use `analysis_on_platform` and are not changed unless `--platform-analysis` is explicitly set. SCA and IaC scans are controlled by their workflow triggers; disabling those triggers prevents those runs.

## Scan and runner decisions

### SAST

SAST stays enabled for languages the integration can package for Pipeline Scan: .NET, Java, JavaScript/TypeScript, Kotlin, Python, Go, Ruby, Scala, PHP, Apex, ColdFusion, Groovy, and C/C++ when a build system is present.

- **No Pipeline Scan support:** Perl, PL/SQL, T-SQL, Classic ASP, RPG, VB6, and Dart disable SAST.
- **Supported by Pipeline Scan but disabled by the integration build:** COBOL (`SAST_PIPELINE_NOT_AUTOPACKAGED`), Swift, and Objective-C (`SAST_NO_SUPPORTED_RUNNER`). The integration packages with `--skip-packagers sql,cobol`, so COBOL produces no upload artifact. Swift/Objective-C require Xcode on macOS, while the integration provides Linux and Windows jobs. `SAST_COMPILED_ONLY` is available for organization-specific rules and is empty by default.
- **C/C++** requires build evidence such as `Makefile`, `CMakeLists.txt`, `meson.build`, `build.ninja`, `configure`, `SConstruct`, `.vcxproj`, `.mk`, or `.bb`.

Tree truncation fails open: it never disables a scan based on incomplete evidence. Configure language tiers with `--config`; tier entries take precedence over `SAST_LANGUAGES`.

### SCA

SCA is enabled when a manifest or lockfile from an integration-supported ecosystem is found: .NET, Go, Java/Kotlin/Scala, JavaScript/TypeScript, PHP, or Python. The manifest determines the ecosystem, not Linguist's language label. For example, `requirements.txt` enables SCA in a notebook repository.

Detection includes standard lockfiles, Gradle catalogs, .NET central package management, `requirements*.txt`, `.sbt` files, and vendored `.jar`/`.dll` hash scanning.

The following files are reported but do **not** enable SCA by themselves because the agent may fail with `no build system found`:

- **Unsupported ecosystems:** `Gemfile`, `Podfile`, `Makefile`.
- **Supporting files:** `global.json`, `Directory.Build.props`, `Directory.Packages.props`, `gradlew`, `mvnw`, `libs.versions.toml`, `setup.cfg`, `pnpm-workspace.yaml`, `go.work.sum`, `.sln`.
- **Wrapper binaries:** `gradle-wrapper.jar`, `maven-wrapper.jar`.

A manifest from an otherwise unexpected ecosystem is still detected and reported as unpaired. To add a custom ecosystem, update `SCA_ECOSYSTEM_MAP` and `SCA_LANGUAGES` in a config file.

### IaC and secrets

`--iac always` (default) keeps IaC/secrets scanning enabled in every repository. It scans supported infrastructure/container files (Terraform, Dockerfiles, Helm/Kubernetes, CloudFormation) and checks repository contents for hardcoded secrets.

- `--iac artifacts`: enable only when IaC/container artifacts are detected. Truncated trees fail open; `--deep-iac` checks ambiguous root YAML/JSON files by content.
- `--iac off` / `--no-iac`: disable IaC/secrets scanning across the selected repositories.

### Windows runner selection

The central default is `ubuntu-latest`. When SAST or SCA is enabled and the repository has Windows-only build requirements, the tool sets `runs_on` on the **build job only**:

```yaml
actions:
  veracode_static_scan:
    build:
      runs_on: windows-latest
  veracode_sca_scan:
    build:
      runs_on: windows-latest
```

`--runner-scope all` instead sets `default: runs_on`, moving every integration job to Windows. This uses more runner minutes. Set a self-hosted label with `--windows-runner '[self-hosted, windows]'`.

Detection uses these signals:

| Signal | Examples | Behavior |
|---|---|---|
| Strong | `packages.config`, `Global.asax`, WebForms files (`*.aspx`, `*.ascx`, `*.asax`, `*.master`, `*.asmx`), `*.vcxproj`, `*.vcproj`, `.sqlproj`, `.wixproj` | Select Windows when .NET/C++ evidence is also present. |
| Weak | `*.xaml`, `web.config`, `app.config`, `*.vbproj`, `*.fsproj` | Do not select Windows by themselves; inspect nearby project files for stronger evidence. |
| Project markers | Old-style MSBuild markers, `<TargetFrameworkVersion>`, `ToolsVersion`, `<UseWPF>`, `<UseWindowsForms>`, `net4x`, or `*-windows` target frameworks | Select Windows when found. MAUI-style `IsOSPlatform`-conditioned TFMs are ignored. |

Plain `.cs`, `.csproj`, and `.sln` files do not imply Windows; SDK-style .NET builds run on Linux. `--deep-dotnet` inspects project files in every repository containing them, including projects with no surface-level Windows signals. Weak-signal inspection is limited by `--max-project-files` (default `5`). Use `--runner off` to disable runner selection. Truncated-tree decisions are marked best-effort.

## Detection safeguards

All safeguards are enabled by default and can be customized with `--config`.

- **Exclude noise:** vendored/generated directories (`node_modules/`, `vendor/`, `bower_components/`, `Pods/`, `.terraform/`), build output (`dist/`, `build/`, `target/`, `bin/`, `obj/`, `out/`), virtualenvs, coverage output, minified bundles, and generated sources are excluded from classification and artifact detection. `packages/` is intentionally included; Go projects can still be detected through root `go.mod` even when `vendor/` exists.
- **Ignore tooling-only languages:** build and test config files (for example, `webpack.config.js`, `tailwind.config.js`, `jest.config.ts`) are removed from Linguist byte counts. A real `package.json` still enables SCA.
- **Ignore generated framework platforms:** when root `pubspec.yaml` exists, generated Flutter platform directories (`android/`, `ios/`, `linux/`, `macos/`, `windows/`, `web/`) are excluded.
- **Normalize language names:** aliases such as `TSX`, `Objective-C++`, `ColdFusion CFC`, and `Java Server Pages` map to their canonical languages.
- **Require evidence for ambiguous extensions:** `.m` needs Apple project evidence; `.cls`/`.trigger` needs Salesforce evidence; a lone `.h` does not identify a C project.
- **Ignore trivial stubs:** languages below `MIN_LANGUAGE_BYTES` (default `200`) do not enable scans. Linguist and extension-based detection are combined so missing or delayed Linguist data does not hide code.
- **Handle incomplete repositories safely:** trees are fetched from `HEAD`; an unreadable tree fails the repository rather than treating it as empty. Truncated trees merge in a root listing and never disable scans. Empty, archived, disabled, and forked repositories are skipped by default.

**Fail-open rule:** ambiguity keeps scans enabled. Overrides disable only scans that are unsupported or have no applicable content; they do not disable scans based on incomplete detection.

## Requirements and authentication

- GitHub CLI (`gh`) installed and available on `PATH`.
- Python 3.9+; standard library only. No pip dependencies.
- One authenticated GitHub identity with access to every target organization.

Authentication precedence is `GH_TOKEN`, `GITHUB_TOKEN`, then credentials from `gh auth login`. For GitHub Enterprise Server, use `GH_HOST` / `GH_ENTERPRISE_TOKEN` as applicable. The script reports the selected credential source but never logs the token.

For a classic PAT, grant:

| Scope | Required for |
|---|---|
| `repo` | Read private repositories and create/update files |
| `workflow` | Update workflow files |
| `read:org` | List repositories and read organization data |
| `read:enterprise` | `--enterprise` organization discovery only |

For SAML SSO organizations, authorize the token for each organization. Organizations the token cannot access are reported and skipped; other organizations continue.

Example:

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
python3 script.py --org my-org --dry-run
```

Or authenticate once with `gh auth login` and omit the token variable.

## Quick start

Run a read-only audit first, pilot on a subset, then roll out through PRs:

```bash
# 1. Audit one or more organizations
python3 script.py --org my-org --dry-run --report audit.json
python3 script.py --org org-a org-b --dry-run --report audit.json
python3 script.py --orgs-file orgs.txt --dry-run --report audit.json
python3 script.py --enterprise my-ent --dry-run --report audit.json

# Limit an enterprise run to organizations listed in a file
python3 script.py --enterprise my-ent --orgs-file pilot.txt --dry-run

# 2. Pilot on selected repositories (include a Windows-bound .NET repo)
python3 script.py --org my-org --include 'team-*' --dry-run

# 3. Apply changes through PRs (default mode)
python3 script.py --org my-org --report run1.json

# Resume after interruption; reports remain cumulative
python3 script.py --org my-org --resume-from run1.json --report run2.json
```

## Command-line reference

At least one of `--org`, `--orgs-file`, or `--enterprise` is required. Organization names are case-insensitive and de-duplicated. Organizations are processed sequentially with a shared rate limiter and write budget.

### Scope

| Option | Default | Description |
|---|---|---|
| `--org ORG [ORG ...]` | — | One or more GitHub organizations. |
| `--orgs-file FILE` | — | Organization logins, one per line; `#` comments allowed. Combines with `--org`. |
| `--enterprise SLUG` | — | Discover every organization in a GitHub Enterprise Cloud enterprise. Requires `read:enterprise`. Combined with explicit organizations, processes only listed organizations in that enterprise. |
| `--include PATTERN [...]` | `*` | Case-insensitive repository glob patterns to include in every organization. |
| `--exclude PATTERN [...]` | `veracode` | Repository glob patterns to skip. The central repo is always excluded. |
| `--central-repo NAME` | `veracode` | Central integration repository; never modified, even with `--force`. Repositories with root `veracode.yml` and `.github/workflows/veracode-*.yml` are also skipped. |
| `--include-archived` | off | Include archived repositories. |
| `--include-forks` | off | Include forks. |

Empty and disabled repositories are always skipped.

### Delivery

| Option | Default | Description |
|---|---|---|
| `--dry-run` | off | Print decisions and generated YAML; make no changes. |
| `--direct-commit` | off | Commit to the default branch instead of opening a PR. |
| `--branch-name NAME` | `chore/veracode-scan-scoping` | PR branch name. A stale branch without an open PR is reset to the default branch head before reuse. |
| `--force` | off | Overwrite a hand-written `veracode.yml`. Managed files do not require this flag. |
| `--reopen-declined` | off | Reopen a PR previously closed without merging. Otherwise report `pr_declined`. |

### Detection and runner tuning

| Option | Default | Description |
|---|---|---|
| `--keep-issue-triggers` | off | Do not disable `issues` triggers for irrelevant scans. |
| `--iac {always,artifacts,off}` | `always` | IaC/secrets policy described above. `--no-iac` aliases `off`. |
| `--deep-iac` | off | Inspect ambiguous root YAML/JSON content with `--iac artifacts` (additional API calls). |
| `--runner {auto,off}` | `auto` | Automatically select Windows for confirmed Windows-bound builds, or disable runner overrides. |
| `--runner-scope {build,all}` | `build` | Set Windows on SAST/SCA build jobs only, or on every integration job. |
| `--windows-runner LABEL` | `windows-latest` | Windows runner label; accepts self-hosted labels such as `'[self-hosted, windows]'`. |
| `--deep-dotnet` | off | Inspect project files in every repository containing `.csproj`, `.vbproj`, or `.fsproj` (additional API calls). |
| `--max-project-files N` | `5` | Maximum project files inspected per repository. |
| `--platform-analysis {true,false}` | unset | Set `analysis_on_platform` for SAST-relevant repositories. Unchanged unless specified. |
| `--config FILE` | built-in | JSON file to customize detection matrices. Validated at startup. |

### Rate limits and reliability

| Option | Default | Description |
|---|---|---|
| `--min-interval SECONDS` | `0.25` | Minimum delay between GitHub API calls. |
| `--min-remaining N` | `100` | Wait for reset when the core rate-limit budget falls below this value. |
| `--write-interval SECONDS` | `1.0` | Minimum delay between write requests. |
| `--max-writes-per-hour N` | `450` | Rolling hourly write cap; `0` disables it. |
| `--gh-timeout SECONDS` | `120` | Timeout for an individual `gh` call before retry. |
| `--no-graphql` | off | Disable batched GraphQL prefetch; use REST calls per repository. |

The tool checks core and GraphQL limits every 50 calls, waits for resets, and uses exponential backoff with jitter for secondary limits and transient errors. Writes are retry-safe. PR mode uses up to three writes per changed repository; the default cap therefore supports roughly 150 changed repositories per hour. Unchanged repositories require no writes.

Languages and existing root `veracode.yml` files are prefetched in batches of 40 repositories through GraphQL. REST is used as a fallback when a repository is missing from a batch or GraphQL is unavailable. Typical API cost is approximately one recursive-tree call per repository, one GraphQL call per 40 repositories, and one search per organization for stale scoping PRs.

### Reports and logging

| Option | Default | Description |
|---|---|---|
| `--report FILE` | — | JSON audit report with per-repository decisions, evidence, actions, outcomes, and errors. Written on normal completion, interruption, or crash. |
| `--resume-from FILE` | — | Skip repositories with terminal outcomes from a prior report and carry their entries forward. Failed and dry-run outcomes are retried. Supports reports from the earlier single-org version. |
| `--csv FILE` | `dry_run_report.csv` on dry-run; otherwise off | Flat, spreadsheet-friendly report; one row per repository. |
| `-v`, `--verbose` | off | Debug logging, including per-scan reasoning. |

## Configuration

Use `--config matrices.json` to customize detection without editing the script. The 37 supported keys are validated at startup.

- `+KEY`: add values to the built-in list/object.
- `-KEY`: remove values or object keys (case-insensitive).
- `KEY`: replace the built-in value entirely. Avoid replacement for detection lists unless that is intentional; for example, replacing `SCA_MANIFEST_NAMES` can disable detection for other ecosystems.

Example:

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

Unknown keys, invalid types, unknown nested fields, and invalid regular expressions are rejected at startup.

**Supported keys:** `APPLE_CORROBORATION_NAMES`, `APPLE_CORROBORATION_SUFFIXES`, `CLASSIFICATION_VENDORED_SEGMENTS`, `CODE_EXTENSIONS`, `FRAMEWORK_PLATFORM_DIRS`, `GENERATED_FILE_SUFFIXES`, `IAC_DIR_HINTS`, `IAC_FILE_NAMES`, `IAC_FILE_SUFFIXES`, `IAC_LANGUAGES`, `IAC_NAME_PREFIXES`, `LANGUAGE_ALIASES`, `MIN_LANGUAGE_BYTES`, `SALESFORCE_CORROBORATION_NAMES`, `SALESFORCE_CORROBORATION_SEGMENTS`, `SAST_BUILD_EVIDENCE`, `SAST_COMPILED_ONLY`, `SAST_LANGUAGES`, `SAST_NO_SUPPORTED_RUNNER`, `SAST_PIPELINE_NOT_AUTOPACKAGED`, `SCA_ECOSYSTEM_MAP`, `SCA_IGNORED_NAMES`, `SCA_LANGUAGES`, `SCA_MANIFEST_NAMES`, `SCA_MANIFEST_SUFFIXES`, `SCA_SUPPORTING_NAMES`, `SCA_SUPPORTING_SUFFIXES`, `TOOLING_CONFIG_BASENAMES`, `TOOLING_CONFIG_STEMS`, `VENDORED_PATH_SEGMENTS`, `WINDOWS_CORROBORATION_LANGUAGES`, `WINDOWS_FILE_NAMES`, `WINDOWS_FILE_SUFFIXES`, `WINDOWS_PROJECT_MARKERS`, `WINDOWS_TFM_REGEX`, `WINDOWS_WEAK_FILE_NAMES`, `WINDOWS_WEAK_FILE_SUFFIXES`.

## Generated files and results

### `veracode.yml`

The tool writes only disabled scan sections and, when needed, Windows runner settings. All other values inherit from the central configuration. Each generated file includes the managed marker and detection reasons in comments.

For a docs-only repository, SAST and SCA triggers are disabled while IaC/secrets remains enabled by default:

```yaml
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

`issues.trigger` is disabled because the central configuration may enable issue-comment scans. Use `--keep-issue-triggers` to leave it unchanged. Existing files are not rewritten just to refresh comments; the JSON/CSV reports always contain current reasons.

### Console summary

Every run ends with counts for organizations, scoped repositories, unchanged/already-correct repositories, skips, failures, and GitHub API/write calls.

### JSON report

The report includes organization metadata, timestamps, API/write counts, interruption state, organization errors, and a `repos` array. Each repository entry includes its default branch, languages, tree-truncation status, scan decisions/reasons/evidence, runner scope, existing-file state, action, and outcome.

- `existing_file`: `managed`, `unmanaged`, or `null`.
- `action`: `write`, `delete`, or `null`.
- Common outcomes: `no_change`, `already_correct`, `would_write`, `would_delete`, `committed`, `pr_opened` (may include `pr_reused`), `skipped_existing_file`, `pr_declined`, `skipped_central_repo`, `failed_branch_creation`, and `failed` (with `error`).
- `stale_pr` indicates an outdated open scoping PR was closed, or would be closed in a dry run.
- `org` is populated only for a single-org run; `orgs` always lists processed organizations. `org_errors` contains organizations that could not be accessed or listed.
- `--resume-from` carries terminal entries forward with `carried_over: true`. Terminal outcomes include `no_change`, `already_correct`, `committed`, `pr_opened`, `skipped_existing_file`, `pr_declined`, and `skipped_central_repo`.

### CSV report

One row per repository with outcome, action, scan decisions/reasons, runner, languages, PR URL, and error. Columns are: `org`, `repo`, `default_branch`, `tree_truncated`, `outcome`, `action`, `existing_file`, `override_written`, `sast`, `sast_reason`, `sca`, `sca_reason`, `iac`, `iac_reason`, `runner`, `runner_reason`, `languages`, `pr_url`, `error`, `carried_over`. The UTF-8 BOM supports Excel. Formula-leading values are escaped to prevent repository-controlled text from being interpreted as spreadsheet formulas.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All repositories and organizations succeeded. |
| `2` | A repository/organization failed, or startup failed (arguments, authentication, or config). |
| `130` | Interrupted. |

## Security and support

- Uses `gh` authentication; credentials are not read directly, stored, or logged by the script.
- PR mode is the default. Direct changes require `--direct-commit`.
- Hand-written `veracode.yml` files are protected unless `--force` is supplied.
- Repository-derived text is sanitized before use in YAML comments, logs, and PR bodies. PR content avoids mentions/Markdown injection, and runner labels are validated.
- A failed repository or inaccessible organization does not stop the rest of the run. Errors are reported and can be retried with `--resume-from`.

This is a companion tool for Veracode's GitHub Workflow Integration and is **not officially supported by Veracode**. For issues, include the JSON `--report` output and exact command used.
