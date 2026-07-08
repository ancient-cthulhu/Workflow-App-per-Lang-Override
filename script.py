#!/usr/bin/env python3
"""
Requirements: gh CLI authenticated (repo + read:org), Python 3.9+, stdlib only.

Usage:
  python3 script.py --org my-org --dry-run --report audit.json
  python3 script.py --org my-org
  python3 script.py --org my-org --no-iac --direct-commit
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import logging
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import quote

log = logging.getLogger("veracode-provision")

# ---------------------------------------------------------------------------
# Detection matrices
# Verified against the Veracode GitHub Workflow Integration docs (2026-07):
# https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning
# and SCA agent support:
# https://docs.veracode.com/r/Using_Veracode_SCA_with_Programming_Languages/
# All of these can be overridden with --config (JSON with the same key names)
# so the script stays correct as Veracode expands support.
# ---------------------------------------------------------------------------

DEFAULT_MATRICES: dict = {
    # SAST default = everything Pipeline Scan supports ("Pipeline Scan
    # supported languages", 2026-03-25): .NET (incl. Xamarin/MAUI), Android,
    # Apex, Apple Platforms, C, C++, COBOL, ColdFusion, Cordova, Groovy, Go,
    # Ionic, Java, JavaScript/TypeScript, Kotlin, PhoneGap, PHP, Python,
    # React Native, Ruby on Rails, Scala, Titanium.
    # Deliberately NOT gated on current autopackager/integration support:
    # the autopackager gains languages over time, and a repo in a supported
    # language should not be silently opted out based on today's packager.
    # NOT included: Perl, PL/SQL, T-SQL, Classic ASP, RPG, VB6, Dart - those
    # are platform Static Analysis (Upload and Scan) only, not pipeline.
    "SAST_LANGUAGES": [
        "C#", "F#", "Visual Basic .NET", "ASP.NET",
        "Go",
        "Java", "Groovy",
        "JavaScript", "TypeScript", "Vue", "JSX", "Svelte",
        "Kotlin",
        "PHP",
        "Python",
        "Ruby",
        "Scala",
        "Apex",
        "ColdFusion",
        "Swift", "Objective-C",
        "C", "C++",
        "COBOL",
    ],
    # Optional disable tiers, EMPTY by default. If packaging failures become
    # a PR-blocking problem for specific ecosystems in your org, move those
    # languages out of SAST_LANGUAGES into the matching tier via --config to
    # disable them with an explanatory reason:
    #   SAST_PIPELINE_NOT_AUTOPACKAGED - packager does not build them yet
    #   SAST_COMPILED_ONLY - need preprocessed/compiled artifacts (e.g. C/C++)
    "SAST_PIPELINE_NOT_AUTOPACKAGED": [],
    "SAST_COMPILED_ONLY": [],
    # Extension fallback used when the languages API is empty or the tree is
    # truncated. Maps extension -> Linguist name (checked against the sets above).
    "CODE_EXTENSIONS": {
        ".cs": "C#", ".cshtml": "C#", ".razor": "C#", ".fs": "F#", ".vb": "Visual Basic .NET",
        ".go": "Go",
        ".java": "Java", ".jsp": "Java", ".groovy": "Groovy",
        ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
        ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
        ".vue": "Vue", ".svelte": "Svelte",
        ".kt": "Kotlin", ".kts": "Kotlin",
        ".py": "Python",
        ".rb": "Ruby", ".erb": "Ruby",
        ".scala": "Scala",
        ".php": "PHP",
        ".dart": "Dart",
        ".pl": "Perl", ".pm": "Perl",
        ".cfm": "ColdFusion", ".cfc": "ColdFusion",
        ".cls": "Apex", ".trigger": "Apex",
        ".c": "C", ".cpp": "C++", ".cc": "C++", ".h": "C",
        ".swift": "Swift", ".m": "Objective-C",
        ".cbl": "COBOL", ".cob": "COBOL",
        ".rs": "Rust", ".ex": "Elixir", ".exs": "Elixir",
    },
    # Ecosystems in the SCA column of the integration's language support
    # table: .NET, Go, Java, JavaScript, Kotlin, PHP, Python, Scala,
    # TypeScript. Ruby, Android, React Native have NO SCA support in the
    # integration (React Native repos still match via JavaScript). The SCA
    # agent itself supports more (Ruby Bundler, CocoaPods, C/C++ Make);
    # add those via --config if you run the agent outside the integration.
    "SCA_LANGUAGES": [
        "C#", "F#", "Visual Basic .NET", "ASP.NET",
        "Go",
        "Java", "Groovy",
        "JavaScript", "TypeScript", "Vue", "JSX", "Svelte",
        "Kotlin",
        "PHP",
        "Python",
        "Scala",
    ],
    # Manifests / lockfiles the SCA agent can resolve, per package manager rows
    # in the agent support table. Exact lowercase basenames.
    "SCA_MANIFEST_NAMES": [
        # Java/Kotlin/Scala: Maven, Gradle, Ant/Ivy, SBT (+ wrappers, catalogs)
        "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
        "settings.gradle.kts", "gradle.lockfile", "build.sbt", "ivy.xml",
        "build.xml", "gradlew", "mvnw", "libs.versions.toml",
        # JavaScript/TypeScript: NPM, Yarn, Bower
        "package.json", "package-lock.json", "npm-shrinkwrap.json",
        "yarn.lock", "bower.json",
        # Python: pip, Pipenv, Poetry (requirements*.txt also matched by rule)
        "requirements.txt", "pipfile", "pipfile.lock", "pyproject.toml",
        "setup.py", "setup.cfg", "poetry.lock",
        # Go: Go modules, Dep, Glide, GoDep, GoVendor, Trash, go get
        "go.mod", "go.sum", "gopkg.toml", "gopkg.lock",
        "glide.yaml", "glide.lock", "trash.lock", "vendor.json",
        "godeps.json", "godeps.lock",
        # PHP: Composer
        "composer.json", "composer.lock",
        # Ruby: Bundler
        "gemfile", "gemfile.lock", "gems.rb",
        # .NET: NuGet (+ central package management)
        "packages.config", "project.json", "directory.build.props",
        "directory.packages.props", "global.json",
        # Objective-C/Swift: CocoaPods (Carthage is NOT agent-supported)
        "podfile", "podfile.lock",
        # C/C++: Make
        "makefile", "gnumakefile",
    ],
    # Manifest suffixes (lowercase). .jar/.dll covered by the agent's
    # "Jars"/"DLL" hash-based quick scan rows, so vendored-binary repos count.
    # .sbt covers plugins.sbt and other sbt build definitions.
    "SCA_MANIFEST_SUFFIXES": [".csproj", ".fsproj", ".vbproj", ".sln",
                              ".nuspec", ".jar", ".dll", ".sbt"],
    # IaC / container / secrets scan signals. Exact lowercase basenames.
    "IAC_FILE_NAMES": [
        "dockerfile", "containerfile", ".dockerignore",
        "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
        "chart.yaml", "values.yaml", "kustomization.yaml", "kustomization.yml",
        "skaffold.yaml", "skaffold.yml",
        "terragrunt.hcl", ".terraform.lock.hcl", ".tflint.hcl",
        "main.bicep", "azuredeploy.json",
        "serverless.yml", "serverless.yaml", "samconfig.toml",
        "template.yaml", "template.yml",
        "cdk.json", "pulumi.yaml", "pulumi.yml",
        "ansible.cfg", "vagrantfile",
        "crossplane.yaml",
    ],
    "IAC_FILE_SUFFIXES": [".tf", ".tf.json", ".tfvars", ".hcl", ".bicep"],
    "IAC_NAME_PREFIXES": ["dockerfile", "docker-compose"],
    # Directory prefixes (lowercase, with trailing slash) where YAML/JSON is
    # treated as IaC.
    "IAC_DIR_HINTS": [
        "terraform/", "infra/", "infrastructure/", "iac/",
        "k8s/", "kubernetes/", "kube/", "helm/", "charts/", "manifests/",
        "deploy/", "deployment/", "deployments/",
        "cloudformation/", "cfn/", "sam/",
        "ansible/", "playbooks/", "roles/",
        "docker/",
    ],
    # Linguist languages that directly indicate IaC content.
    "IAC_LANGUAGES": ["HCL", "Dockerfile", "Bicep", "Smarty", "Open Policy Agent"],
    # Windows runner detection ("default: runs_on: windows-latest").
    # Modern SDK-style .NET builds on the default Linux runner, so plain
    # .cs/.csproj/.sln is NOT a signal. Signals are tiered:
    #
    # STRONG - unambiguous Framework/MSVC artifacts, force Windows directly:
    #   packages.config      pre-PackageReference NuGet (Framework-era msbuild)
    #   global.asax          ASP.NET Framework application file
    #   *.aspx/*.ascx/*.asax/*.master/*.asmx   WebForms / classic web services
    #   *.vcxproj/*.vcproj   Visual C++ / MSVC projects
    #
    # WEAK - ambiguous, trigger automatic project-file inspection instead of
    # forcing Windows (each has a portable counterpart):
    #   app.xaml / *.xaml    WPF, but also MAUI/Avalonia (Linux-buildable)
    #   web.config           ASP.NET Framework, but also Core IIS deploys
    #   *.vbproj/*.fsproj    can be Framework or SDK-style
    #
    # PROJECT MARKERS - lowercase substrings searched inside .csproj/.vbproj/
    # .fsproj when weak signals exist (automatic) or --deep-dotnet is passed:
    "WINDOWS_FILE_NAMES": ["packages.config", "global.asax"],
    "WINDOWS_FILE_SUFFIXES": [".vcxproj", ".vcproj", ".aspx", ".ascx",
                              ".asax", ".master", ".asmx", ".sqlproj",
                              ".wixproj"],
    "WINDOWS_WEAK_FILE_NAMES": ["app.xaml", "web.config"],
    "WINDOWS_WEAK_FILE_SUFFIXES": [".xaml", ".vbproj", ".fsproj"],
    "WINDOWS_PROJECT_MARKERS": [
        "<targetframeworkversion>",          # old-style Framework project
        "toolsversion=",                     # old-style msbuild project
        "schemas.microsoft.com/developer/msbuild/2003",  # old project xmlns
        "<usewpf>true",                      # WPF (Windows desktop)
        "<usewindowsforms>true",             # WinForms (Windows desktop)
        "-windows</targetframework>",        # e.g. net8.0-windows TFM
        "-windows<",                         # TFM list variants
        "<targetframework>net4",             # SDK-style targeting Framework
        "<targetframeworks>net4",
    ],
    # Path segments treated as vendored/generated content and EXCLUDED from
    # extension-language detection, SCA manifest detection, IaC artifact
    # detection, and Windows signal detection. Rationale: committed
    # node_modules or build output must not classify a repo's language, and a
    # packages.config buried in a vendored dependency must not force a
    # Windows runner. The GitHub Linguist API already excludes vendored paths;
    # this makes the extension fallback consistent with it. NOT excluded:
    # 'packages' (legit JS monorepo layout), 'lib', 'src'.
    "VENDORED_PATH_SEGMENTS": [
        "node_modules", "bower_components", "jspm_packages",
        "vendor", "vendors", "third_party", "third-party", "external", "externals",
        "dist", "build", "out", "output", "target",
        "bin", "obj",
        ".venv", "venv", "env", "__pycache__", "site-packages", ".tox", ".eggs",
        "pods", "carthage", "deriveddata",
        ".terraform", ".gradle", ".mvn", ".idea", ".vscode",
        "coverage", ".nyc_output",
    ],
    # Suffixes of generated/minified files excluded from extension-language
    # detection (a repo whose only JS is bundled output is not a JS project).
    "GENERATED_FILE_SUFFIXES": [".min.js", ".bundle.js", ".chunk.js",
                                ".min.mjs", ".pb.go", "_pb2.py", ".g.cs",
                                ".designer.cs", ".generated.cs"],
    # Build-tool configuration files excluded from extension-language
    # detection. A repo whose only .js/.ts files are these is not a
    # JavaScript project (docs sites, Python repos with frontend tooling).
    # They do NOT affect SCA manifest detection: if package.json exists, the
    # repo has an npm dependency tree worth scanning regardless.
    "TOOLING_CONFIG_BASENAMES": [
        "webpack.config.js", "webpack.mix.js", "babel.config.js",
        "babel.config.cjs", "jest.config.js", "jest.config.ts",
        "jest.setup.js", "rollup.config.js", "rollup.config.mjs",
        "vite.config.js", "vite.config.ts", "vitest.config.ts",
        "tailwind.config.js", "tailwind.config.ts", "postcss.config.js",
        "next.config.js", "next.config.mjs", "nuxt.config.js",
        "nuxt.config.ts", "metro.config.js", "svelte.config.js",
        "playwright.config.ts", "playwright.config.js",
        "cypress.config.js", "cypress.config.ts", "protractor.conf.js",
        "karma.conf.js", "gulpfile.js", "gruntfile.js",
        "prettier.config.js", ".eslintrc.js", ".eslintrc.cjs",
        "eslint.config.js", "eslint.config.mjs",
        "commitlint.config.js", "stylelint.config.js", "tsup.config.ts",
    ],
    # Minimum byte count for a Linguist API language to count toward scan
    # enablement (filters trivial stubs; the language is still reported).
    "MIN_LANGUAGE_BYTES": 200,
    # Ambiguous extensions require corroborating files before they count:
    #   .m   - Objective-C vs MATLAB/Mercury; needs Apple project evidence
    #   .cls - Apex vs LaTeX document class vs VB6; needs Salesforce evidence
    # (The Linguist API disambiguates these itself and is trusted as-is;
    # corroboration applies only to the extension fallback.)
    "APPLE_CORROBORATION_NAMES": ["podfile", "podfile.lock", "info.plist",
                                  "cartfile", "package.swift"],
    "APPLE_CORROBORATION_SUFFIXES": [".pbxproj", ".xcworkspacedata",
                                     ".xcscheme", ".swift", ".xcconfig"],
    "SALESFORCE_CORROBORATION_NAMES": ["sfdx-project.json"],
    "SALESFORCE_CORROBORATION_SEGMENTS": ["force-app", "classes", "triggers",
                                          "aura", "lwc"],
}

SECTION_KEYS = {
    "sast": "veracode_static_scan",
    "sca": "veracode_sca_scan",
    "iac": "veracode_iac_secrets_scan",
}

DISABLE_BLOCK = """{key}:
  push:
    trigger: false
  pull_request:
    trigger: false
"""


# ---------------------------------------------------------------------------
# Rate-limit-aware gh CLI wrapper
# ---------------------------------------------------------------------------

class GhError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str):
        self.cmd, self.returncode, self.stderr = cmd, returncode, stderr
        super().__init__(f"gh failed ({returncode}): {' '.join(cmd)}\n{stderr.strip()}")


class GhClient:
    """Wraps the gh CLI with throttling, retries, and rate limit awareness.

    - Enforces a minimum interval between API calls (primary rate hygiene).
    - Every `check_every` calls, queries /rate_limit and sleeps until reset
      if core remaining drops below `min_remaining`.
    - Exponential backoff with jitter on secondary rate limit / abuse
      detection responses and transient network errors.
    """

    TRANSIENT_MARKERS = ("timeout", "timed out", "connection reset", "connection refused",
                        "502", "503", "504", "temporarily unavailable")
    SECONDARY_MARKERS = ("secondary rate limit", "abuse detection",
                         "you have exceeded a secondary rate limit")
    PRIMARY_MARKERS = ("api rate limit exceeded",)

    def __init__(self, min_interval: float = 0.25, min_remaining: int = 100,
                 check_every: int = 50, max_retries: int = 6):
        self.min_interval = min_interval
        self.min_remaining = min_remaining
        self.check_every = check_every
        self.max_retries = max_retries
        self._last_call = 0.0
        self._calls_since_check = 0
        self.api_calls = 0

    def _throttle(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def _maybe_check_rate_limit(self) -> None:
        self._calls_since_check += 1
        if self._calls_since_check < self.check_every:
            return
        self._calls_since_check = 0
        try:
            out = self._run_once(["api", "rate_limit"])
            core = json.loads(out)["resources"]["core"]
            remaining, reset = core["remaining"], core["reset"]
            log.debug("Rate limit: %s remaining, resets at %s", remaining, reset)
            if remaining < self.min_remaining:
                sleep_for = max(reset - time.time(), 0) + 5
                log.warning("Rate limit low (%s remaining). Sleeping %.0fs until reset.",
                            remaining, sleep_for)
                time.sleep(sleep_for)
        except Exception as e:  # never let the health check kill the run
            log.debug("rate_limit check failed, continuing: %s", e)

    def _run_once(self, args: list[str]) -> str:
        self._throttle()
        proc = subprocess.run(["gh"] + args, capture_output=True, text=True)
        self.api_calls += 1
        if proc.returncode == 0:
            return proc.stdout
        raise GhError(["gh"] + args, proc.returncode, proc.stderr or "")

    def run(self, args: list[str], ok_statuses: tuple[int, ...] = ()) -> str:
        """Run a gh command. ok_statuses (e.g. 404) return "" instead of raising."""
        is_api = args and args[0] == "api"
        if is_api:
            self._maybe_check_rate_limit()
        for attempt in range(1, self.max_retries + 1):
            try:
                return self._run_once(args)
            except GhError as e:
                stderr = e.stderr.lower()
                for status in ok_statuses:
                    if f"http {status}" in stderr or f"({status})" in stderr:
                        return ""
                if any(m in stderr for m in self.SECONDARY_MARKERS):
                    wait = min(60 * attempt, 300) + random.uniform(0, 10)
                    log.warning("Secondary rate limit hit. Backing off %.0fs "
                                "(attempt %d/%d).", wait, attempt, self.max_retries)
                    time.sleep(wait)
                    continue
                if any(m in stderr for m in self.PRIMARY_MARKERS):
                    log.warning("Primary rate limit exhausted. Sleeping 60s and "
                                "re-checking.")
                    time.sleep(60)
                    self._calls_since_check = self.check_every  # force check
                    self._maybe_check_rate_limit()
                    continue
                if any(m in stderr for m in self.TRANSIENT_MARKERS) \
                        and attempt < self.max_retries:
                    wait = min(2 ** attempt, 30) + random.uniform(0, 2)
                    log.warning("Transient error, retrying in %.0fs: %s",
                                wait, e.stderr.strip()[:150])
                    time.sleep(wait)
                    continue
                raise
        raise GhError(["gh"] + args, -1, "retries exhausted")

    def json(self, args: list[str], **kw):
        out = self.run(args, **kw)
        return json.loads(out) if out.strip() else None


# ---------------------------------------------------------------------------
# Repo inspection
# ---------------------------------------------------------------------------

@dataclass
class RepoInfo:
    name: str
    default_branch: str
    languages: dict[str, int] = field(default_factory=dict)
    paths: list[str] = field(default_factory=list)
    tree_truncated: bool = False
    existing_veracode_sha: str | None = None  # blob sha of root veracode.yml


@dataclass
class ScanDecision:
    sast: bool
    sca: bool
    iac: bool
    runner: str | None = None  # e.g. "windows-latest"; None = central default
    reasons: dict[str, str] = field(default_factory=dict)


def list_org_repos(gh: GhClient, org: str) -> list[dict]:
    """Paginated org repo listing. No arbitrary ceiling."""
    out = gh.run(["api", "--paginate", f"orgs/{org}/repos?per_page=100&type=all",
                  "--jq", '.[] | {name, default_branch, archived, fork, size, disabled}'])
    repos = [json.loads(line) for line in out.splitlines() if line.strip()]
    log.info("Listed %d repos in %s (%d API pages so far)", len(repos), org,
             max(1, len(repos) // 100))
    return repos


def fetch_languages(gh: GhClient, org: str, repo: str) -> dict[str, int]:
    return gh.json(["api", f"repos/{org}/{repo}/languages"], ok_statuses=(404,)) or {}


def fetch_tree(gh: GhClient, org: str, repo: str, branch: str,
               recursive: bool = True) -> tuple[list[dict], bool]:
    url = f"repos/{org}/{repo}/git/trees/{quote(branch, safe='')}"
    if recursive:
        url += "?recursive=1"
    data = gh.json(["api", url], ok_statuses=(404, 409))  # 409 = empty repo
    if not data:
        return [], False
    entries = [e for e in data.get("tree", []) if e.get("type") == "blob"]
    return entries, bool(data.get("truncated"))


def inspect_repo(gh: GhClient, org: str, repo: dict) -> RepoInfo:
    name = repo["name"]
    branch = repo.get("default_branch") or "main"
    info = RepoInfo(name=name, default_branch=branch)
    info.languages = fetch_languages(gh, org, name)

    # HEAD always resolves the default branch regardless of branch naming
    # (slashes, unicode), unlike passing the branch name as a tree ref.
    entries, truncated = fetch_tree(gh, org, name, "HEAD", recursive=True)
    info.tree_truncated = truncated
    if truncated:
        # Recursive listing was cut off. Root-level files (where manifests and
        # most IaC entry points live) may be missing, so merge in a guaranteed
        # non-recursive root listing.
        root_entries, _ = fetch_tree(gh, org, name, "HEAD", recursive=False)
        seen = {e.get("path") for e in entries}
        entries += [e for e in root_entries if e.get("path") not in seen]
        log.warning("[%s] git tree truncated by API. Detection is best-effort; "
                    "scans are kept ENABLED when in doubt.", name)

    info.paths = [e.get("path", "") for e in entries]
    for e in entries:
        if e.get("path") == "veracode.yml":
            info.existing_veracode_sha = e.get("sha")
            break
    return info


def deep_iac_confirm(gh: GhClient, org: str, repo: str, branch: str,
                     candidates: list[str], max_files: int = 5) -> list[str]:
    """Download a few ambiguous root YAML/JSON files and grep for
    CloudFormation / Kubernetes markers. Costs 1 API call per file."""
    hits = []
    markers = ("awstemplateformatversion", "apiversion:", "kind:")
    for path in candidates[:max_files]:
        data = gh.json(["api", f"repos/{org}/{repo}/contents/{quote(path)}?ref={quote(branch, safe='')}"],
                       ok_statuses=(404,))
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            continue
        try:
            text = base64.b64decode(data.get("content", "")).decode(
                "utf-8", errors="ignore").lower()
        except Exception:
            continue
        if any(m in text for m in markers):
            hits.append(path)
    return hits


def scan_windows_signals(paths: list[str], mx: Matrices) -> tuple[set, set, list]:
    """Return (strong_hits, weak_hits, project_files) for Windows runner
    detection, ignoring vendored/generated paths (a packages.config inside a
    committed dependency must not force a Windows runner). project_files are
    .csproj/.vbproj/.fsproj paths sorted shallowest-first, the candidates for
    content inspection."""
    strong, weak, projects = set(), set(), []
    for p in paths:
        lp = p.lower()
        if not is_scannable_path(lp, mx):
            continue
        base = lp.rsplit("/", 1)[-1]
        if base in mx.windows_file_names or base.endswith(mx.windows_file_suffixes):
            strong.add(base)
        elif base in mx.windows_weak_names or base.endswith(mx.windows_weak_suffixes):
            weak.add(base)
        if base.endswith((".csproj", ".vbproj", ".fsproj")):
            projects.append(p)
    projects.sort(key=lambda p: (p.count("/"), p.lower()))
    return strong, weak, projects


def deep_dotnet_check(gh: GhClient, org: str, repo: str, branch: str,
                      project_paths: list[str], mx: Matrices,
                      max_files: int = 5) -> str | None:
    """Inspect project file contents to distinguish Windows-bound builds
    (.NET Framework, old-style msbuild, WPF/WinForms, net4x or *-windows
    TFMs) from portable SDK-style .NET. Returns the first Windows-marker
    path found, else None. Costs 1 API call per file, capped at max_files.
    Project files that fail to download or decode are skipped without
    concluding anything from them."""
    for path in project_paths[:max_files]:
        data = gh.json(["api", f"repos/{org}/{repo}/contents/{quote(path)}?ref={quote(branch, safe='')}"],
                       ok_statuses=(404,))
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            continue
        try:
            text = base64.b64decode(data.get("content", "")).decode(
                "utf-8", errors="ignore").lower()
        except Exception:
            continue
        if any(marker in text for marker in mx.windows_project_markers):
            return path
    return None


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

class Matrices:
    def __init__(self, overrides: dict | None = None):
        m = json.loads(json.dumps(DEFAULT_MATRICES))  # deep copy
        for key, val in (overrides or {}).items():
            if key not in m:
                raise ValueError(f"Unknown config key: {key}. "
                                 f"Valid keys: {sorted(m)}")
            m[key] = val
        self.sast_languages = set(m["SAST_LANGUAGES"])
        self.sast_not_autopackaged = set(m.get("SAST_PIPELINE_NOT_AUTOPACKAGED", []))
        self.sast_compiled_only = set(m.get("SAST_COMPILED_ONLY", []))
        self.sca_languages = set(m["SCA_LANGUAGES"])
        self.code_extensions = {k.lower(): v for k, v in m["CODE_EXTENSIONS"].items()}
        self.sca_manifest_names = {n.lower() for n in m["SCA_MANIFEST_NAMES"]}
        self.sca_manifest_suffixes = tuple(s.lower() for s in m["SCA_MANIFEST_SUFFIXES"])
        self.iac_file_names = {n.lower() for n in m["IAC_FILE_NAMES"]}
        self.iac_file_suffixes = tuple(s.lower() for s in m["IAC_FILE_SUFFIXES"])
        self.iac_name_prefixes = tuple(p.lower() for p in m["IAC_NAME_PREFIXES"])
        self.iac_dir_hints = tuple(d.lower() for d in m["IAC_DIR_HINTS"])
        self.iac_languages = set(m["IAC_LANGUAGES"])
        self.windows_file_names = {n.lower() for n in m.get("WINDOWS_FILE_NAMES", [])}
        self.windows_file_suffixes = tuple(
            s.lower() for s in m.get("WINDOWS_FILE_SUFFIXES", []))
        self.windows_weak_names = {n.lower() for n in m.get("WINDOWS_WEAK_FILE_NAMES", [])}
        self.windows_weak_suffixes = tuple(
            s.lower() for s in m.get("WINDOWS_WEAK_FILE_SUFFIXES", []))
        self.windows_project_markers = tuple(
            s.lower() for s in m.get("WINDOWS_PROJECT_MARKERS", []))
        self.vendored_segments = {s.lower() for s in m.get("VENDORED_PATH_SEGMENTS", [])}
        self.generated_suffixes = tuple(
            s.lower() for s in m.get("GENERATED_FILE_SUFFIXES", []))
        self.tooling_config_basenames = {
            n.lower() for n in m.get("TOOLING_CONFIG_BASENAMES", [])}
        self.min_language_bytes = int(m.get("MIN_LANGUAGE_BYTES", 0))
        self.apple_corr_names = {n.lower() for n in m.get("APPLE_CORROBORATION_NAMES", [])}
        self.apple_corr_suffixes = tuple(
            s.lower() for s in m.get("APPLE_CORROBORATION_SUFFIXES", []))
        self.sf_corr_names = {n.lower() for n in m.get("SALESFORCE_CORROBORATION_NAMES", [])}
        self.sf_corr_segments = {s.lower() for s in m.get("SALESFORCE_CORROBORATION_SEGMENTS", [])}


def is_scannable_path(lower_path: str, mx: Matrices) -> bool:
    """False for vendored/generated content that must not classify a repo:
    committed node_modules, build output, virtualenvs, minified bundles."""
    if lower_path.endswith(mx.generated_suffixes):
        return False
    for seg in lower_path.split("/")[:-1]:  # directory segments only
        if seg in mx.vendored_segments:
            return False
    return True


def filtered_entries(paths: list[str], mx: Matrices) -> list[tuple[str, str]]:
    """(lower_path, lower_basename) tuples for non-vendored paths."""
    out = []
    for p in paths:
        lp = p.lower()
        if is_scannable_path(lp, mx):
            out.append((lp, lp.rsplit("/", 1)[-1]))
    return out


def languages_from_extensions(entries: list[tuple[str, str]], mx: Matrices) -> set[str]:
    """Language detection fallback from file extensions, with two safeguards
    the Linguist API applies natively: tooling configs do not classify a repo
    (a Python repo with webpack.config.js is not a JavaScript project), and
    ambiguous extensions require corroboration (.m is MATLAB as often as
    Objective-C, .cls is a LaTeX class as often as Apex; enabling SAST on the
    wrong guess produces a failing, PR-blocking scan)."""
    apple_ok = any(
        base in mx.apple_corr_names or lp.endswith(mx.apple_corr_suffixes)
        for lp, base in entries)
    sf_ok = any(
        base in mx.sf_corr_names
        or any(seg in mx.sf_corr_segments for seg in lp.split("/")[:-1])
        for lp, base in entries)

    found = set()
    for lp, base in entries:
        if base in mx.tooling_config_basenames:
            continue
        dot = base.rfind(".")
        if dot == -1:
            continue
        ext = base[dot:]
        lang = mx.code_extensions.get(ext)
        if not lang:
            continue
        if ext == ".m" and not apple_ok:
            continue
        if ext in (".cls", ".trigger") and not sf_ok:
            continue
        found.add(lang)
    return found


def decide(info: RepoInfo, mx: Matrices,
           deep_iac_hits: list[str] | None = None,
           deep_dotnet_hit: str | None = None) -> ScanDecision:
    # Linguist languages below the byte threshold do not enable scans (a
    # 40-byte stub should not classify a repo); union with the extension scan
    # to catch empty/lagging API responses. Vendored and generated paths are
    # excluded from all file-based detection.
    langs = {l for l, b in info.languages.items()
             if b >= mx.min_language_bytes}
    entries = filtered_entries(info.paths, mx)
    ext_langs = languages_from_extensions(entries, mx)
    all_langs = langs | ext_langs
    has_submodules = any(p == ".gitmodules" for p in info.paths)

    # --- SAST (pipeline scan) ---
    sast_langs = all_langs & mx.sast_languages
    sast = bool(sast_langs)

    # --- SCA (agent-based) ---
    manifests = set()
    for _, base in entries:
        if base in mx.sca_manifest_names or base.endswith(mx.sca_manifest_suffixes):
            manifests.add(base)
        elif "requirements" in base and base.endswith(".txt"):
            # requirements-dev.txt, dev-requirements.txt, requirements_test.txt
            manifests.add(base)
    sca_langs = all_langs & mx.sca_languages
    # Require a supported ecosystem AND a resolvable manifest. An SCA agent run
    # without a build system fails and blocks PRs, which is what we are avoiding.
    sca = bool(sca_langs and manifests)
    if not sca and info.tree_truncated and sca_langs:
        sca = True  # cannot prove absence of manifests, stay enabled

    # --- IaC / container / secrets ---
    # Default: ON. The integration's IaC/secrets scan does secret detection
    # and runs on the repo contents with low failure risk. It is valuable
    # everywhere even without explicit IaC/container artifacts, so default
    # to enabled. Disable via --no-iac (sets both to false) if a specific
    # repo should never scan infrastructure (rare).
    iac = True
    iac_artifacts = set()
    for lp, base in entries:
        if base in mx.iac_file_names or base.endswith(mx.iac_file_suffixes) \
                or base.startswith(mx.iac_name_prefixes):
            iac_artifacts.add(base)
        elif lp.startswith(mx.iac_dir_hints) and lp.endswith((".yml", ".yaml", ".json")):
            iac_artifacts.add(lp)
    if all_langs & mx.iac_languages:
        iac_artifacts.add(f"languages:{sorted(all_langs & mx.iac_languages)}")
    if deep_iac_hits:
        iac_artifacts.update(deep_iac_hits)
    iac_reason = ("artifacts present" if iac_artifacts
                  else "no artifacts detected, kept enabled for secret scanning")
    if info.tree_truncated:
        iac_reason += "; tree truncated"

    if sast:
        sast_reason = f"languages={sorted(sast_langs)}"
    elif all_langs & mx.sast_not_autopackaged:
        sast_reason = (f"disabled by config tier SAST_PIPELINE_NOT_AUTOPACKAGED: "
                       f"{sorted(all_langs & mx.sast_not_autopackaged)}")
    elif all_langs & mx.sast_compiled_only:
        sast_reason = (f"disabled by config tier SAST_COMPILED_ONLY: "
                       f"{sorted(all_langs & mx.sast_compiled_only)}")
    else:
        sast_reason = f"no supported language (found: {sorted(all_langs)[:8]})"
        if has_submodules:
            sast_reason += ("; .gitmodules present, code may live in "
                            "submodules the integration cannot see")

    # --- Runner (default: runs_on) ---
    # Central default runner is ubuntu-latest. Windows is set only when a
    # build-based scan (SAST/SCA) is enabled AND either a strong signal or a
    # confirmed project-file marker is present. Weak signals alone never
    # force Windows; they trigger content inspection in the caller instead.
    strong_hits, weak_hits, _ = scan_windows_signals(info.paths, mx)
    if deep_dotnet_hit:
        strong_hits.add(f"project-marker:{deep_dotnet_hit}")
    runner = "windows-latest" if (strong_hits and (sast or sca)) else None
    if runner:
        runner_reason = f"windows signals={sorted(strong_hits)[:5]}"
    elif strong_hits:
        runner_reason = "windows signals present but no build-based scan enabled"
    elif weak_hits:
        runner_reason = (f"weak windows signals {sorted(weak_hits)[:5]} not "
                         f"confirmed by project inspection, kept on linux")
    else:
        runner_reason = "portable ecosystem, central default (linux)"
    if info.tree_truncated:
        runner_reason += "; tree truncated, runner detection best-effort"

    reasons = {
        "sast": sast_reason,
        "runner": runner_reason,
        "sca": (f"manifests={sorted(manifests)[:6]}, ecosystems={sorted(sca_langs)}"
                if (sca_langs and manifests)
                else ("tree truncated, ecosystem present, kept enabled" if sca
                      else "no supported ecosystem+manifest pair")),
        "iac": iac_reason,
    }
    return ScanDecision(sast=sast, sca=sca, iac=iac, runner=runner, reasons=reasons)


def ambiguous_root_yaml(info: RepoInfo, mx: Matrices) -> list[str]:
    """Root-level YAML/JSON not already classified as IaC, candidates for
    --deep-iac content confirmation."""
    out = []
    for p in info.paths:
        if "/" in p:
            continue
        lp = p.lower()
        if not lp.endswith((".yml", ".yaml", ".json")):
            continue
        base = lp.rsplit("/", 1)[-1]
        if base in mx.iac_file_names or base.startswith(mx.iac_name_prefixes):
            continue
        if base in ("package.json", "composer.json", "cdk.json", "tsconfig.json",
                    "package-lock.json", ".eslintrc.json"):
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------------------
# veracode.yml generation (minimal overrides only)
# ---------------------------------------------------------------------------

def build_override_yaml(decision: ScanDecision,
                        platform_analysis: str | None) -> str | None:
    """Return repo-level veracode.yml content, or None if no override needed.

    Only disabled sections (and, when detected, a Windows runner default) are
    written; everything else inherits the central veracode repo config.
    Disabling static triggers only stops PIPELINE scans; platform
    sandbox/policy scans follow analysis_on_platform, written only when
    --platform-analysis is passed.
    """
    parts = [
        "# Managed by script.py - do not edit by hand.",
        f"# Detection: SAST={decision.sast} ({decision.reasons['sast']})",
        f"#            SCA={decision.sca} ({decision.reasons['sca']})",
        f"#            IaC={decision.iac} ({decision.reasons['iac']})",
        f"#            Runner={decision.runner or 'default'} "
        f"({decision.reasons.get('runner', '')})",
        "",
    ]
    wrote_section = False
    if decision.runner:
        parts.append(f"default:\n  runs_on: {decision.runner}\n")
        wrote_section = True
    for kind, key in SECTION_KEYS.items():
        if not getattr(decision, kind):
            parts.append(DISABLE_BLOCK.format(key=key))
            wrote_section = True
        elif kind == "sast" and platform_analysis is not None:
            parts.append(f"{key}:\n  analysis_on_platform: {platform_analysis}\n")
            wrote_section = True
    return "\n".join(parts) if wrote_section else None


def git_blob_sha(content: str) -> str:
    raw = content.encode()
    return hashlib.sha1(b"blob %d\x00" % len(raw) + raw).hexdigest()


# ---------------------------------------------------------------------------
# Delivery: commit / PR
# ---------------------------------------------------------------------------

def create_branch(gh: GhClient, org: str, repo: str, base: str, new: str) -> bool:
    head = gh.json(["api", f"repos/{org}/{repo}/git/ref/heads/{quote(base, safe='')}"],
                   ok_statuses=(404,))
    if not head:
        log.error("[%s] cannot resolve head of %s", repo, base)
        return False
    if gh.json(["api", f"repos/{org}/{repo}/git/ref/heads/{quote(new, safe='')}"], ok_statuses=(404,)):
        log.info("[%s] branch %s already exists, reusing", repo, new)
        return True
    gh.run(["api", "-X", "POST", f"repos/{org}/{repo}/git/refs",
            "-f", f"ref=refs/heads/{new}", "-f", f"sha={head['object']['sha']}"])
    return True


def get_file_sha_on_ref(gh: GhClient, org: str, repo: str, ref: str) -> str | None:
    data = gh.json(["api", f"repos/{org}/{repo}/contents/veracode.yml?ref={quote(ref, safe='')}"],
                   ok_statuses=(404,))
    return data.get("sha") if isinstance(data, dict) else None


def put_file(gh: GhClient, org: str, repo: str, branch: str, content: str,
             existing_sha: str | None, message: str) -> None:
    args = ["api", "-X", "PUT", f"repos/{org}/{repo}/contents/veracode.yml",
            "-f", f"message={message}",
            "-f", f"content={base64.b64encode(content.encode()).decode()}",
            "-f", f"branch={branch}"]
    if existing_sha:
        args += ["-f", f"sha={existing_sha}"]
    gh.run(args)


def open_pr(gh: GhClient, org: str, repo: str, base: str, head: str,
            decision: ScanDecision) -> str:
    existing = gh.run(["pr", "list", "-R", f"{org}/{repo}", "--head", head,
                       "--state", "open", "--json", "url", "--jq", ".[0].url"])
    if existing.strip():
        return existing.strip()
    body = (
        "Automated Veracode scan scoping.\n\n"
        + "\n".join(
            f"- **{k.upper()}**: {'enabled' if getattr(decision, k) else 'disabled'}"
            f" ({decision.reasons[k]})" for k in SECTION_KEYS)
        + f"\n- **Runner**: {decision.runner or 'central default'}"
          f" ({decision.reasons.get('runner', '')})"
        + "\n\nNote: static push/pr triggers only control pipeline scans. Platform "
          "sandbox/policy scans are governed by analysis_on_platform and are "
          "not changed by this file unless explicitly set."
    )
    out = gh.run(["pr", "create", "-R", f"{org}/{repo}", "--base", base,
                  "--head", head,
                  "--title", "Scope Veracode scans to relevant scan types",
                  "--body", body])
    return out.strip()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", required=True, help="GitHub organization")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print decisions and generated YAML, change nothing")
    ap.add_argument("--direct-commit", action="store_true",
                    help="Commit to the default branch instead of opening a PR")
    ap.add_argument("--branch-name", default="chore/veracode-scan-scoping")
    ap.add_argument("--include", nargs="*", default=["*"],
                    help="Glob patterns of repos to include")
    ap.add_argument("--exclude", nargs="*", default=["veracode"],
                    help="Glob patterns to skip (central 'veracode' repo by default)")
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite an existing repo-level veracode.yml")
    ap.add_argument("--no-iac", action="store_true",
                    help="Disable the IaC/secrets scan for all repos. By default "
                         "IaC is enabled for secret detection even without IaC "
                         "artifacts.")
    ap.add_argument("--deep-iac", action="store_true",
                    help="Download a few ambiguous root YAML/JSON files to confirm "
                         "CloudFormation/Kubernetes content (extra API calls)")
    ap.add_argument("--runner", choices=["auto", "off"], default="auto",
                    help="auto (default): write 'default: runs_on: windows-latest' "
                         "when Windows build signals are confirmed and a "
                         "build-based scan is enabled. Weak signals (xaml, "
                         "web.config, vbproj/fsproj) automatically trigger "
                         "project-file inspection. off: never write runs_on.")
    ap.add_argument("--deep-dotnet", action="store_true",
                    help="Extend project-file inspection to every repo with "
                         ".csproj/.vbproj/.fsproj files, even without weak "
                         "surface signals. Catches SDK-style projects that "
                         "target net4x or *-windows TFMs (extra API calls, "
                         "up to 5 per repo)")
    ap.add_argument("--platform-analysis", choices=["true", "false"], default=None,
                    help="Also pin analysis_on_platform for SAST-relevant repos. "
                         "Untouched by default.")
    ap.add_argument("--config", default=None,
                    help="JSON file overriding detection matrices "
                         "(keys: " + ", ".join(sorted(DEFAULT_MATRICES)) + ")")
    ap.add_argument("--report", default=None, help="Write a JSON audit report here")
    ap.add_argument("--min-interval", type=float, default=0.25,
                    help="Minimum seconds between GitHub API calls (default 0.25)")
    ap.add_argument("--min-remaining", type=int, default=100,
                    help="Sleep until reset when core rate limit drops below this")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    overrides = None
    if args.config:
        with open(args.config) as f:
            overrides = json.load(f)
    try:
        mx = Matrices(overrides)
    except ValueError as e:
        log.error("%s", e)
        return 2

    gh = GhClient(min_interval=args.min_interval, min_remaining=args.min_remaining)
    try:
        gh.run(["auth", "status"])
    except (GhError, FileNotFoundError) as e:
        log.error("gh CLI not available or not authenticated: %s", e)
        return 2

    repos = list_org_repos(gh, args.org)
    summary = {"scoped": [], "no_change": [], "unchanged_identical": [],
               "skipped": [], "failed": []}
    report: list[dict] = []

    for repo in repos:
        name = repo["name"]
        if not matches_any(name, args.include) or matches_any(name, args.exclude):
            summary["skipped"].append((name, "filtered")); continue
        if repo.get("archived") and not args.include_archived:
            summary["skipped"].append((name, "archived")); continue
        if repo.get("fork") and not args.include_forks:
            summary["skipped"].append((name, "fork")); continue
        if repo.get("disabled"):
            summary["skipped"].append((name, "disabled")); continue
        if repo.get("size") == 0:
            summary["skipped"].append((name, "empty")); continue

        try:
            info = inspect_repo(gh, args.org, repo)
            if not info.paths and not info.languages:
                summary["skipped"].append((name, "no readable content")); continue

            deep_hits = None
            if args.deep_iac:
                cands = ambiguous_root_yaml(info, mx)
                if cands:
                    deep_hits = deep_iac_confirm(gh, args.org, name,
                                                 info.default_branch, cands)

            dotnet_hit = None
            if args.runner == "auto":
                strong_sig, weak_sig, proj_files = scan_windows_signals(
                    info.paths, mx)
                # Automatic: weak signals need confirmation before Windows is
                # ever chosen, so inspect project files whenever weak signals
                # exist without a strong one. --deep-dotnet extends inspection
                # to ALL repos with project files (catches Framework-targeting
                # SDK-style projects with zero surface signals).
                if not strong_sig and proj_files and (weak_sig or args.deep_dotnet):
                    dotnet_hit = deep_dotnet_check(gh, args.org, name,
                                                   info.default_branch,
                                                   proj_files, mx)

            decision = decide(info, mx, deep_hits, dotnet_hit)
            if args.no_iac:
                decision.iac = False
            if args.runner == "off":
                decision.runner = None
            content = build_override_yaml(decision, args.platform_analysis)

            log.info("[%s] SAST=%s SCA=%s IaC=%s runner=%s", name,
                     decision.sast, decision.sca, decision.iac,
                     decision.runner or "default")
            for k in SECTION_KEYS:
                log.debug("[%s]   %s: %s", name, k, decision.reasons[k])

            report.append({"repo": name, "default_branch": info.default_branch,
                           "languages": info.languages,
                           "tree_truncated": info.tree_truncated,
                           "decision": asdict(decision),
                           "override_written": content is not None})

            if content is None:
                summary["no_change"].append(name)
                log.info("[%s] all default scans relevant, no override needed", name)
                continue

            if info.existing_veracode_sha:
                if git_blob_sha(content) == info.existing_veracode_sha:
                    summary["unchanged_identical"].append(name)
                    log.info("[%s] existing veracode.yml already matches, skipping", name)
                    continue
                if not args.force:
                    summary["skipped"].append(
                        (name, "veracode.yml exists with different content (use --force)"))
                    continue

            if args.dry_run:
                print(f"\n===== {name} (dry run) =====\n{content}")
                summary["scoped"].append((name, "dry-run"))
                continue

            msg = "chore: scope Veracode scans to relevant scan types"
            if args.direct_commit:
                put_file(gh, args.org, name, info.default_branch, content,
                         info.existing_veracode_sha, msg)
                summary["scoped"].append((name, f"committed to {info.default_branch}"))
            else:
                if not create_branch(gh, args.org, name, info.default_branch,
                                     args.branch_name):
                    summary["failed"].append((name, "branch creation failed")); continue
                branch_sha = get_file_sha_on_ref(gh, args.org, name, args.branch_name)
                put_file(gh, args.org, name, args.branch_name, content, branch_sha, msg)
                url = open_pr(gh, args.org, name, info.default_branch,
                              args.branch_name, decision)
                summary["scoped"].append((name, url))
        except GhError as e:
            log.error("[%s] %s", name, e)
            summary["failed"].append((name, str(e)[:200]))
        except Exception as e:  # never let one repo kill an org-wide run
            log.exception("[%s] unexpected error", name)
            summary["failed"].append((name, f"{type(e).__name__}: {e}"))

    if args.report:
        with open(args.report, "w") as f:
            json.dump({"org": args.org, "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                       time.gmtime()), "api_calls": gh.api_calls,
                       "repos": report}, f, indent=2)
        log.info("Audit report written to %s", args.report)

    print("\n========== SUMMARY ==========")
    for key, label in (("scoped", "Scoped (override written/PR)"),
                       ("no_change", "No change needed"),
                       ("unchanged_identical", "Already correct (identical file)"),
                       ("skipped", "Skipped"),
                       ("failed", "Failed")):
        items = summary[key]
        print(f"{label}: {len(items)}")
        for it in items:
            print(f"  {it[0]}: {it[1]}" if isinstance(it, tuple) else f"  {it}")
    print(f"Total GitHub API calls: {gh.api_calls}")
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
