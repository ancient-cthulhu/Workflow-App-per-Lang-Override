#!/usr/bin/env python3
"""
Requirements: an authenticated gh CLI (GH_TOKEN, GITHUB_TOKEN, or `gh auth
login`) with scopes repo, workflow, read:org. Python 3.9+, stdlib only.

Usage:
  python3 script.py --org my-org --dry-run --report audit.json
  python3 script.py --org my-org
  python3 script.py --org my-org --iac artifacts --direct-commit
  python3 script.py --org my-org --resume-from run1.json --report run2.json

Tests:
  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import argparse
import base64
import csv
import fnmatch
import hashlib
import json
import logging
import os
import random
import re
import subprocess
import sys
import time
from collections import deque
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
    # Also NOT included, see the disable tiers below: COBOL, Swift,
    # Objective-C. They are Pipeline Scan languages, but the integration's
    # own build cannot produce an artifact for them.
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
        "C", "C++",
    ],
    # Disable tiers. A language listed here does not enable SAST, and the
    # tier name plus its explanation is recorded in the file header, PR
    # body, and report. Move languages between SAST_LANGUAGES and these
    # tiers via --config ("+KEY" / "-KEY") as the integration evolves.
    #   SAST_PIPELINE_NOT_AUTOPACKAGED - the integration's pipeline build
    #     skips the packager. Verified in veracode/github-actions-integration
    #     (veracode-default-build.yml): pipeline builds run
    #     "veracode package ... --skip-packagers sql,cobol" and the upload
    #     step uses if-no-files-found: error, so a COBOL-only repo fails.
    #   SAST_NO_SUPPORTED_RUNNER - packaging needs a build host the
    #     integration does not provide. Apple packaging requires Xcode
    #     (macOS); the integration's build has Linux and Windows jobs only.
    #   SAST_COMPILED_ONLY - need preprocessed/compiled artifacts.
    "SAST_PIPELINE_NOT_AUTOPACKAGED": ["COBOL"],
    "SAST_NO_SUPPORTED_RUNNER": ["Swift", "Objective-C"],
    "SAST_COMPILED_ONLY": [],
    # Languages that only count toward SAST when a build system is present.
    # C/C++ autopackaging needs make/ninja/bitbake and a successful compile
    # (MSVC projects are handled by the Windows runner). Headers or a few
    # sources without any build definition have nothing to build and the
    # pipeline scan fails. Truncated trees fail open.
    "SAST_BUILD_EVIDENCE": {
        "C": {"names": ["makefile", "gnumakefile", "cmakelists.txt",
                        "meson.build", "build.ninja", "configure.ac",
                        "configure", "sconstruct"],
              "suffixes": [".vcxproj", ".vcproj", ".mk", ".bb"]},
        "C++": {"names": ["makefile", "gnumakefile", "cmakelists.txt",
                          "meson.build", "build.ninja", "configure.ac",
                          "configure", "sconstruct"],
                "suffixes": [".vcxproj", ".vcproj", ".mk", ".bb"]},
    },
    # Linguist reports some languages under their own names rather than the
    # group name (TSX, Objective-C++, ColdFusion CFC, Java Server Pages).
    # They are folded into the canonical name before any decision.
    "LANGUAGE_ALIASES": {
        "TSX": "TypeScript",
        "Objective-C++": "Objective-C",
        "ColdFusion CFC": "ColdFusion",
        "Java Server Pages": "Java",
    },
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
        ".c": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
        ".hpp": "C++", ".hh": "C++", ".h": "C",
        ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C",
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
    # in the agent support table. Exact lowercase basenames. These are all
    # DETECTED and reported, but only manifests belonging to a group in
    # SCA_ECOSYSTEM_MAP whose languages are in SCA_LANGUAGES ENABLE SCA.
    # Gemfile, Podfile and Makefile are listed so the report can say "found
    # but not integration-supported"; they never enable SCA on their own.
    "SCA_MANIFEST_NAMES": [
        # Java/Kotlin/Scala: Maven, Gradle, Ant/Ivy, SBT (+ wrappers, catalogs)
        "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
        "settings.gradle.kts", "gradle.lockfile", "build.sbt", "ivy.xml",
        "build.xml", "gradlew", "mvnw", "libs.versions.toml",
        # JavaScript/TypeScript: NPM, Yarn, pnpm, Bower
        "package.json", "package-lock.json", "npm-shrinkwrap.json",
        "yarn.lock", "bower.json", "pnpm-lock.yaml", "pnpm-workspace.yaml",
        # Python: pip, Pipenv, Poetry, uv, PDM (requirements*.txt also
        # matched by rule)
        "requirements.txt", "pipfile", "pipfile.lock", "pyproject.toml",
        "setup.py", "setup.cfg", "poetry.lock", "uv.lock", "pdm.lock",
        # Go: Go modules/workspaces, Dep, Glide, GoDep, GoVendor, Trash
        "go.mod", "go.sum", "go.work", "go.work.sum",
        "gopkg.toml", "gopkg.lock",
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
    # Build-support files that belong to an ecosystem but do not declare a
    # resolvable dependency tree on their own. They are reported and count
    # toward pairing, but never enable SCA alone: a repo whose only .NET file
    # is global.json, or whose only Python file is a setup.cfg holding
    # flake8 settings, makes the agent fail with "no build system found".
    "SCA_SUPPORTING_NAMES": [
        "global.json", "directory.build.props", "directory.packages.props",
        "gradlew", "mvnw", "libs.versions.toml", "setup.cfg",
        "pnpm-workspace.yaml", "go.work.sum",
    ],
    "SCA_SUPPORTING_SUFFIXES": [".sln"],
    # Basenames never treated as dependency evidence. Build-tool wrapper jars
    # ship with every Gradle/Maven project (including React Native and
    # Flutter android/ folders) and are not application dependencies.
    "SCA_IGNORED_NAMES": ["gradle-wrapper.jar", "maven-wrapper.jar"],
    # Manifest -> ecosystem map. This is what ENABLES SCA: at least one
    # non-supporting manifest from a group whose languages intersect
    # SCA_LANGUAGES. The ecosystem is taken from the manifest itself, so a
    # notebook repo with requirements.txt (Linguist: "Jupyter Notebook") is
    # still scanned. Language pairing is recorded for explainability only:
    # a stray pom.xml in a Python repo is still a real, resolvable
    # dependency tree (fail-open), and the reason says it was unpaired.
    # To scan ecosystems the integration does not support (for example
    # Ruby when running the agent elsewhere), add a group here and its
    # language to SCA_LANGUAGES via --config.
    "SCA_ECOSYSTEM_MAP": {
        "java": {
            "languages": ["Java", "Kotlin", "Groovy", "Scala"],
            "names": ["pom.xml", "build.gradle", "build.gradle.kts",
                      "settings.gradle", "settings.gradle.kts",
                      "gradle.lockfile", "build.sbt", "ivy.xml", "build.xml",
                      "gradlew", "mvnw", "libs.versions.toml"],
            "suffixes": [".sbt", ".jar"],
        },
        "javascript": {
            "languages": ["JavaScript", "TypeScript", "Vue", "JSX", "Svelte"],
            "names": ["package.json", "package-lock.json",
                      "npm-shrinkwrap.json", "yarn.lock", "bower.json",
                      "pnpm-lock.yaml", "pnpm-workspace.yaml"],
            "suffixes": [],
        },
        "python": {
            "languages": ["Python"],
            "names": ["requirements.txt", "pipfile", "pipfile.lock",
                      "pyproject.toml", "setup.py", "setup.cfg",
                      "poetry.lock", "uv.lock", "pdm.lock"],
            "suffixes": [],
        },
        "go": {
            "languages": ["Go"],
            "names": ["go.mod", "go.sum", "go.work", "go.work.sum",
                      "gopkg.toml", "gopkg.lock", "glide.yaml", "glide.lock",
                      "trash.lock", "vendor.json", "godeps.json",
                      "godeps.lock"],
            "suffixes": [],
        },
        "php": {
            "languages": ["PHP"],
            "names": ["composer.json", "composer.lock"],
            "suffixes": [],
        },
        "dotnet": {
            "languages": ["C#", "F#", "Visual Basic .NET", "ASP.NET"],
            "names": ["packages.config", "project.json",
                      "directory.build.props", "directory.packages.props",
                      "global.json"],
            "suffixes": [".csproj", ".fsproj", ".vbproj", ".sln",
                         ".nuspec", ".dll"],
        },
    },
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
    "WINDOWS_WEAK_FILE_NAMES": ["app.xaml", "web.config", "app.config"],
    "WINDOWS_WEAK_FILE_SUFFIXES": [".xaml", ".vbproj", ".fsproj"],
    "WINDOWS_PROJECT_MARKERS": [
        "<targetframeworkversion>",          # old-style Framework project
        "toolsversion=",                     # old-style msbuild project
        "schemas.microsoft.com/developer/msbuild/2003",  # old project xmlns
        "<usewpf>true",                      # WPF (Windows desktop)
        "<usewindowsforms>true",             # WinForms (Windows desktop)
        "<targetframework>net4",             # SDK-style targeting Framework
        "<targetframeworks>net4",
    ],
    # Windows TFMs (net8.0-windows etc.) are matched with a regex anchored
    # inside <TargetFramework(s)> element content, not a raw substring: a
    # loose "-windows<" marker false-matches prose like
    # <PackageTags>non-windows</PackageTags> and forces a portable project
    # onto a Windows runner.
    "WINDOWS_TFM_REGEX": r"<targetframeworks?>[^<]*-windows",
    # Strong Windows file signals only take effect when the repo shows
    # .NET/C++ evidence (language or project files). Without this gate a
    # stray sample .aspx or a file named *.master in a Python or Java repo
    # flips the whole repo onto windows-latest.
    "WINDOWS_CORROBORATION_LANGUAGES": [
        "C#", "F#", "Visual Basic .NET", "ASP.NET", "C", "C++",
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
        "vendor", "vendors", "third_party", "third-party",
        "dist", "build", "out", "output", "target",
        "bin", "obj",
        ".venv", "venv", "__pycache__", "site-packages", ".tox", ".eggs",
        "pods", "carthage", "deriveddata",
        ".terraform", ".gradle", ".mvn", ".idea", ".vscode",
        "coverage", ".nyc_output",
    ],
    # Segments excluded ONLY from language classification, not from
    # manifest/IaC/Windows-signal detection. Rationale: 'env' is usually a
    # virtualenv (thousands of vendored .py files that must not classify the
    # repo) but Terraform repos legitimately keep env/prod/main.tf, and
    # 'external' sometimes holds real first-party code with real manifests.
    # Linguist itself does not treat these as vendored, so excluding them
    # from manifest detection produced incorrect SCA disables.
    "CLASSIFICATION_VENDORED_SEGMENTS": ["env", "external", "externals"],
    # Suffixes of generated/minified files excluded from extension-language
    # detection (a repo whose only JS is bundled output is not a JS project).
    "GENERATED_FILE_SUFFIXES": [".min.js", ".bundle.js", ".chunk.js",
                                ".min.mjs", ".pb.go", "_pb2.py", ".g.cs",
                                ".designer.cs", ".generated.cs",
                                ".d.ts", ".pb.cc", ".pb.h", "_pb.js"],
    # Build-tool configuration files excluded from language classification.
    # A repo whose only .js/.ts files are these is not a JavaScript project
    # (docs sites, Python repos with frontend tooling). Linguist does NOT
    # exclude these files itself, so their tree sizes are also subtracted
    # from the Linguist byte counts before MIN_LANGUAGE_BYTES is applied.
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
        # Gradle Kotlin-DSL build scripts are build configuration, not
        # application Kotlin: a Java repo with build.gradle.kts is not a
        # Kotlin project. They stay in SCA_MANIFEST_NAMES, which is a
        # separate list, so SCA detection is unaffected.
        "build.gradle.kts", "settings.gradle.kts",
    ],
    # Tooling config stems expanded against every JS/TS module extension at
    # load time (webpack.config.ts, vite.config.mjs, ...). The exact-name
    # list above covers only the shapes that don't follow the
    # <tool>.config.<ext> pattern (gulpfile.js, karma.conf.js, .eslintrc.*).
    "TOOLING_CONFIG_STEMS": [
        "webpack.config", "babel.config", "jest.config", "rollup.config",
        "vite.config", "vitest.config", "tailwind.config", "postcss.config",
        "next.config", "nuxt.config", "metro.config", "svelte.config",
        "playwright.config", "cypress.config", "prettier.config",
        "eslint.config", "commitlint.config", "stylelint.config",
        "tsup.config", "astro.config",
    ],
    # Framework scaffolding: when the ROOT marker file exists, the listed
    # top-level directories hold generated platform runners, not first-party
    # code, and are excluded from language classification (Linguist bytes
    # are subtracted), SCA manifest detection, and Windows signals. A
    # `flutter create` app otherwise shows ~20 KB of C++ (windows/, linux/),
    # Swift (ios/, macos/), Kotlin and a Gradle build (android/) that needs
    # the Flutter SDK, which enables SAST and SCA scans that cannot build.
    "FRAMEWORK_PLATFORM_DIRS": {
        "pubspec.yaml": ["android", "ios", "linux", "macos", "windows", "web"],
    },
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

# issues.trigger is disabled too: the reference central config has an
# issue-comment trigger per scan ("Veracode Static Scan" etc.), and an org
# that turns it on would otherwise still run the irrelevant scan on demand.
DISABLE_BLOCK = """{key}:
  push:
    trigger: false
  pull_request:
    trigger: false
"""
ISSUES_DISABLE = """  issues:
    trigger: false
"""

# First line of every generated file. Files carrying it (or the legacy
# "# Detection:" header written by earlier versions) are owned by this tool:
# they are updated when the decision changes and removed when no override is
# needed any more. Files without it are hand-written and never modified
# unless --force is passed.
MANAGED_MARKER = "# managed-by: veracode-scan-scoping"
LEGACY_MANAGED_PREFIX = "# Detection:"

# Runner labels are written verbatim into YAML. Restrict them to what
# GitHub runner labels and a YAML flow list can contain, so a --windows-runner
# value can never inject extra configuration.
RUNNER_LABEL_RE = re.compile(r"^(\[[A-Za-z0-9_.\-, ]+\]|[A-Za-z0-9_.\-]+)$")


def yaml_body(text: str) -> str:
    """Configuration content with comments and blank lines removed. Used to
    decide whether an existing file is already correct: the header comment
    carries detection reasons (file lists, truncation notes) that change
    without changing any setting, and must not cause churn."""
    lines = []
    for line in text.replace("\r\n", "\n").split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines)


def is_managed(text: str) -> bool:
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.strip():
            s = line.strip()
            return s.startswith(MANAGED_MARKER) or s.startswith(LEGACY_MANAGED_PREFIX)
    return False


# ---------------------------------------------------------------------------
# Rate-limit-aware gh CLI wrapper
# ---------------------------------------------------------------------------

class GhError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str,
                 stdout: str = ""):
        self.cmd, self.returncode, self.stderr = cmd, returncode, stderr
        self.stdout = stdout  # gh api graphql prints partial data here
        super().__init__(f"gh failed ({returncode}): {' '.join(cmd)}\n{stderr.strip()}")


class GhClient:
    """Wraps the gh CLI with throttling, retries, and rate limit awareness.

    - Enforces a minimum interval between API calls (primary rate hygiene).
    - Paces write requests separately (POST/PUT/PATCH/DELETE and
      `gh pr create`): GitHub's secondary limits allow roughly 80
      content-generating requests per minute and 500 per hour, and PR mode
      makes up to 3 writes per repo. Without pacing an org-wide rollout
      hits the hourly cap, backs off for ~20 minutes, and marks repos
      failed while the window is still closed.
    - Every `check_every` calls, queries /rate_limit and sleeps until reset
      if core remaining drops below `min_remaining`.
    - Every gh invocation has a timeout, so one stalled connection cannot
      hang an org-wide run. Timeouts are retried like transient errors;
      every write path in this script is idempotent on retry.
    - Exponential backoff with jitter on secondary rate limit / abuse
      detection responses and transient network errors.
    """

    TRANSIENT_RE = re.compile(
        r"\bhttp 50[0234]\b|timed out|timeout|connection reset|"
        r"connection refused|temporarily unavailable|bad gateway|"
        r"service unavailable|unexpected eof|tls handshake")
    SECONDARY_RE = re.compile(
        r"secondary rate limit|abuse detection|\bhttp 429\b")
    PRIMARY_MARKERS = ("api rate limit exceeded",)
    WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

    def __init__(self, min_interval: float = 0.25, min_remaining: int = 100,
                 check_every: int = 50, max_retries: int = 6,
                 timeout: float = 120.0, write_interval: float = 1.0,
                 writes_per_hour: int = 450):
        self.min_interval = min_interval
        self.min_remaining = min_remaining
        self.check_every = check_every
        self.max_retries = max_retries
        self.timeout = timeout
        self.write_interval = write_interval
        self.writes_per_hour = writes_per_hour
        self._last_call = 0.0
        self._last_write = 0.0
        self._write_times: deque[float] = deque()
        self._calls_since_check = 0
        self.api_calls = 0
        self.write_calls = 0

    @classmethod
    def is_write(cls, args: list[str]) -> bool:
        if args[:2] in (["pr", "create"], ["pr", "close"]):
            return True
        for i, a in enumerate(args[:-1]):
            if a in ("-X", "--method") and args[i + 1].upper() in cls.WRITE_METHODS:
                return True
        return False

    def _throttle(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def _pace_write(self) -> None:
        now = time.monotonic()
        while self._write_times and now - self._write_times[0] >= 3600:
            self._write_times.popleft()
        if self.writes_per_hour > 0 and len(self._write_times) >= self.writes_per_hour:
            sleep_for = 3600 - (now - self._write_times[0]) + 1
            log.warning("Write budget of %d/hour reached (GitHub secondary "
                        "limit hygiene). Sleeping %.0fs.", self.writes_per_hour,
                        sleep_for)
            time.sleep(sleep_for)
            self._write_times.popleft()
        wait = self.write_interval - (time.monotonic() - self._last_write)
        if wait > 0:
            time.sleep(wait)
        self._last_write = time.monotonic()
        self._write_times.append(self._last_write)
        self.write_calls += 1

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
        if self.is_write(args):
            self._pace_write()
        self.api_calls += 1
        try:
            proc = subprocess.run(["gh"] + args, capture_output=True, text=True,
                                  timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            raise GhError(["gh"] + args, -1,
                          f"gh timed out after {self.timeout:.0f}s", out)
        if proc.returncode == 0:
            return proc.stdout
        raise GhError(["gh"] + args, proc.returncode, proc.stderr or "",
                      proc.stdout or "")

    def run(self, args: list[str], ok_statuses: tuple[int, ...] = ()) -> str:
        """Run a gh command. ok_statuses (e.g. 404) return "" instead of raising."""
        is_api = args and args[0] == "api"
        if is_api:
            self._maybe_check_rate_limit()
        last: GhError | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return self._run_once(args)
            except GhError as e:
                last = e
                stderr = e.stderr.lower()
                for status in ok_statuses:
                    # Word-bounded match on gh's "HTTP 404" error format. The
                    # previous loose "(404)" substring could swallow unrelated
                    # errors whose message merely contained the number.
                    if re.search(rf"\bhttp {status}\b", stderr):
                        log.debug("Treating HTTP %s as absence: %s",
                                  status, " ".join(e.cmd))
                        return ""
                if self.SECONDARY_RE.search(stderr):
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
                if self.TRANSIENT_RE.search(stderr) and attempt < self.max_retries:
                    wait = min(2 ** attempt, 30) + random.uniform(0, 2)
                    log.warning("Transient error, retrying in %.0fs: %s",
                                wait, e.stderr.strip()[:150])
                    time.sleep(wait)
                    continue
                raise
        raise GhError(["gh"] + args, -1, "retries exhausted; last error: "
                      + (last.stderr.strip()[:300] if last else ""))

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
    sizes: dict[str, int | None] = field(default_factory=dict)  # path -> blob size
    tree_truncated: bool = False
    existing_veracode_sha: str | None = None  # blob sha of root veracode.yml


@dataclass
class ScanDecision:
    sast: bool
    sca: bool
    iac: bool
    runner: str | None = None  # e.g. "windows-latest"; None = central default
    reasons: dict[str, str] = field(default_factory=dict)
    # Full, untruncated evidence behind every decision, for the JSON report.
    # Reason strings truncate lists for readability; audits need everything.
    evidence: dict = field(default_factory=dict)


_CTRL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")


def sanitize(s: str) -> str:
    """Strip control characters (incl. newlines) from repo-derived strings.

    Git tree paths may legally contain newlines. Reason strings built from
    file basenames are embedded into veracode.yml header comments, PR bodies,
    and log lines; without this, a crafted filename can break out of a YAML
    comment and inject live configuration into the committed override."""
    return _CTRL_CHARS.sub(" ", s)


def list_org_repos(gh: GhClient, org: str) -> list[dict]:
    """Paginated org repo listing. No arbitrary ceiling."""
    out = gh.run(["api", "--paginate", f"orgs/{org}/repos?per_page=100&type=all",
                  "--jq", '.[] | {name, default_branch, archived, fork, size, disabled}'])
    repos = [json.loads(line) for line in out.splitlines() if line.strip()]
    log.info("Listed %d repos in %s (%d API pages)", len(repos), org,
             max(1, (len(repos) + 99) // 100))
    return repos


def fetch_languages(gh: GhClient, org: str, repo: str) -> dict[str, int]:
    return gh.json(["api", f"repos/{org}/{repo}/languages"], ok_statuses=(404,)) or {}


def _parse_language_batch(payload: dict, group: list[str],
                          out: dict[str, dict[str, int]]) -> None:
    for j, n in enumerate(group):
        node = payload.get(f"r{j}")
        if not isinstance(node, dict):
            continue  # per-repo GraphQL error -> REST fallback for this repo
        langs: dict[str, int] = {}
        for edge in ((node.get("languages") or {}).get("edges") or []):
            lang = ((edge or {}).get("node") or {}).get("name")
            if lang:
                langs[lang] = langs.get(lang, 0) + int(edge.get("size") or 0)
        out[n] = langs


def batch_fetch_languages(gh: GhClient, org: str, names: list[str],
                          chunk: int = 40) -> dict[str, dict[str, int]]:
    """Fetch language data for many repos per API call via aliased GraphQL
    queries, instead of one REST call per repo. For a 20k-repo org this is
    the difference between finishing inside the rate limit and sleeping for
    hours.

    Batching is an optimization, never a source of truth for absence: any
    repo missing from the result (renamed, inaccessible, whole-batch
    failure) silently falls back to the per-repo REST call in inspect_repo.
    gh exits non-zero when a GraphQL response contains an errors array but
    still prints the partial data body to stdout, so per-repo errors inside
    an otherwise good batch are salvaged rather than discarding the chunk."""
    out: dict[str, dict[str, int]] = {}
    hard_failures = 0
    for i in range(0, len(names), chunk):
        if hard_failures >= 2:
            # GraphQL endpoint is unhealthy; each failed chunk costs a full
            # retry ladder. Stop probing and let every remaining repo use
            # the per-repo REST path instead.
            log.warning("GraphQL batching disabled after %d consecutive "
                        "failures; remaining %d repos use REST.",
                        hard_failures, len(names) - i)
            break
        group = names[i:i + chunk]
        parts = [
            f"r{j}: repository(owner: {json.dumps(org)}, name: {json.dumps(n)}) "
            # Explicit SIZE DESC order: the schema defines no default order,
            # so a plain first:N could drop the dominant language on repos
            # with many small ones. 100 matches the REST endpoint's output.
            "{ languages(first: 100, orderBy: {field: SIZE, direction: DESC}) "
            "{ edges { size node { name } } } }"
            for j, n in enumerate(group)
        ]
        query = "query { " + " ".join(parts) + " }"
        try:
            data = gh.json(["api", "graphql", "-f", f"query={query}"])
            payload = (data or {}).get("data") or {}
            hard_failures = 0
        except GhError as e:
            try:
                payload = (json.loads(e.stdout) or {}).get("data") or {}
            except (json.JSONDecodeError, AttributeError):
                payload = {}
            if not payload:
                hard_failures += 1
                log.warning("GraphQL language batch failed (%d repos fall "
                            "back to REST): %s", len(group),
                            e.stderr.strip()[:150])
                continue
            hard_failures = 0
            log.debug("GraphQL batch had errors, salvaged partial data: %s",
                      e.stderr.strip()[:150])
        except json.JSONDecodeError:
            hard_failures += 1
            log.warning("GraphQL batch returned unparseable data, %d repos "
                        "fall back to REST", len(group))
            continue
        _parse_language_batch(payload, group, out)
    return out


def fetch_tree(gh: GhClient, org: str, repo: str, branch: str,
               recursive: bool = True) -> tuple[list[dict], bool]:
    url = f"repos/{org}/{repo}/git/trees/{quote(branch, safe='')}"
    if recursive:
        url += "?recursive=1"
    # 409 = empty repository, a real absence. 404 is NOT treated as absence:
    # it means the tree could not be read (permissions, SSO, a transient
    # ref problem). Treating it as "no files" disabled SCA on repos with
    # real manifests (fail-closed), so it now fails the repo instead.
    try:
        data = gh.json(["api", url], ok_statuses=(409,))
    except GhError as e:
        if re.search(r"\bhttp 404\b", e.stderr.lower()):
            raise GhError(e.cmd, e.returncode,
                          "git tree not readable (HTTP 404); refusing to decide "
                          "scans without file evidence", e.stdout) from e
        raise
    if not data:
        return [], False
    entries = [e for e in data.get("tree", []) if e.get("type") == "blob"]
    return entries, bool(data.get("truncated"))


def inspect_repo(gh: GhClient, org: str, repo: dict,
                 prefetched_languages: dict[str, dict[str, int]] | None = None) -> RepoInfo:
    name = repo["name"]
    branch = repo.get("default_branch") or "main"
    info = RepoInfo(name=name, default_branch=branch)
    if prefetched_languages is not None and name in prefetched_languages:
        info.languages = prefetched_languages[name]
    else:
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
    info.sizes = {e.get("path", ""): e.get("size") for e in entries}
    for e in entries:
        if e.get("path") == "veracode.yml":
            info.existing_veracode_sha = e.get("sha")
            break
    return info


def _decode_blob(data) -> str | None:
    """Decode a base64 contents/blob API payload. BOM-aware: Visual Studio
    occasionally writes UTF-16 project files, which a plain utf-8 decode
    with errors='ignore' turns into null-interleaved text that silently
    defeats every substring marker."""
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    try:
        raw = base64.b64decode(data.get("content", ""))
    except Exception:
        return None
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8-sig", errors="ignore")


def fetch_file_text_lower(gh: GhClient, org: str, repo: str, branch: str,
                          path: str) -> str | None:
    """Fetch a file via the contents API and return lowercased text, or None
    if it can't be fetched/decoded."""
    data = gh.json(["api", f"repos/{org}/{repo}/contents/{quote(path)}?ref={quote(branch, safe='')}"],
                   ok_statuses=(404,))
    text = _decode_blob(data)
    return text.lower() if text is not None else None


def fetch_blob_text(gh: GhClient, org: str, repo: str, sha: str) -> str | None:
    """Exact content of the blob the tree listing pointed at (no ref race
    between the tree read and the content read)."""
    data = gh.json(["api", f"repos/{org}/{repo}/git/blobs/{quote(sha, safe='')}"],
                   ok_statuses=(404,))
    return _decode_blob(data)


def deep_iac_confirm(gh: GhClient, org: str, repo: str, branch: str,
                     candidates: list[str], max_files: int = 5) -> list[str]:
    """Download a few ambiguous root YAML/JSON files and grep for
    CloudFormation / Kubernetes markers. Costs 1 API call per file."""
    hits = []
    markers = ("awstemplateformatversion", "apiversion:", "kind:")
    for path in candidates[:max_files]:
        text = fetch_file_text_lower(gh, org, repo, branch, path)
        if text and any(m in text for m in markers):
            hits.append(path)
    return hits


def scan_windows_signals(paths: list[str], mx: Matrices) -> tuple[set, set, list]:
    """Return (strong_hits, weak_hits, project_files) for Windows runner
    detection, ignoring vendored/generated paths (a packages.config inside a
    committed dependency must not force a Windows runner) and framework
    platform folders (Flutter's windows/ runner). project_files are
    .csproj/.vbproj/.fsproj paths, the candidates for content inspection,
    ordered so that projects sharing a directory subtree with a weak signal
    (the file that motivated the inspection) come first, then shallowest:
    in a large solution the capped inspection budget should be spent on the
    projects most likely to carry the Windows marker."""
    strong, weak, projects = set(), set(), []
    weak_dirs: set[str] = set()
    fw_dirs = framework_excluded_dirs(paths, mx)
    for p in paths:
        lp = p.lower()
        if not is_scannable_path(lp, mx, framework_dirs=fw_dirs):
            continue
        base = lp.rsplit("/", 1)[-1]
        if base in mx.windows_file_names or base.endswith(mx.windows_file_suffixes):
            strong.add(base)
        elif base in mx.windows_weak_names or base.endswith(mx.windows_weak_suffixes):
            weak.add(base)
            weak_dirs.add(lp.rsplit("/", 1)[0] if "/" in lp else "")
        if base.endswith((".csproj", ".vbproj", ".fsproj")):
            projects.append(p)

    def near_weak_signal(p: str) -> bool:
        d = p.lower().rsplit("/", 1)[0] if "/" in p.lower() else ""
        for w in weak_dirs:
            if d == w or (w and d.startswith(w + "/")) \
                    or (d and w.startswith(d + "/")):
                return True
        return False

    projects.sort(key=lambda p: (0 if near_weak_signal(p) else 1,
                                 p.count("/"), p.lower()))
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
        text = fetch_file_text_lower(gh, org, repo, branch, path)
        if not text:
            continue
        if any(marker in text for marker in mx.windows_project_markers):
            return path
        # Windows TFMs matched only inside <TargetFramework(s)> content; a
        # loose substring here previously false-matched unrelated prose.
        if mx.windows_tfm_regex.search(text):
            return path
    return None


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

SAST_TIER_EXPLANATIONS = {
    "SAST_PIPELINE_NOT_AUTOPACKAGED":
        "integration pipeline build skips this packager",
    "SAST_NO_SUPPORTED_RUNNER":
        "packaging needs a macOS/Xcode build host; the integration builds on "
        "Linux/Windows only",
    "SAST_COMPILED_ONLY":
        "needs preprocessed/compiled artifacts",
}


def _check_shape(path: str, val, proto, record: bool = False) -> None:
    """Validate a --config value against the shape of its default. Top-level
    objects are open maps (any key, values shaped like the existing ones);
    nested objects are records (only the keys the default has). Catching
    this at startup beats a traceback, or worse, silently wrong detection,
    halfway through an org-wide run."""
    if isinstance(proto, bool):
        if not isinstance(val, bool):
            raise ValueError(f"Config {path} must be true/false")
    elif isinstance(proto, int):
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise ValueError(f"Config {path} must be a non-negative integer")
    elif isinstance(proto, str):
        if not isinstance(val, str):
            raise ValueError(f"Config {path} must be a string, got "
                             f"{type(val).__name__}")
    elif isinstance(proto, list):
        # A bare string where a list is expected would otherwise be iterated
        # per character, turning ".jar" into suffixes '.', 'j', 'a', 'r' that
        # match nearly every file.
        if not isinstance(val, list):
            raise ValueError(f"Config {path} must be a list, got "
                             f"{type(val).__name__}")
        elem = proto[0] if proto else ""
        for i, v in enumerate(val):
            _check_shape(f"{path}[{i}]", v, elem, record=True)
    elif isinstance(proto, dict):
        if not isinstance(val, dict):
            raise ValueError(f"Config {path} must be an object, got "
                             f"{type(val).__name__}")
        for k, v in val.items():
            if record:
                if k not in proto:
                    raise ValueError(f"Config {path}: unknown key {k!r}, "
                                     f"expected one of {sorted(proto)}")
                sub = proto[k]
            else:
                sub = proto.get(k, next(iter(proto.values())) if proto else "")
            _check_shape(f"{path}.{k}", v, sub, record=True)


def merge_config(overrides: dict | None) -> dict:
    """Apply --config overrides to a copy of DEFAULT_MATRICES.

      "KEY":  value   replaces the default entirely
      "+KEY": value   appends list items / adds or replaces object entries
      "-KEY": [items] removes list items (case-insensitive) / object keys

    Replacing is rarely what you want for detection lists: replacing
    SCA_MANIFEST_NAMES with three names silently disables SCA for every
    other ecosystem. Prefer "+"/"-"."""
    m = json.loads(json.dumps(DEFAULT_MATRICES))  # deep copy
    if overrides is None:
        return m
    if not isinstance(overrides, dict):
        raise ValueError("Config file must contain a JSON object")
    # Plain replacements first, so "+KEY"/"-KEY" apply on top of them.
    items = sorted(overrides.items(), key=lambda kv: kv[0][:1] in "+-")
    for raw_key, val in items:
        op, key = (raw_key[0], raw_key[1:]) if raw_key[:1] in "+-" else ("", raw_key)
        if key not in m:
            raise ValueError(f"Unknown config key: {raw_key}. Valid keys "
                             f"(optionally prefixed with + or -): {sorted(m)}")
        default = DEFAULT_MATRICES[key]
        if op and not isinstance(default, (list, dict)):
            raise ValueError(f"Config {raw_key}: +/- only apply to lists and "
                             f"objects; use {key} to replace the value")
        if op == "-":
            _check_shape(raw_key, val, [""])
            drop = {v.lower() for v in val}
            if isinstance(m[key], list):
                m[key] = [v for v in m[key] if str(v).lower() not in drop]
            else:
                m[key] = {k: v for k, v in m[key].items() if k.lower() not in drop}
            continue
        _check_shape(raw_key, val, default)
        if op == "+":
            if isinstance(m[key], list):
                have = {str(v).lower() for v in m[key]}
                m[key] = m[key] + [v for v in val if str(v).lower() not in have]
            else:
                merged = dict(m[key])
                merged.update(val)
                m[key] = merged
        else:
            m[key] = val
    try:
        re.compile(m["WINDOWS_TFM_REGEX"])
    except re.error as e:
        raise ValueError(f"Config WINDOWS_TFM_REGEX is not a valid regex: {e}")
    return m


class Matrices:
    def __init__(self, overrides: dict | None = None):
        m = merge_config(overrides)
        self.sast_tiers: list[tuple[str, set[str]]] = [
            ("SAST_PIPELINE_NOT_AUTOPACKAGED", set(m["SAST_PIPELINE_NOT_AUTOPACKAGED"])),
            ("SAST_NO_SUPPORTED_RUNNER", set(m["SAST_NO_SUPPORTED_RUNNER"])),
            ("SAST_COMPILED_ONLY", set(m["SAST_COMPILED_ONLY"])),
        ]
        # A tier always wins over SAST_LANGUAGES, so "+SAST_COMPILED_ONLY"
        # alone is enough to disable a language.
        tiered = set().union(*(members for _, members in self.sast_tiers))
        self.sast_languages = set(m["SAST_LANGUAGES"]) - tiered
        self.sast_build_evidence = {
            lang: ({n.lower() for n in spec.get("names", [])},
                   tuple(s.lower() for s in spec.get("suffixes", [])))
            for lang, spec in m["SAST_BUILD_EVIDENCE"].items()}
        self.language_aliases = dict(m["LANGUAGE_ALIASES"])
        self.sca_languages = set(m["SCA_LANGUAGES"])
        self.code_extensions = {k.lower(): v for k, v in m["CODE_EXTENSIONS"].items()}
        self.sca_ecosystem_map: list[tuple[str, set, set, tuple]] = []
        for group, spec in m["SCA_ECOSYSTEM_MAP"].items():
            self.sca_ecosystem_map.append((
                group,
                set(spec.get("languages", [])),
                {n.lower() for n in spec.get("names", [])},
                tuple(s.lower() for s in spec.get("suffixes", [])),
            ))
        # Every name/suffix of an ecosystem group is detected even if the
        # user forgot to also add it to SCA_MANIFEST_NAMES/SUFFIXES.
        self.sca_manifest_names = {n.lower() for n in m["SCA_MANIFEST_NAMES"]}
        self.sca_manifest_names |= set().union(*(g[2] for g in self.sca_ecosystem_map))
        self.sca_manifest_suffixes = tuple(sorted(
            {s.lower() for s in m["SCA_MANIFEST_SUFFIXES"]}
            | {s for g in self.sca_ecosystem_map for s in g[3]}))
        self.sca_supporting_names = {n.lower() for n in m["SCA_SUPPORTING_NAMES"]}
        self.sca_supporting_suffixes = tuple(
            s.lower() for s in m["SCA_SUPPORTING_SUFFIXES"])
        self.sca_ignored_names = {n.lower() for n in m["SCA_IGNORED_NAMES"]}
        self.iac_file_names = {n.lower() for n in m["IAC_FILE_NAMES"]}
        self.iac_file_suffixes = tuple(s.lower() for s in m["IAC_FILE_SUFFIXES"])
        self.iac_name_prefixes = tuple(p.lower() for p in m["IAC_NAME_PREFIXES"])
        self.iac_dir_hints = tuple(d.lower() for d in m["IAC_DIR_HINTS"])
        self.iac_languages = set(m["IAC_LANGUAGES"])
        self.windows_file_names = {n.lower() for n in m["WINDOWS_FILE_NAMES"]}
        self.windows_file_suffixes = tuple(s.lower() for s in m["WINDOWS_FILE_SUFFIXES"])
        self.windows_weak_names = {n.lower() for n in m["WINDOWS_WEAK_FILE_NAMES"]}
        self.windows_weak_suffixes = tuple(
            s.lower() for s in m["WINDOWS_WEAK_FILE_SUFFIXES"])
        self.windows_project_markers = tuple(
            s.lower() for s in m["WINDOWS_PROJECT_MARKERS"])
        self.windows_tfm_regex = re.compile(m["WINDOWS_TFM_REGEX"])
        self.windows_corr_languages = set(m["WINDOWS_CORROBORATION_LANGUAGES"])
        self.vendored_segments = {s.lower() for s in m["VENDORED_PATH_SEGMENTS"]}
        self.classification_vendored = {
            s.lower() for s in m["CLASSIFICATION_VENDORED_SEGMENTS"]}
        self.generated_suffixes = tuple(s.lower() for s in m["GENERATED_FILE_SUFFIXES"])
        self.tooling_config_basenames = {
            n.lower() for n in m["TOOLING_CONFIG_BASENAMES"]}
        # Expand <stem>.<ext> across all JS/TS module extensions so
        # webpack.config.ts, vite.config.mjs etc. are covered without
        # enumerating every combination by hand.
        for stem in m["TOOLING_CONFIG_STEMS"]:
            for ext in (".js", ".cjs", ".mjs", ".ts", ".mts", ".cts"):
                self.tooling_config_basenames.add(stem.lower() + ext)
        self.framework_platform_dirs = {
            marker.lower(): [d.strip("/").lower() for d in dirs]
            for marker, dirs in m["FRAMEWORK_PLATFORM_DIRS"].items()}
        self.min_language_bytes = int(m["MIN_LANGUAGE_BYTES"])
        self.apple_corr_names = {n.lower() for n in m["APPLE_CORROBORATION_NAMES"]}
        self.apple_corr_suffixes = tuple(
            s.lower() for s in m["APPLE_CORROBORATION_SUFFIXES"])
        self.sf_corr_names = {n.lower() for n in m["SALESFORCE_CORROBORATION_NAMES"]}
        self.sf_corr_segments = {s.lower() for s in m["SALESFORCE_CORROBORATION_SEGMENTS"]}


def framework_excluded_dirs(paths: list[str], mx: Matrices) -> tuple[str, ...]:
    """Lowercase "dir/" prefixes of framework platform folders to ignore.
    Active only when the framework's marker file is at the repo root."""
    root_files = {p.lower() for p in paths if "/" not in p}
    out: list[str] = []
    for marker, dirs in mx.framework_platform_dirs.items():
        if marker in root_files:
            out.extend(d + "/" for d in dirs if d)
    return tuple(out)


def is_scannable_path(lower_path: str, mx: Matrices,
                      classification: bool = False,
                      framework_dirs: tuple[str, ...] = ()) -> bool:
    """False for vendored/generated content that must not classify a repo:
    committed node_modules, build output, virtualenvs, minified bundles,
    and framework platform scaffolding (framework_dirs).

    classification=True additionally excludes segments like env/ and
    external/ that are usually vendored code for language purposes but may
    legitimately hold manifests and IaC (env/prod/main.tf)."""
    if lower_path.endswith(mx.generated_suffixes):
        return False
    if framework_dirs and lower_path.startswith(framework_dirs):
        return False
    for seg in lower_path.split("/")[:-1]:  # directory segments only
        if seg in mx.vendored_segments:
            return False
        if classification and seg in mx.classification_vendored:
            return False
    return True


def filtered_entries(info: RepoInfo, mx: Matrices, classification: bool = False,
                     framework_dirs: tuple[str, ...] = ()
                     ) -> list[tuple[str, str, int | None]]:
    """(lower_path, lower_basename, blob_size) tuples for non-vendored paths.
    blob_size is None when the tree API omitted it (treated as unknown, which
    fails open in size-gated checks)."""
    out = []
    for p in info.paths:
        lp = p.lower()
        if is_scannable_path(lp, mx, classification=classification,
                             framework_dirs=framework_dirs):
            out.append((lp, lp.rsplit("/", 1)[-1], info.sizes.get(p)))
    return out


def _ext_languages(base: str, mx: Matrices) -> tuple[str, ...]:
    """Languages a file counts toward by extension. Headers are ambiguous
    (C, C++, Objective-C) and count toward all three."""
    dot = base.rfind(".")
    if dot == -1:
        return ()
    ext = base[dot:]
    if ext == ".h":
        return ("C", "C++", "Objective-C")
    lang = mx.code_extensions.get(ext)
    return (lang,) if lang else ()


def linguist_effective(info: RepoInfo, mx: Matrices,
                       framework_dirs: tuple[str, ...]) -> tuple[dict, dict, dict]:
    """Linguist languages (aliases folded) with bytes Linguist cannot know
    to ignore taken out: build-tool configs (webpack.config.js, ...) and
    framework platform scaffolding. Linguist already drops vendored and
    generated paths, so only non-vendored files are subtracted.

    Returns (effective_bytes, excluded_bytes, dropped). A language is
    dropped outright when every file of it in the tree is excluded; that is
    robust to byte-count drift between Linguist and the tree API. Truncated
    trees only get the byte subtraction (absence is not provable)."""
    folded: dict[str, int] = {}
    for lang, b in info.languages.items():
        canon = mx.language_aliases.get(lang, lang)
        folded[canon] = folded.get(canon, 0) + int(b or 0)

    excluded: dict[str, int] = {}
    total_files: dict[str, int] = {}
    excluded_files: dict[str, int] = {}
    for p in info.paths:
        lp = p.lower()
        if not is_scannable_path(lp, mx):
            continue  # vendored/generated: Linguist never counted it
        base = lp.rsplit("/", 1)[-1]
        langs = _ext_languages(base, mx)
        if not langs:
            continue
        is_excluded = (base in mx.tooling_config_basenames
                       or bool(framework_dirs and lp.startswith(framework_dirs)))
        size = info.sizes.get(p) or 0
        for lang in langs:
            total_files[lang] = total_files.get(lang, 0) + 1
            if is_excluded:
                excluded_files[lang] = excluded_files.get(lang, 0) + 1
                excluded[lang] = excluded.get(lang, 0) + size

    dropped: dict[str, str] = {}
    effective: dict[str, int] = {}
    for lang, b in folded.items():
        if (not info.tree_truncated and excluded_files.get(lang)
                and excluded_files[lang] == total_files.get(lang)):
            dropped[lang] = "only build-tool config or framework scaffolding files"
            continue
        effective[lang] = max(0, b - excluded.get(lang, 0))
    return effective, excluded, dropped


def languages_from_extensions(entries: list[tuple[str, str, int | None]],
                              mx: Matrices) -> set[str]:
    """Language detection fallback from file extensions, with safeguards the
    Linguist API applies natively: tooling configs do not classify a repo
    (a Python repo with webpack.config.js is not a JavaScript project),
    ambiguous extensions require corroboration (.m is MATLAB as often as
    Objective-C, .cls is a LaTeX class as often as Apex, a lone .h header
    is not a C project), and languages whose total bytes fall below
    MIN_LANGUAGE_BYTES are ignored, mirroring the threshold already applied
    to the Linguist byte counts. Without the byte gate, a 40-byte stub
    filtered out of the Linguist set was immediately re-added by this
    fallback, making the trivial-stub guard dead code."""
    apple_ok = any(
        base in mx.apple_corr_names or lp.endswith(mx.apple_corr_suffixes)
        for lp, base, _ in entries)
    sf_ok = any(
        base in mx.sf_corr_names
        or any(seg in mx.sf_corr_segments for seg in lp.split("/")[:-1])
        for lp, base, _ in entries)
    c_ok = any(
        base.endswith((".c", ".cpp", ".cc", ".cxx"))
        or base in ("makefile", "gnumakefile", "cmakelists.txt")
        for _, base, _ in entries)

    bytes_per_lang: dict[str, int] = {}
    unknown_size: set[str] = set()  # size missing -> fail open, count it
    for lp, base, size in entries:
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
        if ext == ".h" and not c_ok:
            # A lone header without any .c/.cpp/Makefile/CMake evidence must
            # not classify the repo as C: the resulting pipeline scan has
            # nothing to build and fails, blocking PRs.
            continue
        if size is None:
            unknown_size.add(lang)
        else:
            bytes_per_lang[lang] = bytes_per_lang.get(lang, 0) + size
    return unknown_size | {l for l, b in bytes_per_lang.items()
                           if b >= mx.min_language_bytes}


def _group_matches(base: str, gnames: set, gsuffixes: tuple) -> bool:
    if base in gnames or (gsuffixes and base.endswith(gsuffixes)):
        return True
    # requirements-dev.txt, dev-requirements.txt, requirements_test.txt
    return ("requirements.txt" in gnames and "requirements" in base
            and base.endswith(".txt"))


def decide(info: RepoInfo, mx: Matrices,
           deep_iac_hits: list[str] | None = None,
           deep_dotnet_hit: str | None = None,
           windows_signals: tuple[set, set, list] | None = None,
           iac_mode: str = "always",
           windows_runner: str = "windows-latest") -> ScanDecision:
    fw_dirs = framework_excluded_dirs(info.paths, mx)
    # Linguist languages below the byte threshold do not enable scans (a
    # 40-byte stub should not classify a repo); union with the extension scan
    # to catch empty/lagging API responses. Vendored, generated, tooling and
    # framework-scaffolding paths are excluded from all file-based detection;
    # the classification pass uses a stricter vendored list than the
    # manifest/IaC/Windows passes.
    effective, excluded_bytes, dropped = linguist_effective(info, mx, fw_dirs)
    langs = {l for l, b in effective.items() if b >= mx.min_language_bytes}
    class_entries = filtered_entries(info, mx, classification=True,
                                     framework_dirs=fw_dirs)
    entries = filtered_entries(info, mx, classification=False,
                               framework_dirs=fw_dirs)
    ext_langs = languages_from_extensions(class_entries, mx)
    all_langs = langs | ext_langs
    has_submodules = any(p == ".gitmodules" for p in info.paths)

    # --- SAST (pipeline scan) ---
    sast_langs = all_langs & mx.sast_languages
    # Build-system gate (C/C++): judged on all non-scaffolding paths,
    # vendored included, so the gate itself fails open.
    evidence_bases = {p.lower().rsplit("/", 1)[-1] for p in info.paths
                      if not (fw_dirs and p.lower().startswith(fw_dirs))}
    no_build = set()
    if not info.tree_truncated:
        for lang, (names, suffixes) in mx.sast_build_evidence.items():
            if lang in sast_langs and not any(
                    b in names or (suffixes and b.endswith(suffixes))
                    for b in evidence_bases):
                no_build.add(lang)
    sast_langs -= no_build
    sast = bool(sast_langs)
    sast_forced_by_truncation = False
    if not sast and info.tree_truncated:
        # Fail open: a truncated tree plus an empty/lagging Linguist response
        # is missing evidence, not evidence of absence.
        sast = True
        sast_forced_by_truncation = True
    tier_hits = [(tier, sorted(all_langs & members))
                 for tier, members in mx.sast_tiers if all_langs & members]
    not_counted = [f"{l} ({tier})" for tier, ls in tier_hits for l in ls]
    not_counted += [f"{l} (no build system)" for l in sorted(no_build)]

    # --- SCA (agent-based) ---
    manifests: set[str] = set()
    for _, base, _ in entries:
        if base in mx.sca_ignored_names:
            continue
        if base in mx.sca_manifest_names or base.endswith(mx.sca_manifest_suffixes) \
                or ("requirements" in base and base.endswith(".txt")):
            manifests.add(base)
    enabling: set[str] = set()
    supporting: set[str] = set()
    unsupported: set[str] = set()
    eco_hits: dict[str, set[str]] = {}
    eco_languages: set[str] = set()
    for b in sorted(manifests):
        groups = [(g, gl) for g, gl, gn, gs in mx.sca_ecosystem_map
                  if (gl & mx.sca_languages) and _group_matches(b, gn, gs)]
        if not groups:
            unsupported.add(b)
            continue
        is_supporting = b in mx.sca_supporting_names or (
            mx.sca_supporting_suffixes and b.endswith(mx.sca_supporting_suffixes))
        (supporting if is_supporting else enabling).add(b)
        if not is_supporting:
            for g, gl in groups:
                eco_hits.setdefault(g, set()).add(b)
                eco_languages |= gl & mx.sca_languages
    # SCA needs a resolvable manifest from an ecosystem the integration
    # scans. The ecosystem comes from the manifest itself (requirements.txt
    # means pip even when Linguist only reports "Jupyter Notebook"); an
    # agent run with only a Makefile/Gemfile/global.json fails with "no
    # build system found" and, with break_build_on_error, blocks the PR.
    sca = bool(enabling)
    source_eco_langs = all_langs & mx.sca_languages
    sca_forced_by_truncation = False
    if not sca and info.tree_truncated and source_eco_langs:
        sca = True  # cannot prove absence of manifests, stay enabled
        sca_forced_by_truncation = True
    paired = sorted(g for g, gl, _, _ in mx.sca_ecosystem_map
                    if g in eco_hits and gl & all_langs)
    unpaired = sorted(set(eco_hits) - set(paired))

    # --- IaC / container / secrets ---
    iac_artifacts = set()
    for lp, base, _ in entries:
        if base in mx.iac_file_names or base.endswith(mx.iac_file_suffixes) \
                or base.startswith(mx.iac_name_prefixes):
            iac_artifacts.add(base)
        elif lp.startswith(mx.iac_dir_hints) and lp.endswith((".yml", ".yaml", ".json")):
            iac_artifacts.add(lp)
    if all_langs & mx.iac_languages:
        iac_artifacts.add(f"languages:{sorted(all_langs & mx.iac_languages)}")
    if deep_iac_hits:
        iac_artifacts.update(deep_iac_hits)
    if iac_mode == "off":
        iac = False
        iac_reason = "disabled org-wide via --iac off"
    elif iac_mode == "artifacts":
        iac = bool(iac_artifacts) or info.tree_truncated
        if iac_artifacts:
            iac_reason = "artifacts present"
        elif iac:
            iac_reason = ("tree truncated, cannot prove absence of IaC "
                          "artifacts, kept enabled")
        else:
            iac_reason = "no IaC/container artifacts detected (--iac artifacts)"
    else:
        # Default: ON everywhere. The scan also does secret detection on all
        # repo contents with low failure risk.
        iac = True
        iac_reason = ("artifacts present" if iac_artifacts
                      else "no artifacts detected, kept enabled for secret scanning")
    if info.tree_truncated and "truncated" not in iac_reason:
        iac_reason += "; tree truncated"

    if sast_forced_by_truncation:
        sast_reason = ("tree truncated and no supported language proven; "
                       "cannot prove absence, kept enabled (fail-open)")
    elif sast:
        sast_reason = f"languages={sorted(sast_langs)}"
        if not_counted:
            sast_reason += f"; not counted: {not_counted[:6]}"
    else:
        parts = [f"{tier} {ls} ({SAST_TIER_EXPLANATIONS.get(tier, '')})"
                 for tier, ls in tier_hits]
        if no_build:
            parts.append(f"{sorted(no_build)} without a build system "
                         f"(Makefile/CMake/Meson/Ninja/vcxproj)")
        if parts:
            sast_reason = "disabled: " + "; ".join(parts)
        else:
            sast_reason = f"no supported language (found: {sorted(all_langs)[:8]})"
        if has_submodules:
            sast_reason += ("; .gitmodules present, code may live in "
                            "submodules the integration cannot see")
    if dropped:
        sast_reason += f"; ignored Linguist languages {sorted(dropped)} (tooling/scaffolding only)"

    # --- Runner ---
    # Central default runner is ubuntu-latest. A Windows runner is set only
    # when:
    #   1. a build-based scan (SAST/SCA) is enabled, AND
    #   2. a strong signal or confirmed project-file marker is present, AND
    #   3. the repo shows .NET/C++ corroboration (language evidence or
    #      project files). Without (3), a stray sample .aspx or a *.master
    #      file in a Python/Java repo forced the whole repo onto Windows.
    # Weak signals alone never force Windows; they trigger content
    # inspection in the caller instead.
    if windows_signals is not None:
        strong_hits, weak_hits, project_files = windows_signals
    else:
        strong_hits, weak_hits, project_files = scan_windows_signals(info.paths, mx)
    strong_hits = set(strong_hits)  # local copy, never mutate caller state
    corroborated = bool((all_langs & mx.windows_corr_languages)
                        or project_files or deep_dotnet_hit)
    if deep_dotnet_hit:
        strong_hits.add(f"project-marker:{deep_dotnet_hit}")
    runner = (windows_runner
              if (strong_hits and (sast or sca) and corroborated) else None)
    if runner:
        runner_reason = f"windows signals={sorted(strong_hits)[:5]}"
    elif strong_hits and not corroborated:
        runner_reason = (f"windows-like filenames {sorted(strong_hits)[:5]} "
                         f"without .NET/C++ corroboration, kept on linux")
    elif strong_hits:
        runner_reason = "windows signals present but no build-based scan enabled"
    elif weak_hits:
        runner_reason = (f"weak windows signals {sorted(weak_hits)[:5]} not "
                         f"confirmed by project inspection, kept on linux")
    else:
        runner_reason = "portable ecosystem, central default (linux)"
    if info.tree_truncated:
        runner_reason += "; tree truncated, runner detection best-effort"

    if sca_forced_by_truncation:
        sca_reason = ("tree truncated, ecosystem language present, cannot "
                      "prove absence of manifests, kept enabled")
    elif sca:
        sca_reason = (f"manifests={sorted(enabling)[:6]}, "
                      f"ecosystems={sorted(eco_hits)}")
        if paired:
            sca_reason += f"; paired={paired}"
        if unpaired:
            sca_reason += (f"; manifest-only (no matching source language) "
                           f"for {unpaired}, kept enabled fail-open")
    else:
        found = sorted(unsupported | supporting)
        sca_reason = "no integration-supported dependency manifest"
        if found:
            sca_reason += (f" (found only {found[:6]}: not resolvable by the "
                           f"integration's SCA scan on their own)")

    # Sanitize every reason: basenames/paths embedded here end up inside
    # veracode.yml comments, PR bodies, and logs. Filenames may contain
    # newlines, which would otherwise inject content past the YAML comment.
    reasons = {k: sanitize(v) for k, v in {
        "sast": sast_reason,
        "runner": runner_reason,
        "sca": sca_reason,
        "iac": iac_reason,
    }.items()}
    evidence = {
        "linguist_languages": sorted(langs),
        "linguist_dropped": dropped,
        "linguist_excluded_bytes": excluded_bytes,
        "framework_dirs_excluded": list(fw_dirs),
        "extension_languages": sorted(ext_langs),
        "all_languages": sorted(all_langs),
        "sast_not_counted": not_counted,
        "manifests": sorted(manifests),
        "sca_enabling_manifests": sorted(enabling),
        "sca_supporting_manifests": sorted(supporting),
        "sca_unsupported_manifests": sorted(unsupported),
        "sca_ecosystems": sorted(eco_hits),
        "sca_ecosystem_languages": sorted(eco_languages),
        "paired_ecosystems": paired,
        "iac_artifacts": sorted(iac_artifacts),
        "windows_strong": sorted(strong_hits),
        "windows_weak": sorted(weak_hits),
        "windows_corroborated": corroborated,
        "project_files": list(project_files)[:20],
        "has_submodules": has_submodules,
    }
    return ScanDecision(sast=sast, sca=sca, iac=iac, runner=runner,
                        reasons=reasons, evidence=evidence)


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
                    "package-lock.json", ".eslintrc.json", "veracode.yml",
                    "pubspec.yaml"):
            continue
        out.append(p)
    return out


# ---------------------------------------------------------------------------
# veracode.yml generation (minimal overrides only)
# ---------------------------------------------------------------------------

def build_override_yaml(decision: ScanDecision, platform_analysis: str | None,
                        runner_scope: str = "build",
                        disable_issue_triggers: bool = True) -> str | None:
    """Return repo-level veracode.yml content, or None if no override needed.

    Only disabled sections (and, when detected, a Windows runner) are
    written; everything else inherits the central veracode repo config.
    Disabling static triggers only stops PIPELINE scans; platform
    sandbox/policy scans follow analysis_on_platform, written only when
    --platform-analysis is passed.

    runner_scope "build" writes the documented per-scan build runner
    (actions: <scan>: build: runs_on) for the enabled build-based scans, so
    only the build moves to Windows. "all" writes default: runs_on, which
    in the integration's workflows moves every job (check run, cleanup, SCA,
    IaC/secrets) onto the Windows runner.
    """
    parts = [
        f"{MANAGED_MARKER} (settings below are regenerated; edit the tool's "
        f"--config instead)",
        f"# Detection: SAST={decision.sast} ({decision.reasons['sast']})",
        f"#            SCA={decision.sca} ({decision.reasons['sca']})",
        f"#            IaC={decision.iac} ({decision.reasons['iac']})",
        f"#            Runner={decision.runner or 'default'}"
        f"{' (' + runner_scope + ' scope)' if decision.runner else ''} "
        f"({decision.reasons.get('runner', '')})",
        "",
    ]
    wrote_section = False
    if decision.runner:
        if not RUNNER_LABEL_RE.match(decision.runner):
            raise ValueError(f"unsafe runner label {decision.runner!r}")
        if runner_scope == "all":
            parts.append(f"default:\n  runs_on: {decision.runner}\n")
        else:
            block = ["actions:"]
            for kind in ("sast", "sca"):
                if getattr(decision, kind):
                    block.append(f"  {SECTION_KEYS[kind]}:\n    build:\n"
                                 f"      runs_on: {decision.runner}")
            parts.append("\n".join(block) + "\n")
        wrote_section = True
    for kind, key in SECTION_KEYS.items():
        if not getattr(decision, kind):
            parts.append(DISABLE_BLOCK.format(key=key)
                         + (ISSUES_DISABLE if disable_issue_triggers else ""))
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

def _ref_path(branch: str) -> str:
    # Slashes stay literal: GitHub ref endpoints take "heads/feature/x".
    return quote(branch, safe="/")


def get_ref_sha(gh: GhClient, org: str, repo: str, branch: str) -> str | None:
    data = gh.json(["api", f"repos/{org}/{repo}/git/ref/heads/{_ref_path(branch)}"],
                   ok_statuses=(404,))
    if isinstance(data, dict):
        return (data.get("object") or {}).get("sha")
    return None


def ensure_branch(gh: GhClient, org: str, repo: str, base: str, new: str,
                  reset_stale: bool) -> bool:
    """Create the scoping branch from the default branch head, or reuse it.

    reset_stale: the branch exists but no open PR uses it (left over from a
    merged or closed PR). It is moved to the current default head so the new
    PR has a clean, conflict-free diff instead of carrying old commits."""
    base_sha = get_ref_sha(gh, org, repo, base)
    if not base_sha:
        log.error("[%s] cannot resolve head of %s", repo, base)
        return False
    current = get_ref_sha(gh, org, repo, new)
    if current:
        if reset_stale and current != base_sha:
            gh.run(["api", "-X", "PATCH",
                    f"repos/{org}/{repo}/git/refs/heads/{_ref_path(new)}",
                    "-f", f"sha={base_sha}", "-F", "force=true"])
            log.info("[%s] reset stale branch %s to %s head", repo, new, base)
        else:
            log.info("[%s] branch %s already exists, reusing", repo, new)
        return True
    try:
        gh.run(["api", "-X", "POST", f"repos/{org}/{repo}/git/refs",
                "-f", f"ref=refs/heads/{new}", "-f", f"sha={base_sha}"])
    except GhError as e:
        # A POST that succeeded server-side but timed out or returned 5xx
        # client-side is retried, and the retry gets 422 "Reference already
        # exists". That is success, not a failed repo.
        s = e.stderr.lower()
        if re.search(r"\bhttp 422\b", s) and "already exists" in s \
                and get_ref_sha(gh, org, repo, new):
            log.info("[%s] branch %s was created by an earlier attempt", repo, new)
            return True
        raise
    return True


def get_file_sha_on_ref(gh: GhClient, org: str, repo: str, ref: str) -> str | None:
    data = gh.json(["api", f"repos/{org}/{repo}/contents/veracode.yml?ref={quote(ref, safe='')}"],
                   ok_statuses=(404,))
    return data.get("sha") if isinstance(data, dict) else None


def put_file(gh: GhClient, org: str, repo: str, branch: str, content: str,
             existing_sha: str | None, message: str) -> None:
    desired = git_blob_sha(content)
    if existing_sha == desired:
        # Rerun against an existing branch that already carries the desired
        # content: writing again would create a redundant commit.
        log.info("[%s] %s already has desired veracode.yml, skipping write",
                 repo, branch)
        return
    args = ["api", "-X", "PUT", f"repos/{org}/{repo}/contents/veracode.yml",
            "-f", f"message={message}",
            "-f", f"content={base64.b64encode(content.encode()).decode()}",
            "-f", f"branch={branch}"]
    if existing_sha:
        args += ["-f", f"sha={existing_sha}"]
    try:
        gh.run(args)
    except GhError as e:
        s = e.stderr.lower()
        # A PUT that succeeded server-side but timed out client-side gets
        # retried and then fails with a sha conflict. If the branch already
        # has exactly the content we wanted, that is success, not failure.
        if re.search(r"\bhttp (409|422)\b", s) or "does not match" in s:
            current = get_file_sha_on_ref(gh, org, repo, branch)
            if current == desired:
                log.info("[%s] write conflict but %s already has desired "
                         "content, treating as success", repo, branch)
                return
        raise


def delete_file(gh: GhClient, org: str, repo: str, branch: str,
                existing_sha: str | None, message: str) -> None:
    """Remove the tool-managed veracode.yml so the central config applies."""
    if not existing_sha:
        log.info("[%s] %s has no veracode.yml, nothing to delete", repo, branch)
        return
    try:
        gh.run(["api", "-X", "DELETE", f"repos/{org}/{repo}/contents/veracode.yml",
                "-f", f"message={message}", "-f", f"sha={existing_sha}",
                "-f", f"branch={branch}"])
    except GhError as e:
        # Retried after a server-side success: the file is already gone.
        if re.search(r"\bhttp (404|409|422)\b", e.stderr.lower()) \
                and get_file_sha_on_ref(gh, org, repo, branch) is None:
            log.info("[%s] veracode.yml already removed on %s", repo, branch)
            return
        raise


def find_pr(gh: GhClient, org: str, repo: str, head: str, open_only: bool) -> str | None:
    """URL of the newest PR from `head`: open ones, or closed/merged ones."""
    if open_only:
        jq = ".[0].url // empty"
        state = "open"
    else:
        jq = '[.[] | select(.state != "OPEN")][0].url // empty'
        state = "all"
    out = gh.run(["pr", "list", "-R", f"{org}/{repo}", "--head", head,
                  "--state", state, "--json", "url,state", "--jq", jq])
    return out.strip() or None


def _md(s: str) -> str:
    """Render repo-derived text as inline code in PR bodies, so file names
    cannot @mention people, link issues, or inject markdown."""
    return "`" + s.replace("`", "'") + "`"


def create_pr(gh: GhClient, org: str, repo: str, base: str, head: str,
              decision: ScanDecision, action: str, runner_scope: str) -> str:
    if action == "delete":
        intro = ("Automated Veracode scan scoping: every scan type is relevant "
                 "for this repository now, so the tool-managed `veracode.yml` "
                 "is removed and the central configuration applies again.")
    else:
        intro = "Automated Veracode scan scoping."
    body = (
        intro + "\n\n"
        + "\n".join(
            f"- **{k.upper()}**: {'enabled' if getattr(decision, k) else 'disabled'}"
            f" {_md(decision.reasons[k])}" for k in SECTION_KEYS)
        + f"\n- **Runner**: {decision.runner or 'central default'}"
          f"{' (' + runner_scope + ' scope)' if decision.runner else ''}"
          f" {_md(decision.reasons.get('runner', ''))}"
        + "\n\nNote: static push/pr triggers only control pipeline scans. Platform "
          "sandbox/policy scans are governed by analysis_on_platform and are "
          "not changed by this file unless explicitly set."
    )
    title = ("Remove Veracode scan scoping override" if action == "delete"
             else "Scope Veracode scans to relevant scan types")
    try:
        out = gh.run(["pr", "create", "-R", f"{org}/{repo}", "--base", base,
                      "--head", head, "--title", title, "--body", body])
        return out.strip()
    except GhError as e:
        # A create that succeeded server-side but was retried after a
        # timeout fails with "already exists". Recover the URL instead of
        # marking the repo failed.
        if "already exists" in e.stderr.lower():
            url = find_pr(gh, org, repo, head, open_only=True)
            if url:
                return url
        raise


def close_stale_pr(gh: GhClient, org: str, repo: str, url: str) -> None:
    gh.run(["pr", "close", url, "-R", f"{org}/{repo}", "--comment",
            "Closed by veracode-scan-scoping: a fresh scan of the default branch "
            "shows every scan type is relevant, so no override is needed."])


def search_open_scoping_prs(gh: GhClient, org: str, head: str) -> set[str] | None:
    """Repo names (lowercase) with an open PR from the scoping branch, in one
    search query instead of one call per repo. None when search fails; the
    stale-PR cleanup is then skipped (best effort, never fatal)."""
    try:
        out = gh.run(["api", "-X", "GET", "--paginate", "search/issues",
                      "-f", f"q=org:{org} is:pr is:open head:{head}",
                      "-f", "per_page=100", "--jq", ".items[].repository_url"])
    except GhError as e:
        log.warning("Stale-PR search failed, skipping cleanup of outdated "
                    "scoping PRs: %s", e.stderr.strip()[:150])
        return None
    return {line.rstrip("/").rsplit("/", 1)[-1].lower()
            for line in out.splitlines() if line.strip()}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TERMINAL_OUTCOMES = {"no_change", "already_correct", "committed", "pr_opened",
                     "skipped_existing_file", "pr_declined"}


def write_csv_report(path: str, report: list[dict]) -> None:
    """Flatten the per-repo report list into a CSV: one row per repo, scan
    decisions and reasons as columns, easy to open in Excel/Sheets for
    client review of a dry run before anything is written to GitHub."""
    fieldnames = [
        "repo", "default_branch", "tree_truncated", "outcome", "action",
        "existing_file", "override_written",
        "sast", "sast_reason",
        "sca", "sca_reason",
        "iac", "iac_reason",
        "runner", "runner_reason",
        "languages", "pr_url", "error", "carried_over",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in report:
            d = r.get("decision") or {}
            reasons = d.get("reasons", {})
            writer.writerow({
                "repo": r.get("repo"),
                "default_branch": r.get("default_branch"),
                "tree_truncated": r.get("tree_truncated"),
                "outcome": r.get("outcome"),
                "action": r.get("action") or "",
                "existing_file": r.get("existing_file") or "",
                "override_written": r.get("override_written"),
                "sast": d.get("sast"),
                "sast_reason": reasons.get("sast"),
                "sca": d.get("sca"),
                "sca_reason": reasons.get("sca"),
                "iac": d.get("iac"),
                "iac_reason": reasons.get("iac"),
                "runner": d.get("runner") or ("default" if d else ""),
                "runner_reason": reasons.get("runner"),
                "languages": ", ".join(sorted((r.get("languages") or {}).keys())),
                "pr_url": r.get("pr_url", ""),
                "error": r.get("error", ""),
                "carried_over": r.get("carried_over", False),
            })


def matches_any(name: str, patterns: list[str]) -> bool:
    # Case-insensitive: GitHub repo names are case-preserving but not
    # case-sensitive for identity, and fnmatch on POSIX is case-sensitive.
    return any(fnmatch.fnmatch(name.lower(), p.lower()) for p in patterns)


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", required=True, help="GitHub organization")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print decisions and generated YAML, change nothing")
    ap.add_argument("--direct-commit", action="store_true",
                    help="Commit to the default branch instead of opening a PR")
    ap.add_argument("--branch-name", default="chore/veracode-scan-scoping")
    ap.add_argument("--include", nargs="+", default=["*"],
                    help="Glob patterns of repos to include")
    ap.add_argument("--exclude", nargs="*", default=["veracode"],
                    help="Glob patterns to skip (central 'veracode' repo is "
                         "always excluded)")
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="Overwrite a hand-written (unmanaged) veracode.yml. "
                         "Files generated by this tool are updated without it.")
    ap.add_argument("--reopen-declined", action="store_true",
                    help="Open a new PR even where a previous scoping PR was "
                         "closed and the default branch has no managed file "
                         "(treated as declined by the repo owners otherwise)")
    ap.add_argument("--keep-issue-triggers", action="store_true",
                    help="Do not write 'issues: trigger: false' for disabled "
                         "scans. Use when the central config never enables issue "
                         "triggers and files from an earlier version of this "
                         "tool should not get a one-time update PR.")
    ap.add_argument("--iac", choices=["always", "artifacts", "off"], default="always",
                    help="always (default): keep the IaC/secrets scan on for every "
                         "repo (secret detection is useful everywhere). "
                         "artifacts: disable it where no IaC/container artifacts "
                         "are found. off: disable it org-wide.")
    ap.add_argument("--no-iac", action="store_true",
                    help="Deprecated alias for --iac off")
    ap.add_argument("--deep-iac", action="store_true",
                    help="With --iac artifacts: download a few ambiguous root "
                         "YAML/JSON files to confirm CloudFormation/Kubernetes "
                         "content (extra API calls). Ignored otherwise.")
    ap.add_argument("--runner", choices=["auto", "off"], default="auto",
                    help="auto (default): set a Windows runner when Windows "
                         "build signals are confirmed and a build-based scan is "
                         "enabled. Weak signals (xaml, web.config, "
                         "vbproj/fsproj) automatically trigger project-file "
                         "inspection. off: never write a runner.")
    ap.add_argument("--runner-scope", choices=["build", "all"], default="build",
                    help="build (default): write actions: <scan>: build: runs_on "
                         "for the enabled SAST/SCA scans only. all: write "
                         "default: runs_on, which moves every job (check run, "
                         "cleanup, IaC/secrets) to Windows too.")
    ap.add_argument("--windows-runner", default="windows-latest",
                    help="Runner label written for Windows-bound builds "
                         "(default windows-latest). Use your self-hosted label, "
                         "or a flow list like '[self-hosted, windows]'.")
    ap.add_argument("--deep-dotnet", action="store_true",
                    help="Extend project-file inspection to every repo with "
                         ".csproj/.vbproj/.fsproj files, even without weak "
                         "surface signals. Catches SDK-style projects that "
                         "target net4x or *-windows TFMs (extra API calls, "
                         "up to --max-project-files per repo)")
    ap.add_argument("--platform-analysis", choices=["true", "false"], default=None,
                    help="Also pin analysis_on_platform for SAST-relevant repos. "
                         "Untouched by default.")
    ap.add_argument("--config", default=None,
                    help="JSON file overriding detection matrices. Use KEY to "
                         "replace, +KEY to extend, -KEY to remove items "
                         "(keys: " + ", ".join(sorted(DEFAULT_MATRICES)) + ")")
    ap.add_argument("--report", default=None, help="Write a JSON audit report here")
    ap.add_argument("--resume-from", default=None,
                    help="Path to a prior --report JSON. Repos with terminal "
                         "outcomes there (" + ", ".join(sorted(TERMINAL_OUTCOMES))
                         + ") are skipped and their entries carried into the "
                         "new report, so chained resumes stay cumulative. "
                         "Failed and dry-run outcomes are retried.")
    ap.add_argument("--no-graphql", action="store_true",
                    help="Disable batched GraphQL language prefetching and "
                         "use one REST call per repo instead")
    ap.add_argument("--max-project-files", type=int, default=5,
                    help="Max .NET project files downloaded per repo during "
                         "Windows-marker inspection (default 5). Raise for "
                         "orgs with large multi-project solutions where the "
                         "Windows-bound project may sort late.")
    ap.add_argument("--csv", default=None,
                    help="Write a CSV audit report here. Defaults to "
                         "'dry_run_report.csv' automatically when --dry-run "
                         "is set; pass explicitly to also get one on apply runs.")
    ap.add_argument("--min-interval", type=float, default=0.25,
                    help="Minimum seconds between GitHub API calls (default 0.25)")
    ap.add_argument("--min-remaining", type=int, default=100,
                    help="Sleep until reset when core rate limit drops below this")
    ap.add_argument("--write-interval", type=float, default=1.0,
                    help="Minimum seconds between write requests (commits, "
                         "branches, PRs). Default 1.0 keeps under GitHub's "
                         "~80 content-creating requests/minute.")
    ap.add_argument("--max-writes-per-hour", type=int, default=450,
                    help="Rolling hourly cap on write requests (default 450, "
                         "under GitHub's ~500/hour secondary limit). 0 disables.")
    ap.add_argument("--gh-timeout", type=float, default=120.0,
                    help="Seconds before a single gh call is abandoned and "
                         "retried (default 120)")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    iac_mode = "off" if args.no_iac else args.iac
    if args.no_iac and args.iac not in ("always", "off"):
        log.error("--no-iac conflicts with --iac %s", args.iac)
        return 2
    if args.deep_iac and iac_mode != "artifacts":
        log.warning("--deep-iac only affects --iac artifacts; ignoring it "
                    "(no extra API calls will be made).")
    if not RUNNER_LABEL_RE.match(args.windows_runner):
        log.error("--windows-runner %r is not a valid runner label or flow list",
                  args.windows_runner)
        return 2
    if args.max_project_files < 1 or args.gh_timeout <= 0:
        log.error("--max-project-files must be >= 1 and --gh-timeout > 0")
        return 2

    overrides = None
    if args.config:
        try:
            with open(args.config) as f:
                overrides = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error("Cannot read --config %s: %s", args.config, e)
            return 2
    try:
        mx = Matrices(overrides)
    except ValueError as e:
        log.error("%s", e)
        return 2

    # The central 'veracode' config repo must never receive an override,
    # even when the user supplies a custom --exclude list (which replaces
    # the default rather than extending it).
    excludes = list(args.exclude)
    if not matches_any("veracode", excludes):
        excludes.append("veracode")
        log.info("Added central 'veracode' repo to excludes automatically.")

    resume_done: set[str] = set()
    carried: list[dict] = []
    if args.resume_from:
        try:
            with open(args.resume_from) as f:
                prior = json.load(f)
            for r in prior.get("repos", []):
                if isinstance(r, dict) and r.get("repo") \
                        and r.get("outcome") in TERMINAL_OUTCOMES \
                        and r["repo"] not in resume_done:
                    resume_done.add(r["repo"])
                    carried.append(dict(r, carried_over=True))
            log.info("Resume: %d repos with terminal outcomes in %s will be "
                     "skipped and carried into the new report",
                     len(resume_done), args.resume_from)
        except (OSError, json.JSONDecodeError, AttributeError, TypeError) as e:
            log.error("Cannot read --resume-from %s: %s", args.resume_from, e)
            return 2

    gh = GhClient(min_interval=args.min_interval, min_remaining=args.min_remaining,
                  timeout=args.gh_timeout, write_interval=args.write_interval,
                  writes_per_hour=args.max_writes_per_hour)
    # Authentication is whatever gh resolves: GH_TOKEN, then GITHUB_TOKEN,
    # then stored `gh auth login` credentials (GH_ENTERPRISE_TOKEN/GH_HOST
    # for GHES). Checking one env var here gave false assurance when
    # another token took precedence.
    token_source = ("GH_TOKEN" if os.environ.get("GH_TOKEN") else
                    "GITHUB_TOKEN" if os.environ.get("GITHUB_TOKEN") else
                    "gh stored credentials")
    try:
        gh.run(["auth", "status"])
    except (GhError, FileNotFoundError) as e:
        log.error("gh CLI not available or not authenticated (%s): %s",
                  token_source, e)
        return 2
    log.info("Authenticated via %s", token_source)
    try:
        gh.run(["api", f"orgs/{args.org}", "--jq", ".login"])
    except GhError as e:
        log.error("Cannot access org %s with this token (check the org name, "
                  "token scopes repo + read:org, and SAML SSO authorization): %s",
                  args.org, e.stderr.strip()[:200])
        return 2

    try:
        repos = list_org_repos(gh, args.org)
    except GhError as e:
        log.error("Cannot list repos for org %s: %s", args.org, e)
        return 2
    summary = {"scoped": [], "no_change": [], "unchanged_identical": [],
               "skipped": [], "failed": []}
    report: list[dict] = list(carried)
    interrupted = False

    def flush_reports() -> None:
        """Write JSON/CSV reports. Called from a finally block so an
        interrupted or crashed run still leaves its evidence behind instead
        of losing hours of API work."""
        if args.report:
            try:
                with open(args.report, "w") as f:
                    json.dump({"org": args.org,
                               "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                          time.gmtime()),
                               "api_calls": gh.api_calls,
                               "write_calls": gh.write_calls,
                               "interrupted": interrupted,
                               "repos": report}, f, indent=2)
                log.info("Audit report written to %s", args.report)
            except OSError as e:
                log.error("Failed writing --report %s: %s", args.report, e)
        csv_path = args.csv or ("dry_run_report.csv" if args.dry_run else None)
        if csv_path:
            try:
                write_csv_report(csv_path, report)
                log.info("CSV report written to %s", csv_path)
            except OSError as e:
                log.error("Failed writing CSV %s: %s", csv_path, e)

    # Pre-filter so resume skipping and language prefetching only consider
    # repos that will actually be processed.
    todo: list[dict] = []
    for repo in repos:
        name = repo["name"]
        if not matches_any(name, args.include) or matches_any(name, excludes):
            summary["skipped"].append((name, "filtered")); continue
        if repo.get("archived") and not args.include_archived:
            summary["skipped"].append((name, "archived")); continue
        if repo.get("fork") and not args.include_forks:
            summary["skipped"].append((name, "fork")); continue
        if repo.get("disabled"):
            summary["skipped"].append((name, "disabled")); continue
        if repo.get("size") == 0:
            summary["skipped"].append((name, "empty")); continue
        if name in resume_done:
            summary["skipped"].append((name, "already processed (--resume-from)"))
            continue
        todo.append(repo)
    log.info("%d of %d repos to process after filtering", len(todo), len(repos))

    try:
        prefetched_languages: dict[str, dict[str, int]] = {}
        if todo and not args.no_graphql:
            prefetched_languages = batch_fetch_languages(
                gh, args.org, [r["name"] for r in todo])
            log.info("Prefetched languages for %d/%d repos via GraphQL "
                     "(any missing fall back to per-repo REST)",
                     len(prefetched_languages), len(todo))

        # Open scoping PRs that a fresh scan no longer justifies (the repo
        # gained code while the PR sat unmerged) are closed, so a stale
        # "disable SAST" proposal cannot be merged later. PR mode only.
        stale_pr_repos: set[str] | None = set()
        if todo and not args.direct_commit:
            stale_pr_repos = search_open_scoping_prs(gh, args.org, args.branch_name)

        for idx, repo in enumerate(todo, 1):
            name = repo["name"]
            log.info("[%d/%d] %s", idx, len(todo), name)
            report_entry: dict | None = None

            try:
                info = inspect_repo(gh, args.org, repo, prefetched_languages)
                if not info.paths and not info.languages:
                    summary["skipped"].append((name, "no readable content")); continue

                deep_hits = None
                if args.deep_iac and iac_mode == "artifacts":
                    cands = ambiguous_root_yaml(info, mx)
                    if cands:
                        deep_hits = deep_iac_confirm(gh, args.org, name,
                                                     info.default_branch, cands)

                win_signals = scan_windows_signals(info.paths, mx)
                dotnet_hit = None
                if args.runner == "auto":
                    strong_sig, weak_sig, proj_files = win_signals
                    # Automatic: weak signals need confirmation before Windows is
                    # ever chosen, so inspect project files whenever weak signals
                    # exist without a strong one. --deep-dotnet extends inspection
                    # to ALL repos with project files (catches Framework-targeting
                    # SDK-style projects with zero surface signals).
                    if not strong_sig and proj_files and (weak_sig or args.deep_dotnet):
                        dotnet_hit = deep_dotnet_check(gh, args.org, name,
                                                       info.default_branch,
                                                       proj_files, mx,
                                                       max_files=args.max_project_files)

                decision = decide(info, mx, deep_hits, dotnet_hit, win_signals,
                                  iac_mode=iac_mode,
                                  windows_runner=args.windows_runner)
                if args.runner == "off":
                    if decision.runner:
                        decision.reasons["runner"] = ("windows signals detected "
                                                      "but runner selection "
                                                      "disabled via --runner off")
                    decision.runner = None
                content = build_override_yaml(
                    decision, args.platform_analysis, args.runner_scope,
                    disable_issue_triggers=not args.keep_issue_triggers)

                log.info("[%s] SAST=%s SCA=%s IaC=%s runner=%s", name,
                         decision.sast, decision.sca, decision.iac,
                         decision.runner or "default")
                for k in SECTION_KEYS:
                    log.debug("[%s]   %s: %s", name, k, decision.reasons[k])

                report_entry = {"repo": name, "default_branch": info.default_branch,
                                "languages": info.languages,
                                "tree_truncated": info.tree_truncated,
                                "decision": asdict(decision),
                                "runner_scope": args.runner_scope,
                                "override_written": content is not None,
                                "existing_file": None,
                                "action": None,
                                "outcome": None}
                report.append(report_entry)

                # --- Existing file: managed (ours) or hand-written? ---
                existing_text = None
                existing_managed = False
                if info.existing_veracode_sha:
                    if content is not None and \
                            git_blob_sha(content) == info.existing_veracode_sha:
                        report_entry["existing_file"] = "managed"
                        summary["unchanged_identical"].append(name)
                        report_entry["outcome"] = "already_correct"
                        log.info("[%s] existing veracode.yml already matches, skipping", name)
                        continue
                    existing_text = fetch_blob_text(gh, args.org, name,
                                                    info.existing_veracode_sha)
                    existing_managed = existing_text is not None and is_managed(existing_text)
                    report_entry["existing_file"] = ("managed" if existing_managed
                                                     else "unmanaged")

                action = None
                if content is None:
                    if existing_managed:
                        action = "delete"
                    else:
                        note = ("all default scans relevant, no override needed"
                                + ("; hand-written veracode.yml left untouched"
                                   if info.existing_veracode_sha else ""))
                        report_entry["outcome"] = "no_change"
                        summary["no_change"].append(name)
                        log.info("[%s] %s", name, note)
                        if stale_pr_repos and name.lower() in stale_pr_repos:
                            url = find_pr(gh, args.org, name, args.branch_name,
                                          open_only=True)
                            if url:
                                report_entry["stale_pr"] = url
                                if args.dry_run:
                                    log.info("[%s] would close outdated scoping PR %s",
                                             name, url)
                                else:
                                    close_stale_pr(gh, args.org, name, url)
                                    log.info("[%s] closed outdated scoping PR %s",
                                             name, url)
                        continue
                else:
                    if info.existing_veracode_sha:
                        if existing_text is not None and \
                                yaml_body(existing_text) == yaml_body(content):
                            # Same settings, only the reason header differs
                            # (a file list or truncation note changed). No
                            # churn, no --force needed.
                            summary["unchanged_identical"].append(name)
                            report_entry["outcome"] = "already_correct"
                            log.info("[%s] existing veracode.yml has identical "
                                     "settings, skipping", name)
                            continue
                        if not existing_managed and not args.force:
                            summary["skipped"].append(
                                (name, "hand-written veracode.yml with different "
                                       "settings (review, or use --force)"))
                            report_entry["outcome"] = "skipped_existing_file"
                            continue
                        if not existing_managed:
                            log.warning("[%s] --force: overwriting hand-written "
                                        "veracode.yml", name)
                    action = "write"
                report_entry["action"] = action

                if args.dry_run:
                    if action == "delete":
                        print(f"\n===== {name} (dry run) =====\n"
                              f"# would DELETE the managed veracode.yml: every "
                              f"scan type is relevant now\n")
                        report_entry["outcome"] = "would_delete"
                    else:
                        print(f"\n===== {name} (dry run) =====\n{content}")
                        report_entry["outcome"] = "would_write"
                    summary["scoped"].append((name, f"dry-run ({action})"))
                    continue

                msg = ("chore: remove Veracode scan scoping override"
                       if action == "delete" else
                       "chore: scope Veracode scans to relevant scan types")
                if args.direct_commit:
                    if action == "delete":
                        delete_file(gh, args.org, name, info.default_branch,
                                    info.existing_veracode_sha, msg)
                    else:
                        put_file(gh, args.org, name, info.default_branch, content,
                                 info.existing_veracode_sha, msg)
                    summary["scoped"].append((name, f"committed ({action}) to "
                                                    f"{info.default_branch}"))
                    report_entry["outcome"] = "committed"
                    continue

                open_url = find_pr(gh, args.org, name, args.branch_name, open_only=True)
                if not open_url and not existing_managed and not args.reopen_declined:
                    closed_url = find_pr(gh, args.org, name, args.branch_name,
                                         open_only=False)
                    if closed_url:
                        # A previous scoping PR was closed (or merged and the
                        # file later removed) and the default branch carries
                        # no managed file: the owners said no. Do not reopen
                        # on every run.
                        summary["skipped"].append(
                            (name, f"previous scoping PR declined: {closed_url} "
                                   f"(use --reopen-declined)"))
                        report_entry["outcome"] = "pr_declined"
                        report_entry["pr_url"] = closed_url
                        continue
                if not ensure_branch(gh, args.org, name, info.default_branch,
                                     args.branch_name, reset_stale=not open_url):
                    summary["failed"].append((name, "branch creation failed"))
                    report_entry["outcome"] = "failed_branch_creation"
                    continue
                branch_sha = get_file_sha_on_ref(gh, args.org, name, args.branch_name)
                if action == "delete":
                    delete_file(gh, args.org, name, args.branch_name, branch_sha, msg)
                else:
                    put_file(gh, args.org, name, args.branch_name, content,
                             branch_sha, msg)
                url = open_url or create_pr(gh, args.org, name, info.default_branch,
                                            args.branch_name, decision, action,
                                            args.runner_scope)
                summary["scoped"].append((name, url))
                report_entry["outcome"] = "pr_opened"
                report_entry["pr_url"] = url
                report_entry["pr_reused"] = bool(open_url)
            except GhError as e:
                log.error("[%s] %s", name, e)
                summary["failed"].append((name, str(e)[:200]))
                _mark_failed(report, report_entry, name, str(e)[:500])
            except Exception as e:  # never let one repo kill an org-wide run
                log.exception("[%s] unexpected error", name)
                summary["failed"].append((name, f"{type(e).__name__}: {e}"))
                _mark_failed(report, report_entry, name, f"{type(e).__name__}: {e}")

    except KeyboardInterrupt:
        interrupted = True
        log.warning("Interrupted (Ctrl-C). Writing partial reports for the "
                    "%d repos processed so far before exiting.", len(report))
    finally:
        flush_reports()

    print("\n========== SUMMARY ==========")
    for key, label in (("scoped", "Scoped (override written/PR)"),
                       ("no_change", "No change needed"),
                       ("unchanged_identical", "Already correct (identical settings)"),
                       ("skipped", "Skipped"),
                       ("failed", "Failed")):
        items = summary[key]
        print(f"{label}: {len(items)}")
        for it in items:
            print(f"  {it[0]}: {it[1]}" if isinstance(it, tuple) else f"  {it}")
    print(f"Total GitHub API calls: {gh.api_calls} ({gh.write_calls} writes)")
    if interrupted:
        return 130
    return 1 if summary["failed"] else 0


def _mark_failed(report: list[dict], entry: dict | None, name: str,
                 error: str) -> None:
    """Record a failure in the report. Failures before a decision was made
    previously left no trace in the JSON/CSV at all."""
    if entry is None:
        report.append({"repo": name, "outcome": "failed", "error": error})
    else:
        entry["outcome"] = "failed"
        entry["error"] = error


if __name__ == "__main__":
    sys.exit(main())
