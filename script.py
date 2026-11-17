#!/usr/bin/env python3
"""
Requirements: an authenticated gh CLI (GH_TOKEN, GITHUB_TOKEN, or `gh auth
login`) with scopes repo, workflow, read:org (plus read:enterprise for
--enterprise), SSO-authorized for every target org. Python 3.9+, stdlib only.

Usage:
  python3 script.py --org my-org --dry-run --report audit.json
  python3 script.py --org org-a org-b org-c --dry-run --report audit.json
  python3 script.py --orgs-file orgs.txt --report run1.json
  python3 script.py --enterprise my-ent --dry-run --report audit.json
  python3 script.py --enterprise my-ent --orgs-file pilot.txt
  python3 script.py --org my-org --iac artifacts --direct-commit
  python3 script.py --org my-org --resume-from run1.json --report run2.json
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
import signal
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from urllib.parse import quote

log = logging.getLogger("veracode-provision")

# ---------------------------------------------------------------------------
# Detection matrices
# Verified against the Veracode GitHub Workflow Integration docs (2026-07,
# re-checked 2026-11; integration page last updated 2026-10-22):
# https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning
# Pipeline Scan languages (page updated 2026-03-25):
# https://docs.veracode.com/r/Pipeline_Scan_Supported_Languages
# and SCA agent support matrix:
# https://docs.veracode.com/r/Agent_Based_Scans
# Known documentation conflicts (left fail-open on purpose, see README):
#   - the integration's language table lists PHP with SAST "No";
#   - the autopackaging page lists the GitHub integration autopackager as
#     Java, JavaScript, Python, Go, Scala, Kotlin, React Native and Android
#     only, while the integration table marks .NET and Ruby SAST "Yes".
#   Moving a language to a disable tier is one --config line when an org
#   confirms the integration cannot build it.
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
        ".mts": "TypeScript", ".cts": "TypeScript",
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
        # Python: pip, Pipenv, Poetry (agent matrix). uv.lock / pdm.lock are
        # not agent package managers; they are kept as detection evidence
        # because such projects also carry pyproject.toml (fail-open).
        # requirements*.txt is also matched by rule.
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
        # Reported only (no integration or agent support): Rust, Swift
        # Package Manager, Carthage, Elixir, Dart/Flutter pub, Conan, vcpkg,
        # Bun. Listing them makes the report say "found but unsupported"
        # instead of silently ignoring the ecosystem.
        "cargo.toml", "cargo.lock", "package.swift", "package.resolved",
        "cartfile", "cartfile.resolved", "mix.exs", "mix.lock",
        "pubspec.yaml", "pubspec.lock", "conanfile.txt", "conanfile.py",
        "vcpkg.json", "bun.lockb", "bun.lock",
    ],
    # Manifest suffixes (lowercase). .jar/.dll covered by the agent's
    # "Jars"/"DLL" hash-based quick scan rows, so vendored-binary repos count.
    # .sbt covers plugins.sbt and other sbt build definitions.
    "SCA_MANIFEST_SUFFIXES": [".csproj", ".fsproj", ".vbproj", ".sln",
                              ".slnx", ".nuspec", ".jar", ".dll", ".sbt"],
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
    "SCA_SUPPORTING_SUFFIXES": [".sln", ".slnx"],
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
                         ".slnx", ".nuspec", ".dll"],
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
        "crossplane.yaml", "chart.lock", "values.yml",
    ],
    "IAC_FILE_SUFFIXES": [".tf", ".tf.json", ".tfvars", ".hcl", ".bicep",
                          ".bicepparam", ".dockerfile", ".containerfile",
                          ".cfn.yaml", ".cfn.yml", ".cfn.json"],
    # Basename prefixes: Dockerfile.prod, docker-compose.override.yml,
    # Containerfile.dev, Pulumi.<stack>.yaml, helmfile.yaml/helmfile.d.
    "IAC_NAME_PREFIXES": ["dockerfile", "docker-compose", "containerfile",
                          "pulumi.", "helmfile"],
    # Directory names where YAML/JSON is treated as IaC. Matched at ANY
    # depth (services/api/k8s/deploy.yaml), so monorepo layouts count. An
    # entry containing a slash ("platform/envs/") matches that consecutive
    # directory sequence anywhere in the path. Over-matching only keeps the
    # IaC scan on (fail-open); it matters only with --iac artifacts.
    "IAC_DIR_HINTS": [
        "terraform/", "infra/", "infrastructure/", "iac/",
        "k8s/", "kubernetes/", "kube/", "helm/", "charts/", "manifests/",
        "deploy/", "deployment/", "deployments/",
        "cloudformation/", "cfn/", "sam/",
        "ansible/", "playbooks/", "roles/",
        "docker/",
    ],
    # Linguist languages that directly indicate IaC content.
    "IAC_LANGUAGES": ["HCL", "Dockerfile", "Bicep", "Smarty", "Open Policy Agent",
                      "Terraform Template"],
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
    # .fsproj when weak signals exist (automatic) or --deep-dotnet is passed
    # (net4x and *-windows TFMs are matched by WINDOWS_TFM_REGEX below):
    "WINDOWS_FILE_NAMES": ["packages.config", "global.asax"],
    "WINDOWS_FILE_SUFFIXES": [".vcxproj", ".vcproj", ".aspx", ".ascx",
                              ".asax", ".master", ".asmx", ".sqlproj",
                              ".wixproj"],
    # assemblyinfo.cs/.vb: hand-maintained assembly attributes are the norm
    # in old-style (non-SDK) projects, which SDK-style projects generate.
    # Weak only: SDK projects with GenerateAssemblyInfo=false keep one too.
    "WINDOWS_WEAK_FILE_NAMES": ["app.xaml", "web.config", "app.config",
                                "assemblyinfo.cs", "assemblyinfo.vb"],
    "WINDOWS_WEAK_FILE_SUFFIXES": [".xaml", ".vbproj", ".fsproj"],
    "WINDOWS_PROJECT_MARKERS": [
        "<targetframeworkversion>",          # old-style Framework project
        "toolsversion=",                     # old-style msbuild project
        "schemas.microsoft.com/developer/msbuild/2003",  # old project xmlns
        "<usewpf>true",                      # WPF (Windows desktop)
        "<usewindowsforms>true",             # WinForms (Windows desktop)
    ],
    # Windows-bound TFMs (net4x in any position of a multi-target list, and
    # net8.0-windows etc.) are matched with a regex anchored inside
    # <TargetFramework(s)> element content, not a raw substring: a loose
    # "-windows<" marker false-matches prose like
    # <PackageTags>non-windows</PackageTags> and forces a portable project
    # onto a Windows runner. Attributes (Condition=...) are allowed, except
    # IsOSPlatform conditions: the MAUI template adds its -windows TFM only
    # when building ON Windows, so the project still builds on Linux.
    # .NET Framework TFMs are net11, net20, net35 and net4x (no dot); modern
    # TFMs always have a dot (net5.0 ... net10.0, net11.0), so the trailing
    # (?!\.) keeps .NET 11 ("net11.0") from matching Framework 1.1.
    "WINDOWS_TFM_REGEX": (r"<targetframeworks?(?:\s(?![^>]*isosplatform)[^>]*)?>"
                          r"[^<]*(?:-windows|\bnet(?:11|20|35|4\d{1,2})\b(?!\.))"),
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
                                ".d.ts", ".d.mts", ".d.cts", ".pb.cc",
                                ".pb.h", "_pb.js"],
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
    # Framework scaffolding: when a marker file exists (at the root or in a
    # monorepo sub-directory), the listed sibling directories hold generated
    # platform runners, not first-party code, and are excluded
    # from language classification (Linguist bytes
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
# value can never inject extra configuration. A flow list needs at least one
# label and no empty elements ("[ ]", "[a,]" would write an unusable runs_on).
_RUNNER_LABEL = r"[A-Za-z0-9_.\-]+"
RUNNER_LABEL_RE = re.compile(
    rf"^(\[ *{_RUNNER_LABEL} *(?:, *{_RUNNER_LABEL} *)*\]|{_RUNNER_LABEL})\Z")


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

def _short_cmd(cmd: list[str], limit: int = 120) -> str:
    """Command line for error messages and logs, with long values (base64
    file content, PR bodies, GraphQL queries) elided. Keeps reports and logs
    readable and avoids copying payloads into them."""
    out = []
    for a in cmd:
        if len(a) > limit:
            key, eq, _ = a.partition("=")
            a = (f"{key}=<{len(a) - len(key) - 1} chars>" if eq and len(key) < 40
                 else f"<{len(a)} chars>")
        out.append(a)
    return " ".join(out)


class GhError(RuntimeError):
    def __init__(self, cmd: list[str], returncode: int, stderr: str,
                 stdout: str = ""):
        self.cmd, self.returncode, self.stderr = cmd, returncode, stderr
        self.stdout = stdout  # gh api graphql prints partial data here
        super().__init__(f"gh failed ({returncode}): {_short_cmd(cmd)}\n"
                         f"{stderr.strip()[:400]}")


class GhAuthError(GhError):
    """The token is missing, expired or revoked (HTTP 401). Fatal for the
    whole run: every further call would fail the same way."""


class ReadOnlyViolation(RuntimeError):
    """A write was attempted on a read-only (--dry-run) client."""


# Error categories recorded in reports (error_category) so administrators
# can act on failures in bulk instead of reading every message.
_ERROR_PATTERNS = (
    ("auth", r"\bhttp 401\b|bad credentials|requires authentication|gh auth login"),
    ("rate_limit", r"secondary rate limit|abuse detection|\bhttp 429\b|"
                   r"api rate limit exceeded|rate.limited"),
    ("protected_branch", r"protected branch|must be made through a pull request|"
                         r"rule violations?|required status check"),
    ("permission", r"\bhttp 403\b|saml|not accessible by|must have (?:admin|push)"),
    ("not_found", r"\bhttp 404\b"),
    ("conflict", r"\bhttp 409\b|does not match|is at [0-9a-f]+ but expected"),
    ("validation", r"\bhttp 422\b"),
    ("timeout", r"timed out|timeout"),
    ("transient", r"\bhttp 5\d\d\b|connection reset|connection refused|"
                  r"temporarily unavailable|bad gateway|service unavailable|"
                  r"unexpected eof|tls handshake"),
)


def classify_error(exc: BaseException) -> str:
    if isinstance(exc, GhError):
        text = exc.stderr.lower()
        for category, pattern in _ERROR_PATTERNS:
            if re.search(pattern, text):
                return category
        return "unknown"
    if isinstance(exc, ReadOnlyViolation):
        return "dry_run_guard"
    return "unexpected"


class GhClient:
    """Wraps the gh CLI with throttling, retries, and rate limit awareness.

    - Enforces a minimum interval between API calls (primary rate hygiene).
    - Paces write requests separately (POST/PUT/PATCH/DELETE and
      `gh pr create`): GitHub's secondary limits allow roughly 80
      content-generating requests per minute and 500 per hour, and PR mode
      makes up to 3 writes per repo. Without pacing an org-wide rollout
      hits the hourly cap, backs off for ~20 minutes, and marks repos
      failed while the window is still closed.
    - Every `check_every` calls (REST, GraphQL and `gh pr`), queries
      /rate_limit and sleeps until reset if the core or GraphQL budget drops
      below `min_remaining`. A 404 from /rate_limit (GHES with rate limiting
      disabled) turns the check off instead of repeating it all run.
    - Every gh invocation has a timeout, so one stalled connection cannot
      hang an org-wide run. Timeouts are retried like transient errors;
      every write path in this script reconciles remote state on retry.
    - Exponential backoff with jitter on secondary rate limit / abuse
      detection responses and transient network errors.
    - HTTP 401 raises GhAuthError immediately (never retried).
    - read_only=True (dry runs) refuses every write before it is sent, so
      a logic error can never modify a repository during an audit.
    """

    TRANSIENT_RE = re.compile(
        r"\bhttp 50[0234]\b|timed out|timeout|connection reset|"
        r"connection refused|temporarily unavailable|bad gateway|"
        r"service unavailable|unexpected eof|tls handshake")
    SECONDARY_RE = re.compile(
        r"secondary rate limit|abuse detection|\bhttp 429\b")
    AUTH_RE = re.compile(r"\bhttp 401\b|bad credentials|requires authentication")
    PRIMARY_MARKERS = ("api rate limit exceeded",)
    WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

    def __init__(self, min_interval: float = 0.25, min_remaining: int = 100,
                 check_every: int = 50, max_retries: int = 6,
                 timeout: float = 120.0, write_interval: float = 1.0,
                 writes_per_hour: int = 450, read_only: bool = False):
        self.min_interval = min_interval
        self.min_remaining = min_remaining
        self.check_every = check_every
        self.max_retries = max_retries
        self.timeout = timeout
        self.write_interval = write_interval
        self.writes_per_hour = writes_per_hour
        self.read_only = read_only
        self._last_call = 0.0
        self._last_write = 0.0
        self._write_times: deque[float] = deque()
        self._calls_since_check = 0
        self._rate_limit_supported = True
        self.api_calls = 0
        self.write_calls = 0
        self.retries = 0
        self.wait_seconds = 0.0

    @classmethod
    def is_write(cls, args: list[str]) -> bool:
        if args[:2] in (["pr", "create"], ["pr", "close"]):
            return True
        for i, a in enumerate(args[:-1]):
            if a in ("-X", "--method") and args[i + 1].upper() in cls.WRITE_METHODS:
                return True
        return False

    def _sleep(self, seconds: float) -> None:
        self.wait_seconds += seconds
        time.sleep(seconds)

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
            self._sleep(sleep_for)
            self._write_times.popleft()
        wait = self.write_interval - (time.monotonic() - self._last_write)
        if wait > 0:
            time.sleep(wait)
        self._last_write = time.monotonic()
        self._write_times.append(self._last_write)
        self.write_calls += 1

    def _maybe_check_rate_limit(self) -> None:
        if not self._rate_limit_supported or self.check_every <= 0:
            return
        self._calls_since_check += 1
        if self._calls_since_check < self.check_every:
            return
        self._calls_since_check = 0
        try:
            out = self._run_once(["api", "rate_limit"])
            resources = json.loads(out)["resources"]
            # GraphQL (language/blob batches, enterprise discovery) has its
            # own bucket; watching core alone let it run dry unnoticed.
            sleep_for = 0.0
            for bucket in ("core", "graphql"):
                res = resources.get(bucket)
                if not isinstance(res, dict):
                    continue
                remaining, reset = res["remaining"], res["reset"]
                log.debug("Rate limit %s: %s remaining, resets at %s",
                          bucket, remaining, reset)
                if remaining < self.min_remaining:
                    sleep_for = max(sleep_for, max(reset - time.time(), 0) + 5)
                    log.warning("Rate limit low (%s: %s remaining).", bucket,
                                remaining)
            if sleep_for:
                log.warning("Sleeping %.0fs until reset.", sleep_for)
                self._sleep(sleep_for)
        except GhError as e:
            if re.search(r"\bhttp 404\b", e.stderr.lower()):
                self._rate_limit_supported = False
                log.info("Rate-limit endpoint not available (GHES with rate "
                         "limiting disabled?); periodic checks turned off.")
            else:
                log.debug("rate_limit check failed, continuing: %s", e)
        except Exception as e:  # never let the health check kill the run
            log.debug("rate_limit check failed, continuing: %s", e)

    def _run_once(self, args: list[str]) -> str:
        if self.is_write(args):
            if self.read_only:
                raise ReadOnlyViolation(
                    f"dry run: refusing write {_short_cmd(['gh'] + args)}")
            self._throttle()
            self._pace_write()
        else:
            self._throttle()
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
        stderr = proc.stderr or ""
        cls = GhAuthError if self.AUTH_RE.search(stderr.lower()) else GhError
        raise cls(["gh"] + args, proc.returncode, stderr, proc.stdout or "")

    def run(self, args: list[str], ok_statuses: tuple[int, ...] = (),
            max_retries: int | None = None) -> str:
        """Run a gh command. ok_statuses (e.g. 404) return "" instead of
        raising. max_retries overrides the client default for this call."""
        if args[:2] != ["auth", "status"]:
            self._maybe_check_rate_limit()
        tries = max_retries or self.max_retries
        last: GhError | None = None
        for attempt in range(1, tries + 1):
            try:
                return self._run_once(args)
            except GhAuthError:
                raise
            except GhError as e:
                last = e
                stderr = e.stderr.lower()
                for status in ok_statuses:
                    # Word-bounded match on gh's "HTTP 404" error format. The
                    # previous loose "(404)" substring could swallow unrelated
                    # errors whose message merely contained the number.
                    if re.search(rf"\bhttp {status}\b", stderr):
                        log.debug("Treating HTTP %s as absence: %s",
                                  status, _short_cmd(e.cmd))
                        return ""
                retryable = bool(self.SECONDARY_RE.search(stderr)
                                 or any(m in stderr for m in self.PRIMARY_MARKERS)
                                 or self.TRANSIENT_RE.search(stderr))
                if not retryable:
                    raise  # callers inspect the original stderr (409/422...)
                if attempt >= tries:
                    break
                if self.SECONDARY_RE.search(stderr):
                    wait = min(60 * attempt, 300) + random.uniform(0, 10)
                    log.warning("Secondary rate limit hit. Backing off %.0fs "
                                "(attempt %d/%d).", wait, attempt, tries)
                    self.retries += 1
                    self._sleep(wait)
                    continue
                if any(m in stderr for m in self.PRIMARY_MARKERS):
                    log.warning("Primary rate limit exhausted. Sleeping 60s and "
                                "re-checking.")
                    self.retries += 1
                    self._sleep(60)
                    self._calls_since_check = self.check_every  # force check
                    self._maybe_check_rate_limit()
                    continue
                wait = min(2 ** attempt, 30) + random.uniform(0, 2)
                log.warning("Transient error, retrying in %.0fs (attempt "
                            "%d/%d): %s", wait, attempt, tries,
                            e.stderr.strip()[:150])
                self.retries += 1
                self._sleep(wait)
        assert last is not None
        if tries == 1:
            raise last
        raise GhError(last.cmd, last.returncode,
                      f"retries exhausted after {tries} attempts; last error: "
                      + last.stderr.strip()[:300], last.stdout)

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


# C0/C1 controls (incl. NEL \x85), Unicode line/paragraph separators, and
# bidirectional overrides/isolates ("Trojan Source"). YAML 1.1 parsers treat
# NEL, LS and PS as line breaks, so they must not reach a comment line; bidi
# controls can make a PR body or log line read differently than it is.
_CTRL_CHARS = re.compile(
    "[\x00-\x1f\x7f-\x9f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]+")


def sanitize(s: str) -> str:
    """Strip control characters (incl. newlines) from repo-derived strings.

    Git tree paths may legally contain newlines. Reason strings built from
    file basenames are embedded into veracode.yml header comments, PR bodies,
    and log lines; without this, a crafted filename can break out of a YAML
    comment and inject live configuration into the committed override."""
    return _CTRL_CHARS.sub(" ", s)


# Report evidence lists are capped so a repo with thousands of matching
# files (k8s manifests, vendored jars) cannot bloat the JSON report; the
# true count is recorded next to the capped list.
EVIDENCE_CAP = 200

# User-supplied identifiers end up in API paths and search queries. GitHub
# logins/slugs are alphanumeric plus hyphens (GHES may allow '_' and '.');
# anything with '/', '?', '%', '..' or a leading '-' could redirect a REST
# path (orgs/x/../..), smuggle query parameters, or be read by gh as a flag.
_LOGIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")


def valid_login(name: str) -> bool:
    return bool(_LOGIN_RE.match(name)) and ".." not in name


_BAD_REF_CHARS = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]")


def valid_branch_name(name: str) -> bool:
    """Subset of `git check-ref-format --branch`, plus no leading '-' so the
    value can never be parsed as a gh/git option."""
    if not name or len(name) > 200 or name == "@" or "@{" in name:
        return False
    if _BAD_REF_CHARS.search(name) or ".." in name or "//" in name:
        return False
    if name.startswith(("-", "/")) or name.endswith(("/", ".")):
        return False
    return not any(c.startswith(".") or c.endswith(".lock")
                   for c in name.split("/"))


_REPO_FIELDS = ("name", "default_branch", "archived", "fork", "size", "disabled")


def list_org_repos(gh: GhClient, org: str, page_size: int = 100) -> list[dict]:
    """Org repo listing, one gh call per page. No arbitrary ceiling.

    A single `gh api --paginate` call ran every page inside one subprocess
    under one --gh-timeout: a 20k-repo org (200 pages) exceeded it, the
    retry restarted from page 1, and the whole org was reported as
    unlistable. Per-page calls are individually timed, throttled, counted
    and retried. Sorting by creation date ascending keeps pages stable
    while repos are being created during the listing (new repos land on the
    last page); names are de-duplicated in case of a concurrent delete."""
    repos: list[dict] = []
    seen: set[str] = set()
    page = 1
    while True:
        data = gh.json(["api", f"orgs/{org}/repos?per_page={page_size}"
                               f"&type=all&sort=created&direction=asc&page={page}"])
        if data is None:
            data = []
        if not isinstance(data, list):
            raise GhError(["gh", "api", f"orgs/{org}/repos"], -1,
                          f"unexpected repo listing payload on page {page}")
        for r in data:
            name = (r or {}).get("name") if isinstance(r, dict) else None
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            repos.append({k: r.get(k) for k in _REPO_FIELDS})
        if len(data) < page_size:
            break
        page += 1
    log.info("Listed %d repos in %s (%d API pages)", len(repos), org, page)
    return repos


class OrgDiscoveryError(RuntimeError):
    """The target org list could not be determined."""


def read_orgs_file(path: str) -> list[str]:
    """One org login per line; blank lines and '#' comments ignored. Same
    format as the bulk enterprise integration script's --orgs-file."""
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f
                if ln.strip() and not ln.strip().startswith("#")]


def dedupe_orgs(orgs: list[str]) -> list[str]:
    """Org logins are case-insensitive on GitHub; keep first spelling/order."""
    seen: set[str] = set()
    out: list[str] = []
    for o in orgs:
        if o.lower() not in seen:
            seen.add(o.lower())
            out.append(o)
    return out


def list_enterprise_orgs(gh: GhClient, enterprise: str,
                         page_size: int = 100) -> list[str]:
    """All org logins in a GitHub Enterprise Cloud enterprise via GraphQL
    (token needs read:enterprise). Orgs the token cannot see, usually SAML
    SSO not authorized for the PAT on that org, come back as null nodes
    with an entry in `errors`; gh then exits non-zero but still prints the
    partial data, which is salvaged. The result is checked against
    totalCount and a warning names how many orgs are out of reach."""
    query = ("query($enterprise: String!, $first: Int!, $cursor: String) {"
             " enterprise(slug: $enterprise) {"
             " organizations(first: $first, after: $cursor) {"
             " totalCount nodes { login } pageInfo { hasNextPage endCursor }"
             " } } }")
    orgs: list[str] = []
    seen: set[str] = set()
    hidden = 0
    total: int | None = None
    cursor: str | None = None
    while True:
        args = ["api", "graphql", "-f", f"query={query}",
                "-f", f"enterprise={enterprise}", "-F", f"first={page_size}"]
        if cursor:
            args += ["-f", f"cursor={cursor}"]
        try:
            payload = gh.json(args) or {}
            errors: list = []
        except GhError as e:
            try:
                payload = json.loads(e.stdout) if e.stdout.strip() else {}
            except json.JSONDecodeError:
                payload = {}
            errors = [e.stderr.strip()[:200]]
        if not isinstance(payload, dict):
            payload = {}
        errors += [str((x or {}).get("message", x))[:200]
                   for x in (payload.get("errors") or [])]
        ent = (payload.get("data") or {}).get("enterprise")
        conn = (ent or {}).get("organizations")
        if conn is None:
            raise OrgDiscoveryError(
                f"Enterprise '{enterprise}' is not readable with this token "
                f"after {len(orgs)} orgs (check the slug, the read:enterprise "
                f"scope, and SSO authorization): {'; '.join(errors[:3])}")
        for node in conn.get("nodes") or []:
            login = (node or {}).get("login")
            if not login:
                hidden += 1
            elif not valid_login(login):
                log.warning("Skipping enterprise org with an unexpected login "
                            "format: %r", sanitize(login))
            elif login.lower() not in seen:
                seen.add(login.lower())
                orgs.append(login)
        if isinstance(conn.get("totalCount"), int):
            total = conn["totalCount"]
        info = conn.get("pageInfo") or {}
        if not info.get("hasNextPage"):
            break
        nxt = info.get("endCursor")
        if not nxt or nxt == cursor:
            raise OrgDiscoveryError("Enterprise org pagination returned no new "
                                    f"cursor after {len(orgs)} orgs")
        cursor = nxt
    if hidden:
        log.warning("%d enterprise org(s) are hidden from this token (usually "
                    "SAML SSO not authorized for the PAT on those orgs) and "
                    "will NOT be processed", hidden)
    if total is not None and len(orgs) + hidden != total:
        log.warning("Enterprise reports %d orgs but discovery returned %d "
                    "visible + %d hidden; the list may be incomplete",
                    total, len(orgs), hidden)
    log.info("Discovered %d orgs in enterprise %s", len(orgs), enterprise)
    return orgs


def resolve_orgs(gh: GhClient, args) -> list[str]:
    """Target orgs, with the same semantics as the bulk enterprise
    integration script:
      --org / --orgs-file          explicit list (union of both)
      --enterprise                 every org in the enterprise
      --enterprise + explicit list the explicit list filtered to orgs that
                                   are actually in the enterprise"""
    explicit: list[str] = list(args.org or [])
    if args.orgs_file:
        try:
            from_file = read_orgs_file(args.orgs_file)
        except OSError as e:
            raise OrgDiscoveryError(f"Cannot read --orgs-file {args.orgs_file}: {e}")
        if not from_file:
            raise OrgDiscoveryError(f"--orgs-file {args.orgs_file} has no org names")
        explicit += from_file
    bad = [o for o in explicit if not valid_login(o)]
    if bad:
        raise OrgDiscoveryError("Invalid organization login(s): "
                                + ", ".join(repr(sanitize(o)) for o in bad[:5]))
    explicit = dedupe_orgs(explicit)
    if not args.enterprise:
        return explicit
    ent_orgs = list_enterprise_orgs(gh, args.enterprise)
    if not explicit:
        if not ent_orgs:
            raise OrgDiscoveryError(f"Enterprise '{args.enterprise}' returned no "
                                    f"organizations visible to this token")
        return ent_orgs
    ent_lower = {o.lower(): o for o in ent_orgs}
    missing = [o for o in explicit if o.lower() not in ent_lower]
    if missing:
        log.warning("Not in enterprise %s (or hidden by SSO), skipped: %s",
                    args.enterprise, ", ".join(missing))
    kept = [ent_lower[o.lower()] for o in explicit if o.lower() in ent_lower]
    log.info("Filtered to %d of %d enterprise orgs", len(kept), len(ent_orgs))
    return kept


def fetch_languages(gh: GhClient, org: str, repo: str) -> dict[str, int]:
    return gh.json(["api", f"repos/{org}/{repo}/languages"], ok_statuses=(404,)) or {}


def _parse_language_batch(payload: dict, group: list[str],
                          out: dict[str, dict[str, int]],
                          blobs: dict[str, tuple[str, str]] | None = None,
                          empties: set[str] | None = None) -> None:
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
        if empties is not None and node.get("isEmpty") is True:
            empties.add(n)
        blob = node.get("veracodeYml")
        if blobs is not None and isinstance(blob, dict) and blob.get("oid") \
                and isinstance(blob.get("text"), str) and not blob.get("isTruncated"):
            blobs[n] = (blob["oid"], blob["text"].lstrip(chr(0xFEFF)))


GRAPHQL_MIN_SPLIT = 10  # batches larger than this are halved on failure


def batch_fetch_languages(gh: GhClient, org: str, names: list[str],
                          chunk: int = 40,
                          blobs: dict[str, tuple[str, str]] | None = None,
                          empties: set[str] | None = None
                          ) -> dict[str, dict[str, int]]:
    """Fetch language data for many repos per API call via aliased GraphQL
    queries, instead of one REST call per repo. For a 20k-repo org this is
    the difference between finishing inside the rate limit and sleeping for
    hours.

    Batching is an optimization, never a source of truth for absence: any
    repo missing from the result (renamed, inaccessible, whole-batch
    failure) silently falls back to the per-repo REST call in inspect_repo.
    gh exits non-zero when a GraphQL response contains an errors array but
    still prints the partial data body to stdout, so per-repo errors inside
    an otherwise good batch are salvaged rather than discarding the chunk.

    A batch that fails outright (GraphQL timeouts on large repos surface as
    HTTP 502) is split in half and retried, down to GRAPHQL_MIN_SPLIT repos,
    before its repos are left to REST. Two consecutive failures at the
    minimum size disable batching for the rest of the org.

    With `blobs`, the root veracode.yml at HEAD (oid + text) is fetched in
    the same query and stored per repo; the caller uses it only when the
    oid equals the tree's blob sha, else falls back to the REST blob read.
    With `empties`, names whose repository has no commits are collected
    (GitHub's REST `size` is 0 until an hourly job runs, so it cannot tell
    a fresh repo from an empty one)."""
    out: dict[str, dict[str, int]] = {}
    extra = ""
    if blobs is not None:
        extra += ("veracodeYml: object(expression: \"HEAD:veracode.yml\") "
                  "{ ... on Blob { oid text isTruncated } } ")
    if empties is not None:
        extra += "isEmpty "
    hard_failures = 0
    queue: deque[list[str]] = deque(names[i:i + chunk]
                                    for i in range(0, len(names), chunk))
    while queue:
        if hard_failures >= 2:
            # GraphQL endpoint is unhealthy; each failed chunk costs a full
            # retry ladder. Stop probing and let every remaining repo use
            # the per-repo REST path instead.
            log.warning("GraphQL batching disabled after %d consecutive "
                        "failures; remaining %d repos use REST.",
                        hard_failures, sum(len(g) for g in queue))
            break
        group = queue.popleft()
        parts = [
            f"r{j}: repository(owner: {json.dumps(org)}, name: {json.dumps(n)}) "
            # Explicit SIZE DESC order: the schema defines no default order,
            # so a plain first:N could drop the dominant language on repos
            # with many small ones. 100 matches the REST endpoint's output.
            "{ languages(first: 100, orderBy: {field: SIZE, direction: DESC}) "
            "{ edges { size node { name } } } " + extra + "}"
            for j, n in enumerate(group)
        ]
        query = "query { " + " ".join(parts) + " }"
        splittable = len(group) > GRAPHQL_MIN_SPLIT
        try:
            # A splittable batch gets a short retry ladder: halving it is a
            # better remedy for a server-side timeout than resending it.
            data = gh.json(["api", "graphql", "-f", f"query={query}"],
                           max_retries=2 if splittable else None)
            payload = (data or {}).get("data") or {}
            hard_failures = 0
        except GhAuthError:
            raise
        except GhError as e:
            try:
                payload = (json.loads(e.stdout) or {}).get("data") or {}
            except (json.JSONDecodeError, AttributeError):
                payload = {}
            if not payload:
                if splittable:
                    half = len(group) // 2
                    queue.appendleft(group[half:])
                    queue.appendleft(group[:half])
                    log.info("GraphQL batch of %d failed, retrying as two "
                             "batches: %s", len(group), e.stderr.strip()[:150])
                    continue
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
        _parse_language_batch(payload, group, out, blobs, empties)
    return out


def _fetch_tree_raw(gh: GhClient, org: str, repo: str, ref: str,
                    recursive: bool) -> tuple[list[dict], bool]:
    """All tree entries (blobs, trees, submodule commits) for a ref or tree
    sha. 409 (empty repository) returns no entries; 404 fails the repo."""
    url = f"repos/{org}/{repo}/git/trees/{quote(ref, safe='')}"
    if recursive:
        url += "?recursive=1"
    # 409 = empty repository, a real absence. 404 is NOT treated as absence:
    # it means the tree could not be read (permissions, SSO, a transient
    # ref problem). Treating it as "no files" disabled SCA on repos with
    # real manifests (fail-closed), so it now fails the repo instead.
    try:
        data = gh.json(["api", url], ok_statuses=(409,))
    except GhAuthError:
        raise
    except GhError as e:
        if re.search(r"\bhttp 404\b", e.stderr.lower()):
            raise GhError(e.cmd, e.returncode,
                          "git tree not readable (HTTP 404); refusing to decide "
                          "scans without file evidence", e.stdout) from e
        raise
    if not isinstance(data, dict):
        return [], False
    return list(data.get("tree") or []), bool(data.get("truncated"))


def fetch_tree(gh: GhClient, org: str, repo: str, branch: str,
               recursive: bool = True) -> tuple[list[dict], bool]:
    entries, truncated = _fetch_tree_raw(gh, org, repo, branch, recursive)
    return [e for e in entries if e.get("type") == "blob"], truncated


def complete_truncated_tree(gh: GhClient, org: str, repo: str,
                            partial: list[dict], max_fetches: int
                            ) -> tuple[list[dict], bool]:
    """Rebuild a full blob listing after the recursive tree API truncated
    (100,000 entries / 7 MB). Starts from the root listing and fetches each
    top-level directory's subtree recursively by sha; a subtree that is
    itself truncated is descended one level at a time. Bounded by
    max_fetches API calls (the root listing is one of them).

    Returns (blob entries, complete). Partial results are always merged in,
    so detection never sees less than the truncated listing did. When the
    budget runs out the tree stays marked truncated and every fail-open rule
    still applies."""
    blobs: dict[str, dict] = {e["path"]: e for e in partial
                              if e.get("type") == "blob" and e.get("path")}
    if max_fetches <= 0:
        return list(blobs.values()), False
    calls = 1
    root, _ = _fetch_tree_raw(gh, org, repo, "HEAD", recursive=False)
    queue: deque[tuple[str, str]] = deque()
    for e in root:
        if e.get("type") == "blob":
            blobs[e["path"]] = e
        elif e.get("type") == "tree" and e.get("sha"):
            queue.append((e["path"], e["sha"]))
    complete = True
    while queue:
        if calls >= max_fetches:
            complete = False
            break
        prefix, sha = queue.popleft()
        sub, truncated = _fetch_tree_raw(gh, org, repo, sha, recursive=True)
        calls += 1
        for e in sub:
            if e.get("type") == "blob" and e.get("path"):
                blobs[f"{prefix}/{e['path']}"] = dict(e, path=f"{prefix}/{e['path']}")
        if truncated:
            if calls >= max_fetches:
                complete = False
                break
            level, _ = _fetch_tree_raw(gh, org, repo, sha, recursive=False)
            calls += 1
            for e in level:
                full = f"{prefix}/{e.get('path', '')}"
                if e.get("type") == "blob" and e.get("path"):
                    blobs[full] = dict(e, path=full)
                elif e.get("type") == "tree" and e.get("sha"):
                    queue.append((full, e["sha"]))
    log.info("[%s] truncated tree %s with %d subtree calls (%d files)", repo,
             "completed" if complete else "partially completed (budget "
             "exhausted, detection stays fail-open)", calls, len(blobs))
    return sorted(blobs.values(), key=lambda e: e["path"]), complete


def inspect_repo(gh: GhClient, org: str, repo: dict,
                 prefetched_languages: dict[str, dict[str, int]] | None = None,
                 max_subtree_fetches: int = 0) -> RepoInfo:
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
    if truncated:
        if max_subtree_fetches > 0:
            entries, complete = complete_truncated_tree(
                gh, org, name, entries, max_subtree_fetches)
            truncated = not complete
        else:
            # Recursive listing was cut off. Root-level files (where
            # manifests and most IaC entry points live) may be missing, so
            # merge in a guaranteed non-recursive root listing.
            root_entries, _ = fetch_tree(gh, org, name, "HEAD", recursive=False)
            seen = {e.get("path") for e in entries}
            entries += [e for e in root_entries if e.get("path") not in seen]
        if truncated:
            log.warning("[%s] git tree truncated by API. Detection is "
                        "best-effort; scans are kept ENABLED when in doubt.",
                        name)
    info.tree_truncated = truncated

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
        # "/k8s/" style needles, matched against "/" + directory + "/".
        self.iac_dir_hints = tuple(
            "/" + d.strip("/").lower() + "/" for d in m["IAC_DIR_HINTS"]
            if d.strip("/"))
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

    Active wherever the framework's marker file sits: at the root it
    excludes android/, ios/, ... and in a monorepo app directory it excludes
    that app's siblings (apps/mobile/pubspec.yaml -> apps/mobile/android/).
    Root-only matching let a nested Flutter app's Gradle wrapper enable Java
    SCA and its Windows runner (C++/CMake) enable SAST. Markers inside
    vendored paths are ignored so a committed dependency cannot hide code."""
    out: set[str] = set()
    for p in paths:
        lp = p.lower()
        parent, _, base = lp.rpartition("/")
        dirs = mx.framework_platform_dirs.get(base)
        if not dirs or not is_scannable_path(lp, mx):
            continue
        prefix = parent + "/" if parent else ""
        out.update(prefix + d + "/" for d in dirs if d)
    return tuple(sorted(out))


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
    sca_forced_by_truncation = False
    if not sca and info.tree_truncated:
        # Fail open regardless of language: a truncated tree cannot prove
        # absence of manifests (a notebook repo's requirements.txt may sit
        # past the cut-off, and Linguist reports "Jupyter Notebook").
        sca = True
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
        elif lp.endswith((".yml", ".yaml", ".json")) and "/" in lp and any(
                h in "/" + lp.rsplit("/", 1)[0] + "/" for h in mx.iac_dir_hints):
            iac_artifacts.add(lp)
    if all_langs & mx.iac_languages:
        iac_artifacts.add(f"languages:{sorted(all_langs & mx.iac_languages)}")
    if deep_iac_hits:
        iac_artifacts.update(deep_iac_hits)
    if iac_mode == "off":
        iac = False
        iac_reason = ("disabled org-wide via --iac off (secret scanning is "
                      "part of this scan and is disabled too)")
    elif iac_mode == "artifacts":
        iac = bool(iac_artifacts) or info.tree_truncated
        if iac_artifacts:
            iac_reason = "artifacts present"
        elif iac:
            iac_reason = ("tree truncated, cannot prove absence of IaC "
                          "artifacts, kept enabled")
        else:
            iac_reason = ("no IaC/container artifacts detected (--iac "
                          "artifacts); secret scanning is part of this scan "
                          "and is disabled too")
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
        sca_reason = ("tree truncated, cannot prove absence of manifests, "
                      "kept enabled (fail-open)")
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
        "iac_artifacts": sorted(iac_artifacts)[:EVIDENCE_CAP],
        "iac_artifacts_total": len(iac_artifacts),
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


REMOVAL_PR_TITLE = "Remove Veracode scan scoping override"
SCOPING_PR_TITLE = "Scope Veracode scans to relevant scan types"


def find_pr(gh: GhClient, org: str, repo: str, head: str, open_only: bool) -> str | None:
    """URL of the newest open PR from `head`, or (open_only=False) of the
    newest scoping PR closed WITHOUT merging, i.e. one the owners declined.
    Merged PRs were accepted, and the tool's own removal PRs are not a
    verdict on scoping, so neither counts as declined."""
    if open_only:
        out = gh.run(["pr", "list", "-R", f"{org}/{repo}", "--head", head,
                      "--state", "open", "--json", "url,state",
                      "--jq", ".[0].url // empty"])
        return out.strip() or None
    out = gh.run(["pr", "list", "-R", f"{org}/{repo}", "--head", head,
                  "--state", "all", "--json", "url,state,title,mergedAt"])
    try:
        prs = json.loads(out) if out.strip() else []
    except json.JSONDecodeError:
        return None
    # Newest first: only the latest scoping PR's fate counts, so an old
    # rejection later superseded by a merged scoping PR is not "declined".
    for pr in prs if isinstance(prs, list) else []:
        if not isinstance(pr, dict) or str(pr.get("title", "")).startswith(
                REMOVAL_PR_TITLE):
            continue
        state = str(pr.get("state", "")).upper()
        if state == "OPEN":
            continue
        if state == "CLOSED" and not pr.get("mergedAt"):
            return pr.get("url") or None
        return None
    return None


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
    title = (REMOVAL_PR_TITLE if action == "delete" else SCOPING_PR_TITLE)
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


STALE_PR_COMMENTS = {
    "no_override": "a fresh scan of the default branch shows every scan type "
                   "is relevant, so no override is needed.",
    "already_correct": "the default branch already has the correct "
                       "veracode.yml settings, so this PR is no longer needed.",
    "outdated": "its veracode.yml no longer matches a fresh scan of the "
                "default branch.",
}


def close_stale_pr(gh: GhClient, org: str, repo: str, url: str,
                   why: str = "no_override") -> None:
    gh.run(["pr", "close", url, "-R", f"{org}/{repo}", "--comment",
            "Closed by veracode-scan-scoping: " + STALE_PR_COMMENTS[why]])


def reconcile_open_pr(gh: GhClient, org: str, repo: str, args,
                      stale_pr_repos: set[str] | None, report_entry: dict,
                      why: str, desired: str | None = None) -> None:
    """Close the repo's open scoping PR when the default branch no longer
    needs it. With `desired`, a PR whose branch already carries exactly that
    content is kept (it is still the right proposal). Only repos the per-org
    search flagged cost any extra calls; best effort, dry-run safe."""
    if not stale_pr_repos or repo.lower() not in stale_pr_repos:
        return
    url = find_pr(gh, org, repo, args.branch_name, open_only=True)
    if not url:
        return
    if desired is not None and get_file_sha_on_ref(
            gh, org, repo, args.branch_name) == git_blob_sha(desired):
        return
    report_entry["stale_pr"] = url
    if args.dry_run:
        log.info("[%s/%s] would close outdated scoping PR %s", org, repo, url)
    else:
        close_stale_pr(gh, org, repo, url, why)
        log.info("[%s/%s] closed outdated scoping PR %s", org, repo, url)


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
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) >= 1000:
        # The search API returns at most 1000 results per query.
        log.warning("[%s] stale-PR search hit the 1000-result search cap; "
                    "some outdated scoping PRs may not be reconciled this run",
                    org)
    return {ln.rstrip("/").rsplit("/", 1)[-1].lower() for ln in lines}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

TERMINAL_OUTCOMES = {"no_change", "already_correct", "committed", "pr_opened",
                     "skipped_existing_file", "pr_declined",
                     "skipped_central_repo"}

_CENTRAL_WORKFLOW_RE = re.compile(r"^\.github/workflows/veracode-[^/]*\.ya?ml$")


def looks_like_central_repo(paths: list[str]) -> bool:
    """Root veracode.yml plus the integration's .github/workflows/veracode-*
    workflows: the org's central config repo (or a copy of it)."""
    return "veracode.yml" in paths and any(
        _CENTRAL_WORKFLOW_RE.match(p.lower()) for p in paths)


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", chr(13))


def _csv_cell(v):
    """Neutralize spreadsheet formula injection: repo-controlled strings
    (repo names, default branch names, reasons with file names) starting
    with = + - @ TAB or CR are evaluated by Excel/Sheets when the CSV is
    opened. A leading ' makes them plain text."""
    if isinstance(v, str) and v.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + v
    return v


def write_csv_report(path: str, report: list[dict]) -> None:
    """Flatten the per-repo report list into a CSV: one row per repo, scan
    decisions and reasons as columns, easy to open in Excel/Sheets for
    client review of a dry run before anything is written to GitHub."""
    fieldnames = [
        "org", "repo", "default_branch", "tree_truncated", "outcome", "action",
        "existing_file", "override_written",
        "sast", "sast_reason",
        "sca", "sca_reason",
        "iac", "iac_reason",
        "runner", "runner_reason",
        "languages", "pr_url", "error", "carried_over",
        # Appended after the original columns so positional consumers of
        # earlier CSVs keep working.
        "error_category",
    ]
    _atomic_write_text(path, lambda tmp: _write_csv_rows(tmp, fieldnames, report))


def _write_csv_rows(path: str, fieldnames: list[str], report: list[dict]) -> None:
    # utf-8-sig: Excel only detects UTF-8 with a BOM, and the locale default
    # (cp1252 on Windows) crashes on non-ASCII file names in reasons.
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in report:
            d = r.get("decision") or {}
            reasons = d.get("reasons", {})
            row = {
                "org": r.get("org", ""),
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
                "error_category": r.get("error_category", ""),
            }
            writer.writerow({k: _csv_cell(v) for k, v in row.items()})


def matches_any(name: str, patterns: list[str]) -> bool:
    # Case-insensitive: GitHub repo names are case-preserving but not
    # case-sensitive for identity, and fnmatch on POSIX is case-sensitive.
    return any(fnmatch.fnmatch(name.lower(), p.lower()) for p in patterns)


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--org", nargs="+", default=None, metavar="ORG",
                    help="One or more GitHub organizations")
    ap.add_argument("--orgs-file", default=None,
                    help="File with one org login per line ('#' comments "
                         "allowed). Combined with --org; with --enterprise "
                         "it filters the enterprise's orgs.")
    ap.add_argument("--enterprise", default=None, metavar="SLUG",
                    help="Process every org in this GitHub Enterprise Cloud "
                         "enterprise (token needs read:enterprise). With "
                         "--org/--orgs-file, only those orgs are processed.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print decisions and generated YAML, change nothing")
    ap.add_argument("--direct-commit", action="store_true",
                    help="Commit to the default branch instead of opening a PR")
    ap.add_argument("--branch-name", default="chore/veracode-scan-scoping",
                    help="Branch used for scoping PRs (validated as a git "
                         "branch name)")
    ap.add_argument("--include", nargs="+", default=["*"],
                    help="Glob patterns of repos to include")
    ap.add_argument("--exclude", nargs="*", default=["veracode"],
                    help="Glob patterns to skip (the --central-repo is "
                         "always excluded)")
    ap.add_argument("--central-repo", default="veracode", metavar="NAME",
                    help="Name of the central Veracode integration repo "
                         "(default veracode). Always excluded, even with "
                         "--force; any repo that looks like one (root "
                         "veracode.yml + .github/workflows/veracode-*.yml) "
                         "is skipped too.")
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
                         "app.config, AssemblyInfo, vbproj/fsproj) "
                         "automatically trigger project-file inspection. "
                         "off: never write a runner.")
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
    ap.add_argument("--max-subtree-fetches", type=int, default=25,
                    help="When GitHub truncates a repo's recursive tree "
                         "(over 100,000 entries / 7 MB), rebuild it from "
                         "per-directory subtree listings using up to N extra "
                         "API calls (default 25). If the budget runs out the "
                         "repo keeps fail-open handling. 0 disables.")
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


def process_org(gh: GhClient, org: str, repos: list[dict], args, mx: Matrices,
                excludes: list[str], iac_mode: str,
                resume_done: set[tuple[str, str]], report: list[dict],
                summary: dict, on_repo_done=None) -> None:
    """Filter, inspect, decide and deliver for every repo of one org.
    Per-repo failures are recorded and never stop the org or the run.
    KeyboardInterrupt and GhAuthError propagate so the caller can flush
    reports and stop. on_repo_done() is called after every repo (used for
    report checkpoints)."""
    def label(name: str) -> str:
        return f"{org}/{name}"

    # Pre-filter so resume skipping and language prefetching only consider
    # repos that will actually be processed.
    todo: list[dict] = []
    for repo in repos:
        name = repo["name"]
        if name.lower() == args.central_repo.lower() or \
                not matches_any(name, args.include) or matches_any(name, excludes):
            summary["skipped"].append((label(name), "filtered")); continue
        if repo.get("archived") and not args.include_archived:
            summary["skipped"].append((label(name), "archived")); continue
        if repo.get("fork") and not args.include_forks:
            summary["skipped"].append((label(name), "fork")); continue
        if repo.get("disabled"):
            summary["skipped"].append((label(name), "disabled")); continue
        # size == 0 is NOT used as an emptiness test: GitHub computes size
        # hourly and reports 0 for freshly pushed repos. Emptiness comes
        # from GraphQL isEmpty below, or from the tree API's 409.
        if (org.lower(), name.lower()) in resume_done:
            summary["skipped"].append((label(name),
                                       "already processed (--resume-from)"))
            continue
        todo.append(repo)
    log.info("[%s] %d of %d repos to process after filtering", org, len(todo),
             len(repos))

    prefetched_languages: dict[str, dict[str, int]] = {}
    prefetched_blobs: dict[str, tuple[str, str]] = {}
    empty_repos: set[str] = set()
    if todo and not args.no_graphql:
        prefetched_languages = batch_fetch_languages(
            gh, org, [r["name"] for r in todo], blobs=prefetched_blobs,
            empties=empty_repos)
        log.info("[%s] Prefetched languages for %d/%d repos via GraphQL "
                 "(any missing fall back to per-repo REST)", org,
                 len(prefetched_languages), len(todo))
        if empty_repos:
            for repo in todo:
                if repo["name"] in empty_repos:
                    summary["skipped"].append((label(repo["name"]), "empty"))
            todo = [r for r in todo if r["name"] not in empty_repos]

    # Open scoping PRs that a fresh scan no longer justifies (the repo
    # gained code while the PR sat unmerged, the default branch already has
    # the right settings, or --direct-commit just wrote them) are closed,
    # so a stale proposal cannot be merged later.
    stale_pr_repos: set[str] | None = set()
    if todo:
        stale_pr_repos = search_open_scoping_prs(gh, org, args.branch_name)

    for idx, repo in enumerate(todo, 1):
        name = repo["name"]
        log.info("[%s %d/%d] %s", org, idx, len(todo), name)
        report_entry: dict | None = None
        calls_before = gh.api_calls
        try:
            info = inspect_repo(gh, org, repo, prefetched_languages,
                                max_subtree_fetches=args.max_subtree_fetches)
            if not info.paths and not info.languages:
                summary["skipped"].append((label(name), "no readable content"))
                continue
            if looks_like_central_repo(info.paths):
                # A copy/rename of the central integration repo: its
                # veracode.yml is the org-wide config, never an override.
                log.warning("[%s/%s] looks like a central Veracode integration "
                            "repo (root veracode.yml + veracode-* workflows); "
                            "never touched, even with --force", org, name)
                summary["skipped"].append((label(name), "central integration repo"))
                report.append({"org": org, "repo": name,
                               "default_branch": info.default_branch,
                               "outcome": "skipped_central_repo"})
                continue

            deep_hits = None
            if args.deep_iac and iac_mode == "artifacts":
                cands = ambiguous_root_yaml(info, mx)
                if cands:
                    deep_hits = deep_iac_confirm(gh, org, name,
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
                    dotnet_hit = deep_dotnet_check(gh, org, name,
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

            log.info("[%s/%s] SAST=%s SCA=%s IaC=%s runner=%s", org, name,
                     decision.sast, decision.sca, decision.iac,
                     decision.runner or "default")
            # Why a scan is off, or why Windows was chosen, is what an
            # administrator reviews first: INFO. Reasons for enabled scans
            # stay at DEBUG (-v) to keep large runs readable.
            for k in SECTION_KEYS:
                level = logging.DEBUG if getattr(decision, k) else logging.INFO
                log.log(level, "[%s/%s] %s %s: %s", org, name, k.upper(),
                        "on" if getattr(decision, k) else "off",
                        decision.reasons[k])
            if decision.runner:
                log.info("[%s/%s] Windows runner %s: %s", org, name,
                         decision.runner, decision.reasons.get("runner", ""))
            else:
                log.debug("[%s/%s] runner: %s", org, name,
                          decision.reasons.get("runner", ""))

            report_entry = {"org": org, "repo": name,
                            "default_branch": info.default_branch,
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
                    summary["unchanged_identical"].append(label(name))
                    report_entry["outcome"] = "already_correct"
                    log.info("[%s/%s] existing veracode.yml already matches, "
                             "skipping", org, name)
                    reconcile_open_pr(gh, org, name, args, stale_pr_repos,
                                      report_entry, "already_correct")
                    continue
                pre_oid, pre_text = prefetched_blobs.get(name, (None, None))
                if pre_oid == info.existing_veracode_sha:
                    existing_text = pre_text  # same blob, no REST read
                else:
                    existing_text = fetch_blob_text(gh, org, name,
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
                    summary["no_change"].append(label(name))
                    log.info("[%s/%s] %s", org, name, note)
                    reconcile_open_pr(gh, org, name, args, stale_pr_repos,
                                      report_entry, "no_override")
                    continue
            else:
                if info.existing_veracode_sha:
                    if existing_text is not None and \
                            yaml_body(existing_text) == yaml_body(content):
                        # Same settings, only the reason header differs
                        # (a file list or truncation note changed). No
                        # churn, no --force needed.
                        summary["unchanged_identical"].append(label(name))
                        report_entry["outcome"] = "already_correct"
                        log.info("[%s/%s] existing veracode.yml has identical "
                                 "settings, skipping", org, name)
                        reconcile_open_pr(gh, org, name, args, stale_pr_repos,
                                          report_entry, "already_correct")
                        continue
                    if not existing_managed and not args.force:
                        summary["skipped"].append(
                            (label(name), "hand-written veracode.yml with "
                                          "different settings (review, or use "
                                          "--force)"))
                        report_entry["outcome"] = "skipped_existing_file"
                        reconcile_open_pr(gh, org, name, args, stale_pr_repos,
                                          report_entry, "outdated",
                                          desired=content)
                        continue
                    if not existing_managed:
                        log.warning("[%s/%s] --force: overwriting hand-written "
                                    "veracode.yml", org, name)
                action = "write"
            report_entry["action"] = action

            if args.dry_run:
                if action == "delete":
                    print(f"\n===== {org}/{name} (dry run) =====\n"
                          f"# would DELETE the managed veracode.yml: every "
                          f"scan type is relevant now\n")
                    report_entry["outcome"] = "would_delete"
                else:
                    print(f"\n===== {org}/{name} (dry run) =====\n{content}")
                    report_entry["outcome"] = "would_write"
                summary["scoped"].append((label(name), f"dry-run ({action})"))
                continue

            msg = ("chore: remove Veracode scan scoping override"
                   if action == "delete" else
                   "chore: scope Veracode scans to relevant scan types")
            if args.direct_commit:
                if action == "delete":
                    delete_file(gh, org, name, info.default_branch,
                                info.existing_veracode_sha, msg)
                else:
                    put_file(gh, org, name, info.default_branch, content,
                             info.existing_veracode_sha, msg)
                summary["scoped"].append((label(name), f"committed ({action}) "
                                                       f"to {info.default_branch}"))
                report_entry["outcome"] = "committed"
                # An open scoping PR from an earlier PR-mode run is now
                # redundant: the default branch carries the settings.
                reconcile_open_pr(gh, org, name, args, stale_pr_repos,
                                  report_entry,
                                  "no_override" if action == "delete"
                                  else "already_correct")
                continue

            open_url = find_pr(gh, org, name, args.branch_name, open_only=True)
            if not open_url and not existing_managed and not args.reopen_declined:
                closed_url = find_pr(gh, org, name, args.branch_name,
                                     open_only=False)
                if closed_url:
                    # A previous scoping PR was closed without merging and
                    # the default branch carries no managed file: the
                    # owners said no. Do not reopen on every run.
                    summary["skipped"].append(
                        (label(name), f"previous scoping PR declined: "
                                      f"{closed_url} (use --reopen-declined)"))
                    report_entry["outcome"] = "pr_declined"
                    report_entry["pr_url"] = closed_url
                    continue
            if not ensure_branch(gh, org, name, info.default_branch,
                                 args.branch_name, reset_stale=not open_url):
                summary["failed"].append((label(name), "branch creation failed"))
                report_entry["outcome"] = "failed_branch_creation"
                continue
            branch_sha = get_file_sha_on_ref(gh, org, name, args.branch_name)
            if action == "delete":
                delete_file(gh, org, name, args.branch_name, branch_sha, msg)
            else:
                put_file(gh, org, name, args.branch_name, content,
                         branch_sha, msg)
            url = open_url or create_pr(gh, org, name, info.default_branch,
                                        args.branch_name, decision, action,
                                        args.runner_scope)
            summary["scoped"].append((label(name), url))
            report_entry["outcome"] = "pr_opened"
            report_entry["pr_url"] = url
            report_entry["pr_reused"] = bool(open_url)
        except GhAuthError as e:
            _mark_failed(report, report_entry, org, name, str(e)[:500], "auth")
            summary["failed"].append((label(name), "authentication failed"))
            raise
        except GhError as e:
            cat = classify_error(e)
            log.error("[%s/%s] failed (%s): %s", org, name, cat, e)
            summary["failed"].append((label(name), f"[{cat}] {str(e)[:200]}"))
            _mark_failed(report, report_entry, org, name, str(e)[:500], cat)
        except Exception as e:  # never let one repo kill an org-wide run
            log.exception("[%s/%s] unexpected error", org, name)
            cat = classify_error(e)
            summary["failed"].append((label(name), f"[{cat}] "
                                      f"{type(e).__name__}: {e}"))
            _mark_failed(report, report_entry, org, name,
                         f"{type(e).__name__}: {e}", cat)
        finally:
            entry = report_entry if report_entry is not None else (
                report[-1] if report and report[-1].get("repo") == name
                and report[-1].get("org") == org else None)
            if entry is not None:
                entry["api_calls"] = gh.api_calls - calls_before
            if on_repo_done is not None:
                on_repo_done()


CHECKPOINT_EVERY = 25      # repos between report checkpoints
CHECKPOINT_SECONDS = 300   # ... or this many seconds, whichever is first
SUMMARY_LIST_LIMIT = 25    # per-category lines printed without --verbose


def _atomic_write_text(path: str, write) -> None:
    """Write via a temp file and os.replace, so a crash or kill mid-write
    never leaves a truncated report that --resume-from cannot parse."""
    tmp = f"{path}.tmp"
    try:
        write(tmp)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _skip_group(reason: str) -> str:
    """Stable grouping key for skip reasons that embed URLs or names."""
    return reason.split(":", 1)[0].split(" (", 1)[0].strip()


def print_summary(summary: dict, orgs: list[str], org_errors: list[dict],
                  gh: GhClient, elapsed: float, repos_seen: int,
                  verbose: bool) -> None:
    """Counts first, then only the lines an administrator acts on. Large
    runs list at most SUMMARY_LIST_LIMIT entries per category (everything
    is in the JSON/CSV reports); --verbose lists all."""
    limit = None if verbose else SUMMARY_LIST_LIMIT

    def listing(items: list) -> None:
        shown = items if limit is None else items[:limit]
        for it in shown:
            print(f"  {it[0]}: {it[1]}" if isinstance(it, tuple) else f"  {it}")
        if len(items) > len(shown):
            print(f"  ... {len(items) - len(shown)} more (see --report/--csv)")

    print("\n========== SUMMARY ==========")
    print(f"Orgs: {len(orgs)} ({len(org_errors)} not accessible)")
    print(f"Scoped (override written/PR): {len(summary['scoped'])}")
    listing(summary["scoped"])
    print(f"No change needed: {len(summary['no_change'])}")
    if verbose:
        listing(summary["no_change"])
    print(f"Already correct (identical settings): "
          f"{len(summary['unchanged_identical'])}")
    if verbose:
        listing(summary["unchanged_identical"])
    print(f"Skipped: {len(summary['skipped'])}")
    if verbose:
        listing(summary["skipped"])
    else:
        groups: dict[str, int] = {}
        for _, why in summary["skipped"]:
            groups[_skip_group(why)] = groups.get(_skip_group(why), 0) + 1
        for why, n in sorted(groups.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {why}: {n}")
    print(f"Failed: {len(summary['failed'])}")
    listing(summary["failed"])
    per_repo = (gh.api_calls / repos_seen) if repos_seen else 0.0
    print(f"GitHub API calls: {gh.api_calls} ({gh.write_calls} writes, "
          f"{gh.retries} retries, {gh.wait_seconds:.0f}s rate-limit/backoff "
          f"waits); {per_repo:.1f} calls per processed repo; elapsed "
          f"{elapsed / 60:.1f} min")


def _validate_args(args) -> str | None:
    """Return an error message for invalid arguments, else None. Runs before
    any gh call, so bad input never reaches the GitHub API."""
    if not (args.org or args.orgs_file or args.enterprise):
        return "No target orgs: pass --org, --orgs-file and/or --enterprise"
    if args.no_iac and args.iac not in ("always", "off"):
        return f"--no-iac conflicts with --iac {args.iac}"
    if not RUNNER_LABEL_RE.match(args.windows_runner):
        return (f"--windows-runner {args.windows_runner!r} is not a valid "
                f"runner label or flow list")
    if not valid_branch_name(args.branch_name):
        return (f"--branch-name {args.branch_name!r} is not a valid git branch "
                f"name")
    if args.max_project_files < 1 or args.gh_timeout <= 0:
        return "--max-project-files must be >= 1 and --gh-timeout > 0"
    for flag in ("min_interval", "write_interval", "min_remaining",
                 "max_writes_per_hour", "max_subtree_fetches"):
        if getattr(args, flag) < 0:
            return f"--{flag.replace('_', '-')} must be >= 0"
    if args.enterprise and not valid_login(args.enterprise):
        return f"--enterprise {args.enterprise!r} is not a valid enterprise slug"
    explicit = list(args.org or [])
    if args.orgs_file:
        try:
            from_file = read_orgs_file(args.orgs_file)
        except (OSError, UnicodeDecodeError) as e:
            return f"Cannot read --orgs-file {args.orgs_file}: {e}"
        if not from_file:
            return f"--orgs-file {args.orgs_file} has no org names"
        explicit += from_file
    bad = [o for o in explicit if not valid_login(o)]
    if bad:
        return ("Invalid organization login(s): "
                + ", ".join(repr(sanitize(o)) for o in bad[:5]))
    return None


def _load_resume(path: str) -> tuple[set[tuple[str, str]], list[dict]]:
    """Resume state is keyed by (org, repo), case-insensitive. Reports from
    the single-org version carry the org only at the top level; that value
    is used for their entries."""
    resume_done: set[tuple[str, str]] = set()
    carried: list[dict] = []
    with open(path, encoding="utf-8") as f:
        prior = json.load(f)
    prior_org = prior.get("org")
    for r in prior.get("repos", []):
        if not (isinstance(r, dict) and r.get("repo")
                and r.get("outcome") in TERMINAL_OUTCOMES):
            continue
        org_of = r.get("org") or prior_org
        if not isinstance(org_of, str) or not org_of:
            continue
        key = (org_of.lower(), str(r["repo"]).lower())
        if key in resume_done:
            continue
        resume_done.add(key)
        carried.append(dict(r, org=org_of, carried_over=True))
    return resume_done, carried


def _check_auth(gh: GhClient, token_source: str) -> bool:
    """`gh auth status` exits non-zero when ANY configured host or account
    has a problem (a stale second account, an unreachable GHES host), even
    though the active credentials work. On failure, probe the API itself
    (/rate_limit is free and works for PATs and app tokens) before giving
    up."""
    try:
        gh.run(["auth", "status"], max_retries=1)
        log.info("Authenticated via %s", token_source)
        return True
    except FileNotFoundError:
        log.error("GitHub CLI 'gh' was not found on PATH")
        return False
    except GhError as e:
        first = (e.stderr.strip().splitlines() or [""])[0][:200]
        try:
            gh.run(["api", "rate_limit"], max_retries=2)
        except GhError as e2:
            log.error("gh CLI not authenticated (%s): %s", token_source,
                      e2.stderr.strip()[:300] or first)
            return False
        log.warning("`gh auth status` reported a problem (%s) but the API "
                    "accepts the active credentials (%s); continuing.",
                    sanitize(first), token_source)
        return True


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    started = time.monotonic()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s")

    problem = _validate_args(args)
    if problem:
        log.error("%s", problem)
        return 2
    iac_mode = "off" if args.no_iac else args.iac
    if args.deep_iac and iac_mode != "artifacts":
        log.warning("--deep-iac only affects --iac artifacts; ignoring it "
                    "(no extra API calls will be made).")

    overrides = None
    if args.config:
        try:
            with open(args.config, encoding="utf-8") as f:
                overrides = json.load(f)
        except (OSError, ValueError) as e:  # incl. JSON and UTF-8 decode errors
            log.error("Cannot read --config %s: %s", args.config, e)
            return 2
    try:
        mx = Matrices(overrides)
    except ValueError as e:
        log.error("%s", e)
        return 2

    # The central config repo must never receive an override, even when the
    # user supplies a custom --exclude list (which replaces the default
    # rather than extending it). Applies in every org; process_org also
    # checks args.central_repo directly.
    excludes = list(args.exclude)
    if not matches_any(args.central_repo, excludes):
        excludes.append(args.central_repo)
        log.info("Added central '%s' repo to excludes automatically.",
                 args.central_repo)

    resume_done: set[tuple[str, str]] = set()
    carried: list[dict] = []
    if args.resume_from:
        try:
            resume_done, carried = _load_resume(args.resume_from)
            log.info("Resume: %d repos with terminal outcomes in %s will be "
                     "skipped and carried into the new report",
                     len(resume_done), args.resume_from)
        except (OSError, ValueError, AttributeError, TypeError) as e:
            log.error("Cannot read --resume-from %s: %s", args.resume_from, e)
            return 2

    # Dry runs get a read-only client: any write attempt raises before it
    # is sent, independent of the per-call dry-run checks below.
    gh = GhClient(min_interval=args.min_interval, min_remaining=args.min_remaining,
                  timeout=args.gh_timeout, write_interval=args.write_interval,
                  writes_per_hour=args.max_writes_per_hour,
                  read_only=args.dry_run)
    # Authentication is whatever gh resolves: GH_TOKEN, then GITHUB_TOKEN,
    # then stored `gh auth login` credentials (GH_ENTERPRISE_TOKEN/GH_HOST
    # for GHES). Checking one env var here gave false assurance when
    # another token took precedence. One token serves every org, so the
    # rate limiter and write pacing are shared across the whole run.
    token_source = ("GH_TOKEN" if os.environ.get("GH_TOKEN") else
                    "GITHUB_TOKEN" if os.environ.get("GITHUB_TOKEN") else
                    "gh stored credentials")
    if not _check_auth(gh, token_source):
        return 2

    try:
        orgs = resolve_orgs(gh, args)
    except (OrgDiscoveryError, GhError) as e:
        log.error("%s", e)
        return 2
    if not orgs:
        log.error("No orgs left to process")
        return 2
    log.info("Processing %d org(s): %s%s", len(orgs), ", ".join(orgs[:20]),
             f" (+{len(orgs) - 20} more)" if len(orgs) > 20 else "")

    summary = {"scoped": [], "no_change": [], "unchanged_identical": [],
               "skipped": [], "failed": []}
    report: list[dict] = list(carried)
    org_errors: list[dict] = []
    interrupted = False
    aborted: str | None = None
    progress = {"repos": 0, "since_flush": 0, "last_flush": time.monotonic()}

    def flush_reports(final: bool = True) -> None:
        """Write JSON/CSV reports atomically. Called periodically as a
        checkpoint and from a finally block, so an interrupted, killed or
        crashed run still leaves its evidence behind for --resume-from."""
        progress["since_flush"] = 0
        progress["last_flush"] = time.monotonic()
        level = logging.INFO if final else logging.DEBUG
        if args.report:
            doc = {"org": orgs[0] if len(orgs) == 1 else None,
                   "orgs": orgs,
                   "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "api_calls": gh.api_calls,
                   "write_calls": gh.write_calls,
                   "interrupted": interrupted,
                   "aborted": aborted,
                   "complete": final and not interrupted and not aborted,
                   "stats": {"elapsed_seconds": round(time.monotonic() - started, 1),
                             "repos_processed": progress["repos"],
                             "retries": gh.retries,
                             "rate_limit_wait_seconds": round(gh.wait_seconds, 1)},
                   "org_errors": org_errors,
                   "repos": report}

            def write_json(tmp: str) -> None:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(doc, f, indent=2)
            try:
                _atomic_write_text(args.report, write_json)
                log.log(level, "Audit report written to %s", args.report)
            except OSError as e:
                log.error("Failed writing --report %s: %s", args.report, e)
        csv_path = args.csv or ("dry_run_report.csv" if args.dry_run else None)
        if csv_path:
            try:
                write_csv_report(csv_path, report)
                log.log(level, "CSV report written to %s", csv_path)
            except OSError as e:
                log.error("Failed writing CSV %s: %s", csv_path, e)

    def on_repo_done() -> None:
        progress["repos"] += 1
        progress["since_flush"] += 1
        if progress["since_flush"] >= CHECKPOINT_EVERY or \
                time.monotonic() - progress["last_flush"] >= CHECKPOINT_SECONDS:
            flush_reports(final=False)

    def org_failed(org: str, what: str, e: GhError) -> None:
        err = e.stderr.strip()[:300]
        log.error("[%s] %s, skipping this org (check the org name, token "
                  "scopes repo + read:org, and SAML SSO authorization for "
                  "this org): %s", org, what, err)
        org_errors.append({"org": org, "error": f"{what}: {err}",
                           "error_category": classify_error(e)})
        summary["failed"].append((org, f"{what}: {err[:150]}"))

    # SIGTERM (CI cancellation, `kill`, container stop) is handled like
    # Ctrl-C so the finally block below still writes the reports.
    def on_sigterm(signum, frame):
        raise KeyboardInterrupt
    prev_sigterm = None
    try:
        prev_sigterm = signal.signal(signal.SIGTERM, on_sigterm)
    except (ValueError, OSError, AttributeError):  # not main thread / platform
        prev_sigterm = None

    try:
        for oidx, org in enumerate(orgs, 1):
            log.info("========== Org %d/%d: %s ==========", oidx, len(orgs), org)
            try:
                gh.run(["api", f"orgs/{org}", "--jq", ".login"])
            except GhAuthError:
                raise
            except GhError as e:
                org_failed(org, "cannot access org", e)
                continue
            try:
                repos = list_org_repos(gh, org)
            except GhAuthError:
                raise
            except GhError as e:
                org_failed(org, "cannot list repos", e)
                continue
            process_org(gh, org, repos, args, mx, excludes, iac_mode,
                        resume_done, report, summary, on_repo_done)
    except KeyboardInterrupt:
        interrupted = True
        log.warning("Interrupted. Writing partial reports for the %d repos "
                    "processed so far before exiting; rerun with "
                    "--resume-from to continue.", len(report))
    except GhAuthError as e:
        aborted = "authentication"
        log.error("Authentication failed (token expired, revoked, or missing): "
                  "%s. Stopping the run: every remaining call would fail the "
                  "same way. Completed repos are in the report; rerun with "
                  "--resume-from after fixing the credentials.",
                  e.stderr.strip()[:200])
    finally:
        if prev_sigterm is not None:
            try:
                signal.signal(signal.SIGTERM, prev_sigterm)
            except (ValueError, OSError):
                pass
        flush_reports()

    print_summary(summary, orgs, org_errors, gh, time.monotonic() - started,
                  progress["repos"], args.verbose)
    # Exit codes match the sibling bulk tools: 0 ok, 2 any repo or org
    # failed, authentication lost, or nothing could run; 130 interrupted.
    if interrupted:
        return 130
    return 2 if summary["failed"] or org_errors or aborted else 0


def _mark_failed(report: list[dict], entry: dict | None, org: str, name: str,
                 error: str, category: str = "unknown") -> None:
    """Record a failure in the report. Failures before a decision was made
    previously left no trace in the JSON/CSV at all. error_category groups
    failures into actionable classes (auth, permission, protected_branch,
    conflict, rate_limit, timeout, transient, ...)."""
    if entry is None:
        report.append({"org": org, "repo": name, "outcome": "failed",
                       "error": error, "error_category": category})
    else:
        entry["outcome"] = "failed"
        entry["error"] = error
        entry["error_category"] = category


if __name__ == "__main__":
    sys.exit(main())
