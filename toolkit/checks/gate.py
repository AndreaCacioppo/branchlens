#!/usr/bin/env python3
"""
gate.py — the slim mechanical gate (phase 1 of the security pipeline).

One idea replaces the old baseline machinery: every check is scoped to the
DIFF between the base branch and HEAD, and the "what was already there"
reference is computed on the fly from git history (the same files at the
merge-base commit). No stored baseline, no baseline guards, no sealing.

Two tiers of checks, so an environment problem cannot kill the whole run:

  SECURITY CORE (always required; a core check that cannot run makes the
  verdict INCONCLUSIVE):
    - Semgrep on the changed files, new findings vs the base version
    - secret patterns in the added lines of the diff
    - security test files deleted or disabled by the diff
    - scanner suppression files touched by the diff
    - dependency vulnerabilities (Trivy) — only when dependency files changed
    - the exceptions file (expired exceptions block)

  BEST EFFORT (attempted; a real failure still blocks, but "this machine
  cannot build the project" becomes a loud warning instead of a veto):
    - Maven build of an export of HEAD
    - tests (Surefire), including the security-named ones
    - changed code no Semgrep rule examined (named in the verdict line)

Everything is read-only on the target repository: file contents are read from
git objects (git show / git archive), never from the working tree.

Output contract (unchanged from the previous gate, so phase 2 still works):
the run directory gets areas.tsv + run-meta.txt + notes.txt + evidence files,
and checks/verdict.py renders verdict.txt / verdict.json and decides the exit
code: 0 PASSED, 1 FAILED, 2 INCONCLUSIVE, 4 usage error.
"""

import codecs
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone, date
from glob import glob
from xml.etree import ElementTree

# No bytecode for the toolkit's own modules: a .pyc planted in
# checks/__pycache__ would be loaded instead of the source, unseen by the
# source fingerprint.
sys.dont_write_bytecode = True
sys.pycache_prefix = os.path.join(tempfile.gettempdir(),
                                  "preflight-no-bytecode-%d" % os.getpid())

# Progress telemetry for a local viewer (same directory as this script;
# sys.path[0] is the script's directory, so this import works from any cwd).
# Everything in feed.py swallows its own errors: the feed can never break a run.
import feed
import review_scope
# imported now, before any repository code runs: see render_verdict
import verdict

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BUILD_TIMEOUT = int(os.environ.get("PREFLIGHT_BUILD_TIMEOUT", "900"))
TEST_TIMEOUT = int(os.environ.get("PREFLIGHT_TEST_TIMEOUT", "1200"))
SCAN_TIMEOUT = int(os.environ.get("PREFLIGHT_SCAN_TIMEOUT", "600"))

# Severity order used to pick the worst severity of a row.
SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Files whose change can silence a scanner. Deleting one makes the scan
# stricter, so only added/modified/renamed count.
SUPPRESSION_FILE_PATTERNS = (
    ".semgrepignore", ".trivyignore", ".trivyignore.yaml",
    "trivy.yaml", "trivy.yml", "suppressions.xml",
)
SUPPRESSION_NAME_FRAGMENTS = ("spotbugs-exclude", "findbugs-exclude")

# Dependency manifests: when none of these changed, there is nothing new for
# Trivy to judge and the area is NOT APPLICABLE (no network needed at all).
DEPENDENCY_FILE_NAMES = (
    "pom.xml", "package.json", "yarn.lock", "package-lock.json",
    "pnpm-lock.yaml", "Pipfile", "Pipfile.lock", "poetry.lock",
    "pyproject.toml", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
    "uv.lock", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "settings.gradle", "settings.gradle.kts",
)
DEPENDENCY_FILE_PREFIXES = ("requirements",)

# Secret patterns scanned over the ADDED lines of the diff. Each entry is
# (name, regex). The generic assignment pattern is last and is filtered by
# PLACEHOLDER_RE below to keep test fixtures from blocking the gate.
SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("API key (sk-...)", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}")),
    ("credentials in URL",
     re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@")),
    ("hardcoded secret",
     re.compile(r"(?i)(password|passwd|secret|api[_-]?key)\s*[:=]\s*"
                r"[\"'][^\"']{8,}[\"']")),
)
EMPTY_DIFF_REASON = (
    "the diff against %s is empty, so nothing was examined. Pass the base "
    "the change will be compared with; on a first publish, with nothing to "
    "compare with yet, pass the base 'empty-tree' to judge the whole history "
    "as new; to judge uncommitted work, run with --worktree")

# The base for a first publish: the diff starts from the empty tree, and
# every commit of the branch counts as new.
EMPTY_TREE_BASE = "empty-tree"

# The best-effort row naming the changed code no scanner rule examined.
UNCOVERED_CODE_AREA = "Code without scanner rules"

# How each check is named in the progress feed.
CHECK_LABELS = {
    "check_exceptions_file": "Exceptions file",
    "check_secrets": "Secrets",
    "check_security_tests_in_diff": "Security tests in the diff",
    "check_scanner_integrity": "Scanner integrity",
    "check_semgrep": "Semgrep",
    "check_uncovered_code": UNCOVERED_CODE_AREA,
    "check_bandit": "Bandit",
    "check_dependencies": "Dependencies (Trivy)",
    "check_http_hygiene": "Outbound HTTP",
    "check_build_and_tests": "Maven build and tests",
    "check_python_tests": "Python tests",
    "check_python_security_tests": "Python security tests",
}

PLACEHOLDER_RE = re.compile(
    r"(?i)(example|sample|placeholder|changeme|change-me|dummy|your[_-]?"
    r"(key|password|secret|token)|xxxx|\*\*\*|<[^>]*>|\{\{)")

# What the gate treats as code: every changed file except documentation,
# data and binaries. Source code and configuration are named by type; a
# text file of a type no table lists is named as an unknown type, so a new
# kind of file is never skipped in silence.
CODE_LANGUAGE_BY_EXTENSION = {
    "py": "Python", "pyi": "Python",
    "js": "JavaScript", "jsx": "JavaScript", "mjs": "JavaScript",
    "cjs": "JavaScript",
    "ts": "TypeScript", "tsx": "TypeScript", "mts": "TypeScript",
    "cts": "TypeScript",
    "java": "Java",
    "sh": "Shell", "bash": "Shell", "zsh": "Shell", "ksh": "Shell",
    "sbatch": "Shell", "slurm": "Shell", "pbs": "Shell",
    "bashrc": "Shell", "zshrc": "Shell", "profile": "Shell",
    "bash_profile": "Shell", "zprofile": "Shell",
    "kt": "Kotlin", "kts": "Kotlin",
    "go": "Go", "rs": "Rust", "rb": "Ruby", "php": "PHP",
    "c": "C", "h": "C or C++ header", "cc": "C++", "cpp": "C++",
    "cxx": "C++", "hpp": "C++", "hh": "C++", "cs": "C#", "swift": "Swift",
    "scala": "Scala", "groovy": "Groovy", "gradle": "Groovy",
    "dart": "Dart", "lua": "Lua", "r": "R", "jl": "Julia",
    "pl": "Perl", "pm": "Perl", "t": "Perl", "cgi": "Perl", "sql": "SQL",
    "ps1": "PowerShell", "psm1": "PowerShell",
    "bat": "Windows batch", "cmd": "Windows batch",
    "html": "HTML", "htm": "HTML", "vue": "Vue", "svelte": "Svelte",
    "astro": "Astro", "ipynb": "Jupyter notebook", "tf": "Terraform",
    "hcl": "HCL", "nix": "Nix",
    "erb": "ERB template", "ejs": "EJS template", "jsp": "JSP",
    "j2": "Jinja template", "jinja": "Jinja template",
    "jinja2": "Jinja template", "tmpl": "template", "template": "template",
    "hbs": "Handlebars template", "mustache": "Mustache template",
    "twig": "Twig template", "njk": "Nunjucks template",
    "liquid": "Liquid template",
    "ex": "Elixir", "exs": "Elixir", "erl": "Erlang", "hrl": "Erlang",
    "hs": "Haskell", "ml": "OCaml", "fs": "F#", "fsx": "F#",
    "clj": "Clojure", "cljs": "Clojure", "vb": "Visual Basic",
    "zig": "Zig", "nim": "Nim", "cr": "Crystal", "sol": "Solidity",
    "cu": "CUDA", "f90": "Fortran", "f95": "Fortran", "for": "Fortran",
    "s": "Assembly", "asm": "Assembly", "coffee": "CoffeeScript",
    "elm": "Elm", "awk": "awk script", "tcl": "Tcl", "vim": "Vim script",
    "el": "Emacs Lisp", "lisp": "Lisp", "scm": "Scheme", "rkt": "Racket",
    "glsl": "shader", "frag": "shader", "vert": "shader", "comp": "shader",
    "hlsl": "shader", "metal": "shader", "wgsl": "shader",
    "m": "Objective-C or MATLAB", "mm": "Objective-C++",
    "mk": "Makefile", "cmake": "CMake", "bzl": "Starlark",
    "graphql": "GraphQL", "gql": "GraphQL", "proto": "Protocol Buffers",
    "xsl": "XSLT", "xslt": "XSLT",
}
# Configuration can switch on dangerous behaviour (CI jobs run shell,
# a compose file can give a container the host, an XML file can load
# remote classes), so it is treated like code.
CONFIG_LANGUAGE_BY_EXTENSION = {
    "yml": "YAML config", "yaml": "YAML config",
    "xml": "XML config", "xsd": "XML config", "wsdl": "XML config",
    "toml": "TOML config", "conf": "config file (.conf)",
    "ini": "INI config", "cfg": "INI config",
    "properties": "Java properties", "env": "env file",
    "service": "systemd unit", "timer": "systemd unit",
    "socket": "systemd unit", "mount": "systemd unit",
    "plist": "property list", "ga": "Galaxy workflow",
    "pro": "ProGuard rules", "gitmodules": "git submodule list",
    "npmrc": "npm config", "pypirc": "pip upload config",
    "htaccess": "Apache config",
}
# Documentation, data, media, archives and build output: not code.
SKIPPED_EXTENSIONS = frozenset((
    "md", "markdown", "rst", "txt", "adoc", "org", "rtf", "pdf", "doc",
    "docx", "odt", "xls", "xlsx", "ods", "ppt", "pptx", "numbers",
    "csv", "tsv", "json", "jsonl", "ndjson", "geojson", "log", "lock",
    "sum", "mod", "css", "scss", "sass", "less", "map", "snap",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "icns", "bmp", "webp",
    "tif", "tiff", "heic", "psd", "ai", "eps",
    "mp3", "mp4", "m4a", "wav", "flac", "ogg", "mov", "webm", "avi",
    "woff", "woff2", "ttf", "otf", "eot",
    "zip", "gz", "tgz", "tar", "bz2", "xz", "7z", "rar", "jar", "war",
    "whl", "egg", "so", "dylib", "dll", "exe", "bin", "dat", "class",
    "pyc", "o", "a", "wasm",
    "npz", "npy", "pt", "pth", "ckpt", "onnx", "h5", "hdf5", "pkl",
    "pickle", "parquet", "feather", "arrow", "db", "sqlite", "sqlite3",
    "db-journal", "db-wal",
    "fasta", "fa", "fastq", "fq", "fast5", "gbk", "gb", "phy", "tree",
    "nwk", "owl", "graphml", "bam", "sam", "vcf", "bed", "gff", "gtf",
    "shp", "shx", "dbf", "prj", "stl", "obj", "ply",
    "tex", "bib", "bbl", "aux", "toc", "lof", "lot", "nav", "snm", "blg",
    "fls", "fdb_latexmk", "synctex", "out", "cff",
    "patch", "diff", "sha256", "sha1", "md5", "sig", "asc", "pub",
    "completo",
    "gitignore", "gitattributes", "gitkeep", "keep", "nojekyll",
    "editorconfig", "dockerignore", "npmignore", "prettierignore",
    "eslintignore", "mailmap", "python-version", "nvmrc", "node-version",
    "ruby-version", "tool-versions",
))
# Files named without an extension that are documentation.
SKIPPED_NAMES = frozenset((
    "license", "licence", "copying", "notice", "authors", "contributors",
    "changelog", "changes", "readme", "version", "codeowners", "owners",
    "maintainers", "cname",
))
# Files that are code or configuration by their name alone
# (Dockerfile.prod, app.dockerfile, docker-compose.prod.yml and
# application-dev.properties are recognised in code_language).
CODE_LANGUAGE_BY_NAME = {
    "Dockerfile": "Dockerfile", "Containerfile": "Dockerfile",
    "Jenkinsfile": "Jenkinsfile (Groovy)",
    "Makefile": "Makefile", "makefile": "Makefile",
    "GNUmakefile": "Makefile", "CMakeLists.txt": "CMake",
    "Vagrantfile": "Ruby", "Gemfile": "Ruby", "Rakefile": "Ruby",
    "Podfile": "Ruby", "Brewfile": "Ruby", "Procfile": "Procfile",
    "Justfile": "justfile", "justfile": "justfile",
    "Snakefile": "Python", "BUILD": "Starlark", "WORKSPACE": "Starlark",
    "Caddyfile": "Caddy config", "Tiltfile": "Starlark",
    "AndroidManifest.xml": "Android manifest",
    "pom.xml": "Maven POM",
}
GITLAB_CI_LANGUAGE = "GitLab CI pipeline"
COMPOSE_LANGUAGE = "Docker Compose"
SPRING_CONFIG_LANGUAGE = "Spring config"
UNKNOWN_NO_EXTENSION = "unknown type (no extension)"
# code_language's answer when the file's bytes decide (see there).
NEEDS_CONTENT = "needs content"
WORKFLOW_LANGUAGE = "GitHub Actions workflow"
# A script without an extension, by the program its #! line names (version
# digits removed: python3.12 -> python).
LANGUAGE_BY_INTERPRETER = {
    "python": "Python", "node": "JavaScript", "nodejs": "JavaScript",
    "sh": "Shell", "bash": "Shell", "zsh": "Shell", "ksh": "Shell",
    "dash": "Shell", "ash": "Shell", "mksh": "Shell",
    "perl": "Perl", "ruby": "Ruby", "php": "PHP",
}

# The languages the local rules in checks/semgrep-rules/ cover (their
# `languages:` fields; the workflow rules also limit `paths:` to
# .github/workflows/). A core-language file semgrep could not fully scan
# makes the Semgrep row PARTIAL, a veto; a best-effort-language file is
# named in the "Code without scanner rules" row instead, a caveat.
SEMGREP_CORE_LANGUAGES = ("Python", "JavaScript", "TypeScript", "Java")
SEMGREP_BEST_EFFORT_LANGUAGES = ("Shell", "Dockerfile", "Kotlin",
                                 WORKFLOW_LANGUAGE, GITLAB_CI_LANGUAGE,
                                 COMPOSE_LANGUAGE, SPRING_CONFIG_LANGUAGE,
                                 "Android manifest", "Maven POM", "Makefile")
SEMGREP_LANGUAGES = SEMGREP_CORE_LANGUAGES + SEMGREP_BEST_EFFORT_LANGUAGES
# Best-effort languages with rules that match text (pattern-regex,
# metavariable-regex). Semgrep scans a file that is not valid UTF-8, but
# those rules can miss matches in it, so the file is named in the "Code
# without scanner rules" row.
TEXT_RULE_LANGUAGES = ("Shell", "Dockerfile", "Kotlin", GITLAB_CI_LANGUAGE,
                       COMPOSE_LANGUAGE, SPRING_CONFIG_LANGUAGE,
                       "Android manifest", "Maven POM", "Makefile")
NOT_UTF8_REASON = "not UTF-8, so semgrep's text rules can miss lines in it"

# Markers that disable a test when they appear in ADDED lines of a security
# test file (Java, JS and Python test frameworks).
SKIP_MARKER_RE = re.compile(
    r"@Disabled|@Ignore\b|\.skip\s*\(|\bxit\s*\(|\bxdescribe\s*\(|"
    r"pytest\.mark\.skip|unittest\.skip")

# Test settings files that decide which tests run, and the keys in them
# that can leave a test out without deleting or skipping it.
TEST_SETTINGS_FILES = (
    "conftest.py", "pytest.ini", "setup.cfg", "tox.ini", "pyproject.toml",
    "pom.xml", "maven.config",
)
TEST_COLLECTION_RE = re.compile(
    r"collect_ignore|--ignore|--deselect|norecursedirs|testpaths|"
    r"python_files|python_classes|python_functions|addopts|"
    r"pytest_collection_modifyitems|pytest_ignore_collect|"
    r"pytest_deselected|skipTests|maven\.test\.skip|<exclude>|"
    r"(^|\s)-k\s")

# Outbound-HTTP hygiene: tokens that mark added code as an HTTP client, and
# a URL pattern to extract the hosts it talks to. Hosts that appear in code
# without being fetch targets (XML namespaces, schema URLs) are ignored.
HTTP_CLIENT_RE = re.compile(
    r"requests\.(get|post|Session)|session\.(get|post)|urllib\.request|"
    r"\bhttpx\b|\baiohttp\b|http\.client|\baxios\b|\bfetch\s*\(|\bcurl\s")
HTTP_URL_RE = re.compile(
    r"https?://([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})(/[^\s\"'<>)\]]*)?")
HTTP_IGNORED_HOSTS = (
    "localhost", "127.0.0.1", "example.com", "example.org", "example.net",
    "www.w3.org", "schema.org", "maven.apache.org", "json-schema.org",
)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def first_version_line(output):
    """The line of a '--version' output that actually carries the version.

    Some tools print a banner or an upgrade notice BEFORE the number (semgrep
    does), so taking line one records an advert where the evidence record
    promises a version. Prefer the first line that contains something shaped
    like a version number, and fall back to the first line only if none does.
    """
    lines = []
    for line in output.strip().splitlines():
        line = line.strip()
        if line:
            lines.append(line)
    for line in lines:
        if re.search(r"\d+\.\d+", line):
            return line
    return lines[0] if lines else "?"


def parse_test_report_xml(path):
    """Parses a JUnit-style test report, returning its root or None.

    Test frameworks never write a DOCTYPE into these reports, so any DOCTYPE
    or ENTITY declaration means the file is not what it claims to be — and
    stdlib XML parsers can be DoS'd by entity-expansion bombs. Refusing the
    parse outright costs nothing legitimate and closes that door (the report
    is produced by running the scanned repository's own test suite, which is
    exactly the kind of content this gate must not trust blindly)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(8192)
        if "<!DOCTYPE" in head or "<!ENTITY" in head:
            return None
        return ElementTree.parse(path).getroot()
    except (ElementTree.ParseError, OSError):
        return None


def kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass  # the group is already gone


def run(cmd, cwd=None, timeout=120, log_path=None, env=None,
        kill_leftovers=False, stderr_on_success=True):
    """Runs a command, returns (exit_code, output). exit_code is None on
    timeout. Output is stdout+stderr combined, optionally also written to
    log_path as evidence in the run directory.
    stderr_on_success=False drops stderr when the command succeeds, so a
    warning cannot end up in output that is parsed.

    Each command runs in its own process group, so a timeout or Ctrl-C
    kills its children too. kill_leftovers=True also kills the group after
    a normal exit, so a process left behind by the repository's test suite
    cannot keep writing while the verdict is built."""
    try:
        process = subprocess.Popen(
            cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
            stderr=(subprocess.STDOUT if stderr_on_success
                    else subprocess.PIPE),
            text=True, errors="replace", start_new_session=True)
    except FileNotFoundError:
        output = "command not found: %s\n" % cmd[0]
        if log_path:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(output)
        return 127, output
    try:
        output, errors = process.communicate(timeout=timeout)
        code = process.returncode
    except subprocess.TimeoutExpired:
        kill_group(process)
        output, errors = process.communicate()
        code = None
        output = (output or "") + "\n(timed out after %ds)\n" % timeout
    except KeyboardInterrupt:
        kill_group(process)
        raise
    finally:
        if kill_leftovers:
            kill_group(process)
    if errors and code != 0:
        output = (output or "") + errors
    if log_path:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(output)
    return code, output


def new_by_multiset(head_findings, base_findings):
    """head_findings / base_findings: {key: [finding, ...]}, one entry per
    occurrence. A key seen k times at the base and n times at HEAD adds
    n - k new findings: the last n - k in file order, so the line shown
    can belong to an old occurrence."""
    new_findings = []
    for key, occurrences in head_findings.items():
        already = len(base_findings.get(key, []))
        new_findings.extend(occurrences[already:])
    return new_findings


def shebang_interpreter(content):
    """The program a '#!' first line runs ('python3', 'bash'), or None.
    '#!/usr/bin/env [-S] [NAME=value] program' runs program."""
    if not content.startswith(b"#!"):
        return None
    words = content.split(b"\n", 1)[0][2:].decode("utf-8", "replace").split()
    if not words:
        return None
    program = os.path.basename(words[0])
    if program == "env":
        rest = [word for word in words[1:]
                if not word.startswith("-") and "=" not in word]
        program = os.path.basename(rest[0]) if rest else "env"
    return program


def shebang_language(content):
    """The language of a script whose first line is a #!: 'Python',
    'Shell', 'Perl'..., or '<program> script' for any other program. None
    when there is no #! line."""
    program = shebang_interpreter(content)
    if program is None:
        return None
    return LANGUAGE_BY_INTERPRETER.get(program.rstrip("0123456789.").lower(),
                                       "%s script" % program)


def is_workflow_path(path):
    """A GitHub Actions workflow: a YAML file directly in .github/workflows/
    at the repository root, the only place GitHub reads them from."""
    parts = path.split("/")
    return (len(parts) == 3 and parts[:2] == [".github", "workflows"]
            and parts[2].lower().endswith((".yml", ".yaml")))


def file_extension(name):
    """The lower-case extension without the dot; for a dotfile such as
    .bashrc, the name after the dot. None when there is none."""
    lower = name.lower()
    if lower.startswith(".") and lower.count(".") == 1:
        return lower[1:] or None
    if "." not in lower.lstrip("."):
        return None
    return lower.rsplit(".", 1)[1] or None


def is_binary(content):
    """True for bytes that hold a NUL in their first 8000 bytes, as git
    decides it."""
    return b"\0" in content[:8000]


def code_language(path, content=None):
    """The type of a changed file the gate treats as code (source code or
    configuration), else None for documentation, data and binaries.

    A file whose name decides nothing (no extension, or an extension no
    table lists) is decided by its bytes: None when binary, its #! language
    when it has one, else an unknown type. Without content such a file
    answers NEEDS_CONTENT."""
    name = os.path.basename(path)
    lower = name.lower()
    if is_workflow_path(path):
        return WORKFLOW_LANGUAGE
    if name in CODE_LANGUAGE_BY_NAME:
        return CODE_LANGUAGE_BY_NAME[name]
    if lower.startswith(("dockerfile.", "containerfile.")) \
            or lower.endswith(".dockerfile"):
        return "Dockerfile"
    if lower == ".gitlab-ci.yml" or lower.endswith(".gitlab-ci.yml"):
        return GITLAB_CI_LANGUAGE
    if re.match(r"(docker-)?compose([.-][^/]*)?\.ya?ml$", lower):
        return COMPOSE_LANGUAGE
    if re.match(r"(application|bootstrap)([.-][^/]*)?\.(properties|ya?ml)$",
                lower):
        return SPRING_CONFIG_LANGUAGE
    if lower == ".env" or lower.startswith(".env."):
        return "env file"
    if lower in SKIPPED_NAMES:
        return None
    extension = file_extension(name)
    if extension is not None:
        if extension in CODE_LANGUAGE_BY_EXTENSION:
            return CODE_LANGUAGE_BY_EXTENSION[extension]
        if extension in CONFIG_LANGUAGE_BY_EXTENSION:
            return CONFIG_LANGUAGE_BY_EXTENSION[extension]
        if extension in SKIPPED_EXTENSIONS:
            return None
    if content is None:
        return NEEDS_CONTENT
    if is_binary(content):
        return None
    if extension is None:
        return shebang_language(content) or UNKNOWN_NO_EXTENSION
    return "unknown type (.%s)" % extension


def semgrep_scan_name(path, language):
    """The path a changed file gets in the semgrep scan tree. Semgrep picks
    a file's language by its name, so a shell script not named .sh or
    .bash, a Dockerfile not named Dockerfile or *.dockerfile, and a .mts or
    .cts file get a suffix it recognises. Findings are mapped back to the
    real path."""
    name = os.path.basename(path)
    lower = name.lower()
    if language == "Shell" and not lower.endswith((".sh", ".bash")):
        return path + ".sh"
    if language == "Dockerfile" and name != "Dockerfile" \
            and not lower.endswith(".dockerfile"):
        return path + ".dockerfile"
    if lower.endswith((".mts", ".cts")):
        return path + ".ts"
    return path


# --worktree mode only (see make_worktree_snapshot): the temporary index
# and object directory holding the snapshot of the working tree. Git
# commands that read the snapshot need them; the before/after photo of the
# repository's real state must not use them.
SNAPSHOT_GIT_ENV = {}


def git_environment(plain=False):
    if plain or not SNAPSHOT_GIT_ENV:
        return None
    return dict(os.environ, **SNAPSHOT_GIT_ENV)


def git(repo, *args, timeout=120, plain=False):
    # core.fsmonitor names a program git runs on status/diff/add: always
    # off here, whatever the configuration says
    return run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                "-C", repo] + list(args),
               timeout=timeout, env=git_environment(plain),
               stderr_on_success=False)


# Every diff the gate reads is asked for in one fixed shape, so neither the
# user's configuration (color.ui=always hides the '+' of added lines) nor
# the repository's .gitattributes (a '-diff' or textconv driver turns a
# file into "Binary files differ") can change it.
DIFF_CONFIG = (
    "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
    "-c", "diff.relative=false", "-c", "core.quotePath=false",
)
# --ignore-submodules=none: a tracked .gitmodules with 'ignore = all' would
# otherwise hide a submodule commit move from the diff, while a push still
# sends it.
DIFF_FLAGS = (
    "--no-color", "--no-ext-diff", "--no-textconv", "--text",
    "--find-renames", "--src-prefix=a/", "--dst-prefix=b/",
    "--ignore-submodules=none",
)


def git_diff(repo, *args, timeout=120):
    return git(repo, *(DIFF_CONFIG + ("diff",) + DIFF_FLAGS + args),
               timeout=timeout)


def git_log_patches(repo, revision_range, timeout=300):
    """Every commit's own patch in the range, in the same fixed shape as
    git_diff, each introduced by a 'commit:<id>' line. A merge commit shows
    only what was changed by hand while merging (remerge diff), not
    everything the merged branch brought in. Git older than 2.36 has no remerge
    diff and gets the first-parent diff, which errs towards reporting."""
    for merges in ("remerge", "first-parent"):
        code, output = git(repo, *(DIFF_CONFIG + (
            # log.showRoot: the first commit of a history shows its patch
            "-c", "log.showRoot=true",
            "log", "-p", "--format=commit:%H", "--diff-merges=" + merges)
            + DIFF_FLAGS + (revision_range,)), timeout=timeout)
        if code == 0:
            return code, output
    return code, output


def git_log_messages(repo, revision_range, timeout=120):
    """[(commit id, message)] for every commit in the range."""
    code, output = git(repo, "log", "--format=%H%x00%B%x00", revision_range,
                       timeout=timeout)
    messages = []
    fields = output.split("\0")
    for position in range(0, len(fields) - 1, 2):
        messages.append((fields[position].strip(), fields[position + 1]))
    return code, messages


def header_path(text):
    """The file named by the text after '+++ ' in a diff header: 'b/path',
    '"b/p\\303\\251th"' (git's C-quoting) or '/dev/null' (None). The
    trailing tab git adds when the name contains a space is dropped."""
    text = text.rstrip("\t")
    if text.startswith('"') and text.endswith('"'):
        raw = codecs.escape_decode(text[1:-1].encode("utf-8"))[0]
        text = raw.decode("utf-8", "replace")
    if text.startswith("b/"):
        return text[2:]
    return None


def added_lines(diff_text):
    """Yields (path, text) for every line the diff ADDS.

    File headers ('--- a/x', '+++ b/x') are recognised by position, between
    'diff --git' and the first '@@', so an added line starting with '++' is
    still an added line. Lines are split on '\\n' only: splitlines() would
    also split on form feeds and U+2028 and drop the text after one."""
    current = "?"
    in_header = False
    for line in diff_text.split("\n"):
        line = line.rstrip("\r")
        if line.startswith("diff --git "):
            in_header = True
            current = "?"
            continue
        if in_header:
            if line.startswith("+++ "):
                current = header_path(line[4:]) or "?"
            elif line.startswith("@@"):
                in_header = False
            continue
        if line.startswith("+"):
            yield current, line[1:]


def sanitize(value):
    """areas.tsv is tab-separated: tabs and newlines inside a field would
    shift every column after it, so they become spaces; an empty field is
    written as '-' (verdict.py turns it back into an empty string)."""
    text = str(value).replace("\t", " ").replace("\n", " ").strip()
    return text if text else "-"


def findings_in_counts(counts):
    """The number of findings a row's counts field holds: the sum of
    critical/high/medium/low ("0/1/2/0" is 3). "-" or anything else is 0."""
    parts = str(counts).split("/")
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return 0
    return sum(int(part) for part in parts)


class Gate:
    def __init__(self, repo, base_ref):
        self.repo = repo
        self.base_ref = base_ref
        self.rows = []
        self.notes = []
        self.exceptions = []
        self.run_dir = None
        self.tmp_dir = None
        self.feed_path = None   # progress feed for a local viewer, or None
        self.fork_commit = None
        self.changed = []       # list of (status_letter, path)
        self.base_path_of = {}  # renamed/copied file: new path -> old path
        self.blob_of = {}       # changed path -> its modes and blob ids
        # the commit being judged: HEAD, or in --worktree mode a snapshot
        # commit of the working tree that no ref points to
        self.head_ref = "HEAD"
        self.snapshot = False
        # changed code file (not deleted, not a symlink) -> its language
        self.code_language = {}
        # changed file with no extension -> language named by its #! line
        self.script_language = {}
        # best-effort-language file semgrep did not fully scan -> why
        self.semgrep_shortfall = {}
        self.empty_diff = False
        self.reports_root = None
        self.history_range = None   # the commits a push would publish
        self.photo_failed = False
        # what the pytest run reported: {"ran": classnames, "failed": ids}
        self.pytest_results = None
        self.diff_text = ""
        # One export of HEAD shared by every check that needs a real tree
        # (Maven build, pytest); made lazily, at most once per run.
        self.export_attempted = False
        self.export_dir = None
        # (step name, seconds) for timings.txt
        self.timings = []

    # ---- row recording ----------------------------------------------------

    def record(self, area, status, scope="-", reason="-", outcome="-",
               severity="-", counts="-", blocking="-", evidence="-"):
        self.rows.append([area, status, scope, reason, outcome, severity,
                          counts, blocking, evidence])

    def clean(self, area, scope, outcome="no new findings", evidence="-"):
        self.record(area, "TESTED", scope, "-", outcome, "none",
                    "0/0/0/0", "no", evidence)

    def not_possible(self, area, reason, evidence="-"):
        self.record(area, "NOT POSSIBLE", "-", reason, evidence=evidence)

    def not_applicable(self, area, reason):
        self.record(area, "NOT APPLICABLE", "-", reason)

    def blocked(self, area, scope, outcome, severity, counts, evidence="-"):
        self.record(area, "TESTED", scope, "-", outcome, severity, counts,
                    "yes", evidence)

    def note(self, text):
        self.notes.append(text)

    # ---- helpers ----------------------------------------------------------

    def file_exists_at(self, ref, path):
        code, _ = git(self.repo, "cat-file", "-e", "%s:%s" % (ref, path))
        return code == 0

    def iter_blobs(self, names):
        """Yields (name, bytes or None) for each object name ('<ref>:<path>'
        or an object id), in order, through one `git cat-file --batch`
        process. Each object is read as it arrives, so a whole-tree export
        never sits in memory at once. None: missing, or not a file."""
        process = subprocess.Popen(
            ["git", "-c", "core.fsmonitor=false", "-C", self.repo, "cat-file",
             "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=git_environment())

        # the names are written from a second thread: writing them all
        # first could fill the pipe while git waits for us to read
        def write_names():
            try:
                for name in names:
                    process.stdin.write((name + "\n").encode("utf-8"))
                process.stdin.close()
            except OSError:
                pass

        writer = threading.Thread(target=write_names, daemon=True)
        writer.start()
        try:
            for name in names:
                header = process.stdout.readline()
                if not header:
                    return
                header = header.decode("utf-8", "replace").rstrip("\n")
                # "<name> missing" (the name may contain spaces) or
                # "<object id> <type> <size>", then the content and a LF
                if header.endswith(" missing") \
                        or header.endswith(" ambiguous"):
                    yield name, None
                    continue
                parts = header.split(" ")
                if len(parts) != 3 or not parts[2].isdigit():
                    return  # unexpected output: stop rather than misalign
                content = process.stdout.read(int(parts[2]))
                process.stdout.read(1)
                yield name, (content if parts[1] == "blob" else None)
        finally:
            process.stdout.close()
            process.kill()
            process.wait()

    def write_extracted(self, dest, path, content):
        """Writes one extracted file under dest at path; returns False,
        writing nothing, for a path that would land outside dest (a tree
        built with plumbing can hold '..' entries). A file starting with #!
        is made executable: semgrep detects an extensionless script by its
        #! line only when the file is executable."""
        parts = path.split("/")
        if path.startswith("/") or any(part in ("", ".", "..", ".git")
                                       for part in parts):
            return False
        # no symlink is ever written into a scan tree, so a path made of
        # plain components cannot leave dest
        target = os.path.join(dest, *parts)
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(content)
        except OSError:
            return False  # e.g. a file and a directory with the same name
        if content.startswith(b"#!"):
            os.chmod(target, os.stat(target).st_mode | stat.S_IXUSR)
        return True

    def extract_changed(self, paths, dest, side, scan_names=None):
        """Copies changed files into dest by blob id, as `git diff --raw`
        named them: side "head" for the judged version, "base" for the
        merge-base version (under the NEW path, so the two scans compare
        the same file). Reading by id works for any file name, newlines and
        non-UTF-8 bytes included. scan_names: {path: name to write it
        under}, for files that need another name in the scan tree. Returns
        (extracted, links), both by real path: symlinks and submodules go
        into links and are not written."""
        wanted = []
        links = []
        for path in paths:
            blob = self.blob_of.get(path)
            if blob is None:
                continue
            object_id, mode = ((blob["new_id"], blob["new_mode"])
                               if side == "head"
                               else (blob["old_id"], blob["old_mode"]))
            if set(object_id) == {"0"}:
                continue  # the file does not exist on this side
            if mode in ("120000", "160000"):
                links.append(path)
                continue
            wanted.append((path, object_id))
        contents = dict(self.iter_blobs([object_id
                                         for _path, object_id in wanted]))
        extracted = []
        for path, object_id in wanted:
            content = contents.get(object_id)
            name = (scan_names or {}).get(path, path)
            if content is None or not self.write_extracted(dest, name,
                                                           content):
                continue
            extracted.append(path)
        return extracted, links

    def classify_changed_code(self):
        """Fills self.code_language for every changed file the gate treats
        as code (see code_language), and self.script_language for the
        scripts without an extension, whose #! line is read from the judged
        version. Deleted files, symlinks and submodules are not code."""
        undecided = {}
        for status, path in self.changed:
            blob = self.blob_of.get(path)
            if status == "D" or blob is None \
                    or blob["new_mode"] in ("120000", "160000"):
                continue
            language = code_language(path)
            if language == NEEDS_CONTENT:
                undecided[path] = blob["new_id"]
            elif language:
                self.code_language[path] = language
        if not undecided:
            return
        contents = dict(self.iter_blobs(list(undecided.values())))
        for path, object_id in undecided.items():
            content = contents.get(object_id)
            if content is None:
                continue
            language = code_language(path, content)
            if not language:
                continue
            self.code_language[path] = language
            if file_extension(os.path.basename(path)) is None \
                    and language != UNKNOWN_NO_EXTENSION:
                self.script_language[path] = language

    def extract_files(self, ref, paths, dest):
        """Copies the given files AS THEY ARE IN THE COMMIT `ref` into dest,
        keeping their relative paths (used for the dependency manifests,
        whose paths come from ls-tree). Reading git objects instead of the
        working tree is what makes the gate read-only by construction."""
        # --batch reads one object name per line, so a path holding a
        # newline cannot be asked for
        wanted = [(path, "%s:%s" % (ref, path)) for path in paths
                  if "\n" not in path]
        contents = dict(self.iter_blobs([name for _path, name in wanted]))
        extracted = []
        for path, name in wanted:
            content = contents.get(name)
            if content is not None and self.write_extracted(dest, path,
                                                            content):
                extracted.append(path)
        return extracted

    def apply_exceptions(self, scanner, findings, fingerprint_of):
        """Drops the findings covered by a valid (non-expired) exception.
        Returns (kept, suppressed_count). An exception matches when its
        identifier appears anywhere in the finding's fingerprint string."""
        kept, suppressed = [], 0
        for finding in findings:
            fingerprint = fingerprint_of(finding)
            covered = any(
                exc["scanner"] == scanner and exc["identifier"] in fingerprint
                for exc in self.exceptions)
            if covered:
                suppressed += 1
            else:
                kept.append(finding)
        return kept, suppressed

    def counts_field(self, severities):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for severity in severities:
            counts[severity if severity in counts else "low"] += 1
        return "%d/%d/%d/%d" % (counts["critical"], counts["high"],
                                counts["medium"], counts["low"])

    def worst_severity(self, severities):
        for level in SEVERITY_ORDER:
            if level in severities:
                return level
        return "low"

    # ---- the checks -------------------------------------------------------

    def check_exceptions_file(self):
        """Parses checks/exceptions.txt (identifier | scanner | reason |
        owner | expiry). Runs FIRST because valid exceptions are applied as
        suppressions by the Semgrep and Trivy checks below."""
        area = "Exceptions file"
        path = os.path.join(TOOLKIT_DIR, "checks", "exceptions.txt")
        if not os.path.isfile(path):
            self.clean(area, "0 exceptions", "no exceptions file")
            return
        malformed, expired = [], []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = [part.strip() for part in line.split("|")]
                if len(fields) != 5 or not all(fields):
                    malformed.append("line %d" % line_no)
                    continue
                identifier, scanner, _reason, _owner, expiry = fields
                try:
                    expiry_date = date.fromisoformat(expiry)
                except ValueError:
                    malformed.append("line %d (bad date)" % line_no)
                    continue
                if expiry_date < date.today():
                    expired.append("%s (%s, expired %s)"
                                   % (identifier, scanner, expiry))
                else:
                    self.exceptions.append(
                        {"identifier": identifier, "scanner": scanner})
        total = len(self.exceptions) + len(expired)
        if malformed:
            # a typo must never turn into an eternal exception
            self.not_possible(area, "malformed exceptions file: %s"
                              % ", ".join(malformed))
        elif expired:
            self.blocked(area, "%d exceptions" % total,
                         "%d expired exception(s): %s"
                         % (len(expired), "; ".join(expired)),
                         "medium", "0/0/%d/0" % len(expired))
        else:
            self.clean(area, "%d exceptions" % total, "all valid")

    def find_secret(self, content):
        """(pattern name, matched text) for the first real secret on a
        line, or None."""
        for name, pattern in SECRET_PATTERNS:
            # every match, not just the first: a placeholder earlier on the
            # line must not hide a real secret later on it
            for match in pattern.finditer(content):
                # the placeholder filter looks at the matched text only: an
                # XML tag or "example" elsewhere on the line must not hide a
                # real secret
                if not PLACEHOLDER_RE.search(match.group(0)):
                    return name, match.group(0)
        return None

    def check_secrets(self):
        """The added lines of the diff, and of every commit on the branch:
        a key committed and removed by a later commit is absent from the
        net diff, but a push still publishes it."""
        area = "Secrets in the diff"
        if self.empty_diff:
            self.not_possible(area, EMPTY_DIFF_REASON % self.base_ref)
            return
        findings = []
        seen_secrets = set()
        added_count = 0
        for current_file, content in added_lines(self.diff_text):
            added_count += 1
            hit = self.find_secret(content)
            if hit:
                seen_secrets.add(hit[1])
                # never copy the secret itself into the report
                findings.append("%s: %s (%s...)"
                                % (current_file, hit[0], hit[1][:6]))
        history_hits = []
        code, history = git_log_patches(self.repo, self.history_range)
        message_code, messages = git_log_messages(self.repo,
                                                  self.history_range)
        for commit, message in messages:
            for line in message.split("\n"):
                hit = self.find_secret(line)
                if hit and hit[1] not in seen_secrets:
                    seen_secrets.add(hit[1])
                    history_hits.append(
                        "the message of commit %s: %s (%s...) - rewrite the "
                        "branch history before pushing"
                        % (commit[:12], hit[0], hit[1][:6]))
        code = code or message_code
        for block in history.split("\ncommit:"):
            if block.startswith("commit:"):
                block = block[len("commit:"):]
            commit, _newline, patch = block.partition("\n")
            for current_file, content in added_lines(patch):
                hit = self.find_secret(content)
                if hit and hit[1] not in seen_secrets:
                    seen_secrets.add(hit[1])
                    history_hits.append(
                        "%s in commit %s: %s (%s...), no longer in the final "
                        "version but published by a push - rewrite the "
                        "branch history before pushing"
                        % (current_file, commit.strip()[:12], hit[0],
                           hit[1][:6]))
        findings.extend(history_hits)
        scope = "%d added lines" % added_count
        if code != 0:
            self.not_possible(area, "the commits of the branch could not be "
                              "read (git log failed), so a secret added and "
                              "then removed would go unseen")
            return
        if findings:
            evidence_path = os.path.join(self.run_dir, "new-secrets.txt")
            with open(evidence_path, "w", encoding="utf-8") as f:
                f.write("\n".join(findings) + "\n")
            self.blocked(area, scope,
                         "%d possible secret(s) in the added lines: %s"
                         % (len(findings), "; ".join(findings[:3])),
                         "high", self.counts_field(["high"] * len(findings)),
                         "new-secrets.txt")
        else:
            self.clean(area, scope, "no secret patterns in the added lines "
                       "of the diff or of any commit on the branch")

    def looks_like_security_test(self, path):
        # the leading "/" lets a top-level security/ directory match too
        lowered = "/" + path.lower()
        name = os.path.basename(lowered)
        if "securitytest" in name:
            return True
        if ".security." in name and (".test." in name or ".spec." in name):
            return True
        # Python naming: tests/test_security_auth.py, security_roles_test.py
        if name.endswith(".py") and "security" in name and (
                name.startswith("test_") or name.endswith("_test.py")):
            return True
        return "/security/" in lowered and "test" in lowered

    def check_security_tests_in_diff(self):
        """Security tests deleted, renamed away, disabled with a skip
        marker, or left out of test collection by a settings change."""
        area = "Security tests in the diff"
        touched = [(status, path) for status, path in self.changed
                   if self.looks_like_security_test(path)]
        deleted = [path for status, path in touched if status == "D"]
        # a security test renamed to a name no test runner collects counts
        # as deleted
        for status, path in self.changed:
            old_path = self.base_path_of.get(path)
            if (status == "R" and old_path
                    and self.looks_like_security_test(old_path)
                    and not self.looks_like_security_test(path)):
                deleted.append("%s (renamed to %s)" % (old_path, path))
                touched.append((status, path))
        # skip/disable markers in the ADDED lines of security test files,
        # and collection settings changed in conftest.py, pytest.ini, pom.xml
        # and the like
        disabled = []
        excluded = []        # a collection change that names security
        collection = []      # any other collection change: a warning
        for current_file, content in added_lines(self.diff_text):
            name = os.path.basename(current_file)
            if name in TEST_SETTINGS_FILES \
                    and TEST_COLLECTION_RE.search(content):
                if "secur" in content.lower():
                    if current_file not in excluded:
                        excluded.append(current_file)
                elif current_file not in collection:
                    collection.append(current_file)
            if current_file in disabled \
                    or not self.looks_like_security_test(current_file):
                continue
            if SKIP_MARKER_RE.search(content):
                disabled.append(current_file)  # one report per file
        if not touched and not excluded and not collection:
            # this outcome keeps the row out of "N of them examined code"
            self.clean(area, "0 files", verdict.NOTHING_TO_SCAN)
            return
        scope = "%d files" % (len(touched) + len(excluded) + len(collection))
        if deleted or disabled or excluded:
            problems = []
            if deleted:
                problems.append("deletes security tests: %s"
                                % ", ".join(deleted))
            if disabled:
                problems.append("adds skip/disable markers in: %s"
                                % ", ".join(disabled))
            if excluded:
                problems.append("changes test collection to leave out "
                                "security tests in: %s" % ", ".join(excluded))
            count = len(deleted) + len(disabled) + len(excluded)
            self.blocked(area, scope, "; ".join(problems), "high",
                         self.counts_field(["high"] * count),
                         "diff.patch")
        elif collection:
            self.record(area, "TESTED", scope, "-",
                        "test collection settings changed in %s: check that "
                        "no test is left out" % ", ".join(collection),
                        "low", "0/0/0/%d" % len(collection), "no",
                        "diff.patch")
        else:
            names = ", ".join(path for _status, path in touched)
            self.clean(area, scope,
                       "modified without deleting or disabling: " + names,
                       "diff.patch")

    def check_scanner_integrity(self):
        area = "Scanner integrity"
        weakened = []
        for status, path in self.changed:
            if status == "D":
                continue  # deleting a suppression file makes the scan stricter
            name = os.path.basename(path)
            if name in SUPPRESSION_FILE_PATTERNS or any(
                    fragment in name for fragment in
                    SUPPRESSION_NAME_FRAGMENTS):
                weakened.append(path)
        scope = "%d changed files" % len(self.changed)
        if weakened:
            self.blocked(area, scope,
                         "adds or modifies scanner suppression files: %s"
                         % ", ".join(weakened), "high",
                         self.counts_field(["high"] * len(weakened)),
                         "diff-stat.txt")
        else:
            self.clean(area, scope, "no scanner suppression file touched",
                       "diff-stat.txt")

    def semgrep_key(self, result, file_cache):
        """The matched code of one semgrep result, whitespace removed, for
        its (rule, file, code) key. Cut from the extracted file by byte
        offset: semgrep's own 'lines' and 'fingerprint' fields read
        "requires login" unless the user is logged in to semgrep.dev."""
        path = result["path"]
        start = (result.get("start") or {}).get("offset")
        end = (result.get("end") or {}).get("offset")
        if isinstance(start, int) and isinstance(end, int):
            if path not in file_cache:
                try:
                    with open(path, "rb") as f:
                        file_cache[path] = f.read()
                except OSError:
                    file_cache[path] = None
            content = file_cache[path]
            if content is not None:
                matched = content[start:end].decode("utf-8", "replace")
                return "".join(matched.split())
        # no offsets or no file: key on the line number, which errs towards
        # calling findings new
        return "line %s" % (result.get("start") or {}).get("line", "?")

    def check_semgrep(self):
        """Semgrep with the LOCAL rules only (checks/semgrep-rules/): no
        network, no registry download. One semgrep process scans the changed
        files at HEAD and at the merge-base; only the findings new at HEAD
        are reported."""
        area = "Multi-language analysis (Semgrep)"
        if self.empty_diff:
            self.not_possible(area, EMPTY_DIFF_REASON % self.base_ref)
            return
        if shutil.which("semgrep") is None:
            self.not_possible(area, "semgrep absent (brew install semgrep)")
            return
        links = [path for status, path in self.changed
                 if status != "D" and self.blob_of.get(path, {}).get(
                     "new_mode") in ("120000", "160000")]
        if links:
            self.note("symlinks or submodules changed, not scanned as code: "
                      + ", ".join(links[:10]))
        # Only the changed code files of a language the rules cover are
        # scanned; the "Code without scanner rules" row names the rest. A
        # changed .semgrepignore is never extracted: in the scan tree it
        # would hide files from the scan. The Scanner integrity row reports
        # the change to it.
        paths = [path for _status, path in self.changed
                 if self.code_language.get(path) in SEMGREP_LANGUAGES
                 and os.path.basename(path) != ".semgrepignore"]
        if not paths:
            # this outcome keeps the row out of "N of them examined code"
            self.clean(area, "0 code files", verdict.NOTHING_TO_SCAN)
            return
        # the scan-tree name of each file semgrep would not recognise, and
        # the way back to its real path
        scan_names = {}
        taken = set(path for _status, path in self.changed)
        for path in paths:
            name = semgrep_scan_name(path, self.code_language[path])
            if name == path:
                continue
            if name in taken:  # another changed file already has that name
                name = path + ".preflight-scan" + name[len(path):]
            scan_names[path] = name
            taken.add(name)
        real_path_of = dict((name, path) for path, name in scan_names.items())
        head_dir = os.path.join(self.tmp_dir, "semgrep-head")
        base_dir = os.path.join(self.tmp_dir, "semgrep-base")
        extracted, _links = self.extract_changed(paths, head_dir, "head",
                                                 scan_names)
        self.extract_changed(paths, base_dir, "base", scan_names)
        # a changed file that could not be written into the scan tree was
        # never examined, and must not read as a clean scan
        unextracted = [path for path in paths if path not in extracted]
        # An empty .semgrepignore in each root switches off semgrep's
        # built-in ignore list, which skips build/, dist/, test/, tests/,
        # vendor/, node_modules/ and *.min.js.
        for scan_root in (head_dir, base_dir):
            os.makedirs(scan_root, exist_ok=True)
            with open(os.path.join(scan_root, ".semgrepignore"), "w",
                      encoding="utf-8"):
                pass
        rules = os.path.join(TOOLKIT_DIR, "checks", "semgrep-rules")
        combined_path = os.path.join(self.tmp_dir, "semgrep-combined.json")
        log_path = os.path.join(self.run_dir, "semgrep.log")
        # --disable-nosem: a "nosemgrep" comment cannot hide a finding.
        # --no-git-ignore: scan the tree even inside a git-ignored directory.
        # --max-target-bytes: raises semgrep's 1 MB default, which leaves big
        # files unscanned. --metrics=off and no version check: nothing leaves
        # this machine.
        command = ["semgrep", "scan", "--metrics=off", "--disable-nosem",
                   "--no-git-ignore", "--max-target-bytes=10000000",
                   "--config", rules, "--json", "--output", combined_path,
                   head_dir, base_dir]
        environment = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0",
                           SEMGREP_SEND_METRICS="off")
        code, _output = run(command, timeout=2 * SCAN_TIMEOUT,
                            log_path=log_path, env=environment)
        if code != 0 or not os.path.isfile(combined_path):
            # one retry, for an occasional failure that does not repeat;
            # the first attempt's log is kept
            if os.path.isfile(log_path):
                os.replace(log_path, os.path.join(self.run_dir,
                                                  "semgrep-attempt1.log"))
            code, _output = run(command, timeout=2 * SCAN_TIMEOUT,
                                log_path=log_path, env=environment)
        if code != 0 or not os.path.isfile(combined_path):
            # a failure on the base files alone also makes the row NOT POSSIBLE
            self.not_possible(area, "semgrep did not complete on the changed "
                              "files", "semgrep.log")
            return
        with open(combined_path, encoding="utf-8") as f:
            data = json.load(f)

        # Split the one report into its two trees, by path. Anything that
        # names no path goes to HEAD, where a problem makes the row PARTIAL.
        def root_of(path):
            return "base" if str(path).startswith(base_dir + os.sep) \
                else "head"

        parts = {"head": {"results": [], "errors": [], "paths": {}},
                 "base": {"results": [], "errors": [], "paths": {}}}
        for result in data.get("results", []) or []:
            parts[root_of(result.get("path", ""))]["results"].append(result)
        for error in data.get("errors", []) or []:
            parts[root_of(error.get("path", ""))]["errors"].append(error)
        for key, entries in (data.get("paths", {}) or {}).items():
            if not isinstance(entries, list):
                continue
            # a key semgrep did not emit stays absent, so a missing
            # 'scanned' list still switches off the check below
            parts["head"]["paths"][key] = []
            parts["base"]["paths"][key] = []
            for entry in entries:
                entry_path = entry.get("path", "") \
                    if isinstance(entry, dict) else entry
                parts[root_of(entry_path)]["paths"][key].append(entry)
        for name in ("head", "base"):
            with open(os.path.join(self.run_dir, "semgrep-%s.json" % name),
                      "w", encoding="utf-8") as f:
                json.dump(parts[name], f, indent=1)

        file_cache = {}

        def real_path(scan_path, target_dir):
            """The repository path of a file semgrep names in target_dir."""
            relative = os.path.relpath(scan_path, target_dir)
            return real_path_of.get(relative, relative)

        def findings_of(part, target_dir):
            findings = {}
            for result in part["results"]:
                rel_path = real_path(result["path"], target_dir)
                key = (result["check_id"], rel_path,
                       self.semgrep_key(result, file_cache))
                findings.setdefault(key, []).append({
                    "rule": result["check_id"].rsplit(".", 1)[-1],
                    "path": rel_path,
                    "line": result.get("start", {}).get("line", 0),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": {"ERROR": "high", "WARNING": "medium",
                                 "INFO": "low"}.get(
                        result.get("extra", {}).get("severity", "WARNING"),
                        "medium"),
                })
            return findings

        # Files semgrep did not fully examine: reported errors, reported
        # skips, extracted files missing from its scanned-paths list, and
        # files of a TEXT_RULE_LANGUAGES language that are not UTF-8. An
        # unexamined file has zero findings, which must never read as clean.
        # A core-language file goes to head_problems (this row turns
        # PARTIAL); a best-effort-language file goes to semgrep_shortfall,
        # named by the "Code without scanner rules" row.
        head_problems = []
        problem_paths = set()       # every file named below
        unexamined_paths = set()    # the files named in head_problems

        def shortfall(path, why):
            if self.code_language.get(path) in SEMGREP_BEST_EFFORT_LANGUAGES:
                self.semgrep_shortfall.setdefault(path, why)
            else:
                head_problems.append("%s: %s" % (path, why))
                unexamined_paths.add(path)
            problem_paths.add(path)

        for path in unextracted:
            shortfall(path, "could not be read from git into the scan tree")
        for error in parts["head"]["errors"]:
            error_path = error.get("path", "")
            where = (real_path(error_path, head_dir) if error_path
                     else "(no file)")
            # the type is "Syntax error", "Other syntax error" or
            # ["PartialParsing", <ranges>]
            error_type = str(error.get("type", ""))
            if "yntax" in error_type or "PartialParsing" in error_type:
                why = "semgrep could not parse all of it"
            else:
                why = str(error.get("message", ""))[:100] or "semgrep error"
            shortfall(where, why)
        for entry in parts["head"]["paths"].get("skipped", []):
            if isinstance(entry, dict) and entry.get("path"):
                shortfall(real_path(entry["path"], head_dir),
                          entry.get("reason", "skipped"))
        scanned_list = parts["head"]["paths"].get("scanned")
        if isinstance(data.get("paths", {}).get("scanned"), list):
            scanned_set = set(real_path(p, head_dir) for p in scanned_list)
            for path in extracted:
                if path not in scanned_set and path not in problem_paths:
                    shortfall(path, "not scanned by semgrep")
        for path in extracted:
            if self.code_language.get(path) not in TEXT_RULE_LANGUAGES \
                    or path in problem_paths:
                continue
            try:
                with open(os.path.join(head_dir, scan_names.get(path, path)),
                          "rb") as f:
                    f.read().decode("utf-8")
            except UnicodeDecodeError:
                shortfall(path, NOT_UTF8_REASON)
            except OSError:
                shortfall(path, "its encoding could not be checked")

        new_findings = new_by_multiset(findings_of(parts["head"], head_dir),
                                       findings_of(parts["base"], base_dir))
        new_findings, suppressed = self.apply_exceptions(
            "semgrep", new_findings,
            lambda f: "%s %s" % (f["rule"], f["path"]))
        total = len(extracted) + len(unextracted)
        scope = "%d code files" % total
        suffix = (" (%d suppressed by exceptions.txt)" % suppressed
                  if suppressed else "")
        if self.semgrep_shortfall:
            suffix += ("; %d file(s) not fully scanned, named in the %s row"
                       % (len(self.semgrep_shortfall), UNCOVERED_CODE_AREA))
        # Files semgrep skipped or errored on were NOT examined: the row
        # degrades to PARTIAL so the shortfall stays visible in the verdict
        # (a parse error must not read the same as "scanned and clean").
        partial_reason = None
        if head_problems:
            scope = "%d of %d code files" % (
                max(total - len(unexamined_paths), 0), total)
            partial_reason = ("semgrep could not fully scan: "
                              + "; ".join(head_problems[:3]))
        if new_findings:
            evidence_path = os.path.join(self.run_dir, "new-semgrep.txt")
            with open(evidence_path, "w", encoding="utf-8") as f:
                for finding in new_findings:
                    f.write("%s:%d  [%s] %s\n"
                            % (finding["path"], finding["line"],
                               finding["rule"], finding["message"]))
            severities = [f["severity"] for f in new_findings]
            first = new_findings[0]
            self.record(area, "PARTIAL" if partial_reason else "TESTED",
                        scope, partial_reason or "-",
                        "%d new finding(s), e.g. %s at %s:%d%s"
                        % (len(new_findings), first["rule"], first["path"],
                           first["line"], suffix),
                        self.worst_severity(severities),
                        self.counts_field(severities), "yes",
                        "new-semgrep.txt")
        elif partial_reason:
            self.record(area, "PARTIAL", scope, partial_reason,
                        "no new findings" + suffix, "none", "0/0/0/0", "no",
                        "semgrep-head.json")
        else:
            self.clean(area, scope, "no new findings" + suffix,
                       "semgrep-head.json")

    def check_uncovered_code(self):
        """The changed code files no Semgrep rule examined in full: a
        language the local rules do not cover, or a best-effort language
        semgrep could not fully scan (check_semgrep runs first). Best
        effort: a caveat, not a veto. code-files.txt lists every changed
        code file with its language and coverage."""
        area = UNCOVERED_CODE_AREA
        code_files = [path for _status, path in self.changed
                      if path in self.code_language]
        if not code_files:
            self.not_applicable(area, "no code or configuration file changed in "
                                "this diff")
            return
        no_rules = []
        partly = []
        lines = []
        for path in code_files:
            language = self.code_language[path]
            if language not in SEMGREP_LANGUAGES:
                no_rules.append("%s (%s)" % (path, language))
                coverage = "no Semgrep rule for this language"
            elif path in self.semgrep_shortfall:
                partly.append("%s (%s): %s" % (path, language,
                                               self.semgrep_shortfall[path]))
                coverage = "Semgrep rules, " + self.semgrep_shortfall[path]
            else:
                coverage = "Semgrep rules"
            lines.append("%s\t%s\t%s" % (path, language, coverage))
        with open(os.path.join(self.run_dir, "code-files.txt"), "w",
                  encoding="utf-8") as f:
            f.write("# changed code file, language, scanner coverage\n")
            f.write("\n".join(lines) + "\n")
        if not no_rules and not partly:
            self.not_applicable(area, "every changed code file is in a "
                                "language the local Semgrep rules cover")
            return

        def listing(names):
            # the first ten; the evidence file has them all
            text = ", ".join(names[:10])
            if len(names) > 10:
                text += " and %d more" % (len(names) - 10)
            return text

        reasons = []
        if no_rules:
            reasons.append("no Semgrep rule for the type of: "
                           + listing(no_rules))
        if partly:
            reasons.append("Semgrep rules applied only in part to: "
                           + listing(partly))
        covered = len(code_files) - len(no_rules) - len(partly)
        # no outcome: this row records a coverage gap, not a scan
        self.record(area, "PARTIAL",
                    "%d of %d code files" % (covered, len(code_files)),
                    "; ".join(reasons), "-", "none", "0/0/0/0", "no",
                    "code-files.txt")

    def check_bandit(self):
        """Bandit on the changed Python files, HEAD vs merge-base, reporting
        only what is new at HEAD — a second net beside Semgrep, tuned to
        Python idioms (subprocess, pickle, weak crypto, tempfiles). Best
        effort: bandit missing is a loud caveat, not a veto. B101
        (assert_used) is skipped and LOW-confidence findings are dropped:
        both flood real repositories with noise that trains the reader to
        ignore the column."""
        area = "Python analysis (Bandit)"
        candidates = [path for status, path in self.changed
                      if status != "D"
                      and os.path.basename(path) != ".semgrepignore"]
        if shutil.which("bandit") is None:
            changed_py = [p for p in candidates if p.endswith(".py")]
            if changed_py:
                self.not_possible(area, "bandit absent (pip install bandit / "
                                  "brew install bandit) and this diff changes "
                                  "%d Python file(s)" % len(changed_py))
            else:
                self.not_applicable(area, "no Python file changed in this "
                                    "diff")
            return
        head_dir = os.path.join(self.tmp_dir, "bandit-head")
        base_dir = os.path.join(self.tmp_dir, "bandit-base")
        extracted, links = self.extract_changed(candidates, head_dir, "head")
        # .py files, plus scripts with no extension whose #! line names
        # python: bandit scans any file it is handed
        python_files = [path for path in extracted
                        if path.endswith(".py")
                        or self.script_language.get(path) == "Python"]
        unread = [path for path in candidates
                  if path.endswith(".py") and path not in extracted
                  and path not in links]
        if not python_files and not unread:
            self.not_applicable(area, "no Python file changed in this diff")
            return
        self.extract_changed(python_files, base_dir, "base")

        def scan(target_dir, label):
            """Returns (findings, problems), or (None, []) when bandit did
            not run. -n 1: the snippet is the flagged line only, so editing
            the line next to an old finding does not make it new.
            --ignore-nosec: a '# nosec' comment cannot hide a sink. -x with
            a path that does not exist replaces bandit's default excludes,
            which match as substrings and dropped .github/ and .gitlab/."""
            files = [os.path.join(target_dir, path) for path in python_files
                     if os.path.isfile(os.path.join(target_dir, path))]
            if not files:
                return {}, []
            json_path = os.path.join(self.run_dir, "bandit-%s.json" % label)
            # exit code 1 means "issues found", which is a successful scan
            code, _output = run(
                ["bandit", "-n", "1", "--ignore-nosec",
                 "-x", "/nonexistent-placeholder", "-f", "json",
                 "-o", json_path, "--skip", "B101"] + files,
                timeout=SCAN_TIMEOUT,
                log_path=os.path.join(self.run_dir, "bandit-%s.log" % label))
            if code not in (0, 1) or not os.path.isfile(json_path):
                return None, []
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            findings = {}
            for result in data.get("results", []) or []:
                if result.get("issue_confidence", "") == "LOW":
                    continue
                rel_path = os.path.relpath(result.get("filename", "?"),
                                           target_dir)
                # bandit prefixes every snippet line with its line NUMBER;
                # strip them before normalizing, or any edit that shifts
                # lines makes every old finding below it look new
                snippet_lines = []
                for code_line in str(result.get("code", "")).splitlines():
                    snippet_lines.append(re.sub(r"^\s*\d+", "", code_line))
                snippet = "".join("".join(snippet_lines).split())
                key = (result.get("test_id", "?"), rel_path, snippet)
                findings.setdefault(key, []).append({
                    "rule": result.get("test_id", "?"),
                    "path": rel_path,
                    "line": result.get("line_number", 0),
                    "message": result.get("issue_text", ""),
                    "severity": {"HIGH": "high", "MEDIUM": "medium",
                                 "LOW": "low"}.get(
                        result.get("issue_severity", "MEDIUM"), "medium"),
                })
            # what bandit did not actually analyse: files it could not
            # parse, and files missing from its per-file metrics
            problems = []
            for error in data.get("errors", []) or []:
                problems.append("%s: %s" % (
                    os.path.relpath(error.get("filename", "?"), target_dir),
                    str(error.get("reason", "error"))[:80]))
            analysed = set(os.path.relpath(name, target_dir)
                           for name in (data.get("metrics") or {})
                           if name != "_totals")
            for path in python_files:
                if os.path.isfile(os.path.join(target_dir, path)) \
                        and path not in analysed:
                    problems.append("%s: not analysed by bandit" % path)
            return findings, problems

        head_findings, head_problems = scan(head_dir, "head")
        if head_findings is None:
            self.not_possible(area, "bandit did not complete on the HEAD "
                              "version of the changed files", "bandit-head.log")
            return
        base_findings, _base_problems = scan(base_dir, "base")
        if base_findings is None:
            self.note("Bandit could not scan the base versions of the "
                      "changed files: every Bandit finding counts as new")
            base_findings = {}
        new_findings = new_by_multiset(head_findings, base_findings)
        new_findings, suppressed = self.apply_exceptions(
            "bandit", new_findings,
            lambda f: "%s %s" % (f["rule"], f["path"]))
        head_problems = head_problems + ["%s: could not be read from git" % path
                                         for path in unread]
        total = len(python_files) + len(unread)
        scope = "%d changed files" % total
        suffix = (" (%d suppressed by exceptions.txt)" % suppressed
                  if suppressed else "")
        status, reason = "TESTED", "-"
        if head_problems:
            status = "PARTIAL"
            scope = "%d of %d changed files" % (
                max(total - len(head_problems), 0), total)
            reason = ("bandit could not analyse: "
                      + "; ".join(head_problems[:3]))
        if new_findings:
            evidence_path = os.path.join(self.run_dir, "new-bandit.txt")
            with open(evidence_path, "w", encoding="utf-8") as f:
                for finding in new_findings:
                    f.write("%s:%d  [%s] %s\n"
                            % (finding["path"], finding["line"],
                               finding["rule"], finding["message"]))
            severities = [f["severity"] for f in new_findings]
            first = new_findings[0]
            # low-severity findings are advisory (like Trivy's), so a lone
            # B-low nitpick cannot block a publish; medium and high block
            blocking = [f for f in new_findings
                        if f["severity"] in ("critical", "high", "medium")]
            outcome = ("%d new finding(s), e.g. %s at %s:%d%s"
                       % (len(new_findings), first["rule"], first["path"],
                          first["line"], suffix))
            self.record(area, status, scope, reason, outcome,
                        self.worst_severity(severities),
                        self.counts_field(severities),
                        "yes" if blocking else "no", "new-bandit.txt")
        else:
            self.record(area, status, scope, reason,
                        "no new findings" + suffix, "none", "0/0/0/0", "no",
                        "bandit-head.json")

    def is_dependency_file(self, path):
        name = os.path.basename(path)
        parent = os.path.basename(os.path.dirname(path))
        return (name in DEPENDENCY_FILE_NAMES
                or any(name.startswith(prefix) and name.endswith(".txt")
                       for prefix in DEPENDENCY_FILE_PREFIXES)
                # requirements/base.txt, requirements/dev.txt, ...
                or (parent == "requirements" and name.endswith(".txt")))

    def check_dependencies(self):
        """Trivy on the dependency manifests, HEAD vs merge-base, only when
        the diff touches one. An unchanged dependency set needs no network
        and no scan — that alone removes the most fragile step of the old
        gate from the common case."""
        area = "Dependencies (Trivy)"
        changed_deps = [path for status, path in self.changed
                        if status != "D" and self.is_dependency_file(path)]
        if not changed_deps:
            self.not_applicable(area,
                                "no dependency file changed in this diff")
            return
        if shutil.which("trivy") is None:
            self.not_possible(area, "trivy absent (brew install trivy) and "
                              "this diff changes dependency files: %s"
                              % ", ".join(changed_deps))
            return

        def list_dep_files(ref):
            code, output = git(self.repo, "ls-tree", "-r", "-z", "--name-only",
                               ref)
            if code != 0:
                return []
            return [path for path in output.split("\0")
                    if path and self.is_dependency_file(path)]

        def scan(ref, label):
            dest = os.path.join(self.tmp_dir, "deps-" + label)
            # all manifests of that commit, not only the changed ones: a lock
            # file is only interpretable next to its manifest
            self.extract_files(ref, list_dep_files(ref), dest)
            os.makedirs(dest, exist_ok=True)
            json_path = os.path.join(self.run_dir,
                                     "trivy-%s.json" % label)
            log_path = os.path.join(self.run_dir, "trivy-%s.log" % label)
            cmd = ["trivy", "fs", "--quiet", "--format", "json",
                   "--output", json_path, dest]
            # cwd=dest: trivy reads trivy.yaml and .trivyignore from its
            # working directory, and the caller's must not switch the scan off
            code, _ = run(cmd, cwd=dest, timeout=SCAN_TIMEOUT,
                          log_path=log_path)
            if code != 0:
                # network down but DB already cached: try the cached copy,
                # keeping the first attempt's log (the real failure)
                if os.path.isfile(log_path):
                    os.replace(log_path, log_path.replace(".log",
                                                          "-attempt1.log"))
                code, _ = run(cmd + ["--skip-db-update"], cwd=dest,
                              timeout=SCAN_TIMEOUT, log_path=log_path)
            if code != 0:
                return None
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            findings = {}
            for result in data.get("Results", []) or []:
                # which manifest: the same vulnerable package newly added
                # to a second manifest is a new finding
                target = str(result.get("Target", "?"))
                for vuln in result.get("Vulnerabilities", []) or []:
                    key = (vuln.get("VulnerabilityID", "?"),
                           vuln.get("PkgName", "?"), target)
                    findings[key] = {
                        "id": key[0], "package": key[1],
                        "severity": (vuln.get("Severity") or
                                     "UNKNOWN").lower(),
                    }
            return findings

        head_findings = scan(self.head_ref, "head")
        if head_findings is None:
            self.not_possible(area, "trivy could not scan (vulnerability "
                              "database unreachable?) and this diff changes "
                              "dependency files", "trivy-head.log")
            return
        base_findings = scan(self.fork_commit, "base") or {}
        new_keys = [key for key in head_findings if key not in base_findings]
        new_findings = [head_findings[key] for key in new_keys]
        new_findings, suppressed = self.apply_exceptions(
            "trivy", new_findings,
            lambda f: "%s %s" % (f["id"], f["package"]))
        scope = "%d dependency files" % len(changed_deps)
        suffix = (" (%d suppressed by exceptions.txt)" % suppressed
                  if suppressed else "")
        if new_findings:
            # UNKNOWN blocks too: a severity nobody classified yet must not
            # slide through as if it were low
            blocking = [f for f in new_findings
                        if f["severity"] in ("critical", "high", "unknown")]
            advisory = [f for f in new_findings if f not in blocking]
            evidence_path = os.path.join(self.run_dir, "new-trivy.txt")
            with open(evidence_path, "w", encoding="utf-8") as f:
                for finding in new_findings:
                    f.write("%s  %s  (%s)\n" % (finding["id"],
                                                finding["package"],
                                                finding["severity"]))
            severities = [f["severity"] if f["severity"] in SEVERITY_ORDER
                          else "high" for f in new_findings]
            listed = ", ".join("%s (%s)" % (f["id"], f["package"])
                               for f in new_findings[:3])
            if blocking:
                self.blocked(area, scope,
                             "%d new vulnerable dependency(ies): %s%s"
                             % (len(new_findings), listed, suffix),
                             self.worst_severity(severities),
                             self.counts_field(severities), "new-trivy.txt")
            else:
                self.record(area, "TESTED", scope, "-",
                            "%d new low/medium finding(s): %s%s"
                            % (len(new_findings), listed, suffix),
                            self.worst_severity(severities),
                            self.counts_field(severities), "no",
                            "new-trivy.txt")
        else:
            self.clean(area, scope, "no new vulnerabilities" + suffix,
                       "trivy-head.json")

    def check_http_hygiene(self):
        """Outbound-HTTP hygiene, best-effort tier. Dormant unless the diff
        ADDS a URL or HTTP-client code. When it triggers: the robots.txt of
        each new host is checked against the paths the added code fetches
        (blocking only on a clear Disallow hit for User-agent: *), and two
        warn-only hygiene signals are reported — client files without any
        sleep/delay/throttle token, and browser-impersonating User-Agent
        strings. Network problems degrade to PARTIAL (a caveat, not a veto:
        someone else's server being down must not block a publish)."""
        area = "Outbound HTTP in the diff"

        # added lines per file, straight from the diff
        added = {}
        for current, content in added_lines(self.diff_text):
            added.setdefault(current, []).append(content)

        hosts = {}          # host -> set of fetched paths
        client_files = set()
        ua_spoof = False
        for path, lines in added.items():
            for content in lines:
                if HTTP_CLIENT_RE.search(content):
                    client_files.add(path)
                if "Mozilla/5.0" in content:
                    ua_spoof = True
                for match in HTTP_URL_RE.finditer(content):
                    host = match.group(1).lower()
                    if host in HTTP_IGNORED_HOSTS:
                        continue
                    # cut template placeholders ({page}, %5B..., $VAR) so the
                    # robots comparison sees the literal prefix only
                    url_path = re.split(r"[{$%]", match.group(2) or "/")[0]
                    hosts.setdefault(host, set()).add(url_path or "/")
        if not hosts and not client_files:
            self.not_applicable(area,
                                "no URL or HTTP-client code added by this diff")
            return

        # robots.txt of each new host (capped, honest UA, fail-open)
        import concurrent.futures
        import socket
        import urllib.error
        import urllib.request
        import urllib.robotparser

        def fetch_robots(host):
            """(host, body or None, reachable)."""
            request = urllib.request.Request(
                "https://%s/robots.txt" % host,
                headers={"User-Agent": "preflight-gate/1.0 (local check)"})
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return host, response.read(65536).decode("utf-8",
                                                              "replace"), True
            except urllib.error.HTTPError:
                return host, None, True  # no robots.txt: everything allowed
            except (urllib.error.URLError, socket.timeout, OSError):
                return host, None, False

        checked_hosts = []
        unreachable = []
        violations = []
        host_list = sorted(hosts)[:5]
        # the hosts are fetched at the same time: one slow host no longer
        # adds its 10-second timeout to every other
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            answers = list(pool.map(fetch_robots, host_list))
        for host, body, reachable in answers:
            if not reachable:
                unreachable.append(host)
                continue
            checked_hosts.append(host)
            if body is None:
                continue
            # the standard library's parser follows Allow lines and
            # per-agent groups; the rules for "*" are the ones that apply
            parser = urllib.robotparser.RobotFileParser()
            parser.parse(body.splitlines())
            for url_path in sorted(hosts[host]):
                if not parser.can_fetch("*", "https://%s%s" % (host,
                                                                url_path)):
                    violations.append("%s%s (disallowed by robots.txt)"
                                      % (host, url_path))

        warnings = []
        if len(hosts) > len(host_list):
            warnings.append("only the first %d of %d hosts were checked"
                            % (len(host_list), len(hosts)))
        no_delay = []
        for path in sorted(client_files):
            # git(), not a bare git: in --worktree mode the snapshot's
            # objects exist only in the gate's temporary object store
            code, content = git(self.repo, "show",
                                "%s:%s" % (self.head_ref, path))
            if code == 0 and not re.search(
                    r"sleep|delay|rate_?limit|throttle", content, re.I):
                no_delay.append(path)
        if no_delay:
            warnings.append("HTTP-client file(s) with no sleep/delay/"
                            "throttle token: %s" % ", ".join(no_delay))
        if ua_spoof:
            warnings.append("adds a browser-impersonating User-Agent "
                            "(Mozilla/5.0) — the site cannot tell this "
                            "client is a bot")

        evidence_path = os.path.join(self.run_dir, "http-hygiene.txt")
        with open(evidence_path, "w", encoding="utf-8") as f:
            for host in sorted(hosts):
                f.write("host %s: %s\n" % (host,
                                           ", ".join(sorted(hosts[host]))))
            for text in violations:
                f.write("VIOLATION %s\n" % text)
            for text in warnings:
                f.write("warning: %s\n" % text)
            f.write("note: robots.txt read with Python's urllib.robotparser"
                    "\n")

        scope = "%d host(s), %d client file(s)" % (len(hosts),
                                                   len(client_files))
        warn_suffix = ("; " + "; ".join(warnings)) if warnings else ""
        # the hygiene warnings as low findings: one per client file without
        # a delay, one for the User-Agent (the host cap is not a finding)
        hygiene_count = len(no_delay) + (1 if ua_spoof else 0)
        hygiene_severity = "low" if hygiene_count else "none"
        hygiene_counts = "0/0/0/%d" % hygiene_count
        if violations:
            self.blocked(area, scope,
                         "added code fetches robots-disallowed path(s): %s%s"
                         % ("; ".join(violations[:3]), warn_suffix),
                         "medium",
                         self.counts_field(["medium"] * len(violations)),
                         "http-hygiene.txt")
        elif unreachable:
            self.record(area, "PARTIAL",
                        "%d of %d hosts" % (len(checked_hosts), len(host_list)),
                        "robots.txt unreachable for: %s"
                        % ", ".join(unreachable),
                        "no robots violations on the reachable hosts"
                        + warn_suffix,
                        hygiene_severity, hygiene_counts, "no",
                        "http-hygiene.txt")
        else:
            self.record(area, "TESTED", scope, "-",
                        "no robots violations" + warn_suffix,
                        hygiene_severity, hygiene_counts, "no",
                        "http-hygiene.txt")

    def export_head_tree(self):
        """A real directory tree of the judged commit, made lazily and at
        most once per run, shared by the build and test checks. Exporting
        instead of using the working tree keeps the gate read-only and makes
        it judge exactly what the merge request will contain. Returns the
        directory, or None when the export failed.

        Built from git objects (ls-tree + cat-file), so the repository's
        .gitattributes cannot mark failing tests export-ignore and drop
        them from the run. Symlinks and submodules are left out and counted
        in a note."""
        if self.export_attempted:
            return self.export_dir
        self.export_attempted = True
        scan_dir = os.path.join(self.tmp_dir, "scan")
        os.makedirs(scan_dir, exist_ok=True)
        code, listing = git(self.repo, "ls-tree", "-r", "-z", "--full-tree",
                            self.head_ref, timeout=300)
        if code != 0:
            return None
        files = []       # (path, object id, executable)
        left_out = 0
        for entry in listing.split("\0"):
            if not entry or "\t" not in entry:
                continue
            info, path = entry.split("\t", 1)
            mode, kind, object_id = info.split(" ")
            if kind != "blob" or mode == "120000":
                left_out += 1   # a submodule, or a symlink
                continue
            files.append((path, object_id, mode == "100755"))
        contents = self.iter_blobs([object_id for _p, object_id, _x in files])
        written = 0
        for (path, _object_id, executable), (_name, content) in zip(files,
                                                                    contents):
            if content is None:
                return None
            if not self.write_extracted(scan_dir, path, content):
                self.note("the export refused a path that leads outside it: "
                          "%r" % path)
                return None
            if executable:
                exported = os.path.join(scan_dir, path)
                os.chmod(exported, os.stat(exported).st_mode | stat.S_IXUSR)
            written += 1
        if written != len(files):
            return None  # git stopped answering half-way
        if left_out:
            self.note("the build/test export leaves out %d symlink(s) or "
                      "submodule(s)" % left_out)
        self.export_dir = scan_dir
        return scan_dir

    def repo_code_command(self, cmd):
        """The command that runs the repository's own build or tests. With
        PREFLIGHT_SANDBOX=1 on macOS it runs under sandbox-exec, which allows
        writes only to temporary directories, the Maven cache and /dev, and
        denies the toolkit, ~/.claude, the repository and the reports. Off
        by default: it protects against a repository written to attack the
        gate, and it makes honest tests fail (writes under $HOME, setuid
        programs such as ps)."""
        if os.environ.get("PREFLIGHT_SANDBOX") != "1" \
                or sys.platform != "darwin" \
                or shutil.which("sandbox-exec") is None:
            return cmd
        writable = [tempfile.gettempdir(), "/private/tmp",
                    "/private/var/folders", os.path.expanduser("~/.m2"),
                    "/dev"]
        protected = [TOOLKIT_DIR, os.path.expanduser("~/.claude"), self.repo]
        if self.reports_root:
            protected.append(self.reports_root)
        code, common = git(self.repo, "rev-parse", "--path-format=absolute",
                           "--git-common-dir", plain=True)
        if code == 0 and common.strip():
            protected.append(common.strip())  # .git may live elsewhere

        def subpaths(paths):
            rules = ""
            for path in paths:
                real = os.path.realpath(path)
                escaped = real.replace("\\", "\\\\").replace('"', '\\"')
                rules += ' (subpath "%s")' % escaped
            return rules

        # the last matching rule wins
        profile = ("(version 1)(allow default)(deny file-write*)"
                   "(allow file-write*%s)(deny file-write*%s)"
                   % (subpaths(writable), subpaths(protected)))
        return ["sandbox-exec", "-p", profile] + cmd

    def check_build_and_tests(self):
        """Best-effort tier. The build runs on an export of HEAD (git
        archive), never on the working tree. A compilation error in the code
        blocks; a toolchain/environment failure becomes NOT POSSIBLE, which
        verdict.py reports loudly WITHOUT vetoing the whole run — that
        distinction is the main reason this gate can actually complete on
        machines that cannot build the full platform."""
        build_area = "Backend build (Maven)"
        tests_area = "Backend tests (Surefire)"
        security_area = "Java security tests"
        if not self.file_exists_at(self.head_ref, "pom.xml"):
            for area in (build_area, tests_area, security_area):
                self.not_applicable(area, "no pom.xml at the repository root")
            return
        if shutil.which("mvn") is None:
            self.not_possible(build_area, "mvn absent (brew install maven)")
            for area in (tests_area, security_area):
                self.not_possible(area, "the build could not run")
            return

        scan_dir = self.export_head_tree()
        if scan_dir is None:
            self.not_possible(build_area, "git archive HEAD failed")
            for area in (tests_area, security_area):
                self.not_possible(area, "the build could not run")
            return

        build_log = os.path.join(self.run_dir, "mvn-build.log")
        # test-compile, not compile: a change that breaks the TEST sources
        # must fail here as a compilation error, not later as "no report"
        code, output = run(self.repo_code_command(
                               ["mvn", "-B", "clean", "test-compile"]),
                           kill_leftovers=True, cwd=scan_dir,
                           timeout=BUILD_TIMEOUT, log_path=build_log)
        if code is None:
            self.not_possible(build_area,
                              "build did not finish within %ds "
                              "(PREFLIGHT_BUILD_TIMEOUT raises it)"
                              % BUILD_TIMEOUT, "mvn-build.log")
            for area in (tests_area, security_area):
                self.not_possible(area, "the build did not succeed")
            return
        if code != 0:
            if "COMPILATION ERROR" in output:
                # the code itself does not compile: that is a finding about
                # the change, and it blocks
                self.blocked(build_area, "full export of HEAD",
                             "compilation failed", "high", "0/1/0/0",
                             "mvn-build.log")
            else:
                # the build broke before the compiler saw the code (a plugin
                # download, a toolchain problem): the machine cannot judge
                # this area, which is different from the code being broken
                self.not_possible(build_area,
                                  "the build failed before compiling "
                                  "(toolchain or environment, not this "
                                  "change)", "mvn-build.log")
            for area in (tests_area, security_area):
                self.not_possible(area, "the build did not succeed")
            return
        self.clean(build_area, "full export of HEAD",
                   "compilation succeeded", "mvn-build.log")

        test_log = os.path.join(self.run_dir, "mvn-test.log")
        code, output = run(self.repo_code_command(["mvn", "-B", "test"]),
                           kill_leftovers=True, cwd=scan_dir,
                           timeout=TEST_TIMEOUT, log_path=test_log)
        if code is None:
            self.not_possible(tests_area,
                              "tests did not finish within %ds "
                              "(PREFLIGHT_TEST_TIMEOUT raises it)"
                              % TEST_TIMEOUT, "mvn-test.log")
            self.not_possible(security_area, "the tests did not run")
            return

        total = failures = skipped = 0
        failed_names = []
        security_total = security_failed = 0
        report_paths = glob(os.path.join(scan_dir, "**",
                                         "target", "surefire-reports",
                                         "*.xml"), recursive=True)
        for report_path in report_paths:
            suite = parse_test_report_xml(report_path)
            if suite is None:
                continue
            for case in suite.iter("testcase"):
                classname = case.get("classname", "")
                total += 1
                if classname.endswith("SecurityTest") \
                        or ".security." in classname:
                    security_total += 1
                failed = any(child.tag in ("failure", "error")
                             for child in case)
                if failed:
                    failures += 1
                    failed_names.append("%s.%s" % (classname,
                                                   case.get("name", "?")))
                    if classname.endswith("SecurityTest") \
                            or ".security." in classname:
                        security_failed += 1
                elif any(child.tag == "skipped" for child in case):
                    skipped += 1
        if code != 0 and "COMPILATION ERROR" in output:
            self.blocked(tests_area, "test sources", "test compilation failed",
                         "high", "0/1/0/0", "mvn-test.log")
            self.not_possible(security_area, "the tests did not compile")
            return
        if total == 0:
            self.not_possible(tests_area, "mvn test produced no test report",
                              "mvn-test.log")
            self.not_possible(security_area, "the tests did not run")
            return
        scope = "%d test methods" % total
        if code != 0 and not failures:
            # mvn failed but no test in the reports did: some module
            # stopped before its tests ran
            self.record(tests_area, "PARTIAL", scope,
                        "mvn test exited %d with no failing test in the "
                        "reports: some modules may not have run" % code,
                        "%d passed, %d skipped" % (total - skipped, skipped),
                        "none", "0/0/0/0", "no", "mvn-test.log")
            self.not_possible(security_area, "not every module's tests ran")
            return
        if failures:
            listed = ", ".join(failed_names[:5])
            self.blocked(tests_area, scope,
                         "%d failing test(s): %s" % (failures, listed),
                         "high", "0/%d/0/0" % failures, "mvn-test.log")
        else:
            self.clean(tests_area, scope,
                       "%d passed, %d skipped" % (total - skipped, skipped),
                       "mvn-test.log")
        if security_total == 0:
            self.not_applicable(security_area,
                                "no test class named *SecurityTest or in a "
                                ".security. package")
        elif security_failed:
            self.blocked(security_area, "%d security tests" % security_total,
                         "%d failing security test(s)" % security_failed,
                         "high", "0/%d/0/0" % security_failed, "mvn-test.log")
        else:
            self.clean(security_area, "%d security tests" % security_total,
                       "all passed", "mvn-test.log")

    def check_python_tests(self):
        """Best-effort tier, the Python mirror of the Maven tier: without it
        the question "do the tests still pass?" is never asked on a Python
        repository. Runs pytest on the export of HEAD. Failing tests block;
        an environment that cannot run them (pytest absent, dependencies
        missing) is a loud NOT POSSIBLE caveat, never a veto."""
        area = "Python tests (pytest)"
        code, listing = git(self.repo, "ls-tree", "-r", "-z", "--name-only",
                            self.head_ref)
        if code != 0:
            self.not_possible(area, "could not list the files of HEAD")
            return
        test_files = []
        for path in listing.split("\0"):
            name = os.path.basename(path)
            if name.endswith(".py") and (name.startswith("test_")
                                         or name.endswith("_test.py")):
                test_files.append(path)
        if not test_files:
            self.not_applicable(area, "no Python test files (test_*.py / "
                                "*_test.py) in the repository")
            return
        # pytest is asked for through the interpreter running this gate, so
        # "installed" means importable here, not a binary on the PATH
        probe_code, _ = run([sys.executable, "-m", "pytest", "--version"],
                            timeout=60)
        if probe_code != 0:
            self.not_possible(area, "pytest absent for %s (pip install "
                              "pytest) and the repository has %d Python "
                              "test file(s)"
                              % (os.path.basename(sys.executable),
                                 len(test_files)))
            return
        scan_dir = self.export_head_tree()
        if scan_dir is None:
            self.not_possible(area, "the export of the judged commit failed")
            return

        # pytest writes its report to the temporary directory (the sandbox
        # forbids writes to the reports); it is copied into the run directory
        scratch_report = os.path.join(self.tmp_dir, "pytest-report.xml")
        report_path = os.path.join(self.run_dir, "pytest-report.xml")
        test_log = os.path.join(self.run_dir, "pytest.log")
        code, output = run(
            self.repo_code_command(
                [sys.executable, "-m", "pytest", "-q", "--color=no",
                 "--junit-xml=" + scratch_report]),
            kill_leftovers=True, cwd=scan_dir, timeout=TEST_TIMEOUT,
            log_path=test_log)
        if os.path.isfile(scratch_report):
            shutil.copyfile(scratch_report, report_path)
        if code is None:
            self.not_possible(area, "tests did not finish within %ds "
                              "(PREFLIGHT_TEST_TIMEOUT raises it)"
                              % TEST_TIMEOUT, "pytest.log")
            return
        # exit 5 also means "every module was skipped at import"; those
        # skips are in the report, and then it is read like any other run
        report_has_cases = False
        if code == 5 and os.path.isfile(report_path):
            skipped_report = parse_test_report_xml(report_path)
            report_has_cases = (skipped_report is not None
                                and skipped_report.find(".//testcase")
                                is not None)
        if code == 5 and report_has_cases:
            code = 0
        if code == 5:
            self.not_possible(area, "pytest collected no tests, although %d "
                              "file(s) are named like tests (test_*.py, "
                              "*_test.py): check conftest.py and the pytest "
                              "settings, or whether they are tests at all"
                              % len(test_files), "pytest.log")
            return
        if code not in (0, 1):
            # 2/3/4: collection or internal error. Missing dependencies land
            # here, but so does an import your change broke — read the log.
            self.not_possible(area, "pytest could not run the tests (exit "
                              "%d): missing dependencies, or an import this "
                              "change broke — read pytest.log" % code,
                              "pytest.log")
            return

        total = failures = skipped = 0
        failed_names = []
        ran_classnames = set()
        if os.path.isfile(report_path):
            root = parse_test_report_xml(report_path)
            if root is not None:
                for case in root.iter("testcase"):
                    total += 1
                    # a module skipped whole (importorskip at the top) is
                    # reported with an empty classname and the module as name
                    ran_classnames.add(case.get("classname", "")
                                       or case.get("name", ""))
                    failed = any(child.tag in ("failure", "error")
                                 for child in case)
                    if failed:
                        failures += 1
                        failed_names.append("%s::%s"
                                            % (case.get("classname", "?"),
                                               case.get("name", "?")))
                    elif any(child.tag == "skipped" for child in case):
                        skipped += 1
        if total == 0:
            # exit code says tests ran but the report is unreadable: fall
            # back to the exit code alone, never to silence
            if code == 1:
                self.blocked(area, "pytest run", "tests failed (the XML "
                             "report was unreadable — see pytest.log)",
                             "high", "0/1/0/0", "pytest.log")
            else:
                self.not_possible(area, "pytest produced no readable test "
                                  "report", "pytest.log")
            return
        scope = "%d test methods" % total
        if failures:
            listed = ", ".join(failed_names[:5])
            self.blocked(area, scope,
                         "%d failing test(s): %s" % (failures, listed),
                         "high", "0/%d/0/0" % failures, "pytest.log")
        else:
            self.clean(area, scope,
                       "%d passed, %d skipped" % (total - skipped, skipped),
                       "pytest.log")
        self.pytest_results = {"ran": ran_classnames, "failed": failed_names}

    def check_python_security_tests(self):
        """Every security-named Python test file of the judged commit must
        show up in the pytest report. That catches a file left out of
        collection by any means (collect_ignore, a hook, an ini option, a
        conftest spread over several lines). Best effort like the test run
        it reads."""
        area = "Python security tests"
        code, listing = git(self.repo, "ls-tree", "-r", "-z", "--name-only",
                            self.head_ref)
        security_files = []
        for path in listing.split("\0") if code == 0 else []:
            name = os.path.basename(path)
            if name.endswith(".py") and (name.startswith("test_")
                                         or name.endswith("_test.py")) \
                    and self.looks_like_security_test(path):
                security_files.append(path)
        if not security_files:
            self.not_applicable(area, "no security-named Python test file")
            return
        if self.pytest_results is None:
            self.not_possible(area, "the Python tests did not run")
            return
        not_run = []
        failing = []
        for path in security_files:
            # pytest names a test "<dotted path of its file>[.<class>]"
            module = path[:-3].replace("/", ".")
            if not any(name == module or name.startswith(module + ".")
                       for name in self.pytest_results["ran"]):
                not_run.append(path)
            if any(name.split("::")[0] == module
                   or name.split("::")[0].startswith(module + ".")
                   for name in self.pytest_results["failed"]):
                failing.append(path)
        scope = "%d security test file(s)" % len(security_files)
        if failing:
            self.blocked(area, scope, "failing: %s" % ", ".join(failing[:5]),
                         "high", self.counts_field(["high"] * len(failing)),
                         "pytest.log")
        elif not_run:
            # not a veto: a settings change may leave them out on purpose,
            # but a green must not hide that they never ran
            self.not_possible(area, "security test file(s) never ran (not "
                              "collected by pytest): %s"
                              % ", ".join(not_run[:5]), "pytest.log")
        else:
            self.clean(area, scope, "all ran (passed or skipped)",
                       "pytest.log")

    # ---- orchestration ----------------------------------------------------

    def git_state_photo(self):
        """The repository's real state (plain git: never the snapshot's
        temporary index), compared before and after the run."""
        pieces = []
        for args in (("status", "--porcelain=v1",
                      "--ignore-submodules=none"),
                     ("rev-parse", "HEAD"),
                     ("for-each-ref",
                      "--format=%(refname) %(objectname)")):
            code, output = git(self.repo, *args, plain=True)
            if code != 0:
                # two identical failures would otherwise compare equal
                self.photo_failed = True
            pieces.append(output)
        return "\n".join(pieces)

    def write_run_files(self):
        with open(os.path.join(self.run_dir, "areas.tsv"), "w",
                  encoding="utf-8") as f:
            for row in self.rows:
                f.write("\t".join(sanitize(field) for field in row) + "\n")
        if self.notes:
            with open(os.path.join(self.run_dir, "notes.txt"), "w",
                      encoding="utf-8") as f:
                f.write("\n".join(self.notes) + "\n")

    def write_meta(self):
        def answer(*args, repo=None):
            # git's error text must not end up in the evidence as if it
            # were a value
            code, output = git(repo or self.repo, *args, plain=True)
            return output.strip() if code == 0 else ""

        remote = strip_credentials(answer("remote", "get-url", "origin"))
        commit = answer("rev-parse", "HEAD")
        judged = commit
        if self.snapshot:
            _code, judged = git(self.repo, "rev-parse", self.head_ref)
            judged = judged.strip()
        lines = [
            "mode=%s" % ("check-worktree" if self.snapshot else "check"),
            "repo_path=%s" % self.repo,
            "repo_remote=%s" % (remote or "(no origin remote)"),
            "branch=%s" % answer("rev-parse", "--abbrev-ref", "HEAD"),
            "commit=%s" % commit,
            "judged_commit=%s" % judged,
            "base_ref=%s" % self.base_ref,
            "scan_dir=%s" % (self.tmp_dir or "-"),
            "scan_source=diff-scoped: changed files read from git objects "
            "(%s vs merge-base %s); build/tests on an export of it"
            % ("a snapshot of the working tree" if self.snapshot else "HEAD",
               (self.fork_commit or "?")[:12]),
            "toolkit_path=%s" % TOOLKIT_DIR,
            "toolkit_commit=%s" % (answer("rev-parse", "HEAD",
                                          repo=TOOLKIT_DIR)
                                   or "(toolkit not in git)"),
        ]
        with open(os.path.join(self.run_dir, "run-meta.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def collect_versions(self):
        """Asks every tool for its version, in a background thread started
        with the run: it takes about 2 s and nothing else depends on it."""
        lines = ["# tool versions actually used for this run",
                 "utc=%s" % utc_now()]
        # The full command per tool, because they are not all reached the same
        # way: pytest is used THROUGH this interpreter rather than as a binary
        # on PATH, so its version has to be asked for exactly as the gate runs
        # it, or the record would say "absent" for a tool that just ran.
        environment = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0")
        for tool, cmd in (("git", ["git", "--version"]),
                          ("python", [sys.executable, "--version"]),
                          ("semgrep", ["semgrep", "--version"]),
                          ("trivy", ["trivy", "--version"]),
                          ("bandit", ["bandit", "--version"]),
                          ("pytest", [sys.executable, "-m", "pytest",
                                      "--version"]),
                          ("mvn", ["mvn", "-v"]),
                          ("java", ["java", "-version"])):
            if shutil.which(cmd[0]) is None:
                lines.append("%s=(absent)" % tool)
                continue
            code, output = run(cmd, timeout=30, env=environment)
            if code != 0:
                # the binary exists but the tool does not answer — for pytest
                # this is the "not importable by this interpreter" case, which
                # is exactly what the tests area reports as NOT POSSIBLE
                lines.append("%s=(absent)" % tool)
                continue
            lines.append("%s=%s" % (tool, first_version_line(output)))
        self.version_lines = lines

    def write_versions(self):
        lines = getattr(self, "version_lines", None) or [
            "# tool versions could not be collected"]
        with open(os.path.join(self.run_dir, "runtime-versions.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def write_review_scope(self):
        """review-scope.json: what phase 2 reviews (see
        checks/review_scope.py). A failure becomes a note and leaves the
        mechanical verdict alone; phase 2 then stops on the missing file."""
        try:
            _code, numstat = git_diff(self.repo, "--numstat", "-z",
                                      self.fork_commit, self.head_ref)
            _code, head = git(self.repo, "rev-parse", self.head_ref)
            code_without_rules = [
                {"path": path, "language": self.code_language[path]}
                for _status, path in self.changed
                if path in self.code_language
                and self.code_language[path] not in SEMGREP_LANGUAGES]
            code_files = [path for _status, path in self.changed
                          if path in self.code_language]
            scope_data = review_scope.build_scope(
                self.base_ref, self.fork_commit, head.strip(), self.changed,
                numstat, os.path.join(TOOLKIT_DIR, "checks", "review",
                                      "checklist.md"),
                self.script_language, code_without_rules, code_files)
            # the review reads files from the working tree and needs the
            # commit it judges to be HEAD; a snapshot is neither
            scope_data["snapshot"] = self.snapshot
            review_scope.write_scope(self.run_dir, scope_data)
        except Exception as exc:
            self.note("WARNING: review-scope.json could not be written (%r): "
                      "the diff review cannot start from this run" % exc)
            return
        # Name the files no deep dive will read, right away: a file absent
        # from the results reads as examined and clean.
        if self.feed_path:
            dives = scope_data["dives"]
            for path in dives["no_matching_skill"]:
                feed.file_status(self.feed_path, path, "skipped",
                                 reason="no per-file reviewer for this "
                                        "file type")
            for path in dives["dropped_beyond_cap"]:
                feed.file_status(self.feed_path, path, "skipped",
                                 reason="beyond the cap of %d files per run"
                                        % dives["cap"])

    def write_timings(self, total_seconds):
        """timings.txt: seconds per step, slowest first. Evidence only:
        nothing that decides reads it."""
        lines = ["# seconds per gate step, slowest first",
                 "total=%.2f" % total_seconds]
        for name, seconds in sorted(self.timings, key=lambda item: -item[1]):
            lines.append("%s=%.2f" % (name, seconds))
        with open(os.path.join(self.run_dir, "timings.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def record_working_tree(self, dirty):
        """The 'Uncommitted changes' row. dirty: (tracked, untracked) file
        counts outside HEAD. Work outside the judged commit was never
        examined, and a green verdict must not suggest it was."""
        area = "Uncommitted changes"
        if dirty is None:
            self.not_possible(area, "git status failed, so it is unknown "
                              "whether the working tree matches HEAD")
            return
        tracked, untracked = dirty
        described = "%d modified tracked file(s), %d untracked file(s)" % (
            tracked, untracked)
        if self.snapshot:
            self.record(area, "TESTED", described, "-",
                        "judged the working tree as a snapshot (--worktree), "
                        "not a commit: commit it, then run the gate again "
                        "before publishing", "none", "0/0/0/0", "no",
                        "run-meta.txt")
        elif tracked or untracked:
            self.not_possible(area, "%s are not in HEAD, which is what this "
                              "run judges: commit them, or run with "
                              "--worktree to judge the working tree"
                              % described)
        else:
            self.clean(area, "working tree", "working tree matches HEAD")

    def check_toolkit_integrity(self, fingerprint_at_start, local_changes):
        """Says which toolkit judged the run: its uncommitted edits (a
        warning: editing exceptions.txt is normal), and whether its files
        changed while the run was going (then the run cannot say which
        version decided)."""
        area = "Toolkit integrity"
        changed = sorted(path for path, digest
                         in toolkit_fingerprint().items()
                         if fingerprint_at_start.get(path) != digest)
        changed += sorted(path for path in fingerprint_at_start
                          if not os.path.exists(os.path.join(TOOLKIT_DIR,
                                                             path)))
        if changed:
            self.not_possible(area, "toolkit files changed while the run was "
                              "going (%s): run it again"
                              % ", ".join(changed[:5]))
        elif local_changes:
            self.record(area, "TESTED", "toolkit files", "-",
                        "the toolkit has uncommitted changes: "
                        + ", ".join(local_changes[:5]),
                        "low", "0/0/0/1", "no")
        elif local_changes is None:
            self.clean(area, "toolkit files",
                       "unchanged during the run; not a git checkout, so "
                       "earlier modifications cannot be checked")
        else:
            self.clean(area, "toolkit files",
                       "matches its git checkout, unchanged during the run")

    def run_check(self, dirty):
        state_before = self.git_state_photo()
        with open(os.path.join(self.run_dir, "git-state-before.txt"), "w",
                  encoding="utf-8") as f:
            f.write(state_before)
        self.record_working_tree(dirty)

        # the diff this gate judges: merge-base(base, HEAD)..HEAD, i.e.
        # exactly what the merge request will contain
        if self.base_ref == EMPTY_TREE_BASE:
            # a first publish: compare with nothing, every commit is new
            code, fork = git(self.repo, "hash-object", "-t", "tree",
                             os.devnull)
            if code != 0:
                raise RuntimeError("cannot name git's empty tree")
            self.fork_commit = fork.strip()
            self.history_range = self.head_ref
        else:
            code, fork = git(self.repo, "merge-base", self.base_ref,
                             self.head_ref)
            if code != 0:
                raise RuntimeError("no merge base between %s and HEAD"
                                   % self.base_ref)
            self.fork_commit = fork.strip()
            self.history_range = "%s..%s" % (self.fork_commit,
                                             self.head_ref)

        # --raw -z --no-abbrev: for every changed file its modes, its blob
        # ids on both sides and its path, NUL-separated and unquoted (without
        # -z, git quotes a path holding non-ASCII bytes, quotes or tabs, and
        # a quoted path matches no file). The scans read files by blob id; a
        # rename's "before" blob is the old file's, so the findings already
        # in it stay old.
        code, raw = git_diff(self.repo, "--raw", "-z", "--no-abbrev",
                             self.fork_commit, self.head_ref)
        if code != 0:
            raise RuntimeError("git diff --raw failed")
        fields = raw.split("\0")
        position = 0
        while position < len(fields) and fields[position].startswith(":"):
            old_mode, new_mode, old_id, new_id, letters = \
                fields[position][1:].split(" ")
            status = letters[0]  # R100 -> R, C75 -> C
            if status in ("R", "C") and position + 2 < len(fields):
                self.base_path_of[fields[position + 2]] = fields[position + 1]
                path = fields[position + 2]  # judge the NEW path
                position += 3
            elif position + 1 < len(fields):
                path = fields[position + 1]
                position += 2
            else:
                break
            self.blob_of[path] = {"old_mode": old_mode, "new_mode": new_mode,
                                  "old_id": old_id, "new_id": new_id}
            self.changed.append((status, path))
        # An empty diff examines nothing: usually the base is the branch (a
        # first publish with no remote), or the work is not committed. The
        # core checks then say so instead of reporting a clean scan.
        self.empty_diff = not self.changed
        self.classify_changed_code()

        # Tell the progress feed a run started, with the full changed-file
        # list, so a viewer can show every file as "pending" right away.
        if self.feed_path:
            feed.start_run(self.feed_path, os.path.basename(self.run_dir),
                           self.base_ref,
                           [path for _status, path in self.changed])
            feed.phase(self.feed_path, "gate", "running")

        code, self.diff_text = git_diff(self.repo, self.fork_commit,
                                        self.head_ref, timeout=300)
        with open(os.path.join(self.run_dir, "diff.patch"), "w",
                  encoding="utf-8") as f:
            f.write(self.diff_text)
        _code, stat = git_diff(self.repo, "--stat", self.fork_commit,
                               self.head_ref)
        with open(os.path.join(self.run_dir, "diff-stat.txt"), "w",
                  encoding="utf-8") as f:
            f.write(stat)
        _code, shortstat = git_diff(self.repo, "--shortstat",
                                    self.fork_commit, self.head_ref)
        self.note("diff vs %s: %s" % (self.base_ref,
                                      shortstat.strip() or "empty"))

        self.write_review_scope()

        # cheap and core first; the build (slowest, most fragile) goes last,
        # so even an aborted run leaves the security core on disk
        checks = (self.check_exceptions_file,
                  self.check_secrets,
                  self.check_security_tests_in_diff,
                  self.check_scanner_integrity,
                  self.check_semgrep,
                  self.check_uncovered_code,
                  self.check_bandit,
                  self.check_dependencies,
                  self.check_http_hygiene,
                  self.check_build_and_tests,
                  self.check_python_tests,
                  self.check_python_security_tests)
        for check in checks:
            label = CHECK_LABELS.get(check.__name__, check.__name__)
            if self.feed_path:
                feed.check(self.feed_path, "gate", label, "running")
            rows_before = len(self.rows)
            started = time.perf_counter()
            try:
                check()
            except Exception as exc:  # a crashed check must stay visible
                self.not_possible("Gate crash (%s)" % check.__name__,
                                  "this check crashed: %r" % exc)
            seconds = time.perf_counter() - started
            self.timings.append((check.__name__, seconds))
            if self.feed_path:
                self.report_check_to_feed(label, self.rows[rows_before:],
                                          seconds)

        state_after = self.git_state_photo()
        with open(os.path.join(self.run_dir, "git-state-after.txt"), "w",
                  encoding="utf-8") as f:
            f.write(state_after)
        if self.photo_failed:
            self.not_possible("Gate self-check (read-only)",
                              "git could not report the repository's state "
                              "before or after the run",
                              "git-state-after.txt")
        elif state_after == state_before:
            self.clean("Gate self-check (read-only)", "2 git snapshots",
                       "git state identical before and after (verified)",
                       "git-state-after.txt")
        else:
            self.record("Gate self-check (read-only)", "TESTED",
                        "2 git snapshots", "-",
                        "THE GIT STATE CHANGED - compare "
                        "git-state-before.txt and git-state-after.txt",
                        "critical", "1/0/0/0", "yes", "git-state-after.txt")

    def report_check_to_feed(self, label, rows, seconds):
        """One "done" feed event per check, summarising the rows it
        recorded: the worst status, whether any blocks, a one-line detail
        (the outcome, or the reason when it could not run) and the number
        of new findings, blocking or advisory."""
        if not rows:
            feed.check(self.feed_path, "gate", label, "done",
                       result="NOT APPLICABLE", blocking=False,
                       seconds=round(seconds, 2), count=0)
            return
        order = ("NOT POSSIBLE", "PARTIAL", "TESTED", "NOT APPLICABLE")
        worst = min(rows, key=lambda row: order.index(row[1])
                    if row[1] in order else 0)
        blocking = any(row[7] == "yes" for row in rows)
        detail_row = next((row for row in rows if row[7] == "yes"), worst)
        detail = detail_row[4] if detail_row[1] in ("TESTED", "PARTIAL") \
            and detail_row[4] not in ("-", "") else detail_row[3]
        count = sum(findings_in_counts(row[6]) for row in rows)
        feed.check(self.feed_path, "gate", label, "done",
                   result=worst[1], blocking=blocking,
                   detail=sanitize(detail)[:200], seconds=round(seconds, 2),
                   count=count)

    def report_unexamined_to_feed(self):
        """Sends to the feed every area that could NOT be examined, with its
        reason: the bottom line only says how many there are."""
        if not self.feed_path:
            return
        for row in self.rows:
            area_name, status = row[0], row[1]
            if status in ("NOT POSSIBLE", "PARTIAL"):
                feed.area(self.feed_path, area_name, status,
                          sanitize(row[3]))


def strip_credentials(url):
    """Drops the user name and token that a remote URL may carry before its
    host: the run directory is meant to be shared."""
    return re.sub(r"^([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/@]*@", r"\1", url)


def toolkit_fingerprint():
    """{relative path: sha256} for every file the toolkit runs or reads to
    decide: preflight.sh and the code, rules and settings under checks/
    (a .DS_Store written by Finder is none of those)."""
    import hashlib
    fingerprint = {}
    paths = [os.path.join(TOOLKIT_DIR, "preflight.sh")]
    for root, dirs, files in os.walk(os.path.join(TOOLKIT_DIR, "checks")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for name in files:
            if name.endswith(TOOLKIT_CODE_EXTENSIONS):
                paths.append(os.path.join(root, name))
    for path in paths:
        try:
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            continue
        fingerprint[os.path.relpath(path, TOOLKIT_DIR)] = digest
    return fingerprint


# untracked files that can change what the toolkit does (a .DS_Store
# cannot, and must not veto a run)
TOOLKIT_CODE_EXTENSIONS = (".py", ".js", ".mjs", ".sh", ".yaml", ".yml",
                           ".json", ".txt", ".md")


def toolkit_local_changes():
    """Files under checks/ or preflight.sh that differ from the toolkit's
    own git checkout, or None when the toolkit is not a git checkout."""
    code, output = git(TOOLKIT_DIR, "status", "--porcelain=v1",
                       "--untracked-files=all", "--", "checks",
                       "preflight.sh", plain=True)
    if code != 0:
        return None
    changes = []
    for line in output.splitlines():
        path = line[3:].strip()
        if not path or "__pycache__" in path or path.endswith(".pyc"):
            continue
        if line.startswith("??") and not path.endswith(
                TOOLKIT_CODE_EXTENSIONS):
            continue
        changes.append(path)
    return changes


def working_tree_changes(repo):
    """(tracked files modified, untracked files not ignored), or None when
    git status failed (a corrupt index, a timeout): unknown is not clean."""
    code, output = git(repo, "status", "--porcelain=v1", "-z",
                       "--untracked-files=all", "--ignore-submodules=none",
                       plain=True)
    if code != 0:
        return None
    tracked = untracked = 0
    entries = output.split("\0")
    position = 0
    while position < len(entries):
        entry = entries[position]
        position += 1
        if not entry:
            continue
        if entry.startswith("??"):
            untracked += 1
        else:
            tracked += 1
            if entry[0] in ("R", "C"):
                position += 1  # the entry carries its old path next
    return (tracked, untracked)


def make_worktree_snapshot(repo, tmp_dir):
    """A commit object holding the working tree (tracked changes plus
    untracked files that are not ignored), with HEAD as its parent, built
    WITHOUT touching the repository: a temporary index, and new objects
    written to a temporary directory that reads the repository's objects
    as alternates. No ref points to it, nothing lands in .git. Returns the
    commit id, or None when the working tree matches HEAD."""
    code, common = git(repo, "rev-parse", "--path-format=absolute",
                       "--git-common-dir", plain=True)
    if code != 0:
        raise RuntimeError("cannot locate the repository's object store")
    objects = os.path.join(common.strip(), "objects")
    alternates = [objects]
    # a repository cloned with --reference reads further object stores;
    # the snapshot's own object directory must list them too
    try:
        with open(os.path.join(objects, "info", "alternates"),
                  encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    alternates.append(line if os.path.isabs(line)
                                      else os.path.join(objects, line))
    except OSError:
        pass
    snapshot_objects = os.path.join(tmp_dir, "snapshot-objects")
    os.makedirs(snapshot_objects, exist_ok=True)
    SNAPSHOT_GIT_ENV.update({
        "GIT_INDEX_FILE": os.path.join(tmp_dir, "snapshot-index"),
        "GIT_OBJECT_DIRECTORY": snapshot_objects,
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.pathsep.join(alternates),
        "GIT_AUTHOR_NAME": "preflight", "GIT_AUTHOR_EMAIL": "preflight@local",
        "GIT_COMMITTER_NAME": "preflight",
        "GIT_COMMITTER_EMAIL": "preflight@local",
    })
    for args in (("read-tree", "HEAD"), ("add", "-A")):
        code, output = git(repo, *args, timeout=600)
        if code != 0:
            raise RuntimeError("snapshot step 'git %s' failed: %s"
                               % (" ".join(args), output.strip()[:200]))
    code, tree = git(repo, "write-tree")
    _code, head_tree = git(repo, "rev-parse", "HEAD^{tree}")
    if code != 0:
        raise RuntimeError("snapshot step 'git write-tree' failed")
    if tree.strip() == head_tree.strip():
        SNAPSHOT_GIT_ENV.clear()
        return None
    code, commit = git(repo, "commit-tree", tree.strip(), "-p", "HEAD",
                       "-m", "preflight: snapshot of the working tree")
    if code != 0:
        raise RuntimeError("snapshot step 'git commit-tree' failed")
    return commit.strip()


def render_verdict(run_dir):
    """Renders the verdict with the verdict module imported when this run
    STARTED, before any repository code ran: a test suite that rewrote
    verdict.py on disk cannot change this run's result. fail() in verdict.py
    exits; that becomes exit code 2."""
    try:
        return verdict.command_render(run_dir)
    except SystemExit as stop:
        return stop.code if stop.code in (0, 1, 2) else 2
    except Exception as exc:
        print("verdict rendering crashed: %r" % exc, file=sys.stderr)
        return 2


def resolve_base_ref(repo, explicit):
    if explicit == EMPTY_TREE_BASE:
        return explicit
    if explicit:
        code, _ = git(repo, "rev-parse", "--verify", "--quiet", explicit)
        if code != 0:
            return None
        return explicit
    for candidate in ("origin/main", "origin/master", "main", "master"):
        code, _ = git(repo, "rev-parse", "--verify", "--quiet", candidate)
        if code == 0:
            return candidate
    return None


def main_repository_name(repo):
    """The folder name of the main repository, the same for every linked
    worktree of it: the parent of git's common directory. A submodule, or
    a repository whose git directory is not named .git, keeps its own top
    level. Same rule as BranchLens's find_repo_root."""
    code, common = git(repo, "rev-parse", "--git-common-dir", plain=True)
    if code == 0 and common.strip():
        # git may answer relative to repo (the -C directory)
        common_dir = os.path.abspath(os.path.join(repo, common.strip()))
        if os.path.basename(common_dir) == ".git":
            return os.path.basename(os.path.realpath(
                os.path.dirname(common_dir)))
    return os.path.basename(os.path.realpath(repo))


def usage_error(message):
    print("preflight gate ERROR: %s" % message, file=sys.stderr)
    print("usage: gate.py check <repository> [base-ref] [--worktree]",
          file=sys.stderr)
    sys.exit(4)


def stop_on_sigterm(_signal_number, _frame):
    # SIGTERM (a timeout, or a tool stopping the gate) is handled like
    # Ctrl-C, so the run still leaves a verdict behind
    raise KeyboardInterrupt()


def main(argv):
    # Ignore replace refs (refs/replace/*) in every git command of this run
    # and of anything it starts: they make git hand out other objects than
    # the ones a push publishes.
    os.environ["GIT_NO_REPLACE_OBJECTS"] = "1"
    if len(argv) >= 1 and argv[0] == "baseline":
        print("Baselines are no longer needed: the gate compares the changed")
        print("files directly against the base branch (default origin/main).")
        print("Just run:  ./preflight.sh check <repository> [base-ref]")
        return 0
    worktree_mode = "--worktree" in argv
    argv = [arg for arg in argv if arg != "--worktree"]
    if len(argv) < 2 or argv[0] != "check":
        usage_error("expected: check <repository> [base-ref] [--worktree]")
    repo_arg = argv[1]
    if not os.path.isdir(repo_arg):
        usage_error("not a directory: %s" % repo_arg)
    code, toplevel = git(repo_arg, "rev-parse", "--show-toplevel")
    if code != 0:
        usage_error("not a git repository: %s" % repo_arg)
    repo = toplevel.strip()
    base_ref = resolve_base_ref(repo, argv[2] if len(argv) > 2 else None)
    if base_ref is None:
        usage_error("cannot resolve a base ref (tried origin/main, "
                    "origin/master, main, master) — pass one explicitly")

    # Fingerprint the toolkit before any repository code runs, to notice a
    # test suite that rewrites it.
    fingerprint_at_start = toolkit_fingerprint()
    local_changes = toolkit_local_changes()
    signal.signal(signal.SIGTERM, stop_on_sigterm)

    # PREFLIGHT_REPORTS_DIR (empty counts as unset), else one folder per
    # repository, whichever worktree of it is judged
    configured_root = os.environ.get("PREFLIGHT_REPORTS_DIR", "")
    if configured_root:
        reports_root = os.path.abspath(os.path.expanduser(configured_root))
    else:
        reports_root = os.path.abspath(os.path.join(
            os.path.expanduser("~"), "preflight-reports",
            main_repository_name(repo)))
    code, head = git(repo, "rev-parse", "--short", "HEAD")
    short_head = head.strip() if code == 0 else "no-commit"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    # runs are never overwritten: two runs in the same second get -2, -3...
    run_dir = os.path.join(reports_root, "%s-%s" % (stamp, short_head))
    suffix = 1
    while os.path.exists(run_dir):
        suffix += 1
        run_dir = os.path.join(reports_root, "%s-%s-%d"
                               % (stamp, short_head, suffix))
    os.makedirs(run_dir)

    gate = Gate(repo, base_ref)
    gate.run_dir = run_dir
    gate.reports_root = reports_root
    gate.tmp_dir = tempfile.mkdtemp(prefix="preflight-scan-")
    # Work from an empty directory: `python -m pytest` puts the current
    # directory first on sys.path and mvn reads .mvn/ from it, so started
    # inside the repository they would load its own pytest.py or JVM
    # options outside the sandbox.
    os.chdir(gate.tmp_dir)
    # The progress feed lives at a STABLE per-repository path (not inside the
    # timestamped run directory), so a viewer can be pointed at it once.
    gate.feed_path = os.path.join(reports_root, "security-feed.jsonl")
    versions_thread = threading.Thread(target=gate.collect_versions,
                                       daemon=True)
    versions_thread.start()

    print("preflight check - repository: %s" % repo, flush=True)
    print("base ref: %s" % base_ref, flush=True)
    print("report in: %s" % run_dir, flush=True)
    print("security feed: %s" % gate.feed_path, flush=True)

    run_started = time.perf_counter()
    try:
        dirty = working_tree_changes(repo)
        if worktree_mode:
            started = time.perf_counter()
            snapshot = make_worktree_snapshot(repo, gate.tmp_dir)
            gate.timings.append(("working-tree snapshot",
                                 time.perf_counter() - started))
            if snapshot:
                gate.head_ref = snapshot
                gate.snapshot = True
                print("judging the working tree (snapshot %s), not a commit"
                      % snapshot[:12], flush=True)
        gate.run_check(dirty)
    except KeyboardInterrupt:
        # even an interrupted run must leave a rendered verdict behind: a
        # run directory without one is indistinguishable from a crash
        gate.not_possible("Gate crash", "the run was interrupted (Ctrl-C or "
                          "SIGTERM): everything below this point was never "
                          "examined")
    except Exception as exc:
        # whatever already ran stays on record; the crash becomes a row, so
        # the rendered verdict can never be green
        gate.not_possible("Gate crash", "the gate crashed: %r" % exc)
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        gate.check_toolkit_integrity(fingerprint_at_start, local_changes)
        gate.report_unexamined_to_feed()
        gate.write_run_files()
        gate.write_meta()
        started = time.perf_counter()
        versions_thread.join(timeout=120)
        gate.write_versions()
        gate.timings.append(("waiting for tool versions",
                             time.perf_counter() - started))
        gate.write_timings(time.perf_counter() - run_started)
        os.chdir(os.path.dirname(gate.tmp_dir))  # leave it before removing it
        if os.environ.get("PREFLIGHT_KEEP_SCAN_TREE") != "1":
            shutil.rmtree(gate.tmp_dir, ignore_errors=True)

    exit_code = render_verdict(run_dir)
    # Mirror the bottom line into the progress feed (telemetry only; the
    # feed is written FROM the verdict, never read by anything that decides).
    verdict_words = {0: "PASSED", 1: "FAILED", 2: "INCONCLUSIVE"}
    feed.phase(gate.feed_path, "gate", "done",
               verdict_words.get(exit_code, "INCONCLUSIVE"))
    try:
        with open(os.path.join(run_dir, "verdict.txt"),
                  encoding="utf-8", errors="replace") as f:
            bottom_line = f.readline().strip()
        if bottom_line:
            feed.verdict(gate.feed_path, bottom_line,
                         verdict_words.get(exit_code))
    except OSError:
        pass
    if not os.path.isfile(os.path.join(run_dir, "verdict.txt")):
        print("ERROR: verdict.py did not produce verdict.txt; a run whose "
              "evidence record failed to write cannot claim a result.",
              file=sys.stderr)
        return 2
    if exit_code not in (0, 1, 2):
        return 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
