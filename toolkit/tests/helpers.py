"""Shared helpers for the end-to-end tests: throwaway git repositories and a
real gate run on them."""

import json
import os
import subprocess
import sys
import tempfile

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(TOOLKIT_DIR, "checks", "gate.py")


def git(repo, *args):
    subprocess.run(
        ["git", "-C", repo, "-c", "user.name=test",
         "-c", "user.email=test@example.invalid"] + list(args),
        check=True, capture_output=True)


def write(repo, relative_path, content):
    path = os.path.join(repo, relative_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as f:
        f.write(content)


def make_repo(main_files, change):
    """main_files: {path: content} committed on main. change: a function
    that edits the repository on the feature branch. Returns the path."""
    repo = tempfile.mkdtemp(prefix="gate-test-")
    git(repo, "init", "-q", "-b", "main")
    write(repo, "README.md", "fixture\n")
    for relative_path, content in main_files.items():
        write(repo, relative_path, content)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main")
    git(repo, "checkout", "-qb", "feature")
    change(repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "feature")
    return repo


def run_gate(repo, git_config=None, extra_args=(), gate=GATE, base="main",
             cwd=None, extra_env=None):
    """Runs the gate; returns (exit code, {area: row}, run directory).
    git_config: {key: value} applied to every git command the gate runs, as
    if it were in the user's ~/.gitconfig. gate: another copy of gate.py."""
    reports = tempfile.mkdtemp(prefix="gate-reports-")
    environment = dict(os.environ, PREFLIGHT_REPORTS_DIR=reports,
                       **(extra_env or {}))
    for index, (key, value) in enumerate((git_config or {}).items()):
        environment["GIT_CONFIG_KEY_%d" % index] = key
        environment["GIT_CONFIG_VALUE_%d" % index] = value
        environment["GIT_CONFIG_COUNT"] = str(index + 1)
    command = [sys.executable, gate, "check", repo]
    if base:
        command.append(base)
    result = subprocess.run(command + list(extra_args), cwd=cwd,
                            capture_output=True, text=True, env=environment)
    run_dirs = [name for name in os.listdir(reports)
                if os.path.isdir(os.path.join(reports, name))]
    assert len(run_dirs) == 1, result.stdout + result.stderr
    run_dir = os.path.join(reports, run_dirs[0])
    with open(os.path.join(run_dir, "verdict.json")) as f:
        verdict = json.load(f)
    rows = {area["area"]: area for area in verdict["areas"]}
    return result.returncode, rows, run_dir
