"""End-to-end regression tests for checks/gate.py.

Each test builds a throwaway git repository (a `main` branch, then a
`feature` branch with one change), runs the real gate on it and reads the
rows of the verdict.json it writes. Each case reproduces a failure from a
real run. Slow: semgrep runs twice per gate run, a few seconds each.

Run with:  python3 -m pytest tests/ -q
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

from helpers import GATE, git, make_repo, write
from helpers import run_gate as run_gate_with_dir

# A sink the local semgrep rules flag (checks/semgrep-rules).
PICKLE_SINK = (
    "import pickle\n"
    "\n"
    "\n"
    "def load(data):\n"
    "    return pickle.loads(data)\n"
)
FAKE_AWS_KEY = "AKIA" + "Q" * 16

pytestmark = pytest.mark.skipif(
    subprocess.run(["which", "semgrep"], capture_output=True).returncode != 0,
    reason="semgrep is not installed")


def run_gate(repo):
    code, rows, _run_dir = run_gate_with_dir(repo)
    return code, rows


SEMGREP = "Multi-language analysis (Semgrep)"
SECRETS = "Secrets in the diff"
SECURITY_TESTS = "Security tests in the diff"


def test_clean_change_passes():
    def change(repo):
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    code, rows = run_gate(make_repo({}, change))
    assert rows[SEMGREP]["status"] == "TESTED"
    assert code == 0


def test_file_under_tests_is_scanned():
    # semgrep's built-in ignore list skips tests/
    def change(repo):
        write(repo, "tests/test_loader.py", PICKLE_SINK)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SEMGREP]["status"] == "TESTED"
    assert rows[SEMGREP]["blocking"] is True
    assert code == 1


def test_file_under_vendor_is_scanned():
    def change(repo):
        write(repo, "vendor/loader.py", PICKLE_SINK)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SEMGREP]["status"] == "TESTED"
    assert rows[SEMGREP]["blocking"] is True


def test_renamed_file_keeps_its_old_findings_old():
    # the sink is already on main; the change only renames the file and
    # adds a comment
    def change(repo):
        git(repo, "mv", "lib/loader.py", "lib/loading.py")
        write(repo, "lib/loading.py", "# renamed\n" + PICKLE_SINK)
    code, rows = run_gate(make_repo({"lib/loader.py": PICKLE_SINK}, change))
    assert rows[SEMGREP]["status"] == "TESTED"
    assert rows[SEMGREP]["blocking"] is False
    assert code == 0


def test_non_ascii_file_name_is_scanned():
    # git quotes non-ASCII paths by default, and a quoted path matches no file
    def change(repo):
        write(repo, "lib/café.py", PICKLE_SINK)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SEMGREP]["blocking"] is True
    assert code == 1


def test_secret_after_a_form_feed_is_found():
    def change(repo):
        write(repo, "config.py", "timeout = 3\x0ckey = '%s'\n" % FAKE_AWS_KEY)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SECRETS]["blocking"] is True


def test_secret_on_a_line_starting_with_plus_plus_is_found():
    def change(repo):
        write(repo, "app.js", "let i = 0;\n++i; // %s\n" % FAKE_AWS_KEY)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SECRETS]["blocking"] is True


def test_secret_after_a_placeholder_on_the_same_line_is_found():
    def change(repo):
        # built at run time, so this test file carries no secret-shaped line
        real_value = "Real-" + "Secret-9x7"
        write(repo, "settings.py",
              'old_password = "changeme-later"; '
              'new_password = "%s"\n' % real_value)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SECRETS]["blocking"] is True


def test_security_test_renamed_away_blocks():
    security_test = "def test_admin_only():\n    assert True\n"

    def change(repo):
        git(repo, "mv", "tests/test_security_admin.py", "tests/old_admin.py")
    code, rows = run_gate(make_repo(
        {"tests/test_security_admin.py": security_test}, change))
    assert rows[SECURITY_TESTS]["blocking"] is True
    assert code == 1


def test_gitattributes_cannot_hide_a_secret_from_the_diff():
    # a committed '-diff' attribute makes git print "Binary files differ"
    def change(repo):
        write(repo, ".gitattributes", "*.cfg -diff\n")
        write(repo, "app.cfg", "key = %s\n" % FAKE_AWS_KEY)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SECRETS]["blocking"] is True


def test_user_git_config_does_not_change_what_the_gate_reads():
    def change(repo):
        write(repo, "config.py", "key = '%s'\n" % FAKE_AWS_KEY)
    code, rows, _run_dir = run_gate_with_dir(
        make_repo({}, change),
        git_config={"color.ui": "always", "diff.noprefix": "true",
                    "diff.mnemonicPrefix": "true"})
    assert rows[SECRETS]["blocking"] is True


BANDIT = "Python analysis (Bandit)"
PYTEST = "Python tests (pytest)"


def test_a_second_identical_sink_in_the_same_file_is_new():
    # semgrep's snippet field reads "requires login" without an account,
    # which once collapsed every finding of a rule in a file
    def change(repo):
        write(repo, "lib/loader.py",
              PICKLE_SINK + "\n\ndef load_again(data):\n"
              "    return pickle.loads(data)\n")
    code, rows = run_gate(make_repo({"lib/loader.py": PICKLE_SINK}, change))
    assert rows[SEMGREP]["blocking"] is True
    assert code == 1


def test_nosec_does_not_hide_a_bandit_finding():
    def change(repo):
        write(repo, "lib/run.py",
              "import subprocess\n\n\ndef go(cmd):\n"
              "    subprocess.call(cmd, shell=True)  # nosec\n")
    code, rows = run_gate(make_repo({}, change))
    assert rows[BANDIT]["blocking"] is True


def test_bandit_reads_files_under_dot_github():
    def change(repo):
        write(repo, ".github/scripts/deploy.py",
              "import subprocess\n\n\ndef go(cmd):\n"
              "    subprocess.call(cmd, shell=True)\n")
    code, rows = run_gate(make_repo({}, change))
    assert rows[BANDIT]["status"] == "TESTED"
    assert rows[BANDIT]["blocking"] is True


def test_a_script_without_extension_is_scanned():
    def change(repo):
        write(repo, "bin/deploy", "#!/usr/bin/env python3\n" + PICKLE_SINK)
    code, rows = run_gate(make_repo({}, change))
    assert rows[SEMGREP]["blocking"] is True


def test_export_ignore_cannot_hide_a_failing_test():
    calc = "def add(a, b):\n    return a + b\n"
    test = ("from calc import add\n\n\ndef test_add():\n"
            "    assert add(2, 2) == 4\n")

    def change(repo):
        write(repo, "calc.py", "def add(a, b):\n    return a - b\n")
        write(repo, ".gitattributes", "tests/ export-ignore\n")
    code, rows = run_gate(make_repo(
        {"calc.py": calc, "tests/test_calc.py": test}, change))
    assert rows[PYTEST]["blocking"] is True
    assert code == 1


def test_binary_file_does_not_break_the_scan():
    def change(repo):
        write(repo, "assets/logo.bin", bytes(range(256)) * 8)
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    code, rows = run_gate(make_repo({}, change))
    assert rows[SEMGREP]["status"] == "TESTED"
    assert code == 0


def gate_checks_done(run_dir):
    """The gate's 'check' done events in the feed beside run_dir, by name."""
    feed_path = os.path.join(os.path.dirname(run_dir), "security-feed.jsonl")
    with open(feed_path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f]
    return {event["name"]: event for event in events
            if event.get("event") == "check" and event.get("stage") == "gate"
            and event.get("status") == "done"}


def test_each_gate_check_sends_its_number_of_new_findings():
    # pytest.ini changes test collection: an advisory, non-blocking finding;
    # the pickle sink is a blocking Semgrep finding
    def change(repo):
        write(repo, "pytest.ini", "[pytest]\naddopts = -q\n")
        write(repo, "lib/loader.py", PICKLE_SINK)
    _code, rows, run_dir = run_gate_with_dir(make_repo({}, change))
    done = gate_checks_done(run_dir)
    assert all(type(event["count"]) is int for event in done.values())
    advisory = done["Security tests in the diff"]
    assert advisory["count"] == 1
    assert advisory["blocking"] is False
    assert done["Secrets"]["count"] == 0
    # the count is the row's severity counts, summed
    assert done["Semgrep"]["blocking"] is True
    semgrep_total = sum(rows[SEMGREP]["severity_counts"].values())
    assert semgrep_total > 0
    assert done["Semgrep"]["count"] == semgrep_total


# an HTTP client with no delay and a browser User-Agent, and no host to
# fetch robots.txt from: the check stays off the network
HTTP_CLIENT = (
    "import requests\n"
    "\n"
    "\n"
    "def fetch(url):\n"
    # split, so the toolkit's own gate does not read this line as a
    # browser User-Agent
    "    headers = {'User-Agent': 'Mozilla/" "5.0 (X11; Linux x86_64)'}\n"
    "    return requests.get(url, headers=headers, timeout=10).text\n"
)


def test_http_hygiene_warnings_are_counted_as_low_findings():
    def change(repo):
        write(repo, "lib/fetch.py", HTTP_CLIENT)
    code, rows, run_dir = run_gate_with_dir(make_repo({}, change))
    assert code == 0
    http = rows["Outbound HTTP in the diff"]
    assert http["status"] == "TESTED"
    assert http["blocking"] is False
    assert http["severity"] == "low"
    # the file without a delay, and the User-Agent
    assert http["severity_counts"] == {"critical": 0, "high": 0,
                                       "medium": 0, "low": 2}
    assert gate_checks_done(run_dir)["Outbound HTTP"]["count"] == 2
    # the bottom line's advisory tally includes them ("Toolkit integrity"
    # adds one more while the toolkit has uncommitted changes)
    low_total = sum(row["severity_counts"]["low"] for row in rows.values()
                    if row["severity_counts"])
    with open(os.path.join(run_dir, "verdict.txt"), encoding="utf-8") as f:
        assert "no blocking findings (%d low, advisory)" % low_total \
            in f.readline()


def test_a_linked_worktree_reports_under_the_main_repository_name():
    def change(repo):
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    repo = make_repo({}, change)
    worktree = os.path.join(tempfile.mkdtemp(prefix="gate-test-"),
                            "other-worktree-name")
    git(repo, "worktree", "add", "-q", "--detach", worktree, "feature")
    home = tempfile.mkdtemp(prefix="gate-home-")
    environment = dict(os.environ, HOME=home)
    environment.pop("PREFLIGHT_REPORTS_DIR", None)
    result = subprocess.run([sys.executable, GATE, "check", worktree, "main"],
                            capture_output=True, text=True, env=environment)
    reports = os.path.join(home, "preflight-reports")
    main_name = os.path.basename(repo)
    assert os.listdir(reports) == [main_name], result.stdout + result.stderr
    folder = os.path.join(reports, main_name)
    feed_path = os.path.join(folder, "security-feed.jsonl")
    assert os.path.isfile(feed_path)
    assert "security feed: %s\n" % feed_path in result.stdout
    run_dirs = [name for name in os.listdir(folder)
                if os.path.isdir(os.path.join(folder, name))]
    assert len(run_dirs) == 1
