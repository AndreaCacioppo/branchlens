"""End-to-end tests for what the gate judges (the branch's commits, an empty
diff, uncommitted work and --worktree) and for how it protects the toolkit
from the repository's own test code."""

import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from helpers import TOOLKIT_DIR, git, make_repo, run_gate, write

FAKE_AWS_KEY = "AKIA" + "Z" * 16
PICKLE_SINK = ("import pickle\n\n\ndef load(data):\n"
               "    return pickle.loads(data)\n")
SECRETS = "Secrets in the diff"
SEMGREP = "Multi-language analysis (Semgrep)"
UNCOMMITTED = "Uncommitted changes"
TOOLKIT = "Toolkit integrity"
PYTEST = "Python tests (pytest)"

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None,
                                reason="semgrep is not installed")


def test_a_secret_removed_by_a_later_commit_still_blocks():
    def change(repo):
        write(repo, "config.py", "key = '%s'\n" % FAKE_AWS_KEY)
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "add key")
        write(repo, "config.py", "import os\nkey = os.environ['KEY']\n")
    code, rows, _run_dir = run_gate(make_repo({}, change))
    assert rows[SECRETS]["blocking"] is True
    assert "commit" in rows[SECRETS]["outcome"]
    assert code == 1


def test_an_empty_diff_is_not_a_pass():
    # a first publish: no remote, the base is the branch itself
    repo = tempfile.mkdtemp(prefix="gate-test-")
    git(repo, "init", "-q", "-b", "main")
    write(repo, "app.py", PICKLE_SINK)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "only commit")
    code, rows, _run_dir = run_gate(repo, base=None)
    assert rows[SEMGREP]["status"] == "NOT POSSIBLE"
    assert rows[SECRETS]["status"] == "NOT POSSIBLE"
    assert code == 2


def test_the_empty_tree_base_judges_a_first_publish():
    repo = tempfile.mkdtemp(prefix="gate-test-")
    git(repo, "init", "-q", "-b", "main")
    write(repo, "app.py", PICKLE_SINK)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "only commit")
    code, rows, _run_dir = run_gate(repo, base="empty-tree")
    assert rows[SEMGREP]["blocking"] is True
    assert code == 1


def test_a_secret_in_a_commit_message_blocks():
    def change(repo):
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    repo = make_repo({}, change)
    git(repo, "commit", "-q", "--allow-empty", "-m",
        "debugging, key was %s" % FAKE_AWS_KEY)
    code, rows, _run_dir = run_gate(repo)
    assert rows[SECRETS]["blocking"] is True
    assert "message" in rows[SECRETS]["outcome"]


def test_merging_the_base_does_not_report_its_secrets():
    repo = make_repo({}, lambda r: write(r, "feature.py", "X = 1\n"))
    git(repo, "checkout", "-q", "main")
    write(repo, "settings.py", "key = '%s'\n" % FAKE_AWS_KEY)  # on main
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main keeps a key")
    git(repo, "checkout", "-q", "feature")
    git(repo, "merge", "-q", "--no-edit", "main")
    code, rows, _run_dir = run_gate(repo)
    assert rows[SECRETS]["blocking"] is False


def test_uncommitted_work_makes_the_run_inconclusive():
    def change(repo):
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    repo = make_repo({}, change)
    write(repo, "lib/new.py", PICKLE_SINK)  # untracked
    code, rows, _run_dir = run_gate(repo)
    assert rows[UNCOMMITTED]["status"] == "NOT POSSIBLE"
    assert code == 2


def object_files(repo):
    count = 0
    for _root, _dirs, files in os.walk(os.path.join(repo, ".git",
                                                    "objects")):
        count += len(files)
    return count


def test_worktree_mode_judges_uncommitted_work_without_touching_git():
    def change(repo):
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    repo = make_repo({}, change)
    write(repo, "lib/util.py", "def add(a, b):\n    return a - b\n")
    write(repo, "lib/new.py", PICKLE_SINK)
    status_before = subprocess.run(
        ["git", "-C", repo, "status", "--porcelain"],
        capture_output=True, text=True).stdout
    objects_before = object_files(repo)
    code, rows, run_dir = run_gate(repo, extra_args=["--worktree"])
    assert rows[SEMGREP]["blocking"] is True        # the untracked sink
    assert rows[UNCOMMITTED]["status"] == "TESTED"
    assert rows["Gate self-check (read-only)"]["blocking"] is False
    assert code == 1
    status_after = subprocess.run(
        ["git", "-C", repo, "status", "--porcelain"],
        capture_output=True, text=True).stdout
    assert status_after == status_before
    assert object_files(repo) == objects_before
    with open(os.path.join(run_dir, "verdict.txt")) as f:
        assert "UNCOMMITTED working tree" in f.readline()


def copy_toolkit():
    copy = tempfile.mkdtemp(prefix="toolkit-copy-")
    shutil.copytree(os.path.join(TOOLKIT_DIR, "checks"),
                    os.path.join(copy, "checks"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(os.path.join(TOOLKIT_DIR, "preflight.sh"), copy)
    return copy


@pytest.mark.skipif(sys.platform != "darwin"
                    or shutil.which("sandbox-exec") is None,
                    reason="the sandbox is macOS-only")
def test_the_sandbox_keeps_the_tests_away_from_the_toolkit():
    toolkit = copy_toolkit()
    target = os.path.join(toolkit, "checks", "verdict.py")
    with open(target, "rb") as f:
        original = f.read()
    conftest = ("try:\n"
                "    with open(%r, 'a') as f:\n"
                "        f.write('# tampered\\n')\n"
                "except OSError:\n"
                "    pass\n" % target)

    def change(repo):
        write(repo, "conftest.py", conftest)
        write(repo, "tests/test_ok.py", "def test_ok():\n    assert True\n")
    code, rows, _run_dir = run_gate(
        make_repo({}, change), gate=os.path.join(toolkit, "checks",
                                                 "gate.py"),
        extra_env={"PREFLIGHT_SANDBOX": "1"})
    with open(target, "rb") as f:
        assert f.read() == original


def test_a_toolkit_changed_during_the_run_is_not_a_green():
    sys.path.insert(0, os.path.join(TOOLKIT_DIR, "checks"))
    import gate
    checker = gate.Gate("/nonexistent", "main")
    fingerprint = gate.toolkit_fingerprint()
    fingerprint["checks/verdict.py"] = "0" * 64   # "was different before"
    checker.check_toolkit_integrity(fingerprint, [])
    row = checker.rows[-1]
    assert row[0] == TOOLKIT and row[1] == "NOT POSSIBLE"


def test_leaving_security_tests_out_of_collection_blocks():
    def change(repo):
        write(repo, "conftest.py",
              "collect_ignore = ['tests/test_security_admin.py']\n")
    repo = make_repo({"tests/test_security_admin.py":
                      "def test_admin():\n    assert True\n"}, change)
    code, rows, _run_dir = run_gate(repo)
    assert rows["Security tests in the diff"]["blocking"] is True
    assert code == 1


def test_collecting_no_tests_from_existing_test_files_is_not_n_a():
    def change(repo):
        write(repo, "conftest.py",
              "collect_ignore = ['tests/test_security_admin.py']\n")
    repo = make_repo({"tests/test_security_admin.py":
                      "def test_admin():\n    assert True\n"}, change)
    code, rows, _run_dir = run_gate(repo)
    assert rows[PYTEST]["status"] == "NOT POSSIBLE"


SECURITY_TEST = "def test_admin_only():\n    assert is_admin('bob') is False\n"
ADMIN = "def is_admin(user):\n    return user == 'root'\n"
BROKEN_ADMIN = "def is_admin(user):\n    return True\n"


def security_fixture(conftest):
    """main: an admin check and its security test. feature: the check is
    broken and a conftest keeps the security test from running."""
    def change(repo):
        write(repo, "admin.py", BROKEN_ADMIN)
        write(repo, "conftest.py", conftest)
        write(repo, "tests/test_other.py", "def test_ok():\n    assert True\n")
    return make_repo({"admin.py": ADMIN,
                      "tests/test_security_admin.py":
                      "from admin import is_admin\n\n\n" + SECURITY_TEST},
                     change)


def test_a_security_test_that_never_ran_is_named():
    conftest = ("collect_ignore = [\n"
                "    'tests/test_security_admin.py',\n"
                "]\n")
    code, rows, _run_dir = run_gate(security_fixture(conftest))
    assert rows["Python security tests"]["status"] == "NOT POSSIBLE"
    assert "test_security_admin" in rows["Python security tests"]["reason"]


def test_a_security_test_skipped_at_import_is_not_never_ran():
    def change(repo):
        write(repo, "tests/test_security_admin.py",
              "import pytest\npytest.importorskip('module_that_is_absent')\n"
              "\n\ndef test_admin():\n    assert True\n")
    code, rows, _run_dir = run_gate(make_repo(
        {"tests/test_security_admin.py": "def test_admin():\n    assert True\n"},
        change))
    assert rows["Python security tests"]["status"] == "TESTED"
