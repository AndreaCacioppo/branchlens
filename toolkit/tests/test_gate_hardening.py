"""End-to-end tests for the gate's defences against the repository it
judges: objects swapped by replace refs, planted bytecode, repository code
run from the launch directory, and writes from the repository's tests."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from helpers import TOOLKIT_DIR, git, make_repo, run_gate, write

SEMGREP = "Multi-language analysis (Semgrep)"
SAFE = "import json\n\n\ndef load(data):\n    return json.loads(data)\n"
SINK = "import pickle\n\n\ndef load(data):\n    return pickle.loads(data)\n"

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None,
                                reason="semgrep is not installed")


def copy_toolkit():
    copy = tempfile.mkdtemp(prefix="toolkit-copy-")
    shutil.copytree(os.path.join(TOOLKIT_DIR, "checks"),
                    os.path.join(copy, "checks"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(os.path.join(TOOLKIT_DIR, "preflight.sh"), copy)
    return copy


def blob_id(repo, spec):
    return subprocess.run(["git", "-C", repo, "rev-parse", spec],
                          capture_output=True, text=True).stdout.strip()


def test_a_replace_ref_cannot_swap_the_committed_code():
    def change(repo):
        write(repo, "lib/loader.py", SINK)
    repo = make_repo({"lib/loader.py": SAFE}, change)
    # make every git reader see the safe content instead of the sink
    git(repo, "replace", blob_id(repo, "HEAD:lib/loader.py"),
        blob_id(repo, "main:lib/loader.py"))
    code, rows, _run_dir = run_gate(repo)
    assert rows[SEMGREP]["blocking"] is True
    assert code == 1


def test_planted_bytecode_is_never_loaded():
    toolkit = copy_toolkit()
    feed_source = os.path.join(toolkit, "checks", "feed.py")
    # a .pyc whose header matches feed.py, but whose code exits with 99
    external = importlib.util.module_from_spec(
        importlib.util.find_spec("importlib._bootstrap_external"))
    importlib.util.find_spec("importlib._bootstrap_external").loader \
        .exec_module(external)
    stat = os.stat(feed_source)
    code_object = compile("raise SystemExit(99)", feed_source, "exec")
    pyc = external._code_to_timestamp_pyc(code_object, int(stat.st_mtime),
                                          stat.st_size)
    target = importlib.util.cache_from_source(feed_source)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as f:
        f.write(pyc)

    def change(repo):
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    code, rows, _run_dir = run_gate(
        make_repo({}, change), gate=os.path.join(toolkit, "checks",
                                                 "gate.py"))
    assert code == 0


def test_launching_from_inside_the_repository_runs_none_of_its_code():
    # a pytest.py at the repository root would shadow pytest for any
    # `python -m pytest --version` started from that directory
    marker = os.path.join(tempfile.mkdtemp(prefix="marker-"), "probe.txt")
    shadow = ("import sys\n"
              "if '--version' in sys.argv:\n"
              "    with open(%r, 'a') as f:\n"
              "        f.write('shadow pytest answered the version probe\\n')\n"
              % marker)

    def change(repo):
        write(repo, "pytest.py", shadow)
        write(repo, "tests/test_ok.py", "def test_ok():\n    assert True\n")
    repo = make_repo({}, change)
    run_gate(repo, cwd=repo)
    assert not os.path.exists(marker)


@pytest.mark.skipif(sys.platform != "darwin"
                    or shutil.which("sandbox-exec") is None,
                    reason="the sandbox is macOS-only")
def test_the_repository_tests_can_only_write_temporary_files():
    home_probe = os.path.expanduser("~/.preflight-sandbox-probe")
    temp_probe = os.path.join(tempfile.gettempdir(), "preflight-temp-probe")
    for path in (home_probe, temp_probe):
        if os.path.exists(path):
            os.remove(path)
    test = ("def test_writes():\n"
            "    for path in (%r, %r):\n"
            "        try:\n"
            "            open(path, 'w').close()\n"
            "        except OSError:\n"
            "            pass\n" % (home_probe, temp_probe))

    def change(repo):
        write(repo, "tests/test_writes.py", test)
    run_gate(make_repo({}, change), extra_env={"PREFLIGHT_SANDBOX": "1"})
    try:
        assert not os.path.exists(home_probe)
        assert os.path.exists(temp_probe)
    finally:
        for path in (home_probe, temp_probe):
            if os.path.exists(path):
                os.remove(path)


def plumbing(repo, *args, data=None):
    """A git plumbing command; args may be bytes (for raw file names)."""
    result = subprocess.run(["git", "-C", repo] + list(args), input=data,
                            capture_output=True, check=True)
    return result.stdout.decode("utf-8", "replace").strip()


def commit_tree_entries(repo, entries, message="feature"):
    """Commits a tree made of (mode, name bytes, content bytes) entries on
    top of HEAD, bypassing the checks porcelain applies to file names."""
    raw = b""
    for mode, name, content in entries:
        blob = plumbing(repo, "hash-object", "-w", "--stdin", data=content)
        raw += mode + b" " + name + b"\0" + bytes.fromhex(blob)
    tree = plumbing(repo, "hash-object", "-w", "-t", "tree", "--literally",
                    "--stdin", data=raw)
    commit = plumbing(repo, "-c", "user.name=t", "-c", "user.email=t@t",
                      "commit-tree", tree, "-p", "HEAD", "-m", message)
    plumbing(repo, "update-ref", "HEAD", commit)
    # bring the working tree to HEAD; a name the file system refuses (not
    # UTF-8 on APFS) leaves it behind, which only the blocking tests allow
    try:
        plumbing(repo, "reset", "-q", "--hard")
    except subprocess.CalledProcessError:
        plumbing(repo, "reset", "-q")


def base_repo():
    repo = tempfile.mkdtemp(prefix="gate-test-")
    git(repo, "init", "-q", "-b", "main")
    write(repo, "README.md", "fixture\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main")
    git(repo, "checkout", "-qb", "feature")
    return repo


def test_file_names_git_can_hold_are_all_scanned():
    repo = base_repo()
    commit_tree_entries(repo, [
        (b"100644", b"README.md", b"fixture\n"),
        (b"100644", b"new\nline.py", SINK.encode()),
    ])
    code, rows, _run_dir = run_gate(repo)
    assert rows[SEMGREP]["blocking"] is True
    assert code == 1


def test_a_file_name_that_is_not_utf8_is_scanned():
    repo = base_repo()
    commit_tree_entries(repo, [
        (b"100644", b"README.md", b"fixture\n"),
        (b"100644", b"caf\xe9.py", SINK.encode()),
    ])
    code, rows, _run_dir = run_gate(repo)
    assert rows[SEMGREP]["blocking"] is True


def test_a_symlink_named_like_code_is_not_scanned_as_code():
    repo = base_repo()
    commit_tree_entries(repo, [
        (b"100644", b"README.md", b"fixture\n"),
        (b"120000", b"src/alias.py", b"../README.md"),
    ])
    code, rows, _run_dir = run_gate(repo)
    assert rows[SEMGREP]["status"] == "TESTED"
    assert code == 0


def test_the_export_never_writes_outside_its_directory():
    repo = base_repo()
    # the export sits in <tmp>/preflight-scan-*/scan: two '..' levels from
    # there reach <tmp> itself
    outside = os.path.join(tempfile.gettempdir(), "escaped-by-export.txt")
    if os.path.exists(outside):
        os.remove(outside)
    blob = plumbing(repo, "hash-object", "-w", "--stdin", data=b"escaped\n")
    level2 = plumbing(repo, "hash-object", "-w", "-t", "tree", "--literally",
                      "--stdin", data=b"100644 escaped-by-export.txt\0"
                      + bytes.fromhex(blob))
    level1 = plumbing(repo, "hash-object", "-w", "-t", "tree", "--literally",
                      "--stdin", data=b"40000 ..\0" + bytes.fromhex(level2))
    test_blob = plumbing(repo, "hash-object", "-w", "--stdin",
                         data=b"def test_ok():\n    assert True\n")
    root = plumbing(repo, "hash-object", "-w", "-t", "tree", "--literally",
                    "--stdin", data=b"40000 ..\0" + bytes.fromhex(level1)
                    + b"100644 test_ok.py\0" + bytes.fromhex(test_blob))
    commit = plumbing(repo, "-c", "user.name=t", "-c", "user.email=t@t",
                      "commit-tree", root, "-p", "HEAD", "-m", "escape")
    plumbing(repo, "update-ref", "HEAD", commit)
    try:
        run_gate(repo)
        assert not os.path.exists(outside)
    finally:
        if os.path.exists(outside):
            os.remove(outside)


def test_a_submodule_move_hidden_by_gitmodules_is_still_judged():
    # 'ignore = all' in a tracked .gitmodules makes plain git diff and git
    # status skip the submodule, but a push still sends its new commit
    def change(repo):
        submodule = os.path.join(repo, "lib")
        os.makedirs(submodule)
        git(submodule, "init", "-q")
        write(submodule, "inner.txt", "inner\n")
        git(submodule, "add", "-A")
        git(submodule, "commit", "-qm", "inner")
    gitmodules = ('[submodule "lib"]\n\tpath = lib\n\turl = ./lib\n'
                  '\tignore = all\n')
    repo = make_repo({".gitmodules": gitmodules}, change)
    _code, _rows, run_dir = run_gate(repo)
    with open(os.path.join(run_dir, "diff.patch"), encoding="utf-8") as f:
        assert "+Subproject commit " in f.read()
    with open(os.path.join(run_dir, "review-scope.json"),
              encoding="utf-8") as f:
        touched = [entry["path"] for entry in json.load(f)["touched_files"]]
    assert "lib" in touched
