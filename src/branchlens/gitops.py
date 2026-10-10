"""Git backend for BranchLens.

All git subprocess calls and output parsing live here. Everything is read-only
towards the inspected repository: only whitelisted git subcommands are
allowed, subprocesses never go through a shell, and '--' always separates
revisions from path arguments. git itself may still rewrite .git/index when a
diff against a working tree refreshes the file timestamps cached there.
"""

import ast
import bisect
import concurrent.futures
import hashlib
import os
import posixpath
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import warnings

# The only git subcommands this tool is ever allowed to run (all read-only).
GIT_SUBCOMMAND_WHITELIST = {
    "rev-parse",
    "symbolic-ref",
    "for-each-ref",
    "merge-base",
    "diff",
    "status",
    "worktree",
    "ls-files",
    "rev-list",
    "log",
    "show",
    # ls-tree: lists the blobs of one commit's tree. It has no write mode and
    # runs no program named in the inspected repository's config.
    "ls-tree",
    # config: only ever run read-only here (--list), to inspect the repo's own config
    "config",
    # remote: only 'remote get-url', which prints where a remote points
    "remote",
}

MAX_PATCH_CHARS = 500000

# At most this many git commands of one request run side by side.
MAX_PARALLEL_GIT = 8

# Every git call that reads the repository is stopped after this many seconds.
# A repository that arrived as a copy or an archive can hold a FIFO (a named
# pipe) where git expects a file: .gitignore, .gitattributes, .mailmap, or a
# config file named by include.path. git then waits on it forever. The Run
# button's pipeline and Push have their own limits (server.py, publish.py).
# The page gives up on a poll long before this, so a stopped command is
# remembered (see GitChild) and the next request gets its error at once.
GIT_TIMEOUT_SECONDS = 60

# Config overrides that stop the inspected repository from running a program.
# git runs programs its config names even for a read: a filesystem monitor
# (core.fsmonitor), content filters (filter.<name>.clean runs when git reads a
# working-tree file to diff it), the signature checker (gpg.program, run by
# log and show when log.showSignature is on), and hooks (post-index-change
# runs when 'git diff' refreshes stale timestamps in the index). The hooks
# directory becomes /dev/null, which holds no hook. diff.submodule=short stops
# git from diffing inside a submodule with a child git that would run the
# submodule's own diff drivers.
#
# The overrides travel as GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n /
# GIT_CONFIG_VALUE_n environment variables, not as "-c key=value". git splits
# a "-c" argument at the first "=", and a repository can name a filter
# [filter "a=b"]: "-c filter.a=b.clean=" would set the unrelated key
# "filter.a". The environment form keeps key and value apart. Both forms take
# precedence over the repository's own config.
#
# One repository per process, so one module-level list.
# configure_repo_hardening() fills it in when the repository is opened, and
# again on every get_state() and before every branch diff (the routes that run
# git inside a working tree, where filters run).
_BASE_HARDENING_OVERRIDES = [
    ("core.fsmonitor", "false"),
    ("log.showSignature", "false"),
    ("core.hooksPath", os.devnull),
    ("diff.submodule", "short"),
    # Files git opens because config names them. Any of them can be a FIFO,
    # and git would wait on it until the timeout. The cost: the user's own
    # global ignore and attributes files are not read either.
    ("core.excludesFile", os.devnull),
    ("core.attributesFile", os.devnull),
    ("mailmap.file", os.devnull),
]
_HARDENING_OVERRIDES = list(_BASE_HARDENING_OVERRIDES)

# A repository can name any number of filter programs. Past this many the
# repository is refused, never opened with some of them still live.
MAX_HARDENING_OVERRIDES = 1000

# Config is scanned in the root, every worktree and every initialised
# submodule, recursively. Past this many places the repository is refused.
MAX_HARDENING_SCAN_PATHS = 200

# Untracked files are counted in Python with git's rules: a NUL byte in the
# first 8000 bytes means binary, as does a file over 512 MiB (git's default
# core.bigFileThreshold).
UNTRACKED_BINARY_PROBE_BYTES = 8000
MAX_UNTRACKED_FILE_BYTES = 512 * 1024 * 1024

# The commit graph shows at most this many commits; the same listing is the
# only population of commit ids the HTTP API will ever accept.
GRAPH_COMMIT_LIMIT = 150

# Commit subjects are cut to this length inside explanation sentences.
MAX_SUBJECT_CHARS = 60

# A commit message is cut to this length before it travels inside a JSON
# response; nothing stops one from being megabytes long.
MAX_MESSAGE_CHARS = 20000

# --- Dependency network limits (/api/network) ---
# Each cap that fires is reported in the response.
# The tree listing stops after this many entries; the caps below only bound
# what is parsed.
NETWORK_MAX_TREE_ENTRIES = 50000
NETWORK_MAX_SOURCE_FILES = 1500
NETWORK_MAX_FILE_BYTES = 400000
NETWORK_MAX_CONTENT_BYTES = 32000000
NETWORK_MAX_NODES = 3000
NETWORK_MAX_EDGES = 8000
NETWORK_MAX_SYMBOLS_PER_EDGE = 25
NETWORK_MAX_UNRESOLVED_GROUPS = 200
NETWORK_MAX_SKIPPED_ENTRIES = 500
NETWORK_MAX_CLAUSE_CHARS = 400
# The 'import <clause> from' regex reads a clause of up to
# NETWORK_MAX_CLAUSE_CHARS. A longer one (a barrel import of dozens of names,
# or a blank line inside its braces) is found by walking backwards from the
# specifier, at most this many characters.
NETWORK_MAX_LONG_CLAUSE_CHARS = 20000
# The backward walks of one file stop after this many steps in all, about a
# quarter of a second, and the whole file is drawn as not read ("too complex
# to read"). In a file of from''from''... every literal starts a walk over all
# the ones before it.
NETWORK_MAX_WALK_STEPS_PER_FILE = 100 * NETWORK_MAX_LONG_CLAUSE_CHARS
NETWORK_TOO_COMPLEX_REASON = "too complex to read"
NETWORK_MAX_LINES_PER_EDGE = 20
# One 'git show' can print many blobs back to back; these bound one batch's
# command line and peak memory.
NETWORK_READ_BATCH_FILES = 200
NETWORK_READ_BATCH_BYTES = 8000000
# Finished networks kept per commit sha; responses can be megabytes.
NETWORK_CACHE_ENTRIES = 8

# Which files become nodes, and how each is read. A file whose extension is in
# none of these tables is not source code and is not shown at all.
PYTHON_EXTENSIONS = (".py", ".pyi")
JAVASCRIPT_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")
TYPESCRIPT_EXTENSIONS = (".ts", ".tsx", ".mts", ".cts")
JAVA_EXTENSIONS = (".java",)
# Recognised as code, never parsed: its own imports are unknown, but files
# that were read can still have arrows into it. .vue and .svelte are here:
# reading their script block as plain JavaScript would be a guess.
UNSUPPORTED_CODE_EXTENSIONS = (
    ".go", ".rs", ".kt", ".scala", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".cs", ".rb", ".php", ".swift", ".sh", ".bash", ".sql", ".vue", ".svelte",
    ".m", ".mm", ".pl", ".lua", ".r", ".jl",
)


class GitError(Exception):
    """A git operation failed; the message is safe to show to the user."""


class BranchNotFound(GitError):
    """The requested branch does not exist in the repository."""


class FileNotInDiff(GitError):
    """The requested file is not part of the branch's change list."""


class CommitNotInGraph(GitError):
    """The requested commit id is not in the graph's commit listing."""


class FileTooComplex(Exception):
    """Reading one source file's imports ran past its step budget."""


def build_git_command(args, cwd):
    """The exact argv one whitelisted git call runs as."""
    subcommand = args[0]
    if subcommand not in GIT_SUBCOMMAND_WHITELIST:
        raise GitError(f"Refusing to run git subcommand '{subcommand}': not whitelisted.")
    check_read_only_form(args)
    # --no-optional-locks: without it 'git status' rewrites .git/index under
    # .git/index.lock, and a concurrent 'git add' or 'git commit' can fail.
    # 'git diff' against a working tree still refreshes the timestamps
    # cached in .git/index.
    command = ["git", "--no-optional-locks"]
    if cwd is not None:
        command.extend(["-C", cwd])
    if subcommand in ("diff", "show"):
        # The inspected repository's own config may define textconv filters
        # or external diff drivers, which git runs as shell commands. These
        # flags keep every diff internal (git show also produces diffs), so
        # viewing an untrusted repository can never execute code from it.
        # --no-color: color.diff=always in any config would put terminal
        # codes into the patch text. --submodule=short: with
        # diff.submodule=diff, git diffs inside a submodule with a child git
        # that ignores the flags above. --ignore-submodules=none: an
        # 'ignore = all' in the repository's own .gitmodules would hide a
        # submodule's move from the page, while a push still sends it.
        command.extend(
            [subcommand, "--no-ext-diff", "--no-textconv", "--no-color", "--submodule=short",
             "--ignore-submodules=none"]
        )
        command.extend(args[1:])
    elif subcommand == "status":
        # The same 'ignore = all' hides a submodule's uncommitted move.
        command.extend(["status", "--ignore-submodules=none"])
        command.extend(args[1:])
    else:
        command.extend(args)
    return command


def check_read_only_form(args):
    """Refuse the writing forms of 'config', 'worktree', 'symbolic-ref' and
    'remote', and the --output option of 'diff', 'show' and 'log'.

    Only the exact read-only shapes this module uses pass.
    """
    subcommand = args[0]
    rest = args[1:]
    if subcommand in ("diff", "show", "log"):
        # --output=<file> writes the result to a file. Arguments after '--'
        # are paths, never options.
        for argument in rest:
            if argument == "--":
                break
            if argument == "--output" or argument.startswith("--output="):
                raise GitError(f"Refusing to run git {subcommand} with --output, which writes a file.")
    elif subcommand == "config":
        is_listing = rest == ["--name-only", "--list"]
        is_single_get = len(rest) == 2 and rest[0] == "--get"
        if not is_listing and not is_single_get:
            raise GitError("Refusing to run git config in a form that could write.")
    elif subcommand == "worktree":
        if len(rest) == 0 or rest[0] != "list":
            raise GitError("Refusing to run git worktree in a form that could write.")
    elif subcommand == "symbolic-ref":
        if len(rest) != 1 or rest[0].startswith("-"):
            raise GitError("Refusing to run git symbolic-ref in a form that could write.")
    elif subcommand == "remote":
        # Only 'remote get-url --all [--push] <name>'; 'remote update' fetches.
        is_get_url = (
            len(rest) in (3, 4)
            and rest[:2] == ["get-url", "--all"]
            and (len(rest) == 3 or rest[2] == "--push")
            and not rest[-1].startswith("-")
        )
        if not is_get_url:
            raise GitError("Refusing to run git remote in a form that could write.")


def run_git_exit_code(args, cwd=None):
    """The exit code of one whitelisted git call, for the commands that answer
    with it rather than with output ('merge-base --is-ancestor')."""
    git_child = GitChild(
        args, cwd, hardening_environment(), subprocess.DEVNULL, subprocess.DEVNULL,
    )
    git_child.finish()
    git_child.raise_if_timed_out()
    return git_child.process.returncode


def check_git_result(subcommand, returncode, stdout, stderr, allow_exit_code_1):
    """Raise GitError unless git's exit code means success for this command.

    Exit code 0 is success. For 'diff', exit code 1 is also success: git diff
    exits with 1 when the compared contents differ (notably with --no-index),
    unless it printed nothing and complained on stderr ("Could not access").
    Callers can also pass allow_exit_code_1=True for commands like
    'merge-base', where exit code 1 is a meaningful "no result" answer.
    """
    stderr_text = stderr.decode("utf-8", errors="replace").strip()
    if subcommand == "diff" or allow_exit_code_1:
        allowed_exit_codes = (0, 1)
    else:
        allowed_exit_codes = (0,)
    failed_diff = subcommand == "diff" and returncode == 1 and stdout == b"" and stderr_text != ""
    if returncode in allowed_exit_codes and not failed_diff:
        return
    if "lazy fetching disabled" in stderr_text or "from promisor remote" in stderr_text:
        # A partial clone is missing this content; git's own wording
        # names an internal switch.
        raise GitError(
            "This content is not on disk: the repository is a partial "
            "clone and BranchLens never fetches. Run 'git fetch' or view "
            "it after a full checkout."
        )
    raise GitError(f"git {subcommand} failed: {stderr_text}")


# The git children running now, so that the server can stop them all when it
# exits. Each one runs in its own process group (see GitChild), which also
# means a Ctrl+C in the terminal no longer reaches it on its own.
_RUNNING_GIT_CHILDREN = set()
_RUNNING_GIT_LOCK = threading.Lock()

# When each command was last stopped for time, by (directory, subcommand).
# For GIT_TIMEOUT_SECONDS after a stop, and while a later try of the same
# command is still running, that command fails at once with the same error,
# a different 'git diff' in the same directory included. The page gives up on
# a poll after 8 s, so this is how it sees the error, and no poll leaves
# another git waiting. A caller can pass its own timeout_key in place of the
# subcommand: the one-call ahead/behind count does, so its timeout leaves the
# branch list's for-each-ref running.
_LAST_TIMEOUT_BY_KEY = {}


def timeout_error(subcommand):
    return GitError(
        f"git did not answer within {GIT_TIMEOUT_SECONDS} s on "
        f"'git {subcommand}' and was stopped. A file it reads may be a "
        "named pipe, or on a disk that does not respond."
    )


class GitChild:
    """One git process in a process group of its own, stopped when time is up.

    The group matters: git can start git processes of its own (git status
    asks every submodule), and killing only the first one would leave the
    others running and holding the output pipe open. A timer kills the whole
    group after GIT_TIMEOUT_SECONDS. Killing it closes the pipes, so a
    caller that is reading the output gets an end of file and finishes.

    Raises GitError at once, without starting git, while the same command
    in the same directory has recently timed out (see _LAST_TIMEOUT_BY_KEY).
    """

    def __init__(self, args, cwd, environment, stdout, stderr, timeout_key=None):
        self.args = args
        self.timed_out = False
        command = build_git_command(args, cwd)
        self.key = (cwd, timeout_key or args[0])
        with _RUNNING_GIT_LOCK:
            last_timeout = _LAST_TIMEOUT_BY_KEY.get(self.key)
            if last_timeout is not None:
                recent = time.monotonic() - last_timeout < GIT_TIMEOUT_SECONDS
                if recent or self.same_command_is_running():
                    raise timeout_error(args[0])
        self.process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            env=environment, start_new_session=True,
        )
        with _RUNNING_GIT_LOCK:
            _RUNNING_GIT_CHILDREN.add(self)
        self.timer = threading.Timer(GIT_TIMEOUT_SECONDS, self.stop_for_time)
        self.timer.daemon = True
        self.timer.start()

    def same_command_is_running(self):
        """Called with _RUNNING_GIT_LOCK held."""
        for git_child in _RUNNING_GIT_CHILDREN:
            if git_child.key == self.key:
                return True
        return False

    def stop_for_time(self):
        self.timed_out = True
        # Recorded here: the request that started this git may be long gone.
        with _RUNNING_GIT_LOCK:
            _LAST_TIMEOUT_BY_KEY[self.key] = time.monotonic()
        self.kill_group()

    def kill_group(self):
        # A finished and reaped git has no group left, and its number could
        # already belong to another process.
        if self.process.returncode is not None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def finish(self):
        """Wait for git to exit, then stop the timer."""
        self.process.wait()
        self.timer.cancel()
        with _RUNNING_GIT_LOCK:
            _RUNNING_GIT_CHILDREN.discard(self)
            if not self.timed_out:
                # It answered: the next call runs git again.
                _LAST_TIMEOUT_BY_KEY.pop(self.key, None)

    def raise_if_timed_out(self):
        if self.timed_out:
            raise timeout_error(self.args[0])


def stop_running_git():
    """Kill every git child still running. The server calls this on exit."""
    with _RUNNING_GIT_LOCK:
        children = list(_RUNNING_GIT_CHILDREN)
    for git_child in children:
        git_child.kill_group()


def run_git(args, cwd=None, allow_exit_code_1=False, timeout_key=None):
    """Run one whitelisted git command and return its stdout as raw bytes.

    check_git_result() decides which exit codes count as success; any other
    raises GitError with git's stderr included, and so does a git that ran
    past GIT_TIMEOUT_SECONDS. git never reads the server's stdin: 'diff
    --no-index' would read it for a file named '-'. timeout_key: see
    _LAST_TIMEOUT_BY_KEY.
    """
    git_child = GitChild(
        args, cwd, hardening_environment(), subprocess.PIPE, subprocess.PIPE,
        timeout_key=timeout_key,
    )
    try:
        stdout, stderr = git_child.process.communicate()
    finally:
        git_child.finish()
    git_child.raise_if_timed_out()
    check_git_result(args[0], git_child.process.returncode, stdout, stderr, allow_exit_code_1)
    return stdout


def run_git_text(args, cwd=None, allow_exit_code_1=False):
    """Like run_git, but decode stdout to text (NUL bytes survive decoding)."""
    raw = run_git(args, cwd=cwd, allow_exit_code_1=allow_exit_code_1)
    return raw.decode("utf-8", errors="replace")


def run_git_text_limited(args, cwd, max_bytes=4 * MAX_PATCH_CHARS):
    """Like run_git_text, but read at most max_bytes of git's output.

    Returns (text, output_was_cut). Past the limit git is stopped, and its
    exit code is no longer checked. 4 bytes per character always leave room
    for MAX_PATCH_CHARS characters of UTF-8.
    """
    chunks = []
    total_bytes = 0
    output_was_cut = False
    # stderr goes to a file so that git can never block on a full pipe.
    with tempfile.TemporaryFile() as stderr_file:
        git_child = GitChild(args, cwd, hardening_environment(), subprocess.PIPE, stderr_file)
        process = git_child.process
        try:
            while True:
                chunk = process.stdout.read(64 * 1024)
                if chunk == b"":
                    break
                chunks.append(chunk)
                total_bytes += len(chunk)
                if total_bytes >= max_bytes:
                    output_was_cut = True
                    git_child.kill_group()
                    break
            process.stdout.close()
        finally:
            git_child.finish()
        # Output that reached the limit is kept even if the timer fired too.
        if not output_was_cut:
            git_child.raise_if_timed_out()
        returncode = process.returncode
        stdout = b"".join(chunks)[:max_bytes]
        if not output_was_cut:
            stderr_file.seek(0)
            stderr = stderr_file.read(64 * 1024)
            check_git_result(args[0], returncode, stdout, stderr, False)
    return stdout.decode("utf-8", errors="replace"), output_was_cut


def run_side_by_side(function, items):
    """function(item) for every item, run in parallel threads.

    The results come back in the order of items.
    """
    if len(items) <= 1:
        results = []
        for item in items:
            results.append(function(item))
        return results
    worker_count = min(MAX_PARALLEL_GIT, len(items))
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
        return list(pool.map(function, items))


def run_git_side_by_side(commands, cwd):
    """run_git() for each argument list, in parallel; outputs in the same order."""
    def run_one(args):
        return run_git(args, cwd=cwd)
    return run_side_by_side(run_one, commands)


# Inherited variables that point git at another repository, index or object
# store, change how pathspecs match, or add config that beats the overrides.
INHERITED_GIT_VARIABLES_TO_DROP = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
)


def hardening_environment():
    """The environment every git subprocess runs in.

    Carries the config overrides as GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n /
    GIT_CONFIG_VALUE_n. Any of those variables inherited from the parent
    process are replaced, and the ones in INHERITED_GIT_VARIABLES_TO_DROP
    are removed, so the launching environment can neither add config nor
    point git at another repository.
    """
    environment = dict(os.environ)
    strip_config_overrides(environment)
    overrides = _HARDENING_OVERRIDES  # read once; the list is replaced whole
    environment["GIT_CONFIG_COUNT"] = str(len(overrides))
    for index, override in enumerate(overrides):
        environment["GIT_CONFIG_KEY_" + str(index)] = override[0]
        environment["GIT_CONFIG_VALUE_" + str(index)] = override[1]
    # Stops a partial clone from fetching missing objects mid-command
    # (git 2.45 and newer).
    environment["GIT_NO_LAZY_FETCH"] = "1"
    # No transport is allowed, so on an older git a lazy fetch fails too.
    environment["GIT_ALLOW_PROTOCOL"] = "none"
    # git's messages in English, as the sentences that quote them.
    environment["LANGUAGE"] = "en"
    return environment


def strip_config_overrides(environment):
    """Drop inherited GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n variables and
    every name in INHERITED_GIT_VARIABLES_TO_DROP."""
    for name in list(environment):
        if name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            del environment[name]
        elif name in INHERITED_GIT_VARIABLES_TO_DROP:
            del environment[name]


def verify_config_overrides_work(repo_root):
    """Raise unless this git honours GIT_CONFIG_COUNT overrides (git 2.31+).

    Every protection here rides on them, and an older git ignores them
    silently. A throwaway key with a random value is pushed through and
    read back.
    """
    probe_value = "probe-" + os.urandom(8).hex()
    environment = dict(os.environ)
    strip_config_overrides(environment)
    environment["GIT_CONFIG_COUNT"] = "1"
    environment["GIT_CONFIG_KEY_0"] = "branchlens.probe"
    environment["GIT_CONFIG_VALUE_0"] = probe_value
    args = ["config", "--get", "branchlens.probe"]
    git_child = GitChild(
        args, repo_root, environment, subprocess.PIPE, subprocess.PIPE,
    )
    try:
        stdout, _stderr = git_child.process.communicate()
    finally:
        git_child.finish()
    git_child.raise_if_timed_out()
    if stdout.decode("utf-8", errors="replace").strip() != probe_value:
        raise GitError(
            "this git ignores GIT_CONFIG_COUNT overrides, so BranchLens could "
            "not stop the repository from running programs. git 2.31 or newer "
            "is needed."
        )


def list_config_names(path):
    """Every config key git resolves at 'path'.

    The listing has no scope flag. With '--local', git follows no
    'include.path' and skips '.git/config.worktree', so a filter named
    there would be missed. Without a scope it lists every key git resolves
    at this path, includes and worktree config among them.
    """
    try:
        text = run_git_text(["config", "--name-only", "--list"], cwd=path)
    except GitError:
        return []
    names = []
    for name in text.split("\n"):
        name = name.strip()
        if name != "":
            names.append(name)
    return names


def filter_program_names(config_names):
    """The filter.<name>.clean/smudge/process keys among config names."""
    found = []
    for name in config_names:
        if not name.startswith("filter."):
            continue
        if name.rsplit(".", 1)[-1] in ("clean", "smudge", "process"):
            found.append(name)
    return found


def list_filter_config_names(path):
    """Every filter.<name>.clean/smudge/process key git resolves at 'path'."""
    return filter_program_names(list_config_names(path))


def list_initialised_submodules(worktree_path):
    """Directories of the submodules git recurses into from this worktree.

    A gitlink (mode 160000 in the index) whose directory holds a '.git'
    entry. 'status' and 'diff' step into every such directory, configured as
    a submodule or not, and the child git they run there reads that
    repository's own config.
    """
    try:
        raw = run_git(["ls-files", "--stage", "-z"], cwd=worktree_path)
    except GitError:
        return []
    found = []
    # Split as bytes: only the few gitlink records are decoded.
    for record in raw.split(b"\x00"):
        # "<mode> <object> <stage>\t<path>"
        if not record.startswith(b"160000 ") or b"\t" not in record:
            continue
        # surrogateescape keeps a name that is not valid UTF-8 usable as a path.
        relative_path = record.split(b"\t", 1)[1].decode("utf-8", errors="surrogateescape")
        absolute_path = os.path.join(worktree_path, relative_path)
        if os.path.exists(os.path.join(absolute_path, ".git")):
            found.append(os.path.realpath(absolute_path))
    return found


def refuse_redirected_worktree(path):
    """Raise unless core.worktree, set in the config at 'path', points at 'path'.

    A submodule's own config names its checkout this way. Any other target
    would make git diff and list files outside the repository.
    """
    try:
        toplevel = run_git_text(["rev-parse", "--show-toplevel"], cwd=path).strip()
    except GitError:
        toplevel = ""
    if toplevel == "" or os.path.realpath(toplevel) != os.path.realpath(path):
        raise GitError(
            f"'{path}' sets core.worktree to another directory, so git would "
            f"read files outside the repository. Refusing to open it."
        )


def scan_one_place(path):
    """(config key names, initialised submodule directories) at one place.

    Raises GitError when the place's core.worktree points elsewhere.
    """
    config_names = list_config_names(path)
    if "core.worktree" in config_names:
        refuse_redirected_worktree(path)
    return config_names, list_initialised_submodules(path)


def configure_repo_hardening(repo_root, worktree_paths=None):
    """Build the config overrides that stop the inspected repo running programs.

    The base overrides (fsmonitor, signature checks, hooks, submodule
    diffs) apply to every repo. Each content filter the repo resolves is
    added blank: filter.<name>.clean/smudge/process name programs git would
    run, and an empty value turns filtering off (Git LFS content then shows
    as its pointer text). The same filter's filter.<name>.required is set to
    false.

    The root, every worktree and every initialised submodule are scanned,
    recursively. A linked worktree's '.git/worktrees/<name>/config.worktree'
    applies only while git runs inside that worktree, and 'git status' and
    'git diff' do run there. Past MAX_HARDENING_SCAN_PATHS places the
    repository is refused, and so is a place whose core.worktree sends git
    to another directory.

    The module-level list is replaced in one step at the end: other threads
    keep the previous list during the scan, and a refused repository leaves
    it in place.

    worktree_paths, when given, is the listing get_state() already fetched.
    """
    global _HARDENING_OVERRIDES
    if worktree_paths is None:
        try:
            branch_to_worktree, worktree_paths, worktree_raw = get_worktrees(repo_root)
        except GitError:
            worktree_paths = []  # a bare or half-built repo still gets the base overrides
    scan_paths = [repo_root]
    for worktree_path in worktree_paths:
        if worktree_path not in scan_paths:
            scan_paths.append(worktree_path)
    filter_names = []
    # One level at a time, each level's places scanned in parallel: the
    # root and the worktrees, then the submodules found in them, and so on.
    level = list(scan_paths)
    while len(level) > 0:
        scans = run_side_by_side(scan_one_place, level)
        next_level = []
        for config_names, submodule_paths in scans:
            for name in filter_program_names(config_names):
                if name not in filter_names:
                    filter_names.append(name)
            for submodule_path in submodule_paths:
                if submodule_path in scan_paths:
                    continue
                scan_paths.append(submodule_path)
                next_level.append(submodule_path)
                if len(scan_paths) > MAX_HARDENING_SCAN_PATHS:
                    raise GitError(
                        f"This repository has more than {MAX_HARDENING_SCAN_PATHS} "
                        f"worktrees and submodules for BranchLens to check for "
                        f"filters. Refusing to open it."
                    )
        level = next_level
    if len(filter_names) > MAX_HARDENING_OVERRIDES:
        raise GitError(
            f"This repository defines {len(filter_names)} content filters, more "
            f"than the {MAX_HARDENING_OVERRIDES} BranchLens can safely disable. "
            f"Refusing to open it."
        )
    overrides = list(_BASE_HARDENING_OVERRIDES)
    driver_prefixes = []
    for name in filter_names:
        overrides.append((name, ""))
        prefix = name.rsplit(".", 1)[0]
        if prefix not in driver_prefixes:
            driver_prefixes.append(prefix)
    # Each blanked filter is also made not required (Git LFS marks it required).
    for prefix in driver_prefixes:
        overrides.append((prefix + ".required", "false"))
    _HARDENING_OVERRIDES = overrides


def find_repo_root(path):
    """Resolve (main_repo_root, launch_worktree_root) for any path in a repo.

    The main repository root is the parent of the common git dir, so launching
    from inside a linked worktree still shows the whole repository.
    """
    # Symlinks resolved: git's relative answers below are relative to the
    # physical directory, and joining them to a symlinked path would name a
    # different directory.
    absolute_path = os.path.realpath(path)
    if not os.path.isdir(absolute_path):
        raise GitError(f"'{path}' is not a directory.")
    try:
        common_dir_raw = run_git_text(
            ["rev-parse", "--git-common-dir"],
            cwd=absolute_path,
        ).strip()
        # git may answer relative to the launch directory. --path-format=absolute
        # would avoid that but needs git 2.31; joining keeps an absolute answer.
        common_dir = os.path.abspath(os.path.join(absolute_path, common_dir_raw))
    except GitError:
        raise GitError(f"'{path}' is not inside a git repository.")
    try:
        toplevel = run_git_text(
            ["rev-parse", "--show-toplevel"], cwd=absolute_path
        ).strip()
    except GitError:
        toplevel = ""

    if os.path.basename(common_dir) == ".git":
        # Normal repository (possibly launched from a linked worktree):
        # the main working tree is the directory that contains .git.
        main_repo_root = os.path.realpath(os.path.dirname(common_dir))
    elif toplevel != "":
        # Submodule: its common dir lives under the superproject's
        # .git/modules/, so "parent of the common dir" would name the wrong
        # repository. The submodule's own top level is the right root.
        main_repo_root = os.path.realpath(toplevel)
    else:
        raise GitError(
            f"'{path}' is a bare repository; point BranchLens at a "
            "repository with a working tree."
        )

    if toplevel == "":
        launch_worktree_root = main_repo_root
    else:
        launch_worktree_root = os.path.realpath(toplevel)
    return main_repo_root, launch_worktree_root


def read_branch_records(repo_root):
    """List local branches, most recent commit first.

    Returns (raw_bytes, records); the raw output also feeds the state token.
    """
    # lstrip=2 strips exactly "refs/heads/" and keeps slashes in branch names;
    # refname:short could yield "heads/x" when a tag shares the branch name.
    format_string = (
        "%(refname:lstrip=2)%00%(objectname)%00"
        "%(committerdate:iso-strict)%00%(subject)"
    )
    raw = run_git(
        [
            "for-each-ref",
            "--sort=-committerdate",
            "--format=" + format_string,
            "refs/heads",
        ],
        cwd=repo_root,
    )
    records = []
    text = raw.decode("utf-8", errors="replace")
    for line in text.split("\n"):
        if line == "":
            continue
        fields = line.split("\x00")
        if len(fields) != 4:
            continue
        # Hide a branch name starting with '-', which git would read as an
        # option. Only a hand-made ref can look like this.
        if fields[0].startswith("-"):
            continue
        records.append(
            {
                "name": fields[0],
                "commit": fields[1],
                "date": fields[2],
                "subject": fields[3],
            }
        )
    return raw, records


def list_branch_names(repo_root):
    """Fresh list of local branch names (used to validate incoming names)."""
    raw, records = read_branch_records(repo_root)
    names = []
    for record in records:
        names.append(record["name"])
    return names


def find_default_branch(repo_root, branch_names):
    """Return (default_branch, base_source) using the detection chain."""
    try:
        ref = run_git_text(
            ["symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo_root
        ).strip()
    except GitError:
        ref = ""
    if ref.startswith("refs/remotes/origin/"):
        name = ref[len("refs/remotes/origin/"):]
        # Only trust origin/HEAD when a local branch with that name exists;
        # otherwise every later merge-base against it would fail.
        if name in branch_names:
            return name, "origin/HEAD"
    if "main" in branch_names:
        return "main", "local-main"
    if "master" in branch_names:
        return "master", "local-master"
    if len(branch_names) == 1:
        return branch_names[0], "only-branch"
    if len(branch_names) == 0:
        raise GitError("This repository has no commits yet; nothing to show.")
    # The branch checked out in the main repository folder; a detached
    # checkout has none and symbolic-ref fails.
    try:
        head_ref = run_git_text(["symbolic-ref", "HEAD"], cwd=repo_root).strip()
    except GitError:
        head_ref = ""
    if head_ref.startswith("refs/heads/"):
        name = head_ref[len("refs/heads/"):]
        if name in branch_names:
            return name, "main-checkout"
    raise GitError(
        "Could not determine the default branch: there is no remote default, "
        "no branch named main or master, more than one branch exists, and the "
        "main checkout is on none of them."
    )


def find_comparison_ref(repo_root, default_branch):
    """Resolve the ref every other branch is compared with.

    The default branch as last seen online when the repository has it, else
    the local branch: a local default branch that was never pulled would
    make every fork point, count and diff stale. Nothing here fetches: the
    online position is whatever the last fetch or pull left behind.

    Returns {"ref", "synced_online", "tip_sha"}; tip_sha is None when the
    online ref is not in use.
    """
    online_ref = f"refs/remotes/origin/{default_branch}"
    try:
        # --verify --quiet prints the sha and exits 0 when the ref resolves,
        # and exits 1 printing nothing when it does not exist.
        tip_sha = run_git_text(
            ["rev-parse", "--verify", "--quiet", online_ref],
            cwd=repo_root,
            allow_exit_code_1=True,
        ).strip()
    except GitError:
        tip_sha = ""
    if tip_sha != "":
        return {"ref": online_ref, "synced_online": True, "tip_sha": tip_sha}
    return {
        "ref": f"refs/heads/{default_branch}",
        "synced_online": False,
        "tip_sha": None,
    }


def comparison_display_name(default_branch, comparison):
    """The name shown on screen for the ref every branch is compared with.

    When the online copy is in use, every count, fork point and diff is
    measured against refs/remotes/origin/<default>, while the local branch
    of the same name can sit at another commit. The name is then
    "origin/<default>", so no sentence says "main has 3 newer commits" when
    the local main has none.
    """
    if comparison["synced_online"]:
        return "origin/" + default_branch
    return default_branch


def read_remote_setting(push_directory, key):
    """The remote name a config key holds, or "" when it is unset or unusable.

    "" and "." (a local branch as the upstream) count as unset. A name
    starting with "-" is never used: it would read as an option.
    """
    try:
        value = run_git_text(["config", "--get", key], cwd=push_directory).strip()
    except GitError:
        return ""  # git config exits with 1 when the key is not set
    if value in ("", ".") or value.startswith("-"):
        return ""
    return value


def find_push_remote(push_directory, branch):
    """Where a push of this branch goes, picked the way `git push` picks it.

    Returns {"remote", "upstream_remote", "set_upstream"}:
    - remote: branch.<name>.pushRemote, else remote.pushDefault, else the
      branch's upstream remote (branch.<name>.remote), else "origin";
    - upstream_remote: branch.<name>.remote, or "" when the branch has no
      upstream;
    - set_upstream: True only when neither an upstream nor a push remote is
      configured, so a branch that pulls from one remote and pushes to
      another keeps its upstream.
    """
    upstream_remote = read_remote_setting(push_directory, "branch." + branch + ".remote")
    push_remote = read_remote_setting(push_directory, "branch." + branch + ".pushRemote")
    if push_remote == "":
        push_remote = read_remote_setting(push_directory, "remote.pushDefault")
    if push_remote != "":
        remote = push_remote
    elif upstream_remote != "":
        remote = upstream_remote
    else:
        remote = "origin"
    return {
        "remote": remote,
        "upstream_remote": upstream_remote,
        "set_upstream": upstream_remote == "" and push_remote == "",
    }


def read_upstream_branch(push_directory, branch):
    """The name of the branch's upstream branch (branch.<name>.merge), or None.

    `git push` compares this name with the local one: under the default
    push.default it refuses to push to an upstream with another name.
    """
    try:
        merge = run_git_text(
            ["config", "--get", "branch." + branch + ".merge"], cwd=push_directory
        ).strip()
    except GitError:
        return None
    if merge.startswith("refs/heads/") and len(merge) > len("refs/heads/"):
        return merge[len("refs/heads/"):]
    return None


def read_upstream_ref(push_directory, branch):
    """The remote-tracking ref <branch>@{upstream} resolves to, or "".

    "" also when the upstream is configured but its remote-tracking ref is
    missing (never fetched, or pruned).
    """
    if branch.startswith("-"):
        return ""
    try:
        return run_git_text(
            ["rev-parse", "--verify", "--quiet", "--symbolic-full-name",
             branch + "@{upstream}"],
            cwd=push_directory,
            allow_exit_code_1=True,
        ).strip()
    except GitError:
        return ""


def read_ref_commit(push_directory, ref):
    """The object id a ref (or a revision like "<name>^{commit}") names, or "" for none.

    For a remote-tracking ref, that is where the last fetch or push left it;
    nothing here contacts the remote.
    """
    try:
        return run_git_text(
            ["rev-parse", "--verify", "--quiet", ref],
            cwd=push_directory,
            allow_exit_code_1=True,
        ).strip()
    except GitError:
        return ""


def count_commits_missing_on_remote(push_directory, commit, remote_name):
    """How many commits reachable from commit no remote-tracking ref of the remote reaches.

    These are the commits a push that sends commit would publish for the
    first time, as far as the last fetch or push knows. commit must be a
    full commit id and remote_name must hold no glob character, since
    --remotes= takes a pattern. Raises GitError when git cannot count.
    """
    output = run_git_text(
        ["rev-list", "--count", commit, "--not", "--remotes=" + remote_name, "--"],
        cwd=push_directory,
    ).strip()
    try:
        return int(output)
    except ValueError:
        raise GitError("git rev-list printed no count: " + output[:200])


def read_fetch_and_push_urls(push_directory, remote_name):
    """(fetch URLs, push URLs) of a remote, each a list in git's order.

    `git remote get-url --all` lists the URLs a fetch reads from, after
    insteadOf; with --push it lists the ones a push goes to: the pushurl
    entries after pushInsteadOf, or the fetch URLs when there is no
    pushurl. Both lists are empty when there is no such remote.
    """
    if remote_name.startswith("-"):
        return [], []
    url_lists = []
    for extra_flags in ([], ["--push"]):
        urls = []
        try:
            text = run_git_text(
                ["remote", "get-url", "--all"] + extra_flags + [remote_name],
                cwd=push_directory,
            )
        except GitError:
            text = ""  # "No such remote"
        for line in text.split("\n"):
            line = line.strip()
            if line != "" and line not in urls:
                urls.append(line)
        url_lists.append(urls)
    return url_lists[0], url_lists[1]


def read_remote_urls(push_directory, remote_name):
    """Every URL a remote fetches from or pushes to; [] when there is no such remote.

    `git remote get-url` applies insteadOf and pushInsteadOf and lists a
    separate pushurl, so these are the hosts a push would reach.
    """
    fetch_urls, push_urls = read_fetch_and_push_urls(push_directory, remote_name)
    urls = list(fetch_urls)
    for url in push_urls:
        if url not in urls:
            urls.append(url)
    return urls


def read_push_facts(push_directory, branch, known_ref=None, known_commit=None):
    """What a push of this branch would find, read at push_directory (its
    worktree, else the repository root).

    known_ref and known_commit: a fully qualified ref the caller has already
    read, and its commit. They are used only when remote_ref turns out to
    be that same ref, which saves reading it again.

    Returns a dict:
    - remote: the push remote's name (see find_push_remote);
    - set_upstream: whether a push sets the upstream (see find_push_remote);
    - remote_ref: the remote-tracking ref of the push remote's copy. When
      the branch pushes back to its upstream remote, the ref its
      <branch>@{upstream} names (refs/remotes/origin/main for a master that
      tracks origin/main); otherwise refs/remotes/<remote>/<branch>;
    - remote_tip: where remote_ref points, "" when it does not exist;
    - upstream_branch: when the push goes to the upstream remote, the name
      of the upstream branch (branch.<name>.merge); None otherwise or when
      it is not set;
    - first_publish: remote_tip is "" (a push would publish the whole history);
    - remote_exists: whether the remote has URLs, read only for a first
      publish; None otherwise.
    """
    target = find_push_remote(push_directory, branch)
    remote_name = target["remote"]
    remote_ref = "refs/remotes/" + remote_name + "/" + branch
    upstream_branch = None
    if target["upstream_remote"] == remote_name:
        upstream_branch = read_upstream_branch(push_directory, branch)
        upstream_ref = read_upstream_ref(push_directory, branch)
        if upstream_ref.startswith("refs/remotes/" + remote_name + "/"):
            remote_ref = upstream_ref
    if known_ref is not None and known_ref == remote_ref and known_commit:
        remote_tip = known_commit
    else:
        remote_tip = read_ref_commit(push_directory, remote_ref)
    facts = {
        "remote": remote_name,
        "set_upstream": target["set_upstream"],
        "remote_ref": remote_ref,
        "remote_tip": remote_tip,
        "upstream_branch": upstream_branch,
        "first_publish": remote_tip == "",
        "remote_exists": None,
    }
    if facts["first_publish"]:
        facts["remote_exists"] = len(read_remote_urls(push_directory, remote_name)) > 0
    return facts


EMPTY_TREE_SHA1 = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
EMPTY_TREE_SHA256 = "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"


def empty_tree_id(sample_sha):
    """The id of the empty tree in a repository whose commit ids look like sample_sha.

    git knows this tree without storing it; a SHA-256 repository has 64-character ids.
    """
    if len(sample_sha) == 64:
        return EMPTY_TREE_SHA256
    return EMPTY_TREE_SHA1


def _worktree_belongs_to_repo(worktree_path, common_dir):
    """True when this directory is one of this repository's worktrees.

    The main working tree's ".git" is the repository's common git dir, and a
    linked worktree's ".git" file points back into it. A "gitdir" redirect
    to /etc fails both tests; a worktree anywhere else on disk passes.
    """
    # 'git worktree list' names a submodule by its git dir
    # (<superproject>/.git/modules/<name>), which holds no ".git" entry. That
    # path comes from this repository's own rev-parse, so the inspected
    # repository cannot redirect it.
    if os.path.realpath(worktree_path) == common_dir:
        return True
    dot_git = os.path.join(worktree_path, ".git")
    if os.path.isdir(dot_git):
        return os.path.realpath(dot_git) == common_dir
    if os.path.isfile(dot_git):
        try:
            with open(dot_git, encoding="utf-8", errors="replace") as handle:
                content = handle.read().strip()
        except OSError:
            return False
        if not content.startswith("gitdir:"):
            return False
        target = os.path.realpath(
            os.path.join(worktree_path, content[len("gitdir:"):].strip())
        )
        return target == common_dir or target.startswith(common_dir + os.sep)
    return False


def checkout_of_git_dir(common_dir):
    """The checkout of a repository that 'git worktree list' names by its git dir.

    A submodule's main worktree is listed as <superproject>/.git/modules/<name>;
    git finds its files through core.worktree, and rev-parse run in the git dir
    names them. Returns None for a bare repository, which has no checkout, and
    for a checkout whose own '.git' does not point back at common_dir.
    """
    try:
        toplevel = run_git_text(["rev-parse", "--show-toplevel"], cwd=common_dir).strip()
    except GitError:
        return None
    if toplevel == "":
        return None
    toplevel = os.path.realpath(toplevel)
    if toplevel == common_dir or not os.path.isdir(toplevel):
        return None
    if not _worktree_belongs_to_repo(toplevel, common_dir):
        return None
    return toplevel


# repo_root -> the real path of its common git dir, read once per process.
_COMMON_DIR_BY_ROOT = {}


def find_common_dir(repo_root):
    """The real path of the repository's common git dir."""
    common_dir = _COMMON_DIR_BY_ROOT.get(repo_root)
    if common_dir is None:
        common_dir_raw = run_git_text(["rev-parse", "--git-common-dir"], cwd=repo_root).strip()
        common_dir = os.path.realpath(os.path.join(repo_root, common_dir_raw))
        _COMMON_DIR_BY_ROOT[repo_root] = common_dir
    return common_dir


# Whether 'git worktree list' takes -z (git 2.36+): None until first tried.
_WORKTREE_LIST_TAKES_Z = None


def read_worktree_listing(repo_root):
    """'git worktree list --porcelain' output and the separator of its lines.

    With -z every line ends in NUL, so a worktree path holding a newline
    stays whole. A git older than 2.36 refuses -z and gets the newline form.
    """
    global _WORKTREE_LIST_TAKES_Z
    if _WORKTREE_LIST_TAKES_Z is not False:
        try:
            raw = run_git(["worktree", "list", "--porcelain", "-z"], cwd=repo_root)
            _WORKTREE_LIST_TAKES_Z = True
            return raw, "\x00"
        except GitError:
            if _WORKTREE_LIST_TAKES_Z is True:
                raise
    raw = run_git(["worktree", "list", "--porcelain"], cwd=repo_root)
    _WORKTREE_LIST_TAKES_Z = False
    return raw, "\n"


def get_worktrees(repo_root):
    """Map branches to their worktrees via 'git worktree list --porcelain'.

    Returns (branch_to_worktree, all_worktree_paths, raw_bytes); the raw
    output also feeds the state token. Worktrees with a detached HEAD (or
    bare entries) have no branch line and are not mapped to any branch;
    get_state() lists the detached ones apart and leaves out the entry that
    is the git dir itself. A submodule's entry, listed as its git dir, is
    replaced by its checkout. Worktrees whose directory no longer exists
    (deleted, never pruned) are skipped, and their branch shows its
    committed changes only.
    """
    common_dir = find_common_dir(repo_root)
    raw, separator = read_worktree_listing(repo_root)
    output = raw.decode("utf-8", errors="replace")
    branch_to_worktree = {}
    all_worktree_paths = []
    current_path = None
    for line in output.split(separator):
        if line.startswith("worktree "):
            current_path = os.path.realpath(line[len("worktree "):])
            if current_path == common_dir:
                checkout = checkout_of_git_dir(common_dir)
                if checkout is not None:
                    current_path = checkout
            if os.path.isdir(current_path) and _worktree_belongs_to_repo(current_path, common_dir):
                all_worktree_paths.append(current_path)
            else:
                current_path = None
        elif line.startswith("branch ") and current_path is not None:
            ref = line[len("branch "):]
            branch_name = ref.removeprefix("refs/heads/")
            branch_to_worktree[branch_name] = current_path
    return branch_to_worktree, all_worktree_paths, raw


# (comparison tip sha, branch tip sha) -> (ahead, behind). Cleared whole past
# the bound; a lookup that races the clearing recounts.
_AHEAD_BEHIND_CACHE = {}
MAX_AHEAD_BEHIND_CACHE = 4096


def count_ahead_behind(repo_root, comparison_ref, branch,
                       comparison_sha=None, branch_sha=None):
    """Commits this branch has (ahead) / is missing (behind) vs the default.

    comparison_ref is already fully qualified (online or local), so a tag
    sharing a branch name can never win git's ref resolution. When both
    shas are given the count is made between them, not between the refs
    (which may have moved since), and cached under them.
    """
    cache_key = None
    range_spec = f"{comparison_ref}...refs/heads/{branch}"
    if comparison_sha is not None and branch_sha is not None:
        cache_key = (comparison_sha, branch_sha)
        cached = _AHEAD_BEHIND_CACHE.get(cache_key)
        if cached is not None:
            return cached
        range_spec = f"{comparison_sha}...{branch_sha}"
    try:
        output = run_git_text(
            [
                "rev-list",
                "--left-right",
                "--count",
                range_spec,
                "--",
            ],
            cwd=repo_root,
        ).strip()
        left_text, right_text = output.split("\t")
        behind = int(left_text)
        ahead = int(right_text)
    except (GitError, ValueError):
        # A count that fails shows as 0, 0 and is not cached.
        return 0, 0
    if cache_key is not None:
        if len(_AHEAD_BEHIND_CACHE) >= MAX_AHEAD_BEHIND_CACHE:
            _AHEAD_BEHIND_CACHE.clear()
        _AHEAD_BEHIND_CACHE[cache_key] = (ahead, behind)
    return ahead, behind


# Whether this git knows for-each-ref's %(ahead-behind:) (git 2.41+): None
# until first tried, then sticky.
_FOR_EACH_REF_AHEAD_BEHIND = None


def prefill_ahead_behind(repo_root, comparison_sha, branch_records):
    """Fill _AHEAD_BEHIND_CACHE for every branch with one git process.

    The per-branch rev-list loop stays as the fallback (older git, or a
    failure here), and it still answers any pair this leaves out.
    """
    global _FOR_EACH_REF_AHEAD_BEHIND
    if comparison_sha is None or _FOR_EACH_REF_AHEAD_BEHIND is False:
        return
    missing = 0
    for record in branch_records:
        if (comparison_sha, record["commit"]) not in _AHEAD_BEHIND_CACHE:
            missing += 1
    if missing < 2:
        return
    try:
        raw = run_git(
            ["for-each-ref",
             "--format=%(objectname)%00%(ahead-behind:" + comparison_sha + ")",
             "refs/heads"],
            cwd=repo_root,
            timeout_key="for-each-ref ahead-behind",
        )
    except GitError:
        _FOR_EACH_REF_AHEAD_BEHIND = False
        return
    _FOR_EACH_REF_AHEAD_BEHIND = True
    if len(_AHEAD_BEHIND_CACHE) + missing >= MAX_AHEAD_BEHIND_CACHE:
        _AHEAD_BEHIND_CACHE.clear()
    for line in raw.decode("utf-8", errors="replace").split("\n"):
        fields = line.split("\x00")
        if len(fields) != 2:
            continue
        counts = fields[1].split(" ")
        if len(counts) != 2 or not counts[0].isdigit() or not counts[1].isdigit():
            continue
        # %(ahead-behind:X) prints "<ahead> <behind>" relative to X.
        _AHEAD_BEHIND_CACHE[(comparison_sha, fields[0])] = (int(counts[0]), int(counts[1]))


def parse_status_paths(status_raw):
    """The working-tree paths named by 'git status --porcelain -z' output.

    Each entry is "XY <path>\\0"; a rename or copy adds a second record holding
    the original path, which no longer exists on disk and is skipped. A
    record that does not look like an entry is skipped too.
    """
    # X is the index column and Y the working-tree column; either may be a
    # space (" M" is "modified but not staged", "M " is "staged only").
    status_letters = "MADRCUT?! "
    # surrogateescape keeps a name that is not valid UTF-8 usable as a path.
    text = status_raw.decode("utf-8", errors="surrogateescape")
    records = text.split("\x00")
    paths = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 4 or record[2] != " ":
            continue
        if record[0] not in status_letters or record[1] not in status_letters:
            continue
        if record[0] == " " and record[1] == " ":
            continue
        paths.append(record[3:])
        if record[0] in "RC" or record[1] in "RC":
            index += 1  # the paired original path
    return paths


def worktree_content_fingerprint(worktree_path, status_raw):
    """Bytes that change whenever the content of a listed path changes.

    'git status --porcelain' says that a path is modified or untracked, never
    what it holds: a second edit of a modified file leaves its output the
    same. The page reloads only when the state token changes, so each listed
    path's size and modification time go into the token; every write moves
    one of the two.
    """
    pieces = []
    for relative_path in parse_status_paths(status_raw):
        absolute_path = os.path.join(worktree_path, relative_path)
        try:
            info = os.lstat(absolute_path)
            stamp = f"{info.st_size}:{info.st_mtime_ns}"
        except OSError:
            stamp = "gone"  # e.g. a deleted tracked file
        pieces.append(
            relative_path.encode("utf-8", errors="surrogateescape") + b"\x00" + stamp.encode("utf-8")
        )
    return b"\x00".join(pieces)


def short_token(pieces):
    """The first 12 hex characters of the sha256 of the pieces, joined by NUL."""
    return hashlib.sha256(b"\x00".join(pieces)).hexdigest()[:12]


def get_state(repo_root, launch_worktree_root):
    """Full repository state for /api/state."""
    branch_to_worktree, all_worktree_paths, worktree_list_raw = get_worktrees(repo_root)
    # Rescanned on every poll, so a filter, submodule or include added since
    # the last one is covered too.
    configure_repo_hardening(repo_root, all_worktree_paths)
    for_each_ref_raw, branch_records = read_branch_records(repo_root)
    branch_names = []
    sha_by_branch = {}
    for record in branch_records:
        branch_names.append(record["name"])
        sha_by_branch[record["name"]] = record["commit"]

    default_branch, base_source = find_default_branch(repo_root, branch_names)
    comparison = find_comparison_ref(repo_root, default_branch)
    # The commit every count is measured from; part of the count cache key.
    comparison_sha = comparison["tip_sha"]
    if comparison_sha is None:
        comparison_sha = sha_by_branch.get(default_branch)

    # Where a push of the default branch would go, read where it runs from.
    push_directory = branch_to_worktree.get(default_branch)
    if push_directory is None:
        push_directory = repo_root
    # The online tip is already resolved: reuse it instead of a second rev-parse.
    known_ref = comparison["ref"] if comparison["synced_online"] else None
    push_facts = read_push_facts(push_directory, default_branch, known_ref, comparison["tip_sha"])
    push_piece = "\x00".join(
        [push_facts["remote"], push_facts["remote_tip"], str(push_facts["remote_exists"])]
    ).encode("utf-8")

    # The token changes on any change the page shows. The worktree listing
    # covers checkouts and worktree add/remove; each status chunk is prefixed
    # with its worktree path, so the same edit in two worktrees hashes
    # differently. A fetch moves the online tip without touching a local
    # branch, and 'git remote add' moves no branch, so the online tip and the
    # default branch's push facts are in it too.
    #
    # '-uall' lists untracked files one by one instead of collapsing a
    # directory to "dir/", so a new file in an untracked directory moves the
    # token. The fingerprint adds each listed path's size and modification
    # time, so an edit to a listed file moves it too. A status that failed
    # adds git's message.
    online_tip_piece = (comparison["tip_sha"] or "").encode("utf-8")
    token_pieces = [for_each_ref_raw, worktree_list_raw, online_tip_piece,
                    b"\x00" + push_piece + b"\x00"]
    worktree_has_changes = {}
    worktree_status_errors = {}  # worktree path -> git's message, or None
    worktree_edits = {}  # worktree path -> its status output plus fingerprint
    # In parallel, once the overrides above are in place.
    status_results = run_side_by_side(read_worktree_status, all_worktree_paths)
    for worktree_path, status_result in zip(all_worktree_paths, status_results):
        status_raw, status_error = status_result
        fingerprint = worktree_content_fingerprint(worktree_path, status_raw)
        error_piece = (status_error or "").encode("utf-8")
        token_pieces.append(worktree_path.encode("utf-8") + b"\x00")
        token_pieces.append(status_raw)
        token_pieces.append(fingerprint)
        token_pieces.append(b"\x00" + error_piece)
        worktree_has_changes[worktree_path] = len(status_raw) > 0
        worktree_status_errors[worktree_path] = status_error
        worktree_edits[worktree_path] = status_raw + b"\x00" + fingerprint + b"\x00" + error_piece

    state_token = short_token([b"".join(token_pieces)])
    # What the commit graph is built from: branch tips, checkouts, the online
    # tip and the default branch.
    refs_token = short_token(
        [for_each_ref_raw, worktree_list_raw, online_tip_piece, default_branch.encode("utf-8")]
    )
    # What every branch's diff is measured against.
    comparison_piece = "\x00".join(
        [default_branch, comparison["ref"], comparison_sha or ""]
    ).encode("utf-8")

    launch_root_real = os.path.realpath(launch_worktree_root)

    prefill_ahead_behind(repo_root, comparison_sha, branch_records)
    branches = []
    for record in branch_records:
        name = record["name"]
        worktree_path = branch_to_worktree.get(name)
        if name == default_branch and not comparison["synced_online"]:
            # Compared with itself. With an online copy it is counted against
            # that copy like any other branch: ahead is what a push would send.
            ahead = 0
            behind = 0
        else:
            ahead, behind = count_ahead_behind(
                repo_root, comparison["ref"], name,
                comparison_sha, record["commit"],
            )
        has_uncommitted = False
        status_error = None
        edits_piece = b""
        if worktree_path is not None:
            has_uncommitted = worktree_has_changes.get(worktree_path, False)
            status_error = worktree_status_errors.get(worktree_path)
            edits_piece = worktree_path.encode("utf-8") + b"\x00" + worktree_edits.get(
                worktree_path, b""
            )
        # Everything this branch's /api/diff and /api/file answers depend on;
        # the default branch's also depend on its push facts.
        content_pieces = [name.encode("utf-8"), record["commit"].encode("utf-8"),
                          comparison_piece, edits_piece]
        if name == default_branch:
            content_pieces.append(push_piece)
        content_token = short_token(content_pieces)
        branches.append(
            {
                "name": name,
                "is_default": name == default_branch,
                "is_current": worktree_path == launch_root_real,
                "worktree_path": worktree_path,
                "commit": record["commit"],
                "content_token": content_token,
                "last_commit_date": record["date"],
                "last_commit_subject": record["subject"],
                "ahead": ahead,
                "behind": behind,
                "has_uncommitted": has_uncommitted,
                "status_error": status_error,
            }
        )

    # Worktrees on no branch (a rebase, a bisect, a checked-out commit), or on
    # a branch with no commit yet, which has no entry above. The git dir
    # itself (a bare repository's entry) has no checkout.
    branch_worktree_paths = set()
    for branch in branches:
        if branch["worktree_path"] is not None:
            branch_worktree_paths.add(branch["worktree_path"])
    common_dir = find_common_dir(repo_root)
    detached_worktrees = []
    for worktree_path in all_worktree_paths:
        if worktree_path not in branch_worktree_paths and worktree_path != common_dir:
            detached_worktrees.append(
                {
                    "path": worktree_path,
                    "has_uncommitted": worktree_has_changes.get(worktree_path, False),
                    "status_error": worktree_status_errors.get(worktree_path),
                }
            )

    return {
        "repo_name": os.path.basename(os.path.normpath(repo_root)),
        "repo_path": repo_root,
        "default_branch": default_branch,
        "base_source": base_source,
        "default_synced_online": comparison["synced_online"],
        # What ahead and behind were measured against, as the screen names it
        # ("origin/main" when the online copy is in use, "main" when not).
        "comparison_label": comparison_display_name(default_branch, comparison),
        # The default branch's push remote, and whether it has no copy of the
        # branch yet: a run on it then judges its whole history.
        "push_remote": push_facts["remote"],
        "first_publish": push_facts["first_publish"],
        "state_token": state_token,
        "refs_token": refs_token,
        "branches": branches,
        "detached_worktrees": detached_worktrees,
    }


def truncate_subject(subject):
    """Cut a commit subject for explanation sentences (60 chars + ellipsis)."""
    if len(subject) > MAX_SUBJECT_CHARS:
        return subject[:MAX_SUBJECT_CHARS] + "…"
    return subject


def read_worktree_status(worktree_path):
    """('git status --porcelain -z -uall' output, None) for one worktree.

    When git fails: (b"", the error message).
    """
    try:
        return run_git(["status", "--porcelain", "-z", "-uall"], cwd=worktree_path), None
    except GitError as error:
        return b"", str(error)


def build_diff_context(repo_root, branch, base_record=None):
    """Shared base/mode resolution for /api/diff and /api/file.

    base_record, when given, is a commit dict from the graph listing that
    the user picked as the comparison point; it replaces the merge-base.
    The sentence describing the result comes from diff_explanation().
    """
    for_each_ref_raw, branch_records = read_branch_records(repo_root)
    branch_names = []
    sha_by_branch = {}
    for record in branch_records:
        branch_names.append(record["name"])
        sha_by_branch[record["name"]] = record["commit"]
    if branch not in sha_by_branch:
        raise BranchNotFound(f"No branch named '{branch}' was found.")
    # read_branch_records already hides names starting with '-', which git
    # would read as an option.
    if branch.startswith("-"):
        raise BranchNotFound(f"No branch named '{branch}' was found.")
    branch_sha = sha_by_branch[branch]

    default_branch, base_source = find_default_branch(repo_root, branch_names)
    comparison = find_comparison_ref(repo_root, default_branch)
    comparison_label = comparison_display_name(default_branch, comparison)
    branch_to_worktree, all_worktree_paths, worktree_list_raw = get_worktrees(repo_root)
    # A branch diff runs git inside a working tree, where content filters run:
    # rescan first, so a filter or worktree added since the last state poll is
    # blanked before that git call.
    configure_repo_hardening(repo_root, all_worktree_paths)
    worktree_path = branch_to_worktree.get(branch)

    context = {
        "repo_root": repo_root,
        "branch": branch,
        "default_branch": default_branch,
        "comparison_label": comparison_label,
        "worktree_path": worktree_path,
        "base_override": False,
        "base_subject": None,
        "base_is_ancestor": None,
        "base_is_descendant": None,
        # True when the default branch has commits its online copy lacks.
        "unpushed": False,
        # The existing push remote that has no copy of the default branch.
        "first_publish_remote": None,
    }

    if base_record is not None:
        # Comparing with a user-picked point: no merge-base is involved, and
        # the default branch is treated like any other branch (checked out
        # somewhere → live worktree diff, otherwise committed changes only).
        context["merge_base"] = base_record["sha"]
        context["base_commit"] = base_record["sha"][:7]
        context["base_override"] = True
        context["base_subject"] = truncate_subject(base_record["subject"])
        # A point on another line of history is not where the branch started.
        context["base_is_ancestor"] = is_ancestor_commit(
            repo_root, base_record["sha"], branch_sha
        )
        # A later point on the branch's own line: the branch is behind it.
        context["base_is_descendant"] = not context["base_is_ancestor"] and is_ancestor_commit(
            repo_root, branch_sha, base_record["sha"]
        )
        if worktree_path is not None:
            context["mode"] = "worktree"
        else:
            context["mode"] = "committed"
        return context

    if branch == default_branch:
        push_directory = worktree_path if worktree_path is not None else repo_root
        push_facts = read_push_facts(push_directory, branch)
        if push_facts["first_publish"] and push_facts["remote_exists"]:
            # A first publish: every file, listed from the empty tree.
            context["first_publish_remote"] = push_facts["remote"]
            context["merge_base"] = empty_tree_id(branch_sha)
            context["base_commit"] = None
            if worktree_path is not None:
                context["mode"] = "worktree"
            else:
                context["mode"] = "committed"
            return context

    # The fork point is measured against the online copy of the default
    # branch when there is one (see find_comparison_ref).
    comparison_sha = comparison["tip_sha"]
    if comparison_sha is None:
        comparison_sha = sha_by_branch[default_branch]
    merge_base = find_merge_base(repo_root, comparison_sha, branch_sha)
    if merge_base == "" and len(read_shallow_boundary(repo_root)) > 0:
        # The fork point may lie past the edge of the clone.
        raise GitError(
            f"This clone is shallow and does not reach the commit where "
            f"'{branch}' forked from '{comparison_label}'. Run 'git fetch "
            f"--unshallow' (or --deepen=N) to see its changes."
        )
    if merge_base == "":
        raise GitError(
            f"'{branch}' shares no common starting point with "
            f"'{comparison_label}'; their histories are unrelated."
        )
    context["merge_base"] = merge_base
    context["base_commit"] = merge_base[:7]

    if branch == default_branch and merge_base != branch_sha:
        # Local commits the online copy lacks, shown like any branch's work.
        context["unpushed"] = True
        if worktree_path is not None:
            context["mode"] = "worktree"
        else:
            context["mode"] = "committed"
    elif branch == default_branch:
        context["mode"] = "default-branch"
        # This mode diffs against the branch's own tip.
        context["base_commit"] = branch_sha[:7]
    elif worktree_path is not None:
        context["mode"] = "worktree"
    else:
        context["mode"] = "committed"
    return context


# (comparison tip sha, branch tip sha) -> their merge-base, kept only when there
# is one. Cleared whole past the bound.
_MERGE_BASE_CACHE = {}
MAX_MERGE_BASE_CACHE = 4096


def find_merge_base(repo_root, comparison_sha, branch_sha):
    """Where a branch forked from the comparison ref, or "" for unrelated histories.

    merge-base exits with 1 (and prints nothing) when there is no common
    ancestor; any other failure keeps git's own error message.
    """
    if comparison_sha == branch_sha:
        return branch_sha
    cache_key = (comparison_sha, branch_sha)
    cached = _MERGE_BASE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    merge_base = run_git_text(
        ["merge-base", comparison_sha, branch_sha],
        cwd=repo_root,
        allow_exit_code_1=True,
    ).strip()
    if merge_base == "":
        return merge_base
    if len(_MERGE_BASE_CACHE) >= MAX_MERGE_BASE_CACHE:
        _MERGE_BASE_CACHE.clear()
    _MERGE_BASE_CACHE[cache_key] = merge_base
    return merge_base


def diff_explanation(context, has_uncommitted):
    """The sentence shown above a branch's changes.

    has_uncommitted says whether the branch's worktree holds edits not yet
    committed; the sentence mentions them only then.
    """
    branch = context["branch"]
    if has_uncommitted:
        ending = ", including edits not yet committed."
    else:
        ending = "."

    if context["base_override"]:
        base_subject = context["base_subject"]
        if context["base_is_ancestor"]:
            return f'Changes on {branch} since "{base_subject}"' + ending
        if has_uncommitted:
            compared = f"{branch} (with edits not yet committed)"
        else:
            compared = branch
        if context["base_is_descendant"]:
            return (
                f'How {compared} differs from "{base_subject}". {branch} is '
                f"behind that commit on the same line of history, so this is a "
                f"comparison, not a list of changes."
            )
        return (
            f'How {compared} differs from "{base_subject}". They sit on '
            f"different lines of history, so this is a comparison, not a "
            f"list of changes."
        )

    first_publish_remote = context["first_publish_remote"]
    if first_publish_remote is not None:
        # Names the remote-tracking ref that does not resolve.
        not_published = (
            f"There is no {first_publish_remote}/{branch} here yet: a push "
            f"would publish {branch}'s whole history."
        )
        if context["worktree_path"] is None:
            return not_published + " It is not checked out anywhere."
        if has_uncommitted:
            return f"Edits on {branch} not yet committed. " + not_published
        return not_published
    if context["mode"] == "default-branch":
        if context["worktree_path"] is None:
            return f"Nothing is pending on {branch}; it is not checked out anywhere."
        if not has_uncommitted:
            return f"Nothing is pending on {branch}."
        return f"Edits on {branch} not yet committed."
    if context["unpushed"]:
        return f"Changes on {branch} not yet on {context['comparison_label']}" + ending
    return f"Changes on {branch} since it forked from {context['comparison_label']}" + ending


def diff_revision_args(context):
    """Revision arguments and working directory for git diff, per mode."""
    mode = context["mode"]
    if mode == "worktree":
        # Committed plus uncommitted work: diff merge-base against the worktree.
        return [context["merge_base"]], context["worktree_path"]
    if mode == "default-branch":
        # Only edits not yet committed on the default branch.
        return ["HEAD"], context["worktree_path"]
    # Branch not checked out anywhere: committed changes only. refs/heads/
    # keeps the name an unambiguous revision (a tag could share the name).
    return [context["merge_base"], "refs/heads/" + context["branch"]], context["repo_root"]


def parse_name_status(text):
    """Parse 'git diff --name-status -z' output into entry dicts.

    Records are NUL-separated: "M<NUL>path<NUL>" normally, and for renames or
    copies "R100<NUL>old<NUL>new<NUL>" (pre-image path first).
    """
    entries = []
    tokens = text.split("\x00")
    position = 0
    while position < len(tokens):
        status_token = tokens[position]
        if status_token == "":
            break  # the trailing NUL leaves one empty token at the end
        status_letter = status_token[0]
        if status_letter in ("R", "C"):
            if position + 2 >= len(tokens):
                break  # malformed tail
            old_path = tokens[position + 1]
            new_path = tokens[position + 2]
            position += 3
        else:
            if position + 1 >= len(tokens):
                break
            old_path = None
            new_path = tokens[position + 1]
            position += 2
        if status_letter in ("A", "M", "D", "R", "T"):
            # T: the type changed, e.g. a file became a symlink.
            status = status_letter
        else:
            # Any other letter git emits (C, U, ...) maps to M, keeping
            # old_path when it was given.
            status = "M"
        entries.append({"path": new_path, "old_path": old_path, "status": status})
    return entries


def parse_numstat(text):
    """Parse 'git diff --numstat -z' output into {path: (adds, dels, binary)}.

    Normal records are "adds<TAB>dels<TAB>path<NUL>". A rename has an empty
    third field followed by two NUL-separated paths:
    "adds<TAB>dels<TAB><NUL>old<NUL>new<NUL>". Binary files report "-" for
    both counts.
    """
    counts = {}
    tokens = text.split("\x00")
    position = 0
    while position < len(tokens):
        record = tokens[position]
        if record == "":
            break
        parts = record.split("\t", 2)
        if len(parts) != 3:
            position += 1
            continue  # not a numstat record
        adds_text, dels_text, path_part = parts
        if path_part == "":
            if position + 2 >= len(tokens):
                break
            path = tokens[position + 2]  # rename: old path, then new path
            position += 3
        else:
            path = path_part
            position += 1
        if adds_text == "-":
            counts[path] = (None, None, True)
        else:
            try:
                counts[path] = (int(adds_text), int(dels_text), False)
            except ValueError:
                counts[path] = (0, 0, False)
    return counts


def classify_untracked_entry(absolute_path):
    """What kind of thing 'git ls-files --others' named: "file", "symlink" or "directory".

    - "symlink": git stores the link target as the file's one line of
      content. A no-index diff would follow the link instead (and fail when
      the target is a directory), so a symlink is counted from the link.
    - "directory": a directory git does not look inside (an embedded
      repository or a worktree), which ls-files reports as one "dir/" entry.
      It has no line counts.
    """
    if os.path.islink(absolute_path):
        return "symlink"
    if os.path.isdir(absolute_path):
        return "directory"
    return "file"


def count_symlink_lines(absolute_path):
    """Line counts for an untracked symlink: its target text, as git stores it.

    Returns (adds, dels, unreadable). git records a symlink as a mode 120000
    blob holding the target path with no trailing newline, so 'a/b' is one
    added line, as 'git diff --cached --numstat' reports once the link is
    staged.
    """
    try:
        target = os.readlink(absolute_path)
    except OSError:
        return None, None, True
    return len(target.split("\n")), 0, False


# (absolute path, size, mtime, ctime) -> count_untracked_lines() answer.
# Cleared whole before a listing, once it holds more than the bound plus that
# listing's names; a listing larger than the bound still finds its own counts.
_UNTRACKED_COUNT_CACHE = {}
MAX_UNTRACKED_COUNT_CACHE = 20000


def count_untracked_lines(absolute_path):
    """Line counts for one untracked file, the way 'git diff --numstat' counts.

    Returns (adds, dels, binary). git's rules: a NUL byte in the first 8000
    bytes means binary, a final line with no newline still counts, and a file
    over 512 MiB counts as binary. Anything that is not a regular file (a
    FIFO would block a read) gets unknown counts. A file is read again only
    when its size or timestamps change.
    """
    try:
        info = os.lstat(absolute_path)
    except OSError:
        return None, None, False
    if not stat.S_ISREG(info.st_mode):
        return None, None, False
    cache_key = (absolute_path, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    cached = _UNTRACKED_COUNT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    counts = read_line_counts(absolute_path, info.st_size)
    if counts != (None, None, False):  # an unreadable file is tried again
        _UNTRACKED_COUNT_CACHE[cache_key] = counts
    return counts


def read_line_counts(absolute_path, size):
    """(adds, 0, False) for a text file, (None, None, True) for a binary one.

    (None, None, False) when the file cannot be read.
    """
    if size > MAX_UNTRACKED_FILE_BYTES:
        return None, None, True
    if size == 0:
        return 0, 0, False
    line_count = 0
    last_byte = b""
    try:
        with open(absolute_path, "rb") as handle:
            chunk = handle.read(UNTRACKED_BINARY_PROBE_BYTES)
            if b"\x00" in chunk:
                return None, None, True
            while chunk:
                line_count += chunk.count(b"\n")
                last_byte = chunk[-1:]
                chunk = handle.read(1024 * 1024)
    except OSError:
        return None, None, False
    if last_byte != b"\n":
        line_count += 1
    return line_count, 0, False


def join_diff_listings(name_status_raw, numstat_raw):
    """Join --name-status and --numstat outputs into file entries.

    'git show --format=' prints a blank line before its listing, so leading
    newlines are stripped; 'git diff' output never starts with one. Paths
    keep bytes that are not
    valid UTF-8 as surrogate escapes, so two such names stay apart and still
    work as git arguments; displayable_files() turns them into page text.
    """
    name_status_text = name_status_raw.decode("utf-8", errors="surrogateescape").lstrip("\n")
    numstat_text = numstat_raw.decode("utf-8", errors="surrogateescape").lstrip("\n")
    entries = parse_name_status(name_status_text)
    counts = parse_numstat(numstat_text)

    files = []
    for entry in entries:
        adds, dels, is_binary = counts.get(entry["path"], (0, 0, False))
        files.append(
            {
                "path": entry["path"],
                "old_path": entry["old_path"],
                "status": entry["status"],
                "adds": adds,
                "dels": dels,
                "binary": is_binary,
                "untracked": False,
                "entry_kind": "file",
            }
        )
    return files


def sum_line_counts(files):
    """Total added and deleted lines, skipping binary files' null counts."""
    total_adds = 0
    total_dels = 0
    for file_entry in files:
        if file_entry["adds"] is not None:
            total_adds += file_entry["adds"]
        if file_entry["dels"] is not None:
            total_dels += file_entry["dels"]
    return total_adds, total_dels


UNSHOWABLE_NAME_SENTENCE = "This file name is not valid UTF-8; BranchLens cannot show its patch."


def has_undecodable_bytes(raw_path):
    """Whether a surrogate-escaped path holds bytes that are not valid UTF-8."""
    for character in raw_path:
        if "\udc80" <= character <= "\udcff":
            return True
    return False


def display_path(raw_path):
    """A surrogate-escaped path as page text: each bad byte becomes U+FFFD."""
    return raw_path.encode("utf-8", errors="surrogateescape").decode("utf-8", errors="replace")


def displayable_files(files):
    """The change list as the page receives it, every path valid text.

    An entry whose path is not valid UTF-8 gets "unshowable": true; its
    shown path may equal another such entry's.
    """
    shown = []
    for file_entry in files:
        entry = dict(file_entry)
        entry["path"] = display_path(file_entry["path"])
        if file_entry["old_path"] is not None:
            entry["old_path"] = display_path(file_entry["old_path"])
        if has_undecodable_bytes(file_entry["path"]):
            entry["unshowable"] = True
        shown.append(entry)
    return shown


def find_file_entry(files, path, change_description):
    """Locate one path, as the page names it, in a surrogate-escaped change list.

    Raises the 404-mapped error when it is not there, and GitError when the
    only match is a name that is not valid UTF-8.
    """
    matched_unshowable = False
    for candidate in files:
        if display_path(candidate["path"]) != path:
            continue
        if has_undecodable_bytes(candidate["path"]):
            matched_unshowable = True
            continue
        return candidate
    if matched_unshowable:
        raise GitError(UNSHOWABLE_NAME_SENTENCE)
    raise FileNotInDiff(
        f"'{path}' is not among the files changed {change_description}."
    )


def truncate_patch(patch_text, output_was_cut=False):
    """Cut an oversized patch at the last complete line.

    output_was_cut says git's output was already stopped early, so the last
    line may be incomplete. Returns (patch_text, truncated_flag).
    """
    if len(patch_text) <= MAX_PATCH_CHARS and not output_was_cut:
        return patch_text, False
    limit = min(len(patch_text), MAX_PATCH_CHARS)
    cut_position = patch_text.rfind("\n", 0, limit)
    if cut_position == -1:
        return patch_text[:limit], True
    kept = patch_text[: cut_position + 1]
    # A line longer than the limit right after a hunk header would leave the
    # hunk empty; that line is cut in the middle instead.
    last_line = kept.rstrip("\n").rsplit("\n", 1)[-1]
    if last_line.startswith("@@"):
        return patch_text[:limit], True
    return kept, True


def collect_changed_files(context):
    """The full changed-file list for a branch, as the page receives it."""
    return displayable_files(read_changed_files(context))


def read_changed_files(context, with_counts=True):
    """The full changed-file list for a branch, per the context's mode.

    Paths are surrogate-escaped (see join_diff_listings), ready for git.
    with_counts=False skips the --numstat listing: tracked entries then
    carry adds 0, dels 0 and binary False, for callers that count one path
    themselves.
    """
    mode = context["mode"]
    if mode == "default-branch" and context["worktree_path"] is None:
        return []

    revision_args, diff_cwd = diff_revision_args(context)
    # In worktree and default-branch modes diff_cwd is the worktree, where the
    # untracked listing runs too.
    listing_commands = [
        ["diff", "-M", "--name-status", "-z"] + revision_args + ["--"],
    ]
    if with_counts:
        listing_commands.append(["diff", "-M", "--numstat", "-z"] + revision_args + ["--"])
    lists_untracked = mode in ("worktree", "default-branch")
    if lists_untracked:
        listing_commands.append(["ls-files", "--others", "--exclude-standard", "-z"])
    outputs = run_git_side_by_side(listing_commands, diff_cwd)
    if with_counts:
        files = join_diff_listings(outputs[0], outputs[1])
    else:
        files = join_diff_listings(outputs[0], b"")

    if lists_untracked:
        tracked_paths = set()
        for file_entry in files:
            tracked_paths.add(file_entry["path"])
        worktree_path = context["worktree_path"]
        untracked_raw = outputs[-1]
        untracked_names = untracked_raw.decode("utf-8", errors="surrogateescape").split("\x00")
        if len(_UNTRACKED_COUNT_CACHE) > MAX_UNTRACKED_COUNT_CACHE + len(untracked_names):
            _UNTRACKED_COUNT_CACHE.clear()
        for relative_path in untracked_names:
            if relative_path == "":
                continue
            # A path deleted from the index but still on disk appears in both
            # listings; the tracked entry describes it.
            if relative_path in tracked_paths:
                continue
            absolute_path = os.path.join(worktree_path, relative_path)
            entry_kind = classify_untracked_entry(absolute_path)
            if entry_kind == "directory":
                # An embedded repository or a worktree. git names it and stops
                # there, so there is no content to count and none to show.
                adds, dels, is_binary = None, None, False
            elif entry_kind == "symlink":
                adds, dels, unreadable = count_symlink_lines(absolute_path)
                is_binary = False
            else:
                adds, dels, is_binary = count_untracked_lines(absolute_path)
            files.append(
                {
                    "path": relative_path,
                    "old_path": None,
                    "status": "A",
                    "adds": adds,
                    "dels": dels,
                    "binary": is_binary,
                    "untracked": True,
                    "entry_kind": entry_kind,
                }
            )

    files.sort(key=lambda file_entry: file_entry["path"])
    return files


def resolve_base_record(repo_root, base_sha):
    """Validate an optional base= value against the fresh graph listing."""
    if base_sha is None:
        return None
    graph_commits = read_graph_commits(repo_root)
    return resolve_graph_commit(base_sha, graph_commits)


def get_diff(repo_root, branch, base_sha=None):
    """Changed-file overview for /api/diff."""
    base_record = resolve_base_record(repo_root, base_sha)
    context = build_diff_context(repo_root, branch, base_record)
    reads_status = (
        context["worktree_path"] is not None
        and context["mode"] in ("worktree", "default-branch")
    )
    # The listing and the status run side by side.
    jobs = [lambda: collect_changed_files(context)]
    if reads_status:
        jobs.append(lambda: read_worktree_status(context["worktree_path"]))
    results = run_side_by_side(lambda job: job(), jobs)
    files = results[0]
    total_adds, total_dels = sum_line_counts(files)
    # The same test as /api/state's has_uncommitted; a status git could not
    # read is an error here, not a clean worktree.
    has_uncommitted = False
    if reads_status:
        status_raw, status_error = results[1]
        if status_error is not None:
            raise GitError("Could not read the uncommitted changes: " + status_error)
        has_uncommitted = len(status_raw) > 0

    response = {
        "branch": branch,
        "base": context["default_branch"],
        # The ref the fork point, the counts and this diff are measured
        # against (see comparison_display_name).
        "base_label": context["comparison_label"],
        "base_commit": context["base_commit"],
        "mode": context["mode"],
        "explanation": diff_explanation(context, has_uncommitted),
        "files": files,
        "total_adds": total_adds,
        "total_dels": total_dels,
    }
    if context["first_publish_remote"] is not None:
        response["whole_history"] = True
    if context["base_override"]:
        response["base_override"] = True
        response["base_subject"] = context["base_subject"]
        response["base_is_ancestor"] = context["base_is_ancestor"]
        response["base_is_descendant"] = context["base_is_descendant"]
    return response


def get_file_patch(repo_root, branch, path, base_sha=None):
    """Unified diff text for one file, for /api/file."""
    base_record = resolve_base_record(repo_root, base_sha)
    context = build_diff_context(repo_root, branch, base_record)
    response = build_file_patch(context, path)
    if context["base_override"]:
        response["base_is_ancestor"] = context["base_is_ancestor"]
    return response


def build_file_patch(context, path):
    """The /api/file answer for one path of a branch's change list."""
    files = read_changed_files(context, with_counts=False)
    file_entry = find_file_entry(files, path, f"on '{context['branch']}'")

    if file_entry["untracked"] and file_entry["binary"]:
        return {
            "path": path,
            "status": file_entry["status"],
            "binary": True,
            "truncated": False,
            "patch": "",
        }

    if file_entry["untracked"] and file_entry["entry_kind"] == "directory":
        # An embedded repository or a worktree: no file to diff. entry_kind
        # tells the page this is not an empty file.
        return {
            "path": path,
            "status": file_entry["status"],
            "entry_kind": "directory",
            "binary": False,
            "truncated": False,
            "patch": "",
        }
    output_was_cut = False
    if file_entry["untracked"] and file_entry["entry_kind"] == "symlink":
        patch_text = build_symlink_patch(
            path, os.path.join(context["worktree_path"], path)
        )
    elif file_entry["untracked"]:
        # Relative to the worktree (the cwd), so the header reads a/<path>
        # rather than an absolute path. 'diff --no-index' reads stdin for a
        # path of exactly "-", so that one name goes in as "./-".
        if path == "-":
            path_argument = "./-"
        else:
            path_argument = path
        patch_text, output_was_cut = run_git_text_limited(
            ["diff", "--no-index", "--", "/dev/null", path_argument],
            cwd=context["worktree_path"],
        )
        if path == "-":
            patch_text = patch_text.replace("diff --git a/./- b/./-\n", "diff --git a/- b/-\n", 1)
            patch_text = patch_text.replace("+++ b/./-\n", "+++ b/-\n", 1)
    else:
        revision_args, diff_cwd = diff_revision_args(context)
        target_paths = []
        if file_entry["old_path"] is not None:
            # Rename detection needs both the old and the new path in scope.
            target_paths.append(file_entry["old_path"])
        target_paths.append(path)
        changed_paths = []
        for entry in files:
            changed_paths.append(entry["path"])
            if entry["old_path"] is not None:
                changed_paths.append(entry["old_path"])
        path_args = build_exact_pathspecs(target_paths, changed_paths)
        # The patch and this one path's --numstat (which says whether git
        # treats it as binary) side by side.
        def read_patch():
            return run_git_text_limited(
                ["diff", "-M"] + revision_args + ["--"] + path_args,
                cwd=diff_cwd,
            )
        def read_one_count():
            return run_git(
                ["diff", "-M", "--numstat", "-z"] + revision_args + ["--"] + path_args,
                cwd=diff_cwd,
            )
        patch_result, numstat_raw = run_side_by_side(lambda job: job(), [read_patch, read_one_count])
        patch_text, output_was_cut = patch_result
        counts = parse_numstat(numstat_raw.decode("utf-8", errors="surrogateescape").lstrip("\n"))
        if counts.get(file_entry["path"], (0, 0, False))[2]:
            return {
                "path": path,
                "status": file_entry["status"],
                "binary": True,
                "truncated": False,
                "patch": "",
            }

    patch_text, truncated = truncate_patch(patch_text, output_was_cut)

    return {
        "path": path,
        "status": file_entry["status"],
        "entry_kind": file_entry["entry_kind"],
        "binary": False,
        "truncated": truncated,
        "patch": patch_text,
    }


def build_exact_pathspecs(target_paths, all_paths):
    """Pathspecs that select exactly target_paths and nothing else.

    git reads what follows "--" as a pathspec, which differs from a file
    name in two ways:

      * glob characters: 'app/[slug]/page.tsx' is a character class, so it
        also matches 'app/s/page.tsx';
      * a directory prefix: 'tools' also matches everything under a
        directory named 'tools', as in a commit that replaces the directory
        'tools/' with a file named 'tools'.

    Either one puts a second file's hunks into this file's patch.
    ':(top,literal)' turns globbing off and anchors the path at the
    working-tree root; one ':(top,exclude,literal)' per changed path under
    a target removes what the directory prefix still pulls in. Both magics
    match the path exactly, whatever characters it holds.
    """
    specs = []
    for path in target_paths:
        specs.append(":(top,literal)" + path)
    for other in all_paths:
        if other in target_paths:
            continue
        for path in target_paths:
            if other.startswith(path + "/"):
                specs.append(":(top,exclude,literal)" + other)
                break
    return specs


def build_symlink_patch(display_path, absolute_path):
    """The patch git produces for a newly added symlink.

    'git diff --no-index' follows the link and diffs the target's contents,
    and fails when the target is a directory. git stores a symlink as a mode
    120000 blob holding the target path with no trailing newline; this
    writes the text 'git diff --cached' prints once the link is staged.
    """
    try:
        target = os.readlink(absolute_path)
    except OSError:
        return ""
    lines = target.split("\n")
    if len(lines) == 1:
        hunk_header = "@@ -0,0 +1 @@"
    else:
        hunk_header = f"@@ -0,0 +1,{len(lines)} @@"
    parts = [
        f"diff --git a/{display_path} b/{display_path}",
        "new file mode 120000",
        "--- /dev/null",
        f"+++ b/{display_path}",
        hunk_header,
    ]
    for line in lines:
        parts.append("+" + line)
    parts.append("\\ No newline at end of file")
    return "\n".join(parts) + "\n"


def graph_extra_refs(repo_root):
    """The online default-branch ref, when one is in use, as a log argument.

    Without it the graph stops at the local default branch and misses the
    commits everything is compared against.
    """
    try:
        branch_names = list_branch_names(repo_root)
        default_branch, base_source = find_default_branch(repo_root, branch_names)
    except GitError:
        return []  # no commits yet, or no detectable default branch
    comparison = find_comparison_ref(repo_root, default_branch)
    if comparison["synced_online"]:
        return [comparison["ref"]]
    return []


SHALLOW_BOUNDARY_SENTENCE = (
    "This clone is shallow: the commit before this one was not downloaded, "
    "so what this commit changed cannot be shown."
)


def read_shallow_boundary(repo_root):
    """The commit ids at the edge of a shallow clone; empty for a full one.

    git lists them in the common git dir's 'shallow' file and shows each of
    them with no parents, as if it were a root commit.
    """
    shallow_path = os.path.join(find_common_dir(repo_root), "shallow")
    try:
        with open(shallow_path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return set()
    boundary = set()
    for line in text.split("\n"):
        line = line.strip()
        if line != "":
            boundary.add(line)
    return boundary


def read_graph_commits(repo_root, extra_refs=None):
    """The newest 150 commits across all local branches, in date order
    (children before parents).

    The default branch as last seen online joins the listing when the
    repository has one. Returns dicts with sha, parents (first parent first),
    date (the committer date, as the branch list shows), subject and
    shallow_boundary (the clone stops at this commit). A commit= or base=
    parameter is accepted only when it names a commit in this listing.
    extra_refs, when given, is graph_extra_refs() already computed.
    """
    if extra_refs is None:
        extra_refs = graph_extra_refs(repo_root)
    output = run_git_text(
        [
            "log",
            "--branches",
        ]
        + extra_refs
        + [
            "--date-order",
            "-n",
            str(GRAPH_COMMIT_LIMIT),
            # Record separator U+001E between commits, NUL between fields:
            # subjects can contain almost anything, but never NUL or newline.
            "--format=%H%x00%P%x00%cI%x00%s%x1e",
            "--",
        ],
        cwd=repo_root,
    )
    shallow_boundary = read_shallow_boundary(repo_root)
    commits = []
    # Split on the separator plus the newline git prints after each record:
    # a subject may itself contain U+001E, but never a newline, so this
    # two-character boundary cannot appear inside a record.
    for record in output.split("\x1e\n"):
        record = record.strip("\n")
        if record == "":
            continue
        fields = record.split("\x00")
        if len(fields) != 4:
            continue
        sha, parents_text, date, subject = fields
        if parents_text == "":
            parents = []
        else:
            parents = parents_text.split(" ")
        commits.append(
            {
                "sha": sha,
                "parents": parents,
                "date": date,
                "subject": subject,
                "shallow_boundary": sha in shallow_boundary,
            }
        )
    return commits


def resolve_graph_commit(sha, graph_commits):
    """Return the graph record for one incoming commit id, or reject it.

    An id from a request is accepted only when it is 40 (SHA-1) or 64
    (SHA-256) lowercase hex characters and appears in the fresh listing
    /api/graph shows, so nothing else reaches a git command line.
    """
    if sha is None or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha) is None:
        raise CommitNotInGraph("That commit isn't in the current graph.")
    for commit in graph_commits:
        if commit["sha"] == sha:
            return commit
    raise CommitNotInGraph("That commit isn't in the current graph.")


def get_graph(repo_root):
    """Commit graph for /api/graph."""
    # Branch names whose tip is exactly each commit (usually zero or one).
    for_each_ref_raw, branch_records = read_branch_records(repo_root)
    tips_by_sha = {}
    branch_names = []
    for record in branch_records:
        branch_names.append(record["name"])
        if record["commit"] not in tips_by_sha:
            tips_by_sha[record["commit"]] = []
        tips_by_sha[record["commit"]].append(record["name"])

    online_tip_sha = None
    # What graph_extra_refs() would return, from the lookups done here.
    extra_refs = []
    try:
        default_branch, base_source = find_default_branch(repo_root, branch_names)
        comparison = find_comparison_ref(repo_root, default_branch)
        online_tip_sha = comparison["tip_sha"]
        if comparison["synced_online"]:
            extra_refs = [comparison["ref"]]
    except GitError:
        # A repository with no commits yet still gets an empty graph.
        default_branch = None

    commits = read_graph_commits(repo_root, extra_refs)

    truncated = False
    if len(commits) == GRAPH_COMMIT_LIMIT:
        count_text = run_git_text(
            ["rev-list", "--count", "--branches"] + extra_refs + ["--"],
            cwd=repo_root,
        ).strip()
        try:
            truncated = int(count_text) > GRAPH_COMMIT_LIMIT
        except ValueError:
            truncated = False

    graph_commits = []
    for commit in commits:
        graph_commits.append(
            {
                "sha": commit["sha"],
                "short": commit["sha"][:7],
                "parents": commit["parents"],
                "subject": commit["subject"],
                "date": commit["date"],
                "tips": tips_by_sha.get(commit["sha"], []),
            }
        )

    return {
        "default_branch": default_branch,
        "online_tip_sha": online_tip_sha,
        "truncated": truncated,
        "limit": GRAPH_COMMIT_LIMIT,
        "commits": graph_commits,
    }


def collect_range_files(repo_root, base_sha, target_sha):
    """Changed-file list between two revisions, as the page receives it."""
    return displayable_files(read_range_files(repo_root, base_sha, target_sha))


def read_range_files(repo_root, base_sha, target_sha):
    """Changed-file list between two revisions (both already validated),
    with surrogate-escaped paths."""
    outputs = run_git_side_by_side(
        [
            ["diff", "-M", "--name-status", "-z", base_sha, target_sha, "--"],
            ["diff", "-M", "--numstat", "-z", base_sha, target_sha, "--"],
        ],
        repo_root,
    )
    return join_diff_listings(outputs[0], outputs[1])


def collect_commit_files(repo_root, commit):
    """Changed-file list for one commit, as the page receives it."""
    return displayable_files(read_commit_files(repo_root, commit))


def read_commit_files(repo_root, commit):
    """Changed-file list for one commit, diffed against its first parent,
    with surrogate-escaped paths.

    A merge commit thus shows what the merge brought in compared with the
    branch it landed on. A root commit has no parent to diff against, so
    'git show --root' produces the listing; without --root, log.showRoot=false
    in any config would empty it.
    """
    sha = commit["sha"]
    if len(commit["parents"]) >= 1:
        return read_range_files(repo_root, sha + "^1", sha)

    outputs = run_git_side_by_side(
        [
            ["show", "--root", "--format=", "-M", "--name-status", "-z", sha, "--"],
            ["show", "--root", "--format=", "-M", "--numstat", "-z", sha, "--"],
        ],
        repo_root,
    )
    return join_diff_listings(outputs[0], outputs[1])


def read_commit_details(repo_root, sha):
    """One commit's author name, committer name and full message.

    Read one commit at a time, not in the graph listing, whose record
    boundary needs a subject without a newline; a message body can hold one.
    A commit object cannot hold a NUL byte, so NUL separates the fields, and
    the message goes last. '%B' keeps trailing blank lines; they are cut here.

    The committer is whoever last applied the commit, which after a rebase,
    a cherry-pick or someone else's amend is not the author.
    """
    raw = run_git_text(
        ["show", "-s", "--format=%an%x00%cn%x00%B", sha, "--"],
        cwd=repo_root,
    )
    fields = raw.split("\x00", 2)
    if len(fields) != 3:
        return {"author": "", "committer": "", "message": ""}
    author, committer, message = fields
    message = message.rstrip("\n")
    if len(message) > MAX_MESSAGE_CHARS:
        message = message[:MAX_MESSAGE_CHARS] + "\n\n… message truncated."
    return {"author": author, "committer": committer, "message": message}


def is_ancestor_commit(repo_root, maybe_ancestor_sha, descendant_sha):
    """Whether the first commit is reachable from the second.

    'git merge-base --is-ancestor' answers with its exit code: 0 yes, 1 no.
    """
    return run_git_exit_code(
        ["merge-base", "--is-ancestor", maybe_ancestor_sha, descendant_sha],
        cwd=repo_root,
    ) == 0


def get_commit_diff(repo_root, commit_sha, base_sha=None):
    """Changed-file overview for /api/diff?commit= (optionally with base=)."""
    graph_commits = read_graph_commits(repo_root)
    commit = resolve_graph_commit(commit_sha, graph_commits)
    is_merge = len(commit["parents"]) >= 2
    subject = truncate_subject(commit["subject"])

    if base_sha is None:
        mode = "commit"
        if commit["shallow_boundary"]:
            # git would list this commit's whole tree as added.
            files = []
            explanation = SHALLOW_BOUNDARY_SENTENCE
        elif is_merge:
            files = collect_commit_files(repo_root, commit)
            explanation = (
                f'What merge "{subject}" brought in '
                f"(compared with the branch it landed on)."
            )
        else:
            files = collect_commit_files(repo_root, commit)
            explanation = f'What commit "{subject}" changed.'
        base_record = None
        base_is_ancestor = True
        base_is_descendant = False
    else:
        base_record = resolve_graph_commit(base_sha, graph_commits)
        files = collect_range_files(repo_root, base_record["sha"], commit["sha"])
        mode = "range"
        base_subject = truncate_subject(base_record["subject"])
        # Two commits on different branches are no before and after: a file
        # present only at the base was never deleted at the target. The
        # explanation's wording follows this answer.
        base_is_ancestor = is_ancestor_commit(
            repo_root, base_record["sha"], commit["sha"]
        )
        # A later commit on the same line: the commit is behind the base.
        base_is_descendant = not base_is_ancestor and is_ancestor_commit(
            repo_root, commit["sha"], base_record["sha"]
        )
        if base_is_ancestor:
            explanation = (
                f'Everything that changed from "{base_subject}" to "{subject}".'
            )
        elif base_is_descendant:
            explanation = (
                f'How "{subject}" differs from "{base_subject}". It comes before '
                f"that commit on the same line of history, so this is a "
                f"comparison, not a list of changes."
            )
        else:
            explanation = (
                f'How "{subject}" differs from "{base_subject}". They sit on '
                f"different lines of history, so this is a comparison, not a "
                f"list of changes."
            )

    total_adds, total_dels = sum_line_counts(files)
    details = read_commit_details(repo_root, commit["sha"])

    response = {
        "sha": commit["sha"],
        "short": commit["sha"][:7],
        "subject": commit["subject"],
        "message": details["message"],
        "author": details["author"],
        "committer": details["committer"],
        "is_merge": is_merge,
        "mode": mode,
        "explanation": explanation,
        "files": files,
        "total_adds": total_adds,
        "total_dels": total_dels,
    }
    if base_record is not None:
        response["base_override"] = True
        response["base_subject"] = truncate_subject(base_record["subject"])
        response["base_is_ancestor"] = base_is_ancestor
        response["base_is_descendant"] = base_is_descendant
    return response


def get_commit_file_patch(repo_root, commit_sha, path, base_sha=None):
    """Unified diff text for one file of a commit (or of a base..commit range)."""
    graph_commits = read_graph_commits(repo_root)
    commit = resolve_graph_commit(commit_sha, graph_commits)

    if base_sha is None:
        if commit["shallow_boundary"]:
            raise GitError(SHALLOW_BOUNDARY_SENTENCE)
        base_record = None
        files = read_commit_files(repo_root, commit)
    else:
        base_record = resolve_graph_commit(base_sha, graph_commits)
        files = read_range_files(repo_root, base_record["sha"], commit["sha"])

    file_entry = find_file_entry(files, path, "by that commit")

    if file_entry["binary"]:
        return {
            "path": path,
            "status": file_entry["status"],
            "binary": True,
            "truncated": False,
            "patch": "",
        }

    target_paths = []
    if file_entry["old_path"] is not None:
        # Rename detection needs both the old and the new path in scope.
        target_paths.append(file_entry["old_path"])
    target_paths.append(path)
    changed_paths = []
    for entry in files:
        changed_paths.append(entry["path"])
        if entry["old_path"] is not None:
            changed_paths.append(entry["old_path"])
    path_args = build_exact_pathspecs(target_paths, changed_paths)

    if base_record is not None:
        patch_text, output_was_cut = run_git_text_limited(
            ["diff", "-M", base_record["sha"], commit["sha"], "--"] + path_args,
            cwd=repo_root,
        )
    elif len(commit["parents"]) >= 1:
        patch_text, output_was_cut = run_git_text_limited(
            ["diff", "-M", commit["sha"] + "^1", commit["sha"], "--"] + path_args,
            cwd=repo_root,
        )
    else:
        # Root commit: 'git show --root' handles the no-parent case; strip
        # the blank line it may print before the patch even with --format=.
        patch_text, output_was_cut = run_git_text_limited(
            ["show", "--root", "--format=", "-M", commit["sha"], "--"] + path_args,
            cwd=repo_root,
        )
        patch_text = patch_text.lstrip("\n")

    patch_text, truncated = truncate_patch(patch_text, output_was_cut)

    response = {
        "path": path,
        "status": file_entry["status"],
        "binary": False,
        "truncated": truncated,
        "patch": patch_text,
    }
    if base_record is not None:
        response["base_is_ancestor"] = is_ancestor_commit(
            repo_root, base_record["sha"], commit["sha"]
        )
    return response


# --- Dependency network (/api/network) ---
# One commit in, one directed graph out: nodes are files, and an arrow goes
# from the file that uses something to the file that defines it. Nothing here
# runs code from the inspected repository: Python is read with ast.parse
# (which builds a tree and executes nothing), JavaScript, TypeScript and Java
# with a lexical scan.

# More network limits. Like the ones at the top of this module, each is
# reported in the response when it fires.
# Past NETWORK_MAX_TREE_ENTRIES the tree listing only counts entries; at this
# many it stops and kills git. Shared subtrees let a tiny repository list
# millions.
NETWORK_MAX_TREE_COUNT = 200000
# A tree entry with a longer or deeper path is counted, never indexed.
NETWORK_MAX_PATH_BYTES = 1024
NETWORK_MAX_PATH_PARTS = 64
# Import statements kept per file; the rest are counted.
NETWORK_MAX_REQUESTS_PER_FILE = 5000
# At most this many distinct (from, to) links are gathered for the edge cap to
# choose from; links past it are counted.
NETWORK_MAX_EDGE_PAIRS = 20 * NETWORK_MAX_EDGES
# git's output is read in pieces of this size.
NETWORK_READ_CHUNK_BYTES = 65536
# An ls-tree record longer than this has a path over NETWORK_MAX_PATH_BYTES
# (the fields before the path take under 256 bytes); it is counted, not kept.
NETWORK_MAX_TREE_RECORD_BYTES = NETWORK_MAX_PATH_BYTES + 256

# run_git() says the same when a partial clone lacks content.
NETWORK_NOT_ON_DISK_MESSAGE = (
    "This content is not on disk: the repository is a partial clone and "
    "BranchLens never fetches. Run 'git fetch' or view it after a full "
    "checkout."
)

def network_git_environment():
    """hardening_environment(), plus GIT_NO_REPLACE_OBJECTS=1.

    When refs/replace is followed, a blob replaced by a tree makes ls-tree
    report one size and 'git show' print another. Only the network's two
    commands ignore replacements; the other views still follow them.
    """
    environment = hardening_environment()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def start_network_git(args, cwd):
    """Start one whitelisted git command whose output is read as a stream.

    Returns (git_child, stderr_file), git_child being a GitChild. stderr
    goes to a temporary file: an unread pipe could fill up and stall git.
    """
    stderr_file = tempfile.TemporaryFile()
    try:
        git_child = GitChild(
            args, cwd, network_git_environment(), subprocess.PIPE, stderr_file,
        )
    except Exception:
        stderr_file.close()
        raise
    return git_child, stderr_file


def finish_network_git(git_child, stderr_file, args, stopped_early):
    """Wait for a streamed git command to end, and raise GitError if it failed.

    A command the reader stopped early is killed first and its exit status
    ignored. The process is always waited for.
    """
    process = git_child.process
    try:
        if stopped_early:
            git_child.kill_group()
        process.stdout.close()
        git_child.finish()
        git_child.raise_if_timed_out()
        if stopped_early or process.returncode == 0:
            return
        stderr_file.seek(0)
        stderr_text = stderr_file.read().decode("utf-8", errors="replace").strip()
    finally:
        stderr_file.close()
    if "lazy fetching disabled" in stderr_text:
        raise GitError(NETWORK_NOT_ON_DISK_MESSAGE)
    raise GitError(f"git {args[0]} failed: {stderr_text}")


def path_is_too_deep(path_bytes):
    """Whether a tree path is past NETWORK_MAX_PATH_BYTES or _PATH_PARTS."""
    if len(path_bytes) > NETWORK_MAX_PATH_BYTES:
        return True
    return path_bytes.count(b"/") + 1 > NETWORK_MAX_PATH_PARTS


def add_tree_record(record, entries, excluded, excluded_paths):
    """File one ls-tree record (bytes, NUL removed) into the listing."""
    # A path may itself contain a tab, so only the first one is a field
    # separator: '<mode> <type> <oid> <size>\t<path>', the size padded with
    # spaces.
    if b"\t" not in record:
        excluded["other"] += 1
        return
    meta_bytes, path_bytes = record.split(b"\t", 1)
    if path_is_too_deep(path_bytes):
        excluded["too_deep"] += 1
        return
    meta = meta_bytes.decode("utf-8", errors="replace")
    path = path_bytes.decode("utf-8", errors="replace")
    parts = meta.split()
    if len(parts) != 4:
        excluded["other"] += 1
        return
    mode, object_type, object_id, size_text = parts
    # A gitlink's size column is '-', so the type is tested before int().
    if object_type == "commit":
        excluded["submodules"] += 1
        excluded_paths.add(path)
        return
    if object_type != "blob":
        excluded["other"] += 1
        return
    if mode == "120000":
        excluded["symlinks"] += 1
        excluded_paths.add(path)
        return
    if mode not in ("100644", "100755"):
        excluded["other"] += 1
        return
    try:
        size = int(size_text)
    except ValueError:
        # 'BAD': a partial clone lacks this blob. build_network_graph()
        # refuses the commit only if this is a file it would read.
        size = None
    entries.append({"path": path, "blob": object_id, "size": size, "mode": mode})


def list_tree_files(repo_root, sha):
    """Every blob at one commit, plus a tally of what was left out.

    Returns (entries, excluded, excluded_paths, listing_stopped). entries are
    {"path", "blob", "size", "mode"} in path order; "size" is None for a blob
    a partial clone does not have. excluded counts symlinks, submodules, tree
    records that are neither, paths too long or too deep to index, and the
    entries past NETWORK_MAX_TREE_ENTRIES ("unlisted"). excluded_paths holds
    the paths behind the symlink and submodule counts, so an import of a
    symlinked module is reported as one, not as an import that leaves the
    repository.

    git's output is read as a stream and never held whole. The first
    NETWORK_MAX_TREE_ENTRIES records are filed; the ones after are only
    counted, and once the count passes NETWORK_MAX_TREE_COUNT git is killed:
    listing_stopped is then True and "unlisted" is a lower bound
    (NETWORK_MAX_TREE_COUNT minus the listed entries). Without '-z' git
    quotes unusual paths; '-l' adds the byte size read_blob_contents slices
    by.
    """
    args = ["ls-tree", "-r", "-z", "-l", "--full-tree", sha, "--"]
    entries = []
    excluded = {
        "symlinks": 0, "submodules": 0, "other": 0, "unlisted": 0, "too_deep": 0,
    }
    excluded_paths = set()
    listed = 0
    pending = b""
    # True while the rest of an over-long record is being skipped.
    skipping_record = False
    listing_stopped = False
    finished = False
    git_child, stderr_file = start_network_git(args, repo_root)
    try:
        while True:
            chunk = git_child.process.stdout.read(NETWORK_READ_CHUNK_BYTES)
            if chunk == b"":
                finished = True
                break
            if skipping_record:
                end = chunk.find(b"\x00")
                if end == -1:
                    continue
                chunk = chunk[end + 1:]
                skipping_record = False
                if listed < NETWORK_MAX_TREE_ENTRIES:
                    listed += 1
                    excluded["too_deep"] += 1
                else:
                    excluded["unlisted"] += 1
            if listed >= NETWORK_MAX_TREE_ENTRIES:
                # Past the cap a record is only counted: one NUL ends each.
                excluded["unlisted"] += chunk.count(b"\x00")
            else:
                records = (pending + chunk).split(b"\x00")
                # The last piece has no NUL yet; it waits for the next chunk.
                pending = records.pop()
                for record in records:
                    if record == b"":
                        continue
                    if listed < NETWORK_MAX_TREE_ENTRIES:
                        listed += 1
                        add_tree_record(record, entries, excluded, excluded_paths)
                    else:
                        excluded["unlisted"] += 1
                if len(pending) > NETWORK_MAX_TREE_RECORD_BYTES:
                    pending = b""
                    skipping_record = True
            if listed + excluded["unlisted"] > NETWORK_MAX_TREE_COUNT:
                excluded["unlisted"] = NETWORK_MAX_TREE_COUNT - listed
                listing_stopped = True
                break
    finally:
        finish_network_git(git_child, stderr_file, args, not finished)
    entries.sort(key=lambda entry: entry["path"])
    return entries, excluded, excluded_paths, listing_stopped


def read_one_blob_batch(repo_root, batch, contents):
    """Read one batch of blobs with a single 'git show' and slice the result.

    git prints blob contents back to back, with no separator or added
    newline, so the sizes from ls-tree cut the stream apart. A total that
    differs from the sum of the sizes raises GitError, so no parser gets
    shifted bytes. The output is read as a stream and git is stopped as soon
    as it prints more than the sizes add up to.
    """
    blob_ids = []
    expected = 0
    for entry in batch:
        blob_ids.append(entry["blob"])
        expected += entry["size"]
    args = ["show"] + blob_ids + ["--"]
    chunks = []
    received = 0
    finished = False
    git_child, stderr_file = start_network_git(args, repo_root)
    try:
        while received <= expected:
            chunk = git_child.process.stdout.read(NETWORK_READ_CHUNK_BYTES)
            if chunk == b"":
                finished = True
                break
            chunks.append(chunk)
            received += len(chunk)
    finally:
        finish_network_git(git_child, stderr_file, args, not finished)
    if received != expected:
        raise GitError(
            "Reading file contents at that commit produced an unexpected "
            "amount of data."
        )
    stdout = b"".join(chunks)
    consumed = 0
    for entry in batch:
        contents[entry["blob"]] = stdout[consumed:consumed + entry["size"]]
        consumed += entry["size"]


def read_blob_contents(repo_root, entries):
    """{blob_id: bytes} for entries [{"blob", "size"}, ...], read in batches.

    Identical file contents share one blob id, so the ids are de-duplicated
    first. An empty list runs no git command at all: 'git show --' with no
    object would print the current commit instead.
    """
    contents = {}
    ordered = []
    seen_blobs = set()
    for entry in entries:
        if entry["blob"] in seen_blobs:
            continue
        seen_blobs.add(entry["blob"])
        ordered.append(entry)

    batch = []
    batch_bytes = 0
    for entry in ordered:
        too_many = len(batch) >= NETWORK_READ_BATCH_FILES
        too_big = batch_bytes + entry["size"] > NETWORK_READ_BATCH_BYTES
        if (too_many or too_big) and len(batch) > 0:
            read_one_blob_batch(repo_root, batch, contents)
            batch = []
            batch_bytes = 0
        batch.append(entry)
        batch_bytes += entry["size"]
    if len(batch) > 0:
        read_one_blob_batch(repo_root, batch, contents)
    return contents


def language_of_path(path):
    """"python" | "javascript" | "typescript" | "java" | "unsupported" | None."""
    lowered = path.lower()
    for extension in PYTHON_EXTENSIONS:
        if lowered.endswith(extension):
            return "python"
    for extension in JAVASCRIPT_EXTENSIONS:
        if lowered.endswith(extension):
            return "javascript"
    for extension in TYPESCRIPT_EXTENSIONS:
        if lowered.endswith(extension):
            return "typescript"
    for extension in JAVA_EXTENSIONS:
        if lowered.endswith(extension):
            return "java"
    for extension in UNSUPPORTED_CODE_EXTENSIONS:
        if lowered.endswith(extension):
            return "unsupported"
    return None


# The byte-order mark some editors write at the start of a file: ast.parse
# refuses it as an invalid character, so it is stripped before parsing.
UTF8_BOM = "\ufeff"


def count_text_lines(text):
    """Number of lines in a decoded file, counting a last unterminated one."""
    if text == "":
        return 0
    if text.endswith("\n"):
        return text.count("\n")
    return text.count("\n") + 1


def first_existing(file_set, candidate_paths):
    """The first candidate that exists at this commit, or None."""
    for candidate in candidate_paths:
        if candidate in file_set:
            return candidate
    return None


def new_honesty_counts():
    """A fresh set of the counters that say what this view could not see."""
    return {
        "python_star_imports": 0,
        "python_dynamic_imports": 0,
        "python_conditional_imports": 0,
        "js_reexports": 0,
        "js_namespace_imports": 0,
        "js_dynamic_imports": 0,
        "java_wildcard_imports": 0,
        "java_same_package_files": 0,
        "ambiguous_python_modules": 0,
        "python_namespace_packages": 0,
        "self_imports_dropped": 0,
        "symbols_unreadable": 0,
        "js_clauses_too_long": 0,
        "imports_past_file_cap": 0,
        "ambiguous_java_classes": 0,
    }


def add_honesty_counts(total, part):
    """Add one file's honesty counters into the running totals."""
    for name in part:
        total[name] = total.get(name, 0) + part[name]


# --- Python extraction ---

# SyntaxWarnings raised while parsing inspected files (an invalid escape such
# as '\d', on Python 3.12+) would land on the server's terminal; ignore them.
warnings.filterwarnings("ignore", category=SyntaxWarning)

# An import reached through any of these is not guaranteed to happen on every
# run, so its edge is flagged conditional.
PYTHON_BLOCK_NODE_LIST = [
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.If,
    ast.Try,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.With,
    ast.AsyncWith,
]
# ast.TryStar only exists on Python 3.11+.
if getattr(ast, "TryStar", None) is not None:
    PYTHON_BLOCK_NODE_LIST.append(ast.TryStar)
# ast.Match (match/case) only exists on Python 3.10+.
if getattr(ast, "Match", None) is not None:
    PYTHON_BLOCK_NODE_LIST.append(ast.Match)
PYTHON_BLOCK_NODES = tuple(PYTHON_BLOCK_NODE_LIST)


def python_import_root(path, package_directories):
    """The directory a Python file's dotted module name is measured from.

    Walking out of every directory that has an __init__.py yields "" for a
    flat layout and "src" for a src layout, with nothing configured.
    """
    directory = posixpath.dirname(path)
    while directory != "" and directory in package_directories:
        directory = posixpath.dirname(directory)
    return directory


def python_module_name(path, import_root):
    """The dotted name a Python file answers to, measured from one root."""
    if import_root != "":
        prefix = import_root + "/"
        if not path.startswith(prefix):
            return None
        relative = path[len(prefix):]
    else:
        relative = path
    for extension in PYTHON_EXTENSIONS:
        if relative.endswith(extension):
            relative = relative[: -len(extension)]
            break
    name = relative.replace("/", ".")
    if name == "__init__":
        return ""
    if name.endswith(".__init__"):
        name = name[: -len(".__init__")]
    return name


def build_python_module_index(python_paths):
    """Every dotted name each Python file can be imported under.

    Returns (index, import_roots, package_directories). index maps a module
    name to [(import_root, path), ...]. Each file is filed twice: under the
    name measured from its own import root ("pkg.mod") and under the name
    measured from the repository root ("src.pkg.mod"), the way a test
    harness often imports it.

    A directory holding Python files but no __init__.py is a namespace
    package; find_namespace_package() answers for those, without listing
    every ancestor directory of every file here.
    """
    package_directories = set()
    for path in python_paths:
        if posixpath.basename(path) in ("__init__.py", "__init__.pyi"):
            package_directories.add(posixpath.dirname(path))

    index = {}
    import_roots = {}
    for path in python_paths:
        import_root = python_import_root(path, package_directories)
        import_roots[path] = import_root
        # With the repository root as import root both names are the same,
        # so the file is filed once.
        if import_root == "":
            roots = ("",)
        else:
            roots = (import_root, "")
        for root in roots:
            name = python_module_name(path, root)
            if name is None or name == "":
                continue
            if name not in index:
                index[name] = []
            index[name].append((root, path))

    # Shortest root first, then a package's __init__.py (Python loads it
    # before a same-named module beside the directory), then path order, so
    # 'mod.py' wins over 'mod.pyi'. The resolver breaks ties in this order.
    for name in index:
        index[name].sort(key=python_candidate_order)
    return index, import_roots, package_directories


def python_candidate_order(pair):
    """Sort key for one (import_root, path) candidate of a module name."""
    root, path = pair
    return (len(root), posixpath.basename(path) != "__init__.py", path)


def find_namespace_package(dotted_name, python_paths, package_directories):
    """The directory a dotted name names when it is a namespace package, or None.

    Since Python 3.3 a directory holding Python files but no __init__.py is a
    (namespace) package: 'from core import notify' works with no __init__.py
    anywhere. python_paths is sorted, so one binary search finds whether any
    file sits under the directory.
    """
    if dotted_name == "":
        return None
    directory = dotted_name.replace(".", "/")
    if directory in package_directories:
        return None
    if directory_holds_python_files(directory, python_paths):
        return directory
    return None


def directory_holds_python_files(directory, python_paths):
    """Whether any of the sorted python_paths sits under directory."""
    prefix = directory + "/"
    position = bisect.bisect_left(python_paths, prefix)
    return position < len(python_paths) and python_paths[position].startswith(prefix)


def dotted_parts(node):
    """['a', 'b', 'c'] for the expression a.b.c, or None for anything else."""
    parts = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    parts.reverse()
    return parts


def make_python_request(target, level, kind, symbols, line, conditional):
    """One import statement, in the shape the resolver stage consumes."""
    return {
        "target": target,
        "level": level,
        "kind": kind,
        "symbols": symbols,
        "line": line,
        "conditional": conditional,
        "dynamic": False,
        "computed": False,
        "star": False,
        "type_only": False,
        "binding": None,
    }


def collect_python_imports(tree, results, limit):
    """Append one request per imported module, marking conditional ones.

    Returns how many requests were left out because results already held
    `limit` of them.

    The walk keeps its own stack of (node, inside_block) pairs instead of
    recursing, so a long elif chain cannot hit the recursion limit.
    inside_block says whether the node sits inside a function, class, if,
    try, loop, with or match, where an import may not run every time.
    Expressions are not entered: no import statement can sit inside one.
    """
    left_out = 0
    pending = [(tree, False)]
    while len(pending) > 0:
        node, inside_block = pending.pop()
        if isinstance(node, ast.Import):
            for alias in node.names:
                if len(results) >= limit:
                    left_out += 1
                    continue
                request = make_python_request(
                    alias.name, 0, "import", [], node.lineno, inside_block
                )
                if alias.asname is None:
                    request["binding"] = alias.name
                else:
                    request["binding"] = alias.asname
                results.append(request)
            continue
        if isinstance(node, ast.ImportFrom):
            module_name = node.module
            if module_name is None:
                module_name = ""
            # __future__ is never a file in the repository.
            if node.level == 0 and module_name == "__future__":
                continue
            if len(results) >= limit:
                left_out += 1
                continue
            symbols = []
            star = False
            for alias in node.names:
                if alias.name == "*":
                    star = True
                else:
                    # The name as the target defines it: 'as' renames it
                    # locally, and the graph is about what the target has.
                    symbols.append(alias.name)
            if star:
                kind = "star-import"
                symbols = []
            else:
                kind = "from-import"
            request = make_python_request(
                module_name, node.level, kind, symbols,
                node.lineno, inside_block,
            )
            request["star"] = star
            results.append(request)
            continue
        children_inside_block = inside_block or isinstance(node, PYTHON_BLOCK_NODES)
        children = []
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, ast.expr):
                children.append((child, children_inside_block))
        # Reversed onto the stack, so statements come off it in source order.
        children.reverse()
        pending.extend(children)
    return left_out


def longest_bound_prefix(parts, bound_modules, max_prefix_parts):
    """How many leading components of a dotted chain name a bound module.

    0 when none does. Prefixes are built left to right, and the search stops
    at max_prefix_parts, the number of parts in the longest bound name.
    """
    highest = len(parts) - 1
    if highest > max_prefix_parts:
        highest = max_prefix_parts
    prefix = ""
    matched_cut = 0
    for cut in range(1, highest + 1):
        if cut == 1:
            prefix = parts[0]
        else:
            prefix = prefix + "." + parts[cut - 1]
        if prefix in bound_modules:
            matched_cut = cut
    return matched_cut


def collect_python_attribute_uses(tree, bound_modules):
    """{module_name: sorted attribute names} reached through a module alias.

    'from X import a' names its symbols outright; 'import X' does not, so the
    names crossing that arrow are recovered from attribute chains. The longest
    bound prefix wins, so 'a.b.foo()' after 'import a.b' yields 'foo'.

    The walk reads only the outermost node of each dotted chain: 'a.b.c.d'
    is one chain.
    """
    uses = {}
    if len(bound_modules) == 0:
        # No 'import X' in this file, so no attribute chain can name a module.
        return uses

    max_prefix_parts = 1
    for name in bound_modules:
        parts_in_name = name.count(".") + 1
        if parts_in_name > max_prefix_parts:
            max_prefix_parts = parts_in_name

    pending = [tree]
    while len(pending) > 0:
        node = pending.pop()
        if isinstance(node, ast.Attribute):
            parts = dotted_parts(node)
            if parts is not None:
                cut = longest_bound_prefix(parts, bound_modules, max_prefix_parts)
                if cut > 0:
                    module_name = bound_modules[".".join(parts[:cut])]
                    if module_name not in uses:
                        uses[module_name] = set()
                    uses[module_name].add(parts[cut])
                # Everything under this node is part of the same chain.
                continue
        for child in ast.iter_child_nodes(node):
            pending.append(child)

    result = {}
    for module_name in uses:
        result[module_name] = sorted(uses[module_name])
    return result


def python_call_is_dynamic_import(func_node):
    """True for __import__(...), importlib.import_module(...) and
    importlib.__import__(...).

    Other importlib calls, such as importlib.metadata.version("pkg") or
    importlib.reload(x), import no new module, and a bare attribute name such
    as load_module could be any object's method.
    """
    if isinstance(func_node, ast.Name):
        return func_node.id == "__import__"
    parts = dotted_parts(func_node)
    if parts is None:
        return False
    return parts == ["importlib", "import_module"] or parts == ["importlib", "__import__"]


def collect_python_dynamic_imports(tree, results, limit):
    """Append a request per __import__/importlib call, literal or not.

    Returns how many were left out because results already held `limit`
    requests.
    """
    left_out = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not python_call_is_dynamic_import(node.func):
            continue
        if len(results) >= limit:
            left_out += 1
            continue
        specifier = None
        if len(node.args) >= 1:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                specifier = first.value
        if specifier is None:
            request = make_python_request(
                "(computed)", 0, "dynamic-import", [], node.lineno, False
            )
            request["computed"] = True
        else:
            request = make_python_request(
                specifier, 0, "dynamic-import", [], node.lineno, False
            )
        request["dynamic"] = True
        results.append(request)
    return left_out


def python_text_may_import_dynamically(source_text):
    """False only when no __import__ or importlib.import_module call can be in the text.

    Identifiers are NFKC-normalised by the parser, so a non-ASCII file always
    gets the full walk.
    """
    if not source_text.isascii():
        return True
    return "__import__" in source_text or "import_module" in source_text


def extract_python_dependencies(path, source_text):
    """(requests, honesty) for one Python file; requests is None if unparsable.

    ast.parse builds a syntax tree and executes nothing. The tree walks keep
    their own stacks; only the parse can run out of stack, and that is caught
    here.

    At most NETWORK_MAX_REQUESTS_PER_FILE requests are kept; the rest are
    counted in honesty["imports_past_file_cap"].
    """
    honesty = new_honesty_counts()
    requests = []
    try:
        tree = ast.parse(source_text, filename=path)
        left_out = collect_python_imports(
            tree, requests, NETWORK_MAX_REQUESTS_PER_FILE
        )
        bound_modules = {}
        for request in requests:
            if request["kind"] == "import" and request["binding"] is not None:
                bound_modules[request["binding"]] = request["target"]
        attribute_uses = collect_python_attribute_uses(tree, bound_modules)
        # Every 'import X' in one file resolves to the same files and the edge
        # merge unions their names, so only the first statement carries them.
        named_targets = set()
        for request in requests:
            if request["kind"] != "import":
                continue
            if request["target"] in named_targets:
                continue
            named_targets.add(request["target"])
            request["symbols"] = list(attribute_uses.get(request["target"], []))
        if python_text_may_import_dynamically(source_text):
            left_out += collect_python_dynamic_imports(
                tree, requests, NETWORK_MAX_REQUESTS_PER_FILE
            )
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None, honesty

    honesty["imports_past_file_cap"] = left_out
    for request in requests:
        if request["star"]:
            honesty["python_star_imports"] += 1
        if request["conditional"]:
            honesty["python_conditional_imports"] += 1
        if request["dynamic"]:
            honesty["python_dynamic_imports"] += 1
    return requests, honesty


def python_unresolved_reason(module_name):
    """Why an absolute Python module name matched no file at this commit.

    Never "external package": on Python 3.9 there is no
    sys.stdlib_module_names and the fallback list is short, so a standard
    library module can get the second answer, which is still true.
    """
    top_component = module_name.split(".")[0]
    stdlib_names = getattr(sys, "stdlib_module_names", None)
    if stdlib_names is None:
        stdlib_names = set(sys.builtin_module_names)
    if top_component in stdlib_names:
        return "standard library"
    return "not a file in this repository"


def python_relative_specifier(level, target):
    """How a relative import reads in the source, for the unresolved list."""
    return ("." * level) + target


def python_candidate_is_reachable(candidate_root, module_name, importer_path,
                                  importer_root, package_directories):
    """Whether this importer could reach a file filed under that root.

    A dotted module name names a file only when the directory it is measured
    from is on sys.path. Three such directories are certain:

      - the repository root, on sys.path whenever the project runs from it;
      - the importer's own root;
      - any directory the importer sits inside, which is sys.path[0] when a
        script in it is run.

    Any other root counts only when the name starts at a package (a
    directory holding __init__.py). So 'src/pkg/mod.py' is reachable as
    'pkg.mod', as a test harness imports it after putting 'src' on the path,
    while 'tools/logging.py' is not what 'import logging' means elsewhere in
    the repository: there it is the standard library.
    """
    if candidate_root == "":
        return True
    if candidate_root == importer_root:
        return True
    if importer_path.startswith(candidate_root + "/"):
        return True
    top_component = module_name.split(".")[0]
    return posixpath.join(candidate_root, top_component) in package_directories


def resolve_python_module(module_name, importer_path, importer_root, context,
                          honesty):
    """The file a dotted module name refers to for this importer, or None.

    Candidates this importer could not reach are discarded first. Of what is
    left, one measured from the importer's own root wins; otherwise the
    shortest root and then path order decide, and the choice is recorded as
    ambiguous whenever more than one reachable file answered to the name.

    Reachability depends only on the name, the importer's root and the
    importer's directory, so each answer is kept in context["module_memo"]
    for the rest of the build. A kept ambiguous answer still counts once per
    import.
    """
    memo_key = (module_name, importer_root, posixpath.dirname(importer_path))
    remembered = context["module_memo"].get(memo_key)
    if remembered is None:
        remembered = find_python_module(
            module_name, importer_path, importer_root,
            context["module_index"], context["package_directories"],
        )
        context["module_memo"][memo_key] = remembered
    path, ambiguous = remembered
    if ambiguous:
        honesty["ambiguous_python_modules"] += 1
    return path


def find_python_module(module_name, importer_path, importer_root, module_index,
                       package_directories):
    """(path or None, ambiguous) for resolve_python_module()."""
    candidates = module_index.get(module_name)
    if candidates is None or len(candidates) == 0:
        return None, False
    reachable = []
    for candidate_root, candidate_path in candidates:
        if python_candidate_is_reachable(candidate_root, module_name,
                                         importer_path, importer_root,
                                         package_directories):
            reachable.append((candidate_root, candidate_path))
    if len(reachable) == 0:
        return None, False
    for candidate_root, candidate_path in reachable:
        if candidate_root == importer_root:
            return candidate_path, False
    return reachable[0][1], len(reachable) > 1


def python_module_level_names(source_text):
    """Every name a module binds at its own top level, or None if unknowable.

    Settles what 'from pkg import name' imports. Python runs pkg/__init__.py
    first, and imports the submodule pkg/name.py only when __init__.py does
    not bind 'name'.

    Returns None when the answer cannot be known: the file did not parse, or
    it has a star import, which can bind anything.
    """
    try:
        tree = ast.parse(source_text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # Deep nesting raises MemoryError in CPython, not RecursionError.
        return None
    names = set()
    pending = list(tree.body)
    while len(pending) > 0:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue  # names bound inside a body are not module-level
        if isinstance(node, ast.Assign):
            for target in node.targets:
                collect_bound_names(target, names)
            continue
        if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            collect_bound_names(node.target, names)
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    names.add(alias.asname)
                else:
                    names.add(alias.name.split(".")[0])
            continue
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return None  # a star import can bind anything
                if node.level > 0 and node.module is None:
                    # 'from . import x' binds the submodule pkg.x, which the
                    # resolver finds itself.
                    continue
                names.add(alias.asname if alias.asname is not None else alias.name)
            continue
        # if / try / with / for at the top level still bind module-level names,
        # and so do the bodies of except and match clauses, which are not
        # statements themselves.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                pending.append(child)
                continue
            child_body = getattr(child, "body", None)
            if isinstance(child_body, list):
                for inner in child_body:
                    if isinstance(inner, ast.stmt):
                        pending.append(inner)
    return names


def collect_bound_names(target, names):
    """Add every plain name an assignment target binds."""
    if isinstance(target, ast.Name):
        names.add(target.id)
        return
    if isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            collect_bound_names(element, names)


def python_importer_is_inside(importer_path, directory):
    """Whether the importing file lives in this package directory or under it."""
    return importer_path.startswith(directory + "/")


def python_package_init_paths(module_path, importer_path, file_set):
    """The package __init__.py files this import makes Python run.

    'import a.b.c' imports a, then a.b, then a.b.c, so a/__init__.py and
    a/b/__init__.py both run and each gets an arrow. The walk stops at the
    first directory that is not a package, where the import root begins.

    A package the importer lives inside is skipped: its __init__.py ran
    before the importer could be imported, so this statement does not make
    it run.
    """
    initialisers = []
    directory = posixpath.dirname(module_path)
    while directory != "":
        candidate = first_existing(file_set, [
            posixpath.join(directory, "__init__.py"),
            posixpath.join(directory, "__init__.pyi"),
        ])
        if candidate is None:
            break
        if (candidate != module_path
                and not python_importer_is_inside(importer_path, directory)):
            initialisers.append(candidate)
        directory = posixpath.dirname(directory)
    initialisers.reverse()
    return initialisers


def resolve_python_namespace_package(request, directory, file_set, honesty):
    """(resolutions, unresolved) when a name resolved to a namespace package.

    A directory of modules with no __init__.py is a package in Python 3, so
    'from core import notify' reaches core/notify.py. A bare 'import core'
    has no file to point at and draws no arrow; it is counted in
    python_namespace_packages, never listed as "not a file in this
    repository".
    """
    resolutions = []
    unnamed = 0
    for symbol in request["symbols"]:
        submodule = first_existing(
            file_set, python_module_file_candidates(posixpath.join(directory, symbol))
        )
        if submodule is None:
            unnamed += 1
        else:
            resolutions.append({"path": submodule, "symbols": []})
    if len(resolutions) == 0 or unnamed > 0:
        # Either the package itself was imported, or a name in it is not a
        # module: nothing to point at, and the note says so.
        honesty["python_namespace_packages"] += 1
    return resolutions, None


def python_module_file_candidates(stem):
    """The files that can hold module <stem>, in the order Python tries them.

    A package directory with an __init__.py comes before a module file of the
    same name beside it. Stubs come last, as Python never loads a .pyi.
    """
    return [stem + "/__init__.py", stem + ".py", stem + ".pyi", stem + "/__init__.pyi"]


def resolve_python_request(request, importer_path, context, honesty):
    """(resolutions, unresolved) for one Python import statement.

    resolutions is [{"path", "symbols"}, ...]: one 'from . import a, b' can
    point at several files. unresolved is None or a
    {"specifier", "reason"} record; exactly one of the two carries the answer.

    context is what build_network_graph() works out once per commit:
    "module_index", "import_roots" and "package_directories" from
    build_python_module_index(), "python_paths" (sorted), "init_bindings",
    "file_set", "excluded_paths", and "module_memo" for
    resolve_python_module().
    """
    file_set = context["file_set"]
    importer_root = context["import_roots"].get(importer_path, "")
    target = request["target"]
    level = request["level"]

    if request["dynamic"]:
        if request["computed"]:
            return [], {
                "specifier": "(computed)",
                "reason": "dynamic import with a computed name",
            }
        path = resolve_python_module(target, importer_path, importer_root,
                                     context, honesty)
        if path is None:
            return [], {"specifier": target, "reason": "dynamic import"}
        return [{"path": path, "symbols": []}], None

    if level == 0:
        path = resolve_python_module(target, importer_path, importer_root,
                                     context, honesty)
        if path is None:
            # A directory of modules with no __init__.py is a namespace
            # package. The standard library still wins: a namespace portion is
            # only used when no regular module of that name exists anywhere on
            # sys.path, and every stdlib package is a regular one.
            directory = find_namespace_package(
                target, context["python_paths"], context["package_directories"]
            )
            if (directory is not None
                    and python_unresolved_reason(target) != "standard library"):
                return resolve_python_namespace_package(
                    request, directory, file_set, honesty
                )
            reason = python_unresolved_reason(target)
            if reason == "not a file in this repository":
                if python_stem_is_excluded(target.replace(".", "/"),
                                           context["excluded_paths"]):
                    reason = EXCLUDED_PATH_REASON
            return [], {"specifier": target, "reason": reason}
    else:
        base = posixpath.dirname(importer_path)
        # One level is the importer's own directory; each further dot climbs.
        for step in range(level - 1):
            if base == "":
                return [], {
                    "specifier": python_relative_specifier(level, target),
                    "reason": "relative import above the repository root",
                }
            base = posixpath.dirname(base)
        if target == "":
            # 'from . import x' means the package itself, never a sibling
            # '<base>.py' of the same name.
            package_stem = base
            path = first_existing(file_set, [
                posixpath.join(base, "__init__.py"),
                posixpath.join(base, "__init__.pyi"),
            ])
        else:
            package_stem = posixpath.join(base, target.replace(".", "/"))
            path = first_existing(file_set, python_module_file_candidates(package_stem))
        if path is None:
            # A directory with no __init__.py is a namespace package here too:
            # 'from . import helper' in ns/user.py reaches ns/helper.py. The
            # repository root is not one: a top-level script has no package.
            if (package_stem != ""
                    and package_stem not in context["package_directories"]
                    and directory_holds_python_files(package_stem,
                                                     context["python_paths"])):
                return resolve_python_namespace_package(
                    request, package_stem, file_set, honesty
                )
            if target != "" and python_stem_is_excluded(package_stem,
                                                        context["excluded_paths"]):
                reason = EXCLUDED_PATH_REASON
            else:
                reason = "relative import target not found"
            return [], {
                "specifier": python_relative_specifier(level, target),
                "reason": reason,
            }

    init_bindings = context["init_bindings"]
    resolutions = []
    symbols = list(request["symbols"])
    # A name imported from a package is a submodule of it only when the
    # package's __init__.py does not bind that name (see
    # python_module_level_names). When __init__.py could not be read or has
    # a star import, its bindings are unknown and the submodule is drawn.
    if request["kind"] == "from-import" and posixpath.basename(path) in (
        "__init__.py", "__init__.pyi"
    ):
        package_directory = posixpath.dirname(path)
        bound_here = init_bindings.get(path)
        remaining_symbols = []
        for symbol in symbols:
            if bound_here is not None and symbol in bound_here:
                remaining_symbols.append(symbol)  # the attribute wins
                continue
            submodule = first_existing(
                file_set,
                python_module_file_candidates(posixpath.join(package_directory, symbol)),
            )
            if submodule is None:
                remaining_symbols.append(symbol)
            else:
                resolutions.append({"path": submodule, "symbols": []})
        symbols = remaining_symbols
        # Importing anything out of a package runs its __init__.py first, so
        # it gets an arrow, unless the importer is inside the package, where
        # __init__.py ran before this statement.
        if (len(symbols) > 0
                or not python_importer_is_inside(importer_path, package_directory)):
            resolutions.append({"path": path, "symbols": symbols})
    elif len(symbols) > 0 or len(resolutions) == 0:
        resolutions.append({"path": path, "symbols": symbols})

    # Importing a.b.c also runs a/__init__.py and a/b/__init__.py.
    if level == 0:
        for initialiser in python_package_init_paths(path, importer_path, file_set):
            resolutions.append({"path": initialiser, "symbols": []})
    return resolutions, None


# The reason for an import landing on a symlink or a submodule: git lists
# those inside the repository, but this view does not read them.
EXCLUDED_PATH_REASON = (
    "a symlink or submodule at this commit, which this view does not read"
)


def has_excluded_parent(path, excluded_paths):
    """Whether a leading directory of path is a symlink or a submodule."""
    parts = path.split("/")
    for count in range(1, len(parts)):
        if "/".join(parts[:count]) in excluded_paths:
            return True
    return False


def python_stem_is_excluded(stem, excluded_paths):
    """Whether module path stem ('a/b/c') lands on or under a symlink or submodule.

    Every leading directory counts: 'import vendor.lib.core' lands inside a
    submodule at vendor/lib.
    """
    if len(excluded_paths) == 0:
        return False
    for candidate in [stem] + python_module_file_candidates(stem):
        if candidate in excluded_paths:
            return True
    return has_excluded_parent(stem, excluded_paths)


# --- JavaScript / TypeScript extraction ---

# The masking pass jumps between these instead of looping character by
# character: a 400 KB file has long stretches of ordinary code.
JS_SCAN_NEXT = re.compile(r"//|/\*|'|\"|`|/")

# A '/' starts a regular expression only after one of these; anywhere else it
# is division. The check looks at the previous significant character.
JS_REGEX_PRECEDING_CHARS = "(,=:[!&|?{};+-*%~^<>"
JS_REGEX_PRECEDING_WORDS = (
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "do", "else", "yield", "await", "case", "throw",
)

# In masked text a string literal is a run of NUL bytes between two quotes;
# the real specifier is read back out of the original source.
JS_SPEC_PATTERN = r"(?P<q>['\"`])(?P<body>\x00*)(?P=q)"
JS_CLAUSE_PATTERN = r"(?P<clause>[^;]{0," + str(NETWORK_MAX_CLAUSE_CHARS) + r"}?)"

JS_IMPORT_EQUALS = re.compile(
    r"\bimport\s+(?P<local>[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*"
    + JS_SPEC_PATTERN + r"\s*\)"
)
# import("./data.json", { with: { type: "json" } }) carries import
# attributes after a comma; they hold no parentheses.
JS_DYNAMIC_IMPORT = re.compile(
    r"\bimport\s*\(\s*" + JS_SPEC_PATTERN + r"\s*(?:,[^()]*)?\)"
)
# 'import.meta' and 'import(' are not the start of an import statement.
JS_FROM_IMPORT = re.compile(
    r"\bimport\b(?!\s*[.(])" + JS_CLAUSE_PATTERN + r"\bfrom\s*" + JS_SPEC_PATTERN
)
JS_EXPORT_FROM = re.compile(
    r"\bexport\b" + JS_CLAUSE_PATTERN + r"\bfrom\s*" + JS_SPEC_PATTERN
)
JS_REQUIRE = re.compile(r"\brequire\s*\(\s*" + JS_SPEC_PATTERN + r"\s*\)")
JS_BARE_IMPORT = re.compile(r"\bimport\s*" + JS_SPEC_PATTERN)
# Used to find import(/require( calls whose specifier is not a literal. The
# opening is matched first and the next character inspected afterwards: a
# negative lookahead here would be defeated by the \s* backtracking.
JS_CALL_OPEN = re.compile(r"\b(?P<callee>import|require)\s*\(\s*")
JS_REQUIRE_BINDING = re.compile(
    r"(?:const|let|var)\s+(?P<binding>\{[^{}]{0," + str(NETWORK_MAX_CLAUSE_CHARS)
    + r"}\}|[A-Za-z_$][\w$]*)\s*=\s*$"
)
# The text before a require() is searched this far back: what
# JS_REQUIRE_BINDING can match, plus room for 'const ' and ' = '.
JS_REQUIRE_WINDOW_CHARS = NETWORK_MAX_CLAUSE_CHARS + 64
# '} =' right before require(): a destructuring JS_REQUIRE_BINDING could not
# read (too long, or nested).
JS_DESTRUCTURING_END = re.compile(r"\}\s*=\s*$")
# Node's ESM loader and bundlers read a relative specifier as a URL, so a
# '?raw' or '#hash' suffix is not part of the file name.
JS_QUERY_OR_HASH = re.compile(r"[?#]")
JS_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
JS_NAMESPACE_CLAUSE = re.compile(r"^\*\s*as\s+([A-Za-z_$][\w$]*)$")
JS_LEADING_TYPE = re.compile(r"type\b\s*(.*)$", re.DOTALL)
JS_BLANK_LINE = re.compile(r"\n[ \t\r]*\n")

# Every literal in the masked text, used by the recovery pass below to find
# specifiers the fast 'import <clause> from' regex could not reach.
JS_ANY_SPEC = re.compile(JS_SPEC_PATTERN)
# The characters an import or export clause is allowed to contain: names,
# braces, commas, '*' and whitespace. Comments are already blanked to spaces.
JS_CLAUSE_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_${},* \t\r\n"
)
JS_CLAUSE_KEYWORD = re.compile(r"\b(?:import|export)\b")

# Extension ladders. The importer's own family is tried first, because a
# TypeScript project usually means the .ts file when both exist.
# '.d.ts' follows '.ts': './types' may be satisfied by a declaration file
# alone.
JS_TS_EXTENSION_ORDER = (".ts", ".tsx", ".d.ts", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
JS_JS_EXTENSION_ORDER = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".d.ts", ".mts", ".cts")
JS_REWRITTEN_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")
JS_TS_RETRY_EXTENSIONS = (".ts", ".tsx", ".d.ts", ".mts", ".cts")


def js_slash_starts_regex(masked_chars, index):
    """Whether the '/' at this index opens a regex literal rather than division.

    The scan runs backwards over the already-masked buffer, skipping
    whitespace and the bytes comments and strings were blanked with, until a
    real character turns up.
    """
    position = index - 1
    while position >= 0:
        character = masked_chars[position]
        if character in (" ", "\t", "\n", "\r", "\x00"):
            position -= 1
            continue
        break
    if position < 0:
        return True
    character = masked_chars[position]
    if character in JS_REGEX_PRECEDING_CHARS:
        return True
    if character.isalnum() or character in ("_", "$"):
        end = position + 1
        start = end
        while start > 0:
            previous = masked_chars[start - 1]
            if previous.isalnum() or previous in ("_", "$"):
                start -= 1
            else:
                break
        return "".join(masked_chars[start:end]) in JS_REGEX_PRECEDING_WORDS
    return False


def mask_js_source(source_text):
    """A same-length copy with comment, string and regex bodies blanked.

    Offsets and line numbers stay valid, so a match in the masked text can
    be read back out of the original. Returns (masked_text,
    interpolated_starts); the second holds the quote positions of template
    literals with a ${...}, whose specifier cannot be trusted.
    """
    chars = list(source_text)
    interpolated_starts = set()
    length = len(source_text)
    position = 0
    while position < length:
        match = JS_SCAN_NEXT.search(source_text, position)
        if match is None:
            break
        start = match.start()
        token = match.group(0)
        if token == "//":
            index = start
            while index < length and source_text[index] != "\n":
                chars[index] = " "
                index += 1
            position = index
        elif token == "/*":
            # Skip the opening pair first, or '/*/' would close the comment.
            chars[start] = " "
            chars[start + 1] = " "
            index = start + 2
            while index < length:
                if source_text.startswith("*/", index):
                    chars[index] = " "
                    chars[index + 1] = " "
                    index += 2
                    break
                # Newlines survive so line numbers stay right.
                if source_text[index] != "\n":
                    chars[index] = " "
                index += 1
            position = index
        elif token in ("'", '"'):
            quote = token
            index = start + 1
            while index < length:
                character = source_text[index]
                if character == "\\":
                    chars[index] = "\x00"
                    if index + 1 < length and source_text[index + 1] != "\n":
                        chars[index + 1] = "\x00"
                    index += 2
                    continue
                if character == quote:
                    index += 1
                    break
                # A raw newline ends a plain string: an apostrophe in prose
                # then damages one line instead of the rest of the file.
                if character == "\n":
                    break
                chars[index] = "\x00"
                index += 1
            position = index
        elif token == "`":
            index = start + 1
            has_interpolation = False
            while index < length:
                character = source_text[index]
                if character == "\\":
                    chars[index] = "\x00"
                    if index + 1 < length and source_text[index + 1] != "\n":
                        chars[index + 1] = "\x00"
                    index += 2
                    continue
                if character == "`":
                    index += 1
                    break
                if source_text.startswith("${", index):
                    has_interpolation = True
                if character != "\n":
                    chars[index] = "\x00"
                index += 1
            if has_interpolation:
                interpolated_starts.add(start)
            position = index
        else:
            if js_slash_starts_regex(chars, start):
                index = start + 1
                inside_class = False
                while index < length:
                    character = source_text[index]
                    if character == "\\":
                        chars[index] = "\x00"
                        if index + 1 < length and source_text[index + 1] != "\n":
                            chars[index + 1] = "\x00"
                        index += 2
                        continue
                    if character == "\n":
                        break
                    if character == "[":
                        inside_class = True
                    elif character == "]":
                        inside_class = False
                    elif character == "/" and not inside_class:
                        index += 1
                        break
                    chars[index] = "\x00"
                    index += 1
                position = index
            else:
                position = start + 1
    return "".join(chars), interpolated_starts


def js_line_starts(masked_text):
    """The offset every line begins at, computed once for the whole file.

    js_line_number() then finds a match's line with one binary search.
    """
    starts = [0]
    index = masked_text.find("\n")
    while index != -1:
        starts.append(index + 1)
        index = masked_text.find("\n", index + 1)
    return starts


def js_line_number(line_starts, index):
    """The 1-based line number of an offset, from js_line_starts()."""
    return bisect.bisect_right(line_starts, index)


def parse_js_import_clause(clause_text):
    """(symbols, star, type_only, unreadable) for the text before 'from'.

    Symbols are the names as the target exports them: 'A as B' records A, and
    a default import records 'default as B' because the target has no other
    name for it.
    """
    symbols = []
    star = False
    type_only = False
    unreadable = 0
    text = clause_text.strip()

    # 'import type Foo from x' is a type-only import; 'import type from x'
    # imports a default binding that happens to be called type.
    leading_type = JS_LEADING_TYPE.match(text)
    if leading_type is not None:
        rest = leading_type.group(1).strip()
        if rest != "":
            text = rest
            type_only = True

    brace_start = text.find("{")
    if brace_start == -1:
        head = text
        braced = ""
    else:
        head = text[:brace_start]
        brace_end = text.find("}", brace_start)
        if brace_end == -1:
            braced = text[brace_start + 1:]
        else:
            braced = text[brace_start + 1:brace_end]

    for piece in head.split(","):
        piece = piece.strip()
        if piece == "":
            continue
        if piece == "*":
            star = True
            continue
        namespace = JS_NAMESPACE_CLAUSE.match(piece)
        if namespace is not None:
            symbols.append("* as " + namespace.group(1))
            star = True
            continue
        if JS_IDENTIFIER.match(piece) is not None:
            symbols.append("default as " + piece)
        else:
            unreadable += 1

    braced_total = 0
    braced_typed = 0
    for piece in braced.split(","):
        piece = piece.strip()
        if piece == "":
            continue
        braced_total += 1
        member_type = JS_LEADING_TYPE.match(piece)
        if member_type is not None and member_type.group(1).strip() != "":
            piece = member_type.group(1).strip()
            braced_typed += 1
        name = re.split(r"\s+as\s+", piece, maxsplit=1)[0].strip()
        if JS_IDENTIFIER.match(name) is not None:
            symbols.append(name)
        else:
            # A masked string export name, or something this scan cannot read.
            unreadable += 1

    # Type-only when every braced name carries 'type' and nothing is bound
    # before them.
    if braced_total > 0 and braced_typed == braced_total and head.strip() == "":
        type_only = True

    return symbols, star, type_only, unreadable


def parse_js_require_binding(binding_text):
    """(symbols, star, unreadable) for what a require() call was assigned to.

    A bare name binds the whole module object, which is the CommonJS
    equivalent of a namespace import; a destructuring pattern names its parts.
    """
    text = binding_text.strip()
    if text.startswith("{"):
        symbols, star, type_only, unreadable = parse_js_import_clause(text)
        return symbols, star, unreadable
    if JS_IDENTIFIER.match(text) is not None:
        return ["* as " + text], True, 0
    return [], False, 0


def make_js_request(target, kind, symbols, line, star, dynamic, type_only,
                    unreadable_reason, symbols_unreadable=0):
    """One JavaScript/TypeScript import site, in the shared request shape.

    symbols_unreadable counts the names this statement imports that the
    scanner could not read (a string export name, a destructuring pattern),
    so an edge with an empty symbol list is not described as naming no
    symbols.
    """
    return {
        "target": target,
        "level": 0,
        "kind": kind,
        "symbols": symbols,
        "line": line,
        "conditional": False,
        "dynamic": dynamic,
        "computed": unreadable_reason is not None,
        "star": star,
        "type_only": type_only,
        "binding": None,
        "unresolvable_reason": unreadable_reason,
        "symbols_unreadable": symbols_unreadable,
    }


def js_computed_reason(kind):
    """The fixed reason wording for a specifier this scan cannot read."""
    if kind in ("require", "import-equals"):
        return "require with a computed specifier"
    return "dynamic import with a computed specifier"


def js_specifier_of_match(source_text, match, interpolated_starts):
    """(specifier, literal_span, computed) for a matched string literal.

    The masked text only says where the literal is; its characters are read
    back out of the original source. A backslash escape or a ${...} means the
    text on the page is not the module name, so it is never resolved.
    """
    quote_start = match.start("q")
    body_end = match.end("body")
    specifier = source_text[quote_start + 1:body_end]
    computed = quote_start in interpolated_starts or "\\" in specifier
    return specifier, (quote_start, body_end + 1), computed


def js_clause_is_sane(clause_text):
    """Whether a non-greedy import/export clause stayed inside one statement.

    A clause holding a blank line, or the word import or export, has run into
    the next statement (in semicolon-free code, or after TypeScript's
    'import X = A.B').
    """
    if JS_BLANK_LINE.search(clause_text) is not None:
        return False
    if JS_CLAUSE_KEYWORD.search(clause_text) is not None:
        return False
    return True


def js_clause_matches(masked_text, pattern, keyword):
    """Matches of an 'import|export ... from' pattern, re-scanning rejects.

    After a rejected match the search restarts right after its keyword, so
    the imports that clause ran across are still found.
    """
    matches = []
    position = 0
    while True:
        match = pattern.search(masked_text, position)
        if match is None:
            break
        if js_clause_is_sane(match.group("clause")):
            matches.append(match)
            position = match.end()
        else:
            position = match.start() + len(keyword)
    return matches


def js_is_name_char(character):
    """Whether a character can sit inside a JavaScript identifier."""
    return character.isalnum() or character == "_" or character == "$"


def js_statement_before_specifier(masked_text, quote_start, walk_budget):
    """The import/export statement whose 'from' ends at this specifier.

    Returns (keyword, clause_text, keyword_start), or ("too-long", None, None)
    when the walk ran past its bound, or None when this literal is not the
    specifier of an import at all. walk_budget is {"steps_left": n}, shared
    by every walk in one file; this raises FileTooComplex once it runs out.

    The statement is read backwards from its end: skip the 'from', walk back
    over the characters a clause may contain until something else turns up,
    and require the walk to have crossed an 'import' or 'export' keyword.
    The walk cannot run into the previous statement: what ends one (a
    semicolon, a bracket, an operator) is not a clause character. Names may
    hold any
    Unicode letter, and a quoted export name ('{ "a-b" as ab }') is stepped
    over whole; any other literal stops the walk.
    """
    position = quote_start
    while position > 0 and masked_text[position - 1] in " \t\r\n":
        position -= 1
    if position < 4 or masked_text[position - 4:position] != "from":
        return None
    before_from = position - 4
    if before_from > 0 and js_is_name_char(masked_text[before_from - 1]):
        # 'listFrom' rather than the keyword 'from'.
        return None

    walk = before_from
    lowest = before_from - NETWORK_MAX_LONG_CLAUSE_CHARS
    if lowest < 0:
        lowest = 0
    while walk > lowest:
        character = masked_text[walk - 1]
        if character in JS_CLAUSE_CHARS or js_is_name_char(character):
            walk -= 1
            continue
        if character in ("'", '"'):
            # Masked, a quoted name is a quote, a run of NUL bytes and the
            # same quote again.
            opening = walk - 2
            while opening >= lowest and masked_text[opening] == "\x00":
                opening -= 1
            if opening >= lowest and masked_text[opening] == character:
                walk = opening
                continue
        break
    walk_budget["steps_left"] -= before_from - walk
    if walk_budget["steps_left"] < 0:
        raise FileTooComplex()
    cut_short = walk == lowest and lowest > 0

    # The last keyword in the region is the nearest statement start, and the
    # clause is whatever follows it.
    region = masked_text[walk:before_from]
    found = None
    for match in JS_CLAUSE_KEYWORD.finditer(region):
        start_in_text = walk + match.start()
        end_in_text = walk + match.end()
        if start_in_text > 0 and js_is_name_char(masked_text[start_in_text - 1]):
            continue
        if end_in_text < len(masked_text) and js_is_name_char(masked_text[end_in_text]):
            continue
        found = match
    if found is None:
        if cut_short:
            return "too-long", None, None
        return None
    return found.group(0), region[found.end():], walk + found.start()


def js_recover_from_statements(masked_text, source_text, line_starts,
                               interpolated_starts, claimed_spans, honesty):
    """Requests for 'import … from' statements the fast regex could not match.

    JS_FROM_IMPORT and JS_EXPORT_FROM stop at NETWORK_MAX_CLAUSE_CHARS and
    refuse a clause holding a blank line, which misses a barrel import of
    forty names or a braced list grouped by blank lines. Every literal they
    left unclaimed goes to the backwards walk here. Raises FileTooComplex
    when the walks together pass NETWORK_MAX_WALK_STEPS_PER_FILE.
    """
    requests = []
    walk_budget = {"steps_left": NETWORK_MAX_WALK_STEPS_PER_FILE}
    for match in JS_ANY_SPEC.finditer(masked_text):
        specifier, span, computed = js_specifier_of_match(
            source_text, match, interpolated_starts
        )
        if span in claimed_spans:
            continue
        statement = js_statement_before_specifier(
            masked_text, match.start("q"), walk_budget
        )
        if statement is None:
            continue
        keyword, clause_text, keyword_start = statement
        if keyword == "too-long":
            honesty["js_clauses_too_long"] += 1
            continue
        claimed_spans.add(span)
        if keyword == "import":
            kind = "from-import"
        else:
            kind = "export-from"
        line = js_line_number(line_starts, keyword_start)
        if computed:
            requests.append(make_js_request(
                "(computed)", kind, [], line, False, False, False,
                js_computed_reason(kind),
            ))
            continue
        symbols, star, type_only, unreadable = parse_js_import_clause(clause_text)
        honesty["symbols_unreadable"] += unreadable
        requests.append(make_js_request(
            specifier, kind, symbols, line, star, False, type_only, None,
            unreadable,
        ))
    return requests


def extract_js_dependencies(path, source_text):
    """(requests, honesty) for one JavaScript/TypeScript file, lexical only.

    Nothing is parsed or executed: comments, strings and regexes are blanked,
    then a fixed set of import/require/export forms is matched over what is
    left. Patterns run in a fixed order and a literal already claimed by an
    earlier one is never matched again.
    """
    honesty = new_honesty_counts()
    masked_text, interpolated_starts = mask_js_source(source_text)
    line_starts = js_line_starts(masked_text)
    requests = []
    claimed_spans = set()

    # Nested so it shares requests and claimed_spans. (specifier, line), or None
    # when an earlier pattern owns the literal or it is computed (recorded here).
    def claim(match, kind, dynamic=False):
        specifier, span, computed = js_specifier_of_match(
            source_text, match, interpolated_starts
        )
        if span in claimed_spans:
            return None
        claimed_spans.add(span)
        line = js_line_number(line_starts, match.start())
        if computed:
            requests.append(make_js_request(
                "(computed)", kind, [], line, False, dynamic, False,
                js_computed_reason(kind),
            ))
            return None
        return specifier, line

    for match in JS_IMPORT_EQUALS.finditer(masked_text):
        claimed = claim(match, "import-equals")
        if claimed is None:
            continue
        specifier, line = claimed
        requests.append(make_js_request(
            specifier, "import-equals", ["* as " + match.group("local")],
            line, True, False, False, None,
        ))

    for match in JS_DYNAMIC_IMPORT.finditer(masked_text):
        claimed = claim(match, "dynamic-import", dynamic=True)
        if claimed is None:
            continue
        specifier, line = claimed
        requests.append(make_js_request(
            specifier, "dynamic-import", [], line, False, True, False, None,
        ))

    for keyword, pattern, kind in (
        ("import", JS_FROM_IMPORT, "from-import"),
        ("export", JS_EXPORT_FROM, "export-from"),
    ):
        for match in js_clause_matches(masked_text, pattern, keyword):
            claimed = claim(match, kind)
            if claimed is None:
                continue
            specifier, line = claimed
            symbols, star, type_only, unreadable = parse_js_import_clause(
                match.group("clause")
            )
            honesty["symbols_unreadable"] += unreadable
            requests.append(make_js_request(
                specifier, kind, symbols, line, star, False, type_only, None,
                unreadable,
            ))

    # Statements the two patterns above were too small to hold.
    requests.extend(js_recover_from_statements(
        masked_text, source_text, line_starts, interpolated_starts,
        claimed_spans, honesty,
    ))

    for match in JS_REQUIRE.finditer(masked_text):
        claimed = claim(match, "require")
        if claimed is None:
            continue
        specifier, line = claimed
        symbols = []
        star = False
        window_start = match.start() - JS_REQUIRE_WINDOW_CHARS
        if window_start < 0:
            window_start = 0
        unreadable = 0
        window_text = masked_text[window_start:match.start()]
        binding = JS_REQUIRE_BINDING.search(window_text)
        if binding is not None:
            symbols, star, unreadable = parse_js_require_binding(
                binding.group("binding")
            )
            honesty["symbols_unreadable"] += unreadable
        elif JS_DESTRUCTURING_END.search(window_text) is not None:
            # A destructuring that could not be read: its names are unknown.
            unreadable = 1
            honesty["symbols_unreadable"] += 1
        requests.append(make_js_request(
            specifier, "require", symbols, line, star, False, False, None,
            unreadable,
        ))

    for match in JS_BARE_IMPORT.finditer(masked_text):
        claimed = claim(match, "import")
        if claimed is None:
            continue
        specifier, line = claimed
        # Side-effect import: no name crosses the arrow.
        requests.append(make_js_request(
            specifier, "import", [], line, False, False, False, None,
        ))

    # Calls whose specifier is built at runtime: counted, never drawn. A call
    # starting with a literal is skipped only when a pattern above claimed
    # it, so require("./locale/" + lang) counts too.
    for match in JS_CALL_OPEN.finditer(masked_text):
        position = match.end()
        literal = JS_ANY_SPEC.match(masked_text, position)
        if literal is not None:
            literal_span = (literal.start("q"), literal.end("body") + 1)
            if literal_span in claimed_spans:
                continue
        callee = match.group("callee")
        if callee == "import":
            kind = "dynamic-import"
            dynamic = True
        else:
            kind = "require"
            dynamic = False
        requests.append(make_js_request(
            "(computed)", kind, [], js_line_number(line_starts, match.start()),
            False, dynamic, False, js_computed_reason(kind),
        ))

    requests.sort(key=lambda request: request["line"])
    # Past the per-file cap, statements are counted, not followed, and their
    # unreadable names leave the unreadable count.
    if len(requests) > NETWORK_MAX_REQUESTS_PER_FILE:
        left_out = requests[NETWORK_MAX_REQUESTS_PER_FILE:]
        del requests[NETWORK_MAX_REQUESTS_PER_FILE:]
        honesty["imports_past_file_cap"] = len(left_out)
        for request in left_out:
            honesty["symbols_unreadable"] -= request["symbols_unreadable"]
    for request in requests:
        if request["kind"] == "export-from":
            honesty["js_reexports"] += 1
        if request["kind"] == "dynamic-import":
            honesty["js_dynamic_imports"] += 1
        if request["star"]:
            honesty["js_namespace_imports"] += 1
    return requests, honesty


def resolve_js_specifier(specifier, importer_path, file_set):
    """(target_path, reason) for one specifier; exactly one is None.

    file_set is every path at the commit, source or not, so
    './styles.css' resolves to the file it names.
    """
    if specifier == "":
        return None, "no matching file at this commit"
    if specifier.startswith("/"):
        return None, "path outside the repository"
    if not specifier.startswith("."):
        # 'react', 'node:fs', '@/lib/x', '~/utils': this view does not read
        # tsconfig paths, bundler aliases or package.json exports, so these
        # are reported unresolved.
        return None, "bare or aliased specifier"

    target, reason = resolve_relative_js_specifier(specifier, importer_path, file_set)
    if target is None and reason == "no matching file at this commit":
        # './worker?worker', './logo.svg?raw': a query for the bundler. The
        # name as written was tried first, as CommonJS reads '?' and '#'
        # literally.
        stripped = JS_QUERY_OR_HASH.split(specifier, maxsplit=1)[0]
        if stripped != specifier:
            retry_target, _ = resolve_relative_js_specifier(
                stripped, importer_path, file_set
            )
            if retry_target is not None:
                return retry_target, None
    return target, reason


def resolve_relative_js_specifier(specifier, importer_path, file_set):
    """resolve_js_specifier() for a specifier starting with '.'."""
    # './utils/' names a directory: Node and the bundlers go straight to its
    # index file, even when a 'utils.js' sits next to the directory.
    wants_directory = specifier.endswith("/")
    stem = posixpath.normpath(
        posixpath.join(posixpath.dirname(importer_path), specifier)
    )
    if stem == ".." or stem.startswith("../"):
        return None, "path outside the repository"
    if stem == ".":
        # The specifier names the repository root directory itself; nothing
        # in the extension ladder below can match a directory.
        return None, "no matching file at this commit"

    if language_of_path(importer_path) == "typescript":
        extension_order = JS_TS_EXTENSION_ORDER
    else:
        extension_order = JS_JS_EXTENSION_ORDER

    if not wants_directory:
        if stem in file_set:
            return stem, None
        for extension in extension_order:
            if stem + extension in file_set:
                return stem + extension, None
        # TypeScript's ESM output rewrites '.ts' to '.js' in the specifier,
        # so a '.js' that matched nothing is retried as its TypeScript source.
        for written in JS_REWRITTEN_EXTENSIONS:
            if stem.endswith(written):
                base = stem[: -len(written)]
                for extension in JS_TS_RETRY_EXTENSIONS:
                    if base + extension in file_set:
                        return base + extension, None
                break
    for extension in extension_order:
        if stem + "/index" + extension in file_set:
            return stem + "/index" + extension, None
    if stem + "/package.json" in file_set:
        return None, "directory without an index file"
    return None, "no matching file at this commit"


def resolve_js_request(request, importer_path, file_set, excluded_paths=None):
    """(resolutions, unresolved) for one JavaScript/TypeScript import site."""
    if request["unresolvable_reason"] is not None:
        return [], {
            "specifier": request["target"],
            "reason": request["unresolvable_reason"],
            "symbols_unreadable": request.get("symbols_unreadable", 0),
        }
    target, reason = resolve_js_specifier(
        request["target"], importer_path, file_set
    )
    if target is None:
        if excluded_paths:
            # A relative specifier landing on a symlink or submodule, or
            # inside one, stays inside the repository.
            excluded_target, _ = resolve_js_specifier(
                request["target"], importer_path, excluded_paths
            )
            if excluded_target is not None:
                reason = EXCLUDED_PATH_REASON
            elif request["target"].startswith("."):
                stem = posixpath.normpath(posixpath.join(
                    posixpath.dirname(importer_path), request["target"]
                ))
                if has_excluded_parent(stem, excluded_paths):
                    reason = EXCLUDED_PATH_REASON
        return [], {"specifier": request["target"], "reason": reason}
    return [{"path": target, "symbols": list(request["symbols"])}], None


# --- Java ---

# A Java import names a class, never a file: "import a.b.C;" is matched
# against the fully qualified name of every class the repository declares.
# The target must be a dotted name, which keeps the match fast on a long line
# with no ';'. An import may also follow a ';' on the same line. A target
# split across lines or spaced around its dots is not matched.
JAVA_IMPORT_PATTERN = re.compile(
    r"(?m)(?:^|(?<=;))[ \t]*import[ \t]+(static[ \t]+)?"
    r"([\w$]+(?:\.[\w$]+)*(?:\.\*)?)[ \t]*;"
)
JAVA_PACKAGE_PATTERN = re.compile(r"(?m)^[ \t]*package[ \t]+([\w$.]+)[ \t]*;")
JAVA_TARGET_PATTERN = re.compile(r"[\w$]+(?:\.[\w$]+)*(?:\.\*)?")


def mask_java_source(source_text):
    """Blank out comments, strings and char literals, keeping every offset.

    The result has the same length and the same newlines as the input, so a
    match position still gives the right line number, while an import written
    inside a comment or a string cannot be mistaken for a real one.
    """
    result = list(source_text)
    length = len(source_text)
    index = 0
    while index < length:
        char = source_text[index]
        if char == "/" and index + 1 < length and source_text[index + 1] == "/":
            while index < length and source_text[index] != "\n":
                result[index] = " "
                index += 1
            continue
        if char == "/" and index + 1 < length and source_text[index + 1] == "*":
            result[index] = " "
            result[index + 1] = " "
            index += 2
            while index < length:
                if (source_text[index] == "*" and index + 1 < length
                        and source_text[index + 1] == "/"):
                    result[index] = " "
                    result[index + 1] = " "
                    index += 2
                    break
                if source_text[index] != "\n":
                    result[index] = " "
                index += 1
            continue
        # Text block (Java 15+): three quotes to three quotes.
        if char == '"' and source_text[index:index + 3] == '\"\"\"':
            result[index] = result[index + 1] = result[index + 2] = " "
            index += 3
            while index < length:
                if source_text[index:index + 3] == '\"\"\"':
                    result[index] = result[index + 1] = result[index + 2] = " "
                    index += 3
                    break
                if source_text[index] != "\n":
                    result[index] = " "
                index += 1
            continue
        if char == '"' or char == "'":
            quote = char
            result[index] = " "
            index += 1
            while index < length:
                if source_text[index] == "\\":
                    result[index] = " "
                    if index + 1 < length:
                        result[index + 1] = " "
                    index += 2
                    continue
                if source_text[index] == quote:
                    result[index] = " "
                    index += 1
                    break
                if source_text[index] == "\n":
                    # An unterminated literal must not blank the rest of the file.
                    break
                result[index] = " "
                index += 1
            continue
        index += 1
    return "".join(result)


def java_package_of(masked_text):
    """The declared package, or "" for the default package."""
    match = JAVA_PACKAGE_PATTERN.search(masked_text)
    if match is None:
        return ""
    return match.group(1)


def java_fully_qualified_name(package_name, path):
    """The name an import would use for the class this file declares."""
    class_name = path.rsplit("/", 1)[-1]
    class_name = class_name[:-len(".java")]
    if package_name == "":
        return class_name
    return package_name + "." + class_name


def build_java_class_index(java_packages):
    """(class_index, package_members) for every Java file read.

    java_packages maps a path to the package its file declares. class_index
    maps a fully qualified class name to the sorted list of files declaring
    it: a multi-module repository, or main and test trees, can hold two
    copies, and the resolver picks the one nearest the importer.
    package_members maps a package to the files in it, which is what
    "import a.b.*;" needs.
    """
    class_index = {}
    package_members = {}
    for path in sorted(java_packages):
        package_name = java_packages[path]
        fully_qualified = java_fully_qualified_name(package_name, path)
        if fully_qualified not in class_index:
            class_index[fully_qualified] = []
        class_index[fully_qualified].append(path)
        if package_name not in package_members:
            package_members[package_name] = []
        package_members[package_name].append(path)
    return class_index, package_members


def index_unread_java_files(unread_paths):
    """{class name: [paths]} for the Java files that were not read.

    A Java file is named after the public class it declares, so its file name
    is what an import can still be matched against when its package line was
    never read.
    """
    by_class_name = {}
    for path in sorted(unread_paths):
        class_name = posixpath.basename(path)[:-len(".java")]
        if class_name not in by_class_name:
            by_class_name[class_name] = []
        by_class_name[class_name].append(path)
    return by_class_name


def count_java_same_package_files(package_members):
    """Files sharing a package with at least one other file.

    Classes in one package use each other with no import, so imports draw
    no arrow between them.
    """
    total = 0
    for package_name in package_members:
        if len(package_members[package_name]) > 1:
            total += len(package_members[package_name])
    return total


def make_java_request(target, kind, symbols, line, star):
    """One Java import statement, in the shared request shape.

    repeat counts the identical statements this request stands for, and
    lines holds the first NETWORK_MAX_LINES_PER_EDGE of their line numbers.
    """
    return {
        "target": target,
        "level": 0,
        "kind": kind,
        "symbols": symbols,
        "line": line,
        "conditional": False,
        "dynamic": False,
        "computed": False,
        "star": star,
        "type_only": False,
        "binding": None,
        "unresolvable_reason": None,
        "repeat": 1,
        "lines": [line],
    }


def extract_java_dependencies(path, masked_text):
    """(requests, honesty) for one Java file, from its masked source.

    The caller masks it: the pass that finds the class each file declares
    reads the same masked text.

    A statement repeated word for word becomes one request with a repeat
    count, so a repeated package import fans out once. At most
    NETWORK_MAX_REQUESTS_PER_FILE distinct requests are kept; the statements
    behind the rest are counted in honesty["imports_past_file_cap"].
    """
    honesty = {"imports_past_file_cap": 0}
    requests = []
    request_by_statement = {}
    line = 1
    counted_up_to = 0
    for match in JAVA_IMPORT_PATTERN.finditer(masked_text):
        is_static = match.group(1) is not None
        target = match.group(2)
        if JAVA_TARGET_PATTERN.fullmatch(target) is None:
            continue
        # Newlines counted from the previous match.
        line += masked_text.count("\n", counted_up_to, match.start())
        counted_up_to = match.start()
        star = target.endswith(".*")
        if star:
            target = target[:-len(".*")]
        kind = "import-static" if is_static else "import"
        statement = (kind, target, star)
        request = request_by_statement.get(statement)
        if request is not None:
            request["repeat"] += 1
            if len(request["lines"]) < NETWORK_MAX_LINES_PER_EDGE:
                request["lines"].append(line)
            continue
        if len(requests) >= NETWORK_MAX_REQUESTS_PER_FILE:
            honesty["imports_past_file_cap"] += 1
            continue
        request = make_java_request(target, kind, [], line, star)
        request_by_statement[statement] = request
        requests.append(request)
    return requests, honesty


# The reason for an import that matched no file read here while an unread Java
# file has that class's name.
JAVA_UNREAD_REASON = "possibly a class in a Java file this view did not read"


def java_unresolved_reason(target):
    """Why a Java import names nothing in this repository.

    The same two wordings as for Python, so the page counts these imports in
    the same "points outside this repository" sentence.
    """
    if target.startswith("java.") or target.startswith("javax."):
        return "standard library"
    return "not a file in this repository"


def shared_directory_count(first_path, second_path):
    """How many leading directories two paths have in common."""
    first_parts = first_path.split("/")[:-1]
    second_parts = second_path.split("/")[:-1]
    shared = 0
    for first_part, second_part in zip(first_parts, second_parts):
        if first_part != second_part:
            break
        shared += 1
    return shared


def resolve_java_class(target, class_index, importer_path, honesty, repeat):
    """A class name to its file, shortening for nested classes, or None.

    "a.b.Outer.Inner" is declared inside the file of a.b.Outer, so the name is
    shortened one segment at a time until a declared class matches. When
    several files declare the class (two modules, main and test trees), the
    one sharing the most leading directories with the importer wins, then
    path order; a tie for nearest is counted in
    honesty["ambiguous_java_classes"], once per statement.
    """
    name = target
    while name != "":
        candidates = class_index.get(name)
        if candidates is not None:
            best_path = None
            best_shared = -1
            tied = False
            for candidate in candidates:
                shared = shared_directory_count(candidate, importer_path)
                if shared > best_shared:
                    best_path = candidate
                    best_shared = shared
                    tied = False
                elif shared == best_shared:
                    tied = True
            if tied:
                honesty["ambiguous_java_classes"] += repeat
            return best_path
        if "." not in name:
            return None
        name = name.rsplit(".", 1)[0]
    return None


def resolve_unread_java_class(target, unread_java):
    """(path, reason) for a class that no file read here declares.

    A file that was not read (too large, past a limit, not UTF-8) has no known
    package line, but by convention a.b.C lives at <source root>/a/b/C.java.
    When exactly one unread file sits there, it gets the arrow. When several
    could, or one only shares the class name, nothing is drawn and the reason
    says the class may be in a file this view did not read.
    """
    reason = java_unresolved_reason(target)
    name = target
    possible = False
    while "." in name:
        class_name = name.rsplit(".", 1)[1]
        candidates = unread_java.get(class_name, [])
        if len(candidates) > 0:
            possible = True
            suffix = name.replace(".", "/") + ".java"
            matches = []
            for candidate in candidates:
                if candidate == suffix or candidate.endswith("/" + suffix):
                    matches.append(candidate)
            if len(matches) == 1:
                return matches[0], None
            if len(matches) > 1:
                break
        name = name.rsplit(".", 1)[0]
    if possible and reason != "standard library":
        reason = JAVA_UNREAD_REASON
    return None, reason


def resolve_java_request(request, importer_path, class_index, package_members,
                         unread_java, honesty):
    """(resolutions, unresolved) for one Java import request.

    unread_java is index_unread_java_files() for the Java files that were
    not read; honesty receives the wildcard and ambiguity counts, once per
    statement the request stands for.
    """
    target = request["target"]
    repeat = request.get("repeat", 1)

    if request["star"] and request["kind"] == "import":
        # "import a.b.*;" names a package, so an arrow goes to every class of
        # it this repository declares; the file may in fact use only some.
        all_members = package_members.get(target, [])
        members = []
        for member in all_members:
            if member != importer_path:
                members.append(member)
        if len(members) > 0:
            honesty["java_wildcard_imports"] += repeat
            return [{"path": member, "symbols": []} for member in members], None
        if len(all_members) > 0:
            # The importer's own package, holding nothing else: an import of
            # itself, dropped and counted by the caller.
            return [{"path": importer_path, "symbols": []}], None
        # "import a.b.Outer.*;" names one class's nested classes: the arrow
        # goes to that file (the caller drops and counts it if that file is
        # the importer itself).
        owner = resolve_java_class(target, class_index, importer_path, honesty, repeat)
        if owner is None:
            owner, _ = resolve_unread_java_class(target, unread_java)
        if owner is not None:
            return [{"path": owner, "symbols": []}], None
        reason = java_unresolved_reason(target)
        if len(unread_java) > 0 and reason != "standard library":
            # No arrow from a directory match, but the package may be among
            # the files that were not read.
            reason = JAVA_UNREAD_REASON
        return [], {"specifier": target + ".*", "reason": reason}

    if request["kind"] == "import-static":
        # "import static a.b.C.member;" and "import static a.b.C.*;" both name
        # a class; only the trailing member differs.
        if request["star"]:
            class_target = target
            member_symbols = []
        else:
            parts = target.rsplit(".", 1)
            if len(parts) != 2:
                return [], {"specifier": target, "reason": java_unresolved_reason(target)}
            class_target = parts[0]
            member_symbols = [parts[1]]
        resolved = resolve_java_class(class_target, class_index, importer_path,
                                      honesty, repeat)
        if resolved is None:
            resolved, reason = resolve_unread_java_class(class_target, unread_java)
            if resolved is None:
                return [], {"specifier": target, "reason": reason}
        return [{"path": resolved, "symbols": member_symbols}], None

    resolved = resolve_java_class(target, class_index, importer_path, honesty, repeat)
    if resolved is None:
        resolved, reason = resolve_unread_java_class(target, unread_java)
        if resolved is None:
            return [], {"specifier": target, "reason": reason}
    return [{"path": resolved, "symbols": [target.rsplit(".", 1)[-1]]}], None


# --- Graph assembly ---


def add_network_link(links, importer_path, resolution, request, repeat):
    """Fold one resolved import into the per-(from, to) totals.

    Returns False when the link is a new pair and links already holds
    NETWORK_MAX_EDGE_PAIRS of them: it is then not gathered, and the caller
    counts it.

    Symbols are unioned and the flags ORed; 'kind' is the first statement by
    line and 'kinds' lists every distinct one. Only the lowest line numbers
    are kept, as only NETWORK_MAX_LINES_PER_EDGE of them are shown.
    """
    key = (importer_path, resolution["path"])
    link = links.get(key)
    if link is None:
        if len(links) >= NETWORK_MAX_EDGE_PAIRS:
            return False
        link = {
            "symbol_set": set(),
            "kind_set": set(),
            "first_line": request["line"],
            "first_kind": request["kind"],
            "star": False,
            "dynamic": False,
            "conditional": False,
            # True until the first value import.
            "type_only": True,
            "symbols_unreadable": 0,
            "count": 0,
            "line_set": set(),
            # Statements behind this pair that are dynamic imports, for the
            # count of dynamic imports that are drawn.
            "dynamic_count": 0,
        }
        links[key] = link
    for symbol in resolution["symbols"]:
        link["symbol_set"].add(symbol)
    link["kind_set"].add(request["kind"])
    if request["line"] < link["first_line"]:
        link["first_line"] = request["line"]
        link["first_kind"] = request["kind"]
    if request["star"]:
        link["star"] = True
    if request["dynamic"]:
        link["dynamic"] = True
        link["dynamic_count"] += repeat
    if request["conditional"]:
        link["conditional"] = True
    if not request["type_only"]:
        link["type_only"] = False
    link["symbols_unreadable"] += request.get("symbols_unreadable", 0)
    link["count"] += repeat
    for line in request.get("lines", [request["line"]]):
        link["line_set"].add(line)
    if len(link["line_set"]) > 2 * NETWORK_MAX_LINES_PER_EDGE:
        link["line_set"] = set(sorted(link["line_set"])[:NETWORK_MAX_LINES_PER_EDGE])
    return True


def network_edge(key, link):
    """The response's edge dict for one gathered (from, to) pair."""
    symbols = sorted(link["symbol_set"])
    symbol_count = len(symbols)
    symbols_truncated = False
    if symbol_count > NETWORK_MAX_SYMBOLS_PER_EDGE:
        symbols = symbols[:NETWORK_MAX_SYMBOLS_PER_EDGE]
        symbols_truncated = True
    return {
        "from": key[0],
        "to": key[1],
        "symbols": symbols,
        "symbol_count": symbol_count,
        "symbols_truncated": symbols_truncated,
        "kind": link["first_kind"],
        "kinds": sorted(link["kind_set"]),
        "star": link["star"],
        "dynamic": link["dynamic"],
        "conditional": link["conditional"],
        "type_only": link["type_only"],
        # Names this import carries that the scanner could not read.
        "symbols_unreadable": link["symbols_unreadable"],
        "count": link["count"],
        "lines": sorted(link["line_set"])[:NETWORK_MAX_LINES_PER_EDGE],
    }


def files_in_loops(pairs):
    """{path: loop number} for every file on an import loop of two or more.

    Tarjan's algorithm with an explicit stack instead of recursion, so a
    long chain of imports cannot hit the recursion limit. Files are visited
    in path order and each file's targets in sorted order, so the numbering
    is the same on every run.
    """
    targets_of = {}
    for source, target in sorted(pairs):
        if source not in targets_of:
            targets_of[source] = []
        targets_of[source].append(target)
    visit_order = {}
    lowest_reachable = {}
    on_stack = set()
    stack = []
    loop_of = {}
    loop_count = 0
    for start in sorted(targets_of):
        if start in visit_order:
            continue
        visit_order[start] = len(visit_order)
        lowest_reachable[start] = visit_order[start]
        stack.append(start)
        on_stack.add(start)
        # Each step is (file, how many of its targets were looked at).
        steps = [(start, 0)]
        while len(steps) > 0:
            path, done = steps[-1]
            targets = targets_of.get(path, [])
            if done < len(targets):
                steps[-1] = (path, done + 1)
                target = targets[done]
                if target not in visit_order:
                    visit_order[target] = len(visit_order)
                    lowest_reachable[target] = visit_order[target]
                    stack.append(target)
                    on_stack.add(target)
                    steps.append((target, 0))
                elif target in on_stack:
                    if visit_order[target] < lowest_reachable[path]:
                        lowest_reachable[path] = visit_order[target]
                continue
            steps.pop()
            if len(steps) > 0:
                parent = steps[-1][0]
                if lowest_reachable[path] < lowest_reachable[parent]:
                    lowest_reachable[parent] = lowest_reachable[path]
            if lowest_reachable[path] == visit_order[path]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.append(member)
                    if member == path:
                        break
                if len(members) > 1:
                    for member in members:
                        loop_of[member] = loop_count
                    loop_count += 1
    return loop_of


def choose_network_edges(pairs, changed_paths):
    """Which gathered pairs are drawn when there are more than NETWORK_MAX_EDGES.

    Returns (kept_pairs sorted, files_that_lost_links, loop_pairs_cut). Pairs
    touching a file the commit changed come first, then pairs inside an
    import loop, then the rest, each group in path order.
    files_that_lost_links lets the page draw a file whose arrows were cut
    differently from a file that has none.
    """
    if len(pairs) <= NETWORK_MAX_EDGES:
        return sorted(pairs), set(), 0
    loop_of = files_in_loops(pairs)
    touching_commit = []
    inside_loops = []
    rest = []
    for pair in sorted(pairs):
        source, target = pair
        if source in changed_paths or target in changed_paths:
            touching_commit.append(pair)
        elif source in loop_of and loop_of.get(target) == loop_of[source]:
            inside_loops.append(pair)
        else:
            rest.append(pair)
    ordered = touching_commit + inside_loops + rest
    kept = ordered[:NETWORK_MAX_EDGES]
    kept.sort()

    lost_links = set()
    loop_pairs_cut = 0
    for pair in ordered[NETWORK_MAX_EDGES:]:
        source, target = pair
        lost_links.add(source)
        lost_links.add(target)
        if source in loop_of and loop_of.get(target) == loop_of[source]:
            loop_pairs_cut += 1
    return kept, lost_links, loop_pairs_cut


# (blob id, path) -> read_source_file() answer. Most files are the same from
# one commit to the next, so each is parsed once. The cache is bounded by its
# number of records and by the import requests they hold; it is cleared whole
# when either bound would pass.
_SOURCE_FILE_CACHE = {}
_source_file_cache_requests = 0
MAX_SOURCE_FILE_CACHE = 20000
MAX_SOURCE_FILE_CACHE_REQUESTS = 500000


def read_source_file(path, language, blob):
    """Everything the network needs from one source file on its own.

    Returns {"text_ok", "lines", "requests", "honesty", "java_package",
    "init_bound", "unread_reason"}; text_ok is False when the file is not
    UTF-8. requests is None for a file that was not read, and unread_reason
    then says why when the reason is not "unparsable". The record is shared
    through the cache, so callers only read it.
    """
    record = {
        "text_ok": False,
        "lines": None,
        "requests": None,
        "honesty": None,
        "java_package": None,
        "init_bound": None,
        "unread_reason": None,
    }
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return record
    # ast.parse rejects a byte-order mark as an invalid character.
    if text.startswith(UTF8_BOM):
        text = text[1:]
    record["text_ok"] = True
    record["lines"] = count_text_lines(text)
    if language == "python":
        requests, file_honesty = extract_python_dependencies(path, text)
        if posixpath.basename(path) in ("__init__.py", "__init__.pyi"):
            record["init_bound"] = python_module_level_names(text)
    elif language == "java":
        # Only the package name is kept; the masked text is as big as the file.
        masked_text = mask_java_source(text)
        record["java_package"] = java_package_of(masked_text)
        requests, file_honesty = extract_java_dependencies(path, masked_text)
    else:
        try:
            requests, file_honesty = extract_js_dependencies(path, text)
        except FileTooComplex:
            requests = None
            file_honesty = new_honesty_counts()
            record["unread_reason"] = NETWORK_TOO_COMPLEX_REASON
    record["requests"] = requests
    record["honesty"] = file_honesty
    return record


def record_request_count(record):
    """How many import requests one cached record holds."""
    if record["requests"] is None:
        return 0
    return len(record["requests"])


def read_source_records(repo_root, entries, nodes_by_path):
    """{path: read_source_file() record} for the entries to parse.

    Only the files missing from the cache are read from git and parsed.
    """
    global _source_file_cache_requests
    records = {}
    missing_entries = []
    with _NETWORK_CACHE_LOCK:
        for entry in entries:
            cached = _SOURCE_FILE_CACHE.get((entry["blob"], entry["path"]))
            if cached is None:
                missing_entries.append(entry)
            else:
                records[entry["path"]] = cached
    contents = read_blob_contents(repo_root, missing_entries)
    new_records = {}
    new_requests = 0
    for entry in missing_entries:
        blob = contents.get(entry["blob"])
        if blob is None:
            continue
        language = nodes_by_path[entry["path"]]["language"]
        record = read_source_file(entry["path"], language, blob)
        records[entry["path"]] = record
        new_records[(entry["blob"], entry["path"])] = record
        new_requests += record_request_count(record)
    with _NETWORK_CACHE_LOCK:
        too_many_records = (
            len(_SOURCE_FILE_CACHE) + len(new_records) > MAX_SOURCE_FILE_CACHE
        )
        too_many_requests = (
            _source_file_cache_requests + new_requests > MAX_SOURCE_FILE_CACHE_REQUESTS
        )
        if too_many_records or too_many_requests:
            _SOURCE_FILE_CACHE.clear()
            _source_file_cache_requests = 0
        for key in new_records:
            if key in _SOURCE_FILE_CACHE:
                continue
            record = new_records[key]
            request_count = record_request_count(record)
            # A record that does not fit is not cached; it is parsed again
            # next time.
            if _source_file_cache_requests + request_count > MAX_SOURCE_FILE_CACHE_REQUESTS:
                continue
            _SOURCE_FILE_CACHE[key] = record
            _source_file_cache_requests += request_count
    return records


def build_network_graph(repo_root, commit, changed_paths):
    """Nodes, edges, unresolved, skipped and counts for one validated commit."""
    entries, excluded, excluded_paths, listing_stopped = list_tree_files(
        repo_root, commit["sha"]
    )
    files_at_commit = (
        len(entries)
        + excluded["symlinks"]
        + excluded["submodules"]
        + excluded["other"]
        + excluded["unlisted"]
        + excluded["too_deep"]
    )

    # Every path at the commit, so a JavaScript specifier naming a data file
    # or a stylesheet still resolves to something real.
    file_set = set()
    for entry in entries:
        file_set.add(entry["path"])

    nodes_by_path = {}
    readable_entries = []
    python_paths = []
    too_large_count = 0
    unsupported_code_files = 0
    for entry in entries:
        language = language_of_path(entry["path"])
        if language is None:
            # Not source code: counted, never drawn.
            excluded["other"] += 1
            continue
        node = {
            "path": entry["path"],
            "language": language,
            "analyzed": False,
            "reason": None,
            "changed_in_commit": entry["path"] in changed_paths,
            "uses": 0,
            "used_by": 0,
            "links_dropped": False,
            "size": entry["size"],
            "lines": None,
        }
        nodes_by_path[entry["path"]] = node
        if language == "python":
            # Listed even when it will not be read: it is still a valid
            # target for someone else's import.
            python_paths.append(entry["path"])
        if language == "unsupported":
            node["reason"] = "unsupported language"
            unsupported_code_files += 1
            continue
        if entry["size"] is None:
            # A partial clone lacks this source file, and BranchLens never
            # fetches.
            raise GitError(NETWORK_NOT_ON_DISK_MESSAGE)
        if entry["size"] > NETWORK_MAX_FILE_BYTES:
            node["reason"] = "too large"
            too_large_count += 1
            continue
        readable_entries.append(entry)

    # "code_files" is what the screen calls source code in a language this
    # view reads, so a Go or Rust file (code, never parsed) is not in it;
    # those are counted apart.
    code_files = len(nodes_by_path) - unsupported_code_files

    # Parse priority: the files this commit touched first, so a graph cut
    # short still covers the commit the user clicked on.
    changed_first = []
    other_files = []
    for entry in readable_entries:
        if entry["path"] in changed_paths:
            changed_first.append(entry)
        else:
            other_files.append(entry)
    ordered_entries = changed_first + other_files
    # The too-large files count too: they are source code in a language this
    # view reads.
    source_files_total = len(ordered_entries) + too_large_count

    parse_entries = []
    content_bytes = 0
    stopped = False
    for entry in ordered_entries:
        if not stopped:
            if len(parse_entries) >= NETWORK_MAX_SOURCE_FILES:
                stopped = True
            elif content_bytes + entry["size"] > NETWORK_MAX_CONTENT_BYTES:
                stopped = True
        if stopped:
            nodes_by_path[entry["path"]]["reason"] = "graph size limit reached"
        else:
            parse_entries.append(entry)
            content_bytes += entry["size"]
    source_files_read = len(parse_entries)

    records = read_source_records(repo_root, parse_entries, nodes_by_path)
    python_paths.sort()
    module_index, import_roots, package_directories = build_python_module_index(
        python_paths
    )

    # Java needs a whole-repository pass before any file can be resolved: an
    # import names a class, and only a file's own "package" line says which
    # class it declares.
    java_packages = {}
    # What each package __init__.py binds at its top level, settled before
    # any import is resolved: a file can import a package read after it.
    init_bindings = {}
    for entry in parse_entries:
        record = records.get(entry["path"])
        if record is None:
            continue
        if record["java_package"] is not None:
            java_packages[entry["path"]] = record["java_package"]
        if record["init_bound"] is not None:
            init_bindings[entry["path"]] = record["init_bound"]
    java_class_index, java_package_members = build_java_class_index(java_packages)
    # Java files that were not read can still be what an import names.
    unread_java_paths = []
    for path in nodes_by_path:
        if nodes_by_path[path]["language"] == "java" and path not in java_packages:
            unread_java_paths.append(path)
    unread_java = index_unread_java_files(unread_java_paths)

    # Everything the Python resolver needs, worked out once for the commit.
    python_context = {
        "module_index": module_index,
        "import_roots": import_roots,
        "package_directories": package_directories,
        "python_paths": python_paths,
        "init_bindings": init_bindings,
        "file_set": file_set,
        "excluded_paths": excluded_paths,
        "module_memo": {},
    }

    honesty = new_honesty_counts()
    honesty["java_same_package_files"] = count_java_same_package_files(
        java_package_members
    )
    # (from, to) -> what add_network_link() gathered for that pair.
    links = {}
    # Statements whose link was not gathered because links was full, and the
    # files at both ends of them.
    links_not_gathered = 0
    ungathered_ends = set()
    unresolved_groups = {}
    unresolved_total = 0
    # Files read and parsed, counted before any node is hidden.
    files_analyzed = 0

    for entry in parse_entries:
        path = entry["path"]
        node = nodes_by_path[path]
        record = records.get(path)
        if record is None:
            node["reason"] = "graph size limit reached"
            continue
        if not record["text_ok"]:
            node["reason"] = "not UTF-8 text"
            continue
        node["lines"] = record["lines"]

        language = node["language"]
        requests = record["requests"]
        add_honesty_counts(honesty, record["honesty"])
        if requests is None:
            node["reason"] = record["unread_reason"] or "unparsable"
            continue
        node["analyzed"] = True
        files_analyzed += 1

        for request in requests:
            if language == "python":
                resolutions, unresolved = resolve_python_request(
                    request, path, python_context, honesty
                )
            elif language == "java":
                resolutions, unresolved = resolve_java_request(
                    request, path, java_class_index, java_package_members,
                    unread_java, honesty
                )
            else:
                resolutions, unresolved = resolve_js_request(
                    request, path, file_set, excluded_paths
                )
            # A Java request can stand for several identical statements.
            repeat = request.get("repeat", 1)
            if unresolved is not None:
                unresolved_total += repeat
                key = (unresolved["specifier"], unresolved["reason"], language)
                group = unresolved_groups.get(key)
                if group is None:
                    group = {
                        "specifier": unresolved["specifier"],
                        "reason": unresolved["reason"],
                        "language": language,
                        "count": 0,
                        "example_set": set(),
                    }
                    unresolved_groups[key] = group
                group["count"] += repeat
                group["example_set"].add(path)
                continue
            for resolution in resolutions:
                if resolution["path"] == path:
                    honesty["self_imports_dropped"] += repeat
                    continue
                if not add_network_link(links, path, resolution, request, repeat):
                    links_not_gathered += repeat
                    ungathered_ends.add(path)
                    ungathered_ends.add(resolution["path"])

    edges_total = len(links)
    kept_pairs, lost_links, loop_pairs_cut = choose_network_edges(
        list(links), changed_paths
    )
    for path in ungathered_ends:
        lost_links.add(path)
    edges = []
    dynamic_drawn = 0
    for pair in kept_pairs:
        edges.append(network_edge(pair, links[pair]))
        dynamic_drawn += links[pair]["dynamic_count"]

    # A resolved target is always a node, even when it is not source code:
    # an arrow may never point at something the node list does not hold.
    # Counted, so the notes account for every file at the commit.
    promoted_nonsource = 0
    for edge in edges:
        for path in (edge["from"], edge["to"]):
            if path in nodes_by_path:
                continue
            promoted_nonsource += 1
            nodes_by_path[path] = {
                "path": path,
                "language": language_of_path(path),
                "analyzed": False,
                "reason": "not a source file",
                "changed_in_commit": path in changed_paths,
                "uses": 0,
                "used_by": 0,
                "links_dropped": False,
                "size": None,
                "lines": None,
            }
            if excluded["other"] > 0:
                excluded["other"] -= 1

    for edge in edges:
        nodes_by_path[edge["from"]]["uses"] += 1
        nodes_by_path[edge["to"]]["used_by"] += 1

    # A file whose arrows the edge limit cut says so on its own node: its
    # uses and used_by are smaller than what was read.
    for path in lost_links:
        node = nodes_by_path.get(path)
        if node is not None:
            node["links_dropped"] = True

    # Over NETWORK_MAX_NODES, files with no arrows are hidden in reverse path
    # order: first the ones the commit did not change, then, only if that was
    # not enough, the changed ones. A file whose arrows the edge limit cut
    # always stays.
    nodes_hidden = 0
    changed_nodes_hidden = 0
    for hiding_changed in (False, True):
        if len(nodes_by_path) <= NETWORK_MAX_NODES:
            break
        removable = []
        for path in sorted(nodes_by_path):
            node = nodes_by_path[path]
            if node["uses"] != 0 or node["used_by"] != 0 or node["links_dropped"]:
                continue
            if node["changed_in_commit"] == hiding_changed:
                removable.append(path)
        removable.reverse()
        for path in removable:
            if len(nodes_by_path) <= NETWORK_MAX_NODES:
                break
            del nodes_by_path[path]
            nodes_hidden += 1
            if hiding_changed:
                changed_nodes_hidden += 1

    nodes = []
    analyzed_count = 0
    skipped_all = []
    for path in sorted(nodes_by_path):
        node = nodes_by_path[path]
        nodes.append(node)
        if node["analyzed"]:
            analyzed_count += 1
        else:
            skipped_all.append({
                "path": node["path"],
                "reason": node["reason"],
                "size": node["size"],
                "language": node["language"],
            })
    skipped = skipped_all[:NETWORK_MAX_SKIPPED_ENTRIES]

    unresolved = []
    for key in unresolved_groups:
        group = unresolved_groups[key]
        unresolved.append({
            "specifier": group["specifier"],
            "language": group["language"],
            "reason": group["reason"],
            "count": group["count"],
            "examples": sorted(group["example_set"])[:5],
        })
    unresolved.sort(key=lambda group: (-group["count"], group["specifier"]))
    unresolved_groups_total = len(unresolved)
    unresolved = unresolved[:NETWORK_MAX_UNRESOLVED_GROUPS]
    unresolved_groups_shown = len(unresolved)

    bare_specifiers = 0
    outside_repository = 0
    excluded_from_repo = 0
    java_unread_targets = 0
    for group in unresolved_groups.values():
        if group["reason"] == "bare or aliased specifier":
            bare_specifiers += group["count"]
        if group["reason"] in ("standard library", "not a file in this repository"):
            outside_repository += group["count"]
        if group["reason"].startswith("a symlink or submodule at this commit"):
            excluded_from_repo += group["count"]
        if group["reason"] == JAVA_UNREAD_REASON:
            java_unread_targets += group["count"]

    truncated = (
        excluded["unlisted"] > 0
        or excluded["too_deep"] > 0
        or source_files_read < source_files_total
        or too_large_count > 0
        or len(edges) < edges_total
        or nodes_hidden > 0
        or unresolved_groups_shown < unresolved_groups_total
        or honesty["imports_past_file_cap"] > 0
        or links_not_gathered > 0
    )

    return {
        "nodes": nodes,
        "edges": edges,
        "unresolved": unresolved,
        "skipped": skipped,
        "honesty": honesty,
        "counts": {
            "files_at_commit": files_at_commit,
            "code_files": code_files,
            "analyzed": analyzed_count,
            "skipped": len(skipped_all),
            "nodes": len(nodes),
            "edges": len(edges),
            "unresolved_imports": unresolved_total,
            "changed_files": len(changed_paths),
            # Code this view recognises but never parses (Go, Rust, shell, …);
            # not part of code_files.
            "unsupported_code_files": unsupported_code_files,
            # How many distinct unresolved specifiers exist, and how many of
            # them the response carries.
            "unresolved_groups_total": unresolved_groups_total,
            "unresolved_groups_shown": unresolved_groups_shown,
        },
        "excluded": excluded,
        "truncation": {
            "source_files_read": source_files_read,
            "source_files_total": source_files_total,
            "edges_shown": len(edges),
            "edges_total": edges_total,
            "nodes_hidden": nodes_hidden,
            # How many of nodes_hidden the commit changed: hidden only when
            # the unchanged ones were not enough to reach NETWORK_MAX_NODES.
            "changed_nodes_hidden": changed_nodes_hidden,
            # True when the tree listing was stopped: excluded.unlisted, and so
            # counts.files_at_commit, are then lower bounds.
            "tree_listing_stopped": listing_stopped,
            # Import statements whose arrow was never gathered because
            # NETWORK_MAX_EDGE_PAIRS links already were: edges_total is then
            # a lower bound.
            "links_not_gathered": links_not_gathered,
        },
        "truncated": truncated,
        "files_analyzed": files_analyzed,
        "loop_pairs_cut": loop_pairs_cut,
        "dynamic_drawn": dynamic_drawn,
        "bare_specifiers": bare_specifiers,
        "outside_repository": outside_repository,
        "excluded_from_repo": excluded_from_repo,
        "java_unread_targets": java_unread_targets,
        "unsupported_code_files": unsupported_code_files,
        "promoted_nonsource": promoted_nonsource,
    }


def count_phrase(count, singular, plural):
    """"1 symlink is" / "3 symlinks are": a count with the right words after it."""
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural}"


def one_or_many(count, singular, plural):
    """singular when count is 1, else plural: for a word after the count."""
    if count == 1:
        return singular
    return plural


def network_notes(graph):
    """The plain sentences that say what this view could not see.

    One per non-zero counter, each agreeing with its count.
    """
    honesty = graph["honesty"]
    truncation = graph["truncation"]
    notes = []

    stars = honesty["python_star_imports"]
    if stars > 0:
        notes.append(
            count_phrase(stars, "star import (from X import *) was",
                         "star imports (from X import *) were") +
            " found: the names crossing " +
            one_or_many(stars, "that arrow are", "those arrows are") + " unknown."
        )
    dynamic_total = honesty["python_dynamic_imports"] + honesty["js_dynamic_imports"]
    if dynamic_total > 0:
        dynamic_drawn = graph["dynamic_drawn"]
        note = (
            count_phrase(dynamic_total, "import is", "imports are") +
            f" built at runtime; {dynamic_drawn} named a literal module and " +
            one_or_many(dynamic_drawn, "is", "are") + " drawn"
        )
        if dynamic_drawn < dynamic_total:
            note += ", the rest cannot be followed."
        else:
            note += "."
        notes.append(note)
    conditional = honesty["python_conditional_imports"]
    if conditional > 0:
        notes.append(
            count_phrase(conditional, "import sits", "imports sit") +
            " inside a function, a class or a block such as if, try or match, "
            "so " + one_or_many(conditional, "it", "they") +
            " may not happen on every run."
        )
    reexports = honesty["js_reexports"]
    if reexports > 0:
        notes.append(
            count_phrase(reexports, "re-export (export … from) passes",
                         "re-exports (export … from) pass") +
            " names straight through a file; this view does not follow " +
            one_or_many(reexports, "it", "them") +
            " to where the name was first defined."
        )
    namespaces = honesty["js_namespace_imports"]
    if namespaces > 0:
        notes.append(
            count_phrase(namespaces, "import pulls", "imports pull") +
            " in a whole module namespace, so any export may cross " +
            one_or_many(namespaces, "that arrow.", "those arrows.")
        )
    too_long = honesty["js_clauses_too_long"]
    if too_long > 0:
        notes.append(
            count_phrase(too_long, "import statement is", "import statements are") +
            f" longer than {NETWORK_MAX_LONG_CLAUSE_CHARS} characters and could "
            "not be read, so " +
            one_or_many(too_long, "its arrow is", "their arrows are") + " missing."
        )
    past_file_cap = honesty["imports_past_file_cap"]
    if past_file_cap > 0:
        notes.append(
            count_phrase(past_file_cap, "import was", "imports were") +
            f" not followed because a file held more than "
            f"{NETWORK_MAX_REQUESTS_PER_FILE} of them, so arrows from those "
            f"files may be missing."
        )
    wildcards = honesty["java_wildcard_imports"]
    if wildcards > 0:
        notes.append(
            count_phrase(wildcards, "import names", "imports name") +
            " a whole Java package, so an arrow is drawn to every class this "
            "repository declares in it; the file may use only some of them."
        )
    same_package = honesty["java_same_package_files"]
    if same_package > 0:
        notes.append(
            count_phrase(same_package, "of the Java files read shares",
                         "of the Java files read share") +
            " a package with another file. Classes in one package use each "
            "other with no import, so those arrows cannot be drawn here."
        )
    ambiguous_java = honesty["ambiguous_java_classes"]
    if ambiguous_java > 0:
        notes.append(
            count_phrase(ambiguous_java, "import names", "imports name") +
            " a Java class that more than one file declares, each as near "
            "as the other; the first in path order was used."
        )
    java_unread_targets = graph["java_unread_targets"]
    if java_unread_targets > 0:
        notes.append(
            count_phrase(java_unread_targets, "import names", "imports name") +
            " a Java class that may be declared in a file this view did not "
            "read, so no arrow is drawn for " +
            one_or_many(java_unread_targets, "it.", "them.")
        )
    ambiguous_python = honesty["ambiguous_python_modules"]
    if ambiguous_python > 0:
        notes.append(
            count_phrase(ambiguous_python, "import named a module",
                         "imports named a module") +
            " that matched more than one file; the closest match was used."
        )
    namespace_packages = honesty["python_namespace_packages"]
    if namespace_packages > 0:
        notes.append(
            count_phrase(namespace_packages, "import names", "imports name") +
            " a directory of modules that has no __init__.py. It is inside "
            "this repository, but there is no file to point an arrow at, so "
            "none is drawn."
        )
    unreadable = honesty["symbols_unreadable"]
    if unreadable > 0:
        notes.append(
            count_phrase(unreadable, "imported name", "imported names") +
            " could not be read (a string export name, or a destructuring "
            "pattern), so the " +
            one_or_many(unreadable,
                        "arrow that carries it lists fewer names than it really carries.",
                        "arrows that carry them list fewer names than they really carry.")
        )
    self_imports = honesty["self_imports_dropped"]
    if self_imports > 0:
        notes.append(
            count_phrase(self_imports, "import names the file it sits in",
                         "imports name the file they sit in") +
            ", so no arrow is drawn for " + one_or_many(self_imports, "it.", "them.")
        )
    outside = graph["outside_repository"]
    if outside > 0:
        # These imports name no file here: an installed package, the standard
        # library, or a name that matches nothing (a typo, a generated module).
        if graph["excluded"]["unlisted"] > 0:
            # Past the listing cap a file of this repository is not known, so
            # an import of it lands in this count too.
            what = (
                " at something that is not a file this view listed (an "
                "installed package, the standard library, a name that matches "
                "nothing here, or a file past the tree listing cap)"
            )
        else:
            what = (
                " at something that is not a file in this repository (an "
                "installed package, the standard library, or a name that "
                "matches nothing here)"
            )
        notes.append(
            count_phrase(outside, "import points", "imports point") + what +
            " and " + one_or_many(outside, "is", "are") +
            " listed separately, not drawn."
        )
    if graph["bare_specifiers"] > 0:
        notes.append(
            "Bare and aliased specifiers such as 'react' or '@/lib/x' are not "
            "resolved to files: this view does not read tsconfig or bundler "
            "aliases."
        )
    if truncation["source_files_read"] < truncation["source_files_total"]:
        notes.append(
            f"Only {truncation['source_files_read']} of " +
            count_phrase(truncation["source_files_total"], "source file was",
                         "source files were") +
            " read because of the size limit, so arrows from the rest are missing."
        )
    if truncation["edges_shown"] < truncation["edges_total"]:
        notes.append(
            f"{truncation['edges_shown']} of " +
            count_phrase(truncation["edges_total"], "arrow is", "arrows are") +
            " shown because of the size limit."
        )
    loop_pairs_cut = graph["loop_pairs_cut"]
    if loop_pairs_cut > 0:
        notes.append(
            count_phrase(loop_pairs_cut, "of the arrows cut was",
                         "of the arrows cut were") +
            " inside an import loop, so not every loop is drawn whole."
        )
    not_gathered = truncation["links_not_gathered"]
    if not_gathered > 0:
        notes.append(
            count_phrase(not_gathered, "import was", "imports were") +
            f" found after the graph already held {NETWORK_MAX_EDGE_PAIRS} "
            "distinct links, so " +
            one_or_many(not_gathered, "its arrow is", "their arrows are") +
            " missing and the real number of arrows is higher than any total "
            "shown here."
        )
    hidden = truncation["nodes_hidden"]
    changed_hidden = truncation["changed_nodes_hidden"]
    nodes_left = graph["counts"]["nodes"]
    if hidden > 0:
        sentence = (
            count_phrase(hidden, "file with no arrows was", "files with no arrows were")
            + " hidden"
        )
        if changed_hidden > 0:
            sentence += f" ({changed_hidden} of them changed in this commit)"
        if nodes_left <= NETWORK_MAX_NODES:
            sentence += f" to keep the graph at {NETWORK_MAX_NODES} nodes."
        else:
            sentence += (
                f", and the graph still holds {nodes_left} files: a file with "
                f"arrows, or whose arrows the size limit cut, is never hidden."
            )
        notes.append(sentence)
    elif nodes_left > NETWORK_MAX_NODES:
        notes.append(
            f"The graph holds {nodes_left} files, more than "
            f"{NETWORK_MAX_NODES}: a file with arrows, or whose arrows the size "
            f"limit cut, is never hidden."
        )
    unsupported = graph["unsupported_code_files"]
    if unsupported > 0:
        notes.append(
            count_phrase(unsupported, "file at this commit is",
                         "files at this commit are") +
            " code in a language this view does not read: what " +
            one_or_many(unsupported, "it uses", "they use") +
            " is unknown, though arrows into " + one_or_many(unsupported, "it", "them") +
            " from files that were read are still drawn. Such files are not "
            "counted as source code above."
        )
    symlinks = graph["excluded"]["symlinks"]
    if symlinks > 0:
        notes.append(
            count_phrase(symlinks, "symlink at this commit is",
                         "symlinks at this commit are") +
            " not followed: neither read nor drawn, and not counted as source "
            "code above."
        )
    submodules = graph["excluded"]["submodules"]
    if submodules > 0:
        notes.append(
            count_phrase(submodules, "submodule at this commit points",
                         "submodules at this commit point") +
            " at another repository, so nothing inside is read or drawn."
        )
    excluded_from_repo = graph["excluded_from_repo"]
    if excluded_from_repo > 0:
        notes.append(
            count_phrase(excluded_from_repo, "import points", "imports point") +
            " at a symlink or a submodule inside this repository. That does "
            "not leave the repository, but this view does not read " +
            one_or_many(excluded_from_repo, "it", "them") + ", so no arrow is drawn."
        )
    counts = graph["counts"]
    if counts["unresolved_groups_shown"] < counts["unresolved_groups_total"]:
        notes.append(
            f"{counts['unresolved_groups_shown']} of " +
            count_phrase(counts["unresolved_groups_total"],
                         "distinct unresolved specifier is",
                         "distinct unresolved specifiers are") +
            " listed; the rest are counted but not named."
        )
    other = graph["excluded"]["other"]
    if other > 0:
        notes.append(
            count_phrase(other, "other file at this commit is",
                         "other files at this commit are") +
            " not source code and " + one_or_many(other, "is", "are") + " not shown."
        )
    promoted = graph.get("promoted_nonsource", 0)
    if promoted > 0:
        notes.append(
            count_phrase(promoted, "file that is not source code is",
                         "files that are not source code are") +
            " drawn because an import points at " +
            one_or_many(promoted, "it.", "them.")
        )
    unlisted = graph["excluded"]["unlisted"]
    if truncation["tree_listing_stopped"]:
        notes.append(
            f"More than {unlisted} files at this commit were not even listed: "
            f"the tree holds more than {NETWORK_MAX_TREE_COUNT} entries, so "
            f"counting stopped there. Only the first "
            f"{NETWORK_MAX_TREE_ENTRIES} in path order were looked at, so "
            f"arrows from and to the rest are missing."
        )
    elif unlisted > 0:
        notes.append(
            count_phrase(unlisted, "file at this commit was",
                         "files at this commit were") +
            f" not even listed: the tree holds more than "
            f"{NETWORK_MAX_TREE_ENTRIES} entries, and only the first "
            f"{NETWORK_MAX_TREE_ENTRIES} in path order were looked at, so "
            f"arrows from and to the rest are missing."
        )
    too_deep = graph["excluded"]["too_deep"]
    if too_deep > 0:
        notes.append(
            count_phrase(too_deep, "file at this commit has a path",
                         "files at this commit have paths") +
            f" longer than {NETWORK_MAX_PATH_BYTES} bytes or deeper than "
            f"{NETWORK_MAX_PATH_PARTS} directories, so " +
            one_or_many(too_deep, "it is", "they are") +
            " neither read nor drawn, and arrows from and to " +
            one_or_many(too_deep, "it", "them") + " are missing."
        )
    return notes


def collect_commit_paths(repo_root, commit):
    """The set of paths one commit changed, compared with its first parent.

    Names only: collect_commit_files() also counts added and removed lines,
    which diffs every changed blob. -M keeps the set equal to that listing's:
    a renamed file appears under its new path only.
    """
    sha = commit["sha"]
    if len(commit["parents"]) >= 1:
        output = run_git(
            ["diff", "-M", "--name-only", "-z", sha + "^1", sha, "--"],
            cwd=repo_root,
        )
    else:
        # A root commit has no parent to diff against; 'git show' prints a
        # blank line before its listing even with --format=.
        output = run_git(
            ["show", "--root", "--format=", "-M", "--name-only", "-z", sha, "--"],
            cwd=repo_root,
        )
    text = output.decode("utf-8", errors="replace").lstrip("\n")
    paths = set()
    for path in text.split("\x00"):
        if path != "":
            paths.add(path)
    return paths


_NETWORK_CACHE = {}
_NETWORK_CACHE_LOCK = threading.Lock()
# Held while a network is built, so requests arriving together for one commit
# build it once. Separate from _NETWORK_CACHE_LOCK, which the build takes.
_NETWORK_BUILD_LOCK = threading.Lock()


def get_network(repo_root, commit_sha):
    """Dependency network for /api/network?commit=.

    The commit is validated as for /api/diff?commit= (see
    resolve_graph_commit) before the cache is consulted.
    """
    graph_commits = read_graph_commits(repo_root)
    commit = resolve_graph_commit(commit_sha, graph_commits)
    # The boundary commit of a shallow clone gets its own entry: deepening
    # the clone changes its answer without changing its sha.
    cache_key = commit["sha"]
    if commit_is_shallow_boundary(commit):
        cache_key = commit["sha"] + " shallow"

    with _NETWORK_CACHE_LOCK:
        cached = _NETWORK_CACHE.get(cache_key)
    if cached is not None:
        return cached

    with _NETWORK_BUILD_LOCK:
        # Another request may have built this commit while this one waited.
        with _NETWORK_CACHE_LOCK:
            cached = _NETWORK_CACHE.get(cache_key)
        if cached is not None:
            return cached
        response = build_network_response(repo_root, commit)
        with _NETWORK_CACHE_LOCK:
            if len(_NETWORK_CACHE) >= NETWORK_CACHE_ENTRIES:
                # Dicts keep insertion order: the first key is the oldest.
                oldest = next(iter(_NETWORK_CACHE))
                del _NETWORK_CACHE[oldest]
            _NETWORK_CACHE[cache_key] = response
    return response


def commit_is_shallow_boundary(commit):
    """Whether a graph-listing record is a shallow clone's boundary commit.

    Its parents are not in the clone, so a diff against them cannot be made.
    Records that do not carry the key are not boundaries.
    """
    return bool(commit.get("shallow_boundary", False))


def network_explanation(graph, subject, files_analyzed):
    """The one sentence under the notes, chosen by what was found."""
    truncation = graph["truncation"]
    if len(graph["edges"]) > 0:
        return (
            f'How the files at "{subject}" depend on each other; an arrow '
            f"points from a file to the file it uses."
        )
    if files_analyzed > 0:
        # Only files decoded and parsed count as read.
        return (
            f'No links between files were found at "{subject}", from the ' +
            count_phrase(files_analyzed, "source file that", "source files that") +
            " could be read."
        )
    if truncation["source_files_total"] > 0:
        # Files in a language this view reads exist here, but none could be
        # read.
        total_source = truncation["source_files_total"]
        if total_source == 1:
            return (
                f'The one source file at "{subject}" could not be read, so no '
                f"link between files could be found."
            )
        return (
            f"None of the {total_source} source files at "
            f'"{subject}" could be read, so no link between them could be '
            f"found."
        )
    not_looked_at = graph["excluded"]["unlisted"] + graph["excluded"]["too_deep"]
    if not_looked_at > 0:
        # Entries past the listing cap, or with paths too long to index, may
        # be source files.
        more = count_phrase(not_looked_at, "more was", "more were")
        if truncation["tree_listing_stopped"]:
            more = "more than " + more
        return (
            "No Python, JavaScript/TypeScript or Java files were found among "
            f'the entries looked at in "{subject}"; {more} not looked at, so '
            "source files may exist there."
        )
    return (
        f'No Python, JavaScript/TypeScript or Java files exist at '
        f'"{subject}", so there is nothing to link.'
    )


def build_network_response(repo_root, commit):
    """The /api/network answer for one validated commit, built from git."""
    shallow_boundary = commit_is_shallow_boundary(commit)
    if shallow_boundary:
        # Diffing would list the commit's whole tree as added: which files
        # it changed is unknown, so none is marked.
        changed_paths = set()
    else:
        changed_paths = collect_commit_paths(repo_root, commit)
    graph = build_network_graph(repo_root, commit, changed_paths)
    notes = network_notes(graph)
    if shallow_boundary:
        notes.insert(0, SHALLOW_BOUNDARY_SENTENCE)
    files_analyzed = graph["files_analyzed"]
    # Totals the notes and the explanation needed; the response does not
    # carry them.
    for internal_key in ("files_analyzed", "loop_pairs_cut", "dynamic_drawn",
                         "bare_specifiers", "outside_repository",
                         "excluded_from_repo", "java_unread_targets",
                         "unsupported_code_files", "promoted_nonsource"):
        del graph[internal_key]
    explanation = network_explanation(
        graph, truncate_subject(commit["subject"]), files_analyzed
    )

    response = {
        "commit": {
            "sha": commit["sha"],
            "short": commit["sha"][:7],
            "subject": commit["subject"],
        },
        "explanation": explanation,
        "notes": notes,
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "unresolved": graph["unresolved"],
        "skipped": graph["skipped"],
        "honesty": graph["honesty"],
        "counts": graph["counts"],
        "excluded": graph["excluded"],
        "limits": {
            "max_tree_entries": NETWORK_MAX_TREE_ENTRIES,
            "max_source_files": NETWORK_MAX_SOURCE_FILES,
            "max_file_bytes": NETWORK_MAX_FILE_BYTES,
            "max_nodes": NETWORK_MAX_NODES,
            "max_edges": NETWORK_MAX_EDGES,
            "max_symbols_per_edge": NETWORK_MAX_SYMBOLS_PER_EDGE,
        },
        "truncation": graph["truncation"],
        "truncated": graph["truncated"],
    }
    return response
