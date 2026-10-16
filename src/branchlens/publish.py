"""The one write BranchLens makes: pushing a branch after a passed security check.

This is the only file that runs git outside gitops.run_git() and its
read-only allow-list. When the user clicks Push and check_push() allows it,
push_branch() runs `git push` of the exact commit the check judged and, for
a branch with no upstream yet, `git branch --set-upstream-to` after it.
Branch tips, upstream remotes, remote-tracking refs and where a remote
points are read through gitops.
"""

import json
import os
import re
import signal
import stat
import subprocess
import time
from urllib.parse import unquote

from branchlens import gitops

PUSH_TIMEOUT_SECONDS = 120
# Setting the upstream only writes local config; it never waits on the network.
UPSTREAM_TIMEOUT_SECONDS = 30
# Only the end of a long push output is kept.
MAX_PUSH_OUTPUT_CHARS = 8000
# verdict.json and review-scope.json are small; anything bigger is not one.
MAX_VERDICT_FILE_BYTES = 2000000
READY_VERDICT = "READY TO PUBLISH"
# The base the toolkit reads as a first publish: it judges the whole history.
EMPTY_TREE_BASE = "empty-tree"
# A full commit id: 40 hex characters (SHA-1) or 64 (SHA-256).
FULL_COMMIT_ID = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Words from verdict.json and the feed are cut to this length inside reasons.
MAX_QUOTED_WORD_CHARS = 40
# A finding's title and file are cut to this length inside reasons.
MAX_QUOTED_TEXT_CHARS = 120
# `ssh -G` only reads the ssh config; it answers at once or not at all.
SSH_LOOKUP_TIMEOUT_SECONDS = 3
SSH_HOSTNAME_CACHE_SECONDS = 60
MAX_SSH_HOSTNAME_CACHE_ENTRIES = 256
# Environment variables that tell git which repository, work tree, index or
# object store to use. The push drops them: it runs in the branch's worktree.
GIT_LOCATION_VARIABLES = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
)
# The schemes whose address git reads itself. git ignores the host of a
# file:// URL and hands any other scheme to a git-remote-<scheme> helper.
NETWORK_SCHEMES = ("http", "https", "ssh", "git+ssh", "ssh+git", "git")
SSH_SCHEMES = ("ssh", "git+ssh", "ssh+git")
DEFAULT_PORTS = {"http": 80, "https": 443, "ssh": 22, "git": 9418}
RUNNING_REASON = "A security check is running: push once it has finished."
NO_VERDICT_REASON = "The latest security check has no verdict yet."
NO_FORK_REASON = ("The latest check does not record where the history it judged "
                  "starts (no review-scope.json or base_ref): run the check again.")
FORK_DISAGREES_REASON = ("The latest check's records disagree about where the history "
                         "it judged starts (review-scope.json and base_ref): run the "
                         "check again.")
BASE_MISMATCH_REASON = ("The latest check records another base than the one "
                        "BranchLens started it with: run the check again.")


def run_report_folder(reports_root, run_id):
    """The report folder of one run, or None when run_id is unusable.

    run_id comes from the feed, which the review's agents also write to, so
    only a plain folder name directly inside reports_root is accepted, and a
    symlink leading out of it is refused.
    """
    if not isinstance(run_id, str) or run_id in ("", ".", ".."):
        return None
    if "/" in run_id or "\\" in run_id or "\x00" in run_id:
        return None
    root_real = os.path.realpath(reports_root)
    folder_real = os.path.realpath(os.path.join(reports_root, run_id))
    if os.path.dirname(folder_real) != root_real:
        return None
    if not os.path.isdir(folder_real):
        return None
    return folder_real


def open_regular_file(path):
    """The file at path, opened for reading bytes, or None when it is missing or not a plain file.

    A FIFO would block the reader and /dev/zero never ends. O_NONBLOCK keeps
    the open itself from waiting on a FIFO.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        is_regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
    except OSError:
        is_regular = False
    if not is_regular:
        os.close(descriptor)
        return None
    return os.fdopen(descriptor, "rb")


def read_regular_file(path, limit):
    """The bytes of a plain file of at most limit bytes, or None."""
    regular_file = open_regular_file(path)
    if regular_file is None:
        return None
    try:
        with regular_file:
            data = regular_file.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit:
        return None
    return data


def read_json_object(path, limit):
    """The JSON object in a plain file of at most limit bytes, or None.

    ValueError covers bad JSON and an integer with too many digits;
    RecursionError covers a document nested too deeply to parse.
    """
    data = read_regular_file(path, limit)
    if data is None:
        return None
    try:
        value = json.loads(data.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict):
        return None
    return value


def read_verdict_file(folder):
    """The run's verdict.json as a dict, or None when it is missing or unreadable."""
    return read_json_object(os.path.join(folder, "verdict.json"), MAX_VERDICT_FILE_BYTES)


def read_review_scope(folder):
    """The run's review-scope.json as a dict, or None when it is missing or unreadable."""
    return read_json_object(os.path.join(folder, "review-scope.json"), MAX_VERDICT_FILE_BYTES)


def judged_branch_and_commit(verdict):
    """(branch, commit) the run judged, as verdict.json records them.

    Either is None when absent. The branch can be "HEAD" when the run
    judged a detached checkout.
    """
    if verdict is None:
        return None, None
    repository = verdict.get("repository")
    if not isinstance(repository, dict):
        return None, None
    branch = repository.get("branch")
    commit = repository.get("commit")
    if not isinstance(branch, str) or branch == "":
        branch = None
    if not isinstance(commit, str) or commit == "":
        commit = None
    return branch, commit


def foreign_repository_path(verdict, repo_root):
    """repository.path of a verdict that names another repository, else None.

    Repositories whose main folders share a name share one reports folder.
    The path is this repository when, symlinks resolved, it is the root or
    one of its worktrees (a worktree removed since does not count). A
    verdict with no path (older toolkits) or "?" passes; the commit it
    judged must still be the branch's tip.
    """
    if verdict is None:
        return None
    repository = verdict.get("repository")
    if not isinstance(repository, dict):
        return None
    path = repository.get("path")
    if not isinstance(path, str) or path in ("", "?"):
        return None
    real_path = os.path.realpath(path)
    if real_path == os.path.realpath(repo_root):
        return None
    _branch_to_worktree, worktree_paths, _raw = gitops.get_worktrees(repo_root)
    if real_path in worktree_paths:
        return None
    return path


def url_host(url):
    """The host a remote URL points at, lowercased; "" for a local path.

    git accepts three shapes: scheme://[user@]host[:port]/path, the scp-like
    [user@]host:path, and a plain path on this machine.
    """
    url = url.strip()
    if "://" in url:
        after_scheme = url.split("://", 1)[1]
        # git decodes %-escapes in this part: code.example%2eorg is
        # code.example.org.
        host_part = unquote(after_scheme.split("/", 1)[0])
        if "@" in host_part:
            host_part = host_part.rsplit("@", 1)[1]
        if host_part.startswith("["):
            # IPv6 literal: [::1]:22
            host = host_part[1:].split("]", 1)[0]
        else:
            host = host_part.split(":", 1)[0]
        return host.lower().rstrip(".")
    # git reads "host:path" as scp-like only when the colon comes before any
    # slash; "./a:b" or "/srv/a:b" are local paths.
    colon = url.find(":")
    slash = url.find("/")
    if colon <= 0 or (slash != -1 and slash < colon):
        return ""
    after_user = url
    at_sign = url.find("@")
    if at_sign != -1 and at_sign < colon:
        after_user = url[at_sign + 1:]
    if after_user.startswith("["):
        # [user@][2001:db8::1]:path, where the IPv6 literal holds colons of its own.
        closing = after_user.find("]")
        if closing != -1:
            return after_user[1:closing].lower().rstrip(".")
    host = url[:colon]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return host.strip("[]").lower().rstrip(".")


def url_repository(url):
    """(host, path) of a remote URL, or None for a local path or an unclear URL.

    The scheme, the user, the port, the slashes around the path and one
    trailing .git are left out, so https://host/owner/repo.git,
    ssh://git@host:22/owner/repo and git@host:owner/repo all give
    ("host", "owner/repo"). same_repository compares the port and the user
    with url_scheme_user_port. Only the schemes in NETWORK_SCHEMES and the
    scp-like form give a pair.
    """
    host = url_host(url)
    if host == "":
        return None
    url = url.strip()
    if "://" in url:
        scheme, after_scheme = url.split("://", 1)
        if scheme.lower() not in NETWORK_SCHEMES:
            return None
        if "/" not in after_scheme:
            return None
        path = after_scheme.split("/", 1)[1]
    else:
        # scp-like: [user@]host:path. A bracketed host holds colons of its
        # own; such URLs are left to the exact comparison.
        if "[" in url.split(":", 1)[0]:
            return None
        path = url.split(":", 1)[1]
        # host:/srv/app starts at the server's root and host:srv/app in the
        # user's home folder, so a path that starts with / matches nothing.
        if path.startswith("/"):
            return None
    # A server can read %-escapes or ~ (a home folder) one way over http
    # and another over ssh, so such paths match nothing.
    if "%" in path or "~" in path:
        return None
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[:-len(".git")].rstrip("/")
    if path == "":
        return None
    # curl removes . and .. from a path and a filesystem resolves them, so
    # two sides can read them differently.
    segments = path.split("/")
    if "." in segments or ".." in segments:
        return None
    return (host, path)


def url_scheme_user_port(url):
    """(scheme, user, port) of a URL url_repository reads, or None for an unclear port.

    The ssh schemes and the scp-like form all give "ssh". The user is "" when
    the URL names none. With no port the URL gives its scheme's default port.
    """
    url = url.strip()
    if "://" not in url:
        before_colon = url.split(":", 1)[0]
        user = ""
        if "@" in before_colon:
            user = before_colon.rsplit("@", 1)[0]
        return ("ssh", user, DEFAULT_PORTS["ssh"])
    scheme, after_scheme = url.split("://", 1)
    scheme = scheme.lower()
    if scheme in SSH_SCHEMES:
        scheme = "ssh"
    host_part = unquote(after_scheme.split("/", 1)[0])
    user = ""
    if "@" in host_part:
        user, host_part = host_part.rsplit("@", 1)
    if host_part.startswith("["):
        # IPv6 literal: [::1]:22. Anything after "]" other than ":port"
        # fails the isdigit test below.
        port_text = host_part.split("]", 1)[1] if "]" in host_part else ""
        if port_text.startswith(":"):
            port_text = port_text[1:]
    elif ":" in host_part:
        port_text = host_part.split(":", 1)[1]
    else:
        port_text = ""
    if port_text == "":
        return (scheme, user, DEFAULT_PORTS[scheme])
    if not port_text.isdigit():
        return None
    return (scheme, user, int(port_text))


def same_repository(fetch_urls, push_urls):
    """True when a remote fetches from one URL and pushes to one URL of the same repository.

    The two match when host and path match (see url_repository). Over one
    scheme the ports must match too, and two ssh URLs must name the same
    user: on a plain ssh server each user's paths start in their own home
    folder. Over two schemes, such as https to fetch and ssh to push, the
    port and the user are left out.
    """
    if len(fetch_urls) != 1 or len(push_urls) != 1:
        return False
    fetch_repository = url_repository(fetch_urls[0])
    if fetch_repository is None:
        return False
    if fetch_repository != url_repository(push_urls[0]):
        return False
    fetch_details = url_scheme_user_port(fetch_urls[0])
    push_details = url_scheme_user_port(push_urls[0])
    if fetch_details is None or push_details is None:
        return False
    fetch_scheme, fetch_user, fetch_port = fetch_details
    push_scheme, push_user, push_port = push_details
    if fetch_scheme != push_scheme:
        return True
    if fetch_port != push_port:
        return False
    if fetch_scheme == "ssh" and fetch_user != push_user:
        return False
    return True


def is_ssh_url(url):
    """True for a URL git reaches through ssh: ssh://, git+ssh://, ssh+git:// or scp-like."""
    url = url.strip()
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        return scheme in ("ssh", "git+ssh", "ssh+git")
    return url_host(url) != ""


# host as written -> (time looked up, HostName ssh resolves it to, or "").
_SSH_HOSTNAME_CACHE = {}


def ssh_hostname(host):
    """The HostName `ssh -G` resolves a host or Host alias to, or "".

    ssh only reads its config here and connects to nothing. "" when ssh is
    missing, fails or is slow. A custom core.sshCommand or a ProxyCommand
    can still reach another host. Answers are kept for
    SSH_HOSTNAME_CACHE_SECONDS: /api/security asks on every poll.
    """
    if host == "" or host.startswith("-"):
        return ""
    cached = _SSH_HOSTNAME_CACHE.get(host)
    if cached is not None and time.monotonic() - cached[0] < SSH_HOSTNAME_CACHE_SECONDS:
        return cached[1]
    resolved = ""
    try:
        # "--" ends the options: the host can never be read as one.
        result = subprocess.run(
            ["ssh", "-G", "--", host],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=SSH_LOOKUP_TIMEOUT_SECONDS,
        )
        if result.returncode == 0:
            for line in result.stdout.decode("utf-8", errors="replace").split("\n"):
                if line.startswith("hostname "):
                    resolved = line[len("hostname "):].strip().lower().rstrip(".")
                    break
    except (OSError, subprocess.SubprocessError):
        resolved = ""
    if len(_SSH_HOSTNAME_CACHE) >= MAX_SSH_HOSTNAME_CACHE_ENTRIES:
        _SSH_HOSTNAME_CACHE.clear()
    _SSH_HOSTNAME_CACHE[host] = (time.monotonic(), resolved)
    return resolved


def matching_blocked_suffix(host, blocked_host_suffixes):
    """The configured suffix this host falls under, or None.

    A suffix matches the host itself and every name under it: "example.org"
    matches "example.org" and "git.example.org", never "myexample.org".
    """
    if host == "":
        return None
    for suffix in blocked_host_suffixes:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None


def read_branch_tips(repo_root):
    """{branch name: commit id} for every local branch, read now."""
    branch_tips = {}
    for record in gitops.read_branch_records(repo_root)[1]:
        branch_tips[record["name"]] = record["commit"]
    return branch_tips


def current_tip(repo_root, branch):
    """The commit the branch points at right now, or None when there is no such branch."""
    return read_branch_tips(repo_root).get(branch)


def listed_branch_name(branch, branch_tips):
    """A recorded branch name as the branch listing spells it.

    The toolkit records `git rev-parse --abbrev-ref HEAD`, which prints
    "heads/<name>" when a tag has the same name as the branch.
    """
    if branch in branch_tips or not branch.startswith("heads/"):
        return branch
    if branch[len("heads/"):] in branch_tips:
        return branch[len("heads/"):]
    return branch


def find_push_directory(repo_root, branch):
    """The folder a push of this branch runs from: its worktree, else the repository root.

    The remote and its URLs are read from here too: with
    extensions.worktreeConfig a worktree has config the main checkout does
    not see.
    """
    branch_to_worktree, _all_paths, _raw = gitops.get_worktrees(repo_root)
    worktree_path = branch_to_worktree.get(branch)
    if worktree_path is None:
        return repo_root
    return worktree_path


def find_blocked_host(push_directory, remote_name, remote_urls, blocked_host_suffixes):
    """The first blocked host among the push remote's URLs and origin's, or None.

    origin is checked even when the push goes to another remote. For a URL
    reached through ssh, the HostName ssh resolves the host to is checked
    too, so an ssh alias for a blocked host counts as that host.
    """
    if len(blocked_host_suffixes) == 0:
        return None
    urls = list(remote_urls)
    if remote_name != "origin":
        urls = urls + gitops.read_remote_urls(push_directory, "origin")
    for url in urls:
        host = url_host(url)
        if matching_blocked_suffix(host, blocked_host_suffixes) is not None:
            return host
        if is_ssh_url(url):
            resolved = ssh_hostname(host)
            if matching_blocked_suffix(resolved, blocked_host_suffixes) is not None:
                return resolved
    return None


def quoted_word(value):
    """A word from verdict.json or the feed, as a reason quotes it."""
    return str(value)[:MAX_QUOTED_WORD_CHARS]


def quoted_text(value):
    """A finding's title or file from the feed, as a reason quotes it: one line, cut short."""
    text = str(value)
    for character in "\r\n\t":
        text = text.replace(character, " ")
    if len(text) > MAX_QUOTED_TEXT_CHARS:
        text = text[:MAX_QUOTED_TEXT_CHARS] + "…"
    return '"' + text + '"'


def verdict_problem(verdict, run_active, branch, tip, feed_verdict_word, cancelled,
                    blocking_finding):
    """Why the latest run does not allow a push of tip, or None when it does.

    feed_verdict_word is the final verdict word the feed holds for the run
    (None when it has none yet); cancelled is True when this server
    cancelled that run; blocking_finding is the first finding with
    blocking true the feed holds for the run, or None.
    """
    if run_active:
        return RUNNING_REASON
    if verdict is None:
        return NO_VERDICT_REASON
    verdict_word = verdict.get("verdict")
    if verdict_word == "PASSED":
        # Only the gate wrote this verdict: the LLM review did not run, was
        # stopped, failed, or has not merged its result yet.
        return ("The latest check has only the verdict of its mechanical "
                "checks (its LLM review did not run or did not finish): only "
                "READY TO PUBLISH allows a push.")
    if verdict_word != READY_VERDICT:
        return ("The latest check says " + str(verdict_word)
                + ": only READY TO PUBLISH allows a push.")
    # Missing in a gate-only verdict; False when the review could not
    # confirm its own merge.
    if verdict.get("review_merged") is not True:
        return ("The LLM review was not merged into the latest verdict, so it "
                "cannot allow a push.")
    # The toolkit writes review_merged and READY before it reads its own
    # merge back; review_confirmed is written only once that read-back
    # agreed. A run stopped in between leaves it out.
    if verdict.get("review_confirmed") is not True:
        return ("The latest check says READY TO PUBLISH, but the review was not "
                "confirmed by its read-back; run the check again.")
    # Only mode "check" judged a commit. A `check --worktree` verdict judged
    # uncommitted files but records HEAD as its commit; a verdict with any
    # other mode, or none, does not say what it judged.
    mode = verdict.get("mode")
    if mode == "check-worktree":
        return ("The latest check judged uncommitted work, not a commit: "
                "commit it and run the check again.")
    if mode != "check":
        if isinstance(mode, str) and mode != "":
            return ("The latest check did not judge a commit (mode "
                    + quoted_word(mode) + "): run the check again.")
        return ("The latest check does not record what it judged (its "
                "verdict.json has no mode): run the check again.")
    # verdict.json can say READY while the feed's last word is another one:
    # a Cancel after the review merged its result, for example.
    if cancelled:
        return "The latest check was cancelled: run it again."
    if feed_verdict_word is None:
        return ("The latest check has not written its final verdict to the "
                "feed yet: push once it has.")
    if feed_verdict_word != READY_VERDICT:
        return ("The latest check ended " + quoted_word(feed_verdict_word)
                + " in the feed, not READY TO PUBLISH: run the check again.")
    # A READY verdict next to a blocking finding means one of the two is wrong.
    if blocking_finding is not None:
        return ("The latest check holds a blocking finding, "
                + quoted_text(blocking_finding.get("title")) + " in "
                + quoted_text(blocking_finding.get("file"))
                + ", next to its READY TO PUBLISH: run the check again.")
    judged_commit = judged_branch_and_commit(verdict)[1]
    if judged_commit != tip:
        judged_short = (judged_commit or "?")[:7]
        return (branch + " has moved since the check (checked " + judged_short
                + ", now " + tip[:7] + "): run the check again.")
    return None


def has_control_character(text):
    """True when text holds a control character (newlines included)."""
    for character in text:
        if ord(character) < 32 or character == "\x7f":
            return True
    return False


def judged_merge_base(push_directory, base_commit, judged_commit):
    """The merge base of two commits as the toolkit found it, or None when
    they have none or git cannot tell."""
    try:
        fork_commit = gitops.find_judged_merge_base(push_directory, base_commit, judged_commit)
    except gitops.GitError:
        return None
    if not FULL_COMMIT_ID.fullmatch(fork_commit):
        return None
    return fork_commit


def judged_fork_commit(push_directory, folder, verdict, judged_commit):
    """(fork, None) for the commit after which the run's judged history starts,
    or (None, the reason it is unknown).

    The run judged fork..judged_commit. Two records say where that starts:
    verdict.json's base_ref, and the fork_commit of review-scope.json
    (written before the checks start) when its head_commit is judged_commit.

    - base_ref "empty-tree": the empty tree (the whole history).
    - base_ref a full commit id, as in every run BranchLens starts: the
      merge base of that commit and judged_commit, found again now.
    - base_ref another name, such as origin/main in a terminal run: the
      scope's fork, since the name may have moved; without a scope, the
      merge base the name gives now.
    - no base_ref: the scope's fork.

    A scope fork that differs from the one base_ref gives is refused, and
    so is the empty tree under any base_ref but "empty-tree".
    """
    empty_tree = gitops.empty_tree_id(judged_commit)
    scope_fork = None
    scope = read_review_scope(folder)
    if scope is not None and scope.get("head_commit") == judged_commit:
        fork_commit = scope.get("fork_commit")
        if isinstance(fork_commit, str) and FULL_COMMIT_ID.fullmatch(fork_commit):
            scope_fork = fork_commit

    base_ref = verdict.get("base_ref")
    if not isinstance(base_ref, str) or base_ref in ("", "?"):
        base_ref = None

    if base_ref == EMPTY_TREE_BASE:
        expected_fork = empty_tree
    elif base_ref is not None and FULL_COMMIT_ID.fullmatch(base_ref):
        expected_fork = judged_merge_base(push_directory, base_ref, judged_commit)
        if expected_fork is None:
            return None, NO_FORK_REASON
    else:
        # A name, or no base_ref at all: the scope's fork, if there is one.
        if scope_fork == empty_tree:
            return None, FORK_DISAGREES_REASON
        if scope_fork is not None:
            return scope_fork, None
        if base_ref is None or base_ref.startswith("-") or has_control_character(base_ref):
            return None, NO_FORK_REASON
        base_commit = gitops.read_ref_commit(push_directory, base_ref + "^{commit}")
        if not FULL_COMMIT_ID.fullmatch(base_commit):
            return None, NO_FORK_REASON
        expected_fork = judged_merge_base(push_directory, base_commit, judged_commit)
        if expected_fork is None:
            return None, NO_FORK_REASON
        return expected_fork, None

    if scope_fork is not None and scope_fork != expected_fork:
        return None, FORK_DISAGREES_REASON
    return expected_fork, None


def unjudged_history_problem(push_directory, folder, verdict, remote_name, tip,
                             started_base=None):
    """Why a push of tip would publish commits the check never judged, or None.

    A push sends every commit reachable from tip that the remote lacks. The
    run judged only fork..tip, so the commits reachable from the fork that
    no remote-tracking ref of the push remote reaches would go out
    unjudged. A fork at the empty tree means the whole history was judged.

    The remote-tracking refs only say what the fetch address has. A push to
    another address (a pushurl), or to several (more than one url), can
    reach a repository that lacks those commits, so such a remote is
    refused unless the whole history was judged. One exception: a single
    push URL that names the same host and path as the single fetch URL,
    over another transport.

    started_base is the base BranchLens handed to preflight.sh when it
    started this run itself, else None. The verdict must then record that
    same base. This catches a rewrite of that run's folder, not a run
    forged beside it: the run files and the feed are trusted.
    """
    if started_base is not None and verdict.get("base_ref") != started_base:
        return BASE_MISMATCH_REASON
    fork_commit, fork_problem = judged_fork_commit(push_directory, folder, verdict, tip)
    if fork_commit is None:
        return fork_problem
    if fork_commit == gitops.empty_tree_id(tip):
        return None
    fetch_urls, push_urls = gitops.read_fetch_and_push_urls(push_directory, remote_name)
    if push_urls != fetch_urls and not same_repository(fetch_urls, push_urls):
        return ("Push is refused: " + remote_name + " pushes to a different "
                "address than it fetches from, so BranchLens cannot tell what "
                "that address already has.")
    if len(push_urls) > 1:
        return ("Push is refused: " + remote_name + " pushes to "
                + str(len(push_urls)) + " addresses, so BranchLens cannot tell "
                "what each of them already has.")
    # --remotes= reads the name as a pattern.
    for character in "*?[\\":
        if character in remote_name:
            return ("The remote name " + remote_name + " holds the character "
                    + character + ", so the commits it already has cannot be "
                    "counted: push from a terminal.")
    try:
        count = gitops.count_commits_missing_on_remote(push_directory, fork_commit, remote_name)
    except gitops.GitError as error:
        return "The commits a push would send could not be counted: " + str(error)
    if count == 0:
        return None
    if count == 1:
        commits_text = "1 older commit"
    else:
        commits_text = str(count) + " older commits"
    return ("The check judged only " + fork_commit[:7] + ".." + tip[:7]
            + "; the push would also send " + commits_text + " it never "
            "judged: run the check from a commit " + remote_name + " already "
            "has, or compare from the beginning.")


def check_push(repo_root, reports_root, run_id, feed_running, feed_verdict_word,
               cancelled_run_id, run_active, active_branch, active_commit,
               blocked_host_suffixes, feed_findings, started_base=None):
    """Decide whether the Push button may be pressed right now.

    run_id, feed_running, feed_verdict_word and feed_findings describe the
    feed's latest run (feed_running: no verdict event after its start yet;
    feed_verdict_word: its final verdict word, None when it has none;
    feed_findings: its findings, as the feed fold lists them).
    cancelled_run_id is the feed's run_id at this server's last Cancel.
    run_active, active_branch and active_commit describe a run this server
    started (active_commit: the branch's tip when it started).
    started_base is the base this server handed to preflight.sh when the
    feed's latest run is one it started, else None.

    Returns the API's `push` fields (allowed, reason, branch, remote,
    commit), `judged` for /api/security, set_upstream and
    working_directory, which only the push uses, and foreign_repository
    (the path a verdict from another repository names, else None).
    `reason` is one line: why a push is not possible, or what it will run.

    Allowed only when no run is active; the latest run (the feed's last
    start marker) has a verdict.json from this repository saying READY TO
    PUBLISH with the LLM review merged and confirmed by its read-back; that
    verdict judged a commit, not a snapshot of uncommitted work; the run
    was not cancelled, the feed's final verdict is READY TO PUBLISH too and
    the feed holds no blocking finding for it; the commit it judged is
    still its branch's tip; neither the push remote nor origin is on a
    blocked host; the upstream, when the push goes there, has the branch's
    name; the remote-tracking ref of the branch is not already at that
    commit; the run's records agree on where its judged history starts
    (and name the base this server started it with); and, unless the check
    judged the whole history, the remote pushes to the one address it
    fetches from, which already has every commit before the history the
    check judged.
    """
    status = {
        "allowed": False,
        "reason": "",
        "branch": None,
        "remote": None,
        "commit": None,
        "judged": None,
        "set_upstream": False,
        "working_directory": None,
        "foreign_repository": None,
    }

    verdict = None
    folder = None
    if run_id is not None:
        folder = run_report_folder(reports_root, run_id)
        if folder is not None:
            verdict = read_verdict_file(folder)

    # A run on another repository with the same folder name says nothing
    # about this one.
    foreign_path = foreign_repository_path(verdict, repo_root)
    if foreign_path is not None:
        verdict = None
        status["foreign_repository"] = foreign_path

    # What the latest run judged; while a run started here has no verdict
    # yet, the branch it is judging and its tip at the start.
    branch, judged_commit = judged_branch_and_commit(verdict)
    if branch is None and run_active:
        branch = active_branch
        judged_commit = active_commit
    branch_tips = {}
    if branch is not None:
        branch_tips = read_branch_tips(repo_root)
        branch = listed_branch_name(branch, branch_tips)
    if branch is not None or judged_commit is not None:
        status["judged"] = {"branch": branch, "commit": judged_commit}

    if branch is None:
        if run_active:
            status["reason"] = RUNNING_REASON
        elif foreign_path is not None:
            status["reason"] = ("The latest check ran on another repository ("
                                + foreign_path + "): run it here.")
        elif run_id is None:
            status["reason"] = "No security check has run yet."
        elif not feed_running:
            status["reason"] = ("The latest check (" + run_id + ") left no "
                                "readable verdict.json: run it again.")
        else:
            status["reason"] = NO_VERDICT_REASON
        return status

    tip = None
    if not branch.startswith("-"):
        tip = branch_tips.get(branch)
    if tip is None:
        if branch == "HEAD":
            status["reason"] = ("The latest check judged a detached checkout, "
                                "not a branch: there is nothing to push.")
        else:
            status["reason"] = "The branch " + branch + " no longer exists."
        return status
    status["branch"] = branch
    status["commit"] = tip

    # The verdict's reason comes first; a problem with the remote is named
    # after it.
    cancelled = cancelled_run_id is not None and run_id == cancelled_run_id
    blocking_finding = None
    for finding in feed_findings:
        if finding.get("blocking") is True:
            blocking_finding = finding
            break
    verdict_reason = verdict_problem(verdict, run_active, branch, tip,
                                     feed_verdict_word, cancelled, blocking_finding)

    push_directory = find_push_directory(repo_root, branch)
    status["working_directory"] = push_directory
    push_facts = gitops.read_push_facts(push_directory, branch)
    remote_name = push_facts["remote"]
    remote_urls = gitops.read_remote_urls(push_directory, remote_name)
    upstream_branch = push_facts["upstream_branch"]
    remote_reason = None
    if len(remote_urls) == 0:
        remote_reason = "There is no remote named " + remote_name + " to push to."
    else:
        status["remote"] = remote_name
        status["set_upstream"] = push_facts["set_upstream"]
        blocked_host = find_blocked_host(push_directory, remote_name,
                                         remote_urls, blocked_host_suffixes)
        if blocked_host is not None:
            remote_reason = ("Repositories on " + blocked_host + " are pushed "
                             "from another machine: port the change by hand.")
        elif upstream_branch is not None and upstream_branch != branch:
            # git's own push refuses this too (push.default "simple").
            remote_reason = ("The upstream of " + branch + " is " + remote_name
                             + "/" + upstream_branch + ", a branch with another "
                             "name: BranchLens pushes only to a branch of the "
                             "same name, so push this one from a terminal.")

    if verdict_reason is not None and remote_reason is not None:
        if verdict_reason == RUNNING_REASON:
            # Without "push once it has finished": the remote problem stays.
            status["reason"] = "A security check is running. " + remote_reason
        else:
            status["reason"] = verdict_reason + " " + remote_reason
        return status
    if verdict_reason is not None:
        status["reason"] = verdict_reason
        return status
    if remote_reason is not None:
        status["reason"] = remote_reason
        return status

    if push_facts["remote_tip"] == tip:
        status["reason"] = ("Already pushed: " + remote_name + "/" + branch
                            + " is at " + tip[:7] + ".")
        return status

    unjudged_reason = unjudged_history_problem(push_directory, folder, verdict,
                                               remote_name, tip, started_base)
    if unjudged_reason is not None:
        status["reason"] = unjudged_reason
        return status

    status["allowed"] = True
    status["reason"] = "Will run " + command_text(push_command("", remote_name, branch, tip))
    if status["set_upstream"]:
        status["reason"] = (status["reason"] + ", then "
                            + command_text(upstream_command("", remote_name, branch)))
    status["reason"] = status["reason"] + "."
    return status


def push_command(working_directory, remote_name, branch, commit):
    """The push, as an argument list: the judged commit onto refs/heads/<branch>.

    The source is the commit id: a commit made after the last look at the
    tip is never sent. It ends in ^{commit}: git push matches a bare source
    against ref names first, so a tag or branch named like the id would
    send another commit; no ref name can hold "^". --recurse-submodules=no
    and --no-follow-tags keep the push to that commit whatever
    push.recurseSubmodules, submodule.recurse or push.followTags say.
    """
    return ["git", "-C", working_directory, "push", "--recurse-submodules=no",
            "--no-follow-tags", remote_name, commit + "^{commit}:refs/heads/" + branch]


def upstream_command(working_directory, remote_name, branch):
    """The step that makes the pushed branch the local branch's upstream.

    `git push -u` writes no upstream when the source is a commit id. The
    remote-tracking ref is named in full: a tag called <remote>/<branch>
    would make the short name ambiguous.
    """
    return ["git", "-C", working_directory, "branch",
            "--set-upstream-to=refs/remotes/" + remote_name + "/" + branch, branch]


def command_text(command):
    """A command as the page shows it: without the -C <folder> part."""
    return "git " + " ".join(command[3:])


def run_command(command, environment, timeout_seconds):
    """Run one git command in a session of its own. Returns (succeeded, output).

    stdin is /dev/null and the session is new, so neither git nor ssh has a
    terminal to prompt on; after timeout_seconds the whole process group is
    stopped.
    """
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
    except OSError as error:
        return False, "Could not start git: " + str(error)

    timed_out = False
    try:
        output_bytes, _unused = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            # With start_new_session the process group id is git's own pid.
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        output_bytes, _unused = process.communicate()

    output = output_bytes.decode("utf-8", errors="replace").strip()
    if timed_out:
        output = (output + "\n(git " + command[3] + " stopped after "
                  + str(timeout_seconds) + " seconds)")
    succeeded = process.returncode == 0 and not timed_out
    return succeeded, output


def push_branch(working_directory, remote_name, branch, commit, set_upstream):
    """Push commit to refs/heads/<branch> on the remote. Returns (pushed, output).

    When set_upstream is true and the push went through, a second command
    makes <remote>/<branch> the branch's upstream. Its output is added to
    the push's; when it fails, the output says so and the push still counts
    as pushed.

    Runs with the user's own environment (hooks, ssh agent, credential
    helpers), not gitops' hardening environment and not through
    gitops.run_git. GIT_TERMINAL_PROMPT=0 makes git and ssh fail instead of
    waiting for a password nobody can type.
    """
    environment = dict(os.environ)
    # Variables like these, inherited from the shell that started BranchLens,
    # would point git at another repository than the branch's worktree.
    for name in GIT_LOCATION_VARIABLES:
        environment.pop(name, None)
    # Config from the environment (GIT_CONFIG_COUNT and its keys,
    # GIT_CONFIG_PARAMETERS) could send the push to another address, such as
    # a remote.<name>.pushurl, than the one check_push read without it.
    gitops.strip_config_overrides(environment)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    pushed, output = run_command(
        push_command(working_directory, remote_name, branch, commit),
        environment, PUSH_TIMEOUT_SECONDS)
    if pushed and set_upstream:
        upstream_set, upstream_output = run_command(
            upstream_command(working_directory, remote_name, branch),
            environment, UPSTREAM_TIMEOUT_SECONDS)
        if upstream_output != "":
            output = output + "\n" + upstream_output
        if not upstream_set:
            output = (output + "\nThe push went through, but " + remote_name + "/"
                      + branch + " could not be set as the upstream of " + branch + ".")
    if len(output) > MAX_PUSH_OUTPUT_CHARS:
        output = "…" + output[-MAX_PUSH_OUTPUT_CHARS:]
    return pushed, output
