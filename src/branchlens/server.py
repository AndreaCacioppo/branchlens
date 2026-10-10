"""BranchLens HTTP server: command-line entry point and API routes.

This file parses the command line, serves the page, answers the API in JSON,
and starts or stops the security pipeline. gitops.py does the git reads.
publish.py does the one write: a push after a passed security check, then
setting the branch's upstream when it has none.
"""

import argparse
import calendar
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from branchlens import __version__

# gitops and publish (which imports gitops) are imported inside main() and
# the request handlers, so `branchlens --help` and `--version` work even when
# gitops.py is missing or broken. Python caches modules, so a repeated import
# costs nothing.

# The toolkit bundled in a clone: <repository>/toolkit, two levels above
# src/branchlens/. An installed package has no copy of it.
BUNDLED_TOOLKIT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))), "toolkit")
# The feed file name the toolkit writes inside its reports folder.
FEED_FILE_NAME = "security-feed.jsonl"
# The stdout and stderr of a run started from BranchLens, in the same
# reports folder. Every worktree of a repository shares that folder, so the
# name carries the server's process id.
RUN_LOG_FILE_PATTERN = "branchlens-run-{process_id}.log"
RUN_LOG_TAIL_LINES = 20
# The start of a run's log that is searched for its "report in:" line.
RUN_LOG_HEAD_BYTES = 4096
# The reason given for a deleted file, which the review never reads.
DELETED_FILE_REASON = "deleted in this diff, so there is nothing to read"
# The POST bodies are tiny ({"branch": ...}); anything larger is refused.
MAX_POST_BODY_BYTES = 65536
# The bare verdict words the toolkit writes (gate and pipeline).
VERDICT_WORDS = ("READY TO PUBLISH", "DO NOT PUBLISH", "INCONCLUSIVE",
                 "PASSED", "FAILED")
# How long after a Cancel /api/run refuses while the cancelled run's feed
# still reads as running.
CANCEL_SETTLE_SECONDS = 15
# A run this server did not start counts as stopped after this long with no
# feed event (the page's QUIET_FEED_MS). The pipeline stops its LLM review
# after one hour.
QUIET_FEED_SECONDS = 2 * 60 * 60
# After this long with no feed event, the user may start a run over one
# started elsewhere: the page asks first and sends override_stalled.
STALLED_FEED_SECONDS = 10 * 60
# The base the toolkit reads as a first publish: the diff starts from the
# empty tree, so the branch's whole history is judged.
EMPTY_TREE_BASE = "empty-tree"
# The answers to a request without this server's cookie. The URL printed at
# start ends in ?token=...; opening it sets the cookie.
NO_COOKIE_ERROR = ("Missing or outdated access cookie: open the URL BranchLens "
                   "printed in the terminal when it started.")
# The answers to a POST without the page token, or without an Origin header.
NO_PAGE_TOKEN_ERROR = ("Missing or outdated page token: open the URL BranchLens "
                       "printed in the terminal again.")
NO_ORIGIN_ERROR = "Requests that do not say which page sent them (Origin) are refused."
# Why Run cannot start when the Claude Code CLI is missing.
NO_CLAUDE_CLI_REASON = "Run needs the Claude Code CLI (claude) on PATH."
NO_COOKIE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>BranchLens</title></head>
<body>
<p>Open the URL BranchLens printed in the terminal when it started. It ends
with <code>?token=</code> and a long code, and lets this browser in.</p>
<p>A BranchLens that was restarted prints a new URL.</p>
</body>
</html>
"""


class BranchLensHandler(BaseHTTPRequestHandler):
    # Filled in by main() before the server starts.
    repo_root = None
    launch_worktree_root = None
    # Absolute path of the security progress feed (--security-feed), or None.
    # With no feed, /api/security answers {"enabled": false}.
    security_feed_path = None
    # Absolute path of a safety-checks checkout (--toolkit), or None. With
    # one, the page can start the pipeline and push a branch it passed.
    toolkit_path = None
    # Host suffixes a push must never go to (--no-push-host), lowercased.
    blocked_push_hosts = []
    # Three random secrets, made at every start. The URL printed at start
    # carries launch_code. Opening that URL sets the cookie_secret cookie,
    # which every GET of the page or the API must carry, and hands
    # page_token to the page in the address fragment. Every POST must carry
    # the cookie and send page_token back in a header.
    # Browsers send a cookie to every port of 127.0.0.1, so another program
    # listening on this machine can learn cookie_secret. The page keeps
    # page_token in its own storage, which is kept apart per port, and no
    # answer that the cookie alone unlocks contains it.
    launch_code = None
    cookie_secret = None
    page_token = None
    # Random id of this server process, sent with /api/state, so an open page
    # can tell that BranchLens was restarted under it. Not a secret.
    launch_id = None
    # Seconds one socket read or write may wait, so a client that sends
    # nothing or stops halfway cannot hold its thread forever. A push or a
    # slow diff does no socket I/O while it works.
    timeout = 60

    def log_message(self, format, *args):
        # No access log: the page polls every 2 seconds.
        pass

    def end_headers(self):
        # On every response, the base class's own error pages included: no
        # content-type guessing, and no address passed on to another site.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_GET(self):
        try:
            self.route_request()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            # The browser closed the connection mid-reply or stopped
            # reading. socket.timeout is TimeoutError from Python 3.10 on.
            pass

    def host_header_is_local(self):
        """True when the request's Host header names this machine.

        Browsers can be tricked (DNS rebinding) into sending requests to
        127.0.0.1 under an attacker-controlled hostname, which would let a
        web page read the whole repository. Only loopback names may pass.
        """
        host = self.headers.get("Host", "")
        # Strip the :port suffix; an IPv6 literal keeps its brackets.
        if host.startswith("["):
            closing_bracket = host.find("]")
            if closing_bracket != -1:
                host = host[: closing_bracket + 1]
        elif ":" in host:
            host = host.split(":", 1)[0]
        return host.lower() in ("127.0.0.1", "localhost", "[::1]", "::1")

    def route_request(self):
        from branchlens import gitops  # lazy import, see the note at the top of the file

        if not self.host_header_is_local():
            self.send_json(
                403,
                {"error": "Requests are only accepted from this machine."},
            )
            return

        parsed_url = urlparse(self.path)
        route = parsed_url.path
        params = parse_qs(parsed_url.query)

        # Another site, or another port of this machine, can make the
        # browser send API requests whose answers it cannot read; the time
        # git takes would still tell whether a branch or a file exists.
        # Browsers say where a request comes from in Sec-Fetch-Site; a
        # client without that header passes.
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if route.startswith("/api/") and fetch_site not in (None, "same-origin", "none"):
            self.send_json(403, {"error": "Requests from other web pages are refused."})
            return

        # Any user or program on this machine can reach 127.0.0.1. The page
        # and the API answer only the cookie that the URL printed at start
        # sets.
        if route == "/" and "token" in params:
            self.exchange_launch_code(self.read_param(params, "token"))
            return
        if route == "/" or route.startswith("/api/"):
            if not self.has_cookie_secret():
                self.refuse_without_cookie(route)
                return

        try:
            if route == "/":
                self.serve_app_page()
            elif route == "/api/state":
                state = gitops.get_state(self.repo_root, self.launch_worktree_root)
                state["launch_id"] = self.launch_id
                self.send_json(200, state)
            elif route == "/api/graph":
                graph = gitops.get_graph(self.repo_root)
                self.send_json(200, graph)
            elif route == "/favicon.ico":
                # Browsers ask for one on their own; an empty answer keeps
                # the console free of a 404.
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif route == "/api/security":
                self.send_json(200, self.build_security_response())
            elif route == "/api/diff":
                branch = self.read_param(params, "branch")
                commit = self.read_param(params, "commit")
                base = self.read_param(params, "base")
                if not self.check_target_params(branch, commit):
                    return
                if branch is not None:
                    diff = gitops.get_diff(self.repo_root, branch, base)
                else:
                    diff = gitops.get_commit_diff(self.repo_root, commit, base)
                self.send_json(200, diff)
            elif route == "/api/file":
                branch = self.read_param(params, "branch")
                commit = self.read_param(params, "commit")
                base = self.read_param(params, "base")
                file_path = self.read_param(params, "path")
                if not self.check_target_params(branch, commit):
                    return
                if file_path is None:
                    self.send_json(400, {"error": "Missing 'path' query parameter."})
                    return
                if branch is not None:
                    file_patch = gitops.get_file_patch(
                        self.repo_root, branch, file_path, base
                    )
                else:
                    file_patch = gitops.get_commit_file_patch(
                        self.repo_root, commit, file_path, base
                    )
                self.send_json(200, file_patch)
            elif route == "/api/network":
                branch = self.read_param(params, "branch")
                commit = self.read_param(params, "commit")
                # A branch moves; the network is a snapshot of one commit, so
                # there is no sensible answer to give for a branch name.
                if branch is not None:
                    self.send_json(
                        400,
                        {"error": "The network view needs a 'commit', not a 'branch'."},
                    )
                    return
                if commit is None:
                    self.send_json(400, {"error": "Missing 'commit' query parameter."})
                    return
                network = gitops.get_network(self.repo_root, commit)
                self.send_json(200, network)
            else:
                self.send_json(404, {"error": "No such page or API route: " + route})
        # These three subclass GitError, so they are caught first.
        except (
            gitops.BranchNotFound,
            gitops.FileNotInDiff,
            gitops.CommitNotInGraph,
        ) as error:
            self.send_json(404, {"error": str(error)})
        except gitops.GitError as error:
            self.send_json(400, {"error": str(error)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            raise  # let do_GET handle disconnections quietly
        except Exception as error:
            self.send_json(500, {"error": "Unexpected server error: " + str(error)})

    def cookie_name(self):
        """The name of the cookie that carries the cookie secret.

        Browsers share cookies between every port of 127.0.0.1, so the port
        is part of the name: two servers do not overwrite each other's.
        """
        return "branchlens_" + str(self.server.server_address[1])

    def matches_secret(self, value, secret):
        """True when value equals secret, compared in constant time.

        A secret that was never set (None or "") matches nothing.
        """
        if not secret or not isinstance(value, str):
            return False
        return hmac.compare_digest(value.encode("utf-8"), secret.encode("utf-8"))

    def cookie_values(self):
        """Every value the request carries under this server's cookie name, in order."""
        wanted = self.cookie_name()
        values = []
        for header in self.headers.get_all("Cookie") or []:
            for piece in header.split(";"):
                name, separator, value = piece.strip().partition("=")
                if separator == "=" and name.strip() == wanted:
                    values.append(value.strip())
        return values

    def has_cookie_secret(self):
        """True when one of the request's cookies of this server's name holds the cookie secret.

        A page on another 127.0.0.1 port can plant a cookie of the same name
        with a narrower Path such as /api. The browser then sends both, the
        planted one first, so every value is tried, not only the first.
        """
        for value in self.cookie_values():
            if self.matches_secret(value, self.cookie_secret):
                return True
        return False

    def exchange_launch_code(self, code):
        """GET /?token=CODE: swap the code of the printed URL for the two other secrets.

        The right code sets the cookie and sends the browser on to
        /#token=<page token> with a 303, so the code leaves the address bar.
        The fragment never travels to a server; the page moves the token into
        its own storage and takes it out of the address. A wrong code gets
        the same refusal as a request without the cookie.
        """
        if not self.matches_secret(code, self.launch_code) or not self.page_token:
            self.refuse_without_cookie("/")
            return
        self.send_response(303)
        self.send_header("Location", "/#token=" + self.page_token)
        # HttpOnly: no script reads it, the page's own included.
        # SameSite=Strict: a request another site starts does not carry it.
        self.send_header("Set-Cookie", self.cookie_name() + "=" + self.cookie_secret
                         + "; HttpOnly; SameSite=Strict; Path=/")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def refuse_without_cookie(self, route):
        """403 for a request without this server's cookie: a short page for /, JSON for the API."""
        if route != "/":
            self.send_json(403, {"error": NO_COOKIE_ERROR})
            return
        body = NO_COOKIE_PAGE.encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; base-uri 'none'; form-action 'none'; "
                         "frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_param(self, params, name):
        """Return the first value of a query parameter, or None if absent or empty."""
        values = params.get(name, [])
        if len(values) == 0 or values[0] == "":
            return None
        return values[0]

    def check_target_params(self, branch, commit):
        """True when exactly one of branch= and commit= was given.

        Otherwise sends the 400 itself and returns False.
        """
        if branch is not None and commit is not None:
            self.send_json(
                400,
                {"error": "Use either 'branch' or 'commit', not both."},
            )
            return False
        if branch is None and commit is None:
            self.send_json(
                400,
                {"error": "Missing 'branch' or 'commit' query parameter."},
            )
            return False
        return True

    def serve_app_page(self):
        app_page = Path(__file__).parent / "static" / "app.html"
        # The page carries no secret: the cookie alone unlocks it, and the
        # cookie can reach other ports (see page_token above).
        content = app_page.read_bytes()
        # A fresh nonce on the page's one <script> and one <style>, named in
        # the Content-Security-Policy, lets only those two run. Assignments
        # to element.style still work; a style="..." attribute or
        # setAttribute("style", ...) would be blocked. A page without
        # exactly one of each is served without the policy.
        policy = None
        if (content.count(b"<script") == 1 and content.count(b"<script>") == 1
                and content.count(b"<style") == 1 and content.count(b"<style>") == 1):
            nonce = secrets.token_urlsafe(16)
            nonce_attribute = (' nonce="' + nonce + '"').encode("ascii")
            content = content.replace(b"<script>", b"<script" + nonce_attribute + b">")
            content = content.replace(b"<style>", b"<style" + nonce_attribute + b">")
            policy = ("default-src 'none'; script-src 'nonce-" + nonce + "'; "
                      "style-src 'nonce-" + nonce + "'; connect-src 'self'; "
                      "img-src 'self' data:; base-uri 'none'; form-action 'none'; "
                      "frame-ancestors 'none'")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        if policy is not None:
            self.send_header("Content-Security-Policy", policy)
        # No other site may show this page in a frame.
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    # ------------------------------------------------------------ security run

    def toolkit_problem(self):
        """Why no run can be started (one sentence), or None when the toolkit is usable."""
        if self.toolkit_path is None:
            return ("No security toolkit is configured: start BranchLens with "
                    "--toolkit PATH (a folder holding preflight.sh).")
        if not os.path.isfile(os.path.join(self.toolkit_path, "preflight.sh")):
            return "There is no preflight.sh in " + self.toolkit_path + "."
        # The pipeline's review runs `claude -p`; without it every run would
        # end INCONCLUSIVE after the mechanical checks.
        if shutil.which("claude") is None:
            return NO_CLAUDE_CLI_REASON
        return None

    def reports_root(self):
        """The folder holding the feed; every run started here writes its reports there."""
        return os.path.dirname(self.security_feed_path)

    def build_security_response(self):
        """The /api/security answer: the folded feed plus `feed_path`, `runner`,
        `push`, `judged` and what the run's report folder adds."""
        from branchlens import publish

        feed_state = read_security_state(self.security_feed_path)
        if not feed_state.get("enabled"):
            return feed_state
        # A copy: the folded feed is cached.
        response = dict(feed_state)
        response["feed_path"] = self.security_feed_path
        # A run started here hands the toolkit its base as a commit id; the
        # page shows the name that commit was read from instead.
        base_label = RUNNER.base_label_for(feed_state.get("base"))
        if base_label is not None:
            response["base"] = base_label
        runner = RUNNER.describe(self.toolkit_problem())
        status = self.check_push_now(feed_state, runner)
        response["runner"] = runner
        response["push"] = self.describe_push(status)
        response["judged"] = status["judged"]

        verdict_facts = None
        scope = None
        folder = publish.run_report_folder(self.reports_root(), feed_state.get("run_id"))
        if folder is not None:
            verdict_facts = read_verdict_facts(publish.read_verdict_file(folder))
            scope = publish.read_review_scope(folder)
            mark_deleted_files_skipped(response, scope)
        # While a run started elsewhere has no verdict.json yet, its
        # review-scope.json (written before the first check) already names
        # the commit it judges.
        if (response["judged"] is None and status["foreign_repository"] is None
                and feed_state.get("running") is True):
            response["judged"] = judged_from_scope(scope, self.repo_root)
        response["review_incomplete"] = None
        response["mechanical_advisory"] = None
        if verdict_facts is not None:
            response["areas"] = verdict_facts["areas"]
            response["review_incomplete"] = verdict_facts["review_incomplete"]
            response["mechanical_advisory"] = verdict_facts["mechanical_advisory"]
        return response

    def check_push_now(self, feed_state, runner):
        """publish.check_push for the latest run, never raising.

        runner is RUNNER.describe()'s answer. Returns the full status dict,
        set_upstream included.
        """
        from branchlens import gitops
        from branchlens import publish

        try:
            return publish.check_push(
                self.repo_root, self.reports_root(),
                run_id=feed_state.get("run_id"),
                feed_running=feed_state.get("running") is True,
                feed_verdict_word=feed_state.get("verdict_word"),
                cancelled_run_id=RUNNER.last_cancelled_run_id(),
                run_active=runner["active"],
                active_branch=runner["branch"],
                active_commit=RUNNER.started_commit(),
                blocked_host_suffixes=self.blocked_push_hosts,
                feed_findings=feed_state.get("findings") or [],
            )
        except gitops.GitError as error:
            return {"allowed": False, "reason": str(error), "branch": None,
                    "remote": None, "commit": None, "judged": None,
                    "set_upstream": False, "working_directory": None,
                    "foreign_repository": None}

    def describe_push(self, status):
        """The `push` object of /api/security, from check_push_now's status.

        The last push's result is shown only while the status still talks
        about the branch and commit that push sent.
        """
        last_push = RUNNER.last_push()
        last_pushed = None
        last_output = None
        if last_push["branch"] == status["branch"] and last_push["commit"] == status["commit"]:
            last_pushed = last_push["pushed"]
            last_output = last_push["output"]
        return {
            "allowed": status["allowed"],
            "reason": status["reason"],
            "branch": status["branch"],
            "remote": status["remote"],
            "commit": status["commit"],
            "pushed": last_pushed,
            "output": last_output,
        }

    # ------------------------------------------------------------ POST routes

    def do_POST(self):
        try:
            self.route_post_request()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            # The browser went away mid-reply, as in do_GET, or sent less of
            # the body than its Content-Length said.
            pass

    def post_refusal_reason(self):
        """Why this POST must be refused, as one sentence, or None to accept it.

        On top of the Host check: an Origin header naming this server (browsers
        send one with every POST, so a request without it is not the page);
        the cookie; the page token (only the page this server served knows
        it); and Content-Type application/json (a cross-site form cannot
        send it, and a cross-site script would need a preflight, which fails:
        there is no do_OPTIONS).
        """
        if not self.host_header_is_local():
            return "Requests are only accepted from this machine."
        port = self.server.server_address[1]
        origin = self.headers.get("Origin")
        allowed_origins = ("http://127.0.0.1:" + str(port), "http://localhost:" + str(port))
        if origin is None:
            return NO_ORIGIN_ERROR
        if origin not in allowed_origins:
            return "Requests from other web pages are refused."
        if not self.has_cookie_secret():
            return NO_COOKIE_ERROR
        sent_token = self.headers.get("X-BranchLens-Token", "")
        if not self.matches_secret(sent_token, self.page_token):
            return NO_PAGE_TOKEN_ERROR
        content_type = self.headers.get("Content-Type", "")
        # "application/json; charset=utf-8" is the same type with a parameter.
        if content_type.split(";", 1)[0].strip().lower() != "application/json":
            return "Only JSON requests are accepted."
        return None

    def read_json_body(self):
        """The request body as a dict, or None when it is not a JSON object.

        An empty body counts as {} (the cancel route needs no fields).
        """
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length < 0 or length > MAX_POST_BODY_BYTES:
            return None
        if length == 0:
            return {}
        raw_body = self.rfile.read(length)
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        if not isinstance(body, dict):
            return None
        return body

    def route_post_request(self):
        from branchlens import gitops  # lazy import, see the note at the top of the file

        refusal = self.post_refusal_reason()
        if refusal is not None:
            self.send_json(403, {"error": refusal})
            return
        body = self.read_json_body()
        if body is None:
            self.send_json(400, {"error": "The request body must be a JSON object."})
            return
        route = urlparse(self.path).path
        try:
            if route == "/api/run":
                self.start_security_run(body)
            elif route == "/api/cancel":
                # The feed only labels the Cancel for /api/run; a feed that
                # cannot be read must not keep the run from being stopped.
                try:
                    feed_run_id = read_security_state(self.security_feed_path).get("run_id")
                except Exception:
                    feed_run_id = None
                self.send_json(200, {"cancelled": RUNNER.cancel(feed_run_id)})
            elif route == "/api/push":
                self.push_checked_branch(body)
            else:
                self.send_json(404, {"error": "No such API route: " + route})
        # BranchNotFound is a GitError: an unknown branch is a 400 here, not a 404.
        except gitops.GitError as error:
            self.send_json(400, {"error": str(error)})
        except (BrokenPipeError, ConnectionResetError, TimeoutError, socket.timeout):
            raise  # let do_POST handle disconnections quietly
        except Exception as error:
            self.send_json(500, {"error": "Unexpected server error: " + str(error)})

    def find_branch_worktree(self, branch):
        """(worktree path or None, tip commit) of a branch.

        The name must match a fresh branch listing exactly, as for /api/diff;
        otherwise BranchNotFound is raised.
        """
        from branchlens import gitops
        from branchlens import publish

        branch_tips = publish.read_branch_tips(self.repo_root)
        if branch not in branch_tips or branch.startswith("-"):
            raise gitops.BranchNotFound("No branch named '" + branch + "' was found.")
        branch_to_worktree, _all_paths, _raw = gitops.get_worktrees(self.repo_root)
        return branch_to_worktree.get(branch), branch_tips[branch]

    def start_security_run(self, body):
        """POST /api/run {branch, base?}: start the pipeline on one branch."""
        from branchlens import gitops

        branch = body.get("branch")
        base = body.get("base")
        if not isinstance(branch, str) or branch == "":
            self.send_json(400, {"error": "Missing 'branch'."})
            return
        if base is not None and not isinstance(base, str):
            self.send_json(400, {"error": "'base' must be a string."})
            return
        toolkit_problem = self.toolkit_problem()
        if toolkit_problem is not None:
            self.send_json(400, {"error": toolkit_problem})
            return
        if RUNNER.is_active():
            self.send_json(409, {"error": "A security check is already running."})
            return
        feed_state = read_security_state(self.security_feed_path)
        # A cancelled run's mechanical checks may still be writing into the feed.
        if RUNNER.still_stopping(feed_state):
            self.send_json(409, {
                "error": "The cancelled check is still stopping: try again in a few seconds."
            })
            return
        # So may a run this server did not start (a terminal, another page,
        # a server that was restarted): its events would land in the new run.
        # This server's own last run is not active any more, so it ended
        # without a verdict and blocks nothing.
        own_run_id = RUNNER.own_run_id()
        is_own_run = own_run_id is not None and feed_state.get("run_id") == own_run_id
        # The page may override a run that looks stalled, after asking the
        # user; how long the feed has been silent is read here, never taken
        # from the request.
        stalled_override = body.get("override_stalled") is True and feed_is_stalled(feed_state)
        if feed_run_is_live(feed_state) and not is_own_run and not stalled_override:
            self.send_json(409, {
                "error": "A check started outside this page is running: wait for it to finish."
            })
            return
        worktree_path, tip = self.find_branch_worktree(branch)
        if worktree_path is None:
            self.send_json(400, {
                "error": "check this branch out in a worktree to run the pipeline on it"
            })
            return
        # base_ref is what git resolves; base_label is how answers name it.
        if base is None or base == "":
            base_ref, base_label = default_run_base(self.repo_root, branch, worktree_path)
        else:
            if base != EMPTY_TREE_BASE and not is_plain_base_name(base):
                self.send_json(400, {"error": "'" + base + "' is not a commit in this repository."})
                return
            base_ref = base
            base_label = base
        if base_ref == EMPTY_TREE_BASE:
            base_commit = None
            toolkit_base = EMPTY_TREE_BASE
        else:
            base_commit = resolve_base_commit(self.repo_root, base_ref)
            if base_commit is None:
                self.send_json(400, {"error": "'" + base_label + "' is not a commit in this repository."})
                return
            # The commit id: inside the toolkit, a tag or a branch spelled
            # like the name could win git's lookup.
            toolkit_base = base_commit
        # The run judges merge-base(base, branch)..branch: refuse an empty
        # range. A first publish judges the whole history instead.
        if (base_commit is not None
                and gitops.find_merge_base(self.repo_root, base_commit, tip) == tip):
            self.send_json(400, {
                "error": branch + " has no commits that " + base_label + " lacks, so "
                         "there is nothing to check: the check judges commits, "
                         "not uncommitted edits."
            })
            return

        command = [os.path.join(self.toolkit_path, "preflight.sh"), "run", worktree_path,
                   toolkit_base]
        # Runs write into the folder of the feed this server watches.
        environment = dict(os.environ)
        environment["PREFLIGHT_REPORTS_DIR"] = self.reports_root()
        log_path = os.path.join(self.reports_root(),
                                RUN_LOG_FILE_PATTERN.format(process_id=os.getpid()))
        try:
            refusal = RUNNER.start(command, self.toolkit_path, environment, log_path,
                                   branch, tip, toolkit_base, base_label)
        except OSError as error:
            if error.filename == log_path:
                # O_NOFOLLOW refuses a symlink planted where the log goes.
                self.send_json(500, {"error": "Could not open the run log " + log_path
                                     + " (" + str(error.strerror) + "). If a symlink "
                                     "is there, remove it and run the check again."})
                return
            # For example preflight.sh is there but not executable, or the
            # reports folder cannot be created.
            self.send_json(500, {"error": "Could not start preflight.sh: " + str(error)})
            return
        if refusal is not None:
            self.send_json(409, {"error": refusal})
            return
        self.send_json(200, {"started": True, "branch": branch, "base": base_label})

    def push_checked_branch(self, body):
        """POST /api/push {branch}: push the branch the latest check passed.

        Every condition is checked again at the moment of the click.
        """
        from branchlens import publish

        branch = body.get("branch")
        if not isinstance(branch, str) or branch == "":
            self.send_json(400, {"error": "Missing 'branch'.", "pushed": False})
            return
        feed_state = read_security_state(self.security_feed_path)
        if not feed_state.get("enabled"):
            self.send_json(409, {"error": "No security feed is configured.", "pushed": False})
            return
        runner = RUNNER.describe(self.toolkit_problem())
        status = self.check_push_now(feed_state, runner)
        if not status["allowed"]:
            self.send_json(409, {"error": status["reason"], "pushed": False})
            return
        if branch != status["branch"]:
            self.send_json(409, {
                "error": "The latest security check judged " + str(status["branch"])
                         + ", not " + branch + ".",
                "pushed": False,
            })
            return
        # Read the tip again right before the push: a commit made while the
        # checks above ran is refused, not pushed unchecked.
        if publish.current_tip(self.repo_root, branch) != status["commit"]:
            self.send_json(409, {
                "error": branch + " moved while the push was being checked: "
                         "run the check again.",
                "pushed": False,
            })
            return

        refusal = RUNNER.begin_push()
        if refusal is not None:
            self.send_json(409, {"error": refusal, "pushed": False})
            return
        pushed = False
        output = "The push did not complete."
        try:
            # The folder the remote and its URLs were read from: the
            # branch's worktree, else the repository root. The commit is the
            # full id compared with the judged one above.
            pushed, output = publish.push_branch(
                status["working_directory"], status["remote"], branch,
                status["commit"], status["set_upstream"],
            )
        finally:
            RUNNER.finish_push(pushed, output, branch, status["commit"])
        self.send_json(200, {"pushed": pushed, "output": output})

    def send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def parse_feed_lines(text):
    """Parse the JSON-lines feed text into a list of event dicts.

    The writer may be appending while this reads, so a partial or malformed
    line is skipped.
    """
    events = []
    for line in text.split("\n"):
        line = line.strip()
        if line == "":
            continue
        try:
            event = json.loads(line)
        except (ValueError, RecursionError):
            # ValueError: bad JSON, or an integer with too many digits;
            # RecursionError: nesting too deep for the parser.
            continue
        if isinstance(event, dict) and isinstance(event.get("event"), str):
            events.append(event)
    return events


def parse_feed_time(text):
    """Seconds since the epoch for a feed timestamp, or None.

    The feed writes plain UTC stamps like 2026-08-25T10:04:26Z; anything else
    gives None.
    """
    if not isinstance(text, str):
        return None
    try:
        return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        return None


def record_phase(state, event):
    """Add or close a phase.

    A duration is the difference between two of the feed's own timestamps,
    never a number the pipeline reports.
    """
    name = event.get("name")
    if not isinstance(name, str):
        return
    status = str(event.get("status", "running"))
    when = event.get("utc") if isinstance(event.get("utc"), str) else None
    detail = event.get("detail")

    for phase in state["phases"]:
        if phase["name"] == name:
            phase["status"] = status
            if isinstance(detail, str):
                phase["detail"] = detail
            if status in ("done", "failed"):
                phase["ended_utc"] = when
                started = parse_feed_time(phase.get("started_utc"))
                ended = parse_feed_time(when)
                if started is not None and ended is not None:
                    phase["seconds"] = max(ended - started, 0)
            return

    # A phase first seen already finished has no known duration: None, not 0.
    state["phases"].append({
        "name": name,
        "status": status,
        "detail": detail if isinstance(detail, str) else None,
        "started_utc": when,
        "ended_utc": when if status in ("done", "failed") else None,
        "seconds": None,
    })


def record_finding(state, event):
    """Append one finding; fold_security_run sorts the list once, after the fold.

    A finding that names no file is kept, with "?" as its file: dropping a
    blocking one would hide it from the Push check.
    """
    file_path = event.get("file")
    if not isinstance(file_path, str) or file_path == "":
        file_path = "?"
    line = event.get("line")
    if not isinstance(line, int):
        line = None
    finding = {
        "file": file_path,
        "line": line,
        "severity": str(event.get("severity", "low")),
        "title": str(event.get("title", "")),
        "entry": str(event.get("entry", "")) or None,
        "outcome": str(event.get("outcome", "")) or None,
        "blocking": bool(event.get("blocking")),
    }
    state["findings"].append(finding)


def verdict_word_from_detail(detail):
    """The verdict word a `phase verdict done` detail names, or None.

    The merge step writes the bare word ("READY TO PUBLISH"); older toolkits
    wrote it after a "PIPELINE: " prefix.
    """
    if not isinstance(detail, str):
        return None
    if detail.startswith("PIPELINE: "):
        detail = detail[len("PIPELINE: "):]
    if detail in VERDICT_WORDS:
        return detail
    return None


def finding_sort_key(finding):
    """Blocking findings first, then high, medium, low."""
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    blocking_rank = 0 if finding["blocking"] else 1
    return (blocking_rank, severity_rank.get(finding["severity"], 3))


def is_plain_number(value):
    """True for an int or float. bool is excluded: Python counts True as 1."""
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float))


def record_check(state, event, check_positions):
    """Add or update one step of the run (gate check, checklist reviewer,
    deep dive, verification).

    Keyed by stage and name. The latest event replaces the row, which keeps
    the position where it first appeared. check_positions maps each key to
    its index in state["checks"].
    """
    stage = event.get("stage")
    name = event.get("name")
    if not isinstance(stage, str) or not isinstance(name, str):
        return
    status = event.get("status")
    result = event.get("result")
    blocking = event.get("blocking")
    detail = event.get("detail")
    seconds = event.get("seconds")
    count = event.get("count")
    check = {
        "stage": stage,
        "name": name,
        "status": status if isinstance(status, str) else "running",
        "result": result if isinstance(result, str) else None,
        "blocking": blocking if isinstance(blocking, bool) else None,
        "detail": detail if isinstance(detail, str) else None,
        "seconds": seconds if is_plain_number(seconds) else None,
        "count": count if isinstance(count, int) and not isinstance(count, bool) else None,
    }
    key = (stage, name)
    if key in check_positions:
        state["checks"][check_positions[key]] = check
    else:
        check_positions[key] = len(state["checks"])
        state["checks"].append(check)


def fold_security_run(events):
    """Fold the events of the latest run (after the last start marker) into
    the state object the page polls.

    The last event wins. A run can write more than one verdict (the gate's
    first, the pipeline's later). Per-file work that arrives after a verdict
    makes the run count as running again until the next verdict.
    """
    last_start_index = None
    for index in range(len(events) - 1, -1, -1):
        if events[index].get("event") == "start":
            last_start_index = index
            break
    state = {
        "enabled": True,
        "running": False,
        "base": None,
        "run_id": None,
        "verdict": None,
        "verdict_word": None,
        "started_utc": None,
        "last_utc": None,
        "files": {},
        "file_total": 0,
        "file_done": 0,
        "current_path": None,
        # feed v2; empty for older feeds
        "phases": [],
        "findings": [],
        "areas": [],
        # feed v3: one row per step of the run, in first-appearance order
        "checks": [],
    }
    if last_start_index is None:
        return state
    run_events = events[last_start_index:]
    start_event = run_events[0]
    if isinstance(start_event.get("base"), str):
        state["base"] = start_event["base"]
    if isinstance(start_event.get("run_id"), str):
        state["run_id"] = start_event["run_id"]
    listed_files = start_event.get("files")
    if isinstance(listed_files, list):
        for path in listed_files:
            if isinstance(path, str):
                state["files"][path] = {"status": "pending", "count": None}

    if isinstance(start_event.get("utc"), str):
        state["started_utc"] = start_event["utc"]
        state["last_utc"] = start_event["utc"]

    state["running"] = True
    checking_order = []
    check_positions = {}
    for event in run_events[1:]:
        # An event that names another run belongs to it: a cancelled run
        # still stopping, or one interrupted before it wrote its start
        # marker. Events without a run_id (older feeds) count as this run's.
        event_run_id = event.get("run_id")
        if (isinstance(event_run_id, str) and state["run_id"] is not None
                and event_run_id != state["run_id"]):
            continue
        kind = event.get("event")
        if isinstance(event.get("utc"), str):
            state["last_utc"] = event["utc"]
        if kind == "file":
            path = event.get("path")
            status = event.get("status")
            if not isinstance(path, str):
                continue
            if status not in ("checking", "clean", "findings", "skipped"):
                continue
            count = event.get("count")
            if not isinstance(count, int):
                count = None
            entry = {"status": status, "count": count}
            reason = event.get("reason")
            if isinstance(reason, str):
                entry["reason"] = reason
            state["files"][path] = entry
            if status == "checking":
                checking_order.append(path)
            state["running"] = True
        elif kind == "phase":
            record_phase(state, event)
            # Only a phase starting means work resumed. A phase that closes
            # after the verdict leaves the run finished.
            if str(event.get("status", "")) == "running":
                state["running"] = True
            # The review's merge step writes its verdict with no word, then
            # this phase with the word as its detail.
            word = verdict_word_from_detail(event.get("detail"))
            if (event.get("name") == "verdict" and event.get("status") == "done"
                    and word is not None):
                state["verdict_word"] = word
        elif kind == "finding":
            record_finding(state, event)
        elif kind == "check":
            # Steps leave `running` alone; phase events set it.
            record_check(state, event, check_positions)
        elif kind == "area":
            name = event.get("name")
            if isinstance(name, str):
                state["areas"].append({
                    "name": name,
                    "status": str(event.get("status", "NOT POSSIBLE")),
                    "reason": str(event.get("reason", "")),
                })
        elif kind == "verdict":
            text = event.get("text")
            if isinstance(text, str) and text != "":
                state["verdict"] = text
            # Every verdict replaces the word; one without a word clears it.
            word = event.get("verdict")
            if isinstance(word, str) and word != "":
                state["verdict_word"] = word
            else:
                state["verdict_word"] = None
            state["running"] = False

    # A skipped file counts as done: nothing will read it.
    done = 0
    for path in state["files"]:
        if state["files"][path]["status"] in ("clean", "findings", "skipped"):
            done += 1
    state["file_total"] = len(state["files"])
    state["file_done"] = done
    # The file being checked now: the latest "checking" one with no final
    # status yet.
    for path in reversed(checking_order):
        if state["files"][path]["status"] == "checking":
            state["current_path"] = path
            break
    # A stable sort: findings of the same rank keep their arrival order.
    state["findings"].sort(key=finding_sort_key)
    return state


# The last folded feed as one (stamp, state) pair, where the stamp is the
# file's size and modification time. Handler threads share it; one
# assignment stores both halves, so a stamp never meets another fold's state.
_FEED_CACHE = {"entry": None}


def read_security_state(feed_path):
    """The feed folded into a state, or {"enabled": False} without a feed.

    A missing file means no run yet, not an error.
    """
    from branchlens import publish

    if feed_path is None:
        return {"enabled": False}
    try:
        info = os.stat(feed_path)
    except OSError:
        return fold_security_run([])
    stamp = (info.st_size, info.st_mtime_ns)
    entry = _FEED_CACHE["entry"]
    if entry is not None and entry[0] == stamp:
        return entry[1]
    # Only a plain file: a FIFO would block this thread, /dev/zero never ends.
    feed_file = publish.open_regular_file(feed_path)
    if feed_file is None:
        return fold_security_run([])
    try:
        with feed_file:
            text = feed_file.read().decode("utf-8", errors="replace")
    except OSError:
        return fold_security_run([])
    state = fold_security_run(parse_feed_lines(text))
    _FEED_CACHE["entry"] = (stamp, state)
    return state


def utc_now():
    """The current time as a plain UTC stamp, in the feed's own format."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def feed_run_is_live(feed_state):
    """True when the feed's latest run reads as running and is not quiet yet.

    Quiet means no event for QUIET_FEED_SECONDS, as on the page; a time
    that cannot be read counts as recent, as it does there.
    """
    if feed_state.get("running") is not True:
        return False
    last_seconds = parse_feed_time(feed_state.get("last_utc"))
    if last_seconds is None:
        return True
    return time.time() - last_seconds <= QUIET_FEED_SECONDS


def feed_is_stalled(feed_state):
    """True when the feed's last event is at least STALLED_FEED_SECONDS old.

    A time that cannot be read counts as recent.
    """
    last_seconds = parse_feed_time(feed_state.get("last_utc"))
    if last_seconds is None:
        return False
    return time.time() - last_seconds >= STALLED_FEED_SECONDS


def read_log_tail(log_path, line_count):
    """The last lines of a run's log as one string, or "" when it cannot be read.

    Reads only the last 16 KiB.
    """
    from branchlens import publish

    log_file = publish.open_regular_file(log_path)
    if log_file is None:
        return ""
    try:
        with log_file:
            log_file.seek(0, os.SEEK_END)
            size = log_file.tell()
            log_file.seek(max(size - 16384, 0))
            raw = log_file.read(16384)
    except OSError:
        return ""
    lines = raw.decode("utf-8", errors="replace").split("\n")
    # A progress line that redraws itself with \r keeps only its last state.
    cleaned = []
    for line in lines:
        cleaned.append(line.split("\r")[-1])
    while len(cleaned) > 0 and cleaned[-1].strip() == "":
        cleaned.pop()
    return "\n".join(cleaned[-line_count:])


def read_log_run_id(log_path):
    """The run_id of the run a log belongs to, or None until the log names it.

    The toolkit prints "report in: <run folder>" near the top, and the folder's
    name is the run_id its feed events carry. Only complete lines count.
    """
    from branchlens import publish

    if log_path is None:
        return None
    log_file = publish.open_regular_file(log_path)
    if log_file is None:
        return None
    try:
        with log_file:
            head = log_file.read(RUN_LOG_HEAD_BYTES)
    except OSError:
        return None
    complete_lines = head.decode("utf-8", errors="replace").split("\n")[:-1]
    for line in complete_lines:
        if line.startswith("report in: "):
            folder = line[len("report in: "):].strip().rstrip("/")
            return os.path.basename(folder) or None
    return None


def read_verdict_facts(verdict):
    """What the page needs from a run's verdict.json, or None when it lists no areas.

    areas: its NOT POSSIBLE and PARTIAL rows, as {name, status, reason}, the
    LLM review's included.
    review_incomplete: when such a row's name starts with "Diff review" (the
    review merged but did not cover everything), the reason of the "Diff
    review coverage" row, which names every cause, else "<area>: <reason>" of
    the first other one; None when there is no such row.
    mechanical_advisory: the severity_counts of rows with blocking false,
    summed, without the "Diff review" rows (the feed's findings list those).
    """
    if verdict is None or not isinstance(verdict.get("areas"), list):
        return None
    areas = []
    coverage_reason = None
    other_review_reason = None
    mechanical_advisory = 0
    for row in verdict["areas"]:
        if not isinstance(row, dict) or not isinstance(row.get("area"), str):
            continue
        name = row["area"]
        is_review_row = name.startswith("Diff review")
        status = row.get("status")
        if status in ("NOT POSSIBLE", "PARTIAL"):
            reason = row.get("reason") if isinstance(row.get("reason"), str) else ""
            areas.append({"name": name, "status": status, "reason": reason})
            if name == "Diff review coverage":
                coverage_reason = reason
            elif is_review_row and other_review_reason is None:
                other_review_reason = name
                if reason != "":
                    other_review_reason = name + ": " + reason
        counts = row.get("severity_counts")
        if not is_review_row and row.get("blocking") is False and isinstance(counts, dict):
            for count in counts.values():
                if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                    mechanical_advisory += count
    review_incomplete = coverage_reason
    if not coverage_reason and other_review_reason is not None:
        review_incomplete = other_review_reason
    return {"areas": areas, "review_incomplete": review_incomplete,
            "mechanical_advisory": mechanical_advisory}


def judged_from_scope(scope, repo_root):
    """{branch, commit} a run's review-scope.json says it judges, or None.

    commit is its head_commit; branch is the one local branch whose tip is
    that commit, None when no branch or several are there. A snapshot of
    uncommitted work (check --worktree) judges no commit.
    """
    from branchlens import publish

    if scope is None or scope.get("snapshot") is True:
        return None
    head_commit = scope.get("head_commit")
    if not isinstance(head_commit, str) or not publish.FULL_COMMIT_ID.fullmatch(head_commit):
        return None
    branches_at_commit = []
    for name, tip in publish.read_branch_tips(repo_root).items():
        if tip == head_commit:
            branches_at_commit.append(name)
    branch = None
    if len(branches_at_commit) == 1:
        branch = branches_at_commit[0]
    return {"branch": branch, "commit": head_commit}


def mark_deleted_files_skipped(response, scope):
    """Mark as skipped the pending files the diff deletes, which no deep dive reads.

    scope is the run's review-scope.json; its touched_files carry git's
    status letter. response["files"] is replaced, not changed in place: the
    folded feed it came from is cached.
    """
    if scope is None or not isinstance(scope.get("touched_files"), list):
        return
    files = dict(response["files"])
    for entry in scope["touched_files"]:
        if not isinstance(entry, dict) or entry.get("status") != "D":
            continue
        path = entry.get("path")
        if isinstance(path, str) and path in files and files[path]["status"] == "pending":
            files[path] = {"status": "skipped", "count": None, "reason": DELETED_FILE_REASON}
            response["file_done"] += 1
    response["files"] = files


class PipelineRunner:
    """The security run this server started, if any, and the last push.

    One run at a time. Requests arrive on several threads; the lock makes
    checking for an active run and starting one a single step.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.process = None          # the running pipeline (subprocess.Popen), or None
        self.branch = None           # branch of the active or last run
        self.commit = None           # that branch's tip when the run started
        self.started_utc = None
        self.cancelled_at = None     # time.monotonic() of the last Cancel sent
        self.cancelled_run_id = None  # the feed's latest run_id at that Cancel
        self.exit_code = None        # exit code of the last finished run
        self.log_path = None
        self.closed = False          # True once the server is stopping: no new run starts
        self.base_argument = None    # the base handed to preflight.sh: a commit id or "empty-tree"
        self.base_label = None       # the name that base was read from ("origin/main")
        self.push_in_progress = False
        self.last_push_pushed = None  # None until this server pushes
        self.last_push_output = None
        self.last_push_branch = None  # the branch and commit that push sent
        self.last_push_commit = None

    def notice_finished_run(self):
        """Record the exit code once the run has ended. Call with the lock held."""
        if self.process is not None:
            exit_code = self.process.poll()  # None while it still runs
            if exit_code is not None:
                self.exit_code = exit_code
                self.process = None

    def is_active(self):
        with self.lock:
            self.notice_finished_run()
            return self.process is not None

    def describe(self, toolkit_problem):
        """The `runner` object of /api/security; toolkit_problem is None or why no run can start."""
        with self.lock:
            self.notice_finished_run()
            active = self.process is not None
            log_path = self.log_path
            description = {
                "available": toolkit_problem is None,
                "unavailable_reason": toolkit_problem,
                "active": active,
                "branch": self.branch,
                "started_utc": self.started_utc,
                "exit_code": None if active else self.exit_code,
                "run_id": None,
                "log_tail": None,
            }
        if log_path is not None:
            description["run_id"] = read_log_run_id(log_path)
            description["log_tail"] = read_log_tail(log_path, RUN_LOG_TAIL_LINES)
        return description

    def started_commit(self):
        """The branch tip when the active or last run started, or None."""
        with self.lock:
            return self.commit

    def still_stopping(self, feed_state):
        """True while the run this server last cancelled may still write into the feed.

        That is: the Cancel was sent less than CANCEL_SETTLE_SECONDS ago, and
        the feed's latest run is the one it stopped and has no verdict yet.
        """
        with self.lock:
            if self.cancelled_at is None:
                return False
            if time.monotonic() - self.cancelled_at >= CANCEL_SETTLE_SECONDS:
                return False
            return (feed_state.get("run_id") == self.cancelled_run_id
                    and feed_state.get("running") is True)

    def last_cancelled_run_id(self):
        """The feed's latest run_id at this server's last Cancel, or None."""
        with self.lock:
            return self.cancelled_run_id

    def own_run_id(self):
        """The run_id of the last run this server started, or None until its log names it."""
        with self.lock:
            log_path = self.log_path
        return read_log_run_id(log_path)

    def base_label_for(self, feed_base):
        """The name of the base a run started here used, when feed_base is its commit id.

        None for any other base, which then shows as the feed has it.
        """
        with self.lock:
            if feed_base is None or feed_base != self.base_argument:
                return None
            return self.base_label

    def start(self, command, working_directory, environment, log_path, branch, commit,
              base_argument, base_label):
        """Start the pipeline. Returns None, or why it was not started.

        base_argument is the base handed to preflight.sh, base_label the name
        it was read from.
        """
        with self.lock:
            if self.closed:
                return "BranchLens is shutting down."
            self.notice_finished_run()
            if self.process is not None:
                return "A security check is already running."
            if self.push_in_progress:
                return "A push is in progress: run the check once it has finished."
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            # The log starts empty for each run, so its first lines name
            # this run. O_APPEND: a child of an earlier run that is still
            # stopping writes after the new run's lines, never over them.
            # O_NOFOLLOW: the review's agents can write in the reports
            # folder, and a symlink planted there must not be truncated.
            open_flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_APPEND
                          | getattr(os, "O_NOFOLLOW", 0))
            log_descriptor = os.open(log_path, open_flags, 0o644)
            # The child keeps its own handle on the log file.
            with os.fdopen(log_descriptor, "wb") as log_file:
                # Own process group: Cancel stops the run and all it started,
                # and a Ctrl+C at BranchLens does not reach it.
                self.process = subprocess.Popen(
                    command,
                    cwd=working_directory,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            self.branch = branch
            self.commit = commit
            self.started_utc = utc_now()
            self.exit_code = None
            self.log_path = log_path
            self.base_argument = base_argument
            self.base_label = base_label
            self.last_push_pushed = None
            self.last_push_output = None
            self.last_push_branch = None
            self.last_push_commit = None
            return None

    def cancel(self, feed_run_id=None):
        """Ask the active run to stop. True when there was one to ask.

        Sends SIGTERM to the run's process group; the pipeline then stops its
        children and writes a cancelled verdict into the feed. feed_run_id is
        the feed's latest run at this moment, kept for still_stopping().
        """
        with self.lock:
            self.notice_finished_run()
            if self.process is None:
                return False
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except OSError:
                return False
            self.cancelled_at = time.monotonic()
            self.cancelled_run_id = feed_run_id
            return True

    def close(self):
        """Refuse every later start, then cancel the active run. True when there was one.

        Called when the server stops: a request still being handled cannot
        start a run after the cancel.
        """
        with self.lock:
            self.closed = True
        return self.cancel()

    def begin_push(self):
        """Mark a push as started. Returns None, or why it may not start."""
        with self.lock:
            self.notice_finished_run()
            if self.process is not None:
                return "A security check is running: push once it has finished."
            if self.push_in_progress:
                return "A push is already running."
            self.push_in_progress = True
            return None

    def finish_push(self, pushed, output, branch, commit):
        """Record a push's result, and the branch and commit it sent."""
        with self.lock:
            self.push_in_progress = False
            self.last_push_pushed = pushed
            self.last_push_output = output
            self.last_push_branch = branch
            self.last_push_commit = commit

    def last_push(self):
        """{pushed, output, branch, commit} of the last push this server made; all None before any."""
        with self.lock:
            return {
                "pushed": self.last_push_pushed,
                "output": self.last_push_output,
                "branch": self.last_push_branch,
                "commit": self.last_push_commit,
            }


RUNNER = PipelineRunner()


def default_run_base(repo_root, branch, worktree_path):
    """(ref, label): the base used when the page names none.

    ref is fully qualified, so a tag or a branch spelled like it cannot win
    git's lookup; label is the name to show. For the default branch, its
    push remote's copy of it (refs/remotes/upstream/main, shown
    "upstream/main"), or "empty-tree" for both when that remote has none (a
    first publish). For any other branch, the ref every branch is compared
    with (refs/remotes/origin/main, or refs/heads/main without an online
    copy), shown as on screen. worktree_path is the branch's worktree,
    where a push of it runs from.
    """
    from branchlens import gitops

    branch_names = gitops.list_branch_names(repo_root)
    default_branch, _base_source = gitops.find_default_branch(repo_root, branch_names)
    if branch == default_branch:
        push_facts = gitops.read_push_facts(worktree_path, branch)
        if push_facts["first_publish"]:
            return EMPTY_TREE_BASE, EMPTY_TREE_BASE
        remote_ref = push_facts["remote_ref"]
        return remote_ref, remote_ref[len("refs/remotes/"):]
    comparison = gitops.find_comparison_ref(repo_root, default_branch)
    return comparison["ref"], gitops.comparison_display_name(default_branch, comparison)


def is_plain_base_name(base):
    """True when a base given to /api/run is a full commit id or a plain ref name.

    A plain ref name is letters, digits and . _ / - with no "..", not
    starting with "-" and not ending in ".lock" or "/". git's revision
    syntax (":/<text>", "@{...}") would otherwise let free text through.
    """
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base):
        return True
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._/-]*", base):
        return False
    if ".." in base or base.endswith(".lock") or base.endswith("/"):
        return False
    return True


def resolve_base_commit(repo_root, base):
    """The commit id a base names in this repository, or None when it names none.

    Checked before starting, so a bad base is a 400, not a run that fails at once.
    """
    from branchlens import gitops
    from branchlens import publish

    if base.startswith("-") or len(base) > 256 or publish.has_control_character(base):
        return None
    try:
        # --verify --quiet prints the commit id, or nothing with exit code 1.
        resolved = gitops.run_git_text(
            ["rev-parse", "--verify", "--quiet", base + "^{commit}"],
            cwd=repo_root,
            allow_exit_code_1=True,
        ).strip()
    except gitops.GitError:
        return None
    if resolved == "":
        return None
    return resolved


def default_reports_root(main_repo_root):
    """The default reports folder: $PREFLIGHT_REPORTS_DIR, else
    ~/preflight-reports/<main repository folder name>, where a toolkit with
    the one-folder rule writes whichever worktree a run judges."""
    configured = os.environ.get("PREFLIGHT_REPORTS_DIR", "")
    if configured != "":
        return os.path.abspath(os.path.expanduser(configured))
    return str(Path.home() / "preflight-reports" / Path(main_repo_root).name)


def normalise_host_suffixes(values):
    """Lowercased host suffixes from the flag and the environment variable.

    Each value may hold several, separated by commas or spaces; leading and
    trailing dots are dropped ("example.org" and ".example.org" mean the same).
    """
    suffixes = []
    for value in values:
        for piece in value.replace(",", " ").split():
            suffix = piece.strip().strip(".").lower()
            if suffix != "" and suffix not in suffixes:
                suffixes.append(suffix)
    return suffixes


def stop_on_signal(_signal_number, _frame):
    # `kill` (SIGTERM) and a closed terminal (SIGHUP) stop the server like
    # Ctrl+C, so main()'s clean-up runs.
    raise KeyboardInterrupt()


def print_if_possible(text):
    """print(), except that a terminal closed under the server is not an error."""
    try:
        print(text, flush=True)
    except OSError:
        pass


class BranchLensServer(ThreadingHTTPServer):
    # Connections waiting to be accepted; the default of 5 resets a burst of more.
    request_queue_size = 64

    def server_bind(self):
        # HTTPServer.server_bind also calls socket.getfqdn, a reverse DNS
        # lookup that can stall for seconds on macOS. Nothing here uses the
        # name it finds.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]


def create_server(preferred_port):
    """Bind to the preferred port, falling back to 7431..7451, then any free port."""
    candidate_ports = [preferred_port]
    for port in range(7431, 7452):
        if port != preferred_port:
            candidate_ports.append(port)
    candidate_ports.append(0)  # port 0 asks the OS for any free port

    for port in candidate_ports:
        try:
            # Bind to 127.0.0.1 only: the server must not be reachable
            # from other machines.
            return BranchLensServer(("127.0.0.1", port), BranchLensHandler)
        except (OSError, OverflowError):
            # OverflowError covers a --port value outside 0..65535.
            continue
    raise OSError("Could not find a free port to listen on.")


def opens_browser_by_default(platform):
    """Whether BranchLens opens the browser when neither --browser nor --no-browser is given.

    Not on Linux: there the webbrowser module starts the browser with the
    URL as a command-line argument, and every user of the machine can read
    a process's arguments (/proc/<pid>/cmdline). The URL carries the code
    that lets a browser in.
    """
    return not platform.startswith("linux")


def main():
    parser = argparse.ArgumentParser(
        prog="branchlens",
        description="Local web app to browse what each git branch changes. It "
                    "only reads the repository (git may refresh the file stat "
                    "cache in .git/index while comparing a worktree), except "
                    "for the push you click after a passed security check, "
                    "which also sets the branch's upstream when it has none.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="a directory inside a git repository (default: current directory)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7431,
        help="preferred port to listen on (default: 7431)",
    )
    parser.add_argument(
        "--no-browser",
        dest="open_browser",
        action="store_false",
        default=None,
        help="do not open the web browser automatically (the default on Linux)",
    )
    parser.add_argument(
        "--browser",
        dest="open_browser",
        action="store_true",
        help="open the web browser even on Linux, where other users of the "
             "machine can then read the printed URL in the process list",
    )
    parser.add_argument(
        "--security-feed",
        default=None,
        metavar="PATH",
        help="JSON-lines progress file written by the security pipeline; "
             "BranchLens then shows the check's progress live (the file "
             "may not exist yet)",
    )
    parser.add_argument(
        "--toolkit",
        default=None,
        metavar="PATH",
        help="a security toolkit folder (the one holding preflight.sh); "
             "the Check tab can then run the security pipeline and push a "
             "branch it passed. Optional; the pipeline's LLM review needs the "
             "Claude Code CLI (claude -p, logged in), and Push unlocks only "
             "after that review merged into a READY TO PUBLISH verdict. Also "
             "read from PREFLIGHT_TOOLKIT",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="--toolkit with the toolkit bundled in this clone (toolkit/)",
    )
    parser.add_argument(
        "--no-push-host",
        action="append",
        default=[],
        metavar="HOST",
        help="never push to a remote on this host or any name under it "
             "(repeatable; also read from BRANCHLENS_NO_PUSH_HOSTS, "
             "comma-separated)",
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = parser.parse_args()

    from branchlens import gitops

    try:
        main_repo_root, launch_worktree_root = gitops.find_repo_root(args.path)
        # Check the override mechanism works, then disable the inspected
        # repo's config-driven programs before the first request.
        gitops.verify_config_overrides_work(main_repo_root)
        gitops.configure_repo_hardening(main_repo_root)
    except gitops.GitError as error:
        print("branchlens: " + str(error), file=sys.stderr)
        sys.exit(1)

    BranchLensHandler.repo_root = main_repo_root
    BranchLensHandler.launch_worktree_root = launch_worktree_root

    toolkit = args.toolkit
    if toolkit is None and args.check:
        toolkit = BUNDLED_TOOLKIT
    if toolkit is None and os.environ.get("PREFLIGHT_TOOLKIT", "") != "":
        toolkit = os.environ["PREFLIGHT_TOOLKIT"]
    if toolkit is not None:
        toolkit = os.path.abspath(os.path.expanduser(toolkit))
        BranchLensHandler.toolkit_path = toolkit
        if not os.path.isfile(os.path.join(toolkit, "preflight.sh")):
            where = " (the bundled toolkit is only in a clone)" if toolkit == BUNDLED_TOOLKIT else ""
            print("branchlens: warning: no preflight.sh in " + toolkit + where
                  + "; the security check cannot be started from the page",
                  file=sys.stderr)

    if args.security_feed is not None:
        BranchLensHandler.security_feed_path = os.path.abspath(args.security_feed)
    elif toolkit is not None:
        BranchLensHandler.security_feed_path = os.path.join(
            default_reports_root(main_repo_root), FEED_FILE_NAME
        )
    if toolkit is not None and os.path.basename(BranchLensHandler.security_feed_path) != FEED_FILE_NAME:
        print("branchlens: warning: the toolkit writes its progress to "
              + FEED_FILE_NAME + " in the feed's folder, but the feed given is "
              "named differently; runs started from the page will not show",
              file=sys.stderr)

    BranchLensHandler.blocked_push_hosts = normalise_host_suffixes(
        args.no_push_host + [os.environ.get("BRANCHLENS_NO_PUSH_HOSTS", "")]
    )
    # 32 random bytes as hex each: unguessable, and safe in a URL, a cookie
    # and a header. Three separate values, so one that leaks does not give
    # the others away (see BranchLensHandler.page_token).
    BranchLensHandler.launch_code = secrets.token_hex(32)
    BranchLensHandler.cookie_secret = secrets.token_hex(32)
    BranchLensHandler.page_token = secrets.token_hex(32)
    BranchLensHandler.launch_id = secrets.token_hex(8)

    # Request threads get a 256 MiB stack. Python older than 3.9.10 has no
    # recursion guard in its parser: a deeply nested source file read by the
    # network view could overflow the default stack and crash the server.
    # The memory is only reserved.
    try:
        threading.stack_size(256 * 1024 * 1024)
    except (ValueError, RuntimeError):
        pass

    server = create_server(args.port)
    # server_address holds the real port, needed when the OS picked one.
    actual_port = server.server_address[1]
    repo_name = Path(main_repo_root).name
    # The code in the URL is what lets a browser in (see route_request).
    url = f"http://127.0.0.1:{actual_port}/?token={BranchLensHandler.launch_code}"
    # flush=True: scripts that pipe our output read this line to learn the
    # port, and serve_forever() below never returns to flush the buffer.
    print(f"BranchLens serving {repo_name} at {url}", flush=True)
    if BranchLensHandler.security_feed_path is None:
        print("Security feed: none (pass --security-feed or --toolkit to watch one)", flush=True)
    else:
        print("Security feed: " + BranchLensHandler.security_feed_path, flush=True)

    open_browser = args.open_browser
    if open_browser is None:
        open_browser = opens_browser_by_default(sys.platform)
    if open_browser:
        webbrowser.open(url)

    signal.signal(signal.SIGTERM, stop_on_signal)
    # Closing the terminal sends SIGHUP. A launch under nohup ignores it on
    # purpose, and keeps doing so.
    if hasattr(signal, "SIGHUP") and signal.getsignal(signal.SIGHUP) is not signal.SIG_IGN:
        signal.signal(signal.SIGHUP, stop_on_signal)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print_if_possible("Stopped.")
    finally:
        # Each git child runs in a process group of its own, so neither
        # Ctrl+C nor the server's exit reaches it; one waiting on a named
        # pipe would otherwise outlive the server.
        gitops.stop_running_git()
        # Stop a run this server started rather than leave it writing to the
        # feed, and let no request start another one.
        if RUNNER.close():
            print_if_possible("Stopped the security check this server had started.")
        server.server_close()


if __name__ == "__main__":
    main()
