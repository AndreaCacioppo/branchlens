#!/usr/bin/env bash
# End-to-end test for BranchLens. It builds a throwaway fixture repository,
# starts the server against it and checks the HTTP API and the
# documentation. It prints one PASS/FAIL line per check, exits
# nonzero if any failed, runs from any directory and cleans up after itself.

set -u

# Locate the project from this script's own path, never from the cwd.
PROJECT_DIR=$(cd "$(dirname "$0")" && pwd)
SOURCE_DIR="$PROJECT_DIR/src/branchlens"

# Drop every variable that points git at a repository. A hook, 'rebase -x',
# 'bisect run' or an alias in a linked worktree exports GIT_DIR (a pre-commit
# hook exports GIT_INDEX_FILE), and either one overrides 'git -C'.
unset $(git rev-parse --local-env-vars)

# Isolate git from the user's configuration (signing, hooks,
# init.defaultBranch).
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export PYTHONDONTWRITEBYTECODE=1
# The server reads these; values from the user's shell would change its answers.
unset PREFLIGHT_TOOLKIT PREFLIGHT_REPORTS_DIR BRANCHLENS_NO_PUSH_HOSTS

FIXTURE=""
SERVER_PID=""
SERVER_PORT=""

cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  # Every other server records its pid in a file; some start inside
  # $(...), where a variable would be lost.
  if [ -n "$FIXTURE" ] && [ -f "$FIXTURE/extra-pids" ]; then
    for extra_pid in $(cat "$FIXTURE/extra-pids"); do
      kill "$extra_pid" 2>/dev/null
      wait "$extra_pid" 2>/dev/null
    done
  fi
  if [ -n "$FIXTURE" ]; then
    # Keep the fixture (responses, server logs) when a check failed.
    if [ "${FAILED_CHECKS:-0}" -gt 0 ]; then
      echo "Keeping fixture for inspection: $FIXTURE"
    else
      rm -rf "$FIXTURE"
    fi
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------- check plumbing

TOTAL_CHECKS=0
FAILED_CHECKS=0

check() {
  # $1: description  $2: exit status of the check (0 = pass)
  # $3 (optional): what was seen, such as an HTTP status; printed under a FAIL line.
  local description="$1"
  local status="$2"
  local detail="${3:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  if [ "$status" -eq 0 ]; then
    echo "PASS: $description"
  else
    echo "FAIL: $description"
    if [ -n "$detail" ]; then
      echo "  detail: $detail"
    fi
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
  fi
}

# Evaluate one Python expression against a saved JSON response.
# Inside the expression: `data` is the parsed JSON, `extra` is an optional
# string argument (used for path comparisons), `os` is available.
json_check() {
  local description="$1"
  local response_file="$2"
  local expression="$3"
  local extra="${4:-}"
  # stderr is left alone, so a non-JSON body (after a server crash) shows as a
  # parse traceback.
  python3 -c '
import json, os, sys
with open(sys.argv[1]) as handle:
    data = json.load(handle)
extra = sys.argv[3]
result = eval(sys.argv[2])
sys.exit(0 if result else 1)
' "$response_file" "$expression" "$extra"
  local status=$?
  check "$description" "$status"
  if [ "$status" -ne 0 ]; then
    echo "  expression: $expression"
    echo "  response body (first 4000 bytes of $response_file):"
    head -c 4000 "$response_file"
    echo
  fi
}

# Fix both commit dates for the git commands that follow (exported, so
# subshells and the servers see them too).
set_commit_date() {
  export GIT_AUTHOR_DATE="$1"
  export GIT_COMMITTER_DATE="$1"
}

# Compare two saved /api/state answers. Inside the expression, `before` and
# `after` are the parsed JSON and token(state, name) is that branch's
# content_token.
state_pair_check() {
  local description="$1"
  local before_file="$2"
  local after_file="$3"
  local expression="$4"
  python3 -c '
import json, sys
with open(sys.argv[1]) as handle:
    before = json.load(handle)
with open(sys.argv[2]) as handle:
    after = json.load(handle)
def token(state, name):
    return [b["content_token"] for b in state["branches"] if b["name"] == name][0]
sys.exit(0 if eval(sys.argv[3]) else 1)
' "$before_file" "$after_file" "$expression"
  local status=$?
  check "$description" "$status"
  if [ "$status" -ne 0 ]; then
    echo "  expression: $expression"
    echo "  before: $before_file"
    echo "  after: $after_file"
  fi
}

# GET a URL path from a server; the body goes to $2 and the HTTP status is
# echoed. --path-as-is sends ../ to the server as written. The body file is
# removed first, since curl writes it only when an answer arrives.
http_get() {
  local port="$1"
  local body_file="$2"
  local url_path="$3"
  rm -f "$body_file"
  curl -s -m 5 --path-as-is -b "$(cookie_for "$port")" -o "$body_file" -w '%{http_code}' \
    "http://127.0.0.1:$port$url_path"
}

# POST to a server the way the page does: with the cookie and the Origin
# header http://127.0.0.1:<port>. The body goes to $2 and the HTTP status is
# echoed. $4 is the page token, $5 the Content-Type, $6 the body; further
# arguments go to curl as they are. An empty $4 or $5 sends no such header,
# and -H "Origin:" sends no Origin. An argument that sets Origin replaces the
# default one. Like http_get, it removes the body file first.
http_post() {
  local port="$1"
  local body_file="$2"
  local url_path="$3"
  local token="$4"
  local content_type="$5"
  local request_body="$6"
  shift 6
  local origin_given="no"
  local argument
  for argument in "$@"; do
    case "$argument" in
      Origin:*) origin_given="yes" ;;
    esac
  done
  rm -f "$body_file"
  if [ "$origin_given" = "yes" ]; then
    curl -s -m 10 -b "$(cookie_for "$port")" -o "$body_file" -w '%{http_code}' \
      -H "X-BranchLens-Token: $token" -H "Content-Type: $content_type" \
      "$@" --data-binary "$request_body" "http://127.0.0.1:$port$url_path"
  else
    curl -s -m 10 -b "$(cookie_for "$port")" -o "$body_file" -w '%{http_code}' \
      -H "X-BranchLens-Token: $token" -H "Content-Type: $content_type" \
      -H "Origin: http://127.0.0.1:$port" \
      "$@" --data-binary "$request_body" "http://127.0.0.1:$port$url_path"
  fi
}

# Run http_get and check its HTTP status in one step. Sets the global STATUS
# (call it directly, never inside $(...)). $4 is the expected status, $5 the
# check's description.
expect_get() {
  STATUS=$(http_get "$1" "$2" "$3")
  expect_status "$4" "$5"
}

# Check the HTTP status already in STATUS. An empty STATUS is a failure.
# $3 is an optional detail for a FAIL line; it defaults to the status seen.
expect_status() {
  [ -n "$STATUS" ] && [ "$STATUS" = "$1" ]
  local result=$?
  check "$2" "$result" "${3:-got HTTP $STATUS}"
}

# The page token of the server on port $1, which opening its printed URL
# handed over (see wait_for_server); POSTs send it back.
page_token() {
  local port="$1"
  if [ -f "$FIXTURE/page-tokens/$port" ]; then
    cat "$FIXTURE/page-tokens/$port"
  fi
}

# Poll a server's /api/security until a Python expression about the answer
# holds (inside it, `data` is the parsed JSON). Gives up after $3 seconds,
# 30 when not given. $SECONDS counts whole seconds, so the real wait is up
# to one second shorter: give at least 2.
wait_for_security() {
  local port="$1"
  local expression="$2"
  local timeout="${3:-30}"
  local deadline=$((SECONDS + timeout))
  # Polls once before it checks the clock.
  while true; do
    if curl -s -m 5 -b "$(cookie_for "$port")" "http://127.0.0.1:$port/api/security" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    result = eval(sys.argv[1])
except Exception:
    result = False
sys.exit(0 if result else 1)
' "$expression"; then
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      return 1
    fi
    sleep 0.1
  done
}

# Wait up to 5 seconds for a process to be gone (kill -0 only tests that it exists).
process_ends() {
  local pid="$1"
  local attempt=0
  while [ "$attempt" -lt 50 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  return 1
}

get_state_token() {
  curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" "http://127.0.0.1:$SERVER_PORT/api/state" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["state_token"])' 2>/dev/null
}

# Poll a server log until the startup line appears, then echo the port.
# The printed URL carries the server's launch code (?token=...). Opening it
# once, as a browser does, gives the cookie secret (Set-Cookie) and the page
# token (the Location's #token= fragment). They are kept in
# $FIXTURE/launch-codes/<port>, $FIXTURE/cookies/<port> and
# $FIXTURE/page-tokens/<port>: files, because callers run this inside $(...).
wait_for_server() {
  local log_file="$1"
  local attempt=0
  local port
  local launch_code
  local exchange_headers
  while [ "$attempt" -lt 100 ]; do
    if grep -q "BranchLens serving" "$log_file" 2>/dev/null; then
      port=$(sed -n 's|.*http://127\.0\.0\.1:\([0-9]*\).*|\1|p' "$log_file" | head -n 1)
      launch_code=$(sed -n 's|.*http://127\.0\.0\.1:[0-9]*/?token=\([0-9a-f]*\).*|\1|p' "$log_file" | head -n 1)
      mkdir -p "$FIXTURE/cookies" "$FIXTURE/page-tokens" "$FIXTURE/launch-codes"
      printf '%s\n' "$launch_code" > "$FIXTURE/launch-codes/$port"
      exchange_headers=$(curl -s -m 5 -D - -o /dev/null "http://127.0.0.1:$port/?token=$launch_code")
      printf '%s\n' "$exchange_headers" \
        | sed -n "s|^[Ss]et-[Cc]ookie: branchlens_$port=\([0-9a-f]*\);.*|\1|p" \
        | head -n 1 > "$FIXTURE/cookies/$port"
      printf '%s\n' "$exchange_headers" \
        | sed -n 's|^[Ll]ocation: /#token=\([0-9a-f]*\).*|\1|p' \
        | head -n 1 > "$FIXTURE/page-tokens/$port"
      echo "$port"
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  return 1
}

# The cookie a browser that opened the printed URL sends to the server on
# port $1: branchlens_<port>=<cookie secret>, with no value for an unknown
# server.
cookie_for() {
  local port="$1"
  local token=""
  if [ -f "$FIXTURE/cookies/$port" ]; then
    token=$(cat "$FIXTURE/cookies/$port")
  fi
  printf 'branchlens_%s=%s' "$port" "$token"
}

# A new repository on branch main with a commit identity, Test User
# <test@example.com> unless $2 and $3 give another.
new_repo() {
  git init -q -b main "$1"
  git -C "$1" config user.name "${2:-Test User}"
  git -C "$1" config user.email "${3:-test@example.com}"
}

# ---------------------------------------------------------------- fixture repo

FIXTURE=$(mktemp -d)
# The app.html source checks share one module: the page's text and the
# body of one of its functions. Each check passes the page as argv[1].
# PYTHONPATH also lets every Python snippet below, and `python3 -m
# branchlens`, import the branchlens package from src/.
mkdir -p "$FIXTURE/pylib"
cat > "$FIXTURE/pylib/pagesource.py" <<'PY'
import sys

text = open(sys.argv[1], encoding="utf-8").read()


def function_body(name):
    start = text.index("function " + name + "(")
    return text[start:text.index("\n}\n", start)]
PY
export PYTHONPATH="$PROJECT_DIR/src:$FIXTURE/pylib"
REPO="$FIXTURE/repo"
WORKTREE="$FIXTURE/wt"

# Run needs `claude` on the server's PATH. A stub stands in for it, so the
# run tests behave the same with or without the real CLI installed; the
# fake toolkit below never calls it.
mkdir -p "$FIXTURE/fake-bin"
printf '#!/bin/sh\necho "claude stub"\n' > "$FIXTURE/fake-bin/claude"
chmod +x "$FIXTURE/fake-bin/claude"
export PATH="$FIXTURE/fake-bin:$PATH"

echo "Building fixture repository in $FIXTURE"

git init -b main -q "$REPO"
# Stop before the first write if git answers for another repository here.
if [ "$(git -C "$REPO" rev-parse --absolute-git-dir)" != "$(cd "$REPO" && pwd -P)/.git" ]; then
  echo "FAIL: fixture git dir is not the fixture's own .git"
  FAILED_CHECKS=$((FAILED_CHECKS + 1))  # so cleanup keeps the fixture
  exit 1
fi
git -C "$REPO" config user.name "Test User"
git -C "$REPO" config user.email "test@example.com"

# Fixed, strictly increasing commit dates: git sorts branches by committer
# date with one-second resolution, so real clocks would make ordering flaky.
set_commit_date "2026-01-01T10:00:00 +0000"
printf 'line1\nline2\nline3\nline4\nline5\n' > "$REPO/alpha.txt"
mkdir -p "$REPO/src" "$REPO/docs"
printf 'def hello():\n    return "hello"\n' > "$REPO/src/app.py"
printf 'keep1\nkeep2\nkeep3\nkeep4\nkeep5\nkeep6\nkeep7\nkeep8\nkeep9\nkeep10\n' \
  > "$REPO/src/oldname.py"
printf 'to be deleted\n' > "$REPO/docs/gone.txt"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "Initial commit"

set_commit_date "2026-01-01T10:01:00 +0000"
printf 'line1\nline2\nline3\nline4\nline5\nline6\n' > "$REPO/alpha.txt"
git -C "$REPO" commit -q -am "Extend alpha"

# Both feature branches fork here; main then gains 2 commits, so each
# feature branch ends up exactly 2 behind.
git -C "$REPO" branch feature-committed
git -C "$REPO" branch feature-worktree

set_commit_date "2026-01-01T10:02:00 +0000"
printf 'main only file\n' > "$REPO/mainonly.txt"
git -C "$REPO" add mainonly.txt
git -C "$REPO" commit -q -m "Main-only work 1"

set_commit_date "2026-01-01T10:03:00 +0000"
printf 'more main work\n' >> "$REPO/mainonly.txt"
# The one fixture commit carrying a real body: repeated -m flags become
# subject, blank line, paragraph, blank line, paragraph.
git -C "$REPO" commit -q -am "Main-only work 2" \
  -m "A body paragraph explaining the change." \
  -m "A second paragraph."

# feature-committed: modify + add + delete + rename(+edit) + binary,
# all committed, branch NOT checked out anywhere afterwards.
git -C "$REPO" checkout -q feature-committed
set_commit_date "2026-01-01T10:05:00 +0000"
printf 'line1\nline2 CHANGED\nline3\nline4\nline5\nline6\nadded at end\n' > "$REPO/alpha.txt"
printf 'brand new committed file\nsecond line\n' > "$REPO/src/brandnew.py"
git -C "$REPO" rm -q docs/gone.txt
git -C "$REPO" mv src/oldname.py src/newname.py
printf 'keep1\nkeep2\nkeep3\nkeep4\nkeep5\nkeep6\nkeep7\nkeep8\nkeep9\nkeep10\nedit after rename\n' \
  > "$REPO/src/newname.py"
# 'git rm' above removed the now-empty docs/ directory: recreate it.
mkdir -p "$REPO/docs"
printf '\x00\x01\x02\x03BINARYDATA\x00\xff' > "$REPO/docs/image.bin"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m "Committed feature work"
git -C "$REPO" checkout -q main

# feature-worktree: checked out in a linked worktree, with one committed
# change PLUS an uncommitted edit PLUS an untracked file.
git -C "$REPO" worktree add -q "$WORKTREE" feature-worktree
set_commit_date "2026-01-01T10:06:00 +0000"
printf 'committed change in worktree\n' > "$WORKTREE/wt-committed.txt"
git -C "$WORKTREE" add wt-committed.txt
# An --author other than the committer, as after a rebase or a cherry-pick:
# the API reports both names.
git -C "$WORKTREE" commit -q --author="Original Author <orig@example.com>" \
  -m "Worktree committed work"
printf 'line1\nline2\nline3\nline4\nline5\nline6\nUNCOMMITTED EDIT\n' > "$WORKTREE/alpha.txt"
printf 'untracked line 1\nuntracked line 2\nuntracked line 3\n' > "$WORKTREE/scratch.txt"

# Sanity gate: if the fixture itself is broken, stop before asserting anything.
if ! git -C "$REPO" rev-parse -q --verify feature-committed > /dev/null || \
   ! git -C "$WORKTREE" rev-parse -q --verify feature-worktree > /dev/null; then
  echo "FAIL: fixture repository could not be built"
  FAILED_CHECKS=$((FAILED_CHECKS + 1))  # so cleanup keeps the fixture
  exit 1
fi

# ---------------------------------------------------------------- start server

LOG1="$FIXTURE/server1.log"
python3 -m branchlens "$REPO" --port 0 --no-browser > "$LOG1" 2>&1 &
SERVER_PID=$!

SERVER_PORT=$(wait_for_server "$LOG1")
check "server starts and prints its URL" $?
if [ -z "$SERVER_PORT" ]; then
  echo "Server never became ready; log follows:"
  cat "$LOG1"
  exit 1
fi

RESPONSE="$FIXTURE/response"

# ---------------------------------------------------------------- GET /

expect_get "$SERVER_PORT" "$RESPONSE" "/" "200" "GET / returns HTTP 200"
grep -q "<title>BranchLens</title>" "$RESPONSE"
check "GET / returns the app HTML page" $?

# ---------------------------------------------------------------- /api/state

STATE="$FIXTURE/state.json"
expect_get "$SERVER_PORT" "$STATE" "/api/state" "200" "/api/state returns HTTP 200"

json_check "state: repo_name is the fixture repo" "$STATE" \
  'data["repo_name"] == "repo"'
json_check "state: repo_path resolves to the fixture repo" "$STATE" \
  'os.path.realpath(data["repo_path"]) == os.path.realpath(extra)' "$REPO"
json_check "state: default branch is main via local-main" "$STATE" \
  'data["default_branch"] == "main" and data["base_source"] == "local-main"'
json_check "state: a repository with no remote is not synced online" "$STATE" \
  'data["default_synced_online"] is False'
json_check "state: in a repository with no remote, a run on main is a first publish" "$STATE" \
  'data["first_publish"] is True'
json_check "state: branches ordered by most recent commit first" "$STATE" \
  '[b["name"] for b in data["branches"]] == ["feature-worktree", "feature-committed", "main"]'
json_check "state: state_token is a 12-char token" "$STATE" \
  'isinstance(data["state_token"], str) and len(data["state_token"]) == 12'
json_check "state: refs_token and every branch's content_token are 12-char tokens" "$STATE" \
  'len(data["refs_token"]) == 12 and all(len(b["content_token"]) == 12 for b in data["branches"])'
json_check "state: launch_id is 16 hex characters" "$STATE" \
  'len(data["launch_id"]) == 16 and all(c in "0123456789abcdef" for c in data["launch_id"])'
json_check "state: feature-worktree has worktree_path set to the linked worktree" "$STATE" \
  'os.path.realpath(data["branches"][0]["worktree_path"]) == os.path.realpath(extra)' "$WORKTREE"
json_check "state: feature-worktree has_uncommitted is true" "$STATE" \
  'data["branches"][0]["has_uncommitted"] is True'
json_check "state: feature-worktree is 1 ahead and 2 behind" "$STATE" \
  'data["branches"][0]["ahead"] == 1 and data["branches"][0]["behind"] == 2'
json_check "state: feature-committed has no worktree and no uncommitted edits" "$STATE" \
  'data["branches"][1]["worktree_path"] is None and data["branches"][1]["has_uncommitted"] is False'
json_check "state: feature-committed is 1 ahead and 2 behind" "$STATE" \
  'data["branches"][1]["ahead"] == 1 and data["branches"][1]["behind"] == 2'
json_check "state: main is default, current, 0 ahead and 0 behind" "$STATE" \
  'data["branches"][2]["is_default"] is True and data["branches"][2]["is_current"] is True and data["branches"][2]["ahead"] == 0 and data["branches"][2]["behind"] == 0'

# ---------------------------------------------------------------- /api/diff worktree mode

DIFF_WT="$FIXTURE/diff-worktree.json"
expect_get "$SERVER_PORT" "$DIFF_WT" "/api/diff?branch=feature-worktree" "200" "/api/diff feature-worktree returns HTTP 200"

json_check "diff worktree: mode and exact explanation sentence" "$DIFF_WT" \
  'data["mode"] == "worktree" and data["explanation"] == "Changes on feature-worktree since it forked from main, including edits not yet committed."'
json_check "diff worktree: files sorted, committed + uncommitted + untracked all present" "$DIFF_WT" \
  '[f["path"] for f in data["files"]] == ["alpha.txt", "scratch.txt", "wt-committed.txt"]'
json_check "diff worktree: uncommitted edit to alpha.txt counted" "$DIFF_WT" \
  'data["files"][0]["status"] == "M" and data["files"][0]["adds"] == 1 and data["files"][0]["dels"] == 0 and data["files"][0]["untracked"] is False'
json_check "diff worktree: scratch.txt is untracked, new, 3 lines added" "$DIFF_WT" \
  'data["files"][1]["status"] == "A" and data["files"][1]["untracked"] is True and data["files"][1]["adds"] == 3'
json_check "diff worktree: committed worktree file present as tracked addition" "$DIFF_WT" \
  'data["files"][2]["status"] == "A" and data["files"][2]["untracked"] is False'
json_check "diff worktree: totals add up" "$DIFF_WT" \
  'data["total_adds"] == 5 and data["total_dels"] == 0'

# ---------------------------------------------------------------- /api/diff committed mode

DIFF_CM="$FIXTURE/diff-committed.json"
expect_get "$SERVER_PORT" "$DIFF_CM" "/api/diff?branch=feature-committed" "200" "/api/diff feature-committed returns HTTP 200"

json_check "diff committed: mode and exact explanation sentence" "$DIFF_CM" \
  'data["mode"] == "committed" and data["explanation"] == "Changes on feature-committed since it forked from main."'
json_check "diff committed: file list matches name-status, sorted by path" "$DIFF_CM" \
  '[f["path"] for f in data["files"]] == ["alpha.txt", "docs/gone.txt", "docs/image.bin", "src/brandnew.py", "src/newname.py"]'
json_check "diff committed: statuses are M, D, A, A, R" "$DIFF_CM" \
  '[f["status"] for f in data["files"]] == ["M", "D", "A", "A", "R"]'
json_check "diff committed: rename keeps old_path and its counts" "$DIFF_CM" \
  'data["files"][4]["old_path"] == "src/oldname.py" and data["files"][4]["adds"] == 1 and data["files"][4]["dels"] == 0'
json_check "diff committed: binary file flagged with null counts" "$DIFF_CM" \
  'data["files"][2]["binary"] is True and data["files"][2]["adds"] is None and data["files"][2]["dels"] is None'
json_check "diff committed: nothing marked untracked in committed mode" "$DIFF_CM" \
  'all(f["untracked"] is False for f in data["files"])'
json_check "diff committed: totals add up" "$DIFF_CM" \
  'data["total_adds"] == 5 and data["total_dels"] == 2'

# ---------------------------------------------------------------- /api/diff default branch

DIFF_MAIN="$FIXTURE/diff-main.json"
expect_get "$SERVER_PORT" "$DIFF_MAIN" "/api/diff?branch=main" "200" "/api/diff main returns HTTP 200"

json_check "diff default-branch: a clean checkout is empty and not said to hold edits" "$DIFF_MAIN" \
  'data["mode"] == "default-branch" and data["explanation"] == "Nothing is pending on main." and data["files"] == []'

# ---------------------------------------------------------------- /api/file

FILE_RESP="$FIXTURE/file.json"

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?branch=feature-committed&path=alpha.txt" "200" "/api/file modified file returns HTTP 200"
json_check "file modified: patch shows the changed line" "$FILE_RESP" \
  'data["status"] == "M" and data["binary"] is False and "+line2 CHANGED" in data["patch"] and "-line2" in data["patch"] and "@@" in data["patch"]'

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?branch=feature-worktree&path=scratch.txt" "200" "/api/file untracked file returns HTTP 200"
json_check "file untracked: all-new patch built against /dev/null" "$FILE_RESP" \
  'data["status"] == "A" and "--- /dev/null" in data["patch"] and "+untracked line 1" in data["patch"]'

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?branch=feature-committed&path=src/newname.py" "200" "/api/file renamed file returns HTTP 200"
json_check "file renamed: patch has rename headers and the post-rename edit" "$FILE_RESP" \
  'data["status"] == "R" and "rename from src/oldname.py" in data["patch"] and "rename to src/newname.py" in data["patch"] and "+edit after rename" in data["patch"]'

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?branch=feature-committed&path=docs/image.bin" "200" "/api/file binary file returns HTTP 200"
json_check "file binary: flagged binary with empty patch" "$FILE_RESP" \
  'data["binary"] is True and data["patch"] == ""'

# ---------------------------------------------------------------- error cases

ERR="$FIXTURE/error.json"

expect_get "$SERVER_PORT" "$ERR" "/api/diff?branch=no-such-branch" "404" "unknown branch returns HTTP 404"
json_check "unknown branch: body is a JSON error message" "$ERR" \
  'isinstance(data.get("error"), str) and len(data["error"]) > 0'

expect_get "$SERVER_PORT" "$ERR" "/api/file?branch=feature-committed&path=mainonly.txt" "404" "file not in the diff returns HTTP 404"
json_check "file not in diff: body is a JSON error message" "$ERR" \
  'isinstance(data.get("error"), str) and len(data["error"]) > 0'

expect_get "$SERVER_PORT" "$ERR" "/api/file?branch=feature-committed&path=../../etc/hosts" "404" "path traversal in /api/file returns HTTP 404"
json_check "path traversal: body is a JSON error message" "$ERR" \
  'isinstance(data.get("error"), str) and len(data["error"]) > 0'

expect_get "$SERVER_PORT" "$ERR" "/static/../server.py" "404" "GET /static/../server.py returns HTTP 404"

expect_get "$SERVER_PORT" "$ERR" "/anything-else" "404" "GET /anything-else returns HTTP 404"
json_check "unknown route: body is a JSON error message" "$ERR" \
  'isinstance(data.get("error"), str) and len(data["error"]) > 0'

# ---------------------------------------------------------------- live state token

TOKEN_BEFORE=$(get_state_token)
printf 'another untracked file\n' > "$WORKTREE/second-scratch.txt"
TOKEN_DURING=$(get_state_token)
rm "$WORKTREE/second-scratch.txt"
TOKEN_AFTER=$(get_state_token)

[ -n "$TOKEN_BEFORE" ] && [ "$TOKEN_BEFORE" != "$TOKEN_DURING" ]
check "state_token changes when a worktree file appears" $?
[ "$TOKEN_BEFORE" = "$TOKEN_AFTER" ]
check "state_token returns to its old value when the change is undone" $?

# The page reloads a branch's changes only when that branch's content_token
# moves, and the graph only when refs_token moves. An edit in one worktree
# moves its own branch's token and nothing else.
STATE_BEFORE="$FIXTURE/state-before.json"
STATE_DURING="$FIXTURE/state-during.json"
STATE_AFTER="$FIXTURE/state-after.json"
http_get "$SERVER_PORT" "$STATE_BEFORE" "/api/state" > /dev/null
printf 'another untracked file\n' > "$WORKTREE/second-scratch.txt"
http_get "$SERVER_PORT" "$STATE_DURING" "/api/state" > /dev/null
rm "$WORKTREE/second-scratch.txt"
http_get "$SERVER_PORT" "$STATE_AFTER" "/api/state" > /dev/null
state_pair_check "content_token: an edit in a worktree moves its branch's token" \
  "$STATE_BEFORE" "$STATE_DURING" \
  'token(before, "feature-worktree") != token(after, "feature-worktree")'
state_pair_check "content_token: the edit leaves the other branches' tokens and refs_token alone" \
  "$STATE_BEFORE" "$STATE_DURING" \
  'token(before, "feature-committed") == token(after, "feature-committed") and token(before, "main") == token(after, "main") and before["refs_token"] == after["refs_token"]'
state_pair_check "content_token: undoing the edit brings the old token back" \
  "$STATE_BEFORE" "$STATE_AFTER" \
  'token(before, "feature-worktree") == token(after, "feature-worktree")'
state_pair_check "state: one server keeps the same launch_id from answer to answer" \
  "$STATE_BEFORE" "$STATE_AFTER" \
  'before["launch_id"] == after["launch_id"]'

# Moving a branch tip moves that branch's content_token and refs_token.
COMMITTED_TIP=$(git -C "$REPO" rev-parse refs/heads/feature-committed)
git -C "$REPO" update-ref refs/heads/feature-committed refs/heads/main
http_get "$SERVER_PORT" "$STATE_DURING" "/api/state" > /dev/null
git -C "$REPO" update-ref refs/heads/feature-committed "$COMMITTED_TIP"
http_get "$SERVER_PORT" "$STATE_AFTER" "/api/state" > /dev/null
state_pair_check "refs_token: a branch tip that moves moves refs_token and that branch's token" \
  "$STATE_BEFORE" "$STATE_DURING" \
  'before["refs_token"] != after["refs_token"] and token(before, "feature-committed") != token(after, "feature-committed") and token(before, "feature-worktree") == token(after, "feature-worktree")'
state_pair_check "refs_token: moving the tip back brings both tokens back" \
  "$STATE_BEFORE" "$STATE_AFTER" \
  'before["refs_token"] == after["refs_token"] and token(before, "feature-committed") == token(after, "feature-committed")'

# ---------------------------------------------------------------- launch from inside the worktree

LOG2="$FIXTURE/server2.log"
cd "$WORKTREE"
"$PROJECT_DIR/branchlens" --port 0 --no-browser > "$LOG2" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
cd "$PROJECT_DIR"

SERVER_PORT2=$(wait_for_server "$LOG2")
check "launcher starts from inside the linked worktree" $?

if [ -n "$SERVER_PORT2" ]; then
  STATE2="$FIXTURE/state2.json"
  expect_get "$SERVER_PORT2" "$STATE2" "/api/state" "200" "worktree launch: /api/state returns HTTP 200"
  json_check "worktree launch: same main repository is resolved" "$STATE2" \
    'os.path.realpath(data["repo_path"]) == os.path.realpath(extra)' "$REPO"
  json_check "worktree launch: only feature-worktree is current" "$STATE2" \
    '[b["name"] for b in data["branches"] if b["is_current"]] == ["feature-worktree"]'
  # A page tells a restarted server apart by this id.
  FIRST_LAUNCH_ID=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["launch_id"])' "$STATE")
  json_check "worktree launch: a second server has its own launch_id" "$STATE2" \
    'len(data["launch_id"]) == 16 and data["launch_id"] != extra' "$FIRST_LAUNCH_ID"
else
  check "worktree launch: /api/state returns HTTP 200" 1
  check "worktree launch: same main repository is resolved" 1
  check "worktree launch: only feature-worktree is current" 1
  check "worktree launch: a second server has its own launch_id" 1
fi

# ---------------------------------------------------------------- v2 fixture: merge topology

# The fixture grows only now, after the v1 assertions, whose branch order and
# ahead/behind counts it would change. The server reads git on every request,
# so no restart is needed.

set_commit_date "2026-01-01T10:07:00 +0000"
git -C "$REPO" checkout -q -b feature-merged main
printf 'merged work line 1\nmerged work line 2\n' > "$REPO/merged.txt"
git -C "$REPO" add merged.txt
git -C "$REPO" commit -q -m "Merged feature work"

set_commit_date "2026-01-01T10:08:00 +0000"
git -C "$REPO" checkout -q main
# Captured BEFORE the merge: this becomes the merge commit's first parent.
OLD_MAIN_SHA=$(git -C "$REPO" rev-parse refs/heads/main)
git -C "$REPO" merge -q --no-ff -m "Merge feature-merged into main" feature-merged

MERGE_SHA=$(git -C "$REPO" rev-parse refs/heads/main)
MERGED_TIP_SHA=$(git -C "$REPO" rev-parse refs/heads/feature-merged)
ROOT_SHA=$(git -C "$REPO" rev-list --max-parents=0 refs/heads/main)
# "Main-only work 2": a plain one-file commit with no renames or binaries,
# so its non -z numstat output stays trivially parseable below.
NORMAL_SHA=$OLD_MAIN_SHA
# A real object id that is not a commit; the API rejects it.
BLOB_SHA=$(git -C "$REPO" rev-parse "main:alpha.txt")
# Valid-looking 40-hex id that exists nowhere in the repository.
FAKE_SHA="deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

# ---------------------------------------------------------------- /api/graph

GRAPH="$FIXTURE/graph.json"
expect_get "$SERVER_PORT" "$GRAPH" "/api/graph" "200" "/api/graph returns HTTP 200"

json_check "graph: default branch named, not truncated, commit shape complete" "$GRAPH" \
  'data["default_branch"] == "main" and data["truncated"] is False and all(len(c["sha"]) == 40 and c["short"] == c["sha"][:7] and isinstance(c["parents"], list) and isinstance(c["subject"], str) and isinstance(c["date"], str) and isinstance(c["tips"], list) for c in data["commits"])'
REVLIST_ALL=$(git -C "$REPO" rev-list --branches)
# The server builds the graph with this exact git command against the same
# unmutated repo state, so the order must match line for line.
EXPECTED_ORDER=$(git -C "$REPO" log --branches --date-order -n 150 --format=%H)
json_check "graph: lists exactly the commits of all local branches" "$GRAPH" \
  'sorted(c["sha"] for c in data["commits"]) == sorted(extra.split()) and len(data["commits"]) == 8' "$REVLIST_ALL"
json_check "graph: newest commit (the merge) comes first" "$GRAPH" \
  'data["commits"][0]["sha"] == extra' "$MERGE_SHA"
json_check "graph: commits in git's date order, newest first" "$GRAPH" \
  '[c["sha"] for c in data["commits"]] == extra.split()' "$EXPECTED_ORDER"
json_check "graph: the four branch tips are each marked exactly once" "$GRAPH" \
  'sorted(t for c in data["commits"] for t in c["tips"]) == ["feature-committed", "feature-merged", "feature-worktree", "main"]'
json_check "graph: main's tip is the merge commit" "$GRAPH" \
  '[c["tips"] for c in data["commits"] if c["sha"] == extra] == [["main"]]' "$MERGE_SHA"
json_check "graph: merge commit has 2 parents, first parent is the old main tip" "$GRAPH" \
  '[c["parents"] for c in data["commits"] if c["sha"] == extra.split()[0]] == [[extra.split()[1], extra.split()[2]]]' "$MERGE_SHA $OLD_MAIN_SHA $MERGED_TIP_SHA"
json_check "graph: root commit has an empty parent list" "$GRAPH" \
  '[c["parents"] for c in data["commits"] if c["sha"] == extra] == [[]]' "$ROOT_SHA"

# ---------------------------------------------------------------- /api/diff?commit=

DIFF_COMMIT="$FIXTURE/diff-commit.json"
expect_get "$SERVER_PORT" "$DIFF_COMMIT" "/api/diff?commit=$NORMAL_SHA" "200" "/api/diff normal commit returns HTTP 200"

json_check "diff commit: mode, ids and exact explanation sentence" "$DIFF_COMMIT" \
  'data["mode"] == "commit" and data["is_merge"] is False and data["sha"] == extra and data["short"] == extra[:7] and data["explanation"] == "What commit \"Main-only work 2\" changed."' "$NORMAL_SHA"
NUMSTAT_NORMAL=$(git -C "$REPO" show --format= -M --numstat "$NORMAL_SHA")
json_check "diff commit: files match git show --numstat exactly" "$DIFF_COMMIT" \
  'sorted([f["path"], f["adds"], f["dels"]] for f in data["files"]) == sorted([r.split("\t")[2], int(r.split("\t")[0]), int(r.split("\t")[1])] for r in extra.strip().split("\n"))' "$NUMSTAT_NORMAL"

json_check "diff commit: full message carries subject and body verbatim" "$DIFF_COMMIT" \
  'data["message"] == "Main-only work 2\n\nA body paragraph explaining the change.\n\nA second paragraph."'
json_check "diff commit: subject stays the first line only, body excluded" "$DIFF_COMMIT" \
  'data["subject"] == "Main-only work 2" and data["message"].split("\n")[0] == data["subject"]'
json_check "diff commit: author and committer names reported" "$DIFF_COMMIT" \
  'data["author"] == "Test User" and data["committer"] == "Test User"'

# The worktree commit has a different --author, so the two names come back
# distinct.
WT_SHA=$(git -C "$REPO" rev-parse feature-worktree)
DIFF_WT="$FIXTURE/diff-worktree-commit.json"
expect_get "$SERVER_PORT" "$DIFF_WT" "/api/diff?commit=$WT_SHA" "200" "/api/diff for the differing-author commit returns HTTP 200"
json_check "diff commit: author and committer kept apart when they differ" "$DIFF_WT" \
  'data["author"] == "Original Author" and data["committer"] == "Test User"'

DIFF_MERGE="$FIXTURE/diff-merge.json"
expect_get "$SERVER_PORT" "$DIFF_MERGE" "/api/diff?commit=$MERGE_SHA" "200" "/api/diff merge commit returns HTTP 200"

json_check "diff merge: first-parent diff shows only what the merge brought in" "$DIFF_MERGE" \
  'data["is_merge"] is True and [f["path"] for f in data["files"]] == ["merged.txt"] and data["files"][0]["status"] == "A" and data["total_adds"] == 2 and data["total_dels"] == 0'
json_check "diff merge: exact merge explanation sentence" "$DIFF_MERGE" \
  'data["explanation"] == "What merge \"Merge feature-merged into main\" brought in (compared with the branch it landed on)."'

DIFF_ROOT="$FIXTURE/diff-root.json"
expect_get "$SERVER_PORT" "$DIFF_ROOT" "/api/diff?commit=$ROOT_SHA" "200" "/api/diff root commit returns HTTP 200"

json_check "diff root: all four initial files counted as additions" "$DIFF_ROOT" \
  '[f["path"] for f in data["files"]] == ["alpha.txt", "docs/gone.txt", "src/app.py", "src/oldname.py"] and all(f["status"] == "A" for f in data["files"]) and data["total_adds"] == 18 and data["total_dels"] == 0'
json_check "diff root: mode commit with exact explanation sentence" "$DIFF_ROOT" \
  'data["mode"] == "commit" and data["is_merge"] is False and data["explanation"] == "What commit \"Initial commit\" changed."'
json_check "diff root: a body-less commit message is the subject with no trailing blank" "$DIFF_ROOT" \
  'data["message"] == "Initial commit"'

# ---------------------------------------------------------------- /api/file?commit=

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?commit=$NORMAL_SHA&path=mainonly.txt" "200" "/api/file for a commit returns HTTP 200"
json_check "file commit: patch shows the line that commit added" "$FILE_RESP" \
  'data["status"] == "M" and "+more main work" in data["patch"] and "@@" in data["patch"]'

# ---------------------------------------------------------------- commit id validation

expect_get "$SERVER_PORT" "$ERR" "/api/diff?commit=$FAKE_SHA" "404" "well-formed sha not in the graph returns HTTP 404"
# ' is an apostrophe, which cannot appear inside this single-quoted
# argument.
json_check "unknown commit: exact binding error message" "$ERR" \
  'data["error"] == "That commit isn\u0027t in the current graph."'

expect_get "$SERVER_PORT" "$ERR" "/api/diff?commit=$BLOB_SHA" "404" "sha of a blob object returns HTTP 404"

SHORT_SHA=$(printf '%s' "$NORMAL_SHA" | head -c 7)
expect_get "$SERVER_PORT" "$ERR" "/api/diff?commit=$SHORT_SHA" "404" "abbreviated sha returns HTTP 404"

expect_get "$SERVER_PORT" "$ERR" "/api/diff?commit=not-a-sha" "404" "malformed sha returns HTTP 404"

expect_get "$SERVER_PORT" "$ERR" "/api/file?commit=$FAKE_SHA&path=alpha.txt" "404" "/api/file with an unknown commit returns HTTP 404"

expect_get "$SERVER_PORT" "$ERR" "/api/diff?branch=main&commit=$MERGE_SHA" "400" "branch= and commit= together return HTTP 400"
json_check "branch+commit: body is a JSON error message" "$ERR" \
  'isinstance(data.get("error"), str) and len(data["error"]) > 0'

# ---------------------------------------------------------------- compare with any point (base=)

DIFF_BASE="$FIXTURE/diff-branch-base.json"
expect_get "$SERVER_PORT" "$DIFF_BASE" "/api/diff?branch=feature-worktree&base=$ROOT_SHA" "200" "/api/diff branch with base override returns HTTP 200"

json_check "diff branch+base: worktree mode with base_override and base_subject" "$DIFF_BASE" \
  'data["mode"] == "worktree" and data["base_override"] is True and data["base_subject"] == "Initial commit"'
json_check "diff branch+base: exact explanation names the base point" "$DIFF_BASE" \
  'data["explanation"] == "Changes on feature-worktree since \"Initial commit\", including edits not yet committed."'
json_check "diff branch+base: committed, uncommitted and untracked edits all included" "$DIFF_BASE" \
  '[f["path"] for f in data["files"]] == ["alpha.txt", "scratch.txt", "wt-committed.txt"] and data["files"][0]["adds"] == 2 and data["files"][1]["untracked"] is True'

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?branch=feature-worktree&path=alpha.txt&base=$ROOT_SHA" "200" "/api/file branch with base override returns HTTP 200"
json_check "file branch+base: patch spans committed and uncommitted edits" "$FILE_RESP" \
  '"+line6" in data["patch"] and "+UNCOMMITTED EDIT" in data["patch"]'

DIFF_RANGE="$FIXTURE/diff-range.json"
expect_get "$SERVER_PORT" "$DIFF_RANGE" "/api/diff?commit=$MERGE_SHA&base=$ROOT_SHA" "200" "/api/diff commit with base override returns HTTP 200"

json_check "diff range: mode range with base_override and exact explanation" "$DIFF_RANGE" \
  'data["mode"] == "range" and data["base_override"] is True and data["explanation"] == "Everything that changed from \"Initial commit\" to \"Merge feature-merged into main\"."'
NUMSTAT_RANGE=$(git -C "$REPO" diff -M --numstat "$ROOT_SHA" "$MERGE_SHA")
json_check "diff range: files match git diff --numstat exactly" "$DIFF_RANGE" \
  'sorted([f["path"], f["adds"], f["dels"]] for f in data["files"]) == sorted([r.split("\t")[2], int(r.split("\t")[0]), int(r.split("\t")[1])] for r in extra.strip().split("\n"))' "$NUMSTAT_RANGE"

expect_get "$SERVER_PORT" "$DIFF_RANGE" "/api/diff?commit=$MERGE_SHA&base=$MERGE_SHA" "200" "/api/diff with base equal to the target returns HTTP 200"
json_check "diff range: base equal to target yields zero files" "$DIFF_RANGE" \
  'data["files"] == [] and data["total_adds"] == 0 and data["total_dels"] == 0'

expect_get "$SERVER_PORT" "$ERR" "/api/diff?branch=feature-worktree&base=$FAKE_SHA" "404" "base sha not in the graph returns HTTP 404 (branch target)"

expect_get "$SERVER_PORT" "$ERR" "/api/diff?commit=$MERGE_SHA&base=$BLOB_SHA" "404" "base sha of a blob object returns HTTP 404 (commit target)"

expect_get "$SERVER_PORT" "$ERR" "/api/diff?branch=main&commit=$MERGE_SHA&base=$ROOT_SHA" "400" "branch= and commit= together still return HTTP 400 when base= rides along"

# ---------------------------------------------------------------- one entry per path

# A file deleted from the index but still on disk shows up in git as BOTH a
# tracked deletion and an untracked file; the API must list the path once.
git -C "$WORKTREE" rm -q --cached alpha.txt

DIFF_DUP="$FIXTURE/diff-dup.json"
expect_get "$SERVER_PORT" "$DIFF_DUP" "/api/diff?branch=feature-worktree" "200" "/api/diff with an index-deleted file returns HTTP 200"
json_check "diff dedup: no path is listed twice" "$DIFF_DUP" \
  'len(set(f["path"] for f in data["files"])) == len(data["files"])'
json_check "diff dedup: the tracked deletion entry wins" "$DIFF_DUP" \
  '[f["status"] for f in data["files"] if f["path"] == "alpha.txt"] == ["D"] and all(f["untracked"] is False for f in data["files"] if f["path"] == "alpha.txt")'

expect_get "$SERVER_PORT" "$FILE_RESP" "/api/file?branch=feature-worktree&path=alpha.txt" "200" "/api/file for the index-deleted file returns HTTP 200"

expect_get "$SERVER_PORT" "$DIFF_DUP" "/api/diff?branch=feature-worktree&base=$ROOT_SHA" "200" "/api/diff with base override and an index-deleted file returns HTTP 200"
json_check "diff dedup: no path is listed twice with a base override either" "$DIFF_DUP" \
  'len(set(f["path"] for f in data["files"])) == len(data["files"])'

# Put the index entry back exactly as it was (alpha.txt's edit stays unstaged).
git -C "$WORKTREE" reset -q -- alpha.txt

# ---------------------------------------------------------------- separator in a subject

# Git allows U+001E (the graph's record separator) inside a commit subject;
# the subject must come through /api/graph whole, not cut at the separator.
set_commit_date "2026-01-01T10:09:00 +0000"
git -C "$REPO" commit -q --allow-empty -m "$(printf 'before\036after the separator')"
SEPARATOR_SHA=$(git -C "$REPO" rev-parse refs/heads/main)

GRAPH_SEP="$FIXTURE/graph-separator.json"
expect_get "$SERVER_PORT" "$GRAPH_SEP" "/api/graph" "200" "/api/graph with a separator-in-subject commit returns HTTP 200"
json_check "graph: a subject containing the record separator survives whole" "$GRAPH_SEP" \
  '[c["subject"] for c in data["commits"] if c["sha"] == extra] == ["before\u001eafter the separator"]' "$SEPARATOR_SHA"
json_check "graph: no commit record was lost around the odd subject" "$GRAPH_SEP" \
  'len(data["commits"]) == 9'

# ---------------------------------------------------------------- synced-online default branch

# A clone whose local main was never pulled: the online default branch is three
# commits ahead of it. Everything must be measured against the online one.
ONLINE_ORIGIN="$FIXTURE/online-origin"
ONLINE_CLONE="$FIXTURE/online-clone"

new_repo "$ONLINE_ORIGIN"
set_commit_date "2026-02-01T09:00:00 +0000"
printf 'shared\n' > "$ONLINE_ORIGIN/shared.txt"
git -C "$ONLINE_ORIGIN" add shared.txt
git -C "$ONLINE_ORIGIN" commit -q -m "shared starting point"
for step in 1 2 3; do
  set_commit_date "2026-02-01T09:0$step:00 +0000"
  printf 'online %s\n' "$step" > "$ONLINE_ORIGIN/online$step.txt"
  git -C "$ONLINE_ORIGIN" add "online$step.txt"
  git -C "$ONLINE_ORIGIN" commit -q -m "online commit $step"
done

git clone -q "$ONLINE_ORIGIN" "$ONLINE_CLONE"
git -C "$ONLINE_CLONE" config user.name "Test User"
git -C "$ONLINE_CLONE" config user.email "test@example.com"
# never pulled: the local branch stays three commits behind the online one
git -C "$ONLINE_CLONE" reset -q --hard HEAD~3

ONLINE_TIP=$(git -C "$ONLINE_CLONE" rev-parse origin/main)
STALE_LOCAL_TIP=$(git -C "$ONLINE_CLONE" rev-parse --short main)

LOG3="$FIXTURE/server3.log"
cd "$ONLINE_CLONE"
"$PROJECT_DIR/branchlens" --port 0 --no-browser > "$LOG3" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
cd "$PROJECT_DIR"

SERVER_PORT3=$(wait_for_server "$LOG3")
check "launcher starts on a clone whose local branch is behind" $?

if [ -n "$SERVER_PORT3" ]; then
  STATE3="$FIXTURE/state3.json"
  GRAPH3="$FIXTURE/graph3.json"
  DIFF3="$FIXTURE/diff3.json"

  expect_get "$SERVER_PORT3" "$STATE3" "/api/state" "200" "online: /api/state returns HTTP 200"
  json_check "online: the default branch is reported as synced online" "$STATE3" \
    'data["default_synced_online"] is True'

  # Nothing local reaches the three online commits at this point, so they can
  # only appear because the comparison ref joined the log population.
  expect_get "$SERVER_PORT3" "$GRAPH3" "/api/graph" "200" "online: /api/graph returns HTTP 200"
  json_check "online: commits no local branch reaches are still in the graph" "$GRAPH3" \
    'len(data["commits"]) == 4'
  json_check "online: online_tip_sha names the online default branch tip" "$GRAPH3" \
    'data["online_tip_sha"] == extra' "$ONLINE_TIP"
  json_check "online: exactly one commit carries that sha" "$GRAPH3" \
    'len([c for c in data["commits"] if c["sha"] == extra]) == 1' "$ONLINE_TIP"
  json_check "online: tips stay local branch names only" "$GRAPH3" \
    '[c["tips"] for c in data["commits"]] == [[], [], [], ["main"]]'

  # A branch forked from the online tip: its counts and its fork point must be
  # measured there, not against the local branch that was left behind.
  git -C "$ONLINE_CLONE" checkout -q -b feature origin/main
  printf 'feature work\n' > "$ONLINE_CLONE/feat.txt"
  git -C "$ONLINE_CLONE" add feat.txt
  set_commit_date "2026-02-01T09:05:00 +0000"
  git -C "$ONLINE_CLONE" commit -q -m "feature work"
  git -C "$ONLINE_CLONE" checkout -q main

  expect_get "$SERVER_PORT3" "$STATE3" "/api/state" "200" "online: /api/state after branching returns HTTP 200"
  json_check "online: ahead is counted from the online tip, not the stale one" "$STATE3" \
    '[(b["ahead"], b["behind"]) for b in data["branches"] if b["name"] == "feature"] == [(1, 0)]'

  expect_get "$SERVER_PORT3" "$DIFF3" "/api/diff?branch=feature" "200" "online: /api/diff for the branch returns HTTP 200"
  json_check "online: the fork point is the online tip" "$DIFF3" \
    'data["mode"] == "committed" and data["base_commit"] == extra[:7]' "$ONLINE_TIP"
  json_check "online: the stale local tip is not used as the fork point" "$DIFF3" \
    'data["base_commit"] != extra' "$STALE_LOCAL_TIP"
  json_check "online: only the branch's own file is listed" "$DIFF3" \
    '[f["path"] for f in data["files"]] == ["feat.txt"]'

  # The commit ids the API accepts are the same extended listing the graph
  # exposes, so a commit that only the online branch reaches is selectable.
  COMMITDIFF3="$FIXTURE/commitdiff3.json"
  expect_get "$SERVER_PORT3" "$COMMITDIFF3" "/api/diff?commit=$ONLINE_TIP" "200" "online: a commit only the online branch reaches is accepted"
  json_check "online: that commit is diffed against its first parent" "$COMMITDIFF3" \
    'data["mode"] == "commit" and [f["path"] for f in data["files"]] == ["online3.txt"]'

  # A fetch moves the online ref without touching any local branch; the token
  # moves too.
  TOKEN_BEFORE_FETCH=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT3")" "http://127.0.0.1:$SERVER_PORT3/api/state" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["state_token"])' 2>/dev/null)
  set_commit_date "2026-02-01T09:06:00 +0000"
  printf 'online 4\n' > "$ONLINE_ORIGIN/online4.txt"
  git -C "$ONLINE_ORIGIN" add online4.txt
  git -C "$ONLINE_ORIGIN" commit -q -m "online commit 4"
  git -C "$ONLINE_CLONE" fetch -q origin
  TOKEN_AFTER_FETCH=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT3")" "http://127.0.0.1:$SERVER_PORT3/api/state" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["state_token"])' 2>/dev/null)
  [ -n "$TOKEN_BEFORE_FETCH" ] && [ "$TOKEN_BEFORE_FETCH" != "$TOKEN_AFTER_FETCH" ]
  check "online: state_token changes when a fetch moves the online branch" $?
fi

# ---------------------------------------------------------------- hostile repository: no code execution

# A repository can name programs in its own config that git will run even
# though BranchLens only reads the repository. Each check below first proves
# the trap is armed (plain git springs it), then proves BranchLens does not.

# --- content filter: filter.<name>.clean runs when git reads a working file ---

FILTER_REPO="$FIXTURE/filter-repo"
FILTER_MARKER="$FIXTURE/filter-marker"

new_repo "$FILTER_REPO"
printf '*.dat filter=pwn\n' > "$FILTER_REPO/.gitattributes"
printf 'original content\n' > "$FILTER_REPO/secret.dat"
set_commit_date "2026-03-01T10:00:00 +0000"
git -C "$FILTER_REPO" add -A
git -C "$FILTER_REPO" commit -q -m "Add a filtered file"
# Arm the filter only AFTER committing: 'git add' would run it too, and the
# marker would then exist before the test ever starts.
git -C "$FILTER_REPO" config --local filter.pwn.clean "touch $FILTER_MARKER; cat"
# Plain shell write, so no git command reads the file before the server does.
printf 'modified in the working tree\n' > "$FILTER_REPO/secret.dat"

# Self-check: plain git springs the trap, so the assertion below means
# something.
rm -f "$FILTER_MARKER"
git -C "$FILTER_REPO" diff --numstat > /dev/null 2>&1
[ -e "$FILTER_MARKER" ]
check "hostile filter: the fixture really does make plain git run a program" $?
rm -f "$FILTER_MARKER"

LOG4="$FIXTURE/server4.log"
python3 -m branchlens "$FILTER_REPO" --port 0 --no-browser > "$LOG4" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT4=$(wait_for_server "$LOG4")
check "hostile filter: server starts on the repository" $?

if [ -n "$SERVER_PORT4" ]; then
  FILTER_STATE="$FIXTURE/filter-state.json"
  FILTER_DIFF="$FIXTURE/filter-diff.json"
  expect_get "$SERVER_PORT4" "$FILTER_STATE" "/api/state" "200" "hostile filter: /api/state returns HTTP 200"
  expect_get "$SERVER_PORT4" "$FILTER_DIFF" "/api/diff?branch=main" "200" "hostile filter: /api/diff returns HTTP 200"
  # The diff was produced, and the repository's program never ran.
  [ ! -e "$FILTER_MARKER" ]
  check "hostile filter: BranchLens never ran the repository's clean filter" $?
fi

# --- filesystem monitor: core.fsmonitor is a program git launches ---

FSMON_REPO="$FIXTURE/fsmonitor-repo"
FSMON_MARKER="$FIXTURE/fsmonitor-marker"
FSMON_SCRIPT="$FIXTURE/fsmonitor-hook.sh"

new_repo "$FSMON_REPO"
printf 'hello\n' > "$FSMON_REPO/a.txt"
set_commit_date "2026-03-01T10:01:00 +0000"
git -C "$FSMON_REPO" add -A
git -C "$FSMON_REPO" commit -q -m "Initial commit"
# Exit 1 tells git "no fast answer, scan normally", so the repository still
# behaves; only the side effect (the marker) shows the program ran.
printf '#!/bin/sh\ntouch "%s"\nexit 1\n' "$FSMON_MARKER" > "$FSMON_SCRIPT"
chmod +x "$FSMON_SCRIPT"
git -C "$FSMON_REPO" config --local core.fsmonitor "$FSMON_SCRIPT"
printf 'uncommitted edit\n' >> "$FSMON_REPO/a.txt"

rm -f "$FSMON_MARKER"
git -C "$FSMON_REPO" status --porcelain > /dev/null 2>&1
[ -e "$FSMON_MARKER" ]
check "hostile fsmonitor: the fixture really does make plain git run a program" $?
rm -f "$FSMON_MARKER"

LOG5="$FIXTURE/server5.log"
python3 -m branchlens "$FSMON_REPO" --port 0 --no-browser > "$LOG5" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT5=$(wait_for_server "$LOG5")
check "hostile fsmonitor: server starts on the repository" $?

if [ -n "$SERVER_PORT5" ]; then
  FSMON_STATE="$FIXTURE/fsmonitor-state.json"
  expect_get "$SERVER_PORT5" "$FSMON_STATE" "/api/state" "200" "hostile fsmonitor: /api/state returns HTTP 200"
  # Poll twice: the first request opens the repository, later ones are the
  # steady-state path the UI actually uses.
  expect_get "$SERVER_PORT5" "$FSMON_STATE" "/api/state" "200" "hostile fsmonitor: a second /api/state returns HTTP 200"
  [ ! -e "$FSMON_MARKER" ]
  check "hostile fsmonitor: BranchLens never ran the repository's filesystem monitor" $?
fi

# ---------------------------------------------------------------- hostile repository: no out-of-repo reads

# A repository can point ".git/worktrees/<name>/gitdir" at any directory on
# disk. Unchecked, BranchLens would treat that directory as one of its
# worktrees and serve its files; here it is a private second clone.

EVIL_REPO="$FIXTURE/evil-repo"
PRIVATE_CLONE="$FIXTURE/private-clone"
SENTINEL="TOPSECRETSENTINEL9271"

new_repo "$EVIL_REPO"
printf 'hello\n' > "$EVIL_REPO/a.txt"
set_commit_date "2026-03-01T10:02:00 +0000"
git -C "$EVIL_REPO" add -A
git -C "$EVIL_REPO" commit -q -m "Initial commit"
git -C "$EVIL_REPO" branch evil-branch

# The victim directory: a separate clone holding a private untracked file. It
# shares history with the hostile repo, which is what would let the diff of a
# redirected worktree resolve and hand the file's contents back over HTTP.
git clone -q "$EVIL_REPO" "$PRIVATE_CLONE"
printf '%s\n' "$SENTINEL" > "$PRIVATE_CLONE/private-notes.txt"

mkdir -p "$EVIL_REPO/.git/worktrees/evil"
printf '%s/.git\n' "$PRIVATE_CLONE" > "$EVIL_REPO/.git/worktrees/evil/gitdir"
printf 'ref: refs/heads/evil-branch\n' > "$EVIL_REPO/.git/worktrees/evil/HEAD"
printf '../..\n' > "$EVIL_REPO/.git/worktrees/evil/commondir"

# Self-check: git itself reports the redirect, so the assertions below have
# something to reject.
git -C "$EVIL_REPO" worktree list --porcelain | grep -q "$PRIVATE_CLONE"
check "hostile worktree: git really does report the redirected directory" $?

LOG6="$FIXTURE/server6.log"
python3 -m branchlens "$EVIL_REPO" --port 0 --no-browser > "$LOG6" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT6=$(wait_for_server "$LOG6")
check "hostile worktree: server starts on the repository" $?

if [ -n "$SERVER_PORT6" ]; then
  EVIL_STATE="$FIXTURE/evil-state.json"
  EVIL_DIFF="$FIXTURE/evil-diff.json"
  EVIL_FILE="$FIXTURE/evil-file.json"

  expect_get "$SERVER_PORT6" "$EVIL_STATE" "/api/state" "200" "hostile worktree: /api/state returns HTTP 200"
  # realpath both sides: on macOS the temp dir is reached through a symlink.
  json_check "hostile worktree: no branch is mapped to the outside directory" "$EVIL_STATE" \
    'all(os.path.realpath(b["worktree_path"]) != os.path.realpath(extra) for b in data["branches"] if b["worktree_path"])' "$PRIVATE_CLONE"
  ! grep -q "$PRIVATE_CLONE" "$EVIL_STATE"
  check "hostile worktree: the outside path appears nowhere in /api/state" $?

  # The branch must fall back to plain committed viewing, not to reading the
  # redirected directory.
  expect_get "$SERVER_PORT6" "$EVIL_DIFF" "/api/diff?branch=evil-branch" "200" "hostile worktree: /api/diff returns HTTP 200"
  json_check "hostile worktree: the branch is viewed as committed-only" "$EVIL_DIFF" \
    'data["mode"] == "committed"'
  json_check "hostile worktree: the private file is not listed in /api/diff" "$EVIL_DIFF" \
    'all(f["path"] != "private-notes.txt" for f in data["files"])' 

  STATUS=$(http_get "$SERVER_PORT6" "$EVIL_FILE" "/api/file?branch=evil-branch&path=private-notes.txt")
  # An answer must have arrived: '! grep' passes on a missing file.
  [ -s "$EVIL_FILE" ] && ! grep -q "$SENTINEL" "$EVIL_FILE"
  check "hostile worktree: /api/file never returns the private file's contents" $? "got HTTP $STATUS"
fi

# ---------------------------------------------------------------- legitimate setups still work

# The worktree validation rejects only hostile redirects. A submodule is the
# legitimate edge case: 'git worktree list' reports its git dir under
# <superproject>/.git/modules/<name>, which holds no ".git" entry, and its
# uncommitted work must still show.

SUPER_REPO="$FIXTURE/superproject"
SUB_REPO="$FIXTURE/submodule-source"

new_repo "$SUB_REPO"
printf 'submodule content\n' > "$SUB_REPO/s.txt"
set_commit_date "2026-03-01T10:03:00 +0000"
git -C "$SUB_REPO" add -A
git -C "$SUB_REPO" commit -q -m "Submodule initial commit"

new_repo "$SUPER_REPO"
printf 'superproject\n' > "$SUPER_REPO/a.txt"
git -C "$SUPER_REPO" add -A
git -C "$SUPER_REPO" commit -q -m "Superproject initial commit"
# protocol.file.allow: recent git refuses local-path submodules by default.
git -C "$SUPER_REPO" -c protocol.file.allow=always \
  submodule add -q "$SUB_REPO" vendor > /dev/null 2>&1
git -C "$SUPER_REPO" commit -q -m "Add the submodule"
printf 'uncommitted edit inside the submodule\n' >> "$SUPER_REPO/vendor/s.txt"

LOG7="$FIXTURE/server7.log"
python3 -m branchlens "$SUPER_REPO/vendor" --port 0 --no-browser > "$LOG7" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT7=$(wait_for_server "$LOG7")
check "submodule: server starts when pointed inside a submodule" $?

if [ -n "$SERVER_PORT7" ]; then
  SUB_STATE="$FIXTURE/submodule-state.json"
  SUB_DIFF="$FIXTURE/submodule-diff.json"
  expect_get "$SERVER_PORT7" "$SUB_STATE" "/api/state" "200" "submodule: /api/state returns HTTP 200"
  json_check "submodule: the uncommitted edit is still noticed" "$SUB_STATE" \
    'any(b["has_uncommitted"] for b in data["branches"])'
  expect_get "$SERVER_PORT7" "$SUB_DIFF" "/api/diff?branch=main" "200" "submodule: /api/diff returns HTTP 200"
  json_check "submodule: the edited file is listed" "$SUB_DIFF" \
    '[f["path"] for f in data["files"]] == ["s.txt"]'
fi

# ---------------------------------------------------------------- security feed

# Without --security-feed the feature is off.
SEC_OFF="$FIXTURE/security-off.json"
expect_get "$SERVER_PORT" "$SEC_OFF" "/api/security" "200" "security: /api/security answers 200 without the flag"
json_check "security: feature reported off without the flag" "$SEC_OFF" \
  'data == {"enabled": False}'

# With the flag but no file yet: enabled, no run recorded, no error.
FEED_FILE="$FIXTURE/security-feed.jsonl"
LOG8="$FIXTURE/server8.log"
python3 -m branchlens "$REPO" --port 0 --no-browser \
  --security-feed "$FEED_FILE" > "$LOG8" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT8=$(wait_for_server "$LOG8")
[ -n "$SERVER_PORT8" ]
check "security: server starts with --security-feed pointing at a missing file" $?

SEC_EMPTY="$FIXTURE/security-empty.json"
expect_get "$SERVER_PORT8" "$SEC_EMPTY" "/api/security" "200" "security: missing feed file still answers 200"
json_check "security: missing feed = enabled, not running, no files" "$SEC_EMPTY" \
  'data["enabled"] is True and data["running"] is False and data["files"] == {} and data["verdict"] is None'

# The watched feed is named: on the startup line, in /api/security, and on
# the Check tab while the feed holds no run.
grep -qxF "Security feed: none (pass --security-feed or --toolkit to watch one)" "$LOG1"
check "feed path: without a feed, the startup line says none is watched" $?
grep -qxF "Security feed: $FEED_FILE" "$LOG8"
check "feed path: with --security-feed, the startup line names the feed" $?
json_check "feed path: /api/security names the watched feed" "$SEC_EMPTY" \
  'data["feed_path"] == extra' "$FEED_FILE"
python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
timeline = function_body("updateCheckTimeline")
if timeline.index("updateFeedLine(parts.feedLine, view);") > timeline.index("if (nothingYet) {"):
    sys.exit(1)
feed_line = function_body("updateFeedLine")
for piece in ['"Watching "', '": no run recorded there yet."', "securityState.feed_path",
              "var holdsNoRun = view.feed === null && !view.inProgress;",
              'holdsNoRun ? ": no run recorded there yet." : "."']:
    if piece not in feed_line:
        sys.exit(1)
# Shown whenever the path is known, whatever the feed holds.
if 'line.hidden = typeof feedPath !== "string";' not in feed_line:
    sys.exit(1)
if "timeline.appendChild(parts.feedLine);" not in function_body("buildTimelineParts"):
    sys.exit(1)
sys.exit(0)
PY
check "feed path: the Check tab always names the feed it watches, and says when it holds no run" $?

# A run in progress: start marker, one finished file, one being checked,
# a garbage line, and a partial last line (the writer caught mid-append).
cat > "$FEED_FILE" <<'FEED'
{"event": "start", "run_id": "run-1", "base": "origin/main", "files": ["alpha.txt", "beta.txt", "gamma.txt"]}
{"event": "file", "path": "alpha.txt", "status": "checking"}
{"event": "file", "path": "alpha.txt", "status": "findings", "count": 3}
{"event": "file", "path": "beta.txt", "status": "checking"}
this line is garbage and must be skipped {{{
{"event": "file", "path": "beta.txt", "st
FEED

SEC_RUN="$FIXTURE/security-running.json"
STATUS=$(http_get "$SERVER_PORT8" "$SEC_RUN" "/api/security")
json_check "security: running state folds files, counts and current path" "$SEC_RUN" \
  'data["running"] is True and data["base"] == "origin/main" and data["file_total"] == 3 and data["file_done"] == 1 and data["current_path"] == "beta.txt" and data["files"]["alpha.txt"] == {"status": "findings", "count": 3} and data["files"]["beta.txt"]["status"] == "checking" and data["files"]["gamma.txt"]["status"] == "pending"'

# A verdict ends the run and is reported verbatim...
printf '%s\n' '{"event": "verdict", "text": "PREFLIGHT: PASSED - mechanical gate"}' >> "$FEED_FILE"
SEC_DONE="$FIXTURE/security-done.json"
STATUS=$(http_get "$SERVER_PORT8" "$SEC_DONE" "/api/security")
json_check "security: a verdict ends the run and is reported verbatim" "$SEC_DONE" \
  'data["running"] is False and data["verdict"] == "PREFLIGHT: PASSED - mechanical gate"'

# ...but per-file work arriving after it flips the run back to running (the
# pipeline emits the mechanical verdict first and the deep dives after it).
printf '%s\n' '{"event": "file", "path": "beta.txt", "status": "clean"}' >> "$FEED_FILE"
SEC_RESUMED="$FIXTURE/security-resumed.json"
STATUS=$(http_get "$SERVER_PORT8" "$SEC_RESUMED" "/api/security")
json_check "security: per-file work after a verdict counts as running again" "$SEC_RESUMED" \
  'data["running"] is True and data["verdict"] == "PREFLIGHT: PASSED - mechanical gate" and data["files"]["beta.txt"] == {"status": "clean", "count": None} and data["file_done"] == 2'

# A second start marker throws the previous run away entirely.
printf '%s\n' '{"event": "start", "run_id": "run-2", "base": "origin/main", "files": ["delta.txt"]}' >> "$FEED_FILE"
SEC_RESET="$FIXTURE/security-reset.json"
STATUS=$(http_get "$SERVER_PORT8" "$SEC_RESET" "/api/security")
json_check "security: a new start marker resets to the latest run only" "$SEC_RESET" \
  'data["run_id"] == "run-2" and data["running"] is True and data["verdict"] is None and list(data["files"]) == ["delta.txt"] and data["file_done"] == 0'

# ---- feed v2: phases, findings, unexamined areas, skipped files ----------
# A full run in the richer format, written in one go.
cat > "$FEED_FILE" <<'FEED'
{"event": "start", "run_id": "v2", "base": "origin/main", "files": ["a.py", "b.html", "c.js"], "utc": "2026-08-25T10:00:00Z"}
{"event": "phase", "name": "gate", "status": "running", "utc": "2026-08-25T10:00:00Z"}
{"event": "area", "name": "Backend build (Maven)", "status": "NOT POSSIBLE", "reason": "mvn absent", "utc": "2026-08-25T10:00:05Z"}
{"event": "phase", "name": "gate", "status": "done", "detail": "PASSED", "utc": "2026-08-25T10:00:12Z"}
{"event": "verdict", "text": "PREFLIGHT: PASSED - x", "verdict": "PASSED", "utc": "2026-08-25T10:00:12Z"}
{"event": "phase", "name": "dives", "status": "running", "detail": "2 files", "utc": "2026-08-25T10:00:13Z"}
{"event": "file", "path": "b.html", "status": "skipped", "reason": "no per-file reviewer for this file type", "utc": "2026-08-25T10:00:13Z"}
{"event": "file", "path": "a.py", "status": "findings", "count": 2, "utc": "2026-08-25T10:01:00Z"}
{"event": "finding", "file": "a.py", "line": 6, "severity": "low", "title": "advisory note", "entry": "REV-08", "outcome": "PLAUSIBLE", "blocking": false, "utc": "2026-08-25T10:01:01Z"}
{"event": "finding", "file": "a.py", "line": 10, "severity": "high", "title": "pickle RCE", "entry": "REV-06", "outcome": "CONFIRMED", "blocking": true, "utc": "2026-08-25T10:01:02Z"}
{"event": "unknown-future-event", "whatever": 1}
{"event": "phase", "name": "dives", "status": "done", "detail": "2 files", "utc": "2026-08-25T10:01:30Z"}
{"event": "verdict", "text": "PIPELINE: DO NOT PUBLISH - 1 blocking", "verdict": "DO NOT PUBLISH", "utc": "2026-08-25T10:01:40Z"}
{"event": "phase", "name": "verdict", "status": "done", "detail": "DO NOT PUBLISH", "utc": "2026-08-25T10:01:40Z"}
FEED

SEC_V2="$FIXTURE/security-v2.json"
STATUS=$(http_get "$SERVER_PORT8" "$SEC_V2" "/api/security")
json_check "security v2: phases recorded in order with derived durations" "$SEC_V2" \
  '[p["name"] for p in data["phases"]] == ["gate", "dives", "verdict"] and data["phases"][0]["seconds"] == 12 and data["phases"][0]["detail"] == "PASSED"'
json_check "security v2: a phase never seen starting has no invented duration" "$SEC_V2" \
  '[p for p in data["phases"] if p["name"] == "verdict"][0]["seconds"] is None'
json_check "security v2: a phase closing after the verdict does NOT reopen the run" "$SEC_V2" \
  'data["running"] is False and data["verdict_word"] == "DO NOT PUBLISH"'
json_check "security v2: blocking finding sorts ahead of the advisory one" "$SEC_V2" \
  '[f["title"] for f in data["findings"]] == ["pickle RCE", "advisory note"] and data["findings"][0]["line"] == 10 and data["findings"][0]["entry"] == "REV-06"'
json_check "security v2: unexamined area kept with its reason" "$SEC_V2" \
  'len(data["areas"]) == 1 and data["areas"][0]["name"] == "Backend build (Maven)" and data["areas"][0]["reason"] == "mvn absent"'
json_check "security v2: a skipped file carries its reason and counts as resolved" "$SEC_V2" \
  'data["files"]["b.html"]["status"] == "skipped" and "no per-file reviewer" in data["files"]["b.html"]["reason"] and data["file_done"] == 2 and data["file_total"] == 3'
json_check "security v2: an unknown future event is skipped, not fatal" "$SEC_V2" \
  'data["run_id"] == "v2"'
json_check "security v2: with no report folder, nothing is added from one" "$SEC_V2" \
  'data["review_incomplete"] is None and data["mechanical_advisory"] is None and data["files"]["c.js"]["status"] == "pending"'

# ---- the run's report folder: verdict.json rows and deleted files --------
# The folder named by run_id, next to the feed, says what the feed cannot:
# every area the verdict could not examine (the LLM review's too), the
# advisory findings of the mechanical checks, and the files the diff deletes.
mkdir -p "$FIXTURE/folder-run"
cat > "$FIXTURE/folder-run/verdict.json" <<'JSON'
{"verdict": "INCONCLUSIVE", "areas": [
 {"area": "Python analysis (Bandit)", "status": "TESTED", "reason": "", "blocking": false, "severity_counts": {"critical": 0, "high": 0, "medium": 1, "low": 24}},
 {"area": "Backend build (Maven)", "status": "NOT POSSIBLE", "reason": "mvn absent", "blocking": null, "severity_counts": null},
 {"area": "Semgrep", "status": "TESTED", "reason": "", "blocking": true, "severity_counts": {"critical": 0, "high": 2, "medium": 0, "low": 0}},
 {"area": "Diff review REV-03 Authorization, ID", "status": "TESTED", "reason": "", "blocking": false, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 1}},
 {"area": "Diff review coverage", "status": "NOT POSSIBLE", "reason": "incomplete review: no reviewer answered for REV-03", "blocking": null, "severity_counts": null}
]}
JSON
cat > "$FIXTURE/folder-run/review-scope.json" <<'JSON'
{"touched_files": [{"path": "kept.py", "status": "M"}, {"path": "gone.py", "status": "D"}, {"path": "late.py", "status": "D"}]}
JSON
cat > "$FEED_FILE" <<'FEED'
{"event": "start", "run_id": "folder-run", "base": "origin/main", "files": ["kept.py", "gone.py", "late.py"]}
{"event": "area", "name": "Backend build (Maven)", "status": "NOT POSSIBLE", "reason": "mvn absent"}
{"event": "file", "path": "kept.py", "status": "clean"}
{"event": "file", "path": "late.py", "status": "checking"}
FEED
SEC_FOLDER="$FIXTURE/security-folder.json"
http_get "$SERVER_PORT8" "$SEC_FOLDER" "/api/security" > /dev/null
json_check "report folder: areas are verdict.json's NOT POSSIBLE and PARTIAL rows, the review's included" "$SEC_FOLDER" \
  'data["areas"] == [{"name": "Backend build (Maven)", "status": "NOT POSSIBLE", "reason": "mvn absent"}, {"name": "Diff review coverage", "status": "NOT POSSIBLE", "reason": "incomplete review: no reviewer answered for REV-03"}]'
json_check "report folder: an incomplete LLM review gives its reason" "$SEC_FOLDER" \
  'data["review_incomplete"] == "incomplete review: no reviewer answered for REV-03"'
json_check "report folder: advisory findings of the mechanical checks are counted, not the review's or a blocking row's" "$SEC_FOLDER" \
  'data["mechanical_advisory"] == 25'
json_check "report folder: a pending file the diff deletes reads as skipped, with why" "$SEC_FOLDER" \
  'data["files"]["gone.py"] == {"status": "skipped", "count": None, "reason": "deleted in this diff, so there is nothing to read"} and data["files"]["late.py"]["status"] == "checking" and data["file_done"] == 2 and data["file_total"] == 3'

# A failed entry's own row does not name the entry. The coverage row names
# every cause; without one, the entry's area goes before its reason.
cat > "$FIXTURE/folder-run/verdict.json" <<'JSON'
{"verdict": "INCONCLUSIVE", "areas": [
 {"area": "Diff review REV-03 Authorization, IDOR", "status": "NOT POSSIBLE", "reason": "the reviewer for this entry did not answer", "blocking": null, "severity_counts": null},
 {"area": "Diff review coverage", "status": "NOT POSSIBLE", "reason": "incomplete review: no reviewer answered for REV-03", "blocking": null, "severity_counts": null}
]}
JSON
http_get "$SERVER_PORT8" "$SEC_FOLDER" "/api/security" > /dev/null
json_check "report folder: an incomplete review gives the coverage row's reason, not a failed entry's" "$SEC_FOLDER" \
  'data["review_incomplete"] == "incomplete review: no reviewer answered for REV-03" and len(data["areas"]) == 2'
cat > "$FIXTURE/folder-run/verdict.json" <<'JSON'
{"verdict": "INCONCLUSIVE", "areas": [
 {"area": "Diff review REV-03 Authorization, IDOR", "status": "NOT POSSIBLE", "reason": "the reviewer for this entry did not answer", "blocking": null, "severity_counts": null}
]}
JSON
http_get "$SERVER_PORT8" "$SEC_FOLDER" "/api/security" > /dev/null
json_check "report folder: without a coverage row, the reason names the entry's area" "$SEC_FOLDER" \
  'data["review_incomplete"] == "Diff review REV-03 Authorization, IDOR: the reviewer for this entry did not answer"'

# An old feed (no phases, findings or areas) still folds: the viewer and the
# pipeline are versioned apart.
cat > "$FEED_FILE" <<'FEED'
{"event": "start", "run_id": "v1", "base": "origin/main", "files": ["x.py"]}
{"event": "file", "path": "x.py", "status": "clean"}
{"event": "verdict", "text": "PIPELINE: DO NOT PUBLISH - 1 blocking"}
FEED
SEC_V1="$FIXTURE/security-v1.json"
STATUS=$(http_get "$SERVER_PORT8" "$SEC_V1" "/api/security")
json_check "security: an old feed with no v2 events still folds" "$SEC_V1" \
  'data["run_id"] == "v1" and data["file_done"] == 1 and data["running"] is False and data["phases"] == [] and data["findings"] == [] and data["areas"] == [] and data["verdict_word"] is None'

# The review's merge step writes its verdict with no word, then a verdict
# phase whose detail is the word. The gate's PASSED must not survive it.
cat > "$FEED_FILE" <<'FEED'
{"event": "start", "run_id": "merged", "base": "origin/main", "files": ["a.py"]}
{"event": "phase", "name": "gate", "status": "done", "detail": "PASSED"}
{"event": "verdict", "text": "PREFLIGHT: PASSED - gate", "verdict": "PASSED"}
{"event": "finding", "file": "a.py", "line": 1, "severity": "low", "title": "first note", "blocking": false}
{"event": "finding", "file": "a.py", "line": 2, "severity": "high", "title": "veto", "blocking": true}
{"event": "finding", "file": "a.py", "line": 3, "severity": "low", "title": "second note", "blocking": false}
{"event": "verdict", "text": "PIPELINE: DO NOT PUBLISH - new findings: 1 high"}
FEED
SEC_MERGED="$FIXTURE/security-merged.json"
http_get "$SERVER_PORT8" "$SEC_MERGED" "/api/security" > /dev/null
json_check "security: a verdict with no word clears the gate's earlier word" "$SEC_MERGED" \
  'data["verdict"] == "PIPELINE: DO NOT PUBLISH - new findings: 1 high" and data["verdict_word"] is None'
json_check "security: findings of the same rank keep their arrival order" "$SEC_MERGED" \
  '[f["title"] for f in data["findings"]] == ["veto", "first note", "second note"]'
printf '%s\n' '{"event": "phase", "name": "verdict", "status": "done", "detail": "DO NOT PUBLISH"}' >> "$FEED_FILE"
http_get "$SERVER_PORT8" "$SEC_MERGED" "/api/security" > /dev/null
json_check "security: the verdict phase's word becomes the verdict word" "$SEC_MERGED" \
  'data["verdict_word"] == "DO NOT PUBLISH" and data["running"] is False'

# ---- feed v3: one row per step (check events), plus runner and push -------
# Rows are keyed by stage AND name ("Secrets" appears in two stages), the
# latest event replaces a row where it first appeared, and a field the
# latest event lacks becomes null. `true` is not a number of seconds or
# findings, and a check with no stage is dropped.
cat > "$FEED_FILE" <<'FEED'
{"event": "start", "run_id": "checks-run", "base": "origin/main", "files": ["a.py"], "utc": "2026-09-26T10:00:00Z"}
{"event": "phase", "name": "gate", "status": "running", "utc": "2026-09-26T10:00:00Z"}
{"event": "check", "stage": "gate", "name": "Exceptions file", "status": "running"}
{"event": "check", "stage": "gate", "name": "Secrets", "status": "running"}
{"event": "check", "stage": "gate", "name": "Secrets", "status": "done", "result": "TESTED", "blocking": false, "detail": "no secret in the diff", "seconds": 0.02}
{"event": "check", "stage": "gate", "name": "Exceptions file", "status": "done", "result": "NOT APPLICABLE", "blocking": false, "detail": "no exceptions file", "seconds": true}
{"event": "check", "name": "a check with no stage", "status": "done"}
{"event": "check", "stage": "review", "name": "Secrets", "status": "running", "detail": "reading the diff"}
{"event": "check", "stage": "review", "name": "REV-01 SQL injection (OWASP A03)", "status": "running"}
{"event": "check", "stage": "review", "name": "REV-01 SQL injection (OWASP A03)", "status": "done", "count": 0}
{"event": "check", "stage": "review", "name": "Secrets", "status": "done", "count": 2}
{"event": "check", "stage": "verify", "name": "pickle RCE (a.py)", "status": "done", "count": true}
FEED
SEC_V3="$FIXTURE/security-v3.json"
expect_get "$SERVER_PORT8" "$SEC_V3" "/api/security" "200" "security v3: a feed with check events answers 200"
json_check "security v3: one row per stage and name, in first-appearance order" "$SEC_V3" \
  '[(c["stage"], c["name"]) for c in data["checks"]] == [("gate", "Exceptions file"), ("gate", "Secrets"), ("review", "Secrets"), ("review", "REV-01 SQL injection (OWASP A03)"), ("verify", "pickle RCE (a.py)")]'
json_check "security v3: a done row replaces the running one in place" "$SEC_V3" \
  'data["checks"][0] == {"stage": "gate", "name": "Exceptions file", "status": "done", "result": "NOT APPLICABLE", "blocking": False, "detail": "no exceptions file", "seconds": None, "count": None}'
json_check "security v3: a gate row keeps its result, detail and seconds" "$SEC_V3" \
  'data["checks"][1] == {"stage": "gate", "name": "Secrets", "status": "done", "result": "TESTED", "blocking": False, "detail": "no secret in the diff", "seconds": 0.02, "count": None}'
json_check "security v3: the latest event replaces the whole row (its old detail is gone)" "$SEC_V3" \
  'data["checks"][2]["status"] == "done" and data["checks"][2]["count"] == 2 and data["checks"][2]["detail"] is None'
json_check "security v3: a review count of 0 is kept, a count of true is not" "$SEC_V3" \
  'data["checks"][3]["count"] == 0 and data["checks"][4]["count"] is None'
json_check "security v3: check events leave the run running" "$SEC_V3" \
  'data["running"] is True and data["run_id"] == "checks-run"'
json_check "security v3: without a toolkit the runner is unavailable and idle" "$SEC_V3" \
  'data["runner"] == {"available": False, "unavailable_reason": "No security toolkit is configured: start BranchLens with --toolkit PATH (a folder holding preflight.sh).", "active": False, "branch": None, "started_utc": None, "exit_code": None, "run_id": None, "log_tail": None}'
json_check "security v3: a run with no report folder allows no push" "$SEC_V3" \
  'data["push"] == {"allowed": False, "reason": "The latest security check has no verdict yet.", "branch": None, "remote": None, "commit": None, "pushed": None, "output": None}'
json_check "security v3: with no verdict.json and no run started here, what was judged is unknown" "$SEC_V3" \
  'data["judged"] is None'

# Without a toolkit the page cannot start a run; without a feed it cannot push.
FEED_ONLY_TOKEN=$(page_token "$SERVER_PORT8")
POST_BODY="$FIXTURE/post-response.json"
STATUS=$(http_post "$SERVER_PORT8" "$POST_BODY" "/api/run" "$FEED_ONLY_TOKEN" \
  "application/json" '{"branch": "feature-worktree"}')
expect_status "400" "security: /api/run without a toolkit answers HTTP 400"
json_check "security: the no-toolkit refusal says how to configure one" "$POST_BODY" \
  'data["error"] == "No security toolkit is configured: start BranchLens with --toolkit PATH (a folder holding preflight.sh)."'
NO_FEED_TOKEN=$(page_token "$SERVER_PORT")
STATUS=$(http_post "$SERVER_PORT" "$POST_BODY" "/api/push" "$NO_FEED_TOKEN" \
  "application/json" '{"branch": "feature-worktree"}')
expect_status "409" "security: /api/push without a feed answers HTTP 409"
json_check "security: the no-feed refusal says so and pushes nothing" "$POST_BODY" \
  'data == {"error": "No security feed is configured.", "pushed": False}'

# ---------------------------------------------------------------- v3 fixture: dependency network

# Files whose dependencies are known by construction, added in one commit so
# the whole graph can be asserted exactly. Like the v2 block, this runs only
# now, after the assertions whose file lists and totals it would change. The
# dates continue this repository's 2026-01-01 timeline.

set_commit_date "2026-01-01T10:10:00 +0000"
mkdir -p "$REPO/net/pkg" "$REPO/web/lib"

# A real Python package. app.py reaches the same package twice over: once
# absolutely (pkg.config, measured from the 'net' import root) and once
# relatively (from . import util), so both resolver paths are exercised.
# __init__.py's own 'from . import util' binds the submodule, so it must not
# turn 'util' into an attribute that keeps app.py's arrow on __init__.py.
cat > "$REPO/net/pkg/__init__.py" <<'PY_INIT'
from .util import shared_value
from . import util
PY_INIT

cat > "$REPO/net/pkg/util.py" <<'PY_UTIL'
shared_value = 41


def label():
    return "util"
PY_UTIL

cat > "$REPO/net/pkg/config.py" <<'PY_CONFIG'
from .util import *

SETTINGS = {"value": shared_value}
PY_CONFIG

cat > "$REPO/net/pkg/app.py" <<'PY_APP'
import sys

from pkg.config import SETTINGS
from . import util


def main():
    return (sys.argv, SETTINGS, util.label())
PY_APP

# Recognised as code, never parsed.
cat > "$REPO/net/main.go" <<'GO_MAIN'
package main

func main() {}
GO_MAIN

# Does not parse: reported as unparsable.
printf 'def broken(:\n' > "$REPO/net/broken.py"
# Not valid UTF-8: reported, and the reader does not crash.
printf 'x = "\xff\xfe not utf8"\n' > "$REPO/net/notutf8.py"

# TypeScript. Line 1 names './lib/util.js' the way TypeScript's ESM output
# writes it, and must land on the .ts source. Line 2 is a second import with
# no semicolon anywhere before it. Line 3 is a bare third-party specifier that
# must go to 'unresolved', never become an edge. Line 4 lands on a data file,
# which must be promoted to a node so no edge names a missing node.
cat > "$REPO/web/index.ts" <<'TS_INDEX'
import { formatLabel } from "./lib/util.js"
import { LABEL } from "./lib/consts"
import React from "react"
import data from "./data.json"

export function render() {
  return React.createElement("div", null, formatLabel(LABEL) + data.name)
}
TS_INDEX

cat > "$REPO/web/lib/util.ts" <<'TS_UTIL'
import { LABEL } from "./consts"

export function formatLabel(text) {
  return LABEL + ": " + text
}
TS_UTIL

printf 'export var LABEL = "branchlens"\n' > "$REPO/web/lib/consts.ts"
printf '{"name": "fixture"}\n' > "$REPO/web/data.json"

# 420000 bytes, over NETWORK_MAX_FILE_BYTES (400000): never read.
python3 - "$REPO/web/huge.js" <<'PY_PAD'
import sys
handle = open(sys.argv[1], "w")
handle.write("// pad\n" * 60000)
handle.close()
PY_PAD

printf '# Fixture\n' > "$REPO/README.md"

git -C "$REPO" add -A
git -C "$REPO" commit -q -m "Add the network fixture"
NETWORK_SHA=$(git -C "$REPO" rev-parse refs/heads/main)
NETWORK_SHA_UPPER=$(printf '%s' "$NETWORK_SHA" | tr 'a-f' 'A-F')

# ---------------------------------------------------------------- /api/network

NET="$FIXTURE/network.json"
expect_get "$SERVER_PORT" "$NET" "/api/network?commit=$NETWORK_SHA" "200" "/api/network for a commit returns HTTP 200"

json_check "network: commit ids and exact explanation sentence" "$NET" \
  'data["commit"]["sha"] == extra and data["commit"]["short"] == extra[:7] and data["commit"]["subject"] == "Add the network fixture" and data["explanation"] == "How the files at \"Add the network fixture\" depend on each other; an arrow points from a file to the file it uses."' "$NETWORK_SHA"

json_check "network: exactly the code files at the commit are nodes" "$NET" \
  '[n["path"] for n in data["nodes"]] == ["net/broken.py", "net/main.go", "net/notutf8.py", "net/pkg/__init__.py", "net/pkg/app.py", "net/pkg/config.py", "net/pkg/util.py", "src/app.py", "src/oldname.py", "web/data.json", "web/huge.js", "web/index.ts", "web/lib/consts.ts", "web/lib/util.ts"]'

json_check "network: exactly the eight arrows the fixture builds, in order" "$NET" \
  '[[e["from"], e["to"]] for e in data["edges"]] == [["net/pkg/__init__.py", "net/pkg/util.py"], ["net/pkg/app.py", "net/pkg/config.py"], ["net/pkg/app.py", "net/pkg/util.py"], ["net/pkg/config.py", "net/pkg/util.py"], ["web/index.ts", "web/data.json"], ["web/index.ts", "web/lib/consts.ts"], ["web/index.ts", "web/lib/util.ts"], ["web/lib/util.ts", "web/lib/consts.ts"]]'

# ---- arrow direction ---------------------------------------------------------
# app.py imports two files and is imported by none, so it is the tail of every
# arrow that touches it. consts.ts imports nothing and is imported by two
# files, so it is the head of every arrow that touches it.

json_check "network direction: the importing file is the arrow's tail, never its head" "$NET" \
  'sorted([e["from"], e["to"]] for e in data["edges"] if "net/pkg/app.py" in (e["from"], e["to"])) == [["net/pkg/app.py", "net/pkg/config.py"], ["net/pkg/app.py", "net/pkg/util.py"]]'

json_check "network direction: the imported file is the arrow's head, never its tail" "$NET" \
  'sorted([e["from"], e["to"]] for e in data["edges"] if "web/lib/consts.ts" in (e["from"], e["to"])) == [["web/index.ts", "web/lib/consts.ts"], ["web/lib/util.ts", "web/lib/consts.ts"]]'

json_check "network direction: uses is the out-degree and used_by the in-degree, not swapped" "$NET" \
  '[[n["path"], n["uses"], n["used_by"]] for n in data["nodes"] if n["path"] in ("net/pkg/app.py", "net/pkg/util.py", "web/index.ts", "web/lib/consts.ts")] == [["net/pkg/app.py", 2, 0], ["net/pkg/util.py", 0, 3], ["web/index.ts", 3, 0], ["web/lib/consts.ts", 0, 2]]'

# ---- what crosses each arrow ------------------------------------------------

json_check "network: an absolute package import carries the exact imported name" "$NET" \
  '[e["symbols"] for e in data["edges"] if e["from"] == "net/pkg/app.py" and e["to"] == "net/pkg/config.py"] == [["SETTINGS"]]'

json_check "network: from . import util points at util.py, never at the package __init__.py" "$NET" \
  '[[e["to"], e["kind"], e["lines"]] for e in data["edges"] if e["from"] == "net/pkg/app.py"] == [["net/pkg/config.py", "from-import", [3]], ["net/pkg/util.py", "from-import", [4]]] and all(e["to"] != "net/pkg/__init__.py" for e in data["edges"])'

json_check "network: a TypeScript .js specifier resolves to the .ts source, with its symbol" "$NET" \
  '[[e["to"], e["symbols"]] for e in data["edges"] if e["from"] == "web/index.ts"] == [["web/data.json", ["default as data"]], ["web/lib/consts.ts", ["LABEL"]], ["web/lib/util.ts", ["formatLabel"]]]'

json_check "network: two adjacent semicolon-free imports both produce an arrow" "$NET" \
  'sorted(e["lines"][0] for e in data["edges"] if e["from"] == "web/index.ts") == [1, 2, 4]'

json_check "network: a star import is flagged, counted, and names no symbols" "$NET" \
  '[[e["to"], e["kind"], e["star"], e["symbols"]] for e in data["edges"] if e["from"] == "net/pkg/config.py"] == [["net/pkg/util.py", "star-import", True, []]] and data["honesty"]["python_star_imports"] == 1'

# ---- what is not drawn -------------------------------------------------------

json_check "network: the bare specifier and the standard library import are listed unresolved, exactly" "$NET" \
  '[[u["specifier"], u["language"], u["reason"], u["count"], u["examples"]] for u in data["unresolved"]] == [["react", "typescript", "bare or aliased specifier", 1, ["web/index.ts"]], ["sys", "python", "standard library", 1, ["net/pkg/app.py"]]]'

json_check "network: an unresolved specifier never becomes a node or an arrow" "$NET" \
  'all(n["path"] not in ("react", "sys") for n in data["nodes"]) and all(e["to"] not in ("react", "sys") for e in data["edges"])'

json_check "network: exactly the five unreadable files are skipped, each with its reason" "$NET" \
  '[[s["path"], s["reason"], s["language"]] for s in data["skipped"]] == [["net/broken.py", "unparsable", "python"], ["net/main.go", "unsupported language", "unsupported"], ["net/notutf8.py", "not UTF-8 text", "python"], ["web/data.json", "not a source file", None], ["web/huge.js", "too large", "javascript"]]'

json_check "network: skipped is exactly the set of nodes marked not analyzed" "$NET" \
  'sorted(s["path"] for s in data["skipped"]) == sorted(n["path"] for n in data["nodes"] if n["analyzed"] is False)'

json_check "network: an unsupported language is a node that says it was not read" "$NET" \
  '[[n["language"], n["analyzed"], n["reason"], n["uses"], n["used_by"]] for n in data["nodes"] if n["path"] == "net/main.go"] == [["unsupported", False, "unsupported language", 0, 0]]'

json_check "network: the oversized file reports its real size and was never read" "$NET" \
  '[[s["size"], s["reason"]] for s in data["skipped"] if s["path"] == "web/huge.js"] == [[420000, "too large"]] and [n["lines"] for n in data["nodes"] if n["path"] == "web/huge.js"] == [None]'

# Every from and every to appears in nodes. The data file is not source code,
# so it is promoted to a node.
json_check "network: every arrow's ends are both in the node list" "$NET" \
  'all(e["from"] in [n["path"] for n in data["nodes"]] and e["to"] in [n["path"] for n in data["nodes"]] for e in data["edges"])'

json_check "network: a resolved non-source target is promoted to a node, not dropped" "$NET" \
  '[[n["language"], n["analyzed"], n["reason"], n["used_by"]] for n in data["nodes"] if n["path"] == "web/data.json"] == [[None, False, "not a source file", 1]]'

# ---- totals -----------------------------------------------------------------

json_check "network: only the files this commit added are marked changed" "$NET" \
  'sorted(n["path"] for n in data["nodes"] if n["changed_in_commit"] is False) == ["src/app.py", "src/oldname.py"] and all(n["changed_in_commit"] is True for n in data["nodes"] if n["path"].startswith(("net/", "web/")))'

json_check "network: counts match the fixture exactly" "$NET" \
  'data["counts"] == {"files_at_commit": 19, "code_files": 12, "analyzed": 9, "skipped": 5, "nodes": 14, "edges": 8, "unresolved_imports": 2, "changed_files": 13, "unsupported_code_files": 1, "unresolved_groups_total": 2, "unresolved_groups_shown": 2}'

# net/main.go is recognised as code and never parsed, so it is counted outside
# code_files.
json_check "network: a language this view cannot read is counted apart from the ones it can" "$NET" \
  'data["counts"]["unsupported_code_files"] == 1 and [n["reason"] for n in data["nodes"] if n["path"] == "net/main.go"] == ["unsupported language"] and data["counts"]["code_files"] + data["counts"]["unsupported_code_files"] == 13'

json_check "network: non-source files are counted, and README.md is not a node" "$NET" \
  'data["excluded"] == {"symlinks": 0, "submodules": 0, "other": 5, "unlisted": 0, "too_deep": 0} and all(n["path"] != "README.md" for n in data["nodes"])'

json_check "network: honesty counters report the one star import and nothing else" "$NET" \
  'data["honesty"] == {"python_star_imports": 1, "python_dynamic_imports": 0, "python_conditional_imports": 0, "js_reexports": 0, "js_namespace_imports": 0, "js_dynamic_imports": 0, "java_wildcard_imports": 0, "java_same_package_files": 0, "ambiguous_python_modules": 0, "python_namespace_packages": 0, "self_imports_dropped": 0, "symbols_unreadable": 0, "js_clauses_too_long": 0, "imports_past_file_cap": 0, "ambiguous_java_classes": 0}'

json_check "network: one plain sentence per thing the view could not see" "$NET" \
  'data["notes"] == ["1 star import (from X import *) was found: the names crossing that arrow are unknown.", "1 import points at something that is not a file in this repository (an installed package, the standard library, or a name that matches nothing here) and is listed separately, not drawn.", "Bare and aliased specifiers such as \u0027react\u0027 or \u0027@/lib/x\u0027 are not resolved to files: this view does not read tsconfig or bundler aliases.", "Only 11 of 12 source files were read because of the size limit, so arrows from the rest are missing.", "1 file at this commit is code in a language this view does not read: what it uses is unknown, though arrows into it from files that were read are still drawn. Such files are not counted as source code above.", "5 other files at this commit are not source code and are not shown.", "1 file that is not source code is drawn because an import points at it."]'

# Only the size limit fired here. The oversized file is still one of the
# twelve source files at this commit, so it counts in source_files_total.
json_check "network: the size-skipped file stays inside the total it was skipped from" "$NET" \
  'data["truncated"] is True and data["truncation"] == {"source_files_read": 11, "source_files_total": 12, "edges_shown": 8, "edges_total": 8, "nodes_hidden": 0, "changed_nodes_hidden": 0, "tree_listing_stopped": False, "links_not_gathered": 0} and data["limits"]["max_file_bytes"] == 400000'

# Nothing here is near the 8000-edge cap, so no node may claim links were cut.
json_check "network: no file lost links to the edge cap, so none is marked" "$NET" \
  'all(n["links_dropped"] is False for n in data["nodes"])'

# ---- the network is a snapshot at one commit ---------------------------------

NET_ROOT="$FIXTURE/network-root.json"
expect_get "$SERVER_PORT" "$NET_ROOT" "/api/network?commit=$ROOT_SHA" "200" "/api/network for an older commit returns HTTP 200"

json_check "network: an older commit yields only the files that existed then" "$NET_ROOT" \
  '[n["path"] for n in data["nodes"]] == ["src/app.py", "src/oldname.py"] and data["edges"] == [] and data["unresolved"] == []'

json_check "network: exact explanation when files were read but nothing links them" "$NET_ROOT" \
  'data["explanation"] == "No links between files were found at \"Initial commit\", from the 2 source files that could be read."'

# ---------------------------------------------------------------- /api/network errors

expect_get "$SERVER_PORT" "$ERR" "/api/network" "400" "/api/network with no commit returns HTTP 400"
json_check "network: exact missing-parameter message" "$ERR" \
  'data["error"] == "Missing \u0027commit\u0027 query parameter."'

expect_get "$SERVER_PORT" "$ERR" "/api/network?commit=" "400" "/api/network with an empty commit returns HTTP 400"

expect_get "$SERVER_PORT" "$ERR" "/api/network?branch=main" "400" "/api/network with a branch returns HTTP 400"
json_check "network: exact refuse-a-branch message" "$ERR" \
  'data["error"] == "The network view needs a \u0027commit\u0027, not a \u0027branch\u0027."'

expect_get "$SERVER_PORT" "$ERR" "/api/network?branch=main&commit=$NETWORK_SHA" "400" "/api/network with branch= and commit= together returns HTTP 400"
json_check "network: a branch riding along with a valid commit is still refused" "$ERR" \
  'data["error"] == "The network view needs a \u0027commit\u0027, not a \u0027branch\u0027."'

# ------------------------------------------------------- /api/network with Java
# Its own repository, so the exact node and edge lists above stay as they are.

JAVA_REPO="$FIXTURE/java-repo"
mkdir -p "$JAVA_REPO/src/main/java/app/core" \
         "$JAVA_REPO/src/main/java/app/util/support"
new_repo "$JAVA_REPO"

# Main: a plain import, a static import of the same class (the two merge into
# one arrow), one JDK import, one third-party import, and three imports that
# draw nothing: one behind //, one inside /* */, one in a string. All three
# name real classes here, so a masking failure shows up as an edge.
cat > "$JAVA_REPO/src/main/java/app/Main.java" <<'JAVA_MAIN'
package app;

import app.core.Engine;
import app.util.Helper;
import java.util.List;
import org.external.Thing;
import static app.util.Helper.format;
// import app.core.Widget;
/* import app.util.support.Deep; */

public class Main {
    String hint = "import app.core.Widget;";
    List<String> names;
    Thing thing;
}
JAVA_MAIN

cat > "$JAVA_REPO/src/main/java/app/Wild.java" <<'JAVA_WILD'
package app;

import app.core.*;

public class Wild {
}
JAVA_WILD

cat > "$JAVA_REPO/src/main/java/app/core/Engine.java" <<'JAVA_ENGINE'
package app.core;

import app.util.Helper;

public class Engine {
}
JAVA_ENGINE

# Same package as Engine, and used by it with no import: the arrow Engine ->
# Widget cannot exist, which is what the same-package note is about.
cat > "$JAVA_REPO/src/main/java/app/core/Widget.java" <<'JAVA_WIDGET'
package app.core;

public class Widget {
}
JAVA_WIDGET

cat > "$JAVA_REPO/src/main/java/app/util/Helper.java" <<'JAVA_HELPER'
package app.util;

import app.util.support.Deep;

public class Helper {
}
JAVA_HELPER

cat > "$JAVA_REPO/src/main/java/app/util/support/Deep.java" <<'JAVA_DEEP'
package app.util.support;

public class Deep {
}
JAVA_DEEP

set_commit_date "2026-04-01T10:00:00 +0000"
git -C "$JAVA_REPO" add -A
git -C "$JAVA_REPO" commit -q -m "Add the Java fixture"
JAVA_SHA=$(git -C "$JAVA_REPO" rev-parse refs/heads/main)

LOG9="$FIXTURE/server9.log"
python3 -m branchlens "$JAVA_REPO" --port 0 --no-browser > "$LOG9" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT9=$(wait_for_server "$LOG9")
check "java: server starts on the Java repository" $?

if [ -n "$SERVER_PORT9" ]; then
  JAVA_NET="$FIXTURE/java-network.json"
  expect_get "$SERVER_PORT9" "$JAVA_NET" "/api/network?commit=$JAVA_SHA" "200" "java: /api/network returns HTTP 200"

  json_check "java: every .java file is read, none skipped as unsupported" "$JAVA_NET" \
    'all(n["language"] == "java" and n["analyzed"] is True for n in data["nodes"]) and data["skipped"] == []'

  json_check "java: exact node list" "$JAVA_NET" \
    '[n["path"] for n in data["nodes"]] == ["src/main/java/app/Main.java", "src/main/java/app/Wild.java", "src/main/java/app/core/Engine.java", "src/main/java/app/core/Widget.java", "src/main/java/app/util/Helper.java", "src/main/java/app/util/support/Deep.java"]'

  # The direction check: a reversed arrow fails this outright.
  json_check "java: exact edge list, importer first and imported second" "$JAVA_NET" \
    '[[e["from"], e["to"]] for e in data["edges"]] == [["src/main/java/app/Main.java", "src/main/java/app/core/Engine.java"], ["src/main/java/app/Main.java", "src/main/java/app/util/Helper.java"], ["src/main/java/app/Wild.java", "src/main/java/app/core/Engine.java"], ["src/main/java/app/Wild.java", "src/main/java/app/core/Widget.java"], ["src/main/java/app/core/Engine.java", "src/main/java/app/util/Helper.java"], ["src/main/java/app/util/Helper.java", "src/main/java/app/util/support/Deep.java"]]'

  json_check "java: uses and used_by are the right way round" "$JAVA_NET" \
    '[[n["path"].rsplit("/", 1)[-1], n["uses"], n["used_by"]] for n in data["nodes"]] == [["Main.java", 2, 0], ["Wild.java", 2, 0], ["Engine.java", 1, 2], ["Widget.java", 0, 1], ["Helper.java", 1, 2], ["Deep.java", 0, 1]]'

  json_check "java: an import and a static import of one class merge into one arrow" "$JAVA_NET" \
    '[e["symbols"] for e in data["edges"] if e["from"] == "src/main/java/app/Main.java" and e["to"] == "src/main/java/app/util/Helper.java"] == [["Helper", "format"]]'

  json_check "java: a plain import carries the class name as its symbol" "$JAVA_NET" \
    '[e["symbols"] for e in data["edges"] if e["from"] == "src/main/java/app/core/Engine.java"] == [["Helper"]]'

  json_check "java: imports in comments and strings draw nothing" "$JAVA_NET" \
    'all(not (e["from"] == "src/main/java/app/Main.java" and e["to"] in ("src/main/java/app/core/Widget.java", "src/main/java/app/util/support/Deep.java")) for e in data["edges"])'

  json_check "java: a wildcard import reaches every class of that package" "$JAVA_NET" \
    'sorted(e["to"] for e in data["edges"] if e["from"] == "src/main/java/app/Wild.java") == ["src/main/java/app/core/Engine.java", "src/main/java/app/core/Widget.java"] and all(e["star"] is True for e in data["edges"] if e["from"] == "src/main/java/app/Wild.java") and data["honesty"]["java_wildcard_imports"] == 1'

  json_check "java: JDK and third-party imports are listed, never drawn" "$JAVA_NET" \
    '[[u["specifier"], u["reason"], u["count"]] for u in data["unresolved"]] == [["java.util.List", "standard library", 1], ["org.external.Thing", "not a file in this repository", 1]]'

  json_check "java: the same-package silence is counted and spoken" "$JAVA_NET" \
    'data["honesty"]["java_same_package_files"] == 4 and any("share a package" in note and "4" in note for note in data["notes"])'

  json_check "java: imports leaving the repository are counted in a note" "$JAVA_NET" \
    'any("is not a file in this repository" in note for note in data["notes"])'
fi

# --------------------------------------------------- /api/file on awkward content
# Content a unified-diff reader gets wrong: CR bytes, a missing final newline,
# and file content that is itself diff syntax.

PATCH_REPO="$FIXTURE/patch-repo"
mkdir -p "$PATCH_REPO"
new_repo "$PATCH_REPO"

printf 'alpha\r\nbeta\r\n' > "$PATCH_REPO/crlf.txt"
printf 'no trailing newline' > "$PATCH_REPO/nonewline.txt"
printf 'keep\n' > "$PATCH_REPO/lookalike.txt"
set_commit_date "2026-05-01T10:00:00 +0000"
git -C "$PATCH_REPO" add -A
git -C "$PATCH_REPO" commit -q -m "patch baseline"

git -C "$PATCH_REPO" checkout -q -b patchwork
printf 'alpha\r\nbeta CHANGED\r\ngamma\r\n' > "$PATCH_REPO/crlf.txt"
printf 'still no trailing newline' > "$PATCH_REPO/nonewline.txt"
# Seven added lines, four of which are valid unified-diff syntax.
{
  printf 'keep\n'
  printf 'diff --git a/fake.txt b/fake.txt\n'
  printf -- '--- a/fake.txt\n'
  printf '+++ b/fake.txt\n'
  printf '@@ -1 +1 @@\n'
  printf -- '-removed looking line\n'
  printf '+added looking line\n'
  printf '\\ No newline at end of file\n'
} > "$PATCH_REPO/lookalike.txt"
git -C "$PATCH_REPO" add -A
git -C "$PATCH_REPO" commit -q -m "awkward patch content"
git -C "$PATCH_REPO" checkout -q main

LOG10="$FIXTURE/server10.log"
python3 -m branchlens "$PATCH_REPO" --port 0 --no-browser > "$LOG10" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
SERVER_PORT10=$(wait_for_server "$LOG10")
check "patch text: server starts on the awkward-content repository" $?

if [ -n "$SERVER_PORT10" ]; then
  PATCH_CRLF="$FIXTURE/patch-crlf.json"
  expect_get "$SERVER_PORT10" "$PATCH_CRLF" "/api/file?branch=patchwork&path=crlf.txt" "200" "patch text: /api/file for the CRLF file returns HTTP 200"
  # Three CR bytes survive: one context line and two changed lines.
  json_check "patch text: CR bytes survive instead of being normalised away" "$PATCH_CRLF" \
    'data["patch"].count("\r") == 4 and " alpha\r\n" in data["patch"]'

  PATCH_NONL="$FIXTURE/patch-nonewline.json"
  expect_get "$SERVER_PORT10" "$PATCH_NONL" "/api/file?branch=patchwork&path=nonewline.txt" "200" "patch text: /api/file for the newline-less file returns HTTP 200"
  json_check "patch text: a missing final newline is reported by git's own marker" "$PATCH_NONL" \
    'data["patch"].count("\\ No newline at end of file") == 2'

  PATCH_LOOK="$FIXTURE/patch-lookalike.json"
  expect_get "$SERVER_PORT10" "$PATCH_LOOK" "/api/file?branch=patchwork&path=lookalike.txt" "200" "patch text: /api/file for the diff-lookalike file returns HTTP 200"
  # Every one of the seven new lines is an addition, and the file's own
  # "@@ -1 +1 @@" is carried as an added line, never as a second hunk header.
  json_check "patch text: file content that is diff syntax stays content" "$PATCH_LOOK" \
    '[line for line in data["patch"].split("\n") if line.startswith("@@")] == ["@@ -1 +1,8 @@"] and "+@@ -1 +1 @@" in data["patch"] and "+--- a/fake.txt" in data["patch"]'

  PATCH_OVERVIEW="$FIXTURE/patch-overview.json"
  expect_get "$SERVER_PORT10" "$PATCH_OVERVIEW" "/api/diff?branch=patchwork" "200" "patch text: the overview for the awkward branch returns HTTP 200"
  NUMSTAT_PATCH=$(git -C "$PATCH_REPO" diff -M --numstat main patchwork)
  json_check "patch text: counts match git --numstat on all three files" "$PATCH_OVERVIEW" \
    'sorted([f["path"], f["adds"], f["dels"]] for f in data["files"]) == sorted([r.split("\t")[2], int(r.split("\t")[0]), int(r.split("\t")[1])] for r in extra.strip().split("\n"))' "$NUMSTAT_PATCH"
fi




expect_get "$SERVER_PORT" "$ERR" "/api/network?commit=$FAKE_SHA" "404" "/api/network with a sha not in the graph returns HTTP 404"
json_check "network: exact unknown-commit message" "$ERR" \
  'data["error"] == "That commit isn\u0027t in the current graph."'

expect_get "$SERVER_PORT" "$ERR" "/api/network?commit=$NETWORK_SHA_UPPER" "404" "/api/network with an uppercase sha returns HTTP 404"

expect_get "$SERVER_PORT" "$ERR" "/api/network?commit=$BLOB_SHA" "404" "/api/network with the sha of a blob object returns HTTP 404"

expect_get "$SERVER_PORT" "$ERR" "/api/network?commit=../../etc/hosts" "404" "/api/network with a traversal path as the commit returns HTTP 404"

# ---------------------------------------------------------------- network UI surface

# The frontend's testable surface is the served HTML, not a live DOM.

APP_PAGE="$FIXTURE/app-page.html"
expect_get "$SERVER_PORT" "$APP_PAGE" "/" "200" "network UI: GET / returns HTTP 200"

grep -q 'id="tab-network"' "$APP_PAGE" && grep -q '>Network<' "$APP_PAGE"
check "network UI: the served page carries the Network tab" $?

grep -q 'id="network-pane"' "$APP_PAGE" && \
  grep -q 'id="network-canvas"' "$APP_PAGE" && \
  grep -q 'id="network-detail"' "$APP_PAGE"
check "network UI: the pane, the canvas and the detail column are all present" $?

grep -q 'An arrow points from a file to what it depends on' "$APP_PAGE"
check "network UI: the legend states the arrow direction in plain words" $?

# The three marker ids are built in script, so the id text is the argument to
# makeNetworkMarker; the closing quote pins the plain one against the other two.
grep -q 'net-arrow"' "$APP_PAGE" && \
  grep -q 'net-arrow-hi' "$APP_PAGE" && \
  grep -q 'net-arrow-cycle' "$APP_PAGE"
check "network UI: all three arrowhead markers are defined" $?

MISSING_NETWORK_FUNCTION=""
for function_name in buildNetworkLayout findStronglyConnected assignNetworkLayers \
                     placeNetworkNodes renderNetworkDetail openNetworkFile; do
  if ! grep -q "$function_name" "$APP_PAGE"; then
    MISSING_NETWORK_FUNCTION="$function_name"
  fi
done
[ -z "$MISSING_NETWORK_FUNCTION" ]
check "network UI: the layout, cycle and detail functions are all served" $?

grep -q 'so what it uses is unknown' "$APP_PAGE" && \
  grep -q 'this file depends on these' "$APP_PAGE" && \
  grep -q 'if this file changed, these would be affected' "$APP_PAGE"
check "network UI: both directions and the not-read wording are spelled out" $?

# An unread file's used-by list is known: its arrows come from the files that
# were read.
! grep -q 'or is used by anything — is unknown' "$APP_PAGE"
check "network UI: an unread file is never told its used-by status is unknown" $?

# House style: no innerHTML, ES5 only.
APP_SOURCE="$SOURCE_DIR/static/app.html"

[ "$(grep -c -E '\.innerHTML[[:space:]]*=' "$APP_SOURCE")" = "0" ]
check "network UI: app.html assigns innerHTML nowhere" $?

[ "$(grep -c -E '=>' "$APP_SOURCE")" = "0" ] && \
  [ "$(grep -c -E '(^|[^A-Za-z])(const|let) ' "$APP_SOURCE")" = "0" ] && \
  [ "$(grep -c '`' "$APP_SOURCE")" = "2" ]
check "network UI: app.html stays ES5: no arrow functions, no const/let, backticks only in the 2 comment lines" $?

# Scoped to the network CSS block: the first '<style>' half of the file from
# its section comment onwards. The net-node-box guard makes the check fail
# loudly if that comment ever moves, instead of passing over an empty range.
NET_CSS="$FIXTURE/network-css.txt"
sed -n '1,/<\/style>/p' "$APP_SOURCE" | sed -n '/Network view ===/,$p' > "$NET_CSS"
grep -q 'net-node-box' "$NET_CSS" && \
  [ "$(grep -c -E 'add-fg|del-fg' "$NET_CSS")" = "0" ]
check "network UI: the network CSS never borrows the diff red and green" $?

# ------------------------------------------------- v3 fixture: hard imports
#
# Three JavaScript statements the fast 'import <clause> from' regex refuses (a
# blank line inside the braces, twice, and a clause past 400 characters) and a
# Python module whose directory is not a package. They come in their own
# commit, after every assertion that pins totals at earlier commits.

set_commit_date "2026-01-01T10:20:00 +0000"
mkdir -p "$REPO/deps/js" "$REPO/deps/tools" "$REPO/deps/pkgapp"

printf 'export var alpha = 1;\nexport var beta = 2;\n' > "$REPO/deps/js/target.js"

# A blank line groups the names. Legal JavaScript, and one whole statement.
cat > "$REPO/deps/js/blank.js" <<'JS_BLANK'
import {
  alpha,

  beta
} from './target.js';
JS_BLANK

cat > "$REPO/deps/js/blankexport.js" <<'JS_BLANK_EXPORT'
export {
  alpha,

  beta
} from './target.js';
JS_BLANK_EXPORT

# 60 names: far past NETWORK_MAX_CLAUSE_CHARS, the size of a real barrel import.
python3 - "$REPO/deps/js/long.js" <<'PY_LONG'
import sys
names = ", ".join("name%03d" % index for index in range(60))
handle = open(sys.argv[1], "w")
handle.write("import {\n  " + names + "\n} from './target.js';\n")
handle.close()
PY_LONG

# deps/tools has no __init__.py, so deps/tools/logging.py answers to the bare
# name 'logging', for files in deps/tools only.
printf 'def setup():\n    return 1\n' > "$REPO/deps/tools/logging.py"
printf 'import logging\n\nlogging.setup()\n' > "$REPO/deps/tools/runner.py"
printf '' > "$REPO/deps/pkgapp/__init__.py"
printf 'import logging\n\nlogger = logging.getLogger(__name__)\n' \
  > "$REPO/deps/pkgapp/reader.py"

git -C "$REPO" add -A
git -C "$REPO" commit -q -m "Add the hard-to-read imports fixture"
DEPS_SHA=$(git -C "$REPO" rev-parse refs/heads/main)

NET2="$FIXTURE/network-deps.json"
expect_get "$SERVER_PORT" "$NET2" "/api/network?commit=$DEPS_SHA" "200" "/api/network for the hard-to-read-imports commit returns HTTP 200"

json_check "network: a blank line inside an import's braces still draws its arrow" "$NET2" \
  '[[e["to"], e["kind"], e["symbols"]] for e in data["edges"] if e["from"] == "deps/js/blank.js"] == [["deps/js/target.js", "from-import", ["alpha", "beta"]]]'

json_check "network: a blank line inside an export … from still draws its arrow" "$NET2" \
  '[[e["to"], e["kind"], e["symbols"]] for e in data["edges"] if e["from"] == "deps/js/blankexport.js"] == [["deps/js/target.js", "export-from", ["alpha", "beta"]]]'

json_check "network: an import clause past 400 characters still draws its arrow" "$NET2" \
  '[[e["to"], e["symbol_count"], e["symbols_truncated"]] for e in data["edges"] if e["from"] == "deps/js/long.js"] == [["deps/js/target.js", 60, True]]'

# A statement the scan cannot read does not leave its file looking like one
# that imports nothing.
json_check "network: none of the three hard imports leaves its file at degree 0" "$NET2" \
  'all(n["analyzed"] is True and n["uses"] == 1 for n in data["nodes"] if n["path"] in ("deps/js/blank.js", "deps/js/blankexport.js", "deps/js/long.js"))'

# 'import logging' inside deps/tools finds the sibling file: that directory is
# on sys.path for a script run from it.
json_check "network: a sibling module in the same non-package directory resolves" "$NET2" \
  '[[e["to"], e["symbols"]] for e in data["edges"] if e["from"] == "deps/tools/runner.py"] == [["deps/tools/logging.py", ["setup"]]]'

# The same name from anywhere else is the standard library: an unresolved
# record, not an arrow. On Python 3.9 (no sys.stdlib_module_names) the server
# gives the other reason; json_check runs the same python3 as the server.
json_check "network: a non-package directory never captures that name repo-wide" "$NET2" \
  'all(e["to"] != "deps/tools/logging.py" for e in data["edges"] if e["from"] != "deps/tools/runner.py") and any(u["specifier"] == "logging" and u["examples"] == ["deps/pkgapp/reader.py"] and (u["reason"] == "standard library" or (sys.version_info < (3, 10) and u["reason"] == "not a file in this repository")) for u in data["unresolved"])'

json_check "network: nothing was ambiguous and no clause overran its bound" "$NET2" \
  'data["honesty"]["ambiguous_python_modules"] == 0 and data["honesty"]["js_clauses_too_long"] == 0'

grep -q 'NETWORK_LINKS_DROPPED_SENTENCE' "$APP_SOURCE" && \
  grep -q 'links_dropped' "$APP_SOURCE" && \
  grep -q 'some links not drawn' "$APP_SOURCE"
check "network UI: a file whose links the cap cut has its own words, not \"no links\"" $?

# =============================================================================
# Regression tests for defects found in review. Each fails on the behaviour it
# fixed.
# =============================================================================

# A small pool of extra servers, killed by cleanup(). The pid goes to a
# file: callers run this inside $(...), where a variable would be lost.
start_extra_server() {
  # $1: repository path  $2: log file  -> echoes the port
  python3 -m branchlens "$1" --port 0 --no-browser > "$2" 2>&1 &
  echo "$!" >> "$FIXTURE/extra-pids"
  wait_for_server "$2"
}

# ---------------------------------------------------------------- state token
# The token is what makes the browser reload. git status prints the same bytes
# for a file edited once and twice, so a token built from that output alone
# stops moving after the first edit.

TOKEN_REPO="$FIXTURE/tokenrepo"
mkdir -p "$TOKEN_REPO"
new_repo "$TOKEN_REPO" Tester t@example.com
printf 'a\n' > "$TOKEN_REPO/file.txt"
git -C "$TOKEN_REPO" add -A
git -C "$TOKEN_REPO" commit -q -m first
printf 'b\n' >> "$TOKEN_REPO/file.txt"

TOKEN_LOG="$FIXTURE/server-token.log"
TOKEN_PORT=$(start_extra_server "$TOKEN_REPO" "$TOKEN_LOG")
check "state token: server starts on the token fixture" $?

extra_token() {
  curl -s -m 5 -b "$(cookie_for "$TOKEN_PORT")" "http://127.0.0.1:$TOKEN_PORT/api/state" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["state_token"])'
}

TOKEN_A=$(extra_token)
STATUS_A=$(git -C "$TOKEN_REPO" status --porcelain)
printf 'c\nd\ne\n' >> "$TOKEN_REPO/file.txt"
STATUS_B=$(git -C "$TOKEN_REPO" status --porcelain)
TOKEN_B=$(extra_token)

[ "$STATUS_A" = "$STATUS_B" ]
check "state token: git status says exactly the same thing after the second edit" $?
[ -n "$TOKEN_A" ] && [ "$TOKEN_A" != "$TOKEN_B" ]
check "state token: editing an already-modified file moves the token" $?

printf 'x\n' > "$TOKEN_REPO/untracked.txt"
TOKEN_C=$(extra_token)
printf 'y\nz\n' >> "$TOKEN_REPO/untracked.txt"
TOKEN_D=$(extra_token)
[ -n "$TOKEN_C" ] && [ "$TOKEN_C" != "$TOKEN_D" ]
check "state token: editing an already-listed untracked file moves the token" $?

mkdir -p "$TOKEN_REPO/newdir"
printf '1\n' > "$TOKEN_REPO/newdir/one.txt"
TOKEN_E=$(extra_token)
printf '2\n' > "$TOKEN_REPO/newdir/two.txt"
TOKEN_F=$(extra_token)
[ -n "$TOKEN_E" ] && [ "$TOKEN_E" != "$TOKEN_F" ]
check "state token: a new file inside an untracked directory moves the token" $?

# ------------------------------------------------- the ref the counts name
# Everything is measured against origin/<default> when the repository has it,
# and the local branch of that name can sit elsewhere, so every sentence names
# the online ref.

ONLINE_ORIGIN="$FIXTURE/behind-origin.git"
ONLINE_SEED="$FIXTURE/behind-seed"
ONLINE_CLONE="$FIXTURE/behind-clone"
git init -q --bare -b main "$ONLINE_ORIGIN"
new_repo "$ONLINE_SEED" Tester t@example.com
printf '1\n' > "$ONLINE_SEED/a.txt"
git -C "$ONLINE_SEED" add -A
git -C "$ONLINE_SEED" commit -q -m "M1 first"
git -C "$ONLINE_SEED" remote add origin "$ONLINE_ORIGIN"
git -C "$ONLINE_SEED" push -q origin main
git clone -q "$ONLINE_ORIGIN" "$ONLINE_CLONE"
printf '2\n' >> "$ONLINE_SEED/a.txt"
git -C "$ONLINE_SEED" commit -q -am "M2 second"
printf '3\n' >> "$ONLINE_SEED/a.txt"
git -C "$ONLINE_SEED" commit -q -am "M3 third"
git -C "$ONLINE_SEED" push -q origin main
git -C "$ONLINE_CLONE" fetch -q origin
git -C "$ONLINE_CLONE" branch feature refs/heads/main

# Ground truth: feature and the local main are the same commit.
[ "$(git -C "$ONLINE_CLONE" rev-list --count feature..refs/heads/main)" = "0" ]
check "online ref: git says the local default branch has 0 commits feature lacks" $?
[ "$(git -C "$ONLINE_CLONE" rev-list --count feature..refs/remotes/origin/main)" = "2" ]
check "online ref: git says origin/main has 2 commits feature lacks" $?

ONLINE_LOG="$FIXTURE/server-online.log"
ONLINE_PORT=$(start_extra_server "$ONLINE_CLONE" "$ONLINE_LOG")
check "online ref: server starts on the behind-clone fixture" $?

ONLINE_STATE="$FIXTURE/online-state.json"
expect_get "$ONLINE_PORT" "$ONLINE_STATE" "/api/state" "200" "online ref: /api/state returns HTTP 200"

json_check "online ref: the state names the ref the counts were measured against" "$ONLINE_STATE" \
  'data["default_branch"] == "main" and data["default_synced_online"] is True and data["comparison_label"] == "origin/main" and [b["behind"] for b in data["branches"] if b["name"] == "feature"] == [2]'
json_check "online ref: a main that origin has is not a first publish" "$ONLINE_STATE" \
  'data["first_publish"] is False'

ONLINE_DIFF="$FIXTURE/online-diff.json"
expect_get "$ONLINE_PORT" "$ONLINE_DIFF" "/api/diff?branch=feature" "200" "online ref: /api/diff returns HTTP 200"

json_check "online ref: the diff explanation names origin/main, not the local main" "$ONLINE_DIFF" \
  'data["base_label"] == "origin/main" and data["explanation"] == "Changes on feature since it forked from origin/main."'

grep -q 'function comparisonLabel' "$APP_SOURCE" && \
  grep -q 'function diffBaseLabel' "$APP_SOURCE" && \
  grep -q 'comparisonLabel(currentState)' "$APP_SOURCE" && \
  grep -q 'diffBaseLabel(currentDiff)' "$APP_SOURCE"
check "online ref: the sidebar and the header both take the name from the comparison label" $?

# ------------------------------------------- the default branch's own unpushed commits
# Commits on the local default branch that its online copy lacks are what a
# push would send, so they are counted and listed like any branch's work.

UNPUSHED_STATE="$FIXTURE/unpushed-state.json"
UNPUSHED_DIFF="$FIXTURE/unpushed-diff.json"

json_check "unpushed: a main two commits behind its online copy is counted 0 ahead, 2 behind" "$ONLINE_STATE" \
  '[(b["ahead"], b["behind"]) for b in data["branches"] if b["name"] == "main"] == [(0, 2)]'

expect_get "$ONLINE_PORT" "$UNPUSHED_DIFF" "/api/diff?branch=main" "200" "unpushed: /api/diff for main with nothing to push returns HTTP 200"
json_check "unpushed: with nothing to push and a clean checkout, nothing is pending on main" "$UNPUSHED_DIFF" \
  'data["mode"] == "default-branch" and data["explanation"] == "Nothing is pending on main." and data["files"] == []'

printf 'draft\n' > "$ONLINE_CLONE/draft.txt"
expect_get "$ONLINE_PORT" "$UNPUSHED_DIFF" "/api/diff?branch=main" "200" "unpushed: /api/diff for main with an untracked file returns HTTP 200"
json_check "unpushed: with nothing to push, an edit on main is named as not yet committed" "$UNPUSHED_DIFF" \
  'data["mode"] == "default-branch" and data["explanation"] == "Edits on main not yet committed." and [f["path"] for f in data["files"]] == ["draft.txt"]'
rm "$ONLINE_CLONE/draft.txt"

git -C "$ONLINE_CLONE" config user.email t@example.com
git -C "$ONLINE_CLONE" config user.name Tester
printf 'local\n' > "$ONLINE_CLONE/local.txt"
git -C "$ONLINE_CLONE" add local.txt
git -C "$ONLINE_CLONE" commit -q -m "local only"
[ "$(git -C "$ONLINE_CLONE" rev-list --left-right --count refs/remotes/origin/main...refs/heads/main)" = "$(printf '2\t1')" ]
check "unpushed: git says main has 1 commit origin/main lacks, and lacks 2 of its" $?

expect_get "$ONLINE_PORT" "$UNPUSHED_STATE" "/api/state" "200" "unpushed: /api/state returns HTTP 200"
json_check "unpushed: main is counted against origin/main, 1 ahead and 2 behind" "$UNPUSHED_STATE" \
  '[(b["ahead"], b["behind"]) for b in data["branches"] if b["name"] == "main"] == [(1, 2)]'

expect_get "$ONLINE_PORT" "$UNPUSHED_DIFF" "/api/diff?branch=main" "200" "unpushed: /api/diff for main returns HTTP 200"
json_check "unpushed: main lists the commit a push would send" "$UNPUSHED_DIFF" \
  'data["mode"] == "worktree" and [f["path"] for f in data["files"]] == ["local.txt"]'
json_check "unpushed: a clean checkout is not said to hold edits not yet committed" "$UNPUSHED_DIFF" \
  'data["explanation"] == "Changes on main not yet on origin/main."'

printf 'edited\n' >> "$ONLINE_CLONE/local.txt"
expect_get "$ONLINE_PORT" "$UNPUSHED_DIFF" "/api/diff?branch=main" "200" "unpushed: /api/diff for main with an edit returns HTTP 200"
json_check "unpushed: an edit not yet committed is named once there is one" "$UNPUSHED_DIFF" \
  'data["explanation"] == "Changes on main not yet on origin/main, including edits not yet committed." and data["files"][0]["adds"] == 2'

# ------------------------------------------- the trunk checked out in the main folder
# No remote default, no main or master, several branches: the branch the main
# checkout is on is the default branch. A detached main checkout has none.

TRUNK_REPO="$FIXTURE/trunkrepo"
git init -q -b trunk "$TRUNK_REPO"
git -C "$TRUNK_REPO" config user.email t@example.com
git -C "$TRUNK_REPO" config user.name Tester
printf 'base\n' > "$TRUNK_REPO/base.txt"
git -C "$TRUNK_REPO" add -A
git -C "$TRUNK_REPO" commit -q -m "trunk start"
git -C "$TRUNK_REPO" branch topic
TRUNK_LOG="$FIXTURE/server-trunk.log"
TRUNK_PORT=$(start_extra_server "$TRUNK_REPO" "$TRUNK_LOG")
check "trunk: server starts on a repository with no main or master" $?
TRUNK_STATE="$FIXTURE/trunk-state.json"
expect_get "$TRUNK_PORT" "$TRUNK_STATE" "/api/state" "200" "trunk: /api/state returns HTTP 200"
json_check "trunk: the branch checked out in the main folder is the default, via main-checkout" "$TRUNK_STATE" \
  'data["default_branch"] == "trunk" and data["base_source"] == "main-checkout"'
git -C "$TRUNK_REPO" checkout -q --detach
expect_get "$TRUNK_PORT" "$TRUNK_STATE" "/api/state" "400" "trunk: with the main checkout detached, /api/state answers HTTP 400"
json_check "trunk: the error names every rule that did not match" "$TRUNK_STATE" \
  'data["error"] == "Could not determine the default branch: there is no remote default, no branch named main or master, more than one branch exists, and the main checkout is on none of them."'

# ------------------------------------------- Git LFS: a required filter
# The usual global LFS config marks the filter required. With its programs
# blanked and 'required' left on, every status and diff that must read an
# LFS file fails. Only this fixture's server gets that global config.

LFS_REPO="$FIXTURE/lfsrepo"
LFS_GLOBAL="$FIXTURE/lfs-global.config"
printf '[filter "lfs"]\n\tclean = git-lfs clean -- %%f\n\tsmudge = git-lfs smudge -- %%f\n\tprocess = git-lfs filter-process\n\trequired = true\n' \
  > "$LFS_GLOBAL"
new_repo "$LFS_REPO" Tester t@example.com
printf '*.dat filter=lfs\n' > "$LFS_REPO/.gitattributes"
printf 'hello\n' > "$LFS_REPO/a.dat"
git -C "$LFS_REPO" add -A
git -C "$LFS_REPO" commit -q -m "LFS fixture"
# Same size, so git has to read the file again to see the edit.
printf 'jello\n' > "$LFS_REPO/a.dat"

GIT_CONFIG_GLOBAL="$LFS_GLOBAL" git -C "$LFS_REPO" -c filter.lfs.clean= -c filter.lfs.smudge= \
  -c filter.lfs.process= --no-optional-locks status --porcelain > /dev/null 2>&1
[ $? -ne 0 ]
check "lfs: with only its programs blanked, the required filter makes git status fail" $?

LFS_LOG="$FIXTURE/server-lfs.log"
GIT_CONFIG_GLOBAL="$LFS_GLOBAL" python3 -m branchlens "$LFS_REPO" --port 0 --no-browser \
  > "$LFS_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
LFS_PORT=$(wait_for_server "$LFS_LOG")
check "lfs: server starts under a global config with a required LFS filter" $?
LFS_BODY="$FIXTURE/lfs.json"
expect_get "$LFS_PORT" "$LFS_BODY" "/api/state" "200" "lfs: /api/state returns HTTP 200"
json_check "lfs: main's edit to the LFS file is read, with no status error" "$LFS_BODY" \
  '[(b["name"], b["has_uncommitted"], b["status_error"]) for b in data["branches"]] == [("main", True, None)]'
expect_get "$LFS_PORT" "$LFS_BODY" "/api/diff?branch=main" "200" "lfs: /api/diff on main returns HTTP 200"
json_check "lfs: the diff lists the edited LFS file" "$LFS_BODY" \
  '[f["path"] for f in data["files"]] == ["a.dat"] and data["explanation"] == "Edits on main not yet committed."'
expect_get "$LFS_PORT" "$LFS_BODY" "/api/file?branch=main&path=a.dat" "200" "lfs: /api/file on the LFS file returns HTTP 200"
json_check "lfs: the patch shows the edit" "$LFS_BODY" \
  '"-hello\n+jello\n" in data["patch"]'

# ------------------------------------------- a status git cannot read
# A failed status is not a clean worktree: the branch carries git's message,
# and the tokens move so the page redraws the row.

STERR_REPO="$FIXTURE/staterr"
STERR_WT="$FIXTURE/staterr-wt"
new_repo "$STERR_REPO" Tester t@example.com
printf 'a\n' > "$STERR_REPO/a.txt"
git -C "$STERR_REPO" add -A
git -C "$STERR_REPO" commit -q -m "status error fixture"
git -C "$STERR_REPO" worktree add -q -b side "$STERR_WT"
STERR_LOG="$FIXTURE/server-staterr.log"
STERR_PORT=$(start_extra_server "$STERR_REPO" "$STERR_LOG")
check "status error: server starts" $?
STERR_BEFORE="$FIXTURE/staterr-before.json"
STERR_AFTER="$FIXTURE/staterr-after.json"
STERR_DIFF="$FIXTURE/staterr-diff.json"
http_get "$STERR_PORT" "$STERR_BEFORE" "/api/state" > /dev/null
json_check "status error: a clean worktree has no edits and no status error" "$STERR_BEFORE" \
  'sorted((b["name"], b["has_uncommitted"], b["status_error"]) for b in data["branches"]) == [("main", False, None), ("side", False, None)]'
# A few bytes where the worktree's index should be: git status fails there.
printf 'garbage' > "$(git -C "$STERR_WT" rev-parse --absolute-git-dir)/index"
expect_get "$STERR_PORT" "$STERR_AFTER" "/api/state" "200" "status error: /api/state still returns HTTP 200"
json_check "status error: side keeps has_uncommitted false and carries git's message" "$STERR_AFTER" \
  '[(b["has_uncommitted"], b["status_error"].startswith("git status failed: ")) for b in data["branches"] if b["name"] == "side"] == [(False, True)] and [b["status_error"] for b in data["branches"] if b["name"] == "main"] == [None]'
state_pair_check "status error: the state token and side's content token move" "$STERR_BEFORE" "$STERR_AFTER" \
  'before["state_token"] != after["state_token"] and token(before, "side") != token(after, "side") and token(before, "main") == token(after, "main")'

# /api/diff reads the same status; when only that read fails, it answers
# with the error instead of a sentence about edits.
python3 -c '
import sys
from branchlens import gitops
def failing_status(worktree_path):
    return b"", "git status failed: stub"
gitops.read_worktree_status = failing_status
try:
    gitops.get_diff(sys.argv[2], "main")
except gitops.GitError as error:
    sys.exit(0 if str(error) == "Could not read the uncommitted changes: git status failed: stub" else 1)
sys.exit(1)
' "$PROJECT_DIR" "$STERR_REPO"
check "status error: /api/diff answers a failed status with an error, not a sentence" $?

grep -q '"Could not read the uncommitted changes: " + statusError' "$SOURCE_DIR/static/app.html" && \
  grep -q 'makeStatusErrorChip(branch.status_error)' "$SOURCE_DIR/static/app.html" && \
  grep -q 'makeStatusErrorChip(entry.status_error)' "$SOURCE_DIR/static/app.html" && \
  grep -q '"edits unknown"' "$SOURCE_DIR/static/app.html" && \
  grep -q 'branch.has_uncommitted || typeof branch.status_error === "string"' "$SOURCE_DIR/static/app.html"
check "status error: the branch and detached rows show an edits unknown chip with git's message, and badges wait" $?

# ------------------------------------------- a shallow clone, deepened later
# Fetching the missing history reveals the fork point without moving either
# tip: an "unrelated" answer from before must not be served again.

SHALLOW_ORIGIN="$FIXTURE/shallow-origin"
SHALLOW_CLONE="$FIXTURE/shallow-clone"
new_repo "$SHALLOW_ORIGIN" Tester t@example.com
printf 'one\n' > "$SHALLOW_ORIGIN/base.txt"
git -C "$SHALLOW_ORIGIN" add -A
git -C "$SHALLOW_ORIGIN" commit -q -m "fork point"
git -C "$SHALLOW_ORIGIN" checkout -q -b feature
printf 'feature\n' > "$SHALLOW_ORIGIN/feature.txt"
git -C "$SHALLOW_ORIGIN" add -A
git -C "$SHALLOW_ORIGIN" commit -q -m "feature work"
git -C "$SHALLOW_ORIGIN" checkout -q main
printf 'two\n' >> "$SHALLOW_ORIGIN/base.txt"
git -C "$SHALLOW_ORIGIN" commit -q -am "main work"
git clone -q --depth 1 --no-single-branch "file://$SHALLOW_ORIGIN" "$SHALLOW_CLONE"
git -C "$SHALLOW_CLONE" branch -q feature origin/feature
! git -C "$SHALLOW_CLONE" merge-base origin/main feature > /dev/null
check "shallow clone: git finds no fork point before the history is fetched" $?

SHALLOW_LOG="$FIXTURE/server-shallow.log"
SHALLOW_PORT=$(start_extra_server "$SHALLOW_CLONE" "$SHALLOW_LOG")
check "shallow clone: server starts on a shallow clone" $?
SHALLOW_DIFF="$FIXTURE/shallow-diff.json"
http_get "$SHALLOW_PORT" "$SHALLOW_DIFF" "/api/diff?branch=feature" > /dev/null
json_check "shallow clone: while shallow, the refusal says the clone is shallow, not that the histories are unrelated" "$SHALLOW_DIFF" \
  '"This clone is shallow" in data.get("error", "") and "git fetch --unshallow" in data.get("error", "") and "unrelated" not in data.get("error", "")'

git -C "$SHALLOW_CLONE" fetch -q --unshallow
git -C "$SHALLOW_CLONE" merge-base origin/main feature > /dev/null
check "shallow clone: git finds the fork point once the history is fetched" $?
expect_get "$SHALLOW_PORT" "$SHALLOW_DIFF" "/api/diff?branch=feature" "200" "shallow clone: after the fetch, /api/diff for feature returns HTTP 200"
json_check "shallow clone: the same server now finds the fork point" "$SHALLOW_DIFF" \
  'data["explanation"] == "Changes on feature since it forked from origin/main." and [f["path"] for f in data["files"]] == ["feature.txt"]'

# ------------------------------------------- untracked entries that are not files
# 'git ls-files --others' also names symlinks and directories git will not look
# inside (an embedded repository, a worktree). A no-index diff against those
# fails, and since exit code 1 is success for git diff, the failure can read as
# an empty new file with +0 -0.

UNTRACKED_REPO="$FIXTURE/untrackedrepo"
mkdir -p "$UNTRACKED_REPO/src"
new_repo "$UNTRACKED_REPO" Tester t@example.com
printf 'def f():\n    return 1\n' > "$UNTRACKED_REPO/src/moveme.py"
printf 'a\nb\nc\n' > "$UNTRACKED_REPO/modifyme.txt"
git -C "$UNTRACKED_REPO" add -A
git -C "$UNTRACKED_REPO" commit -q -m initial
git -C "$UNTRACKED_REPO" checkout -q -b feat
printf 'a\nB\nC\n' > "$UNTRACKED_REPO/modifyme.txt"
printf 'side\n' > "$UNTRACKED_REPO/side.txt"
git -C "$UNTRACKED_REPO" add -A
git -C "$UNTRACKED_REPO" commit -q -m "feat work"
ln -s src "$UNTRACKED_REPO/linkdir"
git init -q "$UNTRACKED_REPO/nested"
printf 'inner\n' > "$UNTRACKED_REPO/nested/inner.txt"

# Ground truth: git names all three, and the symlink is one line of content.
git -C "$UNTRACKED_REPO" ls-files --others --exclude-standard | grep -q '^nested/$'
check "untracked: git lists the embedded repository as one directory entry" $?
UNTRACKED_NOINDEX=$(git -C "$UNTRACKED_REPO" diff --no-index --numstat -- /dev/null "$UNTRACKED_REPO/linkdir" 2>/dev/null)
[ -z "$UNTRACKED_NOINDEX" ]
check "untracked: a no-index diff against a symlinked directory prints nothing at all" $?

UNTRACKED_LOG="$FIXTURE/server-untracked.log"
UNTRACKED_PORT=$(start_extra_server "$UNTRACKED_REPO" "$UNTRACKED_LOG")
check "untracked: server starts on the untracked-entries fixture" $?

UNTRACKED_DIFF="$FIXTURE/untracked-diff.json"
expect_get "$UNTRACKED_PORT" "$UNTRACKED_DIFF" "/api/diff?branch=feat" "200" "untracked: /api/diff returns HTTP 200"

json_check "untracked: an embedded repository is a directory with no line counts, never a +0 -0 file" "$UNTRACKED_DIFF" \
  '[[f["entry_kind"], f["adds"], f["dels"]] for f in data["files"] if f["path"] == "nested/"] == [["directory", None, None]]'

json_check "untracked: a symlink carries the one line git itself counts for it" "$UNTRACKED_DIFF" \
  '[[f["entry_kind"], f["adds"], f["dels"]] for f in data["files"] if f["path"] == "linkdir"] == [["symlink", 1, 0]]'

json_check "untracked: only real files are counted in the totals" "$UNTRACKED_DIFF" \
  'data["total_adds"] == 4 and data["total_dels"] == 2 and sorted(f["path"] for f in data["files"]) == ["linkdir", "modifyme.txt", "nested/", "side.txt"]'

UNTRACKED_FILE="$FIXTURE/untracked-file.json"
expect_get "$UNTRACKED_PORT" "$UNTRACKED_FILE" "/api/file?branch=feat&path=nested%2F" "200" "untracked: /api/file for the directory entry returns HTTP 200"

json_check "untracked: the patch endpoint says it is a directory, not an empty file" "$UNTRACKED_FILE" \
  'data["entry_kind"] == "directory" and data["patch"] == ""'

UNTRACKED_LINK="$FIXTURE/untracked-link.json"
expect_get "$UNTRACKED_PORT" "$UNTRACKED_LINK" "/api/file?branch=feat&path=linkdir" "200" "untracked: /api/file for the symlink returns HTTP 200"

json_check "untracked: the symlink's patch is the mode 120000 blob git would store" "$UNTRACKED_LINK" \
  'data["entry_kind"] == "symlink" and "new file mode 120000" in data["patch"] and "+src" in data["patch"]'

grep -q 'function isDirectoryEntry' "$APP_SOURCE" && \
  grep -q 'DIRECTORY_ENTRY_SENTENCE' "$APP_SOURCE" && \
  grep -q 'function countChangedEntries' "$APP_SOURCE"
check "untracked UI: a directory entry has its own words and is not counted as a file" $?

# ------------------------------------------------------------------ pathspecs
# What follows "--" is a pathspec: a bare path also matches everything under a
# directory of that name, and its glob characters are read as globs. Either one
# puts a second file's hunks in a patch the page heads with the first file's
# name.

PSPEC_REPO="$FIXTURE/pathspecrepo"
mkdir -p "$PSPEC_REPO/tools" "$PSPEC_REPO/app/[slug]" "$PSPEC_REPO/app/s"
new_repo "$PSPEC_REPO" Tester t@example.com
printf 'SCRIPT line A\nSCRIPT line B\n' > "$PSPEC_REPO/tools/run.sh"
printf 'export default function Slug() { return 1 }\n' > "$PSPEC_REPO/app/[slug]/page.tsx"
printf 'export default function S() { return 2 }\n' > "$PSPEC_REPO/app/s/page.tsx"
git -C "$PSPEC_REPO" add -A
git -C "$PSPEC_REPO" commit -q -m "c1: add the tools directory"
git -C "$PSPEC_REPO" checkout -q -b feature
git -C "$PSPEC_REPO" rm -r -q tools
printf 'NOW TOOLS IS A PLAIN FILE\n' > "$PSPEC_REPO/tools"
printf 'STATIC S ROUTE\n' > "$PSPEC_REPO/app/s/page.tsx"
printf 'export default function Slug() { return 11 }\n' > "$PSPEC_REPO/app/[slug]/page.tsx"
git -C "$PSPEC_REPO" add -A
git -C "$PSPEC_REPO" commit -q -m "c2: replace the tools directory with a plain file"
PSPEC_SHA=$(git -C "$PSPEC_REPO" rev-parse HEAD)

# Ground truth: git treats them as four separate files.
[ "$(git -C "$PSPEC_REPO" diff -M --name-only HEAD^ HEAD | wc -l | tr -d ' ')" = "4" ]
check "pathspec: git reports four separate files at that commit" $?
[ "$(git -C "$PSPEC_REPO" diff -M --name-only HEAD^ HEAD -- tools | wc -l | tr -d ' ')" = "2" ]
check "pathspec: a bare 'tools' pathspec really does match two of them" $?

PSPEC_LOG="$FIXTURE/server-pathspec.log"
PSPEC_PORT=$(start_extra_server "$PSPEC_REPO" "$PSPEC_LOG")
check "pathspec: server starts on the pathspec fixture" $?

for PSPEC_PATH in "tools" "tools%2Frun.sh" "app%2F%5Bslug%5D%2Fpage.tsx" "app%2Fs%2Fpage.tsx"; do
  PSPEC_FILE="$FIXTURE/pathspec-$(printf '%s' "$PSPEC_PATH" | tr '/%' '__').json"
  expect_get "$PSPEC_PORT" "$PSPEC_FILE" "/api/file?commit=$PSPEC_SHA&path=$PSPEC_PATH" "200" "pathspec: /api/file?commit for $PSPEC_PATH returns HTTP 200"
  json_check "pathspec: the commit patch for $PSPEC_PATH holds that file and nothing else" "$PSPEC_FILE" \
    'data["patch"].count("diff --git ") == 1 and data["patch"].startswith("diff --git a/" + data["path"] + " b/" + data["path"])'
done

PSPEC_BRANCH="$FIXTURE/pathspec-branch.json"
expect_get "$PSPEC_PORT" "$PSPEC_BRANCH" "/api/file?branch=feature&path=tools" "200" "pathspec: /api/file?branch for tools returns HTTP 200"
json_check "pathspec: the branch patch for tools holds that file and nothing else" "$PSPEC_BRANCH" \
  'data["patch"].count("diff --git ") == 1 and "SCRIPT line A" not in data["patch"]'

# --------------------------------------------------------------- graph lanes
# Two lanes never share an x: a shared x would draw one column through a
# neighbour's dots, which reads as a parent edge git does not have.

! grep -q 'Math.min(laneIndex, 7)' "$APP_SOURCE"
check "tree lanes: no lane is collapsed onto another lane's x position" $?
grep -q 'function computeTreeLaneGeometry' "$APP_SOURCE" && \
  grep -q 'function laneIsDrawn' "$APP_SOURCE" && \
  grep -q 'function addOverflowMark' "$APP_SOURCE"
check "tree lanes: the geometry shrinks the spacing instead of sharing a slot" $?
[ "$(grep -c 'laneIsDrawn(' "$APP_SOURCE")" -ge 7 ]
check "tree lanes: every line, curve and dot is guarded by the drawn-lane test" $?
grep -q 'more branch lanes than fit in this column' "$APP_SOURCE"
check "tree lanes: a graph too wide to draw says so under the tree" $?

# ------------------------------------------------------------ commit messages
# git's one blank line between subject and body is a separator; further blank
# lines are the author's and stay.

MSG_REPO="$FIXTURE/msgrepo"
mkdir -p "$MSG_REPO"
new_repo "$MSG_REPO" Tester t@example.com
printf 'one\n' > "$MSG_REPO/f.txt"
git -C "$MSG_REPO" add -A
printf 'Triple blank subject\n\n\n\nbody after three blank lines\nsecond\n' > "$FIXTURE/msg.txt"
git -C "$MSG_REPO" commit -q --cleanup=verbatim -F "$FIXTURE/msg.txt"
MSG_SHA=$(git -C "$MSG_REPO" rev-parse HEAD)

MSG_LOG="$FIXTURE/server-msg.log"
MSG_PORT=$(start_extra_server "$MSG_REPO" "$MSG_LOG")
check "commit message: server starts on the message fixture" $?

MSG_DIFF="$FIXTURE/msg-diff.json"
expect_get "$MSG_PORT" "$MSG_DIFF" "/api/diff?commit=$MSG_SHA" "200" "commit message: /api/diff?commit returns HTTP 200"

json_check "commit message: the server hands over the blank lines byte for byte" "$MSG_DIFF" \
  'data["message"] == "Triple blank subject\n\n\n\nbody after three blank lines\nsecond"'

! grep -qF 'replace(/^\n+/, "")' "$APP_SOURCE"
check "commit message: the pane no longer deletes a whole run of blank lines" $?
grep -q 'function splitCommitMessage' "$APP_SOURCE" && \
  grep -q 'body.charAt(0) === "\\n"' "$APP_SOURCE"
check "commit message: exactly one separator newline is removed" $?
! grep -qF 'var lineCount = message.split("\n").length' "$APP_SOURCE"
check "commit message: the line count no longer comes from the raw message" $?
grep -q 'var lineCount = parsed.lineCount' "$APP_SOURCE"
check "commit message: the toggle counts the lines the pane really holds" $?

# ------------------------------------------------------------- network fixes
NETFIX_REPO="$FIXTURE/netfixrepo"
mkdir -p "$NETFIX_REPO/nspkg" "$NETFIX_REPO/shadowpkg" "$NETFIX_REPO/plainpkg"
new_repo "$NETFIX_REPO" Tester t@example.com

# A namespace package: modules with no __init__.py anywhere.
printf 'from nspkg import alpha\nimport nspkg.delta\n' > "$NETFIX_REPO/main.py"
printf 'VALUE = 1\n' > "$NETFIX_REPO/nspkg/alpha.py"
printf 'VALUE = 4\n' > "$NETFIX_REPO/nspkg/delta.py"
printf 'import nspkg\n' > "$NETFIX_REPO/bare.py"

# An __init__ attribute that shadows a sibling module of the same name.
printf "version = '1.0'\n" > "$NETFIX_REPO/shadowpkg/__init__.py"
printf "raise RuntimeError('never imported')\n" > "$NETFIX_REPO/shadowpkg/version.py"
printf 'from shadowpkg import version\n' > "$NETFIX_REPO/use_shadow.py"

# A package whose __init__.py does not bind the name: both files run.
printf 'PLAIN_INIT_MARKER = 1\n' > "$NETFIX_REPO/plainpkg/__init__.py"
printf 'def go():\n    return 1\n' > "$NETFIX_REPO/plainpkg/helper.py"
printf 'from plainpkg import helper\n' > "$NETFIX_REPO/use_plain.py"
printf 'import plainpkg.helper\n' > "$NETFIX_REPO/use_dotted.py"

# Code in a language this view recognises and never parses.
printf 'package main\n' > "$NETFIX_REPO/service.go"

# A JavaScript import whose name the scanner cannot read.
printf 'export const a = 1;\nconst weird = 2;\nexport { weird as "weird-name" };\n' > "$NETFIX_REPO/mod.js"
printf 'import { "weird-name" as w } from "./mod.js";\nexport const x = w;\n' > "$NETFIX_REPO/uses.js"

git -C "$NETFIX_REPO" add -A
git -C "$NETFIX_REPO" commit -q -m "network fixes fixture"
NETFIX_SHA=$(git -C "$NETFIX_REPO" rev-parse HEAD)

# Ground truth from CPython itself, not from BranchLens.
(cd "$NETFIX_REPO" && python3 -c "
import sys
sys.dont_write_bytecode = True
from nspkg import alpha
from shadowpkg import version
assert alpha.VALUE == 1
assert version == '1.0'
assert 'shadowpkg.version' not in sys.modules
import plainpkg.helper
assert 'plainpkg' in sys.modules
") > /dev/null 2>&1
check "network: CPython confirms the namespace package and the shadowed name" $?

NETFIX_LOG="$FIXTURE/server-netfix.log"
NETFIX_PORT=$(start_extra_server "$NETFIX_REPO" "$NETFIX_LOG")
check "network: server starts on the network-fixes fixture" $?

NETFIX="$FIXTURE/netfix.json"
expect_get "$NETFIX_PORT" "$NETFIX" "/api/network?commit=$NETFIX_SHA" "200" "network: /api/network on the network-fixes fixture returns HTTP 200"

json_check "network: a namespace package (no __init__.py) resolves to its modules" "$NETFIX" \
  '["main.py", "nspkg/alpha.py"] in [[e["from"], e["to"]] for e in data["edges"]] and ["main.py", "nspkg/delta.py"] in [[e["from"], e["to"]] for e in data["edges"]]'

json_check "network: a package directory inside the repository is never called an import that leaves it" "$NETFIX" \
  'all(u["reason"] != "not a file in this repository" for u in data["unresolved"] if u["specifier"] == "nspkg") and data["honesty"]["python_namespace_packages"] == 1'

json_check "network: an __init__ attribute wins over the sibling module of the same name" "$NETFIX" \
  '["use_shadow.py", "shadowpkg/__init__.py"] in [[e["from"], e["to"]] for e in data["edges"]] and all([e["from"], e["to"]] != ["use_shadow.py", "shadowpkg/version.py"] for e in data["edges"])'

json_check "network: importing out of a package draws the arrow to the __init__.py that runs" "$NETFIX" \
  'sorted(e["to"] for e in data["edges"] if e["from"] == "use_plain.py") == ["plainpkg/__init__.py", "plainpkg/helper.py"] and sorted(e["to"] for e in data["edges"] if e["from"] == "use_dotted.py") == ["plainpkg/__init__.py", "plainpkg/helper.py"]'

json_check "network: a language this view cannot read is not called one it knows" "$NETFIX" \
  'data["counts"]["unsupported_code_files"] == 1 and [n["reason"] for n in data["nodes"] if n["path"] == "service.go"] == ["unsupported language"] and all(n["path"] != "service.go" for n in data["nodes"] if n["analyzed"])'

json_check "network: an unreadable imported name is recorded on its own arrow" "$NETFIX" \
  '[[e["symbols"], e["symbols_unreadable"]] for e in data["edges"] if e["from"] == "uses.js"] == [[[], 1]] and data["honesty"]["symbols_unreadable"] == 1'

json_check "network: an unreadable name gets its own sentence" "$NETFIX" \
  'any("could not be read" in note for note in data["notes"]) and any("does not read" in note for note in data["notes"])'

grep -q 'symbolsUnreadable' "$APP_SOURCE" && \
  grep -q 'crossing this arrow could not be read' "$APP_SOURCE"
check "network UI: an arrow whose names could not be read never claims it names none" $?
grep -q 'in a language this view reads' "$APP_SOURCE" && \
  grep -q 'unsupported_code_files' "$APP_SOURCE"
check "network UI: the summary line separates languages it reads from ones it does not" $?
grep -q 'unresolved_groups_total' "$APP_SOURCE"
check "network UI: a capped unresolved list says how many it names" $?

# ---- symlinks and submodules at the commit ---------------------------------

SYM_REPO="$FIXTURE/symrepo"
mkdir -p "$SYM_REPO"
new_repo "$SYM_REPO" Tester t@example.com
printf 'VALUE = 1\n' > "$SYM_REPO/real.py"
printf 'import link\n' > "$SYM_REPO/uses_link.py"
ln -s real.py "$SYM_REPO/link.py"
git -C "$SYM_REPO" add -A
git -C "$SYM_REPO" commit -q -m base
SYM_SHA=$(git -C "$SYM_REPO" rev-parse HEAD)

git -C "$SYM_REPO" ls-tree -r --full-tree HEAD | grep -q '^120000 blob .*link.py$'
check "network: git lists the symlink inside the repository at that commit" $?

SYM_LOG="$FIXTURE/server-sym.log"
SYM_PORT=$(start_extra_server "$SYM_REPO" "$SYM_LOG")
check "network: server starts on the symlink fixture" $?

SYM_NET="$FIXTURE/sym-network.json"
expect_get "$SYM_PORT" "$SYM_NET" "/api/network?commit=$SYM_SHA" "200" "network: /api/network on the symlink fixture returns HTTP 200"

json_check "network: a symlink at the commit gets a sentence of its own" "$SYM_NET" \
  'data["excluded"]["symlinks"] == 1 and any("symlink" in note for note in data["notes"])'

json_check "network: an import of a symlinked module is not called one that leaves the repository" "$SYM_NET" \
  '[u["reason"] for u in data["unresolved"] if u["specifier"] == "link"] == ["a symlink or submodule at this commit, which this view does not read"]'

# ---- the unresolved-group cap ----------------------------------------------

CAP_REPO="$FIXTURE/caprepo"
mkdir -p "$CAP_REPO"
new_repo "$CAP_REPO" Tester t@example.com
python3 -c "
import sys
handle = open(sys.argv[1], 'w')
handle.write('\n'.join('import zzzpkg_%03d' % i for i in range(250)) + '\n')
handle.close()
" "$CAP_REPO/many.py"
git -C "$CAP_REPO" add -A
git -C "$CAP_REPO" commit -q -m "many imports"
CAP_SHA=$(git -C "$CAP_REPO" rev-parse HEAD)

[ "$(grep -c '^import zzzpkg_' "$CAP_REPO/many.py")" = "250" ]
check "network cap: the fixture really holds 250 distinct specifiers" $?

CAP_LOG="$FIXTURE/server-cap.log"
CAP_PORT=$(start_extra_server "$CAP_REPO" "$CAP_LOG")
check "network cap: server starts on the many-imports fixture" $?

CAP_NET="$FIXTURE/cap-network.json"
expect_get "$CAP_PORT" "$CAP_NET" "/api/network?commit=$CAP_SHA" "200" "network cap: /api/network on the many-imports fixture returns HTTP 200"

json_check "network cap: a cut unresolved list says so and is marked truncated" "$CAP_NET" \
  'len(data["unresolved"]) == 200 and data["counts"]["unresolved_groups_total"] == 250 and data["counts"]["unresolved_groups_shown"] == 200 and data["truncated"] is True and any("200 of 250" in note for note in data["notes"])'

# ---- a source file that exists but could not be read ------------------------

BIG_REPO="$FIXTURE/bigrepo"
mkdir -p "$BIG_REPO"
new_repo "$BIG_REPO" Tester t@example.com
python3 -c "
import sys
handle = open(sys.argv[1], 'w')
handle.write('import os\n' + '#' * 467990)
handle.close()
" "$BIG_REPO/big.py"
git -C "$BIG_REPO" add -A
git -C "$BIG_REPO" commit -q -m "add big python module"
BIG_SHA=$(git -C "$BIG_REPO" rev-parse HEAD)
printf 'import big\n' > "$BIG_REPO/a.py"
git -C "$BIG_REPO" add -A
git -C "$BIG_REPO" commit -q -m "add a"
BIG_SHA2=$(git -C "$BIG_REPO" rev-parse HEAD)

BIG_LOG="$FIXTURE/server-big.log"
BIG_PORT=$(start_extra_server "$BIG_REPO" "$BIG_LOG")
check "network big: server starts on the oversized-file fixture" $?

BIG_NET="$FIXTURE/big-network.json"
expect_get "$BIG_PORT" "$BIG_NET" "/api/network?commit=$BIG_SHA" "200" "network big: /api/network on the oversized-file commit returns HTTP 200"

json_check "network big: a source file that exists is never reported as not existing" "$BIG_NET" \
  '"could not be read" in data["explanation"] and "No Python" not in data["explanation"] and data["counts"]["code_files"] == 1'

BIG_NET2="$FIXTURE/big-network2.json"
expect_get "$BIG_PORT" "$BIG_NET2" "/api/network?commit=$BIG_SHA2" "200" "network big: /api/network on the importing commit returns HTTP 200"

json_check "network big: an unread file still has a known used_by" "$BIG_NET2" \
  '[[e["from"], e["to"]] for e in data["edges"]] == [["a.py", "big.py"]] and [[n["analyzed"], n["used_by"]] for n in data["nodes"] if n["path"] == "big.py"] == [[False, 1]]'

# ---- each file is parsed once per content -----------------------------------
# A file edited between two commits is read again; one left alone keeps its
# arrows; the same content at another path is parsed for that path.

NETCACHE_REPO="$FIXTURE/netcache"
mkdir -p "$NETCACHE_REPO"
new_repo "$NETCACHE_REPO" Tester t@example.com
printf 'import b\n' > "$NETCACHE_REPO/a.py"
printf 'x = 1\n' > "$NETCACHE_REPO/b.py"
printf 'y = 2\n' > "$NETCACHE_REPO/c.py"
printf 'import c\n' > "$NETCACHE_REPO/d.py"
git -C "$NETCACHE_REPO" add -A
git -C "$NETCACHE_REPO" commit -q -m "a uses b"
NETCACHE_FIRST=$(git -C "$NETCACHE_REPO" rev-parse HEAD)
printf 'import c\n' > "$NETCACHE_REPO/a.py"
git -C "$NETCACHE_REPO" commit -q -am "a uses c"
NETCACHE_SECOND=$(git -C "$NETCACHE_REPO" rev-parse HEAD)

NETCACHE_LOG="$FIXTURE/server-netcache.log"
NETCACHE_PORT=$(start_extra_server "$NETCACHE_REPO" "$NETCACHE_LOG")
check "network cache: server starts on the two-commit fixture" $?

NETCACHE_BODY="$FIXTURE/netcache.json"
expect_get "$NETCACHE_PORT" "$NETCACHE_BODY" "/api/network?commit=$NETCACHE_FIRST" "200" "network cache: /api/network on the first commit returns HTTP 200"
json_check "network cache: the first commit has a using b and d using c" "$NETCACHE_BODY" \
  '[[e["from"], e["to"]] for e in data["edges"]] == [["a.py", "b.py"], ["d.py", "c.py"]]'

expect_get "$NETCACHE_PORT" "$NETCACHE_BODY" "/api/network?commit=$NETCACHE_SECOND" "200" "network cache: /api/network on the second commit returns HTTP 200"
json_check "network cache: the edited file is read again, the unchanged one keeps its arrow" "$NETCACHE_BODY" \
  '[[e["from"], e["to"]] for e in data["edges"]] == [["a.py", "c.py"], ["d.py", "c.py"]] and all(n["analyzed"] for n in data["nodes"])'

# ------------------------------------------------- comparing divergent commits
# A file present at one point and absent at the other was not deleted by any
# commit when the two sit on different branches.

DIV_REPO="$FIXTURE/divrepo"
mkdir -p "$DIV_REPO"
new_repo "$DIV_REPO" Tester t@example.com
printf 'root\n' > "$DIV_REPO/root.txt"
git -C "$DIV_REPO" add -A
git -C "$DIV_REPO" commit -q -m root
git -C "$DIV_REPO" checkout -q -b side
printf 'side one\nside two\n' > "$DIV_REPO/side.txt"
git -C "$DIV_REPO" add -A
git -C "$DIV_REPO" commit -q -m "side work"
DIV_SIDE=$(git -C "$DIV_REPO" rev-parse HEAD)
git -C "$DIV_REPO" checkout -q main
printf 'main\n' > "$DIV_REPO/main.txt"
git -C "$DIV_REPO" add -A
git -C "$DIV_REPO" commit -q -m "main work"
DIV_MAIN=$(git -C "$DIV_REPO" rev-parse HEAD)
git -C "$DIV_REPO" merge -q --no-edit side
DIV_MERGE=$(git -C "$DIV_REPO" rev-parse HEAD)

# Ground truth: nothing ever deleted side.txt and it is still there.
[ -z "$(git -C "$DIV_REPO" log --all --diff-filter=D --format=%h -- side.txt)" ]
check "divergent: git says no commit ever deleted side.txt" $?
git -C "$DIV_REPO" ls-tree --name-only HEAD | grep -q '^side.txt$'
check "divergent: side.txt is still in the repository today" $?

DIV_LOG="$FIXTURE/server-div.log"
DIV_PORT=$(start_extra_server "$DIV_REPO" "$DIV_LOG")
check "divergent: server starts on the divergent fixture" $?

DIV_DIFF="$FIXTURE/div-diff.json"
expect_get "$DIV_PORT" "$DIV_DIFF" "/api/diff?commit=$DIV_MAIN&base=$DIV_SIDE" "200" "divergent: /api/diff across two branches returns HTTP 200"

json_check "divergent: the comparison says it is a comparison, not a list of changes" "$DIV_DIFF" \
  'data["base_is_ancestor"] is False and data["base_is_descendant"] is False and "different lines of history" in data["explanation"] and "Everything that changed" not in data["explanation"]'

DIV_DIFF2="$FIXTURE/div-diff2.json"
expect_get "$DIV_PORT" "$DIV_DIFF2" "/api/diff?commit=$DIV_MERGE&base=$DIV_MAIN" "200" "divergent: /api/diff along real history returns HTTP 200"

json_check "divergent: a real before-and-after keeps its history wording" "$DIV_DIFF2" \
  'data["base_is_ancestor"] is True and data["explanation"].startswith("Everything that changed from")'

grep -q 'COMPARISON_STATUS_WORDS' "$APP_SOURCE" && \
  grep -q 'function isDivergentComparison' "$APP_SOURCE" && \
  grep -q 'so no commit deleted it' "$APP_SOURCE"
check "divergent UI: the pane never reports a deletion no commit made" $?

# The same holds for a branch compared with a point on another line of history.
DIV_BRANCH="$FIXTURE/div-branch.json"
expect_get "$DIV_PORT" "$DIV_BRANCH" "/api/diff?branch=side&base=$DIV_MAIN" "200" "divergent branch: /api/diff for a branch and a base on another line returns HTTP 200"
json_check "divergent branch: the base is not an ancestor, and the sentence says it is a comparison" "$DIV_BRANCH" \
  'data["mode"] == "committed" and data["base_override"] is True and data["base_is_ancestor"] is False and data["explanation"] == "How side differs from \"main work\". They sit on different lines of history, so this is a comparison, not a list of changes."'

DIV_BRANCH_FILE="$FIXTURE/div-branch-file.json"
expect_get "$DIV_PORT" "$DIV_BRANCH_FILE" "/api/file?branch=side&path=main.txt&base=$DIV_MAIN" "200" "divergent branch: /api/file for that pair returns HTTP 200"
json_check "divergent branch: /api/file carries base_is_ancestor too" "$DIV_BRANCH_FILE" \
  'data["status"] == "D" and data["base_is_ancestor"] is False'

grep -q '"on " + (currentDiff.branch' "$APP_SOURCE"
check "divergent branch UI: the banner names the branch, not an empty subject" $?

# A base that already contains the target is a later point on its own line.
git -C "$DIV_REPO" merge-base --is-ancestor side "$DIV_MERGE"
check "behind base: git says side is an ancestor of the merge" $?
DIV_BEHIND="$FIXTURE/div-behind.json"
expect_get "$DIV_PORT" "$DIV_BEHIND" "/api/diff?branch=side&base=$DIV_MERGE" "200" "behind base: /api/diff for a branch and a later commit on its line returns HTTP 200"
json_check "behind base: the branch is said to be behind that commit, not on another line" "$DIV_BEHIND" \
  'data["base_is_ancestor"] is False and data["base_is_descendant"] is True and data["explanation"].startswith("How side differs from") and data["explanation"].endswith("side is behind that commit on the same line of history, so this is a comparison, not a list of changes.")'
expect_get "$DIV_PORT" "$DIV_BEHIND" "/api/diff?commit=$DIV_SIDE&base=$DIV_MERGE" "200" "behind base: /api/diff for a commit and a later commit on its line returns HTTP 200"
json_check "behind base: the commit is said to come before that commit, not to sit on another line" "$DIV_BEHIND" \
  'data["base_is_ancestor"] is False and data["base_is_descendant"] is True and data["explanation"].startswith("How \"side work\" differs from") and data["explanation"].endswith("It comes before that commit on the same line of history, so this is a comparison, not a list of changes.")'
grep -q 'currentDiff.base_is_descendant === true' "$APP_SOURCE" && \
  grep -q 'which is behind that commit on the same line of history' "$APP_SOURCE"
check "behind base UI: the deleted-file banner does not put the two on different lines" $?

expect_get "$DIV_PORT" "$DIV_BRANCH" "/api/diff?branch=main&base=$DIV_SIDE" "200" "divergent branch: /api/diff for a branch and a real ancestor returns HTTP 200"
json_check "divergent branch: a real ancestor keeps the history wording, with no edits claimed on a clean checkout" "$DIV_BRANCH" \
  'data["mode"] == "worktree" and data["base_is_ancestor"] is True and data["explanation"] == "Changes on main since \"side work\"."'

# A checked-out branch with nothing uncommitted must not be said to have edits.
DIV_WT="$FIXTURE/div-wt"
git -C "$DIV_REPO" worktree add -q "$DIV_WT" side
expect_get "$DIV_PORT" "$DIV_BRANCH" "/api/diff?branch=side" "200" "clean worktree: /api/diff returns HTTP 200"
json_check "clean worktree: the sentence ends at the fork point" "$DIV_BRANCH" \
  'data["mode"] == "worktree" and data["explanation"] == "Changes on side since it forked from main."'

# A worktree on no branch is listed apart from the branches, with its edits flagged.
DIV_DETACHED="$FIXTURE/div-detached"
DIV_STATE="$FIXTURE/div-state.json"
git -C "$DIV_REPO" worktree add -q --detach "$DIV_DETACHED" "$DIV_SIDE"
printf 'scratch\n' > "$DIV_DETACHED/scratch.txt"
expect_get "$DIV_PORT" "$DIV_STATE" "/api/state" "200" "detached worktree: /api/state returns HTTP 200"
json_check "detached worktree: listed in detached_worktrees with its edits, and on no branch" "$DIV_STATE" \
  '[(os.path.realpath(w["path"]), w["has_uncommitted"]) for w in data["detached_worktrees"]] == [(os.path.realpath(extra), True)] and all(b["worktree_path"] is None or os.path.realpath(b["worktree_path"]) != os.path.realpath(extra) for b in data["branches"])' "$DIV_DETACHED"
grep -q 'function makeDetachedRow' "$APP_SOURCE" && \
  grep -q 'currentState.detached_worktrees' "$APP_SOURCE"
check "detached worktree UI: the sidebar shows a row for each one" $?

# A bare repository's own entry in the worktree list has no checkout: it is
# not a worktree on no branch.
BARE_REPO="$FIXTURE/bare-project.git"
BARE_WT="$FIXTURE/bare-topic"
git clone -q --bare "$DIV_REPO" "$BARE_REPO"
git -C "$BARE_REPO" worktree add -q "$BARE_WT" main
git -C "$BARE_REPO" worktree list --porcelain | grep -q '^bare$'
check "bare clone: git lists the bare repository itself as a worktree entry" $?
BARE_LOG="$FIXTURE/server-bare.log"
BARE_PORT=$(start_extra_server "$BARE_WT" "$BARE_LOG")
check "bare clone: server starts in a worktree of a bare repository" $?
BARE_STATE="$FIXTURE/bare-state.json"
expect_get "$BARE_PORT" "$BARE_STATE" "/api/state" "200" "bare clone: /api/state returns HTTP 200"
json_check "bare clone: the bare repository is not listed as a worktree on no branch" "$BARE_STATE" \
  'data["detached_worktrees"] == [] and [os.path.realpath(b["worktree_path"]) for b in data["branches"] if b["name"] == "main"] == [os.path.realpath(extra)]' "$BARE_WT"

# ------------------------------------------------------------------- security
# A repository cannot make git run a program. Four ways past an earlier
# defence: a filter behind [include] path=, a filter in config.worktree, a
# filter whose subsection name contains "=", and gpg.program via
# log.showSignature.

HOSTILE_ROOT="$FIXTURE/hostile"
HOSTILE_REPO="$HOSTILE_ROOT/repo"
HOSTILE_MARKER="$HOSTILE_ROOT/marker.txt"
mkdir -p "$HOSTILE_REPO"
printf '#!/bin/sh\necho PWNED >> "%s"\ncat\n' "$HOSTILE_MARKER" > "$HOSTILE_ROOT/evil_clean.sh"
chmod +x "$HOSTILE_ROOT/evil_clean.sh"
printf '#!/bin/sh\necho PWNED-GPG >> "%s"\nexit 1\n' "$HOSTILE_MARKER" > "$HOSTILE_ROOT/evil_gpg.sh"
chmod +x "$HOSTILE_ROOT/evil_gpg.sh"

new_repo "$HOSTILE_REPO" Tester t@example.com
printf 'line1\n' > "$HOSTILE_REPO/inc.txt"
printf 'line1\n' > "$HOSTILE_REPO/wt.txt"
printf 'line1\n' > "$HOSTILE_REPO/eq.txt"
printf 'inc.txt filter=inc\nwt.txt filter=wtf\neq.txt filter=a=b\n' > "$HOSTILE_REPO/.gitattributes"
git -C "$HOSTILE_REPO" add -A
git -C "$HOSTILE_REPO" commit -q -m initial

# 1. a filter hidden behind an include directive
printf '[filter "inc"]\n\tclean = %s\n\tsmudge = cat\n' "$HOSTILE_ROOT/evil_clean.sh" \
  > "$HOSTILE_REPO/.git/extra.config"
git -C "$HOSTILE_REPO" config --local include.path extra.config
# 2. a filter in worktree-scoped config
git -C "$HOSTILE_REPO" config core.repositoryformatversion 1
git -C "$HOSTILE_REPO" config extensions.worktreeConfig true
git -C "$HOSTILE_REPO" config --worktree filter.wtf.clean "$HOSTILE_ROOT/evil_clean.sh"
# 3. a filter whose subsection name contains "="
git -C "$HOSTILE_REPO" config --local "filter.a=b.clean" "$HOSTILE_ROOT/evil_clean.sh"
# 4. a signature checker
git -C "$HOSTILE_REPO" config --local gpg.program "$HOSTILE_ROOT/evil_gpg.sh"
git -C "$HOSTILE_REPO" config --local log.showSignature true
# dirty the working tree so a diff must run the clean filters
printf 'line1\nchanged\n' > "$HOSTILE_REPO/inc.txt"
printf 'line1\nchanged\n' > "$HOSTILE_REPO/wt.txt"
printf 'line1\nchanged\n' > "$HOSTILE_REPO/eq.txt"

# A commit carrying a bogus gpgsig header: no key needed to make git verify.
HOSTILE_TREE=$(git -C "$HOSTILE_REPO" rev-parse 'HEAD^{tree}')
HOSTILE_PARENT=$(git -C "$HOSTILE_REPO" rev-parse HEAD)
HOSTILE_SIGNED=$(printf 'tree %s\nparent %s\nauthor Tester <t@example.com> 1700000000 +0000\ncommitter Tester <t@example.com> 1700000000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQIzBAABCgAdFiEEfake\n =abcd\n -----END PGP SIGNATURE-----\n\nsigned commit\n' "$HOSTILE_TREE" "$HOSTILE_PARENT" \
  | git -C "$HOSTILE_REPO" hash-object -t commit -w --stdin)
git -C "$HOSTILE_REPO" update-ref refs/heads/signed "$HOSTILE_SIGNED"

# Ground truth: git resolves all four, and a '--local' scan sees neither of
# the first two.
[ -z "$(git -C "$HOSTILE_REPO" config --local --name-only --list | grep '^filter\.inc\.')" ]
check "security: the include-hidden filter is invisible to a --local listing" $?
[ -n "$(git -C "$HOSTILE_REPO" config --name-only --list | grep '^filter\.inc\.clean$')" ]
check "security: git itself does resolve the include-hidden filter" $?
[ -n "$(git -C "$HOSTILE_REPO" config --get filter.wtf.clean)" ]
check "security: git itself does resolve the worktree-scoped filter" $?

rm -f "$HOSTILE_MARKER"
HOSTILE_LOG="$FIXTURE/server-hostile.log"
HOSTILE_PORT=$(start_extra_server "$HOSTILE_REPO" "$HOSTILE_LOG")
check "security: server starts on the hostile repository" $?

HOSTILE_BODY="$FIXTURE/hostile.json"
expect_get "$HOSTILE_PORT" "$HOSTILE_BODY" "/api/state" "200" "security: /api/state on the hostile repository returns HTTP 200"
expect_get "$HOSTILE_PORT" "$HOSTILE_BODY" "/api/diff?branch=main" "200" "security: /api/diff on the hostile repository returns HTTP 200"
expect_get "$HOSTILE_PORT" "$HOSTILE_BODY" "/api/graph" "200" "security: /api/graph on the hostile repository returns HTTP 200"
expect_get "$HOSTILE_PORT" "$HOSTILE_BODY" "/api/diff?commit=$HOSTILE_SIGNED" "200" "security: /api/diff for the signed commit returns HTTP 200"
expect_get "$HOSTILE_PORT" "$HOSTILE_BODY" "/api/file?branch=main&path=inc.txt" "200" "security: /api/file on a filtered path returns HTTP 200"

[ ! -f "$HOSTILE_MARKER" ]
check "security: viewing the hostile repository never runs a program it names" $?

# =============================================================================
# Regression tests for the defects found by the 2026-09 audit. Each fails on
# the behaviour it fixed, except the concurrency test, which the old race
# fails on most runs.
# =============================================================================

# ---------------------------------------------------------------- audit 2026-10: suite
# Checks the October 2026 audit found missing from the suite. Each trap is
# sprung with plain git before BranchLens is shown to leave it alone. The page
# script runs under node when node is installed; without node a SKIP line is
# printed.

# --- g13: the startup probe. The server pushes a value through
# GIT_CONFIG_COUNT before it serves, and stops if the value does not come back
# (git older than 2.31 ignores the variable). A git on PATH that unsets the
# variable stands in for such a git.

SUITE_REAL_GIT=$(command -v git)
SUITE_OLD_GIT="$FIXTURE/suite-old-git"
mkdir -p "$SUITE_OLD_GIT"
cat > "$SUITE_OLD_GIT/git" <<SHIM
#!/bin/sh
unset GIT_CONFIG_COUNT
exec "$SUITE_REAL_GIT" "\$@"
SHIM
chmod +x "$SUITE_OLD_GIT/git"

SUITE_PROBE_REAL=$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=suite.probe GIT_CONFIG_VALUE_0=seen \
  git -C "$REPO" config --get suite.probe)
SUITE_PROBE_STAND_IN=$(GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=suite.probe GIT_CONFIG_VALUE_0=seen \
  "$SUITE_OLD_GIT/git" -C "$REPO" config --get suite.probe)
[ "$SUITE_PROBE_REAL" = "seen" ] && [ -z "$SUITE_PROBE_STAND_IN" ]
check "startup probe: the stand-in git really does ignore GIT_CONFIG_COUNT, which the real git honours" $? \
  "real git read '$SUITE_PROBE_REAL', the stand-in read '$SUITE_PROBE_STAND_IN'"

SUITE_PROBE_OUT="$FIXTURE/server-suite-old-git.out"
SUITE_PROBE_ERR="$FIXTURE/server-suite-old-git.err"
PATH="$SUITE_OLD_GIT:$PATH" python3 -m branchlens "$REPO" --port 0 --no-browser \
  > "$SUITE_PROBE_OUT" 2> "$SUITE_PROBE_ERR" &
SUITE_PROBE_PID=$!
echo "$SUITE_PROBE_PID" >> "$FIXTURE/extra-pids"
if process_ends "$SUITE_PROBE_PID"; then
  wait "$SUITE_PROBE_PID"
  SUITE_PROBE_EXIT=$?
else
  kill "$SUITE_PROBE_PID" 2>/dev/null
  wait "$SUITE_PROBE_PID" 2>/dev/null
  SUITE_PROBE_EXIT="none, still running after 5 seconds"
fi
[ "$SUITE_PROBE_EXIT" = "1" ]
check "startup probe: on a git that ignores GIT_CONFIG_COUNT the server stops with exit status 1" $? \
  "exit status: $SUITE_PROBE_EXIT"
grep -q "this git ignores GIT_CONFIG_COUNT" "$SUITE_PROBE_ERR"
check "startup probe: the refusal on stderr says this git ignores GIT_CONFIG_COUNT" $?
! grep -q "BranchLens serving" "$SUITE_PROBE_OUT" "$SUITE_PROBE_ERR"
check "startup probe: the refused server never prints a URL" $?

# --- g13: the server listens on 127.0.0.1 only.

SUITE_BIND=$(python3 - "$PROJECT_DIR" <<'PY'
import sys

from branchlens import server

httpd = server.create_server(0)
print(httpd.server_address[0])
httpd.server_close()
PY
)
[ "$SUITE_BIND" = "127.0.0.1" ]
check "bind: create_server listens on 127.0.0.1 only" $? "listened on '$SUITE_BIND'"

# --- F-26: on Linux the webbrowser module puts the printed URL, with its
# launch code, on the browser's command line, which every user can read.
# There BranchLens opens no browser unless --browser is given.

python3 - "$PROJECT_DIR" <<'PY'
import sys
from branchlens import server
sys.exit(0 if (server.opens_browser_by_default("linux") is False
               and server.opens_browser_by_default("darwin") is True) else 1)
PY
check "browser: by default it is opened on macOS and not on Linux" $?

# Starts server.py's main() with sys.platform set to $1 and webbrowser.open
# replaced by a stub that writes the URL to $2; $3 is the log, the rest are
# arguments. Echoes the port once the server answers, which it does only
# after the browser step.
start_with_platform() {
  local platform="$1"
  local browser_mark="$2"
  local log_file="$3"
  shift 3
  python3 -c '
import sys
import webbrowser
platform, browser_mark, project_dir = sys.argv[1], sys.argv[2], sys.argv[3]
def record_url(url, *args, **kwargs):
    with open(browser_mark, "w") as handle:
        handle.write(url)
    return True
webbrowser.open = record_url
sys.path.insert(0, project_dir)
from branchlens import server
sys.platform = platform
sys.argv = ["branchlens"] + sys.argv[4:]
server.main()
' "$platform" "$browser_mark" "$PROJECT_DIR/src" "$@" > "$log_file" 2>&1 &
  echo "$!" >> "$FIXTURE/extra-pids"
  wait_for_server "$log_file"
}
BROWSER_MARK="$FIXTURE/browser-opened"
rm -f "$BROWSER_MARK"
LINUX_PORT=$(start_with_platform linux "$BROWSER_MARK" "$FIXTURE/server-linux.log" "$REPO" --port 0)
[ -n "$LINUX_PORT" ] && [ -s "$FIXTURE/cookies/$LINUX_PORT" ] && [ ! -e "$BROWSER_MARK" ]
check "browser: on Linux, with no flag, the server starts and opens no browser" $?
rm -f "$BROWSER_MARK"
LINUX_PORT=$(start_with_platform linux "$BROWSER_MARK" "$FIXTURE/server-linux-browser.log" \
  "$REPO" --port 0 --browser)
[ -n "$LINUX_PORT" ] && [ -s "$FIXTURE/cookies/$LINUX_PORT" ] && grep -q "^http://127.0.0.1:$LINUX_PORT/?token=" "$BROWSER_MARK"
check "browser: on Linux, --browser opens the printed URL" $?
rm -f "$BROWSER_MARK"
MAC_PORT=$(start_with_platform darwin "$BROWSER_MARK" "$FIXTURE/server-mac.log" "$REPO" --port 0)
[ -n "$MAC_PORT" ] && [ -s "$FIXTURE/cookies/$MAC_PORT" ] && grep -q "^http://127.0.0.1:$MAC_PORT/?token=" "$BROWSER_MARK"
check "browser: on macOS, with no flag, the printed URL is opened" $?

# --- g13: the Host check on the page itself and on the printed URL, which
# turns the launch code into a cookie and a page token.

SUITE_LAUNCH_CODE=$(cat "$FIXTURE/launch-codes/$SERVER_PORT")
SUITE_PAGE="$FIXTURE/suite-page.html"
SUITE_PAGE_HEADERS="$FIXTURE/suite-page-headers.txt"
rm -f "$SUITE_PAGE"
STATUS=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" -o "$SUITE_PAGE" -w '%{http_code}' \
  -H "Host: 127.0.0.1:$SERVER_PORT" "http://127.0.0.1:$SERVER_PORT/")
[ "$STATUS" = "200" ] && grep -q "<title>BranchLens</title>" "$SUITE_PAGE"
check "host header: under a loopback Host the page is served (the control for the next two)" $? \
  "got HTTP $STATUS"
rm -f "$SUITE_PAGE"
STATUS=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" -o "$SUITE_PAGE" -w '%{http_code}' \
  -H "Host: evil.example" "http://127.0.0.1:$SERVER_PORT/")
[ "$STATUS" = "403" ] && [ -s "$SUITE_PAGE" ] && ! grep -q "<title>BranchLens</title>" "$SUITE_PAGE"
check "host header: under a foreign Host the page is refused with HTTP 403" $? \
  "got HTTP $STATUS"
rm -f "$SUITE_PAGE_HEADERS"
STATUS=$(curl -s -m 5 -D "$SUITE_PAGE_HEADERS" -o /dev/null -w '%{http_code}' \
  -H "Host: evil.example" "http://127.0.0.1:$SERVER_PORT/?token=$SUITE_LAUNCH_CODE")
[ "$STATUS" = "403" ] && [ -s "$SUITE_PAGE_HEADERS" ] && ! grep -qi '^Set-Cookie' "$SUITE_PAGE_HEADERS" \
  && ! grep -qi '^Location' "$SUITE_PAGE_HEADERS"
check "host header: under a foreign Host the printed URL is refused with HTTP 403 and hands out no cookie or page token" $? \
  "got HTTP $STATUS"

# --- g35: the four traps of the hostile repository above, one at a time:
# plain git springs the trap, then BranchLens serves the same content and no
# program of the repository runs. The repository is unchanged since its own
# checks. The three filters share one program, so the server side checks that
# no program runs at all.

# $1 the trap, $2 the line its program writes, $3 the plain git command
# (split on spaces), $4 what the server is asked for, then its paths.
suite_trap_round() {
  local trap_name="$1"
  local marker_line="$2"
  local git_words="$3"
  local asked_for="$4"
  shift 4
  rm -f "$HOSTILE_MARKER"
  git -C "$HOSTILE_REPO" $git_words > /dev/null 2>&1
  grep -qx "$marker_line" "$HOSTILE_MARKER"
  check "armed traps: plain 'git $git_words' runs the $trap_name" $?
  rm -f "$HOSTILE_MARKER"
  local failed_request=""
  local url_path
  local status
  for url_path in "$@"; do
    status=$(http_get "$HOSTILE_PORT" "$FIXTURE/suite-trap.json" "$url_path")
    if [ "$status" != "200" ]; then
      failed_request="$url_path answered HTTP $status"
    fi
  done
  [ -z "$failed_request" ] && [ ! -e "$HOSTILE_MARKER" ]
  check "armed traps: BranchLens then serves $asked_for and runs no program of the repository" $? \
    "${failed_request:-the marker holds: $(cat "$HOSTILE_MARKER" 2>/dev/null | tr '\n' ' ')}"
}
suite_trap_round "filter hidden behind include.path" PWNED \
  "diff --numstat -- inc.txt" "inc.txt's patch" "/api/file?branch=main&path=inc.txt"
suite_trap_round "filter set in config.worktree" PWNED \
  "diff --numstat -- wt.txt" "wt.txt's patch" "/api/file?branch=main&path=wt.txt"
suite_trap_round "filter whose name holds '='" PWNED \
  "diff --numstat -- eq.txt" "eq.txt's patch" "/api/file?branch=main&path=eq.txt"
suite_trap_round "gpg.program that log.showSignature calls" PWNED-GPG \
  "log -1 --format=%H signed" "the graph and the signed commit" "/api/graph" "/api/diff?commit=$HOSTILE_SIGNED"

# --- g139: a filter set in a linked worktree's own config.worktree
# (.git/worktrees/<name>/config.worktree), which git reads only inside that
# worktree. A scan of the root alone never sees it.

HOSTILE_LINKED="$HOSTILE_ROOT/linked"
printf '#!/bin/sh\necho PWNED-LINKED >> "%s"\ncat\n' "$HOSTILE_MARKER" > "$HOSTILE_ROOT/evil_linked.sh"
chmod +x "$HOSTILE_ROOT/evil_linked.sh"
git -C "$HOSTILE_REPO" worktree add -q -b lw "$HOSTILE_LINKED" main
printf 'line1\n' > "$HOSTILE_LINKED/lw.txt"
printf 'lw.txt filter=lwf\n' >> "$HOSTILE_LINKED/.gitattributes"
git -C "$HOSTILE_LINKED" add -A
git -C "$HOSTILE_LINKED" commit -q -m "a file in the linked worktree"
# Armed only now, and only for the linked worktree.
git -C "$HOSTILE_LINKED" config --worktree filter.lwf.clean "$HOSTILE_ROOT/evil_linked.sh"
printf 'line1\nchanged\n' > "$HOSTILE_LINKED/lw.txt"
[ -z "$(git -C "$HOSTILE_REPO" config --get filter.lwf.clean)" ] && \
  [ "$(git -C "$HOSTILE_LINKED" config --get filter.lwf.clean)" = "$HOSTILE_ROOT/evil_linked.sh" ]
check "linked worktree filter: git resolves it inside the linked worktree and not at the root" $?
# The setup above may have run the include-hidden filter on a racily clean
# file: clear the marker first.
rm -f "$HOSTILE_MARKER"
git -C "$HOSTILE_LINKED" diff --numstat -- lw.txt > /dev/null 2>&1
grep -qx PWNED-LINKED "$HOSTILE_MARKER"
check "linked worktree filter: plain git in the linked worktree runs it" $?
rm -f "$HOSTILE_MARKER"

# A server started with the linked worktree in place: its start-up scan is
# the only one before these reads (no /api/state first).
SUITE_LINKED_LOG="$FIXTURE/server-suite-linked.log"
SUITE_LINKED_PORT=$(start_extra_server "$HOSTILE_REPO" "$SUITE_LINKED_LOG")
check "linked worktree filter: a new server starts on the hostile repository" $?
SUITE_LINKED_BODY="$FIXTURE/suite-linked.json"
expect_get "$SUITE_LINKED_PORT" "$SUITE_LINKED_BODY" "/api/diff?branch=lw" "200" "linked worktree filter: /api/diff for the linked worktree's branch returns HTTP 200"
json_check "linked worktree filter: the diff lists the edited file, so git compared it" "$SUITE_LINKED_BODY" \
  '"lw.txt" in [f["path"] for f in data["files"]]'
expect_get "$SUITE_LINKED_PORT" "$SUITE_LINKED_BODY" "/api/file?branch=lw&path=lw.txt" "200" "linked worktree filter: /api/file for the edited file returns HTTP 200"
json_check "linked worktree filter: the patch shows the edit" "$SUITE_LINKED_BODY" '"+changed" in data["patch"]'
[ ! -e "$HOSTILE_MARKER" ]
check "linked worktree filter: a server started with the worktree in place runs no program of the repository" $? \
  "the marker holds: $(cat "$HOSTILE_MARKER" 2>/dev/null | tr '\n' ' ')"

# The server already running when the worktree appeared, after its next
# /api/state poll.
SUITE_POLL_FAILED=""
for SUITE_PATH in "/api/state" "/api/diff?branch=lw" "/api/file?branch=lw&path=lw.txt"; do
  STATUS=$(http_get "$HOSTILE_PORT" "$SUITE_LINKED_BODY" "$SUITE_PATH")
  if [ "$STATUS" != "200" ]; then
    SUITE_POLL_FAILED="$SUITE_PATH answered HTTP $STATUS"
  fi
done
[ -z "$SUITE_POLL_FAILED" ] && [ ! -e "$HOSTILE_MARKER" ]
check "linked worktree filter: a server running before the worktree appeared runs no program of the repository after its next poll" $? \
  "${SUITE_POLL_FAILED:-the marker holds: $(cat "$HOSTILE_MARKER" 2>/dev/null | tr '\n' ' ')}"

# --- g12: GIT_NO_LAZY_FETCH exists from git 2.45. On an older git the
# server's refusal of a missing blob depends on that git's own messages, so
# the server checks in the "lazy fetch" section below run only when a
# throwaway partial clone shows that this git honours the switch
# (LAZY_FETCH_SWITCH).

LAZYPROBE_SRC="$FIXTURE/suite-lazyprobe-src"
LAZYPROBE_CLONE="$FIXTURE/suite-lazyprobe-clone"
new_repo "$LAZYPROBE_SRC"
git -C "$LAZYPROBE_SRC" config uploadpack.allowFilter true
printf 'one\n' > "$LAZYPROBE_SRC/probe.txt"
git -C "$LAZYPROBE_SRC" add -A
git -C "$LAZYPROBE_SRC" commit -q -m first
printf 'one\ntwo\n' > "$LAZYPROBE_SRC/probe.txt"
git -C "$LAZYPROBE_SRC" commit -q -am second
# No checkout: the clone lacks both blobs.
git clone -q --filter=blob:none --no-checkout "file://$LAZYPROBE_SRC" "$LAZYPROBE_CLONE" 2>/dev/null
lazyprobe_missing() {
  git -C "$LAZYPROBE_CLONE" rev-list --objects --missing=print --all | grep -c '^?'
}
LAZYPROBE_BEFORE=$(lazyprobe_missing)
# LC_ALL=C: git's message is matched in English, whatever the user's locale.
LAZYPROBE_MESSAGE=$(LC_ALL=C GIT_NO_LAZY_FETCH=1 git -C "$LAZYPROBE_CLONE" diff HEAD~1 HEAD 2>&1 > /dev/null)
LAZYPROBE_AFTER=$(lazyprobe_missing)
LAZY_FETCH_SWITCH="ignored"
if [ "$LAZYPROBE_BEFORE" = "2" ] && [ "$LAZYPROBE_AFTER" = "2" ] && \
   printf '%s' "$LAZYPROBE_MESSAGE" | grep -q "lazy fetching disabled"; then
  LAZY_FETCH_SWITCH="honoured"
fi
# On git 2.45 or newer the probe must find the switch honoured, or the lazy
# fetch checks would be skipped silently.
SUITE_GIT_NUMBER=$(git --version | sed -n 's/^git version \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' \
  | awk '{ print $1 * 100 + $2 }')
if [ -n "$SUITE_GIT_NUMBER" ] && [ "$SUITE_GIT_NUMBER" -ge 245 ]; then
  [ "$LAZY_FETCH_SWITCH" = "honoured" ]
  check "lazy fetch probe: git 2.45 or newer is found to honour GIT_NO_LAZY_FETCH, so no lazy fetch check is skipped" $? \
    "missing blobs before $LAZYPROBE_BEFORE, after $LAZYPROBE_AFTER; git said: $LAZYPROBE_MESSAGE"
else
  echo "SKIP: lazy fetch probe: this git is older than 2.45 or does not say its version (the probe found the switch $LAZY_FETCH_SWITCH)"
fi

# --- g143: after a Cancel, a new run is refused while the stopped one may
# still write into the feed, and for at most CANCEL_SETTLE_SECONDS (15).
# In-process: the Cancel's time is moved back instead of waiting.

SUITE_SETTLE=$(python3 - "$PROJECT_DIR" <<'PY'
import sys
import time

from branchlens import server

runner = server.PipelineRunner()
runner.cancelled_run_id = "stopped-run"
stopped_feed = {"run_id": "stopped-run", "running": True}
problems = []
if server.CANCEL_SETTLE_SECONDS != 15:
    problems.append("CANCEL_SETTLE_SECONDS is %r" % server.CANCEL_SETTLE_SECONDS)
runner.cancelled_at = time.monotonic()
if runner.still_stopping(stopped_feed) is not True:
    problems.append("just after the Cancel the stopped run does not block")
if runner.still_stopping({"run_id": "newer-run", "running": True}) is not False:
    problems.append("a newer run in the feed is blocked")
if runner.still_stopping({"run_id": "stopped-run", "running": False}) is not False:
    problems.append("a stopped run whose verdict arrived still blocks")
runner.cancelled_at = time.monotonic() - (server.CANCEL_SETTLE_SECONDS - 1)
if runner.still_stopping(stopped_feed) is not True:
    problems.append("one second before the cap the run no longer blocks")
runner.cancelled_at = time.monotonic() - (server.CANCEL_SETTLE_SECONDS + 1)
if runner.still_stopping(stopped_feed) is not False:
    problems.append("one second past the cap the run still blocks")
print("; ".join(problems))
sys.exit(1 if problems else 0)
PY
)
check "cancel settle: a cancelled run blocks a new one for at most 15 seconds, and only while it is the feed's latest run with no verdict" $? \
  "$SUITE_SETTLE"

# --- g144: three rules of the network reader: a batch whose bytes do not
# add up is refused, an empty list of blobs runs no git at all, and the
# files a commit changed are read first when the source-file cap cuts the
# rest.

SUITE_NET_REPO="$FIXTURE/suite-network"
new_repo "$SUITE_NET_REPO"
printf 'VALUE = 1\n' > "$SUITE_NET_REPO/a.py"
printf 'OTHER = 2\n' > "$SUITE_NET_REPO/z.py"
git -C "$SUITE_NET_REPO" add -A
git -C "$SUITE_NET_REPO" commit -q -m "two files"
# The commit changes z.py only; a.py sorts first.
printf 'import a\n' > "$SUITE_NET_REPO/z.py"
git -C "$SUITE_NET_REPO" commit -q -am "z.py uses a.py"
SUITE_NET_SHA=$(git -C "$SUITE_NET_REPO" rev-parse HEAD)
SUITE_NET_BLOB=$(git -C "$SUITE_NET_REPO" rev-parse HEAD:a.py)
SUITE_NET_JSON="$FIXTURE/suite-network.json"
python3 - "$PROJECT_DIR" "$SUITE_NET_JSON" "$SUITE_NET_REPO" "$SUITE_NET_SHA" "$SUITE_NET_BLOB" <<'PY'
import json
import os
import subprocess
import sys

from branchlens import gitops

output_path, repo, sha, blob = sys.argv[2], os.path.realpath(sys.argv[3]), sys.argv[4], sys.argv[5]
real_size = len(b"VALUE = 1\n")
results = {}

# 1. ls-tree's size and git's output disagree, in both directions.
for label, size in (("larger", real_size + 1), ("smaller", real_size - 1)):
    try:
        gitops.read_one_blob_batch(repo, [{"blob": blob, "size": size}], {})
        results[label] = "no error"
    except gitops.GitError as error:
        results[label] = str(error)
contents = {}
gitops.read_one_blob_batch(repo, [{"blob": blob, "size": real_size}], contents)
results["exact"] = contents[blob].decode("utf-8")

# 2. No blob to read: no process may start ('git show --' would print HEAD).
started = []
real_popen = subprocess.Popen


def recording_popen(*args, **kwargs):
    started.append(args)
    return real_popen(*args, **kwargs)


subprocess.Popen = recording_popen
try:
    results["empty"] = gitops.read_blob_contents(repo, [])
except gitops.GitError as error:
    results["empty"] = "GitError: " + str(error)
subprocess.Popen = real_popen
results["empty_processes"] = len(started)

# 3. A cap of one source file: the one the commit changed is read.
gitops.NETWORK_MAX_SOURCE_FILES = 1
network = gitops.get_network(repo, sha)
results["analyzed"] = [node["path"] for node in network["nodes"] if node["analyzed"]]
results["reasons"] = {}
for node in network["nodes"]:
    results["reasons"][node["path"]] = node["reason"]

handle = open(output_path, "w")
json.dump(results, handle)
handle.close()
PY
check "network reader: the in-process checks ran" $?
json_check "network reader: a batch git prints fewer bytes for than ls-tree said is refused" "$SUITE_NET_JSON" \
  'data["larger"] == "Reading file contents at that commit produced an unexpected amount of data."'
json_check "network reader: a batch git prints more bytes for than ls-tree said is refused" "$SUITE_NET_JSON" \
  'data["smaller"] == "Reading file contents at that commit produced an unexpected amount of data."'
json_check "network reader: with the right size the blob's bytes come back whole (the control)" "$SUITE_NET_JSON" \
  'data["exact"] == "VALUE = 1\n"'
json_check "network reader: an empty list of blobs starts no git process and reads nothing" "$SUITE_NET_JSON" \
  'data["empty"] == {} and data["empty_processes"] == 0'
json_check "network reader: past a cap of one source file, the file the commit changed is the one read" "$SUITE_NET_JSON" \
  'data["analyzed"] == ["z.py"] and data["reasons"]["a.py"] == "graph size limit reached"'

# --- g34: the page's JavaScript under node. node --check parses the whole
# script the server sends, and the three blocks app.html keeps free of the
# DOM (PARSER-, MESSAGE- and LANES-EXTRACT) run with a few assertions.

if command -v node > /dev/null 2>&1; then
  SUITE_FULL_PAGE="$FIXTURE/suite-full-page.html"
  SUITE_SCRIPT="$FIXTURE/suite-page-script.js"
  SUITE_BLOCKS="$FIXTURE/suite-page-blocks.js"
  STATUS=$(http_get "$SERVER_PORT" "$SUITE_FULL_PAGE" "/")
  python3 - "$SUITE_FULL_PAGE" "$SUITE_SCRIPT" "$SUITE_BLOCKS" <<'PY'
import re
import sys

page = open(sys.argv[1], encoding="utf-8").read()
# The page holds one script, and a browser ends it at the first </script>.
script = re.search(r"<script[^>]*>(.*?)</script>", page, re.S).group(1)
handle = open(sys.argv[2], "w", encoding="utf-8")
handle.write(script)
handle.close()
blocks = []
for name in ("PARSER", "MESSAGE", "LANES"):
    start = script.index("/* " + name + "-EXTRACT-BEGIN")
    end = script.index("/* " + name + "-EXTRACT-END */")
    blocks.append(script[start:end])
handle = open(sys.argv[3], "w", encoding="utf-8")
handle.write("\n".join(blocks) + "\n")
handle.close()
PY
  check "page script: the served page's script and its three extractable blocks are found" $? "got HTTP $STATUS"
  node --check "$SUITE_SCRIPT"
  check "page script: node parses the whole script the server sends" $?
  cat >> "$SUITE_BLOCKS" <<'JS'
var assert = require("assert");

// The file header before the first hunk is not content; inside a hunk a line
// reading "--- x" or "+++ x" is a deleted or an added line, and git's
// "\ No newline" marker is no line at all.
var hunks = parseUnifiedDiff("diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n keep\n" +
  "--- x\n+++ x\n\\ No newline at end of file\n@@ -9 +9 @@\n-old\n+new\n");
assert.strictEqual(hunks.length, 2);
assert.deepStrictEqual(hunks[0].lines, [
  { type: "ctx", text: "keep" }, { type: "del", text: "-- x" }, { type: "add", text: "++ x" }
]);
assert.deepStrictEqual([hunks[1].oldStart, hunks[1].oldCount, hunks[1].newStart, hunks[1].newCount],
  [9, 1, 9, 1]);

// One blank line after the subject is git's separator; the author's own
// blank lines after it stay, and lineCount counts what the pane shows.
assert.deepStrictEqual(splitCommitMessage("Subject\n\n\n\nbody after three blank lines\nsecond"),
  { subject: "Subject", body: "\n\nbody after three blank lines\nsecond", lineCount: 5 });
assert.deepStrictEqual(splitCommitMessage("Only a subject"),
  { subject: "Only a subject", body: null, lineCount: 1 });
assert.deepStrictEqual(splitCommitMessage("\nNo subject line"),
  { subject: null, body: "\nNo subject line", lineCount: 2 });

// The side branch committed last, so it is listed first. Lane 0 still goes
// to the default branch's chain; the merge's second parent opens a lane, and
// both side lanes end in the root's dot.
var commits = [
  { sha: "s1", parents: ["b0"], tips: ["side"] },
  { sha: "m2", parents: ["m1", "f1"], tips: ["main"] },
  { sha: "f1", parents: ["b0"], tips: [] },
  { sha: "m1", parents: ["b0"], tips: [] },
  { sha: "b0", parents: [], tips: [] }
];
var trunk = buildTrunkShas(commits, "main", null);
assert.deepStrictEqual(Object.keys(trunk).sort(), ["b0", "m1", "m2"]);
function rowsBySha(layout) {
  var rows = {};
  for (var r = 0; r < layout.rows.length; r++) {
    rows[layout.rows[r].sha] = layout.rows[r];
  }
  return rows;
}
var rows = rowsBySha(assignLanes(commits, trunk));
assert.strictEqual(rows.m2.lane, 0);
assert.strictEqual(rows.m1.lane, 0);
assert.strictEqual(rows.b0.lane, 0);
assert.notStrictEqual(rows.s1.lane, 0);
assert.deepStrictEqual(rows.m2.mergeEdges, [rows.f1.lane]);
assert.deepStrictEqual(rows.b0.closes.slice().sort(), [rows.f1.lane, rows.s1.lane].sort());
// With no trunk reserved, the branch that committed last takes lane 0.
assert.strictEqual(rowsBySha(assignLanes(commits, {})).s1.lane, 0);
JS
  node "$SUITE_BLOCKS"
  check "page script: the diff parser, the message split and the lane assignment behave as the page relies on (run in node)" $?
else
  echo "SKIP: page script: node is not installed, so the page's script was neither parsed nor run"
fi

# Binding must not resolve 127.0.0.1 to a host name: that reverse lookup can
# stall for many seconds on a machine with a slow resolver.
python3 - "$PROJECT_DIR" <<'PY'
import socket
import sys

from branchlens import server


def refuse(_host):
    raise AssertionError("server_bind must not call socket.getfqdn")


socket.getfqdn = refuse
listening = server.create_server(0)
try:
    if listening.server_name != "127.0.0.1" or listening.server_port != listening.server_address[1]:
        sys.exit(1)
finally:
    listening.server_close()
sys.exit(0)
PY
check "server: binding never resolves the loopback address to a host name" $?

# ---------------------------------------------------------------- colour codes
# color.diff=always puts terminal escape codes into the patch text; the page
# then finds no hunk and shows every file as empty.

COLOR_REPO="$FIXTURE/colorrepo"
new_repo "$COLOR_REPO"
set_commit_date "2026-06-01T10:00:00 +0000"
printf 'a\nb\n' > "$COLOR_REPO/f.txt"
git -C "$COLOR_REPO" add -A
git -C "$COLOR_REPO" commit -q -m first
git -C "$COLOR_REPO" checkout -q -b feat
printf 'a\nB\nc\n' > "$COLOR_REPO/f.txt"
git -C "$COLOR_REPO" commit -q -am second
git -C "$COLOR_REPO" config color.ui always
git -C "$COLOR_REPO" config color.diff always
printf 'x\ty\n' > "$COLOR_REPO/untracked.txt"

# Self-check: plain git really does colour the patch here.
git -C "$COLOR_REPO" diff main feat | grep -q "$(printf '\033')"
check "colour: the fixture really does make plain git print escape codes" $?

COLOR_LOG="$FIXTURE/server-color.log"
COLOR_PORT=$(start_extra_server "$COLOR_REPO" "$COLOR_LOG")
check "colour: server starts on the coloured repository" $?
COLOR_BODY="$FIXTURE/color.json"
expect_get "$COLOR_PORT" "$COLOR_BODY" "/api/file?branch=feat&path=f.txt" "200" "colour: /api/file returns HTTP 200"
json_check "colour: the patch carries no escape codes" "$COLOR_BODY" \
  '"\x1b" not in data["patch"] and "@@ -1,2 +1,3 @@" in data["patch"]'
STATUS=$(http_get "$COLOR_PORT" "$COLOR_BODY" "/api/file?branch=feat&path=untracked.txt")
json_check "colour: an untracked file's patch header names the file relative to the worktree" "$COLOR_BODY" \
  'data["patch"].startswith("diff --git a/untracked.txt b/untracked.txt\n") and "\x1b" not in data["patch"]'

# ---------------------------------------------------------------- SHA-256 repositories
# A commit id is 64 hex characters here; every listed commit must be
# selectable.

S256_REPO="$FIXTURE/sha256repo"
git init -q -b main --object-format=sha256 "$S256_REPO"
git -C "$S256_REPO" config user.name "Test User"
git -C "$S256_REPO" config user.email "test@example.com"
set_commit_date "2026-06-01T10:01:00 +0000"
printf 'import os\n' > "$S256_REPO/a.py"
git -C "$S256_REPO" add -A
git -C "$S256_REPO" commit -q -m first
S256_LOG="$FIXTURE/server-sha256.log"
S256_PORT=$(start_extra_server "$S256_REPO" "$S256_LOG")
check "sha256: server starts on a SHA-256 repository" $?
S256_BODY="$FIXTURE/sha256.json"
STATUS=$(http_get "$S256_PORT" "$S256_BODY" "/api/graph")
json_check "sha256: the graph lists 64-character ids" "$S256_BODY" \
  'len(data["commits"]) == 1 and len(data["commits"][0]["sha"]) == 64 and data["limit"] == 150'
S256_SHA=$(git -C "$S256_REPO" rev-parse HEAD)
expect_get "$S256_PORT" "$S256_BODY" "/api/diff?commit=$S256_SHA" "200" "sha256: /api/diff?commit= accepts a 64-character id"
expect_get "$S256_PORT" "$S256_BODY" "/api/file?commit=$S256_SHA&path=a.py" "200" "sha256: /api/file?commit= accepts a 64-character id"
expect_get "$S256_PORT" "$S256_BODY" "/api/network?commit=$S256_SHA" "200" "sha256: /api/network?commit= accepts a 64-character id"
expect_get "$S256_PORT" "$S256_BODY" "/api/diff?commit=$(printf 'a%.0s' $(seq 1 63))" "404" "sha256: an id of the wrong length is still refused"

# ---------------------------------------------------------------- external diff and textconv
# diff.<driver>.command and .textconv are programs git runs while diffing.

EXTDIFF_REPO="$FIXTURE/extdiffrepo"
EXTDIFF_MARKER="$FIXTURE/extdiff-marker"
EXTDIFF_SCRIPT="$FIXTURE/extdiff-hook.sh"
new_repo "$EXTDIFF_REPO"
set_commit_date "2026-06-01T10:02:00 +0000"
printf 'one\n' > "$EXTDIFF_REPO/notes.txt"
printf 'notes.txt diff=evil\n' > "$EXTDIFF_REPO/.gitattributes"
git -C "$EXTDIFF_REPO" add -A
git -C "$EXTDIFF_REPO" commit -q -m first
set_commit_date "2026-06-01T10:03:00 +0000"
printf 'one\ntwo\n' > "$EXTDIFF_REPO/notes.txt"
git -C "$EXTDIFF_REPO" commit -q -am second
printf '#!/bin/sh\ntouch "%s"\ncat "$1" 2>/dev/null\nexit 0\n' "$EXTDIFF_MARKER" > "$EXTDIFF_SCRIPT"
chmod +x "$EXTDIFF_SCRIPT"
git -C "$EXTDIFF_REPO" config diff.evil.command "$EXTDIFF_SCRIPT"
git -C "$EXTDIFF_REPO" config diff.evil.textconv "$EXTDIFF_SCRIPT"
printf 'one\ntwo\nthree\n' > "$EXTDIFF_REPO/notes.txt"

rm -f "$EXTDIFF_MARKER"
git -C "$EXTDIFF_REPO" diff HEAD~1 HEAD > /dev/null 2>&1
[ -e "$EXTDIFF_MARKER" ]
check "external diff: the fixture really does make plain git run a program" $?
rm -f "$EXTDIFF_MARKER"

EXTDIFF_LOG="$FIXTURE/server-extdiff.log"
EXTDIFF_PORT=$(start_extra_server "$EXTDIFF_REPO" "$EXTDIFF_LOG")
check "external diff: server starts on the repository" $?
EXTDIFF_BODY="$FIXTURE/extdiff.json"
EXTDIFF_SHA=$(git -C "$EXTDIFF_REPO" rev-parse HEAD)
expect_get "$EXTDIFF_PORT" "$EXTDIFF_BODY" "/api/file?commit=$EXTDIFF_SHA&path=notes.txt" "200" "external diff: /api/file?commit= returns HTTP 200"
json_check "external diff: the patch is git's own, not the program's output" "$EXTDIFF_BODY" \
  '"+two" in data["patch"]'
expect_get "$EXTDIFF_PORT" "$EXTDIFF_BODY" "/api/file?branch=main&path=notes.txt" "200" "external diff: /api/file?branch= returns HTTP 200"
expect_get "$EXTDIFF_PORT" "$EXTDIFF_BODY" "/api/network?commit=$EXTDIFF_SHA" "200" "external diff: /api/network returns HTTP 200"
[ ! -e "$EXTDIFF_MARKER" ]
check "external diff: BranchLens never ran the repository's diff driver or textconv" $?

# ---------------------------------------------------------------- Host header and CORS
# A web page the user visits must not be able to read the repository through
# DNS rebinding: only loopback Host names are answered.

HOST_BODY="$FIXTURE/host.json"
STATUS=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" -o "$HOST_BODY" -w '%{http_code}' -H "Host: evil.example" \
  "http://127.0.0.1:$SERVER_PORT/api/state")
expect_status "403" "host header: a foreign Host name is refused with HTTP 403"
json_check "host header: exact refusal message" "$HOST_BODY" \
  'data["error"] == "Requests are only accepted from this machine."'
STATUS=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" -o "$HOST_BODY" -w '%{http_code}' -H "Host: localhost:$SERVER_PORT" \
  "http://127.0.0.1:$SERVER_PORT/api/state")
expect_status "200" "host header: localhost with a port is accepted"
STATUS=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" -o "$HOST_BODY" -w '%{http_code}' -H "Host: [::1]:$SERVER_PORT" \
  "http://127.0.0.1:$SERVER_PORT/api/state")
expect_status "200" "host header: an IPv6 loopback literal is accepted"
# The status is kept: a curl that gets no answer gives 000 and fails the check.
HOST_HEADERS="$FIXTURE/host-headers.txt"
rm -f "$HOST_HEADERS"
STATUS=$(curl -s -m 5 -b "$(cookie_for "$SERVER_PORT")" -D "$HOST_HEADERS" -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$SERVER_PORT/api/state")
[ "$STATUS" = "200" ] && ! grep -qi "access-control-allow-origin" "$HOST_HEADERS"
check "host header: no Access-Control-Allow-Origin header is ever sent" $? "got HTTP $STATUS"

# ---------------------------------------------------------------- whitelist forms
# The subcommand whitelist alone would let 'config user.name x' or
# 'worktree add' through: only the read-only shapes may pass.

python3 - "$PROJECT_DIR" <<'PY'
import sys
from branchlens import gitops
refused = [
    ["fetch", "origin"], ["push"], ["commit", "-m", "x"],
    ["config", "user.name", "x"], ["config", "--unset", "a.b"], ["config", "--list"],
    ["worktree", "add", "x"], ["worktree", "remove", "x"], ["worktree", "prune"],
    ["symbolic-ref", "HEAD", "refs/heads/x"], ["symbolic-ref", "-d", "HEAD"],
    ["remote", "add", "x", "/tmp/x"], ["remote", "set-url", "origin", "/tmp/x"],
    ["remote", "remove", "origin"], ["remote", "update"], ["remote", "prune", "origin"],
    ["remote", "get-url", "--all", "--push", "--push", "origin"], ["remote", "get-url", "--all", "-x"],
    ["remote"],
]
allowed = [
    ["config", "--name-only", "--list"], ["config", "--get", "a.b"],
    ["worktree", "list", "--porcelain"], ["symbolic-ref", "refs/remotes/origin/HEAD"],
    ["symbolic-ref", "HEAD"],
    ["remote", "get-url", "--all", "origin"], ["remote", "get-url", "--all", "--push", "origin"],
    ["diff", "-M", "HEAD", "--"], ["status", "--porcelain", "-z", "-uall"],
]
for args in refused:
    try:
        gitops.build_git_command(args, None)
    except gitops.GitError:
        continue
    sys.exit(1)
for args in allowed:
    gitops.build_git_command(args, None)
command = gitops.build_git_command(["show", "HEAD", "--"], None)
sys.exit(0 if command[:6] == ["git", "--no-optional-locks", "show", "--no-ext-diff", "--no-textconv", "--no-color"] else 1)
PY
check "whitelist: writing forms of config, worktree, symbolic-ref and remote are refused; diff and show carry --no-color" $?

# ---------------------------------------------------------------- submodule filters
# git status in a superproject runs a status inside each initialised
# submodule, and that child reads the submodule's own config.

SUBF_ROOT="$FIXTURE/subfilter"
SUBF_SUB="$SUBF_ROOT/sub"
SUBF_SUPER="$SUBF_ROOT/super"
SUBF_MARKER="$FIXTURE/subfilter-marker"
mkdir -p "$SUBF_ROOT"
new_repo "$SUBF_SUB"
set_commit_date "2026-06-01T10:04:00 +0000"
printf 'hello\n' > "$SUBF_SUB/s.txt"
printf '* filter=pwn\n' > "$SUBF_SUB/.gitattributes"
git -C "$SUBF_SUB" add -A
git -C "$SUBF_SUB" commit -q -m sub
new_repo "$SUBF_SUPER"
printf 'top\n' > "$SUBF_SUPER/t.txt"
git -C "$SUBF_SUPER" add -A
git -C "$SUBF_SUPER" commit -q -m top
git -C "$SUBF_SUPER" -c protocol.file.allow=always \
  submodule add -q "$SUBF_SUB" sub > /dev/null 2>&1
git -C "$SUBF_SUPER" commit -q -m "add submodule"
# The filter lives in the submodule's config (.git/modules/sub/config),
# armed only after every commit is made.
git -C "$SUBF_SUPER/sub" config filter.pwn.clean "touch $SUBF_MARKER; cat"
printf 'HELLO\n' > "$SUBF_SUPER/sub/s.txt"

rm -f "$SUBF_MARKER"
git -C "$SUBF_SUPER" status --porcelain > /dev/null 2>&1
[ -e "$SUBF_MARKER" ]
check "submodule filter: the fixture really does make a plain superproject status run the program" $?
rm -f "$SUBF_MARKER"

SUBF_LOG="$FIXTURE/server-subfilter.log"
SUBF_PORT=$(start_extra_server "$SUBF_SUPER" "$SUBF_LOG")
check "submodule filter: server starts on the superproject" $?
SUBF_BODY="$FIXTURE/subfilter.json"
expect_get "$SUBF_PORT" "$SUBF_BODY" "/api/state" "200" "submodule filter: /api/state returns HTTP 200"
json_check "submodule filter: the dirty submodule still shows as uncommitted work" "$SUBF_BODY" \
  'data["branches"][0]["has_uncommitted"] is True'
expect_get "$SUBF_PORT" "$SUBF_BODY" "/api/diff?branch=main" "200" "submodule filter: /api/diff returns HTTP 200"
expect_get "$SUBF_PORT" "$SUBF_BODY" "/api/file?branch=main&path=sub" "200" "submodule filter: /api/file on the submodule path returns HTTP 200"
[ ! -e "$SUBF_MARKER" ]
check "submodule filter: BranchLens never ran the submodule's clean filter" $?

# ---------------------------------------------------------------- audit 2026-10: read-side hardening
# Regression checks for the read-side findings of the 2026-10 audit. Every
# hostile-repository check first proves that its trap fires under plain git,
# then proves that BranchLens does not spring it.

# --- hooks: a diff against the working tree rewrites .git/index to refresh
# stale timestamps, and every index write runs the post-index-change hook,
# here named by the repository's own core.hooksPath.

HOOKS_REPO="$FIXTURE/audit-hooks"
HOOKS_DIR="$FIXTURE/audit-hooks-dir"
HOOKS_MARKER="$FIXTURE/audit-hooks-marker"
mkdir -p "$HOOKS_DIR"
new_repo "$HOOKS_REPO"
set_commit_date "2026-10-01T10:00:00 +0000"
printf 'one\n' > "$HOOKS_REPO/edited.txt"
printf 'two\n' > "$HOOKS_REPO/touched.txt"
git -C "$HOOKS_REPO" add -A
git -C "$HOOKS_REPO" commit -q -m first
printf '#!/bin/sh\ntouch "%s"\n' "$HOOKS_MARKER" > "$HOOKS_DIR/post-index-change"
chmod +x "$HOOKS_DIR/post-index-change"
git -C "$HOOKS_REPO" config core.hooksPath "$HOOKS_DIR"
printf 'one\nmore\n' > "$HOOKS_REPO/edited.txt"
# Same content, another timestamp: git re-reads the file, then refreshes the index.
touch -t 202001011200 "$HOOKS_REPO/touched.txt"
rm -f "$HOOKS_MARKER"
git -C "$HOOKS_REPO" diff HEAD > /dev/null 2>&1
[ -e "$HOOKS_MARKER" ]
check "audit hooks: the fixture really does make a plain git diff run the hook" $?
rm -f "$HOOKS_MARKER"
touch -t 202001011201 "$HOOKS_REPO/touched.txt"

HOOKS_LOG="$FIXTURE/server-audit-hooks.log"
HOOKS_PORT=$(start_extra_server "$HOOKS_REPO" "$HOOKS_LOG")
check "audit hooks: server starts on the repository" $?
HOOKS_BODY="$FIXTURE/audit-hooks.json"
expect_get "$HOOKS_PORT" "$HOOKS_BODY" "/api/diff?branch=main" "200" "audit hooks: /api/diff returns HTTP 200"
json_check "audit hooks: the edited file is listed and the touched one is not" "$HOOKS_BODY" \
  '[f["path"] for f in data["files"]] == ["edited.txt"]'
touch -t 202001011202 "$HOOKS_REPO/touched.txt"
expect_get "$HOOKS_PORT" "$HOOKS_BODY" "/api/file?branch=main&path=edited.txt" "200" "audit hooks: /api/file returns HTTP 200"
json_check "audit hooks: the patch shows the edit" "$HOOKS_BODY" '"+more" in data["patch"]'
[ ! -e "$HOOKS_MARKER" ]
check "audit hooks: BranchLens never ran the repository's post-index-change hook" $?

# --- submodule diffs: with diff.submodule=diff, git diffs inside the
# submodule with a child git that ignores --no-ext-diff and runs the
# submodule's own external diff driver.

SUBDIFF_ROOT="$FIXTURE/audit-subdiff"
SUBDIFF_SRC="$SUBDIFF_ROOT/src"
SUBDIFF_SUPER="$SUBDIFF_ROOT/super"
SUBDIFF_MARKER="$FIXTURE/audit-subdiff-marker"
SUBDIFF_SCRIPT="$SUBDIFF_ROOT/driver.sh"
mkdir -p "$SUBDIFF_ROOT"
printf '#!/bin/sh\ntouch "%s"\necho EXTERNAL-DRIVER-OUTPUT\n' "$SUBDIFF_MARKER" > "$SUBDIFF_SCRIPT"
chmod +x "$SUBDIFF_SCRIPT"
set_commit_date "2026-10-01T10:01:00 +0000"
new_repo "$SUBDIFF_SRC"
printf 's1\n' > "$SUBDIFF_SRC/s.txt"
git -C "$SUBDIFF_SRC" add -A
git -C "$SUBDIFF_SRC" commit -q -m s1
new_repo "$SUBDIFF_SUPER"
printf 'top\n' > "$SUBDIFF_SUPER/top.txt"
git -C "$SUBDIFF_SUPER" add -A
git -C "$SUBDIFF_SUPER" commit -q -m top
git -C "$SUBDIFF_SUPER" -c protocol.file.allow=always \
  submodule add -q "$SUBDIFF_SRC" sub > /dev/null 2>&1
git -C "$SUBDIFF_SUPER" commit -q -m "add the submodule"
printf 's2\n' > "$SUBDIFF_SUPER/sub/s.txt"
git -C "$SUBDIFF_SUPER/sub" -c user.name="Test User" -c user.email="test@example.com" \
  commit -q -am s2
git -C "$SUBDIFF_SUPER" add sub
git -C "$SUBDIFF_SUPER" commit -q -m "move the submodule on"
SUBDIFF_SHA=$(git -C "$SUBDIFF_SUPER" rev-parse HEAD)
# Armed only after every commit; the submodule also gets an uncommitted edit.
git -C "$SUBDIFF_SUPER" config diff.submodule diff
git -C "$SUBDIFF_SUPER/sub" config diff.external "$SUBDIFF_SCRIPT"
printf 's2\ndirty\n' > "$SUBDIFF_SUPER/sub/s.txt"
rm -f "$SUBDIFF_MARKER"
git -C "$SUBDIFF_SUPER" diff --no-ext-diff --no-textconv HEAD~1 HEAD -- sub > /dev/null 2>&1
[ -e "$SUBDIFF_MARKER" ]
check "audit submodule diff: the fixture really does make git run the submodule's driver despite --no-ext-diff" $?
rm -f "$SUBDIFF_MARKER"

SUBDIFF_LOG="$FIXTURE/server-audit-subdiff.log"
SUBDIFF_PORT=$(start_extra_server "$SUBDIFF_SUPER" "$SUBDIFF_LOG")
check "audit submodule diff: server starts on the superproject" $?
SUBDIFF_BODY="$FIXTURE/audit-subdiff.json"
expect_get "$SUBDIFF_PORT" "$SUBDIFF_BODY" "/api/file?commit=$SUBDIFF_SHA&path=sub" "200" "audit submodule diff: /api/file?commit= on the submodule returns HTTP 200"
json_check "audit submodule diff: the committed patch is git's own 'Subproject commit' hunk" "$SUBDIFF_BODY" \
  '"+Subproject commit " in data["patch"] and "EXTERNAL-DRIVER-OUTPUT" not in data["patch"]'
expect_get "$SUBDIFF_PORT" "$SUBDIFF_BODY" "/api/file?branch=main&path=sub" "200" "audit submodule diff: /api/file?branch= on the dirty submodule returns HTTP 200"
json_check "audit submodule diff: the uncommitted patch names the dirty submodule commit" "$SUBDIFF_BODY" \
  '"-dirty" in data["patch"] and "EXTERNAL-DRIVER-OUTPUT" not in data["patch"]'
[ ! -e "$SUBDIFF_MARKER" ]
check "audit submodule diff: BranchLens never ran the submodule's external diff driver" $?

# --- a gitlink nothing configures: git steps into every checked-out gitlink,
# with or without a .gitmodules entry or a submodule.* key, and the child git
# runs that repository's own filters.

GITLINK_SUPER="$FIXTURE/audit-gitlink"
GITLINK_MARKER="$FIXTURE/audit-gitlink-marker"
set_commit_date "2026-10-01T10:02:00 +0000"
new_repo "$GITLINK_SUPER"
printf 'top\n' > "$GITLINK_SUPER/top.txt"
git -C "$GITLINK_SUPER" add -A
git -C "$GITLINK_SUPER" commit -q -m top
new_repo "$GITLINK_SUPER/inner"
printf '* filter=pwn\n' > "$GITLINK_SUPER/inner/.gitattributes"
printf 'inner\n' > "$GITLINK_SUPER/inner/s.txt"
git -C "$GITLINK_SUPER/inner" add -A
git -C "$GITLINK_SUPER/inner" commit -q -m inner
GITLINK_SHA=$(git -C "$GITLINK_SUPER/inner" rev-parse HEAD)
git -C "$GITLINK_SUPER" update-index --add --cacheinfo "160000,$GITLINK_SHA,inner"
git -C "$GITLINK_SUPER" commit -q -m "record the gitlink"
[ ! -e "$GITLINK_SUPER/.gitmodules" ] && \
  ! git -C "$GITLINK_SUPER" config --name-only --list | grep -q '^submodule\.'
check "audit gitlink: the superproject configures no submodule at all" $?
git -C "$GITLINK_SUPER/inner" config filter.pwn.clean "touch $GITLINK_MARKER; cat"
touch -t 202001011200 "$GITLINK_SUPER/inner/s.txt"
rm -f "$GITLINK_MARKER"
git -C "$GITLINK_SUPER" status --porcelain > /dev/null 2>&1
[ -e "$GITLINK_MARKER" ]
check "audit gitlink: the fixture really does make a plain status run the inner repository's filter" $?
rm -f "$GITLINK_MARKER"
touch -t 202001011201 "$GITLINK_SUPER/inner/s.txt"

GITLINK_LOG="$FIXTURE/server-audit-gitlink.log"
GITLINK_PORT=$(start_extra_server "$GITLINK_SUPER" "$GITLINK_LOG")
check "audit gitlink: server starts on the superproject" $?
GITLINK_BODY="$FIXTURE/audit-gitlink.json"
expect_get "$GITLINK_PORT" "$GITLINK_BODY" "/api/state" "200" "audit gitlink: /api/state returns HTTP 200"
expect_get "$GITLINK_PORT" "$GITLINK_BODY" "/api/diff?branch=main" "200" "audit gitlink: /api/diff returns HTTP 200"
[ ! -e "$GITLINK_MARKER" ]
check "audit gitlink: BranchLens never ran the inner repository's clean filter" $?

# --- scan cap: past MAX_HARDENING_SCAN_PATHS the scan used to stop quietly
# while git kept recursing, so a filter one level deeper stayed live. The cap
# is lowered to 3 here; at its real value the fixture would need 200
# repositories.

SCANCAP_SUPER="$FIXTURE/audit-scancap"
SCANCAP_MARKER="$FIXTURE/audit-scancap-marker"
set_commit_date "2026-10-01T10:03:00 +0000"
for SCANCAP_PATH in "$SCANCAP_SUPER" "$SCANCAP_SUPER/one" "$SCANCAP_SUPER/two" "$SCANCAP_SUPER/one/deep"; do
  new_repo "$SCANCAP_PATH"
  printf 'content\n' > "$SCANCAP_PATH/s.txt"
done
printf '* filter=pwn\n' > "$SCANCAP_SUPER/one/deep/.gitattributes"
for SCANCAP_PATH in "$SCANCAP_SUPER/one/deep" "$SCANCAP_SUPER/two"; do
  git -C "$SCANCAP_PATH" add -A
  git -C "$SCANCAP_PATH" commit -q -m inner
done
git -C "$SCANCAP_SUPER/one" add s.txt
git -C "$SCANCAP_SUPER/one" update-index --add --cacheinfo \
  "160000,$(git -C "$SCANCAP_SUPER/one/deep" rev-parse HEAD),deep"
git -C "$SCANCAP_SUPER/one" commit -q -m one
git -C "$SCANCAP_SUPER" add s.txt
git -C "$SCANCAP_SUPER" update-index --add --cacheinfo \
  "160000,$(git -C "$SCANCAP_SUPER/one" rev-parse HEAD),one"
git -C "$SCANCAP_SUPER" update-index --add --cacheinfo \
  "160000,$(git -C "$SCANCAP_SUPER/two" rev-parse HEAD),two"
git -C "$SCANCAP_SUPER" commit -q -m super
git -C "$SCANCAP_SUPER/one/deep" config filter.pwn.clean "touch $SCANCAP_MARKER; cat"
touch -t 202001011200 "$SCANCAP_SUPER/one/deep/s.txt"
rm -f "$SCANCAP_MARKER"
git -C "$SCANCAP_SUPER" status --porcelain > /dev/null 2>&1
[ -e "$SCANCAP_MARKER" ]
check "audit scan cap: the fixture really does make a plain status run the filter two levels down" $?
rm -f "$SCANCAP_MARKER"
touch -t 202001011201 "$SCANCAP_SUPER/one/deep/s.txt"

python3 - "$PROJECT_DIR" "$SCANCAP_SUPER" <<'PY'
import sys
import os
from branchlens import gitops
gitops.MAX_HARDENING_SCAN_PATHS = 3
root = os.path.realpath(sys.argv[2])
try:
    gitops.get_state(root, root)
except gitops.GitError as error:
    sys.exit(0 if "Refusing to open it" in str(error) else 1)
sys.exit(1)
PY
check "audit scan cap: a scan past the cap refuses the repository instead of stopping quietly" $?
SCANCAP_LOG="$FIXTURE/server-audit-scancap.log"
python3 - "$PROJECT_DIR" "$SCANCAP_SUPER" > "$SCANCAP_LOG" 2>&1 <<'PY' &
import sys
from branchlens import gitops
gitops.MAX_HARDENING_SCAN_PATHS = 3
from branchlens import server
sys.argv = ["server.py", sys.argv[2], "--port", "0", "--no-browser"]
server.main()
PY
SCANCAP_PID=$!
echo "$SCANCAP_PID" >> "$FIXTURE/extra-pids"
process_ends "$SCANCAP_PID"
check "audit scan cap: the server refuses to start on the repository" $?
grep -q "Refusing to open it" "$SCANCAP_LOG"
check "audit scan cap: the refusal says why" $?
[ ! -e "$SCANCAP_MARKER" ]
check "audit scan cap: BranchLens never ran the filter past the cap" $?

# --- launched inside a submodule: 'git worktree list' names the submodule's
# checkout by its git dir, where untracked files cannot be read and every
# timestamp in the state token reads "gone".

SUBLAUNCH_ROOT="$FIXTURE/audit-sublaunch"
SUBLAUNCH_SRC="$SUBLAUNCH_ROOT/src"
SUBLAUNCH_SUPER="$SUBLAUNCH_ROOT/super"
SUBLAUNCH_SUB="$SUBLAUNCH_SUPER/sub"
mkdir -p "$SUBLAUNCH_ROOT"
set_commit_date "2026-10-01T10:04:00 +0000"
new_repo "$SUBLAUNCH_SRC"
printf 'one\ntwo\nthree\n' > "$SUBLAUNCH_SRC/one.txt"
git -C "$SUBLAUNCH_SRC" add -A
git -C "$SUBLAUNCH_SRC" commit -q -m one
new_repo "$SUBLAUNCH_SUPER"
printf 'top\n' > "$SUBLAUNCH_SUPER/top.txt"
git -C "$SUBLAUNCH_SUPER" add -A
git -C "$SUBLAUNCH_SUPER" commit -q -m top
git -C "$SUBLAUNCH_SUPER" -c protocol.file.allow=always \
  submodule add -q "$SUBLAUNCH_SRC" sub > /dev/null 2>&1
git -C "$SUBLAUNCH_SUPER" commit -q -m "add the submodule"
printf 'one\ntwo\nthree\nfour\n' > "$SUBLAUNCH_SUB/one.txt"
printf 'new 1\nnew 2\nnew 3\n' > "$SUBLAUNCH_SUB/untracked.txt"
ln -s one.txt "$SUBLAUNCH_SUB/link-to-one"
git -C "$SUBLAUNCH_SUB" worktree list --porcelain | head -n 1 | grep -q '/\.git/modules/sub$'
check "audit submodule launch: git really does list the submodule's checkout as its git dir" $?

SUBLAUNCH_LOG="$FIXTURE/server-audit-sublaunch.log"
SUBLAUNCH_PORT=$(start_extra_server "$SUBLAUNCH_SUB" "$SUBLAUNCH_LOG")
check "audit submodule launch: server starts inside the submodule" $?
SUBLAUNCH_STATE="$FIXTURE/audit-sublaunch-state.json"
SUBLAUNCH_BODY="$FIXTURE/audit-sublaunch.json"
expect_get "$SUBLAUNCH_PORT" "$SUBLAUNCH_STATE" "/api/state" "200" "audit submodule launch: /api/state returns HTTP 200"
json_check "audit submodule launch: main is checked out in the submodule's folder, the current one" "$SUBLAUNCH_STATE" \
  '[(os.path.realpath(b["worktree_path"]), b["is_current"]) for b in data["branches"] if b["name"] == "main"] == [(os.path.realpath(extra), True)]' "$SUBLAUNCH_SUB"
expect_get "$SUBLAUNCH_PORT" "$SUBLAUNCH_BODY" "/api/diff?branch=main" "200" "audit submodule launch: /api/diff returns HTTP 200"
json_check "audit submodule launch: the untracked file has its lines and the symlink is a symlink" "$SUBLAUNCH_BODY" \
  '{f["path"]: (f["entry_kind"], f["adds"]) for f in data["files"]} == {"one.txt": ("file", 1), "untracked.txt": ("file", 3), "link-to-one": ("symlink", 1)}'
expect_get "$SUBLAUNCH_PORT" "$SUBLAUNCH_BODY" "/api/file?branch=main&path=untracked.txt" "200" "audit submodule launch: /api/file for the untracked file returns HTTP 200"
json_check "audit submodule launch: the untracked file's patch holds its lines" "$SUBLAUNCH_BODY" \
  '"+new 2" in data["patch"]'
SUBLAUNCH_TOKEN_A=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["state_token"])' "$SUBLAUNCH_STATE")
printf 'one\ntwo\nthree\nfour\nfive\n' > "$SUBLAUNCH_SUB/one.txt"
http_get "$SUBLAUNCH_PORT" "$SUBLAUNCH_STATE" "/api/state" > /dev/null
json_check "audit submodule launch: a second edit of a modified file moves the state token" "$SUBLAUNCH_STATE" \
  'data["state_token"] != extra' "$SUBLAUNCH_TOKEN_A"

# --- core.worktree: set in the repository's own config, it sends every
# working-tree diff to another directory.

CW_ROOT="$FIXTURE/audit-coreworktree"
CW_EVIL="$CW_ROOT/evil"
CW_VICTIM="$CW_ROOT/victim"
CW_SENTINEL="OUTSIDE-FOLDER-SENTINEL-5318"
mkdir -p "$CW_EVIL/notes" "$CW_VICTIM/notes"
printf '%s\n' "$CW_SENTINEL" > "$CW_VICTIM/notes/private.txt"
printf 'placeholder\n' > "$CW_EVIL/notes/private.txt"
set_commit_date "2026-10-01T10:05:00 +0000"
new_repo "$CW_EVIL"
git -C "$CW_EVIL" add -A
git -C "$CW_EVIL" commit -q -m first
# Relative to the git dir: evil/.git/../../victim is the sibling folder.
git -C "$CW_EVIL" config core.worktree ../../victim
git -C "$CW_EVIL" diff HEAD 2>/dev/null | grep -q "$CW_SENTINEL"
check "audit core.worktree: the fixture really does make a plain git diff read the outside folder" $?

CW_LOG="$FIXTURE/server-audit-coreworktree.log"
python3 -m branchlens "$CW_EVIL" --port 0 --no-browser > "$CW_LOG" 2>&1 &
CW_PID=$!
echo "$CW_PID" >> "$FIXTURE/extra-pids"
process_ends "$CW_PID"
check "audit core.worktree: the server refuses to start on the repository" $?
grep -q "core.worktree" "$CW_LOG"
check "audit core.worktree: the refusal names core.worktree" $?
! grep -q "BranchLens serving" "$CW_LOG"
check "audit core.worktree: the server never serves the repository" $?
python3 - "$PROJECT_DIR" "$CW_EVIL" <<'PY'
import os
import sys
from branchlens import gitops
root = os.path.realpath(sys.argv[2])
try:
    gitops.get_state(root, root)
except gitops.GitError as error:
    sys.exit(0 if "core.worktree" in str(error) else 1)
sys.exit(1)
PY
check "audit core.worktree: every state poll refuses it too" $?

# --- the launching environment: GIT_DIR, the pathspec switches and
# GIT_CONFIG_PARAMETERS used to reach every git call the server made.

ENVLEAK_REPO="$FIXTURE/audit-envleak"
ENVLEAK_OTHER="$FIXTURE/audit-envleak-other"
ENVLEAK_HOOKS="$FIXTURE/audit-envleak-hooks"
ENVLEAK_MARKER="$FIXTURE/audit-envleak-marker"
mkdir -p "$ENVLEAK_HOOKS"
printf '#!/bin/sh\ntouch "%s"\n' "$ENVLEAK_MARKER" > "$ENVLEAK_HOOKS/post-index-change"
chmod +x "$ENVLEAK_HOOKS/post-index-change"
set_commit_date "2026-10-01T10:06:00 +0000"
new_repo "$ENVLEAK_REPO"
printf 'a\n' > "$ENVLEAK_REPO/f2.txt"
printf 'same\n' > "$ENVLEAK_REPO/touched.txt"
git -C "$ENVLEAK_REPO" add -A
git -C "$ENVLEAK_REPO" commit -q -m first
git -C "$ENVLEAK_REPO" branch only-here
new_repo "$ENVLEAK_OTHER"
printf 'x\n' > "$ENVLEAK_OTHER/x.txt"
git -C "$ENVLEAK_OTHER" add -A
git -C "$ENVLEAK_OTHER" commit -q -m other
git -C "$ENVLEAK_OTHER" branch other-only
printf 'a\nb\n' > "$ENVLEAK_REPO/f2.txt"
touch -t 202001011200 "$ENVLEAK_REPO/touched.txt"
GIT_DIR="$ENVLEAK_OTHER/.git" git -C "$ENVLEAK_REPO" for-each-ref --format='%(refname)' refs/heads \
  | grep -q other-only
check "audit environment: GIT_DIR really does send a plain git call to another repository" $?
[ -z "$(GIT_LITERAL_PATHSPECS=1 git -C "$ENVLEAK_REPO" diff HEAD -- ':(top,literal)f2.txt')" ]
check "audit environment: GIT_LITERAL_PATHSPECS really does empty a plain git patch" $?
rm -f "$ENVLEAK_MARKER"
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null \
  GIT_CONFIG_PARAMETERS="'core.hooksPath'='$ENVLEAK_HOOKS'" \
  git -C "$ENVLEAK_REPO" diff HEAD > /dev/null 2>&1
[ -e "$ENVLEAK_MARKER" ]
check "audit environment: GIT_CONFIG_PARAMETERS really does beat the override channel" $?
rm -f "$ENVLEAK_MARKER"
touch -t 202001011201 "$ENVLEAK_REPO/touched.txt"

ENVLEAK_LOG="$FIXTURE/server-audit-envleak.log"
env GIT_DIR="$ENVLEAK_OTHER/.git" GIT_LITERAL_PATHSPECS=1 \
  python3 -m branchlens "$ENVLEAK_REPO" --port 0 --no-browser > "$ENVLEAK_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
ENVLEAK_PORT=$(wait_for_server "$ENVLEAK_LOG")
check "audit environment: server starts with GIT_DIR and GIT_LITERAL_PATHSPECS set" $?
ENVLEAK_BODY="$FIXTURE/audit-envleak.json"
expect_get "$ENVLEAK_PORT" "$ENVLEAK_BODY" "/api/state" "200" "audit environment: /api/state returns HTTP 200"
json_check "audit environment: the branches are those of the repository on the command line" "$ENVLEAK_BODY" \
  'sorted(b["name"] for b in data["branches"]) == ["main", "only-here"]'
expect_get "$ENVLEAK_PORT" "$ENVLEAK_BODY" "/api/file?branch=main&path=f2.txt" "200" "audit environment: /api/file returns HTTP 200"
json_check "audit environment: the patch holds the edit despite GIT_LITERAL_PATHSPECS" "$ENVLEAK_BODY" \
  '"+b" in data["patch"]'

ENVLEAK_LOG2="$FIXTURE/server-audit-envleak2.log"
env GIT_CONFIG_PARAMETERS="'core.hooksPath'='$ENVLEAK_HOOKS'" \
  python3 -m branchlens "$ENVLEAK_REPO" --port 0 --no-browser > "$ENVLEAK_LOG2" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
ENVLEAK_PORT2=$(wait_for_server "$ENVLEAK_LOG2")
check "audit environment: server starts with GIT_CONFIG_PARAMETERS naming a hooks folder" $?
touch -t 202001011202 "$ENVLEAK_REPO/touched.txt"
expect_get "$ENVLEAK_PORT2" "$ENVLEAK_BODY" "/api/diff?branch=main" "200" "audit environment: /api/diff returns HTTP 200"
[ ! -e "$ENVLEAK_MARKER" ]
check "audit environment: a hook named through GIT_CONFIG_PARAMETERS never ran" $?

# --- a partial clone on a git that still fetches lazily (older than 2.45):
# GIT_NO_LAZY_FETCH is taken away here to stand in for one.

LAZYOLD_SRC="$FIXTURE/audit-lazyold-src"
LAZYOLD_CLONE="$FIXTURE/audit-lazyold-clone"
set_commit_date "2026-10-01T10:07:00 +0000"
new_repo "$LAZYOLD_SRC"
git -C "$LAZYOLD_SRC" config uploadpack.allowFilter true
printf 'one\n' > "$LAZYOLD_SRC/big.txt"
git -C "$LAZYOLD_SRC" add -A
git -C "$LAZYOLD_SRC" commit -q -m first
printf 'one\ntwo\n' > "$LAZYOLD_SRC/big.txt"
git -C "$LAZYOLD_SRC" commit -q -am second
git clone -q --filter=blob:none --no-checkout "file://$LAZYOLD_SRC" "$LAZYOLD_CLONE" 2>/dev/null
git -C "$LAZYOLD_CLONE" checkout -q main
lazyold_missing() {
  git -C "$LAZYOLD_CLONE" rev-list --objects --missing=print --all | grep -c '^?'
}
[ "$(lazyold_missing)" = "1" ]
check "audit lazy fetch on old git: the partial clone really lacks the older blob" $?
python3 - "$PROJECT_DIR" "$LAZYOLD_CLONE" <<'PY'
import os
import sys
from branchlens import gitops
original_environment = gitops.hardening_environment


def environment_of_an_older_git():
    environment = original_environment()
    del environment["GIT_NO_LAZY_FETCH"]
    return environment


gitops.hardening_environment = environment_of_an_older_git
root = os.path.realpath(sys.argv[2])
sha = gitops.run_git_text(["rev-parse", "HEAD"], cwd=root).strip()
try:
    gitops.get_commit_file_patch(root, sha, "big.txt")
except gitops.GitError as error:
    sys.exit(0 if "partial clone" in str(error) else 1)
sys.exit(1)
PY
check "audit lazy fetch on old git: the diff is refused with the partial-clone sentence" $?
[ "$(lazyold_missing)" = "1" ]
check "audit lazy fetch on old git: the blob is still missing, so nothing was fetched" $?
git -C "$LAZYOLD_CLONE" diff HEAD~1 HEAD > /dev/null 2>&1
[ "$(lazyold_missing)" = "0" ]
check "audit lazy fetch on old git: the fixture really does make plain git fetch the blob" $?

# --- an untracked file named "-": 'diff --no-index' reads stdin for that one
# name, and git used to inherit the server's stdin.

DASH_REPO="$FIXTURE/audit-dash"
set_commit_date "2026-10-01T10:08:00 +0000"
new_repo "$DASH_REPO"
printf 'tracked\n' > "$DASH_REPO/t.txt"
git -C "$DASH_REPO" add -A
git -C "$DASH_REPO" commit -q -m first
printf 'dash line 1\ndash line 2\n' > "$DASH_REPO/-"
printf 'FROM-STDIN\n' | git -C "$DASH_REPO" diff --no-index -- /dev/null - | grep -q '^+FROM-STDIN'
check "audit dash file: plain git really does read stdin for a file named '-'" $?
DASH_LOG="$FIXTURE/server-audit-dash.log"
printf 'FROM-STDIN\n' | python3 -m branchlens "$DASH_REPO" --port 0 --no-browser > "$DASH_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
DASH_PORT=$(wait_for_server "$DASH_LOG")
check "audit dash file: server starts with something waiting on its stdin" $?
DASH_BODY="$FIXTURE/audit-dash.json"
expect_get "$DASH_PORT" "$DASH_BODY" "/api/diff?branch=main" "200" "audit dash file: /api/diff returns HTTP 200"
json_check "audit dash file: '-' is listed as an untracked file of two lines" "$DASH_BODY" \
  '[(f["adds"], f["untracked"]) for f in data["files"] if f["path"] == "-"] == [(2, True)]'
expect_get "$DASH_PORT" "$DASH_BODY" "/api/file?branch=main&path=-" "200" "audit dash file: /api/file for '-' returns HTTP 200"
json_check "audit dash file: the patch is the file's own content under its own name" "$DASH_BODY" \
  '"+dash line 2" in data["patch"] and "FROM-STDIN" not in data["patch"] and data["patch"].startswith("diff --git a/- b/-\n")'

# --- big patches: the whole output used to be read and decoded before it was
# cut to MAX_PATCH_CHARS, and a first line longer than that left an empty hunk.

BIGPATCH_REPO="$FIXTURE/audit-bigpatch"
set_commit_date "2026-10-01T10:09:00 +0000"
new_repo "$BIGPATCH_REPO"
printf 'small\n' > "$BIGPATCH_REPO/small.txt"
git -C "$BIGPATCH_REPO" add -A
git -C "$BIGPATCH_REPO" commit -q -m first
python3 -c "
import sys
with open(sys.argv[1], 'w') as handle:
    for number in range(60000):
        handle.write('line %05d of a three megabyte untracked file ......\n' % number)
with open(sys.argv[2], 'w') as handle:
    handle.write('x' * 600000 + '\n')
" "$BIGPATCH_REPO/big.txt" "$BIGPATCH_REPO/longline.txt"
BIGPATCH_LOG="$FIXTURE/server-audit-bigpatch.log"
BIGPATCH_PORT=$(start_extra_server "$BIGPATCH_REPO" "$BIGPATCH_LOG")
check "audit big patch: server starts on the repository" $?
BIGPATCH_BODY="$FIXTURE/audit-bigpatch.json"
expect_get "$BIGPATCH_PORT" "$BIGPATCH_BODY" "/api/file?branch=main&path=big.txt" "200" "audit big patch: /api/file for a 3 MB untracked file returns HTTP 200"
json_check "audit big patch: the answer is marked truncated and stays within the limit" "$BIGPATCH_BODY" \
  'data["truncated"] is True and len(data["patch"]) <= 500000 and data["patch"].startswith("diff --git a/big.txt")'
expect_get "$BIGPATCH_PORT" "$BIGPATCH_BODY" "/api/file?branch=main&path=longline.txt" "200" "audit big patch: /api/file for a file with one 600000-character line returns HTTP 200"
json_check "audit big patch: the cut keeps part of the long line under its hunk header" "$BIGPATCH_BODY" \
  'data["truncated"] is True and "@@ -0,0 +1 @@\n+xxxx" in data["patch"] and len(data["patch"]) <= 500000'
python3 - "$PROJECT_DIR" "$BIGPATCH_REPO" <<'PY'
import os
import sys
from branchlens import gitops
root = os.path.realpath(sys.argv[2])
text, output_was_cut = gitops.run_git_text_limited(
    ["diff", "--no-index", "--", "/dev/null", "big.txt"], cwd=root, max_bytes=100000
)
if not output_was_cut or len(text) > 100000 or not text.startswith("diff --git"):
    sys.exit(1)
calls = []
limited_runner = gitops.run_git_text_limited


def recording_runner(args, cwd, max_bytes=4 * gitops.MAX_PATCH_CHARS):
    calls.append(args)
    return limited_runner(args, cwd, max_bytes)


gitops.run_git_text_limited = recording_runner
answer = gitops.get_file_patch(root, "main", "big.txt")
sys.exit(0 if len(calls) == 1 and answer["truncated"] is True else 1)
PY
check "audit big patch: git's output is read only up to the limit, and /api/file goes through that reader" $?

# --- writing options and quiet failures of the git runner.

OUTPUT_TARGET="$FIXTURE/audit-output-written"
rm -f "$OUTPUT_TARGET"
git -C "$BIGPATCH_REPO" diff --output="$OUTPUT_TARGET" HEAD > /dev/null 2>&1
[ -e "$OUTPUT_TARGET" ]
check "audit --output: plain git diff really does write a file with --output" $?
python3 - "$PROJECT_DIR" <<'PY'
import sys
from branchlens import gitops
refused = [
    ["diff", "--output=/tmp/x", "HEAD"],
    ["show", "--output", "/tmp/x", "HEAD"],
    ["log", "--output=/tmp/x", "-n", "1"],
]
allowed = [
    ["diff", "-M", "HEAD", "--", "--output=x"],
    ["log", "--output-indicator-new=>", "-n", "1"],
]
for args in refused:
    try:
        gitops.build_git_command(args, None)
    except gitops.GitError:
        continue
    sys.exit(1)
for args in allowed:
    gitops.build_git_command(args, None)
PY
check "audit --output: diff, show and log refuse --output; a path of that name after '--' still passes" $?
python3 - "$PROJECT_DIR" <<'PY'
import sys
from branchlens import gitops
try:
    gitops.check_git_result("diff", 1, b"", b"error: Could not access 'gone.txt'", False)
    sys.exit(1)
except gitops.GitError:
    pass
gitops.check_git_result("diff", 1, b"diff --git a/x b/x\n", b"warning: line endings", False)
gitops.check_git_result("merge-base", 1, b"", b"", True)
PY
check "audit runner: a diff that prints nothing and exits 1 with an error is a failure, not an empty patch" $?

# --- named pipes: a repository that arrived as a copy or an archive can hold
# a FIFO where git expects a file, and git waits on it forever. Every read
# has a deadline, the server kills its git children when it exits, and the
# files config can name for git are /dev/null.

# Proves that a command hangs under plain git: 0 when it is still running
# after one second (it is then killed), 1 when it finished.
git_hangs() {
  python3 -c '
import subprocess, sys
try:
    subprocess.run(sys.argv[1:], stdin=subprocess.DEVNULL, capture_output=True, timeout=1)
except subprocess.TimeoutExpired:
    sys.exit(0)
sys.exit(1)
' "$@"
}

# Waits up to $2 tenths of a second for 'pgrep -f' to find (find) or stop
# finding (gone) a process whose command line holds $3.
wait_for_pgrep() {
  local wanted="$1"
  local tries="$2"
  local pattern="$3"
  local attempt=0
  while [ "$attempt" -lt "$tries" ]; do
    if pgrep -f -- "$pattern" > /dev/null; then
      [ "$wanted" = "find" ] && return 0
    else
      [ "$wanted" = "gone" ] && return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  return 1
}

make_fifo_repo() {
  git init -q -b main "$1"
  git -C "$1" -c user.name="Test User" -c user.email="test@example.com" \
    commit -q --allow-empty -m empty
  # git cannot store a FIFO, so it is made after the commit.
  mkfifo "$1/.gitignore"
}

FIFO_REPO="$FIXTURE/audit-fifo"
make_fifo_repo "$FIFO_REPO"
git_hangs git -C "$FIFO_REPO" status --porcelain
check "audit FIFO: the fixture really does make a plain git status wait on .gitignore" $?

# A server whose git deadline is 2 s instead of 60, so the check is quick.
SHORT_TIMEOUT_LAUNCHER="$FIXTURE/short-git-timeout-server.py"
cat > "$SHORT_TIMEOUT_LAUNCHER" <<'PY'
import sys
sys.path.insert(0, sys.argv.pop(1))
from branchlens import gitops
gitops.GIT_TIMEOUT_SECONDS = 2
from branchlens import server
server.main()
PY
FIFO_LOG="$FIXTURE/server-audit-fifo.log"
python3 "$SHORT_TIMEOUT_LAUNCHER" "$PROJECT_DIR/src" "$FIFO_REPO" --port 0 --no-browser > "$FIFO_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
FIFO_PORT=$(wait_for_server "$FIFO_LOG")
check "audit FIFO: server starts on the repository" $?
FIFO_BODY="$FIXTURE/audit-fifo.json"
STATUS=$(http_get "$FIFO_PORT" "$FIFO_BODY" "/api/state")
expect_status "200" "audit FIFO: /api/state answers within the git deadline" "$STATUS"
json_check "audit FIFO: the branch says git did not answer, as a status error" "$FIFO_BODY" \
  '[b["status_error"].startswith("git did not answer within 2 s on '"'"'git status'"'"'") for b in data["branches"]] == [True]'
# The page gives up on a poll after 8 s, long before git's deadline, so the
# server remembers a stopped command and answers the next request with its
# error at once, without starting git again.
FIFO_TIMED=$(curl -s -m 5 -b "$(cookie_for "$FIFO_PORT")" -o "$FIFO_BODY" \
  -w '%{http_code} %{time_total}' "http://127.0.0.1:$FIFO_PORT/api/state")
python3 -c 'import sys; code, seconds = sys.argv[1].split(); sys.exit(0 if code == "200" and float(seconds) < 1.0 else 1)' "$FIFO_TIMED"
check "audit FIFO: right after the deadline, /api/state answers at once" $? "$FIFO_TIMED"
json_check "audit FIFO: ...with the remembered status error" "$FIFO_BODY" \
  '[b["status_error"].startswith("git did not answer within 2 s on '"'"'git status'"'"'") for b in data["branches"]] == [True]'
STATUS=$(http_get "$FIFO_PORT" "$FIFO_BODY" "/api/diff?branch=main")
expect_status "400" "audit FIFO: /api/diff answers 400 within the git deadline" "$STATUS"
json_check "audit FIFO: /api/diff says which git command did not answer" "$FIFO_BODY" \
  '"git did not answer within 2 s on " in data["error"]'
wait_for_pgrep gone 30 "$FIFO_REPO status"
check "audit FIFO: the deadline killed the git that waited on the pipe" $?

# Once the deadline has passed again, one request tries git anew; while it
# waits, the others still answer at once and start no git of their own.
sleep 2.5
curl -s -m 5 -b "$(cookie_for "$FIFO_PORT")" -o /dev/null "http://127.0.0.1:$FIFO_PORT/api/state" &
FIFO_RETRY_PID=$!
wait_for_pgrep find 20 "$FIFO_REPO status"
check "audit FIFO: after one more deadline, a request runs git status again" $?
FIFO_TIMED=$(curl -s -m 5 -b "$(cookie_for "$FIFO_PORT")" -o "$FIFO_BODY" \
  -w '%{http_code} %{time_total}' "http://127.0.0.1:$FIFO_PORT/api/state")
python3 -c 'import sys; code, seconds = sys.argv[1].split(); sys.exit(0 if code == "200" and float(seconds) < 1.0 else 1)' "$FIFO_TIMED"
check "audit FIFO: while that git waits, another /api/state answers at once" $? "$FIFO_TIMED"
FIFO_WAITING=$(pgrep -f -- "$FIFO_REPO status" | wc -l | tr -d ' ')
[ "$FIFO_WAITING" = "1" ]
check "audit FIFO: ...and only one git status waits on the pipe" $? "$FIFO_WAITING"
wait "$FIFO_RETRY_PID"

# The page's first state request must outlast the server's git deadline,
# or a stopped git's error could never reach it.
python3 - "$SOURCE_DIR" <<'PY_TIMEOUTS'
import re
import sys
from branchlens import gitops
with open(sys.argv[1] + "/static/app.html", encoding="utf-8") as handle:
    page = handle.read()
first_state_ms = int(re.search(r"var TIMEOUT_FIRST_STATE_MS = (\d+);", page).group(1))
sys.exit(0 if first_state_ms > gitops.GIT_TIMEOUT_SECONDS * 1000 else 1)
PY_TIMEOUTS
check "audit FIFO: the page's first state request waits longer than GIT_TIMEOUT_SECONDS" $?

# Default deadline: stopping the server must stop the git it left waiting.
FIFO_LEAK_REPO="$FIXTURE/audit-fifo-leak"
make_fifo_repo "$FIFO_LEAK_REPO"
FIFO_LEAK_LOG="$FIXTURE/server-audit-fifo-leak.log"
python3 -m branchlens "$FIFO_LEAK_REPO" --port 0 --no-browser > "$FIFO_LEAK_LOG" 2>&1 &
FIFO_LEAK_PID=$!
echo "$FIFO_LEAK_PID" >> "$FIXTURE/extra-pids"
FIFO_LEAK_PORT=$(wait_for_server "$FIFO_LEAK_LOG")
check "audit FIFO leak: server starts on the repository" $?
curl -s -m 1 -b "$(cookie_for "$FIFO_LEAK_PORT")" -o /dev/null \
  "http://127.0.0.1:$FIFO_LEAK_PORT/api/state"
wait_for_pgrep find 50 "$FIFO_LEAK_REPO status"
check "audit FIFO leak: a git status is left waiting on the pipe while the server runs" $?
kill "$FIFO_LEAK_PID" 2>/dev/null
process_ends "$FIFO_LEAK_PID"
check "audit FIFO leak: the server stops on SIGTERM" $?
wait_for_pgrep gone 20 "$FIFO_LEAK_REPO status"
check "audit FIFO leak: no git child outlives the server" $?

# FIFOs named by config: each key makes plain git wait, in a different command.
CFGFIFO_REPO="$FIXTURE/audit-cfgfifo"
CFGFIFO_PIPE="$FIXTURE/audit-cfgfifo-pipe"
git init -q -b main "$CFGFIFO_REPO"
printf 'one\n' > "$CFGFIFO_REPO/a.txt"
git -C "$CFGFIFO_REPO" add -A
git -C "$CFGFIFO_REPO" -c user.name="Test User" -c user.email="test@example.com" \
  commit -q -m first
printf 'one\ntwo\n' > "$CFGFIFO_REPO/a.txt"
mkfifo "$CFGFIFO_PIPE"
git -C "$CFGFIFO_REPO" config core.excludesFile "$CFGFIFO_PIPE"
git_hangs git -C "$CFGFIFO_REPO" status --porcelain
CFGFIFO_TRAPS=$?
git -C "$CFGFIFO_REPO" config --unset core.excludesFile
git -C "$CFGFIFO_REPO" config core.attributesFile "$CFGFIFO_PIPE"
git_hangs git -C "$CFGFIFO_REPO" diff HEAD
CFGFIFO_TRAPS=$((CFGFIFO_TRAPS + $?))
git -C "$CFGFIFO_REPO" config --unset core.attributesFile
git -C "$CFGFIFO_REPO" config mailmap.file "$CFGFIFO_PIPE"
git_hangs git -C "$CFGFIFO_REPO" log -1 --format=%an
CFGFIFO_TRAPS=$((CFGFIFO_TRAPS + $?))
[ "$CFGFIFO_TRAPS" -eq 0 ]
check "audit config FIFO: core.excludesFile, core.attributesFile and mailmap.file each make plain git wait" $?
git -C "$CFGFIFO_REPO" config core.excludesFile "$CFGFIFO_PIPE"
git -C "$CFGFIFO_REPO" config core.attributesFile "$CFGFIFO_PIPE"
CFGFIFO_LOG="$FIXTURE/server-audit-cfgfifo.log"
CFGFIFO_PORT=$(start_extra_server "$CFGFIFO_REPO" "$CFGFIFO_LOG")
check "audit config FIFO: server starts on the repository" $?
CFGFIFO_BODY="$FIXTURE/audit-cfgfifo.json"
STATUS=$(http_get "$CFGFIFO_PORT" "$CFGFIFO_BODY" "/api/state")
expect_status "200" "audit config FIFO: /api/state answers at once" "$STATUS"
json_check "audit config FIFO: the edit is seen and git reported no error" "$CFGFIFO_BODY" \
  '[(b["has_uncommitted"], b["status_error"]) for b in data["branches"]] == [(True, None)]'
STATUS=$(http_get "$CFGFIFO_PORT" "$CFGFIFO_BODY" "/api/file?branch=main&path=a.txt")
expect_status "200" "audit config FIFO: /api/file on the edited file answers at once" "$STATUS"
json_check "audit config FIFO: the patch shows the edit" "$CFGFIFO_BODY" '"+two" in data["patch"]'
STATUS=$(http_get "$CFGFIFO_PORT" "$CFGFIFO_BODY" "/api/graph")
expect_status "200" "audit config FIFO: /api/graph answers at once" "$STATUS"

# Every way gitops.py starts git keeps the deadline. An include.path naming
# a FIFO makes every git command wait, before it does anything else.
INCFIFO_REPO="$FIXTURE/audit-incfifo"
git init -q -b main "$INCFIFO_REPO"
git -C "$INCFIFO_REPO" -c user.name="Test User" -c user.email="test@example.com" \
  commit -q --allow-empty -m empty
INCFIFO_SHA=$(git -C "$INCFIFO_REPO" rev-parse HEAD)
mkfifo "$FIXTURE/audit-incfifo-pipe"
git -C "$INCFIFO_REPO" config include.path "$FIXTURE/audit-incfifo-pipe"
git_hangs git -C "$INCFIFO_REPO" rev-parse HEAD
check "audit include FIFO: the fixture really does make every plain git command wait" $?
python3 - "$PROJECT_DIR" "$INCFIFO_REPO" "$INCFIFO_SHA" <<'PY'
import signal
import sys
import time
from branchlens import gitops
gitops.GIT_TIMEOUT_SECONDS = 1
# Without a deadline these calls never return: fail instead of hanging.
signal.alarm(30)
repo, sha = sys.argv[2], sys.argv[3]
calls = [
    ("run_git", lambda: gitops.run_git(["rev-parse", "HEAD"], cwd=repo)),
    ("run_git_text_limited", lambda: gitops.run_git_text_limited(["log", "-1"], repo)),
    ("run_git_exit_code", lambda: gitops.is_ancestor_commit(repo, sha, sha)),
    ("verify_config_overrides_work", lambda: gitops.verify_config_overrides_work(repo)),
    ("start_network_git", lambda: gitops.list_tree_files(repo, sha)),
]
wrong = []
for name, call in calls:
    started = time.monotonic()
    try:
        call()
        wrong.append(name + ": no error")
    except gitops.GitError as error:
        if not str(error).startswith("git did not answer within 1 s on "):
            wrong.append(name + ": " + str(error))
    if time.monotonic() - started > 5:
        wrong.append(name + ": too slow")
if wrong:
    print("  " + "; ".join(wrong))
sys.exit(1 if wrong else 0)
PY
check "audit include FIFO: run_git, the size-limited runner, the exit-code runner, the startup probe and the network reader all stop at the deadline" $?

# --- submodule ignore = all: a tracked .gitmodules setting hid the gitlink's
# move from the diff and the status, while Push still sent it.

SUBIGN_ROOT="$FIXTURE/audit-subignore"
SUBIGN_SRC="$SUBIGN_ROOT/src"
SUBIGN_SUPER="$SUBIGN_ROOT/super"
mkdir -p "$SUBIGN_ROOT"
set_commit_date "2026-10-01T10:02:00 +0000"
git init -q -b main "$SUBIGN_SRC"
git -C "$SUBIGN_SRC" -c user.name="Test User" -c user.email="test@example.com" \
  commit -q --allow-empty -m s1
new_repo "$SUBIGN_SUPER"
printf 'top\n' > "$SUBIGN_SUPER/top.txt"
git -C "$SUBIGN_SUPER" add -A
git -C "$SUBIGN_SUPER" commit -q -m top
git -C "$SUBIGN_SUPER" -c protocol.file.allow=always \
  submodule add -q "$SUBIGN_SRC" lib > /dev/null 2>&1
git -C "$SUBIGN_SUPER" config -f .gitmodules submodule.lib.ignore all
git -C "$SUBIGN_SUPER" add .gitmodules
git -C "$SUBIGN_SUPER" commit -q -m "add the submodule, ignored"
git -C "$SUBIGN_SUPER/lib" -c user.name="Test User" -c user.email="test@example.com" \
  commit -q --allow-empty -m s2
printf 'top\nmore\n' > "$SUBIGN_SUPER/top.txt"
# git 2.54 and later skip a submodule set to ignore = all in 'git add'
# unless -f is given and its path is named.
git -C "$SUBIGN_SUPER" add -f top.txt lib
git -C "$SUBIGN_SUPER" commit -q -m "move the submodule on"
SUBIGN_SHA=$(git -C "$SUBIGN_SUPER" rev-parse HEAD)
git -C "$SUBIGN_SUPER/lib" -c user.name="Test User" -c user.email="test@example.com" \
  commit -q --allow-empty -m s3
# The commit moves the gitlink, the submodule has moved on since, and plain
# git diff and status show neither move.
[ "$(git -C "$SUBIGN_SUPER" rev-parse HEAD~1:lib)" != "$(git -C "$SUBIGN_SUPER" rev-parse HEAD:lib)" ] && \
  [ "$(git -C "$SUBIGN_SUPER" rev-parse HEAD:lib)" != "$(git -C "$SUBIGN_SUPER/lib" rev-parse HEAD)" ] && \
  [ "$(git -C "$SUBIGN_SUPER" diff --name-only HEAD~1 HEAD)" = "top.txt" ] && \
  [ -z "$(git -C "$SUBIGN_SUPER" status --porcelain)" ]
check "audit submodule ignore: the fixture really does hold both moves and hide them from plain git diff and status" $?
SUBIGN_LOG="$FIXTURE/server-audit-subignore.log"
SUBIGN_PORT=$(start_extra_server "$SUBIGN_SUPER" "$SUBIGN_LOG")
check "audit submodule ignore: server starts on the superproject" $?
SUBIGN_BODY="$FIXTURE/audit-subignore.json"
expect_get "$SUBIGN_PORT" "$SUBIGN_BODY" "/api/diff?commit=$SUBIGN_SHA" "200" "audit submodule ignore: /api/diff?commit= returns HTTP 200"
json_check "audit submodule ignore: the commit's diff lists the gitlink move" "$SUBIGN_BODY" \
  'sorted(f["path"] for f in data["files"]) == ["lib", "top.txt"]'
STATUS=$(http_get "$SUBIGN_PORT" "$SUBIGN_BODY" "/api/state")
json_check "audit submodule ignore: the uncommitted move counts as an edit" "$SUBIGN_BODY" \
  '[b["has_uncommitted"] for b in data["branches"] if b["name"] == "main"] == [True]'
expect_get "$SUBIGN_PORT" "$SUBIGN_BODY" "/api/diff?branch=main" "200" "audit submodule ignore: /api/diff?branch= returns HTTP 200"
json_check "audit submodule ignore: the branch's diff lists the uncommitted gitlink move" "$SUBIGN_BODY" \
  '"lib" in [f["path"] for f in data["files"]]'

# --- launched through a symlink into a subdirectory: git answers relative to
# the physical folder, so joining that answer to the symlinked path named
# whatever repository encloses the symlink.

SYMLAUNCH_ROOT="$FIXTURE/audit-symlaunch"
SYMLAUNCH_OUTER="$SYMLAUNCH_ROOT/outer"
SYMLAUNCH_INNER="$SYMLAUNCH_ROOT/data/proj"
SYMLAUNCH_LINK="$SYMLAUNCH_OUTER/work/link"
mkdir -p "$SYMLAUNCH_OUTER/work" "$SYMLAUNCH_INNER/src/sub"
set_commit_date "2026-10-01T10:10:00 +0000"
for SYMLAUNCH_REPO in "$SYMLAUNCH_OUTER" "$SYMLAUNCH_INNER"; do
  new_repo "$SYMLAUNCH_REPO"
done
printf 'outer\n' > "$SYMLAUNCH_OUTER/o.txt"
printf 'inner\n' > "$SYMLAUNCH_INNER/src/sub/i.txt"
for SYMLAUNCH_REPO in "$SYMLAUNCH_OUTER" "$SYMLAUNCH_INNER"; do
  git -C "$SYMLAUNCH_REPO" add -A
  git -C "$SYMLAUNCH_REPO" commit -q -m first
done
git -C "$SYMLAUNCH_OUTER" branch outer-only
git -C "$SYMLAUNCH_INNER" branch inner-only
ln -s "$SYMLAUNCH_INNER/src/sub" "$SYMLAUNCH_LINK"
SYMLAUNCH_RAW=$(git -C "$SYMLAUNCH_LINK" rev-parse --git-common-dir)
python3 -c '
import os, sys
joined = os.path.abspath(os.path.join(sys.argv[1], sys.argv[2]))
sys.exit(0 if os.path.realpath(os.path.dirname(joined)) == os.path.realpath(sys.argv[3]) else 1)
' "$SYMLAUNCH_LINK" "$SYMLAUNCH_RAW" "$SYMLAUNCH_OUTER"
check "audit symlinked launch: joining git's relative answer to the symlinked path really does name the outer repository" $?
python3 - "$PROJECT_DIR" "$SYMLAUNCH_LINK" "$SYMLAUNCH_INNER" <<'PY'
import os
import sys
from branchlens import gitops
main_root, launch_root = gitops.find_repo_root(sys.argv[2])
inner = os.path.realpath(sys.argv[3])
sys.exit(0 if main_root == inner and launch_root == inner else 1)
PY
check "audit symlinked launch: find_repo_root resolves the repository the symlink points into" $?
SYMLAUNCH_LOG="$FIXTURE/server-audit-symlaunch.log"
SYMLAUNCH_PORT=$(start_extra_server "$SYMLAUNCH_LINK" "$SYMLAUNCH_LOG")
check "audit symlinked launch: server starts through the symlink" $?
SYMLAUNCH_BODY="$FIXTURE/audit-symlaunch.json"
http_get "$SYMLAUNCH_PORT" "$SYMLAUNCH_BODY" "/api/state" > /dev/null
json_check "audit symlinked launch: the branches shown are the inner repository's" "$SYMLAUNCH_BODY" \
  'sorted(b["name"] for b in data["branches"]) == ["inner-only", "main"]'

# --- worktree listing: a worktree path holding a newline, and a worktree on a
# branch that has no commit yet.

WTLIST_REPO="$FIXTURE/audit-wtlist"
WTLIST_NEWLINE="$FIXTURE/audit-nl"$'\n'"worktree"
WTLIST_ORPHAN="$FIXTURE/audit-orphan-wt"
set_commit_date "2026-10-01T10:11:00 +0000"
new_repo "$WTLIST_REPO"
printf 'base\n' > "$WTLIST_REPO/base.txt"
git -C "$WTLIST_REPO" add -A
git -C "$WTLIST_REPO" commit -q -m first
git -C "$WTLIST_REPO" worktree add -q -b nl-branch "$WTLIST_NEWLINE"
printf 'edit\n' > "$WTLIST_NEWLINE/new.txt"
git -C "$WTLIST_REPO" worktree add -q --detach "$WTLIST_ORPHAN"
git -C "$WTLIST_ORPHAN" checkout -q --orphan fresh-start
printf 'first file\n' > "$WTLIST_ORPHAN/first.txt"
git -C "$WTLIST_REPO" worktree list --porcelain | grep -q '/audit-nl$'
check "audit worktree listing: the newline form of the listing really does cut the path in two" $?
git -C "$WTLIST_REPO" worktree list --porcelain | grep -q '^branch refs/heads/fresh-start$' && \
  ! git -C "$WTLIST_REPO" rev-parse -q --verify refs/heads/fresh-start > /dev/null
check "audit worktree listing: git really does list a worktree on a branch with no commit yet" $?
WTLIST_LOG="$FIXTURE/server-audit-wtlist.log"
WTLIST_PORT=$(start_extra_server "$WTLIST_REPO" "$WTLIST_LOG")
check "audit worktree listing: server starts on the repository" $?
WTLIST_BODY="$FIXTURE/audit-wtlist.json"
expect_get "$WTLIST_PORT" "$WTLIST_BODY" "/api/state" "200" "audit worktree listing: /api/state returns HTTP 200"
json_check "audit worktree listing: the branch keeps the worktree whose path holds a newline" "$WTLIST_BODY" \
  '[(os.path.realpath(b["worktree_path"]), b["has_uncommitted"]) for b in data["branches"] if b["name"] == "nl-branch"] == [(os.path.realpath(extra), True)]' "$WTLIST_NEWLINE"
json_check "audit worktree listing: the worktree on a branch with no commit is listed with its edits" "$WTLIST_BODY" \
  '[(os.path.realpath(w["path"]), w["has_uncommitted"]) for w in data["detached_worktrees"]] == [(os.path.realpath(extra), True)]' "$WTLIST_ORPHAN"

python3 - "$PROJECT_DIR" "$WTLIST_REPO" <<'PY'
import os
import sys
from branchlens import gitops
root = os.path.realpath(sys.argv[2])
real_run_git = gitops.run_git


def run_git_of_an_older_version(args, cwd=None, allow_exit_code_1=False):
    if args[:2] == ["worktree", "list"] and "-z" in args:
        raise gitops.GitError("git worktree failed: error: unknown switch `z'")
    return real_run_git(args, cwd=cwd, allow_exit_code_1=allow_exit_code_1)


gitops.run_git = run_git_of_an_older_version
branch_to_worktree, paths, raw = gitops.get_worktrees(root)
sys.exit(0 if branch_to_worktree.get("main") == root and gitops._WORKTREE_LIST_TAKES_Z is False else 1)
PY
check "audit worktree listing: a git without 'worktree list -z' falls back to the newline form" $?

# --- caches: ahead/behind counts are stored under the two commit ids they
# name, and the untracked line-count cache must survive a listing larger
# than its bound.

CACHES_REPO="$FIXTURE/audit-caches"
set_commit_date "2026-10-01T10:12:00 +0000"
new_repo "$CACHES_REPO"
printf 'base\n' > "$CACHES_REPO/base.txt"
git -C "$CACHES_REPO" add -A
git -C "$CACHES_REPO" commit -q -m base
git -C "$CACHES_REPO" checkout -q -b feat
printf 'one\n' > "$CACHES_REPO/feat.txt"
git -C "$CACHES_REPO" add -A
git -C "$CACHES_REPO" commit -q -m "feat 1"
CACHES_MAIN_SHA=$(git -C "$CACHES_REPO" rev-parse main)
CACHES_FEAT1_SHA=$(git -C "$CACHES_REPO" rev-parse feat)
printf 'one\ntwo\n' > "$CACHES_REPO/feat.txt"
git -C "$CACHES_REPO" commit -q -am "feat 2"
for CACHES_NUMBER in 1 2 3 4 5 6 7 8; do
  printf 'untracked %s\n' "$CACHES_NUMBER" > "$CACHES_REPO/untracked-$CACHES_NUMBER.txt"
done
python3 - "$PROJECT_DIR" "$CACHES_REPO" "$CACHES_MAIN_SHA" "$CACHES_FEAT1_SHA" <<'PY'
import os
import sys
from branchlens import gitops
root = os.path.realpath(sys.argv[2])
# feat has moved on to "feat 2" since its id was read as "feat 1".
counts = gitops.count_ahead_behind(root, "refs/heads/main", "feat", sys.argv[3], sys.argv[4])
sys.exit(0 if counts == (1, 0) and gitops._AHEAD_BEHIND_CACHE[(sys.argv[3], sys.argv[4])] == (1, 0) else 1)
PY
check "audit caches: ahead/behind is counted between the commit ids it is cached under" $?
python3 - "$PROJECT_DIR" "$CACHES_REPO" <<'PY'
import os
import sys
from branchlens import gitops
root = os.path.realpath(sys.argv[2])
gitops.MAX_UNTRACKED_COUNT_CACHE = 5
files_read = []
real_read_line_counts = gitops.read_line_counts


def counting_read_line_counts(absolute_path, size):
    files_read.append(absolute_path)
    return real_read_line_counts(absolute_path, size)


gitops.read_line_counts = counting_read_line_counts
context = gitops.build_diff_context(root, "feat")
gitops.collect_changed_files(context)
first_pass = len(files_read)
gitops.collect_changed_files(context)
second_pass = len(files_read) - first_pass
sys.exit(0 if context["mode"] == "worktree" and first_pass == 8 and second_pass == 0 else 1)
PY
check "audit caches: a listing larger than the count cache's bound is read from the cache the second time" $?

# --- the commit graph: 160 commits on main after the fork and 3 newer-dated
# ones on feature. In topo order the 150-commit window held no feature commit
# at all. The tree also holds a file at refs/remotes/origin/main, which made
# the clone's graph listing fail as an ambiguous argument.

GRAPHFIX_REPO="$FIXTURE/audit-graph"
GRAPHFIX_CLONE="$FIXTURE/audit-graph-clone"
new_repo "$GRAPHFIX_REPO"
python3 -c '
import datetime
import sys
utc = datetime.timezone.utc


def epoch(year, month, day, hour=0):
    return int(datetime.datetime(year, month, day, hour, tzinfo=utc).timestamp())


def commit(branch, message, committed, authored=None, parent=None, files=None):
    if authored is None:
        authored = committed
    text = message.encode("utf-8")
    lines = ["commit refs/heads/" + branch,
             "author Test User <test@example.com> %d +0000" % authored,
             "committer Test User <test@example.com> %d +0000" % committed,
             "data %d" % len(text), message]
    if parent is not None:
        lines.append("from " + parent)
    for line in files or []:
        lines.append(line)
    return "\n".join(lines) + "\n\n"


stream = "blob\nmark :1\ndata 10\nnot a ref\n\n"
stream += commit("main", "base", epoch(2026, 8, 1), files=["M 100644 :1 refs/remotes/origin/main"]).replace(
    "commit refs/heads/main\n", "commit refs/heads/main\nmark :2\n", 1)
for number in range(1, 161):
    stream += commit("main", "main %d" % number, epoch(2026, 8, 2) + number * 8 * 3600)
for number in (1, 2, 3):
    authored = None
    if number == 3:
        authored = epoch(2026, 1, 1)
    parent = ":2" if number == 1 else None
    stream += commit("feature", "feature %d" % number, epoch(2026, 9, 1, number), authored, parent)
sys.stdout.write(stream)
' | git -C "$GRAPHFIX_REPO" fast-import --quiet
git -C "$GRAPHFIX_REPO" reset -q --hard main
GRAPHFIX_FEATURE_SHA=$(git -C "$GRAPHFIX_REPO" rev-parse feature)
[ "$(git -C "$GRAPHFIX_REPO" log --branches --topo-order -n 150 --format=%s | grep -c '^feature')" = "0" ]
check "audit graph: git's topo order really does leave every feature commit out of the newest 150" $?
GRAPHFIX_LOG="$FIXTURE/server-audit-graph.log"
GRAPHFIX_PORT=$(start_extra_server "$GRAPHFIX_REPO" "$GRAPHFIX_LOG")
check "audit graph: server starts on the repository" $?
GRAPHFIX_BODY="$FIXTURE/audit-graph.json"
GRAPHFIX_STATE="$FIXTURE/audit-graph-state.json"
expect_get "$GRAPHFIX_PORT" "$GRAPHFIX_BODY" "/api/graph" "200" "audit graph: /api/graph returns HTTP 200"
json_check "audit graph: the newest commits include all three feature commits" "$GRAPHFIX_BODY" \
  'sorted(c["subject"] for c in data["commits"] if c["subject"].startswith("feature")) == ["feature 1", "feature 2", "feature 3"] and len(data["commits"]) == 150'
json_check "audit graph: the date shown is the committer date, not the author date" "$GRAPHFIX_BODY" \
  '[c["date"][:19] for c in data["commits"] if c["sha"] == extra] == ["2026-09-01T03:00:00"]' "$GRAPHFIX_FEATURE_SHA"
http_get "$GRAPHFIX_PORT" "$GRAPHFIX_STATE" "/api/state" > /dev/null
python3 -c '
import json, sys
graph = json.load(open(sys.argv[1]))
state = json.load(open(sys.argv[2]))
graph_date = [c["date"] for c in graph["commits"] if c["sha"] == sys.argv[3]]
branch_date = [b["last_commit_date"] for b in state["branches"] if b["name"] == "feature"]
sys.exit(0 if len(graph_date) == 1 and graph_date == branch_date else 1)
' "$GRAPHFIX_BODY" "$GRAPHFIX_STATE" "$GRAPHFIX_FEATURE_SHA"
check "audit graph: the tree and the branch list give the feature tip the same date" $?
expect_get "$GRAPHFIX_PORT" "$GRAPHFIX_BODY" "/api/diff?commit=$GRAPHFIX_FEATURE_SHA" "200" "audit graph: a recent feature commit is accepted in commit mode"

git clone -q "$GRAPHFIX_REPO" "$GRAPHFIX_CLONE"
! git -C "$GRAPHFIX_CLONE" log --branches refs/remotes/origin/main -n 1 > /dev/null 2>&1
check "audit graph: in the clone, a ref given without '--' really is ambiguous with the tracked file" $?
GRAPHFIX_CLONE_LOG="$FIXTURE/server-audit-graph-clone.log"
GRAPHFIX_CLONE_PORT=$(start_extra_server "$GRAPHFIX_CLONE" "$GRAPHFIX_CLONE_LOG")
check "audit graph: server starts on the clone" $?
expect_get "$GRAPHFIX_CLONE_PORT" "$GRAPHFIX_BODY" "/api/graph" "200" "audit graph: /api/graph on the clone returns HTTP 200 despite the file named like the online ref"
json_check "audit graph: the clone's graph is complete up to the limit and says it was cut" "$GRAPHFIX_BODY" \
  'len(data["commits"]) == 150 and data["truncated"] is True and data["online_tip_sha"] is not None'

# --- root commits: log.showRoot=false empties 'git show' for a root commit
# unless --root is given.

SHOWROOT_REPO="$FIXTURE/audit-showroot"
set_commit_date "2026-10-01T10:13:00 +0000"
new_repo "$SHOWROOT_REPO"
printf 'alpha\n' > "$SHOWROOT_REPO/a.txt"
printf 'beta\n' > "$SHOWROOT_REPO/b.txt"
git -C "$SHOWROOT_REPO" add -A
git -C "$SHOWROOT_REPO" commit -q -m "root commit"
git -C "$SHOWROOT_REPO" config log.showRoot false
SHOWROOT_SHA=$(git -C "$SHOWROOT_REPO" rev-parse HEAD)
[ -z "$(git -C "$SHOWROOT_REPO" show --format= --name-status "$SHOWROOT_SHA" --)" ]
check "audit root commit: log.showRoot=false really does empty a plain git show of the root commit" $?
SHOWROOT_LOG="$FIXTURE/server-audit-showroot.log"
SHOWROOT_PORT=$(start_extra_server "$SHOWROOT_REPO" "$SHOWROOT_LOG")
check "audit root commit: server starts on the repository" $?
SHOWROOT_BODY="$FIXTURE/audit-showroot.json"
expect_get "$SHOWROOT_PORT" "$SHOWROOT_BODY" "/api/diff?commit=$SHOWROOT_SHA" "200" "audit root commit: /api/diff?commit= returns HTTP 200"
json_check "audit root commit: the root commit lists the files it added" "$SHOWROOT_BODY" \
  '[(f["path"], f["status"]) for f in data["files"]] == [("a.txt", "A"), ("b.txt", "A")]'
expect_get "$SHOWROOT_PORT" "$SHOWROOT_BODY" "/api/file?commit=$SHOWROOT_SHA&path=a.txt" "200" "audit root commit: /api/file?commit= returns HTTP 200"
json_check "audit root commit: the root commit's patch adds the file" "$SHOWROOT_BODY" '"+alpha" in data["patch"]'

# --- the edge of a shallow clone: git shows the boundary commit with no
# parent, as if it had added every file.

SHALLOWB_SRC="$FIXTURE/audit-shallowb-src"
SHALLOWB_CLONE="$FIXTURE/audit-shallowb-clone"
new_repo "$SHALLOWB_SRC"
printf 'a1\n' > "$SHALLOWB_SRC/a.txt"
printf 'b1\n' > "$SHALLOWB_SRC/b.txt"
git -C "$SHALLOWB_SRC" add -A
set_commit_date "2026-10-01T10:14:00 +0000"
git -C "$SHALLOWB_SRC" commit -q -m one
printf 'a2\n' > "$SHALLOWB_SRC/a.txt"
set_commit_date "2026-10-01T10:15:00 +0000"
git -C "$SHALLOWB_SRC" commit -q -am two
printf 'b2\n' > "$SHALLOWB_SRC/b.txt"
set_commit_date "2026-10-01T10:16:00 +0000"
git -C "$SHALLOWB_SRC" commit -q -am three
git clone -q --depth 2 "file://$SHALLOWB_SRC" "$SHALLOWB_CLONE"
SHALLOWB_EDGE_SHA=$(git -C "$SHALLOWB_CLONE" rev-parse HEAD~1)
SHALLOWB_TIP_SHA=$(git -C "$SHALLOWB_CLONE" rev-parse HEAD)
git -C "$SHALLOWB_CLONE" show --format= --name-status "$SHALLOWB_EDGE_SHA" -- | grep -q '^A.b\.txt$'
check "audit shallow edge: plain git really does show the edge commit adding a file it never touched" $?
SHALLOWB_LOG="$FIXTURE/server-audit-shallowb.log"
SHALLOWB_PORT=$(start_extra_server "$SHALLOWB_CLONE" "$SHALLOWB_LOG")
check "audit shallow edge: server starts on the shallow clone" $?
SHALLOWB_BODY="$FIXTURE/audit-shallowb.json"
expect_get "$SHALLOWB_PORT" "$SHALLOWB_BODY" "/api/diff?commit=$SHALLOWB_EDGE_SHA" "200" "audit shallow edge: /api/diff for the edge commit returns HTTP 200"
json_check "audit shallow edge: no file is listed and the sentence says why" "$SHALLOWB_BODY" \
  'data["files"] == [] and data["explanation"].startswith("This clone is shallow: the commit before this one was not downloaded")'
expect_get "$SHALLOWB_PORT" "$SHALLOWB_BODY" "/api/file?commit=$SHALLOWB_EDGE_SHA&path=a.txt" "400" "audit shallow edge: /api/file for the edge commit is refused with HTTP 400"
json_check "audit shallow edge: the refusal is the same sentence" "$SHALLOWB_BODY" \
  'data["error"].startswith("This clone is shallow: the commit before this one was not downloaded")'
expect_get "$SHALLOWB_PORT" "$SHALLOWB_BODY" "/api/diff?commit=$SHALLOWB_TIP_SHA" "200" "audit shallow edge: the commit after the edge still returns HTTP 200"
json_check "audit shallow edge: the commit after the edge shows its own change" "$SHALLOWB_BODY" \
  '[(f["path"], f["status"]) for f in data["files"]] == [("b.txt", "M")]'

# --- file names that are not valid UTF-8: decoded with replacement
# characters, two such names became one, shared one count and matched no
# file when their patch was asked for. macOS will not create such a file, so
# git writes them straight into a commit.

LATIN_REPO="$FIXTURE/audit-latin"
new_repo "$LATIN_REPO"
python3 -c '
import sys
stream = (
    "commit refs/heads/main\n"
    "mark :1\n"
    "committer Test User <test@example.com> 1790000000 +0000\n"
    "data 4\nbase\n"
    "M 100644 inline ok.txt\ndata 5\nbase\n\n"
    "commit refs/heads/latin\n"
    "committer Test User <test@example.com> 1790000100 +0000\n"
    "data 5\nlatin\n"
    "from :1\n"
    "M 100644 inline \"caf\\351.txt\"\ndata 4\none\n\n"
    "M 100644 inline \"caf\\350.txt\"\ndata 14\none\ntwo\nthree\n\n"
    "M 100644 inline ok.txt\ndata 10\nbase\nmore\n\n"
)
sys.stdout.write(stream)
' | git -C "$LATIN_REPO" fast-import --quiet
git -C "$LATIN_REPO" reset -q --hard main
LATIN_SHA=$(git -C "$LATIN_REPO" rev-parse latin)
git -C "$LATIN_REPO" diff --numstat -z main latin -- | python3 -c '
import sys
raw = sys.stdin.buffer.read()
names = [record.split(b"\t")[2] for record in raw.split(b"\x00") if record.count(b"\t") == 2]
replaced = set(name.decode("utf-8", errors="replace") for name in names)
sys.exit(0 if len(names) == 3 and len(replaced) == 2 else 1)
'
check "audit non-UTF-8 names: decoding git's listing with replacement really does merge two names" $?
LATIN_LOG="$FIXTURE/server-audit-latin.log"
LATIN_PORT=$(start_extra_server "$LATIN_REPO" "$LATIN_LOG")
check "audit non-UTF-8 names: server starts on the repository" $?
LATIN_BODY="$FIXTURE/audit-latin.json"
expect_get "$LATIN_PORT" "$LATIN_BODY" "/api/diff?commit=$LATIN_SHA" "200" "audit non-UTF-8 names: /api/diff?commit= returns HTTP 200"
json_check "audit non-UTF-8 names: two rows with their own counts, both marked unshowable" "$LATIN_BODY" \
  'sorted((f["adds"], f.get("unshowable", False)) for f in data["files"] if f["path"] != "ok.txt") == [(1, True), (3, True)] and data["total_adds"] == 5'
! grep -q '\\udc' "$LATIN_BODY"
check "audit non-UTF-8 names: no lone surrogate escape reaches the JSON" $?
expect_get "$LATIN_PORT" "$LATIN_BODY" "/api/diff?branch=latin" "200" "audit non-UTF-8 names: /api/diff?branch= returns HTTP 200"
json_check "audit non-UTF-8 names: the branch view counts them apart too" "$LATIN_BODY" \
  'sorted(f["adds"] for f in data["files"] if f.get("unshowable")) == [1, 3] and data["total_adds"] == 5'
expect_get "$LATIN_PORT" "$LATIN_BODY" "/api/file?commit=$LATIN_SHA&path=caf%EF%BF%BD.txt" "400" "audit non-UTF-8 names: the patch of such a name is refused with HTTP 400"
json_check "audit non-UTF-8 names: the refusal says the name is not valid UTF-8" "$LATIN_BODY" \
  'data["error"] == "This file name is not valid UTF-8; BranchLens cannot show its patch."'
expect_get "$LATIN_PORT" "$LATIN_BODY" "/api/file?branch=latin&path=ok.txt" "200" "audit non-UTF-8 names: a valid name next to them still gets its patch"
json_check "audit non-UTF-8 names: that patch holds its own edit" "$LATIN_BODY" '"+more" in data["patch"]'

# --- type changes: git reports a file that became a symlink with T, which
# used to be folded into M.

TYPECHANGE_REPO="$FIXTURE/audit-typechange"
set_commit_date "2026-10-01T10:17:00 +0000"
new_repo "$TYPECHANGE_REPO"
printf 'plain file\n' > "$TYPECHANGE_REPO/entry"
printf 'target\n' > "$TYPECHANGE_REPO/target.txt"
git -C "$TYPECHANGE_REPO" add -A
git -C "$TYPECHANGE_REPO" commit -q -m "a file"
rm "$TYPECHANGE_REPO/entry"
ln -s target.txt "$TYPECHANGE_REPO/entry"
set_commit_date "2026-10-01T10:18:00 +0000"
git -C "$TYPECHANGE_REPO" add -A
git -C "$TYPECHANGE_REPO" commit -q -m "now a symlink"
TYPECHANGE_SHA=$(git -C "$TYPECHANGE_REPO" rev-parse HEAD)
[ "$(git -C "$TYPECHANGE_REPO" diff --name-status HEAD~1 HEAD | cut -f1)" = "T" ]
check "audit type change: git itself reports the file-to-symlink change as T" $?
TYPECHANGE_LOG="$FIXTURE/server-audit-typechange.log"
TYPECHANGE_PORT=$(start_extra_server "$TYPECHANGE_REPO" "$TYPECHANGE_LOG")
check "audit type change: server starts on the repository" $?
TYPECHANGE_BODY="$FIXTURE/audit-typechange.json"
expect_get "$TYPECHANGE_PORT" "$TYPECHANGE_BODY" "/api/diff?commit=$TYPECHANGE_SHA" "200" "audit type change: /api/diff?commit= returns HTTP 200"
json_check "audit type change: the entry keeps git's T status" "$TYPECHANGE_BODY" \
  '[(f["path"], f["status"]) for f in data["files"]] == [("entry", "T")]'

# ---- a worktree added between two polls is hardened before git runs in it ----
LATE_ROOT="$FIXTURE/audit-late"
LATE_REPO="$LATE_ROOT/repo"
LATE_MARKER="$LATE_ROOT/marker.txt"
mkdir -p "$LATE_REPO"
printf '#!/bin/sh\necho PWNED >> "%s"\ncat\n' "$LATE_MARKER" > "$LATE_ROOT/evil_clean.sh"
chmod +x "$LATE_ROOT/evil_clean.sh"
new_repo "$LATE_REPO" Tester t@example.com
git -C "$LATE_REPO" config core.repositoryformatversion 1
git -C "$LATE_REPO" config extensions.worktreeConfig true
printf 'line1\n' > "$LATE_REPO/t.txt"
printf 'line1\n' > "$LATE_REPO/u.txt"
printf 't.txt filter=trap\nu.txt filter=trap2\n' > "$LATE_REPO/.gitattributes"
git -C "$LATE_REPO" add -A
git -C "$LATE_REPO" commit -q -m initial
LATE_LOG="$FIXTURE/server-audit-late.log"
LATE_PORT=$(start_extra_server "$LATE_REPO" "$LATE_LOG")
check "audit late worktree: server starts on the repository" $?
LATE_BODY="$FIXTURE/audit-late.json"
expect_get "$LATE_PORT" "$LATE_BODY" "/api/state" "200" "audit late worktree: /api/state before the worktree exists returns HTTP 200"
# The worktree, its filter and a dirty file arrive after that poll.
git -C "$LATE_REPO" worktree add -q -b late "$LATE_ROOT/late" main
git -C "$LATE_ROOT/late" config --worktree filter.trap.clean "$LATE_ROOT/evil_clean.sh"
printf 'line1\nchanged\n' > "$LATE_ROOT/late/t.txt"
rm -f "$LATE_MARKER"
git -C "$LATE_ROOT/late" diff --quiet >/dev/null 2>&1
[ -f "$LATE_MARKER" ]
check "audit late worktree: plain git in the new worktree runs the filter (the trap is armed)" $?
rm -f "$LATE_MARKER"
STATUS=$(http_get "$LATE_PORT" "$LATE_BODY" "/api/diff?branch=late")
[ "$STATUS" = "200" ] && [ ! -f "$LATE_MARKER" ]
check "audit late worktree: /api/diff on a worktree added since the last poll runs no filter" $?
STATUS=$(http_get "$LATE_PORT" "$LATE_BODY" "/api/file?branch=late&path=t.txt")
[ "$STATUS" = "200" ] && [ ! -f "$LATE_MARKER" ]
check "audit late worktree: /api/file on that worktree runs no filter either" $?

# A filter added to the repository's own config after the last poll, with the
# worktree listing unchanged, is blanked before the next branch diff too.
git -C "$LATE_REPO" config filter.trap2.clean "$LATE_ROOT/evil_clean.sh"
printf 'line1\nchanged\n' > "$LATE_REPO/u.txt"
rm -f "$LATE_MARKER"
git -C "$LATE_REPO" diff --quiet >/dev/null 2>&1
[ -f "$LATE_MARKER" ]
check "audit late config: plain git in the main checkout runs the new filter (the trap is armed)" $?
rm -f "$LATE_MARKER"
STATUS=$(http_get "$LATE_PORT" "$LATE_BODY" "/api/diff?branch=main")
[ "$STATUS" = "200" ] && [ ! -f "$LATE_MARKER" ]
check "audit late config: /api/diff after a filter was added since the last poll runs no filter" "$?" "status $STATUS, marker: $(cat "$LATE_MARKER" 2>/dev/null)"
STATUS=$(http_get "$LATE_PORT" "$LATE_BODY" "/api/file?branch=main&path=u.txt")
[ "$STATUS" = "200" ] && [ ! -f "$LATE_MARKER" ]
check "audit late config: /api/file after that change runs no filter either" "$?" "status $STATUS, marker: $(cat "$LATE_MARKER" 2>/dev/null)"

# Runtime imports: the note says "the rest cannot be followed" only when some
# were not drawn.
DYNAMIC_REPO="$FIXTURE/audit-dynamic"
new_repo "$DYNAMIC_REPO" Tester t@example.com
printf 'import importlib\nimportlib.import_module("b")\n' > "$DYNAMIC_REPO/a.py"
printf 'VALUE = 1\n' > "$DYNAMIC_REPO/b.py"
git -C "$DYNAMIC_REPO" add -A
git -C "$DYNAMIC_REPO" commit -q -m "a loads b at runtime"
python3 - "$PROJECT_DIR" "$DYNAMIC_REPO" <<'PY'
import sys

from branchlens import gitops

repo = sys.argv[2]
commit = gitops.run_git_text(["rev-parse", "HEAD"], cwd=repo).strip()
notes = gitops.get_network(repo, commit)["notes"]
expected = "1 import is built at runtime; 1 named a literal module and is drawn."
if expected not in notes or any("the rest cannot be followed" in note for note in notes):
    print("  notes: " + repr(notes))
    sys.exit(1)
sys.exit(0)
PY
check "audit network: with every runtime import drawn, the note claims no rest that cannot be followed" $?

# ---------------------------------------------------------------- lazy fetch
# A partial clone fetches a missing blob the moment a diff needs it.

LAZY_SRC="$FIXTURE/lazysrc"
LAZY_CLONE="$FIXTURE/lazyclone"
new_repo "$LAZY_SRC"
git -C "$LAZY_SRC" config uploadpack.allowFilter true
set_commit_date "2026-06-01T10:05:00 +0000"
printf 'one\n' > "$LAZY_SRC/big.txt"
git -C "$LAZY_SRC" add -A
git -C "$LAZY_SRC" commit -q -m first
set_commit_date "2026-06-01T10:06:00 +0000"
printf 'one\ntwo\n' > "$LAZY_SRC/big.txt"
git -C "$LAZY_SRC" commit -q -am second
git clone -q --filter=blob:none --no-checkout "file://$LAZY_SRC" "$LAZY_CLONE" 2>/dev/null
git -C "$LAZY_CLONE" checkout -q main

missing_blobs() {
  git -C "$LAZY_CLONE" rev-list --objects --missing=print --all | grep -c '^?'
}
[ "$(missing_blobs)" = "1" ]
check "lazy fetch: the partial clone really lacks the older blob" $?

LAZY_LOG="$FIXTURE/server-lazy.log"
LAZY_BODY="$FIXTURE/lazy.json"
LAZY_SHA=$(git -C "$LAZY_CLONE" rev-parse HEAD)
# These checks need GIT_NO_LAZY_FETCH (git 2.45); LAZY_FETCH_SWITCH comes
# from the probe in the "audit 2026-10: suite" section.
if [ "$LAZY_FETCH_SWITCH" = "honoured" ]; then
  LAZY_PORT=$(start_extra_server "$LAZY_CLONE" "$LAZY_LOG")
  check "lazy fetch: server starts on the partial clone" $?
  expect_get "$LAZY_PORT" "$LAZY_BODY" "/api/file?commit=$LAZY_SHA&path=big.txt" "400" "lazy fetch: a diff needing the missing blob is refused with HTTP 400"
  json_check "lazy fetch: the refusal says the clone is partial and nothing is fetched" "$LAZY_BODY" \
    '"partial clone" in data["error"] and "never fetches" in data["error"]'
  [ "$(missing_blobs)" = "1" ]
  check "lazy fetch: the blob is still missing afterwards, so nothing was fetched" $?
else
  echo "SKIP: lazy fetch: the server's 4 checks on the partial clone (this git ignores GIT_NO_LAZY_FETCH)"
fi
# Self-check, last because it fills the hole: plain git does fetch here.
git -C "$LAZY_CLONE" diff HEAD~1 HEAD > /dev/null 2>&1
[ "$(missing_blobs)" = "0" ]
check "lazy fetch: the fixture really does make plain git fetch the blob" $?

# ---------------------------------------------------------------- hardening under load
# The override list used to be reset to two entries at the start of every
# poll and refilled only after several git calls; a diff on another thread
# in that window ran with the repository's filters live.

if [ -n "$SERVER_PORT4" ]; then
  rm -f "$FILTER_MARKER"
  for round in $(seq 1 25); do
    curl -s -m 5 -b "$(cookie_for "$SERVER_PORT4")" -o /dev/null "http://127.0.0.1:$SERVER_PORT4/api/state" &
    HAMMER_A=$!
    curl -s -m 5 -b "$(cookie_for "$SERVER_PORT4")" -o /dev/null "http://127.0.0.1:$SERVER_PORT4/api/file?branch=main&path=secret.dat" &
    HAMMER_B=$!
    curl -s -m 5 -b "$(cookie_for "$SERVER_PORT4")" -o /dev/null "http://127.0.0.1:$SERVER_PORT4/api/diff?branch=main" &
    HAMMER_C=$!
    # Named pids: a bare 'wait' would also wait for the servers running in
    # the background, which never exit.
    wait "$HAMMER_A" "$HAMMER_B" "$HAMMER_C"
  done
  [ ! -e "$FILTER_MARKER" ]
  check "hostile filter: 25 rounds of concurrent state and diff requests never ran the clean filter" $?
fi

# ---------------------------------------------------------------- connection bursts
# The server is paused while 40 connections open, so all of them wait in the
# listen queue; socketserver's default queue of 5 reset the rest.

python3 -c '
import os, signal, socket, sys
port = int(sys.argv[1])
server_pid = int(sys.argv[2])
os.kill(server_pid, signal.SIGSTOP)
connections = []
try:
    for attempt in range(40):
        try:
            connections.append(socket.create_connection(("127.0.0.1", port), timeout=2))
        except OSError:
            pass
finally:
    os.kill(server_pid, signal.SIGCONT)
answered = 0
for connection in connections:
    try:
        connection.sendall(b"GET /favicon.ico HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        if b" 204 " in connection.recv(64):
            answered += 1
    except OSError:
        pass
    connection.close()
sys.exit(0 if answered == 40 else 1)
' "$SERVER_PORT" "$SERVER_PID"
check "connection bursts: 40 connections opened while the server is busy are all answered" $?

# ---------------------------------------------------------------- git messages in English
# git's errors are quoted inside English sentences, whatever the user's locale.

python3 -c '
import sys
from branchlens import gitops
sys.exit(0 if gitops.hardening_environment().get("LANGUAGE") == "en" else 1)
' "$PROJECT_DIR"
check "git messages: every read runs git with English messages" $?

# ---------------------------------------------------------------- parser fixes
# One commit, one network request, several assertions.

PARSE_REPO="$FIXTURE/parserepo"
new_repo "$PARSE_REPO"
mkdir -p "$PARSE_REPO/js" "$PARSE_REPO/py/pkg" "$PARSE_REPO/java/a/b"
# JavaScript: '/*/' does not close a comment; .d.ts resolves; a mixed
# 'type' import is not type-only while an all-type one is.
printf '/*/ import hidden from "./hidden";\n*/\nimport { type A, B } from "./mixed";\nimport { type C } from "./types";\nexport default 1;\n' > "$PARSE_REPO/js/main.ts"
printf 'export const hidden = 1;\n' > "$PARSE_REPO/js/hidden.ts"
printf 'export type A = number;\nexport const B = 2;\n' > "$PARSE_REPO/js/mixed.ts"
printf 'export type C = string;\n' > "$PARSE_REPO/js/types.d.ts"
# Python: a package __init__ nested 300000 levels deep must not fail the
# whole request. Python before 3.9.10 has no recursion guard in its parser:
# this depth crashes a thread with the default stack (100000 does not) and
# parses on the 256 MiB stack server.py gives request threads. Newer Pythons
# refuse it with an error.
python3 -c "open('$PARSE_REPO/py/pkg/__init__.py', 'w').write('x = ' + '-' * 300000 + '1\n')"
# What this python3 makes of the file on a 256 MiB stack:
PARSE_DEEP_VERDICT=$(python3 -c '
import ast
import sys
import threading

# As server.py does it, a platform that refuses the size included.
try:
    threading.stack_size(256 * 1024 * 1024)
except (ValueError, RuntimeError):
    pass
source = open(sys.argv[1]).read()
verdict = []


def parse():
    try:
        ast.parse(source)
        verdict.append("parses")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        verdict.append("refuses")


thread = threading.Thread(target=parse)
thread.start()
thread.join()
print(verdict[0] if verdict else "neither")
' "$PARSE_REPO/py/pkg/__init__.py")
printf 'from pkg import x\n' > "$PARSE_REPO/py/app.py"
# Java: a 20000-space import with no semicolon (the old regex took minutes),
# an import after a semicolon on the same line, and 'Outer.*'.
python3 -c "open('$PARSE_REPO/java/a/b/Bad.java', 'w').write('package a.b; import a.b.Outer.*;\nimport ' + ' ' * 20000 + '\nclass Bad {}\n')"
printf 'package a.b;\npublic class Outer { public static class Inner {} }\n' > "$PARSE_REPO/java/a/b/Outer.java"
set_commit_date "2026-06-01T10:07:00 +0000"
git -C "$PARSE_REPO" add -A
git -C "$PARSE_REPO" commit -q -m "parser fixture"
PARSE_LOG="$FIXTURE/server-parse.log"
PARSE_PORT=$(start_extra_server "$PARSE_REPO" "$PARSE_LOG")
check "parser: server starts on the parser fixture" $?
PARSE_BODY="$FIXTURE/parse.json"
PARSE_SHA=$(git -C "$PARSE_REPO" rev-parse HEAD)
expect_get "$PARSE_PORT" "$PARSE_BODY" "/api/network?commit=$PARSE_SHA" "200" "parser: /api/network answers within the 5 s curl limit despite the 20000-space Java import"
json_check "parser: '/*/' does not close a JavaScript comment, so no arrow to hidden.ts" "$PARSE_BODY" \
  'not any(e["from"] == "js/main.ts" and e["to"] == "js/hidden.ts" for e in data["edges"])'
json_check "parser: './types' resolves to types.d.ts and that arrow is type-only" "$PARSE_BODY" \
  'any(e["from"] == "js/main.ts" and e["to"] == "js/types.d.ts" and e["type_only"] is True for e in data["edges"])'
json_check "parser: 'import { type A, B }' is not a type-only arrow" "$PARSE_BODY" \
  'any(e["from"] == "js/main.ts" and e["to"] == "js/mixed.ts" and e["type_only"] is False for e in data["edges"])'
json_check "parser: the 300000-deep __init__.py is read as this Python's parser reads it (unparsable when it refuses), not a failed request" "$PARSE_BODY" \
  '[(n["analyzed"], n["reason"]) for n in data["nodes"] if n["path"] == "py/pkg/__init__.py"] == ([(False, "unparsable")] if extra == "refuses" else [(True, None)])' "$PARSE_DEEP_VERDICT"
json_check "parser: 'import a.b.Outer.*' after a ';' on the same line draws an arrow to Outer.java" "$PARSE_BODY" \
  'any(e["from"] == "java/a/b/Bad.java" and e["to"] == "java/a/b/Outer.java" for e in data["edges"])'
expect_get "$PARSE_PORT" "$PARSE_BODY" "/api/network?commit=$PARSE_SHA" "200" "parser: a second request for the same commit is answered (from the cache) with HTTP 200"
json_check "parser: the limits block names the tree-entry cap" "$PARSE_BODY" \
  'data["limits"]["max_tree_entries"] == 50000'

# ---------------------------------------------------------------- audit 2026-10: network view
# Regression checks for the October 2026 audit of the dependency network. Each
# one fails on the code as it was before its fix. Most run in-process: a
# Python block imports gitops from this checkout, calls it on small
# repositories built here with plain git, and writes what it saw to a JSON
# file that the checks below read.

AUDIT_NET="$FIXTURE/audit-network"
mkdir -p "$AUDIT_NET"

# g108: the v3 fixture's net/pkg/__init__.py now also says 'from . import
# util'. That binds the submodule, so it must not make 'util' an attribute
# that keeps arrows on __init__.py, and __init__.py's own statement must reach
# util.py instead of being dropped as an import of itself.
json_check "audit g108: __init__.py's own 'from . import util' draws its arrow to util.py" "$NET" \
  '[[e["lines"], e["count"]] for e in data["edges"] if e["from"] == "net/pkg/__init__.py" and e["to"] == "net/pkg/util.py"] == [[[1, 2], 2]] and data["honesty"]["self_imports_dropped"] == 0'
json_check "audit g108: another file's 'from . import util' still points at util.py, not __init__.py" "$NET" \
  '["net/pkg/app.py", "net/pkg/util.py"] in [[e["from"], e["to"]] for e in data["edges"]] and all(e["to"] != "net/pkg/__init__.py" for e in data["edges"] if e["from"] == "net/pkg/app.py")'

# Pure functions, no git involved.
AUDIT_PURE="$AUDIT_NET/pure.json"
python3 - "$PROJECT_DIR" "$AUDIT_PURE" <<'PY_AUDIT_PURE'
import json
import sys

from branchlens import gitops

results = {}


def python_requests(source):
    requests, honesty = gitops.extract_python_dependencies("probe.py", source)
    return requests, honesty


# g108
results["g108_bound"] = sorted(gitops.python_module_level_names(
    "from .util import shared_value\nfrom . import util\n"))
results["g108_star_still_unknown"] = gitops.python_module_level_names(
    "from . import *\n") is None

# g118: an import inside a case body may not run. Python 3.9 has no match
# statement, so there the file is unparsable and both values stay None.
requests, honesty = python_requests("match x:\n    case 1:\n        import json\n")
results["g118_match"] = None
results["g118_counted"] = None
if requests is not None:
    results["g118_match"] = [[r["target"], r["conditional"]] for r in requests]
    results["g118_counted"] = honesty["python_conditional_imports"]

# g119: a valid file with a 1000-branch elif chain is still read.
source = "x = 0\nif x == 0:\n    pass\n"
for index in range(1, 1000):
    source += "elif x == %d:\n    pass\n" % index
source += "import os.path\n"
requests, honesty = python_requests(source)
results["g119_elif"] = None if requests is None else [r["target"] for r in requests]
requests, honesty = python_requests(
    "import a\ndef f():\n    import b\nimport c\n")
results["g119_order"] = [[r["target"], r["conditional"]] for r in requests]

# g29: importlib calls that import nothing are not dynamic imports.
requests, honesty = python_requests(
    "import importlib.metadata\nimportlib.metadata.version('app')\n"
    "importlib.invalidate_caches()\nimportlib.reload(importlib)\n")
results["g29_not_dynamic"] = [[r["target"], r["dynamic"]] for r in requests]
results["g29_not_counted"] = honesty["python_dynamic_imports"]
requests, honesty = python_requests("import importlib\nimportlib.import_module('app')\n")
results["g29_import_module"] = [[r["target"], r["dynamic"]] for r in requests]

# g112: at most 5000 requests per file, and the rest are counted.
requests, honesty = python_requests("import " + ", ".join(["x"] * 6000) + "\n")
results["g112_python"] = [len(requests), honesty["imports_past_file_cap"]]
requests, honesty = python_requests(
    "import x\n" * 3 + "x.alpha()\nx.beta()\n")
results["g112_names_once"] = [r["symbols"] for r in requests]
js_source = "".join("import './m%d.js';\n" % index for index in range(5100))
requests, honesty = gitops.extract_js_dependencies("big.js", js_source)
results["g112_js"] = [len(requests), honesty["imports_past_file_cap"],
                      requests[-1]["line"]]

handle = open(sys.argv[2], "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_PURE
check "audit: the in-process checks of the pure functions ran" $?

json_check "audit g108: 'from . import x' in __init__.py binds no attribute; a star import still makes the bindings unknown" "$AUDIT_PURE" \
  'data["g108_bound"] == ["shared_value"] and data["g108_star_still_unknown"] is True'
json_check "audit g118: an import inside a match/case body is conditional and counted (Python 3.9: the file is unparsable)" "$AUDIT_PURE" \
  '(data["g118_match"] == [["json", True]] and data["g118_counted"] == 1) if sys.version_info >= (3, 10) else (data["g118_match"] is None and data["g118_counted"] is None)'
json_check "audit g119: a valid file with a 1000-branch elif chain is read, not called unparsable" "$AUDIT_PURE" \
  'data["g119_elif"] == ["os.path"]'
json_check "audit g119: the walk keeps source order and the conditional flag" "$AUDIT_PURE" \
  'data["g119_order"] == [["a", False], ["b", True], ["c", False]]'
json_check "audit g29: importlib.metadata.version() and friends are not dynamic imports" "$AUDIT_PURE" \
  'data["g29_not_dynamic"] == [["importlib.metadata", False]] and data["g29_not_counted"] == 0'
json_check "audit g29: importlib.import_module() still is one" "$AUDIT_PURE" \
  'data["g29_import_module"] == [["importlib", False], ["app", True]]'
json_check "audit g112: a Python file keeps 5000 requests and counts the rest" "$AUDIT_PURE" \
  'data["g112_python"] == [5000, 1000]'
json_check "audit g112: repeated 'import x' statements carry the attribute names once" "$AUDIT_PURE" \
  'data["g112_names_once"] == [["alpha", "beta"], [], []]'
json_check "audit g112: a JavaScript file keeps its first 5000 imports by line and counts the rest" "$AUDIT_PURE" \
  'data["g112_js"] == [5000, 100, 5000]'

# g120: SyntaxWarnings raised by inspected source neither reach the server's
# terminal nor, under -W error, turn a valid file into an unparsable one.
AUDIT_WARN_ERR="$AUDIT_NET/warnings.err"
python3 -W error::SyntaxWarning - "$PROJECT_DIR" 2> "$AUDIT_WARN_ERR" <<'PY_AUDIT_WARN'
import sys

from branchlens import gitops

source = "import re\npattern = '\\d+'\n"
requests, honesty = gitops.extract_python_dependencies("w.py", source)
sys.exit(0 if requests is not None and [r["target"] for r in requests] == ["re"] else 1)
PY_AUDIT_WARN
check "audit g120: a file whose source raises a SyntaxWarning is read even under -W error" $?
python3 - "$PROJECT_DIR" 2> "$AUDIT_WARN_ERR" <<'PY_AUDIT_WARN2'
import sys

from branchlens import gitops

gitops.extract_python_dependencies("w.py", "pattern = '\\d+'\n")
PY_AUDIT_WARN2
[ ! -s "$AUDIT_WARN_ERR" ]
check "audit g120: parsing it prints nothing on stderr" $?

# One small repository per group of fixes, each read by get_network()
# in-process. audit_commit commits whatever is in the folder and echoes the
# commit id.
audit_commit() {
  git -C "$1" add -A
  git -C "$1" commit -q -m "$2"
  git -C "$1" rev-parse HEAD
}
set_commit_date "2026-06-01T10:07:30 +0000"

AUDIT_PY="$AUDIT_NET/python"
new_repo "$AUDIT_PY"
printf 'VALUE = 1\n' > "$AUDIT_PY/app.py"
printf 'import importlib.metadata\n\nversion = importlib.metadata.version("app")\n' \
  > "$AUDIT_PY/version_check.py"
python3 -c "
import sys
handle = open(sys.argv[1], 'w')
handle.write('import app\n' * 5005)
handle.close()
" "$AUDIT_PY/many.py"
AUDIT_PY_SHA=$(audit_commit "$AUDIT_PY" "python audit fixture")

# Prints get_network() for each 'repository sha' pair into one JSON object,
# keyed by the label given first.
audit_networks() {
  python3 - "$PROJECT_DIR" "$@" <<'PY_AUDIT_NETWORKS'
import json
import sys

from branchlens import gitops

output_path = sys.argv[2]
answers = {}
arguments = sys.argv[3:]
for index in range(0, len(arguments), 3):
    label, repository, sha = arguments[index:index + 3]
    try:
        answers[label] = gitops.get_network(repository, sha)
    except gitops.GitError as error:
        answers[label] = {"error": str(error)}
handle = open(output_path, "w")
json.dump(answers, handle)
handle.close()
PY_AUDIT_NETWORKS
}

AUDIT_PY_JSON="$AUDIT_NET/python.json"
audit_networks "$AUDIT_PY_JSON" python "$AUDIT_PY" "$AUDIT_PY_SHA"
check "audit: get_network ran on the Python fixture" $?

json_check "audit g29: importlib.metadata.version('app') next to app.py draws no arrow and counts nothing" "$AUDIT_PY_JSON" \
  'all(e["from"] != "version_check.py" for e in data["python"]["edges"]) and data["python"]["honesty"]["python_dynamic_imports"] == 0'
json_check "audit g112: imports past the per-file cap are counted, said, and mark the graph truncated" "$AUDIT_PY_JSON" \
  '[[e["from"], e["to"], e["count"]] for e in data["python"]["edges"]] == [["many.py", "app.py", 5000]] and data["python"]["honesty"]["imports_past_file_cap"] == 5 and "5 imports were not followed because a file held more than 5000 of them, so arrows from those files may be missing." in data["python"]["notes"] and data["python"]["truncated"] is True'

# ---- which Python file an import means ---------------------------------------

AUDIT_PYRES="$AUDIT_NET/python-resolver"
new_repo "$AUDIT_PYRES"
mkdir -p "$AUDIT_PYRES/dual" "$AUDIT_PYRES/pkg/sub" "$AUDIT_PYRES/ns/inner" \
  "$AUDIT_PYRES/pkg2" "$AUDIT_PYRES/web"
# g114: a module turned into a package with the old file left behind. Python
# loads the package.
printf 'OLD = 1\n' > "$AUDIT_PYRES/dual.py"
printf 'NEW = 1\n' > "$AUDIT_PYRES/dual/__init__.py"
printf 'import dual\n' > "$AUDIT_PYRES/use_dual.py"
printf '' > "$AUDIT_PYRES/pkg/__init__.py"
printf 'OLD = 1\n' > "$AUDIT_PYRES/pkg/sub.py"
printf 'NEW = 1\n' > "$AUDIT_PYRES/pkg/sub/__init__.py"
printf 'from .sub import NEW\n' > "$AUDIT_PYRES/pkg/user.py"
printf 'from pkg import sub\n' > "$AUDIT_PYRES/use_pkg.py"
# g115: relative imports inside a directory with no __init__.py.
printf 'H = 1\n' > "$AUDIT_PYRES/ns/helper.py"
printf 'from . import helper\nfrom .inner import deep\n' > "$AUDIT_PYRES/ns/user.py"
printf 'D = 1\n' > "$AUDIT_PYRES/ns/inner/deep.py"
printf 'from . import helper\n' > "$AUDIT_PYRES/top_relative.py"
# g116: modules inside submodules, reached absolutely, relatively and from
# JavaScript.
printf 'import vendor.lib.core\nfrom vendor.lib.core import thing\n' \
  > "$AUDIT_PYRES/use_vendor.py"
printf '' > "$AUDIT_PYRES/pkg2/__init__.py"
printf 'from .lib.core import thing\n' > "$AUDIT_PYRES/pkg2/mod.py"
printf "import thing from './vendor/lib/x.js'\n" > "$AUDIT_PYRES/web/a.js"
git -C "$AUDIT_PYRES" add -A
# Submodule entries straight into the index ('add -A' would drop them again,
# as their directories do not exist here).
for gitlink in vendor/lib pkg2/lib web/vendor/lib; do
  git -C "$AUDIT_PYRES" update-index --add --cacheinfo \
    "160000,1234567890123456789012345678901234567890,$gitlink"
done
git -C "$AUDIT_PYRES" commit -q -m "python resolver fixture"
AUDIT_PYRES_SHA=$(git -C "$AUDIT_PYRES" rev-parse HEAD)

# Ground truth from CPython: the package wins over dual.py, and a relative
# import inside a namespace package reaches its sibling.
(cd "$AUDIT_PYRES" && python3 -c "
import sys
sys.dont_write_bytecode = True
import dual
assert hasattr(dual, 'NEW') and not hasattr(dual, 'OLD')
import ns.user
assert ns.user.helper.H == 1 and ns.user.deep.D == 1
") > /dev/null 2>&1
check "audit g114/g115: CPython loads the package over dual.py and resolves the namespace relative imports" $?

AUDIT_PYRES_JSON="$AUDIT_NET/python-resolver.json"
audit_networks "$AUDIT_PYRES_JSON" res "$AUDIT_PYRES" "$AUDIT_PYRES_SHA"
check "audit: get_network ran on the Python resolver fixture" $?

json_check "audit g114: 'import dual' points at dual/__init__.py, not at dual.py beside it" "$AUDIT_PYRES_JSON" \
  '[e["to"] for e in data["res"]["edges"] if e["from"] == "use_dual.py"] == ["dual/__init__.py"]'
json_check "audit g114: relative and from-package imports choose the package too" "$AUDIT_PYRES_JSON" \
  '[e["to"] for e in data["res"]["edges"] if e["from"] == "pkg/user.py"] == ["pkg/sub/__init__.py"] and sorted(e["to"] for e in data["res"]["edges"] if e["from"] == "use_pkg.py") == ["pkg/__init__.py", "pkg/sub/__init__.py"]'
json_check "audit g115: 'from . import helper' in a directory with no __init__.py reaches the sibling" "$AUDIT_PYRES_JSON" \
  'sorted(e["to"] for e in data["res"]["edges"] if e["from"] == "ns/user.py") == ["ns/helper.py", "ns/inner/deep.py"] and all("ns/user.py" not in u["examples"] for u in data["res"]["unresolved"])'
json_check "audit g115: a top-level script's 'from . import x' is still reported as not found" "$AUDIT_PYRES_JSON" \
  '[[u["specifier"], u["reason"]] for u in data["res"]["unresolved"] if u["examples"] == ["top_relative.py"]] == [[".", "relative import target not found"]]'
json_check "audit g116: imports of a module inside a submodule are never called imports that leave the repository" "$AUDIT_PYRES_JSON" \
  'sorted([u["specifier"], u["count"]] for u in data["res"]["unresolved"] if u["reason"] == "a symlink or submodule at this commit, which this view does not read") == [["./vendor/lib/x.js", 1], [".lib.core", 1], ["vendor.lib.core", 2]] and all(u["reason"] != "not a file in this repository" for u in data["res"]["unresolved"])'

# g113: thousands of files sharing one module name cost one pass each, and an
# import resolved again from the same directory is not recomputed.
AUDIT_INDEX_JSON="$AUDIT_NET/index.json"
python3 - "$PROJECT_DIR" "$AUDIT_INDEX_JSON" <<'PY_AUDIT_INDEX'
import json
import sys
import time

from branchlens import gitops

paths = sorted("d%05d/x.py" % index for index in range(20000))
started = time.time()
index, import_roots, package_directories = gitops.build_python_module_index(paths)
results = {"index_seconds": time.time() - started, "candidates": len(index["x"])}
calls = []
original_find = gitops.find_python_module


def counting_find(*args):
    calls.append(args[0])
    return original_find(*args)


gitops.find_python_module = counting_find
context = {
    "module_index": index, "import_roots": import_roots,
    "package_directories": package_directories, "python_paths": paths,
    "init_bindings": {}, "file_set": set(paths), "excluded_paths": set(),
    "module_memo": {},
}
honesty = gitops.new_honesty_counts()
answers = set()
for repeat in range(1000):
    answers.add(gitops.resolve_python_module(
        "x", "d00007/y.py", "d00007", context, honesty))
results["answers"] = sorted(answers)
results["searches"] = len(calls)
# An ambiguous answer still counts once per import when it is remembered.
ambiguous_index = {"m": [("", "m.py"), ("lib", "lib/m.py")]}
ambiguous_context = dict(context)
ambiguous_context.update({"module_index": ambiguous_index,
                          "package_directories": {"lib/m"}, "module_memo": {}})
for repeat in range(3):
    gitops.resolve_python_module("m", "tests/t.py", "tests", ambiguous_context, honesty)
results["ambiguous"] = honesty["ambiguous_python_modules"]
handle = open(sys.argv[2], "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_INDEX
check "audit: the module index checks ran" $?
json_check "audit g113: indexing 20000 files of one name takes well under a second" "$AUDIT_INDEX_JSON" \
  'data["index_seconds"] < 1.0 and data["candidates"] == 20000'
json_check "audit g113: 1000 imports from one directory search the candidates once" "$AUDIT_INDEX_JSON" \
  'data["answers"] == ["d00007/x.py"] and data["searches"] == 1'
json_check "audit g113: a remembered ambiguous answer is still counted once per import" "$AUDIT_INDEX_JSON" \
  'data["ambiguous"] == 3'

# ---- JavaScript and TypeScript ----------------------------------------------

AUDIT_JS="$AUDIT_NET/javascript"
new_repo "$AUDIT_JS"
mkdir -p "$AUDIT_JS/web/utils"
# g101: specifiers built at runtime from a literal, and a literal import()
# with import attributes. g104: bundler query suffixes. g105: a trailing
# slash names the directory, even with utils.js beside it.
cat > "$AUDIT_JS/web/calls.js" <<'JS_AUDIT_CALLS'
const messages = require("./locale/" + language)
const page = import("./pages/" + name)
const data = import("./d.json", { with: { type: "json" } })
import worker from "./worker?worker"
import logo from "./logo.svg?raw"
const utils = require("./utils/")
JS_AUDIT_CALLS
printf '{"a": 1}\n' > "$AUDIT_JS/web/d.json"
printf 'export default 1;\n' > "$AUDIT_JS/web/worker.js"
printf '<svg/>\n' > "$AUDIT_JS/web/logo.svg"
printf 'module.exports = 1;\n' > "$AUDIT_JS/web/utils.js"
printf 'module.exports = 2;\n' > "$AUDIT_JS/web/utils/index.js"
# g106: import.meta before a semicolon-free re-export.
printf 'const url = import.meta.url\nexport { shared } from "./shared"\n' \
  > "$AUDIT_JS/web/meta.js"
printf 'export const shared = 1;\n' > "$AUDIT_JS/web/shared.js"
# g103: a destructuring require of 14 names (past 200 characters, under 400),
# one of 30 names (past the 400 the pattern reads), and one nested pattern.
python3 -c "
import sys
def names(count):
    return ''.join('  helperFunctionNumber%02d,\n' % index for index in range(count))
handle = open(sys.argv[1], 'w')
handle.write('const {\n' + names(14) + '} = require(\"./helpers\")\n')
handle.write('const {\n' + names(30) + '} = require(\"./many\")\n')
handle.write('const { inner: { deep } } = require(\"./nested\")\n')
handle.close()
" "$AUDIT_JS/web/destructure.js"
printf 'module.exports = {};\n' > "$AUDIT_JS/web/helpers.js"
printf 'module.exports = {};\n' > "$AUDIT_JS/web/many.js"
printf 'module.exports = {};\n' > "$AUDIT_JS/web/nested.js"
# g102: import clauses past 400 characters holding a non-ASCII name and a
# string export name.
python3 -c "
import sys
names = ',\n  '.join('componentName%02d' % index for index in range(30))
handle = open(sys.argv[1], 'w', encoding='utf-8')
handle.write('import {\n  ' + names + ',\n  perché\n} from \"./big\"\n')
handle.close()
handle = open(sys.argv[2], 'w', encoding='utf-8')
handle.write('import {\n  ' + names + ',\n  \"kebab-name\" as kebab\n} from \"./big\"\n')
handle.close()
" "$AUDIT_JS/web/unicode.ts" "$AUDIT_JS/web/stringname.ts"
printf 'export const componentName00 = 0;\n' > "$AUDIT_JS/web/big.ts"
AUDIT_JS_SHA=$(audit_commit "$AUDIT_JS" "javascript audit fixture")

AUDIT_JS_JSON="$AUDIT_NET/javascript.json"
audit_networks "$AUDIT_JS_JSON" js "$AUDIT_JS" "$AUDIT_JS_SHA"
check "audit: get_network ran on the JavaScript fixture" $?

json_check "audit g101: require() and import() of a literal plus a runtime part are counted as computed" "$AUDIT_JS_JSON" \
  'sorted([u["reason"], u["count"], u["examples"]] for u in data["js"]["unresolved"] if u["specifier"] == "(computed)") == [["dynamic import with a computed specifier", 1, ["web/calls.js"]], ["require with a computed specifier", 1, ["web/calls.js"]]]'
json_check "audit g101: a literal import() with import attributes draws its arrow" "$AUDIT_JS_JSON" \
  '[[e["kind"], e["dynamic"]] for e in data["js"]["edges"] if e["from"] == "web/calls.js" and e["to"] == "web/d.json"] == [["dynamic-import", True]]'
json_check "audit g104: './worker?worker' and './logo.svg?raw' resolve to the files they name" "$AUDIT_JS_JSON" \
  '["web/calls.js", "web/worker.js"] in [[e["from"], e["to"]] for e in data["js"]["edges"]] and ["web/calls.js", "web/logo.svg"] in [[e["from"], e["to"]] for e in data["js"]["edges"]]'
json_check "audit g105: './utils/' resolves to the directory's index file, not to utils.js" "$AUDIT_JS_JSON" \
  '["web/calls.js", "web/utils/index.js"] in [[e["from"], e["to"]] for e in data["js"]["edges"]] and ["web/calls.js", "web/utils.js"] not in [[e["from"], e["to"]] for e in data["js"]["edges"]]'
json_check "audit g106: import.meta before a re-export leaves it an export-from on its own line" "$AUDIT_JS_JSON" \
  '[[e["kind"], e["lines"], e["symbols"], e["symbols_unreadable"]] for e in data["js"]["edges"] if e["from"] == "web/meta.js"] == [["export-from", [2], ["shared"], 0]]'
json_check "audit g103: a destructuring require past 200 characters keeps its 14 names" "$AUDIT_JS_JSON" \
  '[[e["symbol_count"], e["symbols_unreadable"]] for e in data["js"]["edges"] if e["from"] == "web/destructure.js" and e["to"] == "web/helpers.js"] == [[14, 0]]'
json_check "audit g103: a destructuring too long or too nested to read is unknown, never 'no named symbols'" "$AUDIT_JS_JSON" \
  '[[e["to"], e["symbols"], e["symbols_unreadable"]] for e in data["js"]["edges"] if e["from"] == "web/destructure.js" and e["to"] != "web/helpers.js"] == [["web/many.js", [], 1], ["web/nested.js", [], 1]]'
json_check "audit g102: a long import clause holding a non-ASCII name still draws its arrow with every name" "$AUDIT_JS_JSON" \
  '[[e["symbol_count"], e["symbols_unreadable"]] for e in data["js"]["edges"] if e["from"] == "web/unicode.ts"] == [[31, 0]]'
json_check "audit g102: a long import clause holding a string export name draws its arrow and counts that name" "$AUDIT_JS_JSON" \
  '[[e["symbol_count"], e["symbols_unreadable"]] for e in data["js"]["edges"] if e["from"] == "web/stringname.ts"] == [[30, 1]] and data["js"]["honesty"]["js_clauses_too_long"] == 0'

# A file made only of from''from''…: each literal sent the backwards walk
# over every one before it, about 78 s of one core for 400 KB under the
# network build lock. Past its step budget the file is drawn as not read.
AUDIT_JSWALK="$AUDIT_NET/jswalk"
new_repo "$AUDIT_JSWALK"
mkdir -p "$AUDIT_JSWALK/web"
python3 -c "
import sys
handle = open(sys.argv[1], 'w')
handle.write((\"from''\" * 66666)[:399996])
handle.close()
" "$AUDIT_JSWALK/web/walk.js"
printf "import { a } from './walk.js';\n" > "$AUDIT_JSWALK/web/user.js"
AUDIT_JSWALK_SHA=$(audit_commit "$AUDIT_JSWALK" "a file the walk cannot finish")
AUDIT_JSWALK_LOG="$FIXTURE/server-audit-jswalk.log"
AUDIT_JSWALK_PORT=$(start_extra_server "$AUDIT_JSWALK" "$AUDIT_JSWALK_LOG")
check "audit walk budget: server starts on the repository" $?
AUDIT_JSWALK_JSON="$AUDIT_NET/jswalk.json"
rm -f "$AUDIT_JSWALK_JSON"
AUDIT_JSWALK_ANSWER=$(curl -s -m 10 -b "$(cookie_for "$AUDIT_JSWALK_PORT")" -o "$AUDIT_JSWALK_JSON" \
  -w '%{http_code} %{time_total}' "http://127.0.0.1:$AUDIT_JSWALK_PORT/api/network?commit=$AUDIT_JSWALK_SHA")
python3 -c '
import sys
code, seconds = sys.argv[1].split()
sys.exit(0 if code == "200" and float(seconds) < 2 else 1)
' "$AUDIT_JSWALK_ANSWER"
check "audit walk budget: /api/network answers within 2 s" $? "$AUDIT_JSWALK_ANSWER"
json_check "audit walk budget: the file is drawn as not read, too complex to read, with no arrow out" "$AUDIT_JSWALK_JSON" \
  '[(n["analyzed"], n["reason"]) for n in data["nodes"] if n["path"] == "web/walk.js"] == [(False, "too complex to read")] and [e for e in data["edges"] if e["from"] == "web/walk.js"] == []'
json_check "audit walk budget: the arrow into it from a file that was read is still drawn" "$AUDIT_JSWALK_JSON" \
  '[[e["from"], e["to"]] for e in data["edges"]] == [["web/user.js", "web/walk.js"]]'

# ---- Java ---------------------------------------------------------------------

AUDIT_JAVA="$AUDIT_NET/java"
new_repo "$AUDIT_JAVA"
mkdir -p "$AUDIT_JAVA/a" "$AUDIT_JAVA/b" "$AUDIT_JAVA/p" "$AUDIT_JAVA/t" \
  "$AUDIT_JAVA/tools" "$AUDIT_JAVA/service-a/src/main/java/com/acme/dto" \
  "$AUDIT_JAVA/service-b/src/main/java/com/acme/dto" \
  "$AUDIT_JAVA/service-b/src/main/java/com/acme/app"
# g30: classes in a file too large to read and in one that is not UTF-8, plus
# a third-party class sharing the large file's class name.
printf 'package a;\nimport b.Big;\nimport b.Latin;\nimport b.Seen;\nimport org.lib.Big;\nimport org.other.Thing;\npublic class A {}\n' \
  > "$AUDIT_JAVA/a/A.java"
printf 'package b;\npublic class Seen {}\n' > "$AUDIT_JAVA/b/Seen.java"
python3 -c "
import sys
handle = open(sys.argv[1], 'w')
handle.write('package b;\npublic class Big {}\n' + '// padding\n' * 40000)
handle.close()
" "$AUDIT_JAVA/b/Big.java"
printf 'package b;\n// caf\xe9\npublic class Latin {}\n' > "$AUDIT_JAVA/b/Latin.java"
# g100: one class declared in two modules. Main sits in service-b; Root is
# as near to one copy as to the other.
for module in service-a service-b; do
  printf 'package com.acme.dto;\npublic class UserDto {}\n' \
    > "$AUDIT_JAVA/$module/src/main/java/com/acme/dto/UserDto.java"
done
printf 'package com.acme.app;\nimport com.acme.dto.UserDto;\npublic class Main {}\n' \
  > "$AUDIT_JAVA/service-b/src/main/java/com/acme/app/Main.java"
printf 'package tools;\nimport com.acme.dto.UserDto;\npublic class Root {}\n' \
  > "$AUDIT_JAVA/tools/Root.java"
# g93 and g28: a static wildcard and a JDK wildcard draw no package fan-out;
# a package wildcard written three times fans out once, counted three times.
printf 'package t;\nimport static org.junit.Assert.*;\nimport java.util.*;\nimport p.*;\nimport p.*;\nimport p.*;\npublic class T {}\n' \
  > "$AUDIT_JAVA/t/T.java"
printf 'package p;\npublic class P1 {}\n' > "$AUDIT_JAVA/p/P1.java"
printf 'package p;\npublic class P2 {}\n' > "$AUDIT_JAVA/p/P2.java"
AUDIT_JAVA_SHA=$(audit_commit "$AUDIT_JAVA" "java audit fixture")

AUDIT_JAVA_JSON="$AUDIT_NET/java.json"
audit_networks "$AUDIT_JAVA_JSON" java "$AUDIT_JAVA" "$AUDIT_JAVA_SHA"
check "audit: get_network ran on the Java fixture" $?

json_check "audit g30: a class in a Java file that was not read still gets its arrow" "$AUDIT_JAVA_JSON" \
  'sorted(e["to"] for e in data["java"]["edges"] if e["from"] == "a/A.java") == ["b/Big.java", "b/Latin.java", "b/Seen.java"]'
json_check "audit g30: the unread files keep a known used_by and their reasons" "$AUDIT_JAVA_JSON" \
  '[[n["path"], n["analyzed"], n["reason"], n["used_by"]] for n in data["java"]["nodes"] if n["path"] in ("b/Big.java", "b/Latin.java")] == [["b/Big.java", False, "too large", 1], ["b/Latin.java", False, "not UTF-8 text", 1]]'
json_check "audit g30: a class that may sit in an unread file is not called one that leaves the repository" "$AUDIT_JAVA_JSON" \
  'sorted([u["specifier"], u["reason"]] for u in data["java"]["unresolved"] if u["examples"] == ["a/A.java"]) == [["org.lib.Big", "possibly a class in a Java file this view did not read"], ["org.other.Thing", "not a file in this repository"]] and "1 import names a Java class that may be declared in a file this view did not read, so no arrow is drawn for it." in data["java"]["notes"]'
json_check "audit g100: an import of a class two modules declare points at the importer's own module" "$AUDIT_JAVA_JSON" \
  '[e["to"] for e in data["java"]["edges"] if e["from"] == "service-b/src/main/java/com/acme/app/Main.java"] == ["service-b/src/main/java/com/acme/dto/UserDto.java"]'
json_check "audit g100: a tie between equally near copies is counted and said" "$AUDIT_JAVA_JSON" \
  '[e["to"] for e in data["java"]["edges"] if e["from"] == "tools/Root.java"] == ["service-a/src/main/java/com/acme/dto/UserDto.java"] and data["java"]["honesty"]["ambiguous_java_classes"] == 1 and "1 import names a Java class that more than one file declares, each as near as the other; the first in path order was used." in data["java"]["notes"]'
json_check "audit g93: static and JDK wildcards are not counted as package fan-outs; each written package wildcard is" "$AUDIT_JAVA_JSON" \
  'data["java"]["honesty"]["java_wildcard_imports"] == 3'
json_check "audit g28: a repeated wildcard fans out once and its arrows still count every statement" "$AUDIT_JAVA_JSON" \
  '[[e["to"], e["count"], e["lines"]] for e in data["java"]["edges"] if e["from"] == "t/T.java"] == [["p/P1.java", 3, [4, 5, 6]], ["p/P2.java", 3, [4, 5, 6]]]'

# g94: the cache keeps a Java file's package name, not its masked text, and
# is bounded by the import requests its records hold.
AUDIT_CACHE_JSON="$AUDIT_NET/cache.json"
python3 - "$PROJECT_DIR" "$AUDIT_CACHE_JSON" "$AUDIT_PY" "$AUDIT_PY_SHA" <<'PY_AUDIT_CACHE'
import json
import sys

from branchlens import gitops

results = {}
record = gitops.read_source_file(
    "a/b/C.java", "java", b"package a.b;\nimport c.D;\npublic class C {}\n")
results["java_record"] = [sorted(record), record["java_package"]]
gitops.MAX_SOURCE_FILE_CACHE_REQUESTS = 100
gitops.get_network(sys.argv[3], sys.argv[4])
largest = 0
total = 0
for cached in gitops._SOURCE_FILE_CACHE.values():
    count = gitops.record_request_count(cached)
    total += count
    largest = max(largest, count)
results["cache"] = [len(gitops._SOURCE_FILE_CACHE), largest, total,
                    gitops._source_file_cache_requests]
handle = open(sys.argv[2], "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_CACHE
check "audit: the cache checks ran" $?
json_check "audit g94: a cached Java record holds its package name and no masked source" "$AUDIT_CACHE_JSON" \
  'data["java_record"] == [["honesty", "init_bound", "java_package", "lines", "requests", "text_ok", "unread_reason"], "a.b"]'
json_check "audit g94: a file whose requests would pass the cache bound is not kept, and the tally matches" "$AUDIT_CACHE_JSON" \
  'data["cache"] == [2, 1, 1, 1]'

# ---- reading the tree --------------------------------------------------------

# g111: 100000 entries from a few shared subtrees. With the caps lowered for
# the test, the listing files 50 entries, counts to 200 and then kills git.
AUDIT_BOMB="$AUDIT_NET/bomb"
new_repo "$AUDIT_BOMB"
AUDIT_BOMB_BLOB=$(printf 'x\n' | git -C "$AUDIT_BOMB" hash-object -w --stdin)
AUDIT_BOMB_TREE=$(for index in 0 1 2 3 4 5 6 7 8 9; do
  printf '100644 blob %s\tf%d\n' "$AUDIT_BOMB_BLOB" "$index"
done | git -C "$AUDIT_BOMB" mktree)
for level in 1 2 3 4; do
  AUDIT_BOMB_TREE=$(for index in 0 1 2 3 4 5 6 7 8 9; do
    printf '040000 tree %s\td%d\n' "$AUDIT_BOMB_TREE" "$index"
  done | git -C "$AUDIT_BOMB" mktree)
done
AUDIT_BOMB_SHA=$(git -C "$AUDIT_BOMB" commit-tree "$AUDIT_BOMB_TREE" -m "tree bomb")
git -C "$AUDIT_BOMB" update-ref refs/heads/main "$AUDIT_BOMB_SHA"
[ "$(git -C "$AUDIT_BOMB" ls-tree -r --full-tree "$AUDIT_BOMB_SHA" | wc -l | tr -d ' ')" = "100000" ]
check "audit g111: the shared-subtree fixture really lists 100000 entries" $?

AUDIT_BOMB_JSON="$AUDIT_NET/bomb.json"
python3 - "$PROJECT_DIR" "$AUDIT_BOMB_JSON" "$AUDIT_BOMB" "$AUDIT_BOMB_SHA" <<'PY_AUDIT_BOMB'
import json
import subprocess
import sys

from branchlens import gitops

listings = []
original_popen = subprocess.Popen


def recording_popen(command, *args, **kwargs):
    process = original_popen(command, *args, **kwargs)
    if "ls-tree" in command:
        listings.append(process)
    return process


subprocess.Popen = recording_popen
gitops.NETWORK_MAX_TREE_ENTRIES = 50
gitops.NETWORK_MAX_TREE_COUNT = 200
results = {}
entries, excluded, excluded_paths, stopped = gitops.list_tree_files(
    sys.argv[3], sys.argv[4])
results["listing"] = [len(entries), excluded["unlisted"], stopped]
results["git_killed_and_waited"] = [process.returncode for process in listings]
answer = gitops.get_network(sys.argv[3], sys.argv[4])
results["network"] = answer
handle = open(sys.argv[2], "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_BOMB
check "audit: the tree-listing checks ran" $?
json_check "audit g111: past the count ceiling the listing stops with a lower bound" "$AUDIT_BOMB_JSON" \
  'data["listing"] == [50, 150, True]'
json_check "audit g111: git was killed there and waited for, not left to list 100000 entries" "$AUDIT_BOMB_JSON" \
  'len(data["git_killed_and_waited"]) == 1 and data["git_killed_and_waited"][0] is not None and data["git_killed_and_waited"][0] < 0'
json_check "audit g111: the answer flags the stopped listing, keeps the arithmetic, and says 'more than'" "$AUDIT_BOMB_JSON" \
  'data["network"]["truncation"]["tree_listing_stopped"] is True and data["network"]["excluded"]["unlisted"] == 150 and data["network"]["counts"]["files_at_commit"] == 200 and data["network"]["truncated"] is True and "More than 150 files at this commit were not even listed: the tree holds more than 200 entries, so counting stopped there. Only the first 50 in path order were looked at, so arrows from and to the rest are missing." in data["network"]["notes"]'

# g27: paths deeper than 64 directories or longer than 1024 bytes are counted,
# never indexed; the 75 KB one also spans more than one read of git's output.
AUDIT_DEEP="$AUDIT_NET/deep"
new_repo "$AUDIT_DEEP"
AUDIT_DEEP_USER=$(printf 'import ok\n' | git -C "$AUDIT_DEEP" hash-object -w --stdin)
AUDIT_DEEP_OK=$(printf 'VALUE = 1\n' | git -C "$AUDIT_DEEP" hash-object -w --stdin)
python3 - "$AUDIT_DEEP_USER" "$AUDIT_DEEP_OK" <<'PY_AUDIT_DEEP' | git -C "$AUDIT_DEEP" update-index --add --index-info
import sys

user_blob, ok_blob = sys.argv[1], sys.argv[2]
deep_path = "/".join(["d"] * 64) + "/deep.py"
long_path = "/".join(["x" * 210] * 5) + "/long.py"
huge_path = "/".join(["h" * 250] * 300) + "/huge.py"
print("100644 blob %s\tok.py" % ok_blob)
print("100644 blob %s\tuser.py" % user_blob)
for path in (deep_path, long_path, huge_path):
    print("100644 blob %s\t%s" % (user_blob, path))
PY_AUDIT_DEEP
AUDIT_DEEP_TREE=$(git -C "$AUDIT_DEEP" write-tree)
AUDIT_DEEP_SHA=$(git -C "$AUDIT_DEEP" commit-tree "$AUDIT_DEEP_TREE" -m "deep paths")
git -C "$AUDIT_DEEP" update-ref refs/heads/main "$AUDIT_DEEP_SHA"

# g117: a refs/replace entry turning a blob into a tree.
AUDIT_REPLACE="$AUDIT_NET/replace"
new_repo "$AUDIT_REPLACE"
mkdir -p "$AUDIT_REPLACE/sub"
printf 'import b\n' > "$AUDIT_REPLACE/a.py"
printf 'VALUE = 1\n' > "$AUDIT_REPLACE/b.py"
printf 'C = 3\n' > "$AUDIT_REPLACE/sub/c.py"
AUDIT_REPLACE_SHA=$(audit_commit "$AUDIT_REPLACE" "replace fixture")
AUDIT_REPLACE_BLOB=$(git -C "$AUDIT_REPLACE" rev-parse HEAD:b.py)
AUDIT_REPLACE_TREE=$(git -C "$AUDIT_REPLACE" rev-parse HEAD:sub)
git -C "$AUDIT_REPLACE" update-ref "refs/replace/$AUDIT_REPLACE_BLOB" "$AUDIT_REPLACE_TREE"
[ "$(git -C "$AUDIT_REPLACE" cat-file -t "$AUDIT_REPLACE_BLOB")" = "tree" ]
check "audit g117: git itself now reads b.py's blob as a tree" $?

# g109: a blob-less partial clone. The oldest commit's m.py was never
# fetched; the middle commit lacks only a data file.
AUDIT_PARTIAL_SRC="$AUDIT_NET/partial-src"
AUDIT_PARTIAL="$AUDIT_NET/partial"
new_repo "$AUDIT_PARTIAL_SRC"
git -C "$AUDIT_PARTIAL_SRC" config uploadpack.allowFilter true
printf 'x = 1\n' > "$AUDIT_PARTIAL_SRC/m.py"
printf 'one\n' > "$AUDIT_PARTIAL_SRC/data.bin"
audit_commit "$AUDIT_PARTIAL_SRC" "first" > /dev/null
printf 'import data\nx = 2\n' > "$AUDIT_PARTIAL_SRC/m.py"
printf 'two\n' > "$AUDIT_PARTIAL_SRC/data.bin"
audit_commit "$AUDIT_PARTIAL_SRC" "second" > /dev/null
printf 'three\n' > "$AUDIT_PARTIAL_SRC/data.bin"
audit_commit "$AUDIT_PARTIAL_SRC" "third" > /dev/null
git clone -q --filter=blob:none --no-checkout "file://$AUDIT_PARTIAL_SRC" "$AUDIT_PARTIAL" 2>/dev/null
git -C "$AUDIT_PARTIAL" checkout -q main
AUDIT_PARTIAL_FIRST=$(git -C "$AUDIT_PARTIAL" rev-parse HEAD~2)
AUDIT_PARTIAL_SECOND=$(git -C "$AUDIT_PARTIAL" rev-parse HEAD~1)
audit_missing_blobs() {
  git -C "$AUDIT_PARTIAL" rev-list --objects --missing=print --all | grep -c '^?'
}
[ "$(audit_missing_blobs)" = "3" ]
check "audit g109: the partial clone really lacks three blobs" $?

AUDIT_READ_JSON="$AUDIT_NET/reading.json"
audit_networks "$AUDIT_READ_JSON" deep "$AUDIT_DEEP" "$AUDIT_DEEP_SHA" \
  replace "$AUDIT_REPLACE" "$AUDIT_REPLACE_SHA" \
  partial_first "$AUDIT_PARTIAL" "$AUDIT_PARTIAL_FIRST" \
  partial_second "$AUDIT_PARTIAL" "$AUDIT_PARTIAL_SECOND"
check "audit: get_network ran on the tree-reading fixtures" $?

json_check "audit g27: over-deep and over-long paths are counted apart, never indexed, and said" "$AUDIT_READ_JSON" \
  'data["deep"]["excluded"]["too_deep"] == 3 and [n["path"] for n in data["deep"]["nodes"]] == ["ok.py", "user.py"] and data["deep"]["counts"]["files_at_commit"] == 5 and data["deep"]["truncated"] is True and "3 files at this commit have paths longer than 1024 bytes or deeper than 64 directories, so they are neither read nor drawn, and arrows from and to them are missing." in data["deep"]["notes"]'
json_check "audit g27: the rest of that commit is still read" "$AUDIT_READ_JSON" \
  '[[e["from"], e["to"]] for e in data["deep"]["edges"]] == [["user.py", "ok.py"]]'
json_check "audit g117: a blob replaced by a tree no longer refuses the whole network" "$AUDIT_READ_JSON" \
  '"error" not in data["replace"] and [[e["from"], e["to"]] for e in data["replace"]["edges"]] == [["a.py", "b.py"]] and [n["lines"] for n in data["replace"]["nodes"] if n["path"] == "b.py"] == [1]'
json_check "audit g109: a source file a partial clone lacks refuses the network with the not-on-disk sentence" "$AUDIT_READ_JSON" \
  '"partial clone" in data["partial_first"].get("error", "") and "never fetches" in data["partial_first"]["error"]'
json_check "audit g109: a lacking data file does not, and is counted like any data file" "$AUDIT_READ_JSON" \
  '"error" not in data["partial_second"] and [[n["path"], n["analyzed"]] for n in data["partial_second"]["nodes"]] == [["m.py", True]] and data["partial_second"]["excluded"]["other"] == 1'
[ "$(audit_missing_blobs)" = "3" ]
check "audit g109: nothing was fetched along the way" $?

# g99: the network learns which files changed from names alone; the set is
# the one the diff listing gives, renames and root commits included.
AUDIT_FEATURE_SHA=$(git -C "$REPO" rev-parse feature-committed)
AUDIT_PATHS_JSON="$AUDIT_NET/paths.json"
python3 - "$PROJECT_DIR" "$AUDIT_PATHS_JSON" "$REPO" "$NETWORK_SHA" "$ROOT_SHA" "$AUDIT_FEATURE_SHA" <<'PY_AUDIT_PATHS'
import json
import sys

from branchlens import gitops

repo = sys.argv[3]
commands = []
original_run_git = gitops.run_git


def recording_run_git(args, cwd=None, allow_exit_code_1=False):
    commands.append(list(args))
    return original_run_git(args, cwd=cwd, allow_exit_code_1=allow_exit_code_1)


gitops.run_git = recording_run_git
gitops.get_network(repo, sys.argv[4])
results = {"numstat_used": any("--numstat" in args for args in commands)}
commits = {}
for commit in gitops.read_graph_commits(repo):
    commits[commit["sha"]] = commit
for label, sha in (("network", sys.argv[4]), ("root", sys.argv[5]), ("rename", sys.argv[6])):
    commit = commits[sha]
    listed = set()
    for file_entry in gitops.collect_commit_files(repo, commit):
        listed.add(file_entry["path"])
    results[label] = [sorted(gitops.collect_commit_paths(repo, commit)), sorted(listed)]
handle = open(sys.argv[2], "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_PATHS
check "audit: the changed-path checks ran" $?
json_check "audit g99: building the network runs no line-counting diff" "$AUDIT_PATHS_JSON" \
  'data["numstat_used"] is False'
json_check "audit g99: the names-only set equals the diff listing's, for a root commit and a rename too" "$AUDIT_PATHS_JSON" \
  'all(data[label][0] == data[label][1] and len(data[label][0]) > 0 for label in ("network", "root", "rename")) and "src/newname.py" in data["rename"][0] and "src/oldname.py" not in data["rename"][0]'

# ---- building the graph -------------------------------------------------------

# Five links: touch.py -> x1.py touches the commit's one changed file,
# la.py <-> lb.py is a loop, and a1 -> a2 and a3 -> a4 (a dynamic import)
# sort before the loop. The caps are lowered for the test.
AUDIT_ASM="$AUDIT_NET/assembly"
new_repo "$AUDIT_ASM"
printf 'import a2\n' > "$AUDIT_ASM/a1.py"
printf 'X = 1\n' > "$AUDIT_ASM/a2.py"
printf 'import importlib\n\nimportlib.import_module("a4")\n' > "$AUDIT_ASM/a3.py"
printf 'Y = 1\n' > "$AUDIT_ASM/a4.py"
printf 'import lb\n' > "$AUDIT_ASM/la.py"
printf 'import la\n' > "$AUDIT_ASM/lb.py"
printf 'Z = 1\n' > "$AUDIT_ASM/x1.py"
printf 'import x1\n' > "$AUDIT_ASM/touch.py"
AUDIT_ASM_FIRST=$(audit_commit "$AUDIT_ASM" "assembly base")
printf 'import x1\n\nW = 2\n' > "$AUDIT_ASM/touch.py"
AUDIT_ASM_SECOND=$(audit_commit "$AUDIT_ASM" "touch one file")
printf 'import x1\n\nW = 3\n' > "$AUDIT_ASM/touch.py"
AUDIT_ASM_THIRD=$(audit_commit "$AUDIT_ASM" "touch it again")

# g32: a root commit of ten unconnected files, all of them changed by it.
AUDIT_HIDE="$AUDIT_NET/hide"
new_repo "$AUDIT_HIDE"
for index in 0 1 2 3 4 5 6 7 8 9; do
  printf 'VALUE = %d\n' "$index" > "$AUDIT_HIDE/iso$index.py"
done
AUDIT_HIDE_SHA=$(audit_commit "$AUDIT_HIDE" "ten lone files")

# g31, g96, g92, g97: self-imports, an ambiguous module name, a .vue file
# imported from JavaScript, and counts of two.
AUDIT_NOTES="$AUDIT_NET/notes"
new_repo "$AUDIT_NOTES"
mkdir -p "$AUDIT_NOTES/lib" "$AUDIT_NOTES/alpha/util" "$AUDIT_NOTES/beta/util" \
  "$AUDIT_NOTES/tests" "$AUDIT_NOTES/web"
printf 'import loop\n' > "$AUDIT_NOTES/loop.py"
printf 'from . import self_ref\n' > "$AUDIT_NOTES/lib/__init__.py"
printf 'import lib.self_ref\nimport lib.self_ref\n' > "$AUDIT_NOTES/lib/self_ref.py"
# 'util' is a package in two directories that are not packages themselves.
printf 'A = 1\n' > "$AUDIT_NOTES/alpha/util/__init__.py"
printf 'B = 1\n' > "$AUDIT_NOTES/beta/util/__init__.py"
printf 'import util\n' > "$AUDIT_NOTES/tests/check_util.py"
printf "import App from './App.vue'\nimport Card from './Card.svelte'\n" > "$AUDIT_NOTES/web/main.js"
printf '<template><div/></template>\n' > "$AUDIT_NOTES/web/App.vue"
printf '<div></div>\n' > "$AUDIT_NOTES/web/Card.svelte"
printf 'from x import *\nfrom y import *\n' > "$AUDIT_NOTES/stars.py"
AUDIT_NOTES_SHA=$(audit_commit "$AUDIT_NOTES" "notes fixture")

# g91: the only source files are not UTF-8, one importing the other.
AUDIT_LATIN="$AUDIT_NET/latin"
new_repo "$AUDIT_LATIN"
printf 'import b\n# caf\xe9\n' > "$AUDIT_LATIN/a.py"
printf 'X = "\xe9"\n' > "$AUDIT_LATIN/b.py"
AUDIT_LATIN_SHA=$(audit_commit "$AUDIT_LATIN" "latin")

# g33: the tree-bomb fixture again, plus a commit whose one source file
# sorts first and imports the standard library.
AUDIT_BOMB_SOURCE_BLOB=$(printf 'import os\n' | git -C "$AUDIT_BOMB" hash-object -w --stdin)
AUDIT_BOMB_TREE2=$( (printf '100644 blob %s\ta.py\n' "$AUDIT_BOMB_SOURCE_BLOB"
  git -C "$AUDIT_BOMB" ls-tree "$AUDIT_BOMB_SHA") | git -C "$AUDIT_BOMB" mktree)
AUDIT_BOMB_SHA2=$(git -C "$AUDIT_BOMB" commit-tree "$AUDIT_BOMB_TREE2" -p "$AUDIT_BOMB_SHA" -m "bomb with a source file")
git -C "$AUDIT_BOMB" update-ref refs/heads/main "$AUDIT_BOMB_SHA2"

AUDIT_ASM_JSON="$AUDIT_NET/assembly.json"
python3 - "$PROJECT_DIR" "$AUDIT_ASM_JSON" "$AUDIT_ASM" "$AUDIT_ASM_SECOND" \
  "$AUDIT_HIDE" "$AUDIT_HIDE_SHA" "$AUDIT_NOTES" "$AUDIT_NOTES_SHA" \
  "$AUDIT_LATIN" "$AUDIT_LATIN_SHA" "$AUDIT_BOMB" "$AUDIT_BOMB_SHA" "$AUDIT_BOMB_SHA2" \
  <<'PY_AUDIT_ASSEMBLY'
import json
import sys

from branchlens import gitops

(output_path, asm_repo, asm_sha, hide_repo, hide_sha, notes_repo, notes_sha,
 latin_repo, latin_sha, bomb_repo, bomb_sha, bomb_sha2) = sys.argv[2:]
defaults = {
    "NETWORK_MAX_EDGES": gitops.NETWORK_MAX_EDGES,
    "NETWORK_MAX_NODES": gitops.NETWORK_MAX_NODES,
    "NETWORK_MAX_EDGE_PAIRS": gitops.NETWORK_MAX_EDGE_PAIRS,
    "NETWORK_MAX_TREE_ENTRIES": gitops.NETWORK_MAX_TREE_ENTRIES,
    "NETWORK_MAX_TREE_COUNT": gitops.NETWORK_MAX_TREE_COUNT,
}


def network(repo, sha, **caps):
    """get_network() with some caps lowered, never served from the cache."""
    for name in defaults:
        setattr(gitops, name, caps.get(name, defaults[name]))
    gitops._NETWORK_CACHE.clear()
    try:
        return gitops.get_network(repo, sha)
    finally:
        for name in defaults:
            setattr(gitops, name, defaults[name])


results = {
    "edges3": network(asm_repo, asm_sha, NETWORK_MAX_EDGES=3),
    "edges1": network(asm_repo, asm_sha, NETWORK_MAX_EDGES=1),
    "pairs3": network(asm_repo, asm_sha, NETWORK_MAX_EDGE_PAIRS=3),
    "nodes1": network(asm_repo, asm_sha, NETWORK_MAX_NODES=1),
    "hide4": network(hide_repo, hide_sha, NETWORK_MAX_NODES=4),
    "notes": network(notes_repo, notes_sha),
    "latin": network(latin_repo, latin_sha),
    "bomb": network(bomb_repo, bomb_sha, NETWORK_MAX_TREE_ENTRIES=50,
                    NETWORK_MAX_TREE_COUNT=200),
    "bomb_source": network(bomb_repo, bomb_sha2, NETWORK_MAX_TREE_ENTRIES=50,
                           NETWORK_MAX_TREE_COUNT=200),
}
handle = open(output_path, "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_ASSEMBLY
check "audit: the graph-building checks ran" $?

json_check "audit g95: past the edge cap a loop's arrows are kept before ordinary ones" "$AUDIT_ASM_JSON" \
  '[[e["from"], e["to"]] for e in data["edges3"]["edges"]] == [["la.py", "lb.py"], ["lb.py", "la.py"], ["touch.py", "x1.py"]] and "3 of 5 arrows are shown because of the size limit." in data["edges3"]["notes"]'
json_check "audit g95: the dynamic import whose arrow was cut is not counted as drawn" "$AUDIT_ASM_JSON" \
  '"1 import is built at runtime; 0 named a literal module and are drawn, the rest cannot be followed." in data["edges3"]["notes"]'
json_check "audit g95: when a loop's own arrows are cut, a note says so" "$AUDIT_ASM_JSON" \
  '[[e["from"], e["to"]] for e in data["edges1"]["edges"]] == [["touch.py", "x1.py"]] and "2 of the arrows cut were inside an import loop, so not every loop is drawn whole." in data["edges1"]["notes"] and all(not any("import loop" in note for note in data[label]["notes"]) for label in ("edges3", "pairs3"))'
json_check "audit g28: links past the gathering bound are counted, marked and said" "$AUDIT_ASM_JSON" \
  'data["pairs3"]["truncation"]["links_not_gathered"] == 2 and data["pairs3"]["truncation"]["edges_total"] == 3 and data["pairs3"]["truncated"] is True and [[n["path"], n["links_dropped"]] for n in data["pairs3"]["nodes"] if n["path"] in ("la.py", "lb.py")] == [["la.py", True], ["lb.py", True]] and "2 imports were found after the graph already held 3 distinct links, so their arrows are missing and the real number of arrows is higher than any total shown here." in data["pairs3"]["notes"]'
json_check "audit g28: the commit's own link was gathered first" "$AUDIT_ASM_JSON" \
  '["touch.py", "x1.py"] in [[e["from"], e["to"]] for e in data["pairs3"]["edges"]]'
json_check "audit g32: past the node cap, changed files with no arrows are hidden too, and counted apart" "$AUDIT_ASM_JSON" \
  '[n["path"] for n in data["hide4"]["nodes"]] == ["iso0.py", "iso1.py", "iso2.py", "iso3.py"] and data["hide4"]["truncation"]["nodes_hidden"] == 6 and data["hide4"]["truncation"]["changed_nodes_hidden"] == 6 and "6 files with no arrows were hidden (6 of them changed in this commit) to keep the graph at 4 nodes." in data["hide4"]["notes"]'
json_check "audit g32: a graph still over the node cap says why instead of claiming it fits" "$AUDIT_ASM_JSON" \
  'data["nodes1"]["counts"]["nodes"] == 8 and "The graph holds 8 files, more than 1: a file with arrows, or whose arrows the size limit cut, is never hidden." in data["nodes1"]["notes"]'
json_check "audit g31: imports of the importing file itself get a sentence of their own" "$AUDIT_ASM_JSON" \
  'data["notes"]["honesty"]["self_imports_dropped"] == 3 and "3 imports name the file they sit in, so no arrow is drawn for them." in data["notes"]["notes"]'
json_check "audit g96: the ambiguity note counts imports, not module names" "$AUDIT_ASM_JSON" \
  '"1 import named a module that matched more than one file; the closest match was used." in data["notes"]["notes"]'
json_check "audit g92: a .vue file imported from JavaScript has its arrow, and the note no longer denies it" "$AUDIT_ASM_JSON" \
  'sorted(e["to"] for e in data["notes"]["edges"] if e["from"] == "web/main.js") == ["web/App.vue", "web/Card.svelte"] and "2 files at this commit are code in a language this view does not read: what they use is unknown, though arrows into them from files that were read are still drawn. Such files are not counted as source code above." in data["notes"]["notes"]'
json_check "audit g97: notes for counts of two agree in number" "$AUDIT_ASM_JSON" \
  '"2 star imports (from X import *) were found: the names crossing those arrows are unknown." in data["notes"]["notes"] and "2 imports point at something that is not a file in this repository (an installed package, the standard library, or a name that matches nothing here) and are listed separately, not drawn." in data["notes"]["notes"]'
json_check "audit g97: notes for counts of one and more agree in number on the submodule fixture" "$AUDIT_PYRES_JSON" \
  '"3 submodules at this commit point at another repository, so nothing inside is read or drawn." in data["res"]["notes"] and "4 imports point at a symlink or a submodule inside this repository. That does not leave the repository, but this view does not read them, so no arrow is drawn." in data["res"]["notes"]'
json_check "audit g91: files that could not be decoded are never called files that were read" "$AUDIT_ASM_JSON" \
  'data["latin"]["counts"]["analyzed"] == 0 and data["latin"]["explanation"] == "None of the 2 source files at \"latin\" could be read, so no link between them could be found."'
json_check "audit g91: one file read gets the singular" "$AUDIT_ASM_JSON" \
  'data["bomb_source"]["explanation"] == "No links between files were found at \"bomb with a source file\", from the 1 source file that could be read."'
json_check "audit g33: past the listing cap, the explanation never claims no source file exists" "$AUDIT_ASM_JSON" \
  'data["bomb"]["explanation"] == "No Python, JavaScript/TypeScript or Java files were found among the entries looked at in \"tree bomb\"; more than 150 more were not looked at, so source files may exist there."'
json_check "audit g33: past the listing cap, an unresolved import may be a file that was not listed" "$AUDIT_ASM_JSON" \
  '"1 import points at something that is not a file this view listed (an installed package, the standard library, a name that matches nothing here, or a file past the tree listing cap) and is listed separately, not drawn." in data["bomb_source"]["notes"]'

# g98: requests for one commit arriving together build it once; a build that
# fails does not leave the others waiting; the cache drops its oldest entry.
AUDIT_FLIGHT_JSON="$AUDIT_NET/single-flight.json"
python3 - "$PROJECT_DIR" "$AUDIT_FLIGHT_JSON" "$AUDIT_ASM" "$AUDIT_ASM_FIRST" \
  "$AUDIT_ASM_SECOND" "$AUDIT_ASM_THIRD" <<'PY_AUDIT_FLIGHT'
import json
import sys
import threading
import time

from branchlens import gitops

output_path, repo, first, second, third = sys.argv[2:]
builds = []
original_build = gitops.build_network_response


def slow_build(repo_root, commit):
    builds.append(commit["sha"])
    time.sleep(0.3)
    return original_build(repo_root, commit)


gitops.build_network_response = slow_build
answers = []


def ask():
    answers.append(gitops.get_network(repo, second))


threads = [threading.Thread(target=ask) for index in range(4)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
results = {
    "builds": len(builds),
    "answers": len(answers),
    "same_answer": all(answer is answers[0] for answer in answers),
}


def failing_build(repo_root, commit):
    raise gitops.GitError("simulated failure")


gitops._NETWORK_CACHE.clear()
gitops.build_network_response = failing_build
try:
    gitops.get_network(repo, first)
    results["failure_raised"] = False
except gitops.GitError:
    results["failure_raised"] = True
gitops.build_network_response = original_build
results["after_failure"] = gitops.get_network(repo, first)["commit"]["sha"] == first

gitops._NETWORK_CACHE.clear()
gitops.NETWORK_CACHE_ENTRIES = 2
for sha in (first, second, third):
    gitops.get_network(repo, sha)
results["cached"] = [sha in gitops._NETWORK_CACHE for sha in (first, second, third)]
handle = open(output_path, "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_FLIGHT
check "audit: the single-flight checks ran" $?
json_check "audit g98: four simultaneous requests for one commit build it once and share the answer" "$AUDIT_FLIGHT_JSON" \
  'data["builds"] == 1 and data["answers"] == 4 and data["same_answer"] is True'
json_check "audit g98: a failed build raises and the next request builds normally" "$AUDIT_FLIGHT_JSON" \
  'data["failure_raised"] is True and data["after_failure"] is True'
json_check "audit g98: a full cache drops its oldest commit, not all of them" "$AUDIT_FLIGHT_JSON" \
  'data["cached"] == [False, True, True]'

# A shallow clone's boundary commit (flagged by the graph listing) has no
# parent to diff against: no file is marked changed, no diff is run, and a
# note says why. Its answer is cached apart from the same commit unflagged.
AUDIT_SHALLOW_JSON="$AUDIT_NET/shallow.json"
python3 - "$PROJECT_DIR" "$AUDIT_SHALLOW_JSON" "$AUDIT_ASM" "$AUDIT_ASM_SECOND" <<'PY_AUDIT_SHALLOW'
import json
import sys

from branchlens import gitops

output_path, repo, sha = sys.argv[2:]
if not hasattr(gitops, "SHALLOW_BOUNDARY_SENTENCE"):
    gitops.SHALLOW_BOUNDARY_SENTENCE = "Stand-in sentence for the shallow boundary."
original_read = gitops.read_graph_commits
original_paths = gitops.collect_commit_paths
path_lookups = []


def flagged_read(repo_root, *args, **kwargs):
    commits = original_read(repo_root, *args, **kwargs)
    for commit in commits:
        if commit["sha"] == sha:
            commit["shallow_boundary"] = True
    return commits


def recording_paths(repo_root, commit):
    path_lookups.append(commit["sha"])
    return original_paths(repo_root, commit)


gitops.collect_commit_paths = recording_paths
gitops.read_graph_commits = flagged_read
boundary = gitops.get_network(repo, sha)
results = {
    "first_note": boundary["notes"][0] == gitops.SHALLOW_BOUNDARY_SENTENCE,
    "changed_files": boundary["counts"]["changed_files"],
    "changed_nodes": [n["path"] for n in boundary["nodes"] if n["changed_in_commit"]],
    "path_lookups": len(path_lookups),
}
gitops.read_graph_commits = original_read
plain = gitops.get_network(repo, sha)
results["plain_changed"] = [n["path"] for n in plain["nodes"] if n["changed_in_commit"]]
results["plain_has_sentence"] = gitops.SHALLOW_BOUNDARY_SENTENCE in plain["notes"]
handle = open(output_path, "w")
json.dump(results, handle)
handle.close()
PY_AUDIT_SHALLOW
check "audit: the shallow-boundary checks ran" $?
json_check "audit: a shallow boundary commit marks no file changed, runs no diff, and says why first" "$AUDIT_SHALLOW_JSON" \
  'data["first_note"] is True and data["changed_files"] == 0 and data["changed_nodes"] == [] and data["path_lookups"] == 0'
json_check "audit: the same commit without the flag is built apart, with its changed file" "$AUDIT_SHALLOW_JSON" \
  'data["plain_changed"] == ["touch.py"] and data["plain_has_sentence"] is False'

# ---------------------------------------------------------------- tree listing cap
# 50101 index entries pointing at one blob: only 50000 are looked at, and
# the response says so instead of indexing all of them.

CAP_REPO="$FIXTURE/treecaprepo"
new_repo "$CAP_REPO"
CAP_BLOB=$(printf 'import os\n' | git -C "$CAP_REPO" hash-object -w --stdin)
python3 -c "
import sys
blob = sys.argv[1]
lines = ['100644 blob %s\ta.py' % blob]
for i in range(50100):
    lines.append('100644 blob %s\tf%05d.txt' % (blob, i))
sys.stdout.write('\n'.join(lines) + '\n')
" "$CAP_BLOB" | git -C "$CAP_REPO" update-index --index-info
CAP_TREE=$(git -C "$CAP_REPO" write-tree)
set_commit_date "2026-06-01T10:08:00 +0000"
CAP_SHA=$(git -C "$CAP_REPO" commit-tree "$CAP_TREE" -m "many entries")
git -C "$CAP_REPO" update-ref refs/heads/main "$CAP_SHA"
CAP_LOG="$FIXTURE/server-treecap.log"
CAP_PORT=$(start_extra_server "$CAP_REPO" "$CAP_LOG")
check "tree cap: server starts on the 50101-entry repository" $?
CAP_BODY="$FIXTURE/treecap.json"
expect_get "$CAP_PORT" "$CAP_BODY" "/api/network?commit=$CAP_SHA" "200" "tree cap: /api/network returns HTTP 200"
json_check "tree cap: 101 entries were not listed, the graph is marked truncated and a note says so" "$CAP_BODY" \
  'data["excluded"]["unlisted"] == 101 and data["truncated"] is True and any("not even listed" in n for n in data["notes"])'

# ---------------------------------------------------------------- counts after the caches
# ahead/behind is cached per pair of commits: a new commit must still move it.

git -C "$TOKEN_REPO" checkout -q -b counted
set_commit_date "2026-06-01T10:09:00 +0000"
git -C "$TOKEN_REPO" commit -q -am "first on counted"
COUNT_BODY="$FIXTURE/count.json"
STATUS=$(http_get "$TOKEN_PORT" "$COUNT_BODY" "/api/state")
json_check "counts: a new branch is one ahead" "$COUNT_BODY" \
  '[b["ahead"] for b in data["branches"] if b["name"] == "counted"] == [1]'
set_commit_date "2026-06-01T10:10:00 +0000"
printf 'more\n' >> "$TOKEN_REPO/file.txt"
git -C "$TOKEN_REPO" commit -q -am "second on counted"
STATUS=$(http_get "$TOKEN_PORT" "$COUNT_BODY" "/api/state")
json_check "counts: a second commit moves the cached count to two" "$COUNT_BODY" \
  '[b["ahead"] for b in data["branches"] if b["name"] == "counted"] == [2]'

# Untracked files are counted in Python now; the numbers must be git's.
printf 'a\nb\nc' > "$TOKEN_REPO/nonewline.txt"
printf '\x00\x01binary\n' > "$TOKEN_REPO/blob.bin"
printf 'x\r\ny\r\n' > "$TOKEN_REPO/crlf.txt"
expect_get "$TOKEN_PORT" "$COUNT_BODY" "/api/diff?branch=counted" "200" "untracked counts: /api/diff returns HTTP 200"
json_check "untracked counts: a last line without a newline still counts, CRLF counts per line, a NUL means binary" "$COUNT_BODY" \
  '{f["path"]: (f["adds"], f["binary"]) for f in data["files"] if f["path"] in ("nonewline.txt", "blob.bin", "crlf.txt")} == {"nonewline.txt": (3, False), "blob.bin": (None, True), "crlf.txt": (2, False)}'
GIT_NONL=$(git -C "$TOKEN_REPO" diff --no-index --numstat -- /dev/null "$TOKEN_REPO/nonewline.txt" | cut -f1)
[ "$GIT_NONL" = "3" ]
check "untracked counts: git itself counts the no-newline file the same way" $?

# Counts are cached per file: a rewrite of the same size must still be recounted.
# The cache key holds the file's timestamps; the wait covers filesystems
# that keep them to the second.
sleep 1.1
printf 'abcd\n' > "$TOKEN_REPO/nonewline.txt"
expect_get "$TOKEN_PORT" "$COUNT_BODY" "/api/diff?branch=counted" "200" "untracked counts: /api/diff after a same-size rewrite returns HTTP 200"
json_check "untracked counts: a same-size rewrite is counted again, not served from the cache" "$COUNT_BODY" \
  '[f["adds"] for f in data["files"] if f["path"] == "nonewline.txt"] == [1]'

# ------------------------------------------------- network legend, capped graph
# On a capped graph the legend says how many source files went unread, so the
# over-600-files line says "Nothing was dropped" only when nothing was capped.

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

text = open(sys.argv[1]).read()
start = text.index("if (networkLayout.nodes.length > NETWORK_HARD_NODES)")
block = text[start:start + 1200]
# The explanatory comment names the sentence too; judge the code alone.
block = "\n".join(line for line in block.split("\n")
                  if not line.strip().startswith("//"))

if "Nothing was dropped" not in block:
    sys.exit(1)                      # the sentence moved; this test is stale
if "currentNetwork.truncated" not in block:
    sys.exit(1)                      # unguarded again
# The bare claim must sit after the truncation test, i.e. in the else branch.
if block.index("Nothing was dropped") < block.index("currentNetwork.truncated"):
    sys.exit(1)
sys.exit(0)
PY
check "network: the \"nothing was dropped\" line is conditional on truncation" $?

# ---------------------------------------------------------------- run, cancel and push
# Starting the security pipeline from the page, and the one write BranchLens
# makes: a push after READY TO PUBLISH on the branch's current tip. A fake
# toolkit stands in for the pipeline and a local bare repository is the
# remote. The blocked host is a placeholder under the reserved .example domain.

RUN_ORIGIN="$FIXTURE/run-origin.git"
RUN_REPO="$FIXTURE/runrepo"
RUN_WT="$FIXTURE/runrepo-feature"
RUN_REPORTS="$FIXTURE/run-reports"
RUN_FEED="$RUN_REPORTS/security-feed.jsonl"
TOOLKIT="$FIXTURE/fake-toolkit"

set_commit_date "2026-02-01T10:00:00 +0000"
git init -q --bare -b main "$RUN_ORIGIN"
new_repo "$RUN_REPO"
printf 'print("run fixture")\n' > "$RUN_REPO/app.py"
git -C "$RUN_REPO" add -A
git -C "$RUN_REPO" commit -q -m "Run fixture: first commit"
git -C "$RUN_REPO" remote add origin "$RUN_ORIGIN"
# Publishing main gives the repository an origin/main: the default base.
git -C "$RUN_REPO" push -q origin main
git -C "$RUN_REPO" branch no-worktree
git -C "$RUN_REPO" worktree add -q -b feature "$RUN_WT"
set_commit_date "2026-02-01T10:01:00 +0000"
printf 'def feature():\n    return 1\n' > "$RUN_WT/feature.py"
git -C "$RUN_WT" add -A
git -C "$RUN_WT" commit -q -m "Feature work"

mkdir -p "$TOOLKIT"
cat > "$TOOLKIT/preflight.sh" <<'FAKE'
#!/bin/bash
# Fake security toolkit. `preflight.sh run <repo> [base]` writes feed events
# and a run folder with verdict.json the way the real one does, then exits
# 0 (READY TO PUBLISH) or 1 (DO NOT PUBLISH), or 2 when stopped by SIGTERM.
# A `knobs` file next to it changes what it does without a server restart:
# FAKE_VERDICT, FAKE_REVIEW_MERGED (true or false), FAKE_REVIEW_CONFIRMED
# (true, false, or absent to leave the key out), FAKE_BLOCKING_FINDING (set:
# the feed gets a blocking finding before the verdict; nofile: one that
# names no file), FAKE_SLEEP (seconds
# the review takes), FAKE_GATE_SLEEP (seconds the mechanical checks take)
# and FAKE_TERM_SILENT (on SIGTERM, exit without writing a verdict).
toolkit_dir=$(cd "$(dirname "$0")" && pwd)
if [ "$1" != "run" ] || [ -z "$2" ]; then
  echo "usage: preflight.sh run <repository> [base-ref]" >&2
  exit 4
fi
FAKE_VERDICT="READY TO PUBLISH"
FAKE_REVIEW_MERGED=true
FAKE_REVIEW_CONFIRMED=true
FAKE_BLOCKING_FINDING=""
FAKE_SLEEP=""
FAKE_GATE_SLEEP=""
FAKE_TERM_SILENT=""
if [ -f "$toolkit_dir/knobs" ]; then
  . "$toolkit_dir/knobs"
fi
# Record how BranchLens started this run, for the test to compare.
python3 -c '
import json, os, sys
with open(sys.argv[1], "w") as handle:
    json.dump({"args": sys.argv[2:], "cwd": os.getcwd(),
               "reports_dir": os.environ.get("PREFLIGHT_REPORTS_DIR")}, handle)
' "$toolkit_dir/last-call.json" "$@"
echo "$$" > "$toolkit_dir/run.pid"

repo="$2"
base="${3:-origin/main}"
root="${PREFLIGHT_REPORTS_DIR:?PREFLIGHT_REPORTS_DIR must be set}"
feed="$root/security-feed.jsonl"
sha=$(git -C "$repo" rev-parse HEAD)
short=$(git -C "$repo" rev-parse --short HEAD)
branch=$(git -C "$repo" rev-parse --abbrev-ref HEAD)
stamp=$(date -u +%Y-%m-%dT%H-%M-%SZ)
run_dir="$root/$stamp-$short"
n=1
while [ -e "$run_dir" ]; do
  n=$((n + 1))
  run_dir="$root/$stamp-$short-$n"
done
mkdir -p "$run_dir"
run_id=$(basename "$run_dir")

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
emit() { printf '%s\n' "$1" >> "$feed"; }
# $1 verdict word, $2 exit code, $3 review_merged, $4 review_confirmed
# (true or false; absent or empty leaves the key out).
write_verdict() {
  local confirmed=""
  if [ "${4:-absent}" != "absent" ]; then
    confirmed='"review_confirmed": '"$4"', '
  fi
  printf '{"verdict": "%s", "exit_code": %s, "review_merged": %s, %s"mode": "check", "base_ref": "%s", "repository": {"path": "%s", "branch": "%s", "commit": "%s"}}\n' \
    "$1" "$2" "$3" "$confirmed" "$base" "$repo" "$branch" "$sha" > "$run_dir/verdict.json"
}

# SIGTERM (Cancel) ends the run the way the real toolkit does: a cancelled
# INCONCLUSIVE verdict in the feed, exit code 2.
on_term() {
  if [ -z "$FAKE_TERM_SILENT" ]; then
    emit '{"event":"verdict","utc":"'"$(now)"'","text":"PIPELINE: INCONCLUSIVE — the run was cancelled","verdict":"INCONCLUSIVE"}'
  fi
  echo "cancelled"
  exit 2
}
trap on_term TERM

echo "preflight check - repository: $repo"
echo "base ref: $base"
echo "report in: $run_dir"
emit '{"event":"start","utc":"'"$(now)"'","run_id":"'"$run_id"'","base":"'"$base"'","files":["feature.py"]}'
# review-scope.json before the checks, as the real gate writes it: the
# judged history starts after fork_commit (the empty tree for empty-tree).
if [ "$base" = "empty-tree" ]; then
  fork=$(git -C "$repo" hash-object -t tree /dev/null)
else
  fork=$(git -C "$repo" merge-base "$base" HEAD)
fi
printf '{"scope_format": 2, "base_ref": "%s", "fork_commit": "%s", "head_commit": "%s", "snapshot": false}\n' \
  "$base" "$fork" "$sha" > "$run_dir/review-scope.json"
emit '{"event":"phase","utc":"'"$(now)"'","name":"gate","status":"running"}'
emit '{"event":"check","utc":"'"$(now)"'","stage":"gate","name":"Exceptions file","status":"running"}'
emit '{"event":"check","utc":"'"$(now)"'","stage":"gate","name":"Secrets","status":"running"}'
if [ -n "$FAKE_GATE_SLEEP" ]; then
  sleep "$FAKE_GATE_SLEEP" &
  gate_sleep_pid=$!
  echo "$gate_sleep_pid" > "$toolkit_dir/sleep.pid"
  wait "$gate_sleep_pid"
fi
emit '{"event":"check","utc":"'"$(now)"'","stage":"gate","name":"Secrets","status":"done","result":"TESTED","blocking":false,"detail":"no secret in the diff","seconds":0.02}'
emit '{"event":"check","utc":"'"$(now)"'","stage":"gate","name":"Exceptions file","status":"done","result":"NOT APPLICABLE","blocking":false,"detail":"no exceptions file","seconds":0.01}'
emit '{"event":"phase","utc":"'"$(now)"'","name":"gate","status":"done","detail":"PASSED"}'
write_verdict "PASSED" 0 false
emit '{"event":"verdict","utc":"'"$(now)"'","text":"PREFLIGHT: PASSED — 2 checks","verdict":"PASSED"}'
echo "gate passed"
emit '{"event":"phase","utc":"'"$(now)"'","name":"review","status":"running","detail":"LLM review of the diff"}'
if [ -n "$FAKE_SLEEP" ]; then
  # Sleep in the background and `wait`: a trap cannot interrupt a foreground
  # command, but it does interrupt `wait`.
  sleep "$FAKE_SLEEP" &
  sleep_pid=$!
  echo "$sleep_pid" > "$toolkit_dir/sleep.pid"
fi
emit '{"event":"check","utc":"'"$(now)"'","stage":"review","name":"REV-01 SQL injection (OWASP A03)","status":"running"}'
if [ -n "$FAKE_SLEEP" ]; then
  wait "$sleep_pid"
fi
emit '{"event":"check","utc":"'"$(now)"'","stage":"review","name":"REV-01 SQL injection (OWASP A03)","status":"done","count":0}'
emit '{"event":"check","utc":"'"$(now)"'","stage":"verify","name":"Example finding (feature.py)","status":"running"}'
emit '{"event":"check","utc":"'"$(now)"'","stage":"verify","name":"Example finding (feature.py)","status":"done"}'
if [ "$FAKE_VERDICT" = "READY TO PUBLISH" ]; then
  code=0
else
  code=1
fi
if [ "$FAKE_BLOCKING_FINDING" = "nofile" ]; then
  emit '{"event":"finding","utc":"'"$(now)"'","severity":"high","title":"Secret in the build log","outcome":"CONFIRMED","blocking":true}'
elif [ -n "$FAKE_BLOCKING_FINDING" ]; then
  emit '{"event":"finding","utc":"'"$(now)"'","file":"feature.py","line":2,"severity":"high","title":"SQL injection in the query builder","outcome":"CONFIRMED","blocking":true}'
fi
write_verdict "$FAKE_VERDICT" "$code" "$FAKE_REVIEW_MERGED" "$FAKE_REVIEW_CONFIRMED"
emit '{"event":"phase","utc":"'"$(now)"'","name":"review","status":"done","detail":"'"$FAKE_VERDICT"'"}'
emit '{"event":"verdict","utc":"'"$(now)"'","text":"PIPELINE: '"$FAKE_VERDICT"' — fake run","verdict":"'"$FAKE_VERDICT"'"}'
echo "PIPELINE: $FAKE_VERDICT"
exit $code
FAKE
chmod +x "$TOOLKIT/preflight.sh"

RUN_LOG="$FIXTURE/server-run.log"
python3 -m branchlens "$RUN_REPO" --port 0 --no-browser \
  --toolkit "$TOOLKIT" --security-feed "$RUN_FEED" \
  --no-push-host work.example > "$RUN_LOG" 2>&1 &
RUN_SERVER_PID=$!
echo "$RUN_SERVER_PID" >> "$FIXTURE/extra-pids"
RUN_PORT=$(wait_for_server "$RUN_LOG")
check "run: server starts with a toolkit, a feed and a blocked push host" $?

RUN_SEC="$FIXTURE/run-security.json"
POST_BODY="$FIXTURE/post-response.json"

# Start a check on a branch and wait for it to end. $1: the JSON body.
run_check_and_wait() {
  local request_body="$1"
  local status
  status=$(http_post "$RUN_PORT" "$POST_BODY" "/api/run" "$RUN_TOKEN" \
    "application/json" "$request_body")
  [ "$status" = "200" ] && wait_for_security "$RUN_PORT" 'data["runner"]["active"] is False'
}

# A READY TO PUBLISH verdict.json in folder $1, for commit $2 of feature,
# as a run started from a terminal would leave it.
write_ready_verdict() {
  mkdir -p "$1"
  printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "review_merged": true, "review_confirmed": true, "mode": "check", "base_ref": "origin/main", "repository": {"branch": "feature", "commit": "%s"}}\n' \
    "$2" > "$1/verdict.json"
}

# ---- the served page ----------------------------------------------------------

RUN_PAGE="$FIXTURE/run-page.html"
RUN_HEADERS="$FIXTURE/run-page-headers.txt"
curl -s -m 5 -b "$(cookie_for "$RUN_PORT")" -D "$RUN_HEADERS" -o "$RUN_PAGE" "http://127.0.0.1:$RUN_PORT/"
RUN_TOKEN=$(page_token "$RUN_PORT")
RUN_COOKIE_SECRET=$(cat "$FIXTURE/cookies/$RUN_PORT")
RUN_LAUNCH_CODE=$(cat "$FIXTURE/launch-codes/$RUN_PORT")
[ "${#RUN_TOKEN}" -eq 64 ] && [ "${#RUN_COOKIE_SECRET}" -eq 64 ] && [ "${#RUN_LAUNCH_CODE}" -eq 64 ]
check "page: the printed URL hands over a 64-hex-digit cookie secret and page token" $?
[ "$RUN_TOKEN" != "$RUN_COOKIE_SECRET" ] && [ "$RUN_TOKEN" != "$RUN_LAUNCH_CODE" ] \
  && [ "$RUN_COOKIE_SECRET" != "$RUN_LAUNCH_CODE" ]
check "page: the launch code, the cookie secret and the page token are three different values" $?
# Browsers send the cookie to every port of 127.0.0.1, so whatever the
# cookie alone unlocks may reach another local server: never the page token.
grep -q "<title>BranchLens</title>" "$RUN_PAGE" && ! grep -q "$RUN_TOKEN" "$RUN_PAGE" \
  && ! grep -q "branchlens-token" "$RUN_PAGE" && ! grep -q "$RUN_LAUNCH_CODE" "$RUN_PAGE"
check "page: the page the cookie unlocks holds neither the page token nor the launch code" $?
grep -qi '^X-Frame-Options: *DENY' "$RUN_HEADERS"
check "page: the page is served with X-Frame-Options: DENY" $?
grep -qi '^Cache-Control: *no-store' "$RUN_HEADERS"
check "page: the page is served with Cache-Control: no-store" $?
[ -n "$FEED_ONLY_TOKEN" ] && [ "$RUN_TOKEN" != "$FEED_ONLY_TOKEN" ]
check "page: every server start makes a new token" $?

# ---- before any run -------------------------------------------------------------

http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "run: before any run there are no steps and the runner is idle" "$RUN_SEC" \
  'data["enabled"] is True and data["checks"] == [] and data["runner"] == {"available": True, "unavailable_reason": None, "active": False, "branch": None, "started_utc": None, "exit_code": None, "run_id": None, "log_tail": None}'
json_check "run: before any run no push is allowed" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "No security check has run yet." and data["push"]["pushed"] is None'
json_check "run: before any run nothing has been judged" "$RUN_SEC" \
  'data["judged"] is None'

# ---- POST rules -----------------------------------------------------------------
# Each refused request is otherwise a valid /api/run; the check after the
# list confirms that none of them started a run.

# $1 description, $2 expected HTTP status, $3 expected error sentence, then
# http_post's arguments without the port and body file: path, token,
# content type, body, extra curl arguments.
expect_post_error() {
  local description="$1"
  local expected_status="$2"
  local expected_error="$3"
  shift 3
  local status
  status=$(http_post "$RUN_PORT" "$POST_BODY" "$@")
  [ "$status" = "$expected_status" ]
  check "$description: HTTP $expected_status" $?
  json_check "$description: exact error" "$POST_BODY" 'data["error"] == extra' "$expected_error"
}

RUN_BODY='{"branch": "feature"}'
TOKEN_ERROR="Missing or outdated page token: open the URL BranchLens printed in the terminal again."
JSON_ERROR="Only JSON requests are accepted."
ORIGIN_ERROR="Requests from other web pages are refused."
NO_ORIGIN_ERROR="Requests that do not say which page sent them (Origin) are refused."
POST_NO_COOKIE_ERROR="Missing or outdated access cookie: open the URL BranchLens printed in the terminal when it started."
expect_post_error "post rules: no token" 403 "$TOKEN_ERROR" \
  /api/run "" "application/json" "$RUN_BODY"
expect_post_error "post rules: a wrong token" 403 "$TOKEN_ERROR" \
  /api/run "0000000000000000000000000000000000000000000000000000000000000000" \
  "application/json" "$RUN_BODY"
expect_post_error "post rules: another server's token" 403 "$TOKEN_ERROR" \
  /api/run "$FEED_ONLY_TOKEN" "application/json" "$RUN_BODY"
expect_post_error "post rules: Content-Type text/plain" 403 "$JSON_ERROR" \
  /api/run "$RUN_TOKEN" "text/plain" "$RUN_BODY"
expect_post_error "post rules: a form-encoded body" 403 "$JSON_ERROR" \
  /api/run "$RUN_TOKEN" "application/x-www-form-urlencoded" "branch=feature"
expect_post_error "post rules: no Content-Type" 403 "$JSON_ERROR" \
  /api/run "$RUN_TOKEN" "" "$RUN_BODY"
expect_post_error "post rules: a foreign Origin" 403 "$ORIGIN_ERROR" \
  /api/run "$RUN_TOKEN" "application/json" "$RUN_BODY" -H "Origin: http://evil.example"
expect_post_error "post rules: Origin null" 403 "$ORIGIN_ERROR" \
  /api/run "$RUN_TOKEN" "application/json" "$RUN_BODY" -H "Origin: null"
expect_post_error "post rules: an Origin on another port" 403 "$ORIGIN_ERROR" \
  /api/run "$RUN_TOKEN" "application/json" "$RUN_BODY" -H "Origin: http://127.0.0.1:1"
expect_post_error "post rules: an https Origin" 403 "$ORIGIN_ERROR" \
  /api/run "$RUN_TOKEN" "application/json" "$RUN_BODY" -H "Origin: https://127.0.0.1:$RUN_PORT"
# Browsers send Origin with every POST; a request without it is not the page.
expect_post_error "post rules: the cookie and the token but no Origin" 403 "$NO_ORIGIN_ERROR" \
  /api/run "$RUN_TOKEN" "application/json" "$RUN_BODY" -H "Origin:"
expect_post_error "post rules: the cookie secret sent as the page token" 403 "$TOKEN_ERROR" \
  /api/run "$RUN_COOKIE_SECRET" "application/json" "$RUN_BODY"
expect_post_error "post rules: the launch code sent as the page token" 403 "$TOKEN_ERROR" \
  /api/run "$RUN_LAUNCH_CODE" "application/json" "$RUN_BODY"

# A server on another port of 127.0.0.1 that the browser visits receives the
# cookie. With its value alone, sent as the token and with the right Origin,
# a POST must fail; so must the right page token without the cookie.
# $1 description, $2 the token header.
expect_post_without_cookie() {
  local status
  rm -f "$POST_BODY"
  status=$(curl -s -m 10 -o "$POST_BODY" -w '%{http_code}' \
    -H "X-BranchLens-Token: $2" -H "Content-Type: application/json" \
    -H "Origin: http://127.0.0.1:$RUN_PORT" --data-binary "$RUN_BODY" \
    "http://127.0.0.1:$RUN_PORT/api/run")
  [ "$status" = "403" ]
  check "$1: HTTP 403" $? "got HTTP $status"
  json_check "$1: says the cookie is missing" "$POST_BODY" 'data["error"] == extra' "$POST_NO_COOKIE_ERROR"
}
expect_post_without_cookie "post rules: the cookie's value as the token, with no cookie" "$RUN_COOKIE_SECRET"
expect_post_without_cookie "post rules: the page token with no cookie" "$RUN_TOKEN"
# GETs need the cookie: the page token is no way in.
STATUS=$(curl -s -m 5 -o "$POST_BODY" -w '%{http_code}' -H "X-BranchLens-Token: $RUN_TOKEN" \
  "http://127.0.0.1:$RUN_PORT/api/state")
expect_status "403" "post rules: a GET with the page token but no cookie answers HTTP 403" "got HTTP $STATUS"
expect_post_error "post rules: a foreign Host" 403 "Requests are only accepted from this machine." \
  /api/run "$RUN_TOKEN" "application/json" "$RUN_BODY" -H "Host: evil.example:$RUN_PORT"
expect_post_error "post rules: a JSON array body" 400 "The request body must be a JSON object." \
  /api/run "$RUN_TOKEN" "application/json" '[1, 2]'
expect_post_error "post rules: a body that is not JSON" 400 "The request body must be a JSON object." \
  /api/run "$RUN_TOKEN" "application/json" 'not json'
BIG_BODY=$(python3 -c 'print("{\"branch\": \"feature\", \"pad\": \"" + "a" * 70000 + "\"}")')
expect_post_error "post rules: a body over 64 KiB" 400 "The request body must be a JSON object." \
  /api/run "$RUN_TOKEN" "application/json" "$BIG_BODY"
expect_post_error "post rules: POST to a GET route" 404 "No such API route: /api/state" \
  /api/state "$RUN_TOKEN" "application/json" '{}'

# GET on a POST route is an unknown page, never a run.
expect_get "$RUN_PORT" "$POST_BODY" "/api/run" "404" "post rules: GET /api/run answers HTTP 404"
json_check "post rules: GET /api/run names the unknown route" "$POST_BODY" \
  'data["error"] == "No such page or API route: /api/run"'

# A browser sends OPTIONS before a cross-site JSON POST; the server has no
# do_OPTIONS, so it answers 501 with no CORS header.
OPTIONS_HEADERS="$FIXTURE/options-headers.txt"
STATUS=$(curl -s -m 5 -X OPTIONS -D "$OPTIONS_HEADERS" -o /dev/null -w '%{http_code}' \
  -H "Origin: http://evil.example" -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type, x-branchlens-token" \
  "http://127.0.0.1:$RUN_PORT/api/run")
expect_status "501" "post rules: a CORS preflight (OPTIONS) answers HTTP 501"
[ "$STATUS" = "501" ] && ! grep -qi '^Access-Control-' "$OPTIONS_HEADERS"
check "post rules: the preflight answer carries no Access-Control header" $? "got HTTP $STATUS"

# The accepted forms, on /api/cancel: with nothing running it only answers.
expect_post_ok() {
  # $1 description, then http_post's arguments without the port and body file
  local description="$1"
  shift 1
  local status
  status=$(http_post "$RUN_PORT" "$POST_BODY" "$@")
  [ "$status" = "200" ]
  check "$description: HTTP 200" $?
  json_check "$description: nothing to cancel" "$POST_BODY" 'data == {"cancelled": False}'
}
expect_post_ok "post rules: the page's own request (cookie, token, Origin) is accepted" \
  /api/cancel "$RUN_TOKEN" "application/json" '{}'
expect_post_ok "post rules: Origin http://127.0.0.1:<port> is accepted" \
  /api/cancel "$RUN_TOKEN" "application/json" '{}' -H "Origin: http://127.0.0.1:$RUN_PORT"
expect_post_ok "post rules: Origin http://localhost:<port> is accepted" \
  /api/cancel "$RUN_TOKEN" "application/json" '{}' -H "Origin: http://localhost:$RUN_PORT"
expect_post_ok "post rules: Host localhost, a charset parameter and an empty body are accepted" \
  /api/cancel "$RUN_TOKEN" "application/json; charset=utf-8" '' -H "Host: localhost:$RUN_PORT"

[ ! -e "$RUN_FEED" ] && [ ! -e "$TOOLKIT/last-call.json" ]
check "post rules: none of the refused requests started a run" $?

# ---- /api/run refusals ------------------------------------------------------------

expect_post_error "run: no branch" 400 "Missing 'branch'." \
  /api/run "$RUN_TOKEN" "application/json" '{}'
expect_post_error "run: a branch that is not a string" 400 "Missing 'branch'." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": 3}'
expect_post_error "run: an unknown branch" 400 "No branch named 'nope' was found." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "nope"}'
expect_post_error "run: a branch name that looks like an option" 400 "No branch named '-x' was found." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "-x"}'
expect_post_error "run: a branch with no worktree" 400 \
  "check this branch out in a worktree to run the pipeline on it" \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "no-worktree"}'
expect_post_error "run: a base that looks like an option" 400 "'-x' is not a commit in this repository." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "feature", "base": "-x"}'
expect_post_error "run: a base that is not a commit" 400 "'nonsense' is not a commit in this repository." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "feature", "base": "nonsense"}'
expect_post_error "run: a base that is not a string" 400 "'base' must be a string." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "feature", "base": 3}'
# main is where origin/main is: the run would judge an empty range.
expect_post_error "run: a branch with no commits its base lacks" 400 \
  "main has no commits that origin/main lacks, so there is nothing to check: the check judges commits, not uncommitted edits." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "main"}'
expect_post_error "run: a branch already contained in the given base" 400 \
  "main has no commits that feature lacks, so there is nothing to check: the check judges commits, not uncommitted edits." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "main", "base": "feature"}'
[ ! -e "$TOOLKIT/last-call.json" ]
check "run: none of the refused runs reached the toolkit" $?

# ---- a READY TO PUBLISH run ---------------------------------------------------------

STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/run" "$RUN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "200" "run: starting a check on a worktree branch answers HTTP 200"
json_check "run: the answer names the branch and the default base" "$POST_BODY" \
  'data == {"started": True, "branch": "feature", "base": "origin/main"}'
wait_for_security "$RUN_PORT" 'data["runner"]["active"] is False'
check "run: the fake pipeline finishes" $?

http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "run: the runner reports the branch, start time and exit code 0" "$RUN_SEC" \
  'data["runner"]["available"] is True and data["runner"]["active"] is False and data["runner"]["branch"] == "feature" and data["runner"]["exit_code"] == 0 and len(data["runner"]["started_utc"]) == 20 and data["runner"]["started_utc"].endswith("Z")'
json_check "run: log_tail holds the end of the run's output" "$RUN_SEC" \
  'data["runner"]["log_tail"].startswith("preflight check - repository: ") and data["runner"]["log_tail"].endswith("PIPELINE: READY TO PUBLISH")'
json_check "run: the runner names its run by the report folder its log gives" "$RUN_SEC" \
  'data["runner"]["run_id"] is not None and data["runner"]["run_id"] == data["run_id"]'
json_check "run: a verdict.json with no areas list leaves the feed's areas and adds nothing" "$RUN_SEC" \
  'data["areas"] == [] and data["review_incomplete"] is None and data["mechanical_advisory"] is None'
json_check "run: the steps are listed in first-appearance order, all done" "$RUN_SEC" \
  '[c["name"] for c in data["checks"]] == ["Exceptions file", "Secrets", "REV-01 SQL injection (OWASP A03)", "Example finding (feature.py)"] and all(c["status"] == "done" for c in data["checks"])'
json_check "run: the gate step started first keeps its place and its final result" "$RUN_SEC" \
  'data["checks"][0]["result"] == "NOT APPLICABLE" and data["checks"][0]["seconds"] == 0.01'
json_check "run: the feed's verdict is READY TO PUBLISH" "$RUN_SEC" \
  'data["running"] is False and data["verdict_word"] == "READY TO PUBLISH"'
RUN_ORIGIN_MAIN=$(git -C "$RUN_REPO" rev-parse refs/remotes/origin/main)
json_check "run: preflight.sh got 'run', the branch's worktree and the base" "$TOOLKIT/last-call.json" \
  'data["args"][0] == "run" and os.path.realpath(data["args"][1]) == os.path.realpath(extra) and data["args"][2:] == ["'"$RUN_ORIGIN_MAIN"'"]' "$RUN_WT"
json_check "run: preflight.sh runs from the toolkit folder" "$TOOLKIT/last-call.json" \
  'os.path.realpath(data["cwd"]) == os.path.realpath(extra)' "$TOOLKIT"
json_check "run: PREFLIGHT_REPORTS_DIR is the folder of the watched feed" "$TOOLKIT/last-call.json" \
  'os.path.realpath(data["reports_dir"]) == os.path.realpath(extra)' "$RUN_REPORTS"
grep -q "PIPELINE: READY TO PUBLISH" "$RUN_REPORTS/branchlens-run-$RUN_SERVER_PID.log"
check "run: the run's output is written to branchlens-run-<server pid>.log in the reports folder" $?
[ ! -e "$RUN_REPORTS/branchlens-run.log" ]
check "run: no log is written under the name every server would share" $?

FEATURE_TIP=$(git -C "$RUN_WT" rev-parse HEAD)
json_check "push: allowed after READY TO PUBLISH on the branch's current tip" "$RUN_SEC" \
  'data["push"]["allowed"] is True and data["push"]["branch"] == "feature" and data["push"]["remote"] == "origin" and data["push"]["commit"] == extra and data["push"]["pushed"] is None and data["push"]["output"] is None' "$FEATURE_TIP"
json_check "push: the reason is the exact command, with the upstream step for a branch with no upstream" "$RUN_SEC" \
  'data["push"]["reason"] == "Will run git push --recurse-submodules=no --no-follow-tags origin " + extra + ":refs/heads/feature, then git branch --set-upstream-to=refs/remotes/origin/feature feature."' "$FEATURE_TIP"
json_check "judged: a finished run names the branch and commit its verdict.json records" "$RUN_SEC" \
  'data["judged"] == {"branch": "feature", "commit": extra}' "$FEATURE_TIP"
RUN_STATE="$FIXTURE/run-state.json"
http_get "$RUN_PORT" "$RUN_STATE" "/api/state" > /dev/null
json_check "state: each branch carries its tip, to compare with what was judged" "$RUN_STATE" \
  '[b["commit"] for b in data["branches"] if b["name"] == "feature"] == [extra]' "$FEATURE_TIP"

# ---- blocked push hosts ---------------------------------------------------------------
# The run above is READY on the tip, so only the host can refuse these.

# $1 description, $2 the host the reason must name.
expect_blocked_host() {
  local description="$1"
  local host="$2"
  local expected="Repositories on $host are pushed from another machine: port the change by hand."
  http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
  json_check "$description: push not allowed, the reason names the host" "$RUN_SEC" \
    'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$expected"
  local status
  status=$(http_post "$RUN_PORT" "$POST_BODY" "/api/push" "$RUN_TOKEN" \
    "application/json" '{"branch": "feature"}')
  [ "$status" = "409" ]
  check "$description: POST /api/push is refused with HTTP 409" $?
  json_check "$description: the refusal carries the same reason" "$POST_BODY" \
    'data == {"error": extra, "pushed": False}' "$expected"
}

git -C "$RUN_REPO" config remote.origin.pushurl "https://code.work.example/team/app.git"
expect_blocked_host "blocked host: a pushurl on the host" "code.work.example"
git -C "$RUN_REPO" config remote.origin.pushurl "git@scp.work.example:team/app.git"
expect_blocked_host "blocked host: an scp-like pushurl" "scp.work.example"
git -C "$RUN_REPO" config remote.origin.pushurl "https://CODE.Work.Example./team/app.git"
expect_blocked_host "blocked host: upper case and a trailing dot" "code.work.example"
git -C "$RUN_REPO" config remote.origin.pushurl "https://notwork.example/team/app.git"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
# Not blocked: the refusal is the later one, for a pushurl BranchLens cannot judge.
json_check "blocked host: a host that only ends in the same letters is not blocked" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"].startswith("Push is refused: origin pushes to a different address")'
git -C "$RUN_REPO" config --unset remote.origin.pushurl

git -C "$RUN_REPO" config "url.ssh://git@git.work.example/.insteadOf" "$RUN_ORIGIN"
expect_blocked_host "blocked host: an insteadOf rewrite of origin's URL" "git.work.example"
git -C "$RUN_REPO" config --unset "url.ssh://git@git.work.example/.insteadOf"
git -C "$RUN_REPO" config "url.ssh://git@push.work.example/.pushInsteadOf" "$RUN_ORIGIN"
expect_blocked_host "blocked host: a pushInsteadOf rewrite of origin's URL" "push.work.example"
git -C "$RUN_REPO" config --unset "url.ssh://git@push.work.example/.pushInsteadOf"

# origin is checked even when the branch tracks, and would push to, another remote.
RUN_MIRROR="$FIXTURE/run-mirror.git"
git init -q --bare -b main "$RUN_MIRROR"
git -C "$RUN_REPO" remote add mirror "$RUN_MIRROR"
git -C "$RUN_REPO" config branch.feature.remote mirror
git -C "$RUN_REPO" config branch.feature.merge refs/heads/feature
git -C "$RUN_REPO" config remote.origin.pushurl "https://code.work.example/team/app.git"
expect_blocked_host "blocked host: origin on the host while the branch tracks another remote" \
  "code.work.example"
git -C "$RUN_REPO" config --unset remote.origin.pushurl
git -C "$RUN_REPO" config --unset branch.feature.remote
git -C "$RUN_REPO" config --unset branch.feature.merge
git -C "$RUN_REPO" remote remove mirror

# With extensions.worktreeConfig a worktree has config the main checkout
# does not see. The push runs from the branch's worktree, so its remote is
# read from there as well.
git -C "$RUN_REPO" config extensions.worktreeConfig true
git -C "$RUN_WT" config --worktree remote.origin.pushurl "https://wt.work.example/team/app.git"
expect_blocked_host "blocked host: a pushurl set only in the branch's worktree config" \
  "wt.work.example"
git -C "$RUN_WT" config --worktree --unset remote.origin.pushurl
git -C "$RUN_REPO" config --unset extensions.worktreeConfig

! git --git-dir="$RUN_ORIGIN" rev-parse -q --verify refs/heads/feature > /dev/null
check "blocked host: no refused push reached the remote" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "blocked host: with the settings removed the push is allowed again" "$RUN_SEC" \
  'data["push"]["allowed"] is True and data["push"]["remote"] == "origin"'

# ---- a remote that pushes elsewhere than it fetches from ----------------------------------
# origin/main says what the fetch address has. A pushurl, or a second url,
# sends the push to a repository that may lack every older commit, which
# the check never judged (02 F-01).

RUN_PUBLIC="$FIXTURE/run-public.git"
git init -q --bare -b main "$RUN_PUBLIC"
PUSHURL_REASON="Push is refused: origin pushes to a different address than it fetches from, so BranchLens cannot tell what that address already has."
git -C "$RUN_REPO" config remote.origin.pushurl "$RUN_PUBLIC"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: a pushurl other than the fetch URL turns the push off" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$PUSHURL_REASON"
expect_post_error "pushurl: POST /api/push with a different pushurl" 409 "$PUSHURL_REASON" \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
[ -z "$(git --git-dir="$RUN_PUBLIC" for-each-ref)" ]
check "pushurl: the push address received nothing" $?
# A pushurl that names the fetch URL itself changes nothing.
git -C "$RUN_REPO" config remote.origin.pushurl "$RUN_ORIGIN"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: a pushurl equal to the fetch URL still allows the push" "$RUN_SEC" \
  'data["push"]["allowed"] is True'
git -C "$RUN_REPO" config --unset remote.origin.pushurl
# pushInsteadOf rewrites only the push address.
git -C "$RUN_REPO" config "url.$RUN_PUBLIC.pushInsteadOf" "$RUN_ORIGIN"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: a pushInsteadOf rewrite of the fetch URL turns the push off" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$PUSHURL_REASON"
git -C "$RUN_REPO" config --unset "url.$RUN_PUBLIC.pushInsteadOf"
# Two url entries: a fetch reads the first, a push goes to both.
git -C "$RUN_REPO" config --add remote.origin.url "$RUN_PUBLIC"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: a remote with two URLs turns the push off" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "Push is refused: origin pushes to 2 addresses, so BranchLens cannot tell what each of them already has."'
git -C "$RUN_REPO" config --unset remote.origin.url "$RUN_PUBLIC"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: with one URL again the push is allowed" "$RUN_SEC" \
  'data["push"]["allowed"] is True'
# git ignores the host of a file:// URL, so this pushurl writes to the local
# RUN_PUBLIC although host and path match the fetch URL.
git -C "$RUN_REPO" config remote.origin.url "https://code.example$RUN_PUBLIC"
git -C "$RUN_REPO" config remote.origin.pushurl "file://code.example$RUN_PUBLIC"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: a file:// pushurl with the fetch URL's host and path is refused" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$PUSHURL_REASON"
expect_post_error "pushurl: POST /api/push with a file:// pushurl" 409 "$PUSHURL_REASON" \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
[ -z "$(git --git-dir="$RUN_PUBLIC" for-each-ref)" ]
check "pushurl: the file:// address received nothing" $?
git -C "$RUN_REPO" config --unset remote.origin.pushurl

# The same repository over another transport, such as https to fetch and
# ssh to push, is allowed. Only /api/security is asked here: a POST would
# try to reach code.example.
SAME_REPO_FETCH="https://code.example/team/app.git"
git -C "$RUN_REPO" config remote.origin.url "$SAME_REPO_FETCH"
git -C "$RUN_REPO" config remote.origin.pushurl "git@code.example:team/app.git"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: an ssh pushurl to the repository origin fetches over https is allowed" "$RUN_SEC" \
  'data["push"]["allowed"] is True'
git -C "$RUN_REPO" config --unset remote.origin.pushurl
git -C "$RUN_REPO" config "url.git@code.example:.pushInsteadOf" "https://code.example/"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: a pushInsteadOf rewrite to ssh for the same repository is allowed" "$RUN_SEC" \
  'data["push"]["allowed"] is True'
git -C "$RUN_REPO" config --unset "url.git@code.example:.pushInsteadOf"
git -C "$RUN_REPO" config remote.origin.pushurl "git@other.example:team/app.git"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: the same path on another host is refused" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$PUSHURL_REASON"
git -C "$RUN_REPO" config remote.origin.pushurl "git@code.example:team/other.git"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: another path on the same host is refused" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$PUSHURL_REASON"
git -C "$RUN_REPO" config remote.origin.pushurl "git@code.example:team/app.git"
git -C "$RUN_REPO" config --add remote.origin.pushurl "ssh://git@code.example/team/app"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: two pushurls are refused, even to the same repository" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"].startswith("Push is refused: origin pushes to")'
git -C "$RUN_REPO" config --unset-all remote.origin.pushurl
git -C "$RUN_REPO" config remote.origin.url "$RUN_ORIGIN"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "pushurl: with origin's own URL again the push is allowed" "$RUN_SEC" \
  'data["push"]["allowed"] is True'

python3 - "$PROJECT_DIR" <<'PY'
import sys

from branchlens import publish

expected = {
    "https://code.example/team/app.git": ("code.example", "team/app"),
    "https://user@Code.Example:8443/team/app/": ("code.example", "team/app"),
    "ssh://git@code.example:22/team/app.git": ("code.example", "team/app"),
    "git@code.example:team/app.git": ("code.example", "team/app"),
    "code.example:team/app": ("code.example", "team/app"),
    "code.example:/team/app": None,
    "/srv/git/app.git": None,
    "file:///srv/git/app.git": None,
    "file://code.example/team/app": None,
    "foo://code.example/team/app": None,
    "https://code.example/team/./app": None,
    "https://code.example/team/x/../app": None,
    "https://code.example": None,
    "https://code.example/team/%61pp": None,
    "git@code.example:~/app.git": None,
}
wrong = []
for url, pair in expected.items():
    if publish.url_repository(url) != pair:
        wrong.append((url, publish.url_repository(url)))
same = [
    (["https://code.example/team/app.git"], ["git@code.example:team/app.git"], True),
    (["https://code.example/team/app.git"], ["git@other.example:team/app.git"], False),
    (["https://code.example/team/app.git"], ["git@code.example:team/app.git", "ssh://code.example/team/app"], False),
    (["/srv/git/app.git"], ["/srv/git/app"], False),
    (["https://code.example/team/app.git"], ["file://code.example/team/app"], False),
    (["https://code.example/team/app"], ["https://code.example:9999/team/app"], False),
    (["https://code.example/team/app"], ["https://code.example:443/team/app.git"], True),
    (["https://code.example/team/app"], ["ssh://git@code.example:2222/team/app"], True),
    (["git@code.example:team/app.git"], ["alice@code.example:team/app.git"], False),
    (["git@code.example:team/app.git"], ["ssh://git@code.example/team/app"], True),
    (["ssh://git@code.example/team/app"], ["ssh://git@code.example:2222/team/app"], False),
    (["https://code.example/team/app"], ["https://code.example:x/team/app"], False),
]
for fetch_urls, push_urls, answer in same:
    if publish.same_repository(fetch_urls, push_urls) is not answer:
        wrong.append((fetch_urls, push_urls))
for item in wrong:
    print("  wrong:", item)
sys.exit(1 if wrong else 0)
PY
check "pushurl: url_repository and same_repository read host and path, and refuse local paths, other schemes, another port or ssh user over one scheme, and more than one URL" $?
[ -z "$(git --git-dir="$RUN_PUBLIC" for-each-ref)" ]
check "pushurl: the second address received nothing" $?

# ---- /api/push refusals and a successful push ---------------------------------------------

expect_post_error "push: another branch than the one checked" 409 \
  "The latest security check judged feature, not main." \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "main"}'
expect_post_error "push: no branch" 400 "Missing 'branch'." \
  /api/push "$RUN_TOKEN" "application/json" '{}'

STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/push" "$RUN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "200" "push: a push after READY TO PUBLISH answers HTTP 200"
json_check "push: the push succeeds and returns git's own output" "$POST_BODY" \
  'data["pushed"] is True and extra + " -> feature" in data["output"]' "$FEATURE_TIP"
[ "$(git --git-dir="$RUN_ORIGIN" rev-parse -q --verify refs/heads/feature)" = "$FEATURE_TIP" ]
check "push: the bare origin now has feature at the checked commit" $?
[ "$(git -C "$RUN_REPO" config --get branch.feature.remote)" = "origin" ]
check "push: the upstream step made origin the branch's upstream" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "push: /api/security reports the push and its output" "$RUN_SEC" \
  'data["push"]["pushed"] is True and extra + " -> feature" in data["push"]["output"]' "$FEATURE_TIP"
ALREADY_PUSHED_REASON="Already pushed: origin/feature is at ${FEATURE_TIP:0:7}."
json_check "push: once origin/feature is at the tip, no second push is offered" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$ALREADY_PUSHED_REASON"
expect_post_error "push: POST /api/push after the branch is already pushed" 409 \
  "$ALREADY_PUSHED_REASON" /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'

# ---- the tip moved after the run -----------------------------------------------------------

set_commit_date "2026-02-01T10:02:00 +0000"
printf 'def feature():\n    return 2\n' > "$RUN_WT/feature.py"
git -C "$RUN_WT" commit -q -am "Feature work, second step"
MOVED_TIP=$(git -C "$RUN_WT" rev-parse HEAD)
MOVED_REASON="feature has moved since the check (checked ${FEATURE_TIP:0:7}, now ${MOVED_TIP:0:7}): run the check again."
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "moved tip: a commit after the run turns the push off, naming both commits" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$MOVED_REASON"
expect_post_error "moved tip: POST /api/push" 409 "$MOVED_REASON" \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
[ "$(git --git-dir="$RUN_ORIGIN" rev-parse -q --verify refs/heads/feature)" = "$FEATURE_TIP" ]
check "moved tip: the remote still has the commit that was checked" $?

# ---- verdicts that do not allow a push ---------------------------------------------------------

printf 'FAKE_VERDICT="DO NOT PUBLISH"\n' > "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "verdicts: a DO NOT PUBLISH run starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: DO NOT PUBLISH ends with exit code 1" "$RUN_SEC" \
  'data["runner"]["exit_code"] == 1 and data["verdict_word"] == "DO NOT PUBLISH"'
json_check "verdicts: DO NOT PUBLISH allows no push" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check says DO NOT PUBLISH: only READY TO PUBLISH allows a push."'
json_check "verdicts: a new run forgets the previous push result" "$RUN_SEC" \
  'data["push"]["pushed"] is None and data["push"]["output"] is None'
expect_post_error "verdicts: POST /api/push after DO NOT PUBLISH" 409 \
  "The latest check says DO NOT PUBLISH: only READY TO PUBLISH allows a push." \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
# The verdict comes first; a blocked host is named after it.
git -C "$RUN_REPO" config remote.origin.pushurl "https://code.work.example/team/app.git"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: DO NOT PUBLISH on a blocked host names the verdict, then the host" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check says DO NOT PUBLISH: only READY TO PUBLISH allows a push. Repositories on code.work.example are pushed from another machine: port the change by hand."'
git -C "$RUN_REPO" config --unset remote.origin.pushurl

NOT_MERGED_REASON="The LLM review was not merged into the latest verdict, so it cannot allow a push."
printf 'FAKE_REVIEW_MERGED=false\n' > "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "verdicts: a READY run whose review was not merged starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: READY TO PUBLISH with review_merged false allows no push" "$RUN_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$NOT_MERGED_REASON"

# The toolkit writes review_merged and READY before it reads its merge back;
# only review_confirmed says the read-back agreed (02 F-02).
NOT_CONFIRMED_REASON="The latest check says READY TO PUBLISH, but the review was not confirmed by its read-back; run the check again."
printf 'FAKE_REVIEW_CONFIRMED=absent\n' > "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "verdicts: a READY run with no review_confirmed key starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: READY TO PUBLISH with no review_confirmed allows no push" "$RUN_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$NOT_CONFIRMED_REASON"
expect_post_error "verdicts: POST /api/push with no review_confirmed" 409 "$NOT_CONFIRMED_REASON" \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
printf 'FAKE_REVIEW_CONFIRMED=false\n' > "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "verdicts: a READY run with review_confirmed false starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: READY TO PUBLISH with review_confirmed false allows no push" "$RUN_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$NOT_CONFIRMED_REASON"

BLOCKING_FINDING_REASON='The latest check holds a blocking finding, "SQL injection in the query builder" in "feature.py", next to its READY TO PUBLISH: run the check again.'
printf 'FAKE_BLOCKING_FINDING=1\n' > "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "verdicts: a READY run with a blocking finding in the feed starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: a blocking finding next to READY TO PUBLISH allows no push" "$RUN_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and [f["blocking"] for f in data["findings"]] == [True] and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$BLOCKING_FINDING_REASON"
expect_post_error "verdicts: POST /api/push next to a blocking finding" 409 "$BLOCKING_FINDING_REASON" \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
NOFILE_FINDING_REASON='The latest check holds a blocking finding, "Secret in the build log" in "?", next to its READY TO PUBLISH: run the check again.'
printf 'FAKE_BLOCKING_FINDING=nofile\n' > "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "verdicts: a READY run with a blocking finding that names no file starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "verdicts: a blocking finding with no file is kept, as file ?, and allows no push" "$RUN_SEC" \
  '[(f["file"], f["blocking"]) for f in data["findings"]] == [("?", True)] and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$NOFILE_FINDING_REASON"
rm -f "$TOOLKIT/knobs"

# ---- cancel a slow run -------------------------------------------------------------------------

printf 'FAKE_SLEEP=30\n' > "$TOOLKIT/knobs"
rm -f "$TOOLKIT/run.pid" "$TOOLKIT/sleep.pid"
STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/run" "$RUN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "200" "cancel: a slow run starts"
wait_for_security "$RUN_PORT" \
  'data["runner"]["active"] is True and [c["status"] for c in data["checks"] if c["name"].startswith("REV-01")] == ["running"]'
check "cancel: the slow run reaches its review step" $?
RUNNING_REASON="A security check is running: push once it has finished."
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "cancel: while running, exit_code is null and no push is allowed" "$RUN_SEC" \
  'data["runner"]["active"] is True and data["runner"]["exit_code"] is None and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$RUNNING_REASON"
expect_post_error "cancel: a second run while one is active" 409 "A security check is already running." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
expect_post_error "cancel: a push while a run is active" 409 "$RUNNING_REASON" \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'

STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/cancel" "$RUN_TOKEN" "application/json" '{}')
expect_status "200" "cancel: POST /api/cancel answers HTTP 200"
json_check "cancel: there was a run to cancel" "$POST_BODY" 'data == {"cancelled": True}'
# Ten seconds, against a review that sleeps for thirty.
wait_for_security "$RUN_PORT" 'data["runner"]["active"] is False' 10
check "cancel: the run stops within 10 seconds, long before its 30-second review would end" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "cancel: the cancelled run ends with exit code 2 and the feed's cancelled verdict" "$RUN_SEC" \
  'data["runner"]["exit_code"] == 2 and data["verdict_word"] == "INCONCLUSIVE" and "cancelled" in data["verdict"]'
process_ends "$(cat "$TOOLKIT/run.pid")"
check "cancel: preflight.sh itself is gone" $?
process_ends "$(cat "$TOOLKIT/sleep.pid")"
check "cancel: the process it started is gone too (the whole group was stopped)" $?
json_check "cancel: the gate's PASSED verdict, left by the stopped review, allows no push" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check has only the verdict of its mechanical checks (its LLM review did not run or did not finish): only READY TO PUBLISH allows a push."'
STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/cancel" "$RUN_TOKEN" "application/json" '{}')
json_check "cancel: with nothing running there is nothing to cancel" "$POST_BODY" \
  'data == {"cancelled": False}'
rm -f "$TOOLKIT/knobs"

# ---- a run cancelled during its mechanical checks ----------------------------------------------
# The toolkit's gate can still write into the feed a few seconds after the
# pipeline has exited. Until the stopped run's verdict arrives, and for at
# most 15 seconds, a new run is refused.

printf 'FAKE_GATE_SLEEP=30\nFAKE_TERM_SILENT=1\n' > "$TOOLKIT/knobs"
rm -f "$TOOLKIT/sleep.pid"
STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/run" "$RUN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "200" "stopping: a run with slow mechanical checks starts"
wait_for_security "$RUN_PORT" \
  'data["runner"]["active"] is True and [c["status"] for c in data["checks"] if c["name"] == "Secrets"] == ["running"]'
check "stopping: the run reaches its mechanical checks" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "judged: before its verdict.json exists, a run started here names its branch and starting tip" "$RUN_SEC" \
  'data["judged"] == {"branch": "feature", "commit": extra} and data["push"]["reason"] == "A security check is running: push once it has finished."' "$MOVED_TIP"
git -C "$RUN_REPO" config remote.origin.pushurl "https://code.work.example/team/app.git"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "stopping: while running on a blocked host, the reason promises no later push" "$RUN_SEC" \
  'data["push"]["reason"] == "A security check is running. Repositories on code.work.example are pushed from another machine: port the change by hand."'
git -C "$RUN_REPO" config --unset remote.origin.pushurl

STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/cancel" "$RUN_TOKEN" "application/json" '{}')
json_check "stopping: there was a run to cancel" "$POST_BODY" 'data == {"cancelled": True}'
wait_for_security "$RUN_PORT" 'data["runner"]["active"] is False'
check "stopping: the run stops" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "stopping: the stopped run wrote no verdict, so its feed still reads as running" "$RUN_SEC" \
  'data["runner"]["exit_code"] == 2 and data["running"] is True and data["push"]["reason"] == "The latest security check has no verdict yet."'
expect_post_error "stopping: a new run while the stopped one may still write" 409 \
  "The cancelled check is still stopping: try again in a few seconds." \
  /api/run "$RUN_TOKEN" "application/json" '{"branch": "feature"}'

# The stopped gate's own verdict arrives late, with no verdict.json.
printf '%s\n' '{"event": "verdict", "text": "PREFLIGHT: INCONCLUSIVE - stopped", "verdict": "INCONCLUSIVE"}' >> "$RUN_FEED"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "no verdict.json: a finished run that left none says so" "$RUN_SEC" \
  'data["running"] is False and data["push"]["reason"] == "The latest check (" + data["run_id"] + ") left no readable verdict.json: run it again."'
json_check "no verdict.json: once the run started here has ended, what it judged is unknown" "$RUN_SEC" \
  'data["judged"] is None'
rm -f "$TOOLKIT/knobs"
run_check_and_wait '{"branch": "feature"}'
check "stopping: once the stopped run's verdict has arrived, a new run starts and finishes" $?

# ---- the run_id in the feed is not trusted ---------------------------------------------------
# A READY verdict for the current tip sits in a folder OUTSIDE the reports
# folder. Only a plain folder name inside it may be used.

OUTSIDE_RUN="$FIXTURE/outside-run"
write_ready_verdict "$OUTSIDE_RUN" "$MOVED_TIP"
write_ready_verdict "$RUN_REPORTS/hand-run" "$MOVED_TIP"
ln -s "$OUTSIDE_RUN" "$RUN_REPORTS/linked-run"
mkdir -p "$RUN_REPORTS/nomerge-run"
printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "repository": {"branch": "feature", "commit": "%s"}}\n' \
  "$MOVED_TIP" > "$RUN_REPORTS/nomerge-run/verdict.json"

# $1: the run_id of a new start event appended to the feed. $2, when given:
# the word of a verdict event appended after it, as a finished run leaves.
append_start() {
  printf '{"event": "start", "run_id": "%s", "base": "origin/main", "files": []}\n' "$1" >> "$RUN_FEED"
  if [ -n "${2:-}" ]; then
    printf '{"event": "verdict", "text": "PIPELINE: %s", "verdict": "%s"}\n' "$2" "$2" >> "$RUN_FEED"
  fi
  local status
  status=$(http_get "$RUN_PORT" "$RUN_SEC" "/api/security")
  # The fixture folder's path is shortened, so the line reads the same in every run.
  [ "$status" = "200" ]
  check "run_id: /api/security answers HTTP 200 after a start event naming ${1/#"$FIXTURE"/<fixture>}" $? \
    "got HTTP $status"
}
append_start "hand-run" "READY TO PUBLISH"
json_check "run_id: a folder inside the reports folder is used (a run started from a terminal)" "$RUN_SEC" \
  'data["run_id"] == "hand-run" and data["push"]["allowed"] is True'
append_start "../outside-run"
json_check "run_id: ../ out of the reports folder reads as no verdict" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest security check has no verdict yet."'
expect_post_error "run_id: POST /api/push after a ../ run_id" 409 \
  "The latest security check has no verdict yet." \
  /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'
append_start "$OUTSIDE_RUN"
json_check "run_id: an absolute path reads as no verdict" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest security check has no verdict yet."'
append_start "linked-run"
json_check "run_id: a symlink leading out of the reports folder reads as no verdict" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest security check has no verdict yet."'
append_start ".."
json_check "run_id: .. reads as no verdict" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest security check has no verdict yet."'
append_start "nomerge-run"
json_check "run_id: a verdict with no review_merged key allows no push" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$NOT_MERGED_REASON"

# `check --worktree` judges a snapshot of uncommitted files and records HEAD
# as its commit: even READY on the tip must not unlock the push.
SNAPSHOT_REASON="The latest check judged uncommitted work, not a commit: commit it and run the check again."
mkdir -p "$RUN_REPORTS/snapshot-run"
printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "review_merged": true, "review_confirmed": true, "mode": "check-worktree", "repository": {"branch": "feature", "commit": "%s"}}\n' \
  "$MOVED_TIP" > "$RUN_REPORTS/snapshot-run/verdict.json"
append_start "snapshot-run"
json_check "run_id: a verdict on a snapshot of uncommitted work allows no push" "$RUN_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$SNAPSHOT_REASON"
expect_post_error "run_id: POST /api/push after a working-tree snapshot verdict" 409 \
  "$SNAPSHOT_REASON" /api/push "$RUN_TOKEN" "application/json" '{"branch": "feature"}'

# With a tag named like the branch, `rev-parse --abbrev-ref HEAD` records
# "heads/feature": it still means the branch feature.
mkdir -p "$RUN_REPORTS/heads-run"
printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "review_merged": true, "review_confirmed": true, "mode": "check", "base_ref": "origin/main", "repository": {"branch": "heads/feature", "commit": "%s"}}\n' \
  "$MOVED_TIP" > "$RUN_REPORTS/heads-run/verdict.json"
append_start "heads-run" "READY TO PUBLISH"
json_check "run_id: a branch recorded as heads/<name> is the branch <name>" "$RUN_SEC" \
  'data["push"]["allowed"] is True and data["push"]["branch"] == "feature" and data["judged"] == {"branch": "feature", "commit": extra}' "$MOVED_TIP"

# ---- a push the remote rejects -------------------------------------------------------------

printf '#!/bin/sh\necho "fixture remote: pushes are refused here" >&2\nexit 1\n' \
  > "$RUN_ORIGIN/hooks/pre-receive"
chmod +x "$RUN_ORIGIN/hooks/pre-receive"
run_check_and_wait '{"branch": "feature"}'
check "rejected push: a READY run on the new tip starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "rejected push: the push is allowed on BranchLens's side" "$RUN_SEC" \
  'data["push"]["allowed"] is True and data["push"]["commit"] == extra' "$MOVED_TIP"
json_check "push: with an upstream the next push has no upstream step" "$RUN_SEC" \
  'data["push"]["reason"] == "Will run git push --recurse-submodules=no --no-follow-tags origin " + extra + ":refs/heads/feature."' "$MOVED_TIP"
STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/push" "$RUN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "200" "rejected push: POST /api/push answers HTTP 200"
json_check "rejected push: pushed is false and the output is git's and the remote's own words" "$POST_BODY" \
  'data["pushed"] is False and "pushes are refused here" in data["output"] and "pre-receive hook declined" in data["output"]'
[ "$(git --git-dir="$RUN_ORIGIN" rev-parse -q --verify refs/heads/feature)" = "$FEATURE_TIP" ]
check "rejected push: the remote keeps its previous commit" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "rejected push: /api/security reports pushed false" "$RUN_SEC" \
  'data["push"]["pushed"] is False and "pre-receive hook declined" in data["push"]["output"]'
rm -f "$RUN_ORIGIN/hooks/pre-receive"

# ---- two servers, one reports folder ---------------------------------------------------------
# Every worktree of a repository shares one reports folder, and one
# BranchLens per worktree is the usual setup. Each server reads the run id
# from its own log, so neither takes the other's run for its own (02 F-08).

TWIN_TOOLKIT="$FIXTURE/twin-toolkit"
mkdir -p "$TWIN_TOOLKIT"
cp "$TOOLKIT/preflight.sh" "$TWIN_TOOLKIT/preflight.sh"
TWIN_LOG="$FIXTURE/server-twin.log"
TWIN_SEC="$FIXTURE/twin-security.json"
python3 -m branchlens "$RUN_WT" --port 0 --no-browser \
  --toolkit "$TWIN_TOOLKIT" --security-feed "$RUN_FEED" > "$TWIN_LOG" 2>&1 &
TWIN_SERVER_PID=$!
echo "$TWIN_SERVER_PID" >> "$FIXTURE/extra-pids"
TWIN_PORT=$(wait_for_server "$TWIN_LOG")
check "two servers: a second server starts on the worktree, watching the same feed" $?
TWIN_TOKEN=$(page_token "$TWIN_PORT")

run_check_and_wait '{"branch": "feature"}'
check "two servers: the first server's run starts and finishes" $?
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
FIRST_SERVER_RUN_ID=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["runner"]["run_id"])' "$RUN_SEC")
STATUS=$(http_post "$TWIN_PORT" "$POST_BODY" "/api/run" "$TWIN_TOKEN" "application/json" '{"branch": "feature"}')
[ "$STATUS" = "200" ] && wait_for_security "$TWIN_PORT" 'data["runner"]["active"] is False'
check "two servers: the second server's run starts and finishes" $?
http_get "$TWIN_PORT" "$TWIN_SEC" "/api/security" > /dev/null
json_check "two servers: the second server names its own run, the feed's latest" "$TWIN_SEC" \
  'data["runner"]["run_id"] == data["run_id"] and data["runner"]["run_id"] != extra' "$FIRST_SERVER_RUN_ID"
http_get "$RUN_PORT" "$RUN_SEC" "/api/security" > /dev/null
json_check "two servers: the first server still names its own run, not the second's" "$RUN_SEC" \
  'data["runner"]["run_id"] == extra and data["run_id"] != extra' "$FIRST_SERVER_RUN_ID"
[ -f "$RUN_REPORTS/branchlens-run-$RUN_SERVER_PID.log" ] && [ -f "$RUN_REPORTS/branchlens-run-$TWIN_SERVER_PID.log" ]
check "two servers: each server writes a log of its own" $?

# A live run of the first server is a run started elsewhere for the second.
printf 'FAKE_SLEEP=30\n' > "$TOOLKIT/knobs"
STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/run" "$RUN_TOKEN" "application/json" '{"branch": "feature"}')
[ "$STATUS" = "200" ] && wait_for_security "$RUN_PORT" \
  'data["runner"]["active"] is True and [c["status"] for c in data["checks"] if c["name"].startswith("REV-01")] == ["running"]'
check "two servers: a slow run of the first server reaches its review" $?
http_get "$TWIN_PORT" "$TWIN_SEC" "/api/security" > /dev/null
json_check "two servers: the second server does not take the live run for its own" "$TWIN_SEC" \
  'data["runner"]["active"] is False and data["runner"]["run_id"] != data["run_id"]'
STATUS=$(http_post "$TWIN_PORT" "$POST_BODY" "/api/run" "$TWIN_TOKEN" "application/json" '{"branch": "feature"}')
expect_status "409" "two servers: the second server refuses a run while the first one's is live" "got HTTP $STATUS"
json_check "two servers: the refusal says a check started elsewhere is running" "$POST_BODY" \
  'data["error"] == "A check started outside this page is running: wait for it to finish."'
http_post "$RUN_PORT" "$POST_BODY" "/api/cancel" "$RUN_TOKEN" "application/json" '{}' > /dev/null
wait_for_security "$RUN_PORT" 'data["runner"]["active"] is False and data["running"] is False'
check "two servers: the first server's slow run is cancelled" $?
rm -f "$TOOLKIT/knobs"
kill "$TWIN_SERVER_PID"
wait "$TWIN_SERVER_PID" 2>/dev/null

# ---- toolkit, reports folder and blocked hosts from the environment -------------------------
# No flag at all: the toolkit comes from PREFLIGHT_TOOLKIT, the feed defaults
# to $PREFLIGHT_REPORTS_DIR/security-feed.jsonl, and the blocked hosts come
# from BRANCHLENS_NO_PUSH_HOSTS.

ENV_REPORTS="$FIXTURE/env-reports"
write_ready_verdict "$ENV_REPORTS/terminal-run" "$MOVED_TIP"
printf '{"event": "start", "run_id": "terminal-run", "base": "origin/main", "files": []}\n' \
  > "$ENV_REPORTS/security-feed.jsonl"
printf '{"event": "verdict", "text": "PIPELINE: READY TO PUBLISH", "verdict": "READY TO PUBLISH"}\n' \
  >> "$ENV_REPORTS/security-feed.jsonl"
ENV_LOG="$FIXTURE/server-env.log"
PREFLIGHT_TOOLKIT="$TOOLKIT" PREFLIGHT_REPORTS_DIR="$ENV_REPORTS" \
  BRANCHLENS_NO_PUSH_HOSTS="other.example, work.example" \
  python3 -m branchlens "$RUN_REPO" --port 0 --no-browser > "$ENV_LOG" 2>&1 &
ENV_SERVER_PID=$!
echo "$ENV_SERVER_PID" >> "$FIXTURE/extra-pids"
ENV_PORT=$(wait_for_server "$ENV_LOG")
check "environment: server starts with the toolkit and reports folder from the environment" $?
ENV_SEC="$FIXTURE/env-security.json"
http_get "$ENV_PORT" "$ENV_SEC" "/api/security" > /dev/null
json_check "environment: the default feed is the one in PREFLIGHT_REPORTS_DIR" "$ENV_SEC" \
  'data["enabled"] is True and data["run_id"] == "terminal-run"'
json_check "environment: PREFLIGHT_TOOLKIT makes the runner available" "$ENV_SEC" \
  'data["runner"]["available"] is True and data["runner"]["active"] is False'
json_check "environment: a READY run started from a terminal allows the push" "$ENV_SEC" \
  'data["push"]["allowed"] is True'
git -C "$RUN_REPO" config remote.origin.pushurl "https://code.work.example/team/app.git"
http_get "$ENV_PORT" "$ENV_SEC" "/api/security" > /dev/null
json_check "environment: a host from BRANCHLENS_NO_PUSH_HOSTS is refused" "$ENV_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "Repositories on code.work.example are pushed from another machine: port the change by hand."'
git -C "$RUN_REPO" config --unset remote.origin.pushurl

# The reports folder takes writes from the review's agents: a symlink put
# where this server's log goes is refused, and the file it names is not truncated.
LOG_LINK_TARGET="$FIXTURE/log-link-target.txt"
printf 'keep me\n' > "$LOG_LINK_TARGET"
ln -s "$LOG_LINK_TARGET" "$ENV_REPORTS/branchlens-run-$ENV_SERVER_PID.log"
STATUS=$(http_post "$ENV_PORT" "$POST_BODY" "/api/run" "$(page_token "$ENV_PORT")" \
  "application/json" '{"branch": "feature"}')
expect_status "500" "run log: a symlink in place of the log refuses the run with HTTP 500" "got HTTP $STATUS"
json_check "run log: the refusal names the run log, not preflight.sh" "$POST_BODY" \
  'data["error"].startswith("Could not open the run log ") and ("/branchlens-run-" + extra + ".log (") in data["error"] and "If a symlink is there, remove it" in data["error"]' \
  "$ENV_SERVER_PID"
[ "$(cat "$LOG_LINK_TARGET")" = "keep me" ] && [ -L "$ENV_REPORTS/branchlens-run-$ENV_SERVER_PID.log" ]
check "run log: the file the symlink names is left as it was" $?

# ---- the default feed, launched from a linked worktree ----------------------------------------
# One rule for every worktree: ~/preflight-reports/<main repository folder name>.

HOME_FEED="$FIXTURE/home/preflight-reports/repo/security-feed.jsonl"
HOME_LOG="$FIXTURE/server-home.log"
HOME="$FIXTURE/home" python3 -m branchlens "$WORKTREE" --port 0 --no-browser \
  --toolkit "$TOOLKIT" > "$HOME_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
HOME_PORT=$(wait_for_server "$HOME_LOG")
check "default feed: server starts from a linked worktree with a toolkit" $?
HOME_SEC="$FIXTURE/home-security.json"
http_get "$HOME_PORT" "$HOME_SEC" "/api/security" > /dev/null
json_check "default feed: a linked worktree watches the main repository's folder" "$HOME_SEC" \
  'data["feed_path"] == extra' "$HOME_FEED"
grep -qxF "Security feed: $HOME_FEED" "$HOME_LOG"
check "default feed: the startup line names that feed" $?

# ---- a toolkit folder that cannot run ---------------------------------------------------------

BROKEN_TOOLKIT="$FIXTURE/broken-toolkit"
mkdir -p "$BROKEN_TOOLKIT"
BROKEN_LOG="$FIXTURE/server-broken.log"
python3 -m branchlens "$RUN_REPO" --port 0 --no-browser \
  --toolkit "$BROKEN_TOOLKIT" --security-feed "$FIXTURE/broken-reports/security-feed.jsonl" \
  > "$BROKEN_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
BROKEN_PORT=$(wait_for_server "$BROKEN_LOG")
check "broken toolkit: server starts with a toolkit folder that has no preflight.sh" $?
grep -q "warning: no preflight.sh in" "$BROKEN_LOG"
check "broken toolkit: the server warns about the missing preflight.sh" $?
BROKEN_SEC="$FIXTURE/broken-security.json"
http_get "$BROKEN_PORT" "$BROKEN_SEC" "/api/security" > /dev/null
json_check "broken toolkit: the runner is not available" "$BROKEN_SEC" \
  'data["runner"]["available"] is False'
json_check "broken toolkit: the runner says the folder has no preflight.sh" "$BROKEN_SEC" \
  'data["runner"]["unavailable_reason"] == "There is no preflight.sh in " + extra + "."' "$BROKEN_TOOLKIT"
BROKEN_TOKEN=$(page_token "$BROKEN_PORT")
STATUS=$(http_post "$BROKEN_PORT" "$POST_BODY" "/api/run" "$BROKEN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "400" "broken toolkit: /api/run without preflight.sh answers HTTP 400"
json_check "broken toolkit: the refusal names the folder" "$POST_BODY" \
  'data["error"] == "There is no preflight.sh in " + extra + "."' "$BROKEN_TOOLKIT"
# A preflight.sh that exists but is not executable cannot be started.
printf '#!/bin/sh\nexit 0\n' > "$BROKEN_TOOLKIT/preflight.sh"
chmod -x "$BROKEN_TOOLKIT/preflight.sh"
STATUS=$(http_post "$BROKEN_PORT" "$POST_BODY" "/api/run" "$BROKEN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "500" "broken toolkit: a preflight.sh that cannot start answers HTTP 500"
json_check "broken toolkit: the error says preflight.sh could not start" "$POST_BODY" \
  'data["error"].startswith("Could not start preflight.sh: ")'
http_get "$BROKEN_PORT" "$BROKEN_SEC" "/api/security" > /dev/null
json_check "broken toolkit: no run was recorded" "$BROKEN_SEC" \
  'data["runner"]["available"] is True and data["runner"]["active"] is False and data["runner"]["branch"] is None'

# ---- a PATH without the claude CLI ---------------------------------------------------------------
# The pipeline's review runs `claude -p`. A PATH that holds only git (the
# claude stub and the real CLI often sit next to python3, so no directory of
# the normal PATH is kept) makes Run unavailable, with the reason on the card.

NO_CLAUDE_BIN="$FIXTURE/no-claude-bin"
mkdir -p "$NO_CLAUDE_BIN"
ln -s "$(command -v git)" "$NO_CLAUDE_BIN/git"
NO_CLAUDE_PYTHON=$(command -v python3)
NO_CLAUDE_LOG="$FIXTURE/server-no-claude.log"
NO_CLAUDE_REASON="Run needs the Claude Code CLI (claude) on PATH."
PATH="$NO_CLAUDE_BIN" "$NO_CLAUDE_PYTHON" -m branchlens "$RUN_REPO" --port 0 --no-browser \
  --toolkit "$TOOLKIT" --security-feed "$FIXTURE/no-claude-reports/security-feed.jsonl" \
  > "$NO_CLAUDE_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
NO_CLAUDE_PORT=$(wait_for_server "$NO_CLAUDE_LOG")
check "no claude: server starts with a PATH that holds only git" $?
NO_CLAUDE_SEC="$FIXTURE/no-claude-security.json"
http_get "$NO_CLAUDE_PORT" "$NO_CLAUDE_SEC" "/api/security" > /dev/null
json_check "no claude: /api/security says Run needs the claude CLI" "$NO_CLAUDE_SEC" \
  'data["runner"]["available"] is False and data["runner"]["unavailable_reason"] == extra' "$NO_CLAUDE_REASON"
STATUS=$(http_post "$NO_CLAUDE_PORT" "$POST_BODY" "/api/run" "$(page_token "$NO_CLAUDE_PORT")" \
  "application/json" '{"branch": "feature"}')
expect_status "400" "no claude: /api/run answers HTTP 400" "got HTTP $STATUS"
json_check "no claude: the refusal says Run needs the claude CLI" "$POST_BODY" \
  'data["error"] == extra' "$NO_CLAUDE_REASON"
! ls "$FIXTURE/no-claude-reports"/branchlens-run*.log > /dev/null 2>&1
check "no claude: no run was started" $?

# ---- a first publish ---------------------------------------------------------------------------
# The default branch of a repository with no remote, or whose remote has no
# copy of it, runs compared with nothing: the toolkit's empty-tree base.

FP_REPO="$FIXTURE/firstpub"
FP_ORIGIN="$FIXTURE/firstpub-origin.git"
FP_TOOLKIT="$FIXTURE/firstpub-toolkit"
new_repo "$FP_REPO"
printf 'print("first publish")\n' > "$FP_REPO/app.py"
git -C "$FP_REPO" add -A
git -C "$FP_REPO" commit -q -m "First publish fixture"
FP_TIP=$(git -C "$FP_REPO" rev-parse HEAD)
# A toolkit folder of its own: the shared one keeps knobs and pid files.
mkdir -p "$FP_TOOLKIT"
cp "$TOOLKIT/preflight.sh" "$FP_TOOLKIT/preflight.sh"
FP_LOG="$FIXTURE/server-firstpub.log"
python3 -m branchlens "$FP_REPO" --port 0 --no-browser \
  --toolkit "$FP_TOOLKIT" --security-feed "$FIXTURE/firstpub-reports/security-feed.jsonl" \
  > "$FP_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
FP_PORT=$(wait_for_server "$FP_LOG")
check "first publish: server starts on a repository with no remote" $?
FP_TOKEN=$(page_token "$FP_PORT")
FP_STATE="$FIXTURE/firstpub-state.json"
FP_DIFF="$FIXTURE/firstpub-diff.json"
FP_SEC="$FIXTURE/firstpub-security.json"
FIRST_PUBLISH_SENTENCE="There is no origin/main here yet: a push would publish main's whole history."
FP_STATE_BEFORE="$FIXTURE/firstpub-state-before.json"
FP_FILE="$FIXTURE/firstpub-file.json"

# Start a run on this server and wait for it to end. $1: the JSON body.
run_first_publish_check() {
  local status
  status=$(http_post "$FP_PORT" "$POST_BODY" "/api/run" "$FP_TOKEN" "application/json" "$1")
  [ "$status" = "200" ] && wait_for_security "$FP_PORT" 'data["runner"]["active"] is False'
}

http_get "$FP_PORT" "$FP_STATE" "/api/state" > /dev/null
json_check "first publish: with no remote, the state says a run on main is a first publish" "$FP_STATE" \
  'data["first_publish"] is True and data["default_synced_online"] is False'
http_get "$FP_PORT" "$FP_DIFF" "/api/diff?branch=main" > /dev/null
json_check "first publish: with no remote, nothing is pending on a clean main" "$FP_DIFF" \
  'data["mode"] == "default-branch" and data["explanation"] == "Nothing is pending on main."'
run_first_publish_check '{"branch": "main"}'
check "first publish: with no remote, a run on main starts and finishes" $?
json_check "first publish: with no remote, the run's base is empty-tree" "$POST_BODY" \
  'data == {"started": True, "branch": "main", "base": "empty-tree"}'
json_check "first publish: with no remote, preflight.sh got the empty-tree base" "$FP_TOOLKIT/last-call.json" \
  'data["args"][2:] == ["empty-tree"]'
http_get "$FP_PORT" "$FP_SEC" "/api/security" > /dev/null
json_check "first publish: with no remote, a READY run leaves Push off with the no-remote reason" "$FP_SEC" \
  'data["base"] == "empty-tree" and data["push"]["allowed"] is False and data["push"]["reason"] == "There is no remote named origin to push to."'

http_get "$FP_PORT" "$FP_STATE_BEFORE" "/api/state" > /dev/null
git init -q --bare -b main "$FP_ORIGIN"
git -C "$FP_REPO" remote add origin "$FP_ORIGIN"
http_get "$FP_PORT" "$FP_STATE" "/api/state" > /dev/null
json_check "first publish: a remote with no copy of main keeps it a first publish" "$FP_STATE" \
  'data["first_publish"] is True and data["push_remote"] == "origin"'
state_pair_check "first publish: adding the remote moves the state token and main's content token" \
  "$FP_STATE_BEFORE" "$FP_STATE" \
  'before["state_token"] != after["state_token"] and token(before, "main") != token(after, "main")'
http_get "$FP_PORT" "$FP_DIFF" "/api/diff?branch=main" > /dev/null
json_check "first publish: the header says a push would publish main's whole history, and lists every file" "$FP_DIFF" \
  'data["mode"] == "worktree" and data["explanation"] == extra and [f["path"] for f in data["files"]] == ["app.py"] and data["base_commit"] is None and data.get("whole_history") is True' "$FIRST_PUBLISH_SENTENCE"
expect_get "$FP_PORT" "$FP_FILE" "/api/file?branch=main&path=app.py" "200" "first publish: a file of main's whole history opens: HTTP 200"
json_check "first publish: the file is shown as added from the empty tree" "$FP_FILE" \
  'data["status"] == "A" and "+print(\"first publish\")" in data["patch"]'
printf 'draft\n' > "$FP_REPO/draft.txt"
http_get "$FP_PORT" "$FP_DIFF" "/api/diff?branch=main" > /dev/null
json_check "first publish: edits not yet committed are named before the whole history" "$FP_DIFF" \
  'data["explanation"] == "Edits on main not yet committed. " + extra and [f["path"] for f in data["files"]] == ["app.py", "draft.txt"]' "$FIRST_PUBLISH_SENTENCE"
rm "$FP_REPO/draft.txt"
git -C "$FP_REPO" checkout -q --detach
http_get "$FP_PORT" "$FP_DIFF" "/api/diff?branch=main" > /dev/null
json_check "first publish: a main checked out nowhere is said to be so after the whole history" "$FP_DIFF" \
  'data["mode"] == "committed" and data["explanation"] == extra + " It is not checked out anywhere." and [f["path"] for f in data["files"]] == ["app.py"]' "$FIRST_PUBLISH_SENTENCE"
git -C "$FP_REPO" checkout -q main
run_first_publish_check '{"branch": "main"}'
check "first publish: with a remote that lacks main, a run on main starts and finishes" $?
json_check "first publish: with a remote that lacks main, the run's base is empty-tree" "$POST_BODY" \
  'data == {"started": True, "branch": "main", "base": "empty-tree"}'
http_get "$FP_PORT" "$FP_SEC" "/api/security" > /dev/null
json_check "first publish: a READY run allows the first push of main" "$FP_SEC" \
  'data["push"]["allowed"] is True and data["push"]["reason"] == "Will run git push --recurse-submodules=no --no-follow-tags origin " + extra + ":refs/heads/main, then git branch --set-upstream-to=refs/remotes/origin/main main."' "$FP_TIP"
STATUS=$(http_post "$FP_PORT" "$POST_BODY" "/api/push" "$FP_TOKEN" "application/json" '{"branch": "main"}')
expect_status "200" "first publish: pushing main answers HTTP 200"
json_check "first publish: the push succeeds" "$POST_BODY" 'data["pushed"] is True'

http_get "$FP_PORT" "$FP_STATE" "/api/state" > /dev/null
json_check "first publish: once origin has main, it is no longer a first publish" "$FP_STATE" \
  'data["first_publish"] is False and data["comparison_label"] == "origin/main"'
STATUS=$(http_post "$FP_PORT" "$POST_BODY" "/api/run" "$FP_TOKEN" "application/json" '{"branch": "main"}')
expect_status "400" "first publish: after the push, a run on main compares with origin/main: HTTP 400"
json_check "first publish: after the push, main has nothing origin/main lacks" "$POST_BODY" \
  'data["error"] == "main has no commits that origin/main lacks, so there is nothing to check: the check judges commits, not uncommitted edits."'
run_first_publish_check '{"branch": "main", "base": "empty-tree"}'
check "first publish: a given empty-tree base is accepted and the run finishes" $?
json_check "first publish: the answer names the given empty-tree base" "$POST_BODY" \
  'data == {"started": True, "branch": "main", "base": "empty-tree"}'
json_check "first publish: preflight.sh got the given empty-tree base" "$FP_TOOLKIT/last-call.json" \
  'data["args"][2:] == ["empty-tree"]'

# The push remote is main's upstream remote, not origin. First it lacks main
# while origin has it and main is ahead of origin/main: the header, the state
# and the run all read a first publish.
FP_UPSTREAM="$FIXTURE/firstpub-upstream.git"
git init -q --bare -b main "$FP_UPSTREAM"
git -C "$FP_REPO" remote add upstream "$FP_UPSTREAM"
git -C "$FP_REPO" config branch.main.remote upstream
printf 'print("second")\n' > "$FP_REPO/second.py"
git -C "$FP_REPO" add second.py
git -C "$FP_REPO" commit -q -m "Second commit"
http_get "$FP_PORT" "$FP_STATE" "/api/state" > /dev/null
json_check "push remote: an upstream that lacks main makes it a first publish while origin has it" "$FP_STATE" \
  'data["first_publish"] is True and data["push_remote"] == "upstream" and data["comparison_label"] == "origin/main"'
http_get "$FP_PORT" "$FP_DIFF" "/api/diff?branch=main" > /dev/null
json_check "push remote: the header names upstream/main and lists main's whole history" "$FP_DIFF" \
  'data["mode"] == "worktree" and data["explanation"] == "There is no upstream/main here yet: a push would publish main'"'"'s whole history." and [f["path"] for f in data["files"]] == ["app.py", "second.py"]'
run_first_publish_check '{"branch": "main"}'
check "push remote: with an upstream that lacks main, a run on main starts and finishes" $?
json_check "push remote: with an upstream that lacks main, the run's base is empty-tree" "$POST_BODY" \
  'data == {"started": True, "branch": "main", "base": "empty-tree"}'

# Then upstream has main, origin is gone and main is ahead of upstream/main:
# the run compares with upstream/main.
git -C "$FP_REPO" push -q upstream main
git -C "$FP_REPO" remote remove origin
printf 'print("third")\n' > "$FP_REPO/third.py"
git -C "$FP_REPO" add third.py
git -C "$FP_REPO" commit -q -m "Third commit"
http_get "$FP_PORT" "$FP_STATE" "/api/state" > /dev/null
json_check "push remote: an upstream that has main is not a first publish, with no origin" "$FP_STATE" \
  'data["first_publish"] is False and data["push_remote"] == "upstream" and data["comparison_label"] == "main"'
run_first_publish_check '{"branch": "main"}'
check "push remote: with no origin, a run on main starts and finishes" $?
json_check "push remote: with no origin, the run's base is upstream/main" "$POST_BODY" \
  'data == {"started": True, "branch": "main", "base": "upstream/main"}'
FP_UPSTREAM_MAIN=$(git -C "$FP_REPO" rev-parse refs/remotes/upstream/main)
json_check "push remote: preflight.sh got the upstream/main base" "$FP_TOOLKIT/last-call.json" \
  'data["args"][2:] == [extra]' "$FP_UPSTREAM_MAIN"

# ---- stopping the server stops its run ----------------------------------------------------------

printf 'FAKE_SLEEP=30\n' > "$TOOLKIT/knobs"
rm -f "$TOOLKIT/run.pid" "$TOOLKIT/sleep.pid"
STATUS=$(http_post "$RUN_PORT" "$POST_BODY" "/api/run" "$RUN_TOKEN" \
  "application/json" '{"branch": "feature"}')
expect_status "200" "server stop: a slow run starts"
wait_for_security "$RUN_PORT" \
  'data["runner"]["active"] is True and [c["status"] for c in data["checks"] if c["name"].startswith("REV-01")] == ["running"]'
check "server stop: the slow run reaches its review step" $?
kill "$RUN_SERVER_PID"
wait "$RUN_SERVER_PID" 2>/dev/null
process_ends "$(cat "$TOOLKIT/run.pid")"
check "server stop: kill on the server also stops the run it started" $?
process_ends "$(cat "$TOOLKIT/sleep.pid")"
check "server stop: the run's own children are stopped too" $?
python3 - "$RUN_FEED" <<'PY'
import json, sys
verdicts = []
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("event") == "verdict":
        verdicts.append(event)
last = verdicts[-1]
sys.exit(0 if last.get("verdict") == "INCONCLUSIVE" and "cancelled" in last.get("text", "") else 1)
PY
check "server stop: the stopped run leaves its cancelled verdict in the feed" $?
rm -f "$TOOLKIT/knobs"

# ---------------------------------------------------------------- audit 2026-10: push and run gate
# Regression checks for the October 2026 audit of the run and the push. The
# push sends exactly the commit the check judged and nothing it never saw
# (older history, submodule commits, tags); the run's base is the qualified
# ref, handed to the toolkit as a commit id; the push goes to the remote git
# itself would pick.

GATE_ORIGIN="$FIXTURE/gate-origin.git"
GATE_FORK="$FIXTURE/gate-fork.git"
GATE_SUB_REMOTE="$FIXTURE/gate-sub-remote.git"
GATE_SUB_SOURCE="$FIXTURE/gate-sub-source"
GATE_REPO="$FIXTURE/gate"
GATE_WT="$FIXTURE/gate-wt"
GATE_REPORTS="$FIXTURE/gate-reports"
GATE_FEED="$GATE_REPORTS/security-feed.jsonl"
GATE_TOOLKIT="$FIXTURE/gate-toolkit"
GATE_SHIM="$FIXTURE/gate-shim"
GATE_SEC="$FIXTURE/gate-security.json"
GATE_POST="$FIXTURE/gate-post.json"

set_commit_date "2026-03-01T10:00:00 +0000"
git init -q --bare -b main "$GATE_ORIGIN"
git init -q --bare -b main "$GATE_FORK"
git init -q --bare -b main "$GATE_SUB_REMOTE"
new_repo "$GATE_SUB_SOURCE"
printf 'library\n' > "$GATE_SUB_SOURCE/lib.txt"
git -C "$GATE_SUB_SOURCE" add -A
git -C "$GATE_SUB_SOURCE" commit -q -m "Submodule: first commit"
git -C "$GATE_SUB_SOURCE" push -q "$GATE_SUB_REMOTE" main

new_repo "$GATE_REPO"
printf 'print("gate")\n' > "$GATE_REPO/app.py"
git -C "$GATE_REPO" add -A
git -C "$GATE_REPO" commit -q -m "Gate fixture: first commit"
git -C "$GATE_REPO" remote add origin "$GATE_ORIGIN"
git -C "$GATE_REPO" push -q origin main
GATE_MAIN=$(git -C "$GATE_REPO" rev-parse HEAD)
git -C "$GATE_REPO" worktree add -q -b gated "$GATE_WT"
set_commit_date "2026-03-01T10:01:00 +0000"
# protocol.file.allow: git refuses a submodule from a local path without it.
git -C "$GATE_WT" -c protocol.file.allow=always submodule add -q "$GATE_SUB_REMOTE" sub
git -C "$GATE_WT" commit -q -m "Gated: add the submodule"
GATE_FIRST=$(git -C "$GATE_WT" rev-parse HEAD)
# The submodule gets a commit no check judges, on a branch named like the
# superproject's, and the superproject records it.
git -C "$GATE_WT/sub" config user.name "Test User"
git -C "$GATE_WT/sub" config user.email "test@example.com"
git -C "$GATE_WT/sub" checkout -q -b gated
printf 'not judged\n' > "$GATE_WT/sub/unjudged.txt"
git -C "$GATE_WT/sub" add -A
git -C "$GATE_WT/sub" commit -q -m "Submodule commit no check judged"
printf 'def gated():\n    return 1\n' > "$GATE_WT/gated.py"
git -C "$GATE_WT" add -A
git -C "$GATE_WT" commit -q -m "Gated: feature work and the submodule bump"
GATE_TIP=$(git -C "$GATE_WT" rev-parse HEAD)
# Settings that widen a plain push: submodules on demand, and reachable tags.
git -C "$GATE_REPO" config submodule.recurse true
git -C "$GATE_REPO" config push.followTags true
git -C "$GATE_WT" tag -a gated-tag -m "A tag no check judged"

mkdir -p "$GATE_TOOLKIT" "$GATE_SHIM"
cp "$TOOLKIT/preflight.sh" "$GATE_TOOLKIT/preflight.sh"
# git as the gate server finds it on PATH. Once armed, it commits on the
# branch the moment a push starts: a commit landing after BranchLens last
# read the tip.
REAL_GIT=$(command -v git)
cat > "$GATE_SHIM/git" <<SHIM
#!/bin/bash
if [ "\$1" = "-C" ] && [ "\$3" = "push" ] && [ -f "$GATE_SHIM/armed" ]; then
  rm -f "$GATE_SHIM/armed"
  "$REAL_GIT" -C "$GATE_WT" commit -q --allow-empty -m "Landed as the push started"
fi
exec "$REAL_GIT" "\$@"
SHIM
chmod +x "$GATE_SHIM/git"

GATE_LOG="$FIXTURE/server-gate.log"
PATH="$GATE_SHIM:$PATH" python3 -m branchlens "$GATE_REPO" --port 0 --no-browser \
  --toolkit "$GATE_TOOLKIT" --security-feed "$GATE_FEED" > "$GATE_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
GATE_PORT=$(wait_for_server "$GATE_LOG")
check "gate: server starts on a fixture with a submodule, a tag and a git stand-in" $?
GATE_TOKEN=$(page_token "$GATE_PORT")

# Start a check on the gate server and wait for it to end. $1: the JSON body.
gate_run() {
  local status
  status=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" "$1")
  [ "$status" = "200" ] && wait_for_security "$GATE_PORT" 'data["runner"]["active"] is False'
}

# ---- the run's base: the qualified ref, handed over as a commit id (g134) ----
# A tag named origin/main (fetched from someone's fork, say) on a commit
# origin lacks wins git's lookup of the short name, and would shrink the
# judged range to the commits after it.

git -C "$GATE_REPO" tag origin/main "$GATE_FIRST"
[ "$(git -C "$GATE_REPO" rev-parse -q --verify 'origin/main^{commit}' 2>/dev/null)" = "$GATE_FIRST" ]
check "run base: in the fixture the short name origin/main means the tag" $?
gate_run '{"branch": "gated"}'
check "run base: a run on gated starts and finishes" $?
json_check "run base: the answer names the base as the page shows it" "$GATE_POST" \
  'data == {"started": True, "branch": "gated", "base": "origin/main"}'
json_check "run base: preflight.sh got the commit id of refs/remotes/origin/main" "$GATE_TOOLKIT/last-call.json" \
  'data["args"][2:] == [extra]' "$GATE_MAIN"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "run base: /api/security names the run's base, not the commit id handed over" "$GATE_SEC" \
  'data["base"] == "origin/main" and data["verdict_word"] == "READY TO PUBLISH"'
git -C "$GATE_REPO" tag -d origin/main > /dev/null

# ---- the push sends the judged commit and nothing else (g9, g8) ----------------

json_check "push gate: the reason shows both commands, with the full commit id" "$GATE_SEC" \
  'data["push"]["allowed"] is True and data["push"]["reason"] == "Will run git push --recurse-submodules=no --no-follow-tags origin " + extra + ":refs/heads/gated, then git branch --set-upstream-to=refs/remotes/origin/gated gated."' "$GATE_TIP"
touch "$GATE_SHIM/armed"
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/push" "$GATE_TOKEN" "application/json" '{"branch": "gated"}')
expect_status "200" "push gate: POST /api/push answers HTTP 200"
json_check "push gate: the push goes through and the upstream step's output follows git's" "$GATE_POST" \
  'data["pushed"] is True and extra + " -> gated" in data["output"] and "set up to track" in data["output"]' "$GATE_TIP"
GATE_LANDED=$(git -C "$GATE_WT" rev-parse HEAD)
[ ! -e "$GATE_SHIM/armed" ] && [ "$GATE_LANDED" != "$GATE_TIP" ]
check "push gate: a commit landed on gated as the push started" $?
[ "$(git --git-dir="$GATE_ORIGIN" rev-parse -q --verify refs/heads/gated)" = "$GATE_TIP" ]
check "push gate: the remote has the judged commit" $?
! git --git-dir="$GATE_ORIGIN" cat-file -e "$GATE_LANDED" 2>/dev/null
check "push gate: the commit that landed after the check never reached the remote" $?
! git --git-dir="$GATE_SUB_REMOTE" rev-parse -q --verify refs/heads/gated > /dev/null
check "push gate: under submodule.recurse the submodule's unjudged commit is not pushed" $?
! git --git-dir="$GATE_ORIGIN" rev-parse -q --verify refs/tags/gated-tag > /dev/null
check "push gate: under push.followTags the tag is not pushed" $?
[ "$(git -C "$GATE_REPO" config --get branch.gated.remote)" = "origin" ] && \
  [ "$(git -C "$GATE_REPO" config --get branch.gated.merge)" = "refs/heads/gated" ]
check "push gate: the upstream step made origin/gated the branch's upstream" $?

# ---- the last push's result belongs to its branch and commit (g41) ------------

http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "last push: once the branch has moved, the push's result is not shown under it" "$GATE_SEC" \
  'data["push"]["commit"] == extra and data["push"]["pushed"] is None and data["push"]["output"] is None' "$GATE_LANDED"

# ---- never history the check did not judge (g11) -------------------------------
# gated now holds a commit the remote lacks: the one that landed. A run that
# judges only the commit after it must not unlock a push that sends both.

set_commit_date "2026-03-01T10:02:00 +0000"
printf 'def gated():\n    return 2\n' > "$GATE_WT/gated.py"
git -C "$GATE_WT" commit -q -am "Gated: second step"
GATE_TIP2=$(git -C "$GATE_WT" rev-parse HEAD)
gate_run '{"branch": "gated", "base": "'"$GATE_LANDED"'"}'
check "unjudged history: a run that judges only the newest commit finishes" $?
UNJUDGED_REASON="The check judged only ${GATE_LANDED:0:7}..${GATE_TIP2:0:7}; the push would also send 1 older commit it never judged: run the check against the remote's copy or from the empty tree."
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "unjudged history: READY on a narrow range leaves Push off, naming the range and the rest" "$GATE_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$UNJUDGED_REASON"
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/push" "$GATE_TOKEN" "application/json" '{"branch": "gated"}')
expect_status "409" "unjudged history: POST /api/push is refused with HTTP 409"
[ "$(git --git-dir="$GATE_ORIGIN" rev-parse -q --verify refs/heads/gated)" = "$GATE_TIP" ]
check "unjudged history: the remote keeps the commit judged before" $?
gate_run '{"branch": "gated"}'
check "unjudged history: a run against the remote's copy finishes" $?
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "unjudged history: judged from origin/main, the push is allowed" "$GATE_SEC" \
  'data["push"]["allowed"] is True and data["push"]["commit"] == extra' "$GATE_TIP2"

# ---- a given base: a commit id or a plain ref name (g152) ---------------------

expect_gate_bad_base() {
  local status
  status=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" \
    '{"branch": "gated", "base": "'"$1"'"}')
  [ "$status" = "400" ]
  check "given base: '$1' answers HTTP 400" $?
  json_check "given base: '$1' is refused as no commit" "$GATE_POST" \
    'data["error"] == extra' "'$1' is not a commit in this repository."
}
expect_gate_bad_base ':/x|text'
expect_gate_bad_base 'gated@{1}'
expect_gate_bad_base 'gated~1'
expect_gate_bad_base 'main..gated'

# ---- runs started from a terminal ----------------------------------------------
# Written by hand: $1 run_id, $2 more verdict.json fields, $3 more repository
# fields, $4 the feed's final verdict word ("" for none yet).

GATE_CHECK_FIELDS='"mode": "check", "base_ref": "origin/main", '
gate_terminal_run() {
  mkdir -p "$GATE_REPORTS/$1"
  printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "review_merged": true, "review_confirmed": true, %s"repository": {%s"branch": "gated", "commit": "%s"}}\n' \
    "$2" "$3" "$GATE_TIP2" > "$GATE_REPORTS/$1/verdict.json"
  printf '{"event": "start", "run_id": "%s", "base": "origin/main", "files": []}\n' "$1" >> "$GATE_FEED"
  if [ -n "$4" ]; then
    printf '{"event": "verdict", "text": "PIPELINE: %s", "verdict": "%s"}\n' "$4" "$4" >> "$GATE_FEED"
  fi
  http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
}

# Without review-scope.json, verdict.json's base_ref says where the judged
# history starts (g11).
gate_terminal_run "base-ref-run" "$GATE_CHECK_FIELDS" "" "READY TO PUBLISH"
json_check "unjudged history: with no review-scope.json, base_ref origin/main is resolved now" "$GATE_SEC" \
  'data["push"]["allowed"] is True'
gate_terminal_run "empty-tree-run" '"mode": "check", "base_ref": "empty-tree", ' "" "READY TO PUBLISH"
json_check "unjudged history: base_ref empty-tree judged the whole history" "$GATE_SEC" \
  'data["push"]["allowed"] is True'
gate_terminal_run "no-base-run" '"mode": "check", ' "" "READY TO PUBLISH"
json_check "unjudged history: with neither review-scope.json nor base_ref, Push stays off" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check does not record where the history it judged starts (no review-scope.json or base_ref): run the check again."'
gate_terminal_run "narrow-run" '"mode": "check", "base_ref": "'"$GATE_LANDED"'", ' "" "READY TO PUBLISH"
json_check "unjudged history: a narrow base_ref keeps Push off" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$UNJUDGED_REASON"
printf '{"fork_commit": "%s", "head_commit": "%s"}\n' "$GATE_MAIN" "$GATE_TIP" \
  > "$GATE_REPORTS/narrow-run/review-scope.json"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "unjudged history: a review-scope.json about another commit is not used" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == extra' "$UNJUDGED_REASON"
printf '{"fork_commit": "%s", "head_commit": "%s"}\n' "$GATE_MAIN" "$GATE_TIP2" \
  > "$GATE_REPORTS/narrow-run/review-scope.json"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "unjudged history: review-scope.json's fork_commit comes before base_ref" "$GATE_SEC" \
  'data["push"]["allowed"] is True'

# Only mode "check" judged a commit (g148).
gate_terminal_run "mode-unknown-run" '"mode": "?", "base_ref": "origin/main", ' "" "READY TO PUBLISH"
json_check "mode: a verdict with mode ? allows no push" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check did not judge a commit (mode ?): run the check again."'
gate_terminal_run "mode-missing-run" '"base_ref": "origin/main", ' "" "READY TO PUBLISH"
json_check "mode: a verdict with no mode allows no push" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check does not record what it judged (its verdict.json has no mode): run the check again."'

# The feed's final word must agree with verdict.json (g10).
gate_terminal_run "no-feed-verdict-run" "$GATE_CHECK_FIELDS" "" ""
json_check "feed verdict: READY in verdict.json but no verdict in the feed yet allows no push" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check has not written its final verdict to the feed yet: push once it has."'
gate_terminal_run "late-cancel-run" "$GATE_CHECK_FIELDS" "" "READY TO PUBLISH"
printf '{"event": "verdict", "text": "PIPELINE: INCONCLUSIVE - the run was cancelled", "verdict": "INCONCLUSIVE"}\n' >> "$GATE_FEED"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "feed verdict: READY in verdict.json, INCONCLUSIVE last in the feed, allows no push" "$GATE_SEC" \
  'data["verdict_word"] == "INCONCLUSIVE" and data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check ended INCONCLUSIVE in the feed, not READY TO PUBLISH: run the check again."'

# A verdict must come from this repository: one of its folders, symlinks
# resolved (g137).
mkdir -p "$FIXTURE/gate-elsewhere"
gate_terminal_run "elsewhere-run" "$GATE_CHECK_FIELDS" '"path": "'"$FIXTURE/gate-elsewhere"'", ' "READY TO PUBLISH"
json_check "other repository: a verdict naming another folder allows no push" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check ran on another repository (" + extra + "): run it here."' "$FIXTURE/gate-elsewhere"
json_check "other repository: nothing counts as judged here" "$GATE_SEC" \
  'data["judged"] is None'
gate_terminal_run "worktree-path-run" "$GATE_CHECK_FIELDS" '"path": "'"$GATE_WT/"'", ' "READY TO PUBLISH"
json_check "other repository: the branch's worktree, spelled another way, is this repository" "$GATE_SEC" \
  'data["push"]["allowed"] is True and data["judged"] == {"branch": "gated", "commit": extra}' "$GATE_TIP2"

# ---- a run this server cancelled never unlocks Push (g10) ----------------------
# The review's merge can write READY just before the Cancel lands.

printf 'FAKE_SLEEP=30\nFAKE_TERM_SILENT=1\n' > "$GATE_TOOLKIT/knobs"
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" '{"branch": "gated"}')
[ "$STATUS" = "200" ] && wait_for_security "$GATE_PORT" \
  'data["runner"]["active"] is True and [c["status"] for c in data["checks"] if c["name"].startswith("REV-01")] == ["running"]'
check "cancelled run: a slow run reaches its review" $?
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/cancel" "$GATE_TOKEN" "application/json" '{}')
wait_for_security "$GATE_PORT" 'data["runner"]["active"] is False'
check "cancelled run: the run stops" $?
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
CANCELLED_RUN=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["run_id"])' "$GATE_SEC")
printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "review_merged": true, "review_confirmed": true, %s"repository": {"branch": "gated", "commit": "%s"}}\n' \
  "$GATE_CHECK_FIELDS" "$GATE_TIP2" > "$GATE_REPORTS/$CANCELLED_RUN/verdict.json"
printf '{"event": "verdict", "text": "PIPELINE: READY TO PUBLISH", "verdict": "READY TO PUBLISH"}\n' >> "$GATE_FEED"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "cancelled run: READY in verdict.json and in the feed still allows no push" "$GATE_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check was cancelled: run it again."'
rm -f "$GATE_TOOLKIT/knobs"

# ---- the push remote is the one git push would pick (g7) ----------------------
# The fork has main, so it already holds every commit before the judged range.

git -C "$GATE_REPO" remote add fork "$GATE_FORK"
git -C "$GATE_REPO" push -q fork main
GATE_VIA_FORK="Will run git push --recurse-submodules=no --no-follow-tags fork $GATE_TIP2:refs/heads/gated."
gate_terminal_run "push-remote-run" "$GATE_CHECK_FIELDS" "" "READY TO PUBLISH"
git -C "$GATE_REPO" config branch.gated.pushRemote fork
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "push remote: branch.<name>.pushRemote is where the push goes, with no upstream step" "$GATE_SEC" \
  'data["push"]["allowed"] is True and data["push"]["remote"] == "fork" and data["push"]["reason"] == extra' "$GATE_VIA_FORK"
git -C "$GATE_REPO" config --unset branch.gated.pushRemote
git -C "$GATE_REPO" config remote.pushDefault fork
git -C "$GATE_REPO" config --unset branch.gated.remote
git -C "$GATE_REPO" config --unset branch.gated.merge
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "push remote: remote.pushDefault counts too, and a push remote never gets the upstream step" "$GATE_SEC" \
  'data["push"]["allowed"] is True and data["push"]["remote"] == "fork" and data["push"]["reason"] == extra' "$GATE_VIA_FORK"
git -C "$GATE_REPO" config --unset remote.pushDefault
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "push remote: with neither and no upstream, the push goes to origin with the upstream step" "$GATE_SEC" \
  'data["push"]["remote"] == "origin" and data["push"]["reason"] == "Will run git push --recurse-submodules=no --no-follow-tags origin " + extra + ":refs/heads/gated, then git branch --set-upstream-to=refs/remotes/origin/gated gated."' "$GATE_TIP2"
git -C "$GATE_REPO" config branch.gated.remote origin
git -C "$GATE_REPO" config branch.gated.merge refs/heads/gated

# ---- an upstream with another name (g88) ---------------------------------------
# A clone whose main was renamed master still tracks origin/main.

GATE_CLONE="$FIXTURE/gate-clone"
CLONE_REPORTS="$FIXTURE/gate-clone-reports"
CLONE_SEC="$FIXTURE/gate-clone-security.json"
CLONE_STATE="$FIXTURE/gate-clone-state.json"
CLONE_DIFF="$FIXTURE/gate-clone-diff.json"
git clone -q "$GATE_ORIGIN" "$GATE_CLONE"
git -C "$GATE_CLONE" config user.name "Test User"
git -C "$GATE_CLONE" config user.email "test@example.com"
git -C "$GATE_CLONE" branch -m main master
CLONE_LOG="$FIXTURE/server-gate-clone.log"
python3 -m branchlens "$GATE_CLONE" --port 0 --no-browser \
  --toolkit "$GATE_TOOLKIT" --security-feed "$CLONE_REPORTS/security-feed.jsonl" > "$CLONE_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
CLONE_PORT=$(wait_for_server "$CLONE_LOG")
check "renamed branch: server starts on a clone whose master tracks origin/main" $?
CLONE_TOKEN=$(page_token "$CLONE_PORT")
http_get "$CLONE_PORT" "$CLONE_STATE" "/api/state" > /dev/null
json_check "renamed branch: master is the default branch and not a first publish" "$CLONE_STATE" \
  'data["default_branch"] == "master" and data["first_publish"] is False'
http_get "$CLONE_PORT" "$CLONE_DIFF" "/api/diff?branch=master" > /dev/null
json_check "renamed branch: the header does not claim a push would publish master's whole history" "$CLONE_DIFF" \
  'data.get("whole_history") is not True and data["files"] == []'
STATUS=$(http_post "$CLONE_PORT" "$GATE_POST" "/api/run" "$CLONE_TOKEN" "application/json" '{"branch": "master"}')
expect_status "400" "renamed branch: a run on master compares with origin/main, which has all of it: HTTP 400"
json_check "renamed branch: the refusal names origin/main" "$GATE_POST" \
  'data["error"] == "master has no commits that origin/main lacks, so there is nothing to check: the check judges commits, not uncommitted edits."'
printf 'more\n' > "$GATE_CLONE/more.txt"
git -C "$GATE_CLONE" add more.txt
git -C "$GATE_CLONE" commit -q -m "Master: more work"
CLONE_TIP=$(git -C "$GATE_CLONE" rev-parse HEAD)
mkdir -p "$CLONE_REPORTS/renamed-run"
printf '{"verdict": "READY TO PUBLISH", "exit_code": 0, "review_merged": true, "review_confirmed": true, "mode": "check", "base_ref": "origin/main", "repository": {"branch": "master", "commit": "%s"}}\n' \
  "$CLONE_TIP" > "$CLONE_REPORTS/renamed-run/verdict.json"
printf '{"event": "start", "run_id": "renamed-run", "base": "origin/main", "files": []}\n{"event": "verdict", "text": "PIPELINE: READY TO PUBLISH", "verdict": "READY TO PUBLISH"}\n' \
  >> "$CLONE_REPORTS/security-feed.jsonl"
http_get "$CLONE_PORT" "$CLONE_SEC" "/api/security" > /dev/null
json_check "renamed branch: Push is off and names the upstream's other name" "$CLONE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The upstream of master is origin/main, a branch with another name: BranchLens pushes only to a branch of the same name, so push this one from a terminal."'

# ---- hostile run files and feed lines (g22) -------------------------------------
# The reports folder takes writes from the toolkit's agents too. A FIFO or a
# link to /dev/zero must not hang a request, and a line Python's parser
# refuses must not break /api/security, Cancel or Run.

mkdir -p "$GATE_REPORTS/fifo-run" "$GATE_REPORTS/zero-run"
mkfifo "$GATE_REPORTS/fifo-run/verdict.json"
ln -s /dev/zero "$GATE_REPORTS/zero-run/verdict.json"
append_gate_run() {
  # $1 run_id; $2, when given, the word of a verdict event after its start
  printf '{"event": "start", "run_id": "%s", "base": "origin/main", "files": []}\n' "$1" >> "$GATE_FEED"
  if [ -n "${2:-}" ]; then
    printf '{"event": "verdict", "text": "PIPELINE: %s", "verdict": "%s"}\n' "$2" "$2" >> "$GATE_FEED"
  fi
}
append_gate_run "fifo-run" "READY TO PUBLISH"
expect_get "$GATE_PORT" "$GATE_SEC" "/api/security" "200" "hostile files: a FIFO as verdict.json does not hang /api/security"
json_check "hostile files: a FIFO is no readable verdict.json" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check (fifo-run) left no readable verdict.json: run it again."'
append_gate_run "zero-run" "READY TO PUBLISH"
expect_get "$GATE_PORT" "$GATE_SEC" "/api/security" "200" "hostile files: a link to /dev/zero as verdict.json is answered at once"
json_check "hostile files: /dev/zero is no readable verdict.json" "$GATE_SEC" \
  'data["push"]["allowed"] is False and data["push"]["reason"] == "The latest check (zero-run) left no readable verdict.json: run it again."'

append_gate_run "parser-run"
python3 - "$GATE_FEED" <<'PY'
import sys

with open(sys.argv[1], "a", encoding="utf-8") as feed:
    # More digits than Python turns into an int (ValueError), and nesting
    # deeper than its parser follows (RecursionError).
    feed.write('{"event": "file", "path": "huge.py", "status": "clean", "count": ' + "9" * 5000 + "}\n")
    feed.write("[" * 100000 + "]" * 100000 + "\n")
    feed.write('{"event": "file", "path": "after.py", "status": "clean"}\n')
PY
expect_get "$GATE_PORT" "$GATE_SEC" "/api/security" "200" "hostile lines: /api/security answers HTTP 200 past a huge integer and deep nesting"
# A Python with no limit on the digits of an int (3.9 before 3.9.14, 3.10
# before 3.10.7) reads the first line as a valid event; only the nested one
# is refused there.
json_check "hostile lines: the two lines are skipped and the next one is read" "$GATE_SEC" \
  'data["run_id"] == "parser-run" and "after.py" in data["files"] and ("huge.py" not in data["files"] or not hasattr(sys, "get_int_max_str_digits"))'
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/cancel" "$GATE_TOKEN" "application/json" '{}')
expect_status "200" "hostile lines: /api/cancel answers HTTP 200"

# A FIFO as the feed itself, on a server of its own.
FIFO_FEED="$FIXTURE/fifo-feed/security-feed.jsonl"
mkdir -p "$FIXTURE/fifo-feed"
mkfifo "$FIFO_FEED"
FIFO_LOG="$FIXTURE/server-fifo-feed.log"
python3 -m branchlens "$GATE_REPO" --port 0 --no-browser \
  --security-feed "$FIFO_FEED" > "$FIFO_LOG" 2>&1 &
echo "$!" >> "$FIXTURE/extra-pids"
FIFO_PORT=$(wait_for_server "$FIFO_LOG")
check "hostile files: server starts with a FIFO as its feed" $?
FIFO_SEC="$FIXTURE/fifo-security.json"
expect_get "$FIFO_PORT" "$FIFO_SEC" "/api/security" "200" "hostile files: a FIFO as the feed does not hang /api/security"
json_check "hostile files: a FIFO as the feed reads as no run yet" "$FIFO_SEC" \
  'data["enabled"] is True and data["run_id"] is None'

# ---- events of another run (g146) ------------------------------------------------

append_gate_run "own-events-run" "READY TO PUBLISH"
printf '%s\n' '{"event": "file", "run_id": "older-run", "path": "straggler.py", "status": "checking"}' \
  '{"event": "verdict", "run_id": "older-run", "text": "PREFLIGHT: INCONCLUSIVE", "verdict": "INCONCLUSIVE"}' >> "$GATE_FEED"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "other run's events: a straggler naming another run_id leaves the latest run finished" "$GATE_SEC" \
  'data["run_id"] == "own-events-run" and data["running"] is False and data["verdict_word"] == "READY TO PUBLISH" and "straggler.py" not in data["files"]'

# ---- what a run started elsewhere judges before its verdict.json (g39) -----------

mkdir -p "$GATE_REPORTS/scope-only-run"
printf '{"base_ref": "origin/main", "fork_commit": "%s", "head_commit": "%s", "snapshot": false}\n' \
  "$GATE_MAIN" "$GATE_TIP2" > "$GATE_REPORTS/scope-only-run/review-scope.json"
append_gate_run "scope-only-run"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "judged: during a terminal run's gate phase, review-scope.json names the branch and commit" "$GATE_SEC" \
  'data["running"] is True and data["judged"] == {"branch": "gated", "commit": extra}' "$GATE_TIP2"
git -C "$GATE_REPO" branch twin "$GATE_TIP2"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "judged: when two branches sit at that commit, only the commit is named" "$GATE_SEC" \
  'data["judged"] == {"branch": None, "commit": extra}' "$GATE_TIP2"
git -C "$GATE_REPO" branch -D twin > /dev/null
printf '{"base_ref": "origin/main", "fork_commit": "%s", "head_commit": "%s", "snapshot": true}\n' \
  "$GATE_MAIN" "$GATE_TIP2" > "$GATE_REPORTS/scope-only-run/review-scope.json"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "judged: a snapshot of uncommitted work names nothing" "$GATE_SEC" \
  'data["judged"] is None'

# ---- a run started elsewhere is still writing (g136) -----------------------------
# scope-only-run reads as running, and its events have no time: as on the
# page, that counts as recent.

STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" '{"branch": "gated"}')
expect_status "409" "foreign run: /api/run while a run started elsewhere writes answers HTTP 409"
json_check "foreign run: the refusal says to wait for it" "$GATE_POST" \
  'data["error"] == "A check started outside this page is running: wait for it to finish."'
printf '{"event": "start", "run_id": "quiet-run", "utc": "2026-01-01T00:00:00Z", "base": "origin/main", "files": []}\n' >> "$GATE_FEED"
gate_run '{"branch": "gated"}'
check "foreign run: one silent for more than two hours no longer blocks a run" $?
# This server's own run, killed without a verdict: no Cancel, no settling time.
printf 'FAKE_SLEEP=30\nFAKE_TERM_SILENT=1\n' > "$GATE_TOOLKIT/knobs"
rm -f "$GATE_TOOLKIT/run.pid" "$GATE_TOOLKIT/sleep.pid"
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" '{"branch": "gated"}')
[ "$STATUS" = "200" ] && wait_for_security "$GATE_PORT" \
  'data["runner"]["active"] is True and data["runner"]["run_id"] == data["run_id"] and [c["status"] for c in data["checks"] if c["name"].startswith("REV-01")] == ["running"]'
check "own run: a slow run reaches its review" $?
kill -TERM "$(cat "$GATE_TOOLKIT/run.pid")" "$(cat "$GATE_TOOLKIT/sleep.pid")" 2>/dev/null
wait_for_security "$GATE_PORT" 'data["runner"]["active"] is False and data["running"] is True'
check "own run: killed outside BranchLens, it leaves its feed reading as running" $?
rm -f "$GATE_TOOLKIT/knobs"
gate_run '{"branch": "gated"}'
check "own run: this server's own dead run does not block the next one" $?

# ---- the server's lifetime (g150, g151, g153, g110) ------------------------------

python3 - "$PROJECT_DIR" "$FIXTURE/cache-feed.jsonl" <<'PY'
import sys

from branchlens import server

feed_path = sys.argv[2]
with open(feed_path, "w", encoding="utf-8") as feed:
    feed.write('{"event": "start", "run_id": "cache-run", "files": []}\n')
first = server.read_security_state(feed_path)
second = server.read_security_state(feed_path)
entry = server._FEED_CACHE["entry"]
ok = (list(server._FEED_CACHE) == ["entry"] and entry[1] is first and second is first
      and first["run_id"] == "cache-run")
sys.exit(0 if ok else 1)
PY
check "feed cache: stamp and state are kept together in one slot" $?

python3 - "$PROJECT_DIR" <<'PY'
import sys

from branchlens import server

runner = server.PipelineRunner()
runner.close()
refusal = runner.start(["true"], "/", {}, "/nonexistent/run.log", "main", "0" * 40, "empty-tree", "empty-tree")
sys.exit(0 if refusal == "BranchLens is shutting down." and runner.process is None else 1)
PY
check "server stop: once the server is stopping, no request can start a run" $?

python3 - "$PROJECT_DIR" <<'PY'
import socket
import sys
import threading
import time

from branchlens import server

# A client that declares a body and sends only part of it.
server.BranchLensHandler.page_token = "t"
server.BranchLensHandler.cookie_secret = "c"
server.BranchLensHandler.timeout = 1
httpd = server.create_server(0)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
port = httpd.server_address[1]
connection = socket.create_connection(("127.0.0.1", port), timeout=10)
request_head = ("POST /api/cancel HTTP/1.0\r\nHost: 127.0.0.1\r\n"
                "Origin: http://127.0.0.1:%d\r\nCookie: branchlens_%d=c\r\n"
                "X-BranchLens-Token: t\r\nContent-Type: application/json\r\n"
                "Content-Length: 100\r\n\r\n" % (port, port))
connection.sendall(request_head.encode("ascii") + b"{\"a\": 1")
started = time.monotonic()
try:
    answer = connection.recv(100)
except OSError:
    answer = b""
waited = time.monotonic() - started
httpd.shutdown()
sys.exit(0 if answer == b"" and waited < 8 else 1)
PY
check "idle client: a request that stops halfway is dropped after the socket timeout" $?
python3 - "$PROJECT_DIR" <<'PY'
import sys

from branchlens import server

sys.exit(0 if server.BranchLensHandler.timeout == 60 else 1)
PY
check "idle client: each socket read or write waits at most 60 seconds" $?
grep -q 'threading.stack_size(256 \* 1024 \* 1024)' "$SOURCE_DIR/server.py"
check "deep nesting: request threads get a 256 MiB stack" $?

# Closing the terminal (SIGHUP) stops the server and the run it started.
HUP_TOOLKIT="$FIXTURE/hup-toolkit"
HUP_FEED="$FIXTURE/hup-reports/security-feed.jsonl"
mkdir -p "$HUP_TOOLKIT"
cp "$TOOLKIT/preflight.sh" "$HUP_TOOLKIT/preflight.sh"
printf 'FAKE_SLEEP=30\n' > "$HUP_TOOLKIT/knobs"
HUP_LOG="$FIXTURE/server-hup.log"
# Started through a launcher that puts SIGHUP back to its default first: a
# suite run under nohup inherits it ignored, which the server respects.
python3 -c 'import signal, sys; signal.signal(signal.SIGHUP, signal.SIG_DFL); sys.path.insert(0, sys.argv[1]); sys.argv = ["branchlens"] + sys.argv[2:]; from branchlens import server; server.main()' \
  "$PROJECT_DIR/src" "$GATE_REPO" --port 0 --no-browser \
  --toolkit "$HUP_TOOLKIT" --security-feed "$HUP_FEED" > "$HUP_LOG" 2>&1 &
HUP_SERVER_PID=$!
echo "$HUP_SERVER_PID" >> "$FIXTURE/extra-pids"
HUP_PORT=$(wait_for_server "$HUP_LOG")
HUP_TOKEN=$(page_token "$HUP_PORT")
STATUS=$(http_post "$HUP_PORT" "$GATE_POST" "/api/run" "$HUP_TOKEN" "application/json" '{"branch": "gated"}')
[ "$STATUS" = "200" ] && wait_for_security "$HUP_PORT" \
  'data["runner"]["active"] is True and [c["status"] for c in data["checks"] if c["name"].startswith("REV-01")] == ["running"]'
check "hangup: a slow run reaches its review" $?
kill -HUP "$HUP_SERVER_PID"
process_ends "$HUP_SERVER_PID"
check "hangup: SIGHUP stops the server" $?
process_ends "$(cat "$HUP_TOOLKIT/run.pid")" && process_ends "$(cat "$HUP_TOOLKIT/sleep.pid")"
check "hangup: the run it started is stopped too" $?
grep -q "Stopped the security check this server had started." "$HUP_LOG"
check "hangup: the server says it stopped the run" $?

# ---- --no-push-host and the host a push really reaches (g135) --------------------

SSH_SHIM="$FIXTURE/ssh-shim"
mkdir -p "$SSH_SHIM"
# ssh as BranchLens finds it on PATH: `ssh -G -- <host>` prints the
# configuration ssh would use; this one maps the alias work-alias.
cat > "$SSH_SHIM/ssh" <<'SSH'
#!/bin/bash
if [ "$1" = "-G" ] && [ "$2" = "--" ]; then
  if [ "$3" = "work-alias" ]; then
    echo "hostname git.work.example"
  else
    echo "hostname $3"
  fi
  echo "port 22"
  exit 0
fi
exit 255
SSH
chmod +x "$SSH_SHIM/ssh"
PATH="$SSH_SHIM:$PATH" python3 - "$PROJECT_DIR" <<'PY'
import sys

from branchlens import publish

hosts = {
    "ssh://code.work%2eexample/team/app.git": "code.work.example",
    "https://code.work%2Eexample/team/app.git": "code.work.example",
    "me@[2001:db8::1]:team/app.git": "2001:db8::1",
    "[::1]:team/app.git": "::1",
    "me@scp.work.example:team/app.git": "scp.work.example",
    "/srv/repos/a:b": "",
}
for url, host in hosts.items():
    if publish.url_host(url) != host:
        print("url_host", url, "->", publish.url_host(url))
        sys.exit(1)
blocked = ["work.example"]
cases = [
    (["work-alias:team/app.git"], "git.work.example"),
    (["ssh://me@work-alias/team/app.git"], "git.work.example"),
    (["ssh://code.work%2eexample/team/app.git"], "code.work.example"),
    (["other-alias:team/app.git"], None),
    (["https://work-alias/team/app.git"], None),
]
for urls, expected in cases:
    found = publish.find_blocked_host(".", "origin", urls, blocked)
    if found != expected:
        print("find_blocked_host", urls, "->", found)
        sys.exit(1)
sys.exit(0)
PY
check "blocked host: %-escapes, IPv6 literals and an ssh alias's HostName are all checked" $?

# ---- the page's Content-Security-Policy and the common headers (g155) -------------

GATE_PAGE="$FIXTURE/gate-page.html"
GATE_HEADERS="$FIXTURE/gate-page-headers.txt"
GATE_HEADERS2="$FIXTURE/gate-page-headers-2.txt"
curl -s -m 5 -b "$(cookie_for "$GATE_PORT")" -D "$GATE_HEADERS" -o "$GATE_PAGE" "http://127.0.0.1:$GATE_PORT/"
python3 - "$GATE_HEADERS" "$GATE_PAGE" <<'PY'
import re
import sys

headers = open(sys.argv[1], encoding="latin-1").read()
page = open(sys.argv[2], encoding="utf-8").read()
match = re.search(r"(?im)^Content-Security-Policy: (.*?)\r?$", headers)
if match is None:
    sys.exit(1)
expected = (r"default-src 'none'; script-src 'nonce-([A-Za-z0-9_-]{16,})'; "
            r"style-src 'nonce-\1'; connect-src 'self'; img-src 'self' data:; "
            r"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
policy = re.fullmatch(expected, match.group(1))
if policy is None:
    sys.exit(1)
nonce = policy.group(1)
ok = (page.count("<script") == 1 and page.count('<script nonce="' + nonce + '">') == 1
      and page.count("<style") == 1 and page.count('<style nonce="' + nonce + '">') == 1)
sys.exit(0 if ok else 1)
PY
check "page: a strict Content-Security-Policy names a nonce the page's one script and one style carry" $?
curl -s -m 5 -b "$(cookie_for "$GATE_PORT")" -D "$GATE_HEADERS2" -o /dev/null "http://127.0.0.1:$GATE_PORT/"
FIRST_POLICY=$(grep -i '^Content-Security-Policy' "$GATE_HEADERS")
SECOND_POLICY=$(grep -i '^Content-Security-Policy' "$GATE_HEADERS2")
[ -n "$FIRST_POLICY" ] && [ -n "$SECOND_POLICY" ] && [ "$FIRST_POLICY" != "$SECOND_POLICY" ]
check "page: every load of the page gets a new nonce" $?

# $1 what is asked for; then curl's arguments.
expect_common_headers() {
  local description="$1"
  shift
  local headers_file="$FIXTURE/common-headers.txt"
  rm -f "$headers_file"
  curl -s -m 5 -b "$(cookie_for "$GATE_PORT")" -D "$headers_file" -o /dev/null "$@"
  grep -qi '^X-Content-Type-Options: *nosniff' "$headers_file" && \
    grep -qi '^Referrer-Policy: *no-referrer' "$headers_file"
  check "common headers: $description carries nosniff and no-referrer" $?
}
expect_common_headers "the page" "http://127.0.0.1:$GATE_PORT/"
expect_common_headers "a JSON answer" "http://127.0.0.1:$GATE_PORT/api/state"
expect_common_headers "the empty favicon answer" "http://127.0.0.1:$GATE_PORT/favicon.ico"
expect_common_headers "a 404" "http://127.0.0.1:$GATE_PORT/no-such-page"
expect_common_headers "the 501 to a CORS preflight" -X OPTIONS "http://127.0.0.1:$GATE_PORT/api/run"

# ---- requests another page makes the browser send (g77) ---------------------------
# A browser says where a request comes from; only this page itself, or the
# user typing the address, may make BranchLens run git.

# $1 the Sec-Fetch-Site value, $2 the path, $3 the expected HTTP status.
expect_fetch_site() {
  local status
  status=$(curl -s -m 5 -b "$(cookie_for "$GATE_PORT")" -o "$GATE_POST" -w '%{http_code}' -H "Sec-Fetch-Site: $1" \
    "http://127.0.0.1:$GATE_PORT$2")
  [ "$status" = "$3" ]
  check "cross-site: Sec-Fetch-Site $1 on $2 answers HTTP $3" $?
}
expect_fetch_site cross-site /api/state 403
json_check "cross-site: the refusal says requests from other pages are refused" "$GATE_POST" \
  'data == {"error": "Requests from other web pages are refused."}'
# Another port of this machine is the same site, but not the same origin.
expect_fetch_site same-site "/api/diff?branch=gated" 403
expect_fetch_site same-origin /api/state 200
expect_fetch_site none /api/state 200
expect_fetch_site cross-site / 200

# ---- the token in the printed URL becomes a cookie (g6) ---------------------------
# Any user or program on this machine can reach 127.0.0.1. The page and the
# API answer only a browser that opened the URL printed at start.

NO_COOKIE_ERROR="Missing or outdated access cookie: open the URL BranchLens printed in the terminal when it started."
ACCESS_BODY="$FIXTURE/access-body.txt"
ACCESS_HEADERS="$FIXTURE/access-headers.txt"
ACCESS_JAR="$FIXTURE/access-cookies.txt"
GATE_COOKIE_TOKEN=$(cat "$FIXTURE/cookies/$GATE_PORT")
GATE_LAUNCH_CODE=$(cat "$FIXTURE/launch-codes/$GATE_PORT")
GATE_URL=$(sed -n 's|^BranchLens serving gate at \(http://127\.0\.0\.1:[0-9]*/?token=[0-9a-f]*\)$|\1|p' "$GATE_LOG")
[ "${#GATE_LAUNCH_CODE}" -eq 64 ] && [ "$GATE_URL" = "http://127.0.0.1:$GATE_PORT/?token=$GATE_LAUNCH_CODE" ]
check "access: the startup line prints the URL with the 64-hex-digit launch code" $?

STATUS=$(curl -s -m 5 -D "$ACCESS_HEADERS" -o "$ACCESS_BODY" -w '%{http_code}' "http://127.0.0.1:$GATE_PORT/")
[ "$STATUS" = "403" ] && grep -q "printed in the terminal" "$ACCESS_BODY" && ! grep -q "$GATE_COOKIE_TOKEN" "$ACCESS_BODY" \
  && ! grep -q "$GATE_TOKEN" "$ACCESS_BODY" && ! grep -q "$GATE_LAUNCH_CODE" "$ACCESS_BODY"
check "access: GET / without the cookie is a 403 page that says to open the printed URL, and holds no secret" $?
grep -qi "^Content-Security-Policy: default-src 'none';" "$ACCESS_HEADERS"
check "access: the refusal page allows no script and no style" $?
for api_path in /api/state /api/security "/api/diff?branch=gated" /api/graph; do
  STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' "http://127.0.0.1:$GATE_PORT$api_path")
  expect_status "403" "access: GET $api_path without the cookie answers HTTP 403"
  json_check "access: GET $api_path without the cookie says to open the printed URL" "$ACCESS_BODY" \
    'data == {"error": extra}' "$NO_COOKIE_ERROR"
done
STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' \
  -b "branchlens_$GATE_PORT=0000000000000000000000000000000000000000000000000000000000000000" \
  "http://127.0.0.1:$GATE_PORT/api/state")
expect_status "403" "access: a wrong token in the cookie answers HTTP 403"
CLONE_COOKIE_TOKEN=$(cat "$FIXTURE/cookies/$CLONE_PORT")
STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' -b "branchlens_$GATE_PORT=$CLONE_COOKIE_TOKEN" \
  "http://127.0.0.1:$GATE_PORT/api/state")
expect_status "403" "access: another server's token answers HTTP 403"
STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' -b "branchlens_$CLONE_PORT=$GATE_COOKIE_TOKEN" \
  "http://127.0.0.1:$GATE_PORT/api/state")
expect_status "403" "access: the right token under another port's cookie name answers HTTP 403"

# A page on another 127.0.0.1 port can plant branchlens_<port> with a wrong
# value (02 F-25). The browser then sends it next to the real one, and first
# when its Path is narrower. Any value that matches lets the request in.
PLANTED_COOKIE="branchlens_$GATE_PORT=planted"
STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' -b "$PLANTED_COOKIE" "http://127.0.0.1:$GATE_PORT/")
[ "$STATUS" = "403" ] && grep -q "Open the URL BranchLens printed in the terminal" "$ACCESS_BODY"
check "planted cookie: alone it gets the 403 page that says to open the printed URL" $? "got HTTP $STATUS"
for planted_place in first last; do
  if [ "$planted_place" = "first" ]; then
    cookie_pair="$PLANTED_COOKIE; branchlens_$GATE_PORT=$GATE_COOKIE_TOKEN"
  else
    cookie_pair="branchlens_$GATE_PORT=$GATE_COOKIE_TOKEN; $PLANTED_COOKIE"
  fi
  STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' -b "$cookie_pair" "http://127.0.0.1:$GATE_PORT/")
  expect_status "200" "planted cookie: GET / with the planted cookie $planted_place and the real one answers HTTP 200"
  STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' -b "$cookie_pair" "http://127.0.0.1:$GATE_PORT/api/state")
  expect_status "200" "planted cookie: GET /api/state with the planted cookie $planted_place and the real one answers HTTP 200"
done
STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' \
  -b "$PLANTED_COOKIE; branchlens_$GATE_PORT=$GATE_COOKIE_TOKEN" -H "X-BranchLens-Token: $GATE_TOKEN" \
  -H "Origin: http://127.0.0.1:$GATE_PORT" \
  -H "Content-Type: application/json" --data-binary '{}' "http://127.0.0.1:$GATE_PORT/api/cancel")
expect_status "200" "planted cookie: a POST with the planted cookie first, then the real one, is accepted"
# A browser jar as the planting page leaves it: one cookie at Path=/ (which
# replaced the real one) and one at Path=/api. One visit to the printed URL
# lets the browser back in.
for planted_path in / /api; do
  printf '127.0.0.1\tFALSE\t%s\tFALSE\t0\tbranchlens_%s\tplanted\n' "$planted_path" "$GATE_PORT" > "$ACCESS_JAR"
  STATUS=$(curl -s -m 5 -c "$ACCESS_JAR" -b "$ACCESS_JAR" -o "$ACCESS_BODY" -w '%{http_code}' \
    "http://127.0.0.1:$GATE_PORT/api/state")
  expect_status "403" "planted cookie at Path=$planted_path: the API answers HTTP 403 before the printed URL is opened"
  STATUS=$(curl -s -m 5 -L -c "$ACCESS_JAR" -b "$ACCESS_JAR" -o "$ACCESS_BODY" -w '%{http_code}' "$GATE_URL")
  [ "$STATUS" = "200" ] && grep -q "<title>BranchLens</title>" "$ACCESS_BODY"
  check "planted cookie at Path=$planted_path: opening the printed URL again loads the page" $? "got HTTP $STATUS"
  STATUS=$(curl -s -m 5 -c "$ACCESS_JAR" -b "$ACCESS_JAR" -o "$ACCESS_BODY" -w '%{http_code}' \
    "http://127.0.0.1:$GATE_PORT/api/state")
  expect_status "200" "planted cookie at Path=$planted_path: after that the API answers HTTP 200"
done
rm -f "$ACCESS_JAR"
STATUS=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$GATE_PORT/favicon.ico")
expect_status "204" "access: the favicon needs no cookie"

STATUS=$(curl -s -m 5 -D "$ACCESS_HEADERS" -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$GATE_PORT/?token=0000000000000000000000000000000000000000000000000000000000000000")
[ "$STATUS" = "403" ] && ! grep -qi '^Set-Cookie' "$ACCESS_HEADERS"
check "access: a wrong token in the URL answers HTTP 403 and sets no cookie" $?
# Another local server the browser visits learns the cookie's value; it must
# not work as the launch code, or it would hand out the page token.
for wrong_code in "$GATE_COOKIE_TOKEN" "$GATE_TOKEN"; do
  STATUS=$(curl -s -m 5 -D "$ACCESS_HEADERS" -o "$ACCESS_BODY" -w '%{http_code}' \
    "http://127.0.0.1:$GATE_PORT/?token=$wrong_code")
  [ "$STATUS" = "403" ] && ! grep -qi '^Set-Cookie' "$ACCESS_HEADERS" && ! grep -qi '^Location' "$ACCESS_HEADERS"
  check "access: the cookie secret or the page token in the URL answers HTTP 403 and hands out nothing" $?
done
STATUS=$(curl -s -m 5 -D "$ACCESS_HEADERS" -o /dev/null -w '%{http_code}' "$GATE_URL")
expect_status "303" "access: the printed URL answers HTTP 303"
python3 - "$ACCESS_HEADERS" "$GATE_PORT" "$GATE_COOKIE_TOKEN" "$GATE_TOKEN" <<'PY'
import sys

lines = open(sys.argv[1], encoding="latin-1").read().replace("\r", "").split("\n")
headers = {}
for line in lines[1:]:
    name, separator, value = line.partition(": ")
    if separator:
        headers.setdefault(name.lower(), []).append(value)
cookie = "branchlens_" + sys.argv[2] + "=" + sys.argv[3] + "; HttpOnly; SameSite=Strict; Path=/"
location = "/#token=" + sys.argv[4]
sys.exit(0 if headers.get("location") == [location] and headers.get("set-cookie") == [cookie] else 1)
PY
check "access: it sets branchlens_<port>=<cookie secret> (HttpOnly, SameSite=Strict, Path=/) and sends the browser to /#token=<page token>" $?
STATUS=$(curl -s -m 5 -D "$ACCESS_HEADERS" -o /dev/null -w '%{http_code}' "$GATE_URL")
[ "$STATUS" = "303" ] && grep -qi "^Location: /#token=$GATE_TOKEN" "$ACCESS_HEADERS"
check "access: the printed URL works again, for a second browser" $?
rm -f "$ACCESS_JAR"
STATUS=$(curl -s -m 5 -L -c "$ACCESS_JAR" -b "$ACCESS_JAR" -o "$ACCESS_BODY" -w '%{http_code}' "$GATE_URL")
[ "$STATUS" = "200" ] && grep -q "<title>BranchLens</title>" "$ACCESS_BODY" && ! grep -q "$GATE_TOKEN" "$ACCESS_BODY"
check "access: a client that follows the printed URL gets the page, which holds no page token" $?
STATUS=$(curl -s -m 5 -o "$ACCESS_BODY" -w '%{http_code}' -H "X-BranchLens-Token: $GATE_TOKEN" \
  -H "Origin: http://127.0.0.1:$GATE_PORT" \
  -H "Content-Type: application/json" --data-binary '{}' "http://127.0.0.1:$GATE_PORT/api/cancel")
expect_status "403" "access: a POST with the page token and Origin but no cookie answers HTTP 403"

# ---- the final word as older toolkits wrote it (g10) ------------------------------
# The merge step writes a verdict with no word, then `phase verdict done`
# with the word; older toolkits put "PIPELINE: " before it.

gate_terminal_run "prefixed-word-run" "$GATE_CHECK_FIELDS" "" ""
printf '%s\n' '{"event": "verdict", "text": "PIPELINE: READY TO PUBLISH - no blocking findings"}' \
  '{"event": "phase", "name": "verdict", "status": "done", "detail": "PIPELINE: READY TO PUBLISH"}' >> "$GATE_FEED"
http_get "$GATE_PORT" "$GATE_SEC" "/api/security" > /dev/null
json_check "feed verdict: a final word written after a PIPELINE: prefix still counts" "$GATE_SEC" \
  'data["verdict_word"] == "READY TO PUBLISH" and data["running"] is False and data["push"]["allowed"] is True'

# ---- the push ignores git variables that name another repository (g5) -------------

ENV_PUSH_ORIGIN="$FIXTURE/env-push-origin.git"
ENV_PUSH_REPO="$FIXTURE/env-push"
ENV_PUSH_DECOY="$FIXTURE/env-push-decoy"
git init -q --bare -b main "$ENV_PUSH_ORIGIN"
for repo_dir in "$ENV_PUSH_REPO" "$ENV_PUSH_DECOY"; do
  new_repo "$repo_dir"
  printf '%s\n' "$repo_dir" > "$repo_dir/file.txt"
  git -C "$repo_dir" add -A
  git -C "$repo_dir" commit -q -m "First commit"
done
git -C "$ENV_PUSH_REPO" remote add origin "$ENV_PUSH_ORIGIN"
ENV_PUSH_TIP=$(git -C "$ENV_PUSH_REPO" rev-parse HEAD)
python3 - "$PROJECT_DIR" "$ENV_PUSH_REPO" "$ENV_PUSH_DECOY" "$ENV_PUSH_TIP" <<'PY'
import os
import sys

from branchlens import publish

repo, decoy, tip = sys.argv[2], sys.argv[3], sys.argv[4]
# As if BranchLens had been started from a shell that points git elsewhere.
os.environ["GIT_DIR"] = os.path.join(decoy, ".git")
os.environ["GIT_WORK_TREE"] = decoy
pushed, output = publish.push_branch(repo, "origin", "main", tip, False)
if not pushed:
    print(output)
sys.exit(0 if pushed else 1)
PY
check "push environment: GIT_DIR and GIT_WORK_TREE from the shell do not redirect the push" $?
[ "$(git --git-dir="$ENV_PUSH_ORIGIN" rev-parse -q --verify refs/heads/main)" = "$ENV_PUSH_TIP" ]
check "push environment: the judged commit reached the branch's own remote" $?

# ---- a remote tip the caller already read (g79) -------------------------------------
# read_push_facts reuses it only for the very ref it resolves, after the
# upstream lookup: a master tracking origin/main never takes origin/master's.

python3 - "$PROJECT_DIR" "$GATE_REPO" "$GATE_CLONE" <<'PY'
import sys

from branchlens import gitops

gate, clone = sys.argv[2], sys.argv[3]
stand_in = "f" * 40
gate_main = gitops.read_ref_commit(gate, "refs/remotes/origin/main")
clone_main = gitops.read_ref_commit(clone, "refs/remotes/origin/main")
cases = [
    (gate, "main", "refs/remotes/origin/main", stand_in),
    (gate, "main", "refs/remotes/origin/other", gate_main),
    (clone, "master", "refs/remotes/origin/master", clone_main),
    (clone, "master", "refs/remotes/origin/main", stand_in),
]
for folder, branch, known_ref, expected in cases:
    facts = gitops.read_push_facts(folder, branch, known_ref, stand_in)
    if facts["remote_tip"] != expected:
        print(branch, known_ref, "->", facts["remote_tip"])
        sys.exit(1)
sys.exit(0 if len(gate_main) == 40 and len(clone_main) == 40 else 1)
PY
check "push facts: a remote tip read by the caller is reused only for the ref the push resolves to" $?

# ---- starting over a run that looks stalled (g21) ----------------------------------
# The page sends override_stalled after asking the user. The server honours
# it only when the feed itself has been silent for at least 10 minutes.

STALLED_ERROR="A check started outside this page is running: wait for it to finish."
utc_seconds_ago() {
  python3 -c 'import sys, time; print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - int(sys.argv[1]))))' "$1"
}
printf '{"event": "start", "run_id": "fresh-foreign-run", "utc": "%s", "base": "origin/main", "files": []}\n' \
  "$(utc_seconds_ago 0)" >> "$GATE_FEED"
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" \
  '{"branch": "gated", "override_stalled": true}')
expect_status "409" "stalled override: a run elsewhere that wrote just now still refuses the override: HTTP 409"
json_check "stalled override: the refusal is the usual one" "$GATE_POST" 'data["error"] == extra' "$STALLED_ERROR"
printf '{"event": "start", "run_id": "stalled-foreign-run", "utc": "%s", "base": "origin/main", "files": []}\n' \
  "$(utc_seconds_ago 660)" >> "$GATE_FEED"
STATUS=$(http_post "$GATE_PORT" "$GATE_POST" "/api/run" "$GATE_TOKEN" "application/json" '{"branch": "gated"}')
expect_status "409" "stalled override: without the override, a run elsewhere silent for 11 minutes still blocks: HTTP 409"
gate_run '{"branch": "gated", "override_stalled": true}'
check "stalled override: with it, a run elsewhere silent for 11 minutes no longer blocks: the run starts and finishes" $?

# ---------------------------------------------------------------- security page
# The banner, badges and verdict card read what the run judged. These are
# source checks: the suite has no browser.

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# The Run card, the banner and the verdict card all name the empty-tree base
# through one helper, and the idle Run card reads first_publish.
calls = ["appendRunBase(runCard.base, baseKey)", "appendRunBase(banner, feed.base)",
         "appendRunBase(context, feed.base)"]
if any(call not in text for call in calls):
    sys.exit(1)
if '"nothing (first publish)"' not in text or '": the whole history is checked"' not in text:
    sys.exit(1)
if "currentState.first_publish === true" not in text or "baseLabel = defaultRunBase(target);" not in text:
    sys.exit(1)
sys.exit(0)
PY
check "first publish: the Run card, banner and verdict card say a run on the empty tree compares with nothing" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
start = text.index("function defaultRunBase(")
body = text[start:text.index("\n}\n", start)]
# The default branch's base is its push remote's copy, as the server picks it.
if 'currentState.push_remote + "/" + currentState.default_branch' not in body:
    sys.exit(1)
if body.index("currentState.first_publish === true") > body.index("currentState.push_remote +"):
    sys.exit(1)
sys.exit(0)
PY
check "push remote: the idle Run card names the default branch's push remote copy as its base" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
banner = function_body("renderSecurityBanner")
# the toolkit's own sentence (which may say "run security-pipeline") stays
# on the Check tab; the banner names branch, time and word
if "feed.verdict)" in banner or "createTextNode(feed.verdict" in banner:
    sys.exit(1)
if "Last security check" not in banner or "rel-time" not in banner:
    sys.exit(1)
if 'securityBannerElement.addEventListener("click"' not in text:
    sys.exit(1)
sys.exit(0)
PY
check "security page: the banner names the branch and time, not the pipeline's sentence, and opens the Check tab" $?

grep -q 'var showBadges = selectionIsJudged(view);' "$SOURCE_DIR/static/app.html" && \
  grep -q 'function selectionIsJudged' "$SOURCE_DIR/static/app.html"
check "security page: badges show only on the branch and commit the run judged" $?

grep -q 'linkRowToFile(row, finding.file, finding.line)' "$SOURCE_DIR/static/app.html" && \
  grep -q 'function jumpToPendingLine' "$SOURCE_DIR/static/app.html" && \
  grep -q 'selectBranch(judgedName);' "$SOURCE_DIR/static/app.html"
check "security page: a finding opens the judged branch's file at its line" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
start = text.index(".issue-title {")
rule = text[start:text.index("}", start)]
sys.exit(1 if "nowrap" in rule or "ellipsis" in rule else 0)
PY
check "security page: finding titles wrap instead of being cut" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
panel = function_body("renderCheckPanel")
update = function_body("updateCheckTimeline")
if "updateCheckTimeline(" not in panel:
    sys.exit(1)
if "syncRows(parts.gate.body" not in update or "syncRows(parts.review.body" not in update:
    sys.exit(1)
# the timeline element itself is never emptied and redrawn
if "clearNode(timeline)" in text or "clearNode(runCard.timeline)" in text:
    sys.exit(1)
sys.exit(0)
PY
check "security page: the Check timeline updates its rows in place instead of rebuilding" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
badge = function_body("securityBadgeInfo")
finished = function_body("makeFinishedState")
dive = function_body("makeDiveRow")
# before the merge a count is of candidates; after it, of the verdict's findings
if '"candidate", "candidates"' not in badge or "verdictFindings[path]" not in badge:
    sys.exit(1)
if 'text: "waiting"' not in badge or 'text: "reading"' not in badge or '"unverified"' not in badge:
    sys.exit(1)
if '"candidate", "candidates"' not in finished or '"candidate", "candidates"' not in dive:
    sys.exit(1)
if '"finding", "findings"' in finished or '"finding", "findings"' in dive or "nothing found" in finished:
    sys.exit(1)
if '"ADVISORY · "' not in text or '"WARNINGS · "' in text:
    sys.exit(1)
sys.exit(0)
PY
check "security page: rows count candidates, badges count the verdict's findings once the review merged" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
review = function_body("buildReviewStage")
verdict = function_body("buildVerdictStage")
summary = function_body("verdictSummaryText")
if '"verifying findings, "' not in review or '"merging the results"' not in review:
    sys.exit(1)
if "Math.min(fraction, 0.9)" not in review or "feed.review_incomplete" not in review:
    sys.exit(1)
if '"confirming the verdict"' not in verdict:
    sys.exit(1)
if "feed.mechanical_advisory" not in summary or '"LLM review incomplete"' not in summary:
    sys.exit(1)
sys.exit(0)
PY
check "security page: the review stage names the step in progress, an incomplete review, and the checks' advisory findings" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
if "noticeSecurityMiss(" not in function_body("handleSecurityResult"):
    sys.exit(1)
if "noticeSecurityMiss(" not in function_body("pollSecurity"):
    sys.exit(1)
if "securityUnreadable()" not in function_body("runButtonState"):
    sys.exit(1)
# the output box follows new lines only when the reader is at its end
if "logWasAtBottom" not in function_body("updateRunCardWith"):
    sys.exit(1)
sys.exit(0)
PY
check "security page: failing /api/security answers are said and hold Run and Push; the run output keeps the reader's place" $?

grep -q '"NOT FULLY EXAMINED"' "$SOURCE_DIR/static/app.html" && \
  ! grep -q 'area-sigil' "$SOURCE_DIR/static/app.html" && \
  ! grep -q '"COULD NOT RUN"' "$SOURCE_DIR/static/app.html"
check "security page: partly examined areas are not reported as could not run" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# NOT POSSIBLE is "not examined": an area can be one without anything failing to run
if '"NOT POSSIBLE": "not examined"' not in text or "could not run" in text:
    sys.exit(1)
if '" areas not examined"' not in function_body("verdictSummaryText"):
    sys.exit(1)
# the banner and the card note use the push reason's verb
if "has changed since" in text or '" has moved since"' not in function_body("renderSecurityBanner"):
    sys.exit(1)
if '" has moved since this check "' not in function_body("makeVerdictCard"):
    sys.exit(1)
if 'pluralize(rows.length, "check", "checks")' not in function_body("buildGateStage"):
    sys.exit(1)
if "mechanical_advisory" not in function_body("buildStages"):
    sys.exit(1)
if "the verifications below" in text or "none was verified" in text:
    sys.exit(1)
if "up to 20 are verified" not in function_body("reviewStageItems"):
    sys.exit(1)
sys.exit(0)
PY
check "security page: NOT POSSIBLE reads not examined, a moved branch has one verb, the gate counts checks and opens on advisory findings, candidates are verified up to 20" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# after a merged review, a step row left running is not a run that ended early
ended = function_body("endedEarlyStage")
if "reviewMerged(view.feed)" not in ended or 'stages.review.state === "stopped"' not in ended:
    sys.exit(1)
for name in ("makeReviewerRow", "makeStepRow"):
    if "sentNoFinalReport(check.status, view)" not in function_body(name):
        sys.exit(1)
if "sentNoFinalReport(entry.status, view)" not in function_body("makeDiveRow"):
    sys.exit(1)
if '"no report"' not in function_body("makeNoReportState"):
    sys.exit(1)
for name in ("reviewerRowItem", "diveRowItem", "stepRowItem"):
    if "reviewRowContext(view)" not in function_body(name):
        sys.exit(1)
sys.exit(0)
PY
check "security page: after a merged review, a step with no final report reads no report, and the run is not said to have ended early" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# every selection, the one restored from the address included, redraws the
# "Last check" line on the Check tab, not only the Run card
selection = function_body("updateSidebarSelection")
if 'if (viewMode === "check") {\n    renderCheckPanel();' not in selection:
    sys.exit(1)
if "switchView(saved.view)" not in function_body("openStartingView"):
    sys.exit(1)
sys.exit(0)
PY
check "security page: a branch selected on the Check tab, a restored one included, redraws the Last check line" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# two rows with one key (two titles for one REV id) keep a row each, and a
# child that is not reused is removed even when its key repeated
sync = function_body("syncRows")
if "keyCounts" not in sync or "element.rowKey = key;" not in sync:
    sys.exit(1)
if "wanted.indexOf(oldChildren[r]) === -1" not in sync:
    sys.exit(1)
sys.exit(0)
PY
check "security page: rows that share a key are kept one each, never multiplied" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# a commit picked in the Tree is kept in the address and selected again on reload
remember = function_body("rememberViewInAddress")
if '"commit=" + encodeURIComponent(selectedCommitSha)' not in remember:
    sys.exit(1)
if "commit: null" not in function_body("readViewFromAddress"):
    sys.exit(1)
start = function_body("openStartingView")
if "selectCommit(saved.commit)" not in start or "restoringCommit = true" not in start:
    sys.exit(1)
if start.index("selectCommit(saved.commit)") > start.index("fileToRestore = saved.file"):
    sys.exit(1)
# a restored commit that is gone opens a branch instead of the vanished card
if "restoringCommit ? autoSelectBranch() : null" not in function_body("handleCommitVanished"):
    sys.exit(1)
sys.exit(0)
PY
check "page: a commit picked in the Tree is kept in the address; a reload selects it again, or a branch when it is gone" $?

# ---------------------------------------------------------------- layout, keyboard, network page
# Source checks, like the ones above: the suite has no browser.

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
narrow = text.index("@media (max-width: 1100px)")
if "--wide-sidebar: 340px" not in text[narrow:narrow + 80]:
    sys.exit(1)
for mode in ("tree", "check", "network"):
    if "#app." + mode + "-mode { grid-template-columns: var(--wide-sidebar) 1fr; }" not in text:
        sys.exit(1)
if "420 - svgWidth" in text or "--wide-sidebar" not in function_body("treeColumnWidth"):
    sys.exit(1)
if text.count("@media (max-width: 900px)") < 2 or "#content { grid-row: 3; }" not in text:
    sys.exit(1)
sys.exit(0)
PY
check "page: a narrow window narrows the wide sidebar and stacks the panes" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
if '<nav id="branch-list" tabindex="0"' not in text:
    sys.exit(1)
if 'branchListElement.addEventListener("keydown"' not in text:
    sys.exit(1)
for made in ('makeText("button", "tip-chip mono"', 'makeText("button", "compare-chip"',
             'makeText("button", "stop-compare-pill"', 'makeText("button", "commit-message-action"'):
    if made not in text:
        sys.exit(1)
if ".tree-row.selected .compare-chip" not in text:
    sys.exit(1)
if "tabIndex = 0" not in function_body("refreshCheckFileLinks"):
    sys.exit(1)
if '"keydown"' not in function_body("linkRowToFile"):
    sys.exit(1)
sys.exit(0)
PY
check "page: the branch list, chips, header actions and Check file rows work from the keyboard" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# A row opens its file on another branch only when that branch's own file
# list, read with the page's compare base, has the path.
target = function_body("checkedFileTarget")
if "judgedFileListFor(judgedBranch)" not in target or "list.paths.indexOf(path) === -1" not in target:
    sys.exit(1)
if target.index("list.paths.indexOf(path) === -1") > target.rindex('return "branch";'):
    sys.exit(1)
if "branch.content_token, baseSha" not in function_body("judgedFileListKey"):
    sys.exit(1)
if "targetQuery(branch.name, null, baseSha)" not in function_body("loadJudgedFileList"):
    sys.exit(1)
links = function_body("refreshCheckFileLinks")
for piece in ["loadJudgedFileList(judgedBranch)", "!judgedFileListPending",
              '"This file is not among the changes shown for " + judgedName',
              "judgedFileListProblem(judgedName, judgedBranch)"]:
    if piece not in links:
        sys.exit(1)
problem = function_body("judgedFileListProblem")
if '"Reading the changes on "' not in problem or '"Could not read the changes on "' not in problem:
    sys.exit(1)
sys.exit(0)
PY
check "page: a Check file row is a link only when the judged branch's file list has its path, and its title says why not" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
if 'id="view-tabs" role="tablist"' not in text or text.count('role="tab"') != 4:
    sys.exit(1)
if '"aria-selected"' not in function_body("markTab"):
    sys.exit(1)
if '"Zoom out"' not in text or '"Zoom in"' not in text:
    sys.exit(1)
if '"edits not yet committed"' not in function_body("makeUncommittedDot"):
    sys.exit(1)
row = function_body("makeBranchRow")
if '"new commit", "new commits"' not in row or '" missing"' not in row:
    sys.exit(1)
if '" ahead"' in row or '" behind"' in row:
    sys.exit(1)
sys.exit(0)
PY
check "page: tabs, zoom buttons and the amber dot are named for screen readers; branch rows say new commits and missing" $?

# Copy on select reads only the code cells of the diff body, from a mouse
# selection and a keyboard one alike, and Cmd+C gets the same text.
python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
lines = function_body("selectedDiffLines")
if 'diffBodyElement.querySelectorAll("td.code")' not in lines:
    sys.exit(1)
if "diffBodyElement.contains(range.commonAncestorContainer)" not in lines:
    sys.exit(1)
if "Range.START_TO_START" not in lines or "Range.END_TO_END" not in lines:
    sys.exit(1)
copy = function_body("copySelectedDiffText")
if "navigator.clipboard.writeText(text)" not in copy or '"Copied "' not in copy:
    sys.exit(1)
if 'document.addEventListener("mouseup"' not in text or 'event.key === "Shift"' not in text:
    sys.exit(1)
if 'document.addEventListener("copy"' not in text:
    sys.exit(1)
if 'event.clipboardData.setData("text/plain", lines.join("\\n"))' not in text:
    sys.exit(1)
notice = text.index('id="copy-notice"')
if 'aria-live="polite"' not in text[notice:notice + 120] or "hidden" not in text[notice:notice + 120]:
    sys.exit(1)
if "readText" in text:
    sys.exit(1)  # the page never reads the clipboard
sys.exit(0)
PY
check "page: selecting code in the diff copies the code cells only, from the mouse, Shift and Cmd+C alike, and says so" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
refresh = function_body("afterGraphRefresh")
guard = refresh.find("networkCommitSha() !== currentNetworkSha")
if guard < 0 or refresh.find("renderNetworkPane()") < guard:
    sys.exit(1)
if "var NETWORK_READABLE_ZOOM = 1;" not in text:
    sys.exit(1)
if "NETWORK_READABLE_ZOOM" not in function_body("showNetworkStartView"):
    sys.exit(1)
graph = function_body("renderNetworkGraph")
if "showNetworkStartView()" not in graph or "fitNetworkToView()" in graph:
    sys.exit(1)
if "event.ctrlKey" not in function_body("onNetworkWheel"):
    sys.exit(1)
sys.exit(0)
PY
check "network: a graph refresh redraws the pane only for a new commit; a drawing opens readable and the wheel scrolls it" $?

# A dim-mode rule whose subject is every node or edge restyles the whole
# graph on each hover; only the two layer groups may be named after it.
python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import re
import sys

from pagesource import text, function_body
css = text[:text.index("</style>")]
rules = re.findall(r"#network-svg\.dim-mode ([^{]+)\{", css)
if sorted(rule.strip() for rule in rules) != ["#network-edges", "#network-nodes"]:
    sys.exit(1)
if "#network-overlay { pointer-events: none; }" not in css:
    sys.exit(1)
if "networkOverlayElement.appendChild(copy)" not in text:
    sys.exit(1)
sys.exit(0)
PY
check "network: hover fades the two layer groups and draws copies in an overlay that ignores the pointer" $?

# ---------------------------------------------------------------- audit 2026-10: page
# Source checks for the page fixes of the October 2026 audit, plus the pure
# helpers run in node when it is installed. The suite has no browser.

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
if '<div id="sr-status" class="visually-hidden" role="status" aria-live="polite"></div>' not in text:
    sys.exit(1)
if ".visually-hidden {" not in text or "srStatusElement.textContent = text;" not in function_body("announce"):
    sys.exit(1)
footer = function_body("setFooter")
if 'announce("Lost contact with the local server.")' not in footer or \
        'announce("Back in contact with the local server.")' not in footer:
    sys.exit(1)
if "announceCheckChange(view);" not in function_body("handleSecurityResult"):
    sys.exit(1)
change = function_body("announceCheckChange")
if '"Security check started"' not in change or "verdict_word" not in change:
    sys.exit(1)
push = function_body("pushBranch")
if 'announce("Pushed "' not in push or 'announce("The push did not go through.")' not in push:
    sys.exit(1)
# a rebuilt verdict body gives the focus back, or to the stage itself
verdict_body = function_body("updateVerdictBody")
if verdict_body.index("refreshCheckFileLinks();") > verdict_body.index("again.focus();"):
    sys.exit(1)
if "shell.element.focus();" not in verdict_body or "element.tabIndex = -1;" not in function_body("makeStageShell"):
    sys.exit(1)
if 'row.setAttribute("data-focus-key", "finding:" + index);' not in function_body("makeFindingRow"):
    sys.exit(1)
sys.exit(0)
PY
check "page audit: one hidden live region says when the connection, a check or a push changes, and a rebuilt verdict keeps the focus" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body


def listener_body(head):
    start = text.index(head)
    return text[start:text.index("\n});\n", start)]


for head in ('branchListElement.addEventListener("keydown"',
             'treeListElement.addEventListener("keydown"',
             'fileListElement.addEventListener("keydown"'):
    if "announce(" not in listener_body(head):
        sys.exit(1)
for piece in ('<main id="main">', "</main>", '<h1 id="repo-name"></h1>',
              '<div id="tree-list" tabindex="0" aria-label="History">',
              '<div id="file-list" tabindex="0" aria-label="Changed files">',
              '<section id="file-panel" aria-label="Files">',
              '<section id="diff-pane" aria-label="Diff">',
              '<section id="network-pane" aria-label="Network">'):
    if piece not in text:
        sys.exit(1)
if '<div id="main">' in text or '<div id="repo-name">' in text:
    sys.exit(1)
sys.exit(0)
PY
check "page audit: arrow keys in the three lists announce the selection; a main landmark, a heading and named lists" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
if '<div id="view-tabs" role="tablist" aria-label="Views">' not in text:
    sys.exit(1)
# only the open tab is a Tab stop
if text.count('role="tab" aria-selected="false" tabindex="-1"') != 3:
    sys.exit(1)
if "tabElement.tabIndex = isSelected ? 0 : -1;" not in function_body("markTab"):
    sys.exit(1)
start = text.index('document.getElementById("view-tabs").addEventListener("keydown"')
keys = text[start:text.index("\n});\n", start)]
for piece in ('"ArrowLeft"', '"ArrowRight"', '"Home"', '"End"', "switchView(shown[index].mode);",
              "shown[index].element.focus();", 'appElement.classList.contains("has-security")'):
    if piece not in keys:
        sys.exit(1)
# on the Check tab the banner is not a button
link = function_body("updateSecurityBannerLink")
if 'removeAttribute("role")' not in link or 'removeAttribute("tabindex")' not in link:
    sys.exit(1)
if "updateSecurityBannerLink();" not in function_body("switchView"):
    sys.exit(1)
sys.exit(0)
PY
check "page audit: the view tabs move with the arrow keys and only the open one is a Tab stop; the banner is no button on the Check tab" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# only the newest /api/network answer renders, and a layout drawn for an
# older answer of the same commit is never taken for the current one
load = function_body("loadNetwork")
if "var serial = networkRequestSerial;" not in load or "if (serial === networkRequestSerial) {" not in load:
    sys.exit(1)
if "if (serial !== networkRequestSerial) {" not in load or "if (networkRequestSha === sha)" in load:
    sys.exit(1)
canvas = function_body("renderNetworkCanvas")
if "if (networkDrawnLayout === networkLayout) {" not in canvas or \
        "networkDrawnLayout = networkLayout;" not in canvas:
    sys.exit(1)
if "networkDrawnSha === currentNetworkSha" in text:
    sys.exit(1)
if "networkDrawnLayout === networkLayout" not in function_body("networkIsLive"):
    sys.exit(1)
# a network fetch that died is asked for again by the poll
heal = function_body("healIncompleteLoads")
if "networkRequestSha === null" not in heal or "networkErrorText === null" not in heal:
    sys.exit(1)
if heal.index("renderNetworkPane();") > heal.index("if (!hasSelection()) {"):
    sys.exit(1)
sys.exit(0)
PY
check "network audit: a late answer for a commit picked again cannot leave the drawing without its elements; a dead fetch is retried" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# maps keyed by paths have no prototype, so __proto__ is an ordinary path
if "return Object.create(null);" not in function_body("makePathMap"):
    sys.exit(1)
for name, piece in (("networkAdjacency", "var outgoing = makePathMap();"),
                    ("networkAdjacency", "var incoming = makePathMap();"),
                    ("findStronglyConnected", "var compOf = makePathMap();"),
                    ("findStronglyConnected", "var onStack = makePathMap();"),
                    ("buildNetworkLayout", "var index = makePathMap();"),
                    ("buildNetworkLayout", "outgoingEdges: makePathMap(),"),
                    ("networkDirectoryList", "var seen = makePathMap();"),
                    ("applyNetworkDirectoryColors", "var colorOf = makePathMap();"),
                    ("resetNetworkState", "networkPositionOverrides = makePathMap();"),
                    ("resetNetworkLayout", "networkPositionOverrides = makePathMap();")):
    if piece not in function_body(name):
        sys.exit(1)
# shortcuts with a modifier stay the browser's
keydown = function_body("onNetworkKeydown")
if keydown.index("event.ctrlKey || event.metaKey || event.altKey") > keydown.index("var key = event.key;"):
    sys.exit(1)
# hover waits a moment, and a selection, a press or a redraw cancels it
if "var NETWORK_HOVER_DELAY_MS = 80;" not in text:
    sys.exit(1)
if "NETWORK_HOVER_DELAY_MS" not in function_body("scheduleNetworkHover"):
    sys.exit(1)
for name in ("selectNetworkNode", "highlightNetworkCycles", "onNetworkNodePointerDown",
             "onNetworkPointerDown", "resetNetworkState", "renderNetworkGraph"):
    if "cancelNetworkHover();" not in function_body(name):
        sys.exit(1)
sys.exit(0)
PY
check "network audit: path maps have no prototype, modifier shortcuts pass through, hover waits 80 ms" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# the plus key has the solid swatch a read file is drawn with
legend = function_body("renderNetworkLegend")
if 'makeNetworkLegendKey("",\n      "Solid outline and a plus after the name' not in legend:
    sys.exit(1)
# unresolved imports stop the note from saying the files import nothing
no_links = function_body("networkNoLinksSentence")
if "unresolved_imports" not in no_links or '"none of their imports could be followed to another file "' not in no_links:
    sys.exit(1)
if "no link at all" in text or '" no drawn link in either direction."' not in function_body("renderNetworkSummary"):
    sys.exit(1)
# a tree listing that stopped early makes the file counts lower bounds, and
# files never looked at may be source code
if "truncation.tree_listing_stopped === true" not in function_body("networkListingStopped"):
    sys.exit(1)
not_looked = function_body("networkFilesNotLookedAt")
if "excluded.unlisted" not in not_looked or "excluded.too_deep" not in not_looked:
    sys.exit(1)
if '(networkListingStopped() ? "more than " : "")' not in function_body("networkNotLookedAtWords"):
    sys.exit(1)
empty = function_body("networkEmptyGraphParts")
if "networkFilesNotLookedAt() > 0 || networkListingStopped()" not in empty or \
        '"None of the files BranchLens looked at are in a language it can read "' not in empty or \
        '" not looked at, so "' not in empty:
    sys.exit(1)
if empty.index("networkFilesNotLookedAt() > 0") > empty.index('"None of the " + atCommit'):
    sys.exit(1)
summary = function_body("renderNetworkSummary")
if "networkListingStopped()" not in summary or '"More than " + filesWords' not in summary:
    sys.exit(1)
if '"of those looked at, "' not in summary or '" not looked at."' not in summary:
    sys.exit(1)
# links the server stopped gathering make the link total a lower bound
if 'truncation.links_not_gathered, 0) > 0 ? "at least " : ""' not in function_body("renderNetworkLegendNotes"):
    sys.exit(1)
sys.exit(0)
PY
check "network audit: the plus key is solid, no-links wording counts unresolved imports, file counts say more than N or name the files not looked at, a link total can be at least Y" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
if '<div id="network-canvas" tabindex="0" role="group" aria-label="Dependency network" ' \
        'aria-describedby="network-key-help"></div>' not in text:
    sys.exit(1)
if 'keyHelp.id = "network-key-help";' not in function_body("renderNetworkLegend"):
    sys.exit(1)
# a panel button that rebuilds the panel hands the focus to its first line
if "head.focus({ preventScroll: true });" not in function_body("focusNetworkDetailHead"):
    sys.exit(1)
if "head.tabIndex = -1;" not in function_body("renderNetworkDetail") or \
        "head.tabIndex = -1;" not in function_body("renderNetworkSummary"):
    sys.exit(1)
for name in ("makeNetworkNeighbourRow", "makeNetworkLoopRow", "renderNetworkDetail",
             "makeNetworkSymbolChips", "makeNetworkSkippedSection", "makeNetworkUnresolvedSection"):
    if "focusNetworkDetailHead();" not in function_body(name):
        sys.exit(1)
if 'announce("Selected " + path + ": "' not in function_body("selectNetworkNode"):
    sys.exit(1)
sys.exit(0)
PY
check "network audit: the drawing is a named group with its keys described; panel buttons keep the focus in the panel; a selection is announced" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# picking another file clears the old file's table before the new one loads
select = function_body("selectFile")
if "renderDiffBody();" not in select or select.index("renderDiffBody();") > select.index("loadFile();"):
    sys.exit(1)
# a 404 with a compare base drops the base and asks again, whatever the
# cached graph says; the file loader lets the comparison decide
diff = function_body("loadDiff")
if "requestBase !== null && !graphHasSha(requestBase)" in text:
    sys.exit(1)
if "if (result.status === 404) {\n      if (requestBase !== null) {" not in diff:
    sys.exit(1)
file_body = function_body("loadFile")
start = file_body.index("if (result.status === 404) {")
block = file_body[start:file_body.index("return;\n    }", start)]
if "refreshDiff();" not in block or "baseSha = null" in block or "fileVanished = true;" not in block:
    sys.exit(1)
sys.exit(0)
PY
check "page audit: a new file clears the old table at once; a 404 under a compare base is settled by the comparison, not the cached graph" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# the mode helpers sit between the parser markers, so they can be extracted
start = text.index("/* PARSER-EXTRACT-BEGIN")
end = text.index("/* PARSER-EXTRACT-END */")
for name in ("function parseUnifiedDiff(", "function parsePatchModes(", "function patchModeNote("):
    if not start < text.index(name) < end:
        sys.exit(1)
if "patchModeNote(parsePatchModes(currentFile.patch" not in function_body("renderDiffSticky"):
    sys.exit(1)
body = function_body("renderDiffBody")
if '"The contents did not change. "' not in body or "patchModeNote(parsePatchModes(" not in body:
    sys.exit(1)
# a type change has its own word and keeps the 64px chip column
if 'T: "type changed"' not in text or 'T: "edited typechanged"' not in text or 'T: "type differs"' not in text:
    sys.exit(1)
if ".word-chip.typechanged {\n  white-space: normal;" not in text:
    sys.exit(1)
if "hasOwnKey(STATUS_CLASSES, status)" not in function_body("statusClass"):
    sys.exit(1)
# a name that is not valid UTF-8 is listed and counted but never opened
row = function_body("makeFileRow")
if 'row.classList.add("unshowable");' not in row or "UNSHOWABLE_SENTENCE" not in row:
    sys.exit(1)
if row.index('row.classList.add("unshowable");') > row.index('row.addEventListener("click"'):
    sys.exit(1)
if "unshowable === true" not in function_body("pickLargestFile"):
    sys.exit(1)
for name in ("loadDiff", "openNetworkFile", "checkedFileTarget", "renderNetworkDetail"):
    if "findShowableFileEntry(" not in function_body(name):
        sys.exit(1)
start = text.index('fileListElement.addEventListener("keydown"')
if "unshowable !== true" not in text[start:text.index("\n});\n", start)]:
    sys.exit(1)
sys.exit(0)
PY
check "page audit: mode and type changes get a note and a type-changed chip; unshowable names are listed but never opened" $?

if command -v node > /dev/null 2>&1; then
  PARSER_HELPERS="$FIXTURE/parser-helpers.js"
  python3 - "$SOURCE_DIR/static/app.html" "$PARSER_HELPERS" <<'PY'
import sys

from pagesource import text, function_body
start = text.index("/* PARSER-EXTRACT-BEGIN")
end = text.index("/* PARSER-EXTRACT-END */")
open(sys.argv[2], "w", encoding="utf-8").write(text[start:end] + "\n")
PY
  cat >> "$PARSER_HELPERS" <<'JS'
var assert = require("assert");
function modesOf(patch) {
  var modes = parsePatchModes(patch);
  return modes.oldMode + " " + modes.newMode;
}
function noteOf(patch) {
  return patchModeNote(parsePatchModes(patch));
}
var chmod = "diff --git a/run.sh b/run.sh\nold mode 100644\nnew mode 100755\n";
assert.strictEqual(modesOf(chmod), "100644 100755");
assert.strictEqual(noteOf(chmod), "mode 100644 → 100755 (now executable)");
assert.strictEqual(parseUnifiedDiff(chmod).length, 0);
assert.strictEqual(noteOf("diff --git a/s b/s\nold mode 100755\nnew mode 100644\n"),
  "mode 100755 → 100644 (no longer executable)");
// git writes a type change as the old file deleted, then the new one created
var typeChange = "diff --git a/f b/f\ndeleted file mode 100644\nindex 379d332..0000000\n" +
  "--- a/f\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-one\n-two\n" +
  "diff --git a/f b/f\nnew file mode 120000\nindex 0000000..42061c0\n" +
  "--- /dev/null\n+++ b/f\n@@ -0,0 +1 @@\n+README.md\n\\ No newline at end of file\n";
assert.strictEqual(modesOf(typeChange), "100644 120000");
assert.strictEqual(noteOf(typeChange),
  "mode 100644 → 120000: now a symbolic link; the added line is its target");
assert.strictEqual(parseUnifiedDiff(typeChange).length, 2);
assert.strictEqual(noteOf("diff --git a/l b/l\nnew file mode 120000\nindex 0000000..1234567\n" +
  "--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+target\n"),
  "a new symbolic link; the added line is its target");
assert.strictEqual(noteOf("diff --git a/b b/b\nnew file mode 100755\nindex 0000000..1234567\n"),
  "a new executable file (mode 100755)");
// a submodule update names its mode only on the index line
var submodule = "diff --git a/sub b/sub\nindex 1111111..2222222 160000\n--- a/sub\n+++ b/sub\n" +
  "@@ -1 +1 @@\n-Subproject commit 1111111\n+Subproject commit 2222222\n";
assert.strictEqual(modesOf(submodule), "160000 160000");
assert.ok(noteOf(submodule).indexOf("submodule") !== -1);
// plain edits and new plain files say nothing, and hunk lines are never headers
var plain = "diff --git a/x b/x\nindex 1111111..2222222 100644\n--- a/x\n+++ b/x\n" +
  "@@ -1 +1 @@\n-old mode 100755\n+new mode 100644\n";
assert.strictEqual(modesOf(plain), "100644 100644");
assert.strictEqual(noteOf(plain), null);
assert.strictEqual(noteOf("diff --git a/n b/n\nnew file mode 100644\nindex 0000000..1234567\n"), null);
assert.strictEqual(noteOf(""), null);
// a patch cut short by the size cap may stop in the middle of any line
var cut = "diff --git a/x b/x\nindex 1111111..2222222 100644\n--- a/x\n+++ b/x\n" +
  "@@ -1,3 +1,3 @@\n line one\n-old\n+new li";
var cutHunks = parseUnifiedDiff(cut);
assert.strictEqual(cutHunks.length, 1);
assert.deepStrictEqual(cutHunks[0].lines[2], { type: "add", text: "new li" });
var cutHeader = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n@@ -10,4 +1";
assert.strictEqual(parseUnifiedDiff(cutHeader).length, 1);
assert.strictEqual(noteOf("diff --git a/x b/x\nnew file mo"), null);
JS
  node "$PARSER_HELPERS"
  check "page audit: parsePatchModes and patchModeNote read mode-only, type, symlink and submodule patches (run in node)" $?
else
  echo "SKIP: node is not installed, so the extracted parser helpers were not run"
fi

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
css = text[:text.index("</style>")]


def css_rule(selector):
    start = css.index("\n" + selector + " {")
    return css[start:css.index("}", start)]


# an empty commit is not described as changes still to come
body = function_body("renderDiffBody")
if '"This commit changes no files, for example an empty "' not in body or \
        "selectedCommitSha !== null && baseSha === null" not in body:
    sys.exit(1)
# no "worktree" in visible copy
if "(an embedded repository or a worktree)" in text or \
        "another checked-out copy of this one" not in text:
    sys.exit(1)
# ellipsized names carry their full text as a title
if "nameSpan.title = branch.name;" not in function_body("makeBranchRow") or \
        'line2.title = branch.last_commit_subject || "";' not in function_body("makeBranchRow"):
    sys.exit(1)
if "repoNameElement.title = currentState.repo_name;" not in function_body("renderSidebar"):
    sys.exit(1)
run_card = function_body("updateRunCardWith")
if 'runCard.branch.title = runningName || "";' not in run_card or \
        'runCard.branch.title = target !== null ? target.name : "";' not in run_card:
    sys.exit(1)
# a long tip name shrinks to an ellipsis; the subject takes only the room left
for selector in (".tip-chip", ".online-chip"):
    rule = css_rule(selector)
    for piece in ("flex: 0 1 auto;", "max-width: 16em;", "overflow: hidden;", "text-overflow: ellipsis;"):
        if piece not in rule:
            sys.exit(1)
if "flex: 1 1 0;" not in css_rule(".tree-subject"):
    sys.exit(1)
tip = function_body("makeTipChip")
if "chip.title = branchName;" not in tip or 'branchName + " (checked out here)"' not in tip:
    sys.exit(1)
sys.exit(0)
PY
check "page audit: an empty commit says so, no worktree in the copy, long names keep a tooltip and tip chips shrink instead of hiding the row" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# the first state may take over a minute; a timeout reads as slow, not lost
if "var TIMEOUT_FIRST_STATE_MS = 75000;" not in text:
    sys.exit(1)
if 'fetchJson("/api/state", TIMEOUT_FIRST_STATE_MS)' not in function_body("initialize"):
    sys.exit(1)
if 'error.name === "AbortError" ? "slow" : "lost"' not in function_body("footerStateFor"):
    sys.exit(1)
if '"The local server is slow to answer; waiting…"' not in function_body("setFooter"):
    sys.exit(1)
for name in ("loadGraph", "loadDiff", "loadFile", "loadNetwork", "pollOnce", "initialize"):
    body = function_body(name)
    if "setFooter(footerStateFor(error));" not in body or 'setFooter("lost")' in body:
        sys.exit(1)
sys.exit(0)
PY
check "page audit: the first state waits up to 75 s, and a request that timed out says the server is slow, not lost" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys
from pagesource import text, function_body
start = text.index("function linkRowToFile(")
body = text[start:text.index("\n}\n", start)]
sys.exit(0 if 'path === "?"' in body.split("return;")[0] else 1)
PY
check "page audit: a finding whose file is the server's ? gets no link to a file" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# nothing known about the judged code: no badges; only its commit known: a
# clean branch at that commit, or that commit in the Tree
judged = function_body("selectionIsJudged")
if "if (judged === null) {\n    return false;" not in judged:
    sys.exit(1)
if "if (judged.branch === null) {\n    return judged.commit !== null && branch.commit === judged.commit;" not in judged:
    sys.exit(1)
if "selectedCommitSha === judged.commit" not in judged:
    sys.exit(1)
target = function_body("checkedFileTarget")
if 'selectionIsJudged(view) && findShowableFileEntry(path) !== null ? "here" : null' not in target:
    sys.exit(1)
links = function_body("refreshCheckFileLinks")
if 'judgedName === "HEAD"' not in links or '"This check judged a folder checked out on no branch, so its "' not in links:
    sys.exit(1)
if links.index('judgedName === "HEAD"') > links.index('"The branch " + judgedName + " no longer exists"'):
    sys.exit(1)
# the reported line is outlined only on the code the check judged
jump = function_body("jumpToPendingLine")
if "bestIsExact && selectionIsJudged(buildRunView())" not in jump or "data-jump-note" not in jump:
    sys.exit(1)
# a failed read of the judged file list is tried again
if "JUDGED_LIST_RETRY_MS" not in function_body("judgedFileListFor"):
    sys.exit(1)
if function_body("loadJudgedFileList").count("failedAt: Date.now()") != 2:
    sys.exit(1)
# finding paths are matched to the feed's keys
start = text.index("/* CHECK-EXTRACT-BEGIN")
if not start < text.index("function findingFileKey(") < text.index("/* CHECK-EXTRACT-END */"):
    sys.exit(1)
by_file = function_body("verdictFindingsByFile")
if "findingFileKey(findings[i].file, view.feed.files)" not in by_file or "var byFile = makePathMap();" not in by_file:
    sys.exit(1)
badge = function_body("securityBadgeInfo")
if '"no verdict finding was matched to this file"' not in badge or "allFindingsMatched ?" not in badge:
    sys.exit(1)
if "unmatchedFindingCount(view) === 0" not in function_body("updateSecurityBadges"):
    sys.exit(1)
if "path = findingFileKey(path, " not in function_body("linkRowToFile"):
    sys.exit(1)
sys.exit(0)
PY
check "check audit: badges need a known judged commit, a detached run says so, the line is outlined only on judged code, finding paths match feed keys" $?

if command -v node > /dev/null 2>&1; then
  CHECK_HELPERS="$FIXTURE/check-helpers.js"
  python3 - "$SOURCE_DIR/static/app.html" "$CHECK_HELPERS" <<'PY'
import sys

from pagesource import text, function_body
blocks = []
start = text.find("/* CHECK-EXTRACT-BEGIN")
while start != -1:
    end = text.index("/* CHECK-EXTRACT-END */", start)
    blocks.append(text[start:end])
    start = text.find("/* CHECK-EXTRACT-BEGIN", end)
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(blocks) + "\n")
PY
  cat >> "$CHECK_HELPERS" <<'JS'
var assert = require("assert");
var files = { "a.py": {}, "src/a.py": {}, "src/lib/util.py": {}, "run.sh": {} };
assert.strictEqual(findingFileKey("run.sh", files), "run.sh");
assert.strictEqual(findingFileKey("./run.sh", files), "run.sh");
assert.strictEqual(findingFileKey("././src/lib/util.py", files), "src/lib/util.py");
// an absolute path takes the longest key it ends with, on a "/" boundary
assert.strictEqual(findingFileKey("/home/me/repo/src/a.py", files), "src/a.py");
assert.strictEqual(findingFileKey("/home/me/repo/a.py", files), "a.py");
assert.strictEqual(findingFileKey("/home/me/repo/xa.py", files), "/home/me/repo/xa.py");
assert.strictEqual(findingFileKey("./missing.py", files), "missing.py");
assert.strictEqual(findingFileKey("", files), "");
assert.strictEqual(findingFileKey("./run.sh", null), "run.sh");
// a key named like an Object property is still an ordinary key
var odd = Object.create(null);
odd["__proto__"] = {};
assert.strictEqual(findingFileKey("./__proto__", odd), "__proto__");
assert.strictEqual(findingFileKey("constructor", {}), "constructor");
// a word for the shell: bare when safe, else single-quoted
assert.strictEqual(shellWord("feature/x"), "feature/x");
assert.strictEqual(shellWord("../feature-x"), "../feature-x");
assert.strictEqual(shellWord("x$(touch${IFS}m);id"), "'x$(touch${IFS}m);id'");
assert.strictEqual(shellWord("a;b|c&d"), "'a;b|c&d'");
assert.strictEqual(shellWord("it's"), "'it'\\''s'");
assert.strictEqual(shellWord("=ls"), "'=ls'");
assert.strictEqual(shellWord("a`id`"), "'a`id`'");
JS
  node "$CHECK_HELPERS"
  check "check audit: findingFileKey matches ./ and absolute spellings to the feed's keys; shellWord quotes unsafe words (run in node)" $?
else
  echo "SKIP: node is not installed, so the extracted Check-tab helpers were not run"
fi

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# the suggested command quotes the branch name for the shell
state = function_body("runButtonState")
if 'shellWord("../" + target.name.replace(/\\//g, "-"))' not in state or "shellWord(target.name)" not in state:
    sys.exit(1)
if '"git worktree add ../" + target.name' in text:
    sys.exit(1)
start = text.index("/* CHECK-EXTRACT-BEGIN", text.index("function findingFileKey("))
if not start < text.index("function shellWord(") < text.index("/* CHECK-EXTRACT-END */", start):
    sys.exit(1)
# Run asks first; Push already did
run = function_body("startRun")
if "window.confirm(question)" not in run or '"Run the security check on " + target.name + "?"' not in run:
    sys.exit(1)
if run.index("window.confirm(question)") > run.index('pendingAction = "run";'):
    sys.exit(1)
if "window.confirm(question)" not in function_body("pushBranch"):
    sys.exit(1)
# a check started elsewhere that went silent stops blocking Run after 10 min
if "var STALLED_FEED_MINUTES = 10;" not in text:
    sys.exit(1)
if "stalledMinutes < STALLED_FEED_MINUTES" not in state or "stalledMinutes: stalledMinutes" not in state:
    sys.exit(1)
if '"A check started outside this page has reported nothing for "' not in run:
    sys.exit(1)
banner = function_body("renderSecurityBanner")
if '": no progress for " + silent + " min"' not in banner:
    sys.exit(1)
if 'json = json + " silent " + silent;' not in function_body("handleSecurityResult"):
    sys.exit(1)
sys.exit(0)
PY
check "check audit: the suggested command quotes the branch name, Run asks first, and a silent outside check stops blocking Run after 10 minutes" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# feed strings are looked up as own keys only
chip = function_body("makeResultChip")
if "hasOwnKey(RESULT_CLASSES, result)" not in chip or "hasOwnKey(RESULT_WORDS, result)" not in chip:
    sys.exit(1)
if "hasOwnKey(VERIFICATION_WORDS, check.result)" not in function_body("makeFinishedState"):
    sys.exit(1)
if "hasOwnKey(VERIFICATION_WORDS, finding.outcome)" not in function_body("makeFindingRow"):
    sys.exit(1)
for lookup in ("RESULT_CLASSES[result] ||", "RESULT_WORDS[result] ||", "VERIFICATION_WORDS[check.result];",
               "VERIFICATION_WORDS[finding.outcome] ||"):
    if lookup in text:
        sys.exit(1)
# a review with no phase event in a run that stopped is stopped, not done
review = function_body("buildReviewStage")
if 'reviewPhase === null && (view.inProgress || view.stopped)' not in review:
    sys.exit(1)
# the tab title never names the previous run's verdict for a run that failed to start
title = function_body("updateDocumentTitle")
if 'checkEndedUnseen && view.failedEarly' not in title or '"Check failed to start"' not in title:
    sys.exit(1)
if title.index("checkEndedUnseen && view.failedEarly") > title.index("checkEndedUnseen && view.feed !== null"):
    sys.exit(1)
sys.exit(0)
PY
check "check audit: feed words are own-key lookups, a stopped run's unreported review reads stopped, a failed start never borrows the last verdict" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
css = text[:text.index("</style>")]


def css_rule(selector):
    start = css.index("\n" + selector + " {")
    return css[start:css.index("}", start)]


def media_block(head):
    start = css.index(head)
    depth = 0
    for index in range(css.index("{", start), len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start:index]
    return ""


# reduced motion stops the pseudo-element animations too
if "*, *::before, *::after {\n    animation: none !important;" not in \
        media_block("@media (prefers-reduced-motion: reduce)"):
    sys.exit(1)
# high contrast draws selection with system colours
forced = media_block("@media (forced-colors: active)")
for piece in (".view-tab, .branch-row, .file-row { border-color: Canvas; }",
              "border-left-color: Highlight;", ".tree-row.selected { outline: 2px solid Highlight;",
              "background: Mark;", "#live-dot.off { background: GrayText; }"):
    if piece not in forced:
        sys.exit(1)
# printing gives the whole diff
printed = media_block("@media print")
for piece in ("html, body { height: auto; overflow: visible; }",
              "#sidebar, #security-banner, #file-panel { display: none !important; }",
              "#app:not(.network-mode) #network-pane { display: none; }",
              ".diff-chunk { content-visibility: visible; }", "#diff-sticky { position: static; }"):
    if piece not in printed:
        sys.exit(1)
# a long message scrolls in its box; its toggle keeps the page still
message = css_rule(".commit-message-text")
if "max-height: 40vh;" not in message or "overflow-y: auto;" not in message:
    sys.exit(1)
if '.focus({ preventScroll: true });' not in function_body("renderCommitMessage"):
    sys.exit(1)
# a long branch name wraps; nothing widens the main column or moves the page
if "overflow-wrap: anywhere;" not in css_rule(".name-chip"):
    sys.exit(1)
if "grid-template-columns: minmax(0, 1fr);" not in css_rule("#main"):
    sys.exit(1)
if "html, body { height: 100%; overflow: hidden; overflow: clip; }" not in css:
    sys.exit(1)
# a short half-screen window scrolls and keeps room for the diff and the drawing
narrow = media_block("/* a half-screen window: the file list sits above the diff")
if "#main { overflow-y: auto; }" not in narrow or "min-height: 320px;" not in narrow:
    sys.exit(1)
network = media_block("/* a half-screen window: the detail column moves under the canvas")
if "grid-template-rows: auto minmax(200px, 1fr) auto;" not in network or network.count("max-height: 20vh;") != 2:
    sys.exit(1)
if "#file-panel { max-height: 22vh; }" not in media_block("@media (max-width: 900px) and (max-height: 560px)"):
    sys.exit(1)
sys.exit(0)
PY
check "page audit: reduced motion, high contrast and print styles; long messages and names never push the page; a short window scrolls" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
# a confirmed start over a silent outside check says so to the server
run = function_body("startRun")
if "body.override_stalled = true;" not in run or 'postJson("/api/run", body)' not in run:
    sys.exit(1)
if run.index("body.override_stalled = true;") < run.index("window.confirm(question)"):
    sys.exit(1)
# a restarted server needs its new address; a reload is refused
if "reload this page" in text or '"BranchLens was restarted: open the new address it printed "' not in text:
    sys.exit(1)
# rows that share a stand-in path keep one row each
files = function_body("renderFileList")
if "row.listKey = listKey;" not in files or "oldRowsByKey[oldRows[r].listKey]" not in files or \
        "previousFileRowJson[listKey]" not in files:
    sys.exit(1)
# the edge of a shallow clone is not called an empty commit
body = function_body("renderDiffBody")
if "commitIsShallowBoundary(selectedCommitSha)" not in body or '"No files are listed: this clone stops at this "' not in body:
    sys.exit(1)
if "shallow_boundary === true" not in function_body("commitIsShallowBoundary"):
    sys.exit(1)
if "renderDiffBody();" not in function_body("afterGraphRefresh"):
    sys.exit(1)
if '"This commit is no longer among the commits shown; "' not in body or "no longer in the graph" in text:
    sys.exit(1)
# a folder on a branch with no commit yet is listed with the folders on no branch
detached = function_body("makeDetachedRow")
if '"not compared"' not in detached or '"No branch with commits here; its edits are not shown."' not in detached:
    sys.exit(1)
if "On no branch — its edits" in text:
    sys.exit(1)
sys.exit(0)
PY
check "page audit: a confirmed start over a silent check says so to the server; restart, shallow edge, unborn branch and duplicate stand-in names are worded right" $?

python3 - "$SOURCE_DIR/static/app.html" <<'PY'
import sys

from pagesource import text, function_body
css = text[:text.index("</style>")]


def css_rule(selector):
    start = css.index("\n" + selector + " {")
    return css[start:css.index("}", start)]


light = css[css.index(":root {"):css.index("}", css.index(":root {"))]
# contrast: AA text on the light tokens, readable gutters on coloured rows
for token in ("--lane5: #57606a;", "--amber-dot: #9a6700;", "--amber-banner-fg: #7d4e00;",
              "--add-fg: #116329;"):
    if token not in light:
        sys.exit(1)
if "tr.row-add td.gutter, tr.row-del td.gutter { color: var(--text); }" not in css:
    sys.exit(1)
if "opacity: 0.75;" not in css_rule(".net-edge"):
    sys.exit(1)
# one monospace stack, kept in a token
if "--mono-font: ui-monospace, SFMono-Regular" not in light or css.count("SFMono-Regular") != 1:
    sys.exit(1)
for selector in (".name-chip", ".commit-message-text", ".console-log"):
    if "font-family: var(--mono-font);" not in css_rule(selector):
        sys.exit(1)
if ".mono { font-family: var(--mono-font); }" not in css:
    sys.exit(1)
if "font-family" in css_rule("td.gutter") or "font-family" in css_rule("td.code"):
    sys.exit(1)
if "font-size: 10px;" not in css_rule(".net-node-dir") or "font-size: 9px" in css:
    sys.exit(1)
sys.exit(0)
PY
check "page audit: light tokens and diff gutters meet contrast, network edges are clearer, one monospace token, nothing under 10px" $?

if command -v node > /dev/null 2>&1; then
  LANE_HELPERS="$FIXTURE/lane-helpers.js"
  python3 - "$SOURCE_DIR/static/app.html" "$LANE_HELPERS" <<'PY'
import sys

from pagesource import text, function_body
start = text.index("/* LANES-EXTRACT-BEGIN")
end = text.index("/* LANES-EXTRACT-END */")
open(sys.argv[2], "w", encoding="utf-8").write(text[start:end] + "\n")
PY
  cat >> "$LANE_HELPERS" <<'JS'
var assert = require("assert");
// Newest first in date order: children come before parents, but the
// branches interleave instead of each running in one block.
var commits = [
  { sha: "m3", parents: ["m2"], tips: ["main"] },
  { sha: "g2", parents: ["g1"], tips: ["side"] },
  { sha: "m2", parents: ["m1", "f2"], tips: [] },
  { sha: "f2", parents: ["f1"], tips: [] },
  { sha: "g1", parents: ["m0"], tips: [] },
  { sha: "m1", parents: ["m0"], tips: [] },
  { sha: "f1", parents: ["m0"], tips: [] },
  { sha: "m0", parents: [], tips: [] }
];
var trunk = buildTrunkShas(commits, "main", null);
var layout = assignLanes(commits, trunk);
var rowOf = {};
layout.rows.forEach(function (row) { rowOf[row.sha] = row; });
["m3", "m2", "m1", "m0"].forEach(function (sha) {
  assert.strictEqual(rowOf[sha].lane, 0, sha + " keeps the trunk lane");
});
// every edge drawn from a commit ends in its parent's dot: straight down its
// own lane, or bending into the parent from the lane that expected it
function landsOn(lane, parentSha) {
  var parentRow = rowOf[parentSha];
  return parentRow.lane === lane || parentRow.closes.indexOf(lane) !== -1;
}
commits.forEach(function (commit) {
  var row = rowOf[commit.sha];
  if (commit.parents.length > 0) {
    assert.ok(row.hasOutgoing, commit.sha + " draws its first-parent edge");
    assert.ok(landsOn(row.lane, commit.parents[0]), commit.sha + " reaches its first parent");
  }
  row.mergeEdges.forEach(function (lane, index) {
    assert.ok(landsOn(lane, commit.parents[index + 1]), commit.sha + " reaches its merged parent");
  });
});
// no two different commits wait on the same lane at once
var waiting = [];
commits.forEach(function (commit) {
  var row = rowOf[commit.sha];
  for (var i = 0; i < waiting.length; i++) {
    if (waiting[i] === commit.sha) {
      waiting[i] = null;
    }
  }
  if (row.hasOutgoing) {
    assert.ok(waiting[row.lane] === null || waiting[row.lane] === undefined ||
      waiting[row.lane] === commit.parents[0], "lane " + row.lane + " is free for " + commit.sha);
    waiting[row.lane] = commit.parents[0];
  }
});
JS
  node "$LANE_HELPERS"
  check "page audit: lane assignment still ends every edge in its parent when a date-ordered history interleaves branches (run in node)" $?
else
  echo "SKIP: node is not installed, so the extracted lane helpers were not run"
fi

# ---------------------------------------------------------------- documentation

# Every relative link in the documentation names a file that exists.
python3 - "$PROJECT_DIR" <<'PY'
import os
import re
import sys

project_dir = sys.argv[1]
documents = ["README.md"]
broken = []
for name in documents:
    text = open(os.path.join(project_dir, name), encoding="utf-8").read()
    for match in re.finditer(r"\]\(([^)#\s]+)(#[^)]*)?\)", text):
        target = match.group(1)
        if target.startswith("http://") or target.startswith("https://"):
            continue
        linked_path = os.path.join(project_dir, os.path.dirname(name), target)
        if not os.path.exists(linked_path):
            broken.append(name + " -> " + target)
if broken:
    print("  broken:", broken)
sys.exit(1 if broken else 0)
PY
check "every relative link in README.md names a file that exists" $?
VERSION_LINE=$(python3 -m branchlens --version 2>&1)
LAUNCHER_VERSION_LINE=$("$PROJECT_DIR/branchlens" --version 2>&1)
PYPROJECT_VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$PROJECT_DIR/pyproject.toml")
[ -n "$PYPROJECT_VERSION" ] && [ "$VERSION_LINE" = "branchlens $PYPROJECT_VERSION" ] && \
  [ "$LAUNCHER_VERSION_LINE" = "$VERSION_LINE" ] && \
  grep -q '^branchlens = "branchlens.server:main"$' "$PROJECT_DIR/pyproject.toml"
check "pyproject.toml holds the version python -m branchlens and the launcher print, and the branchlens.server:main console script" $?
# A json.py in the folder `python -m branchlens` starts from must not be
# imported in place of the standard library's json.
SHADOW_DIR="$FIXTURE/shadow-cwd"
mkdir -p "$SHADOW_DIR"
printf 'open("shadow-imported", "w").close()\n' > "$SHADOW_DIR/json.py"
(cd "$SHADOW_DIR" && python3 -m branchlens --version > /dev/null 2>&1) && \
  [ ! -e "$SHADOW_DIR/shadow-imported" ]
check "python -m branchlens imports no module from the folder it starts in" $?
grep -qF "python -m py_compile branchlens src/branchlens/*.py" "$PROJECT_DIR/.github/workflows/ci.yml" && \
  grep -q "run: bash test.sh" "$PROJECT_DIR/.github/workflows/ci.yml"
check "the CI workflow compiles the launcher and the package and runs test.sh" $?
grep -q "Report a vulnerability" "$PROJECT_DIR/README.md"
check "the README names the private reporting route" $?
grep -q "bash test.sh" "$PROJECT_DIR/README.md"
check "the README says how to run the tests" $?
DEMO_GIF="$PROJECT_DIR/docs/demo.gif"
DEMO_GIF_BYTES=0
DEMO_GIF_SIGNATURE=""
if [ -f "$DEMO_GIF" ]; then
  DEMO_GIF_BYTES=$(wc -c < "$DEMO_GIF" | tr -d ' ')
  DEMO_GIF_SIGNATURE=$(head -c 6 "$DEMO_GIF" | od -An -tx1 | tr -d ' \n')
fi
# GIF89a or GIF87a.
case "$DEMO_GIF_SIGNATURE" in
  474946383961|474946383761) DEMO_GIF_IS_GIF="yes" ;;
  *) DEMO_GIF_IS_GIF="no" ;;
esac
[ "$DEMO_GIF_IS_GIF" = "yes" ] && [ "$DEMO_GIF_BYTES" -lt 2000000 ] && \
  grep -q "](docs/demo.gif)" "$PROJECT_DIR/README.md"
check "docs/demo.gif is a GIF under 2 MB, and the README shows it" $? "signature $DEMO_GIF_SIGNATURE, $DEMO_GIF_BYTES bytes"
BUNDLED_TOOLKIT=$(cd "$PROJECT_DIR/src" && python3 -c "from branchlens import server; print(server.BUNDLED_TOOLKIT)")
[ "$BUNDLED_TOOLKIT" = "$PROJECT_DIR/toolkit" ] && [ -x "$BUNDLED_TOOLKIT/preflight.sh" ] && \
  python3 "$PROJECT_DIR/branchlens" --help | grep -q -- "--check" && \
  grep -q "run: make -C toolkit install-skills" "$PROJECT_DIR/.github/workflows/ci.yml"
check "--check points at the bundled toolkit/preflight.sh, and CI tests the toolkit" $? "$BUNDLED_TOOLKIT"

# ---------------------------------------------------------------- summary

echo
PASSED=$((TOTAL_CHECKS - FAILED_CHECKS))
echo "SUMMARY: $PASSED/$TOTAL_CHECKS checks passed"
if [ "$FAILED_CHECKS" -gt 0 ]; then
  exit 1
fi
exit 0
