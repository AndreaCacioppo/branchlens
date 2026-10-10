#!/usr/bin/env python3
"""
pipeline.py — the whole pipeline in one command: the mechanical gate, then,
when it passes, the LLM review of the diff in a headless `claude -p` session.

    ./preflight.sh run <repository> [base-ref]

BranchLens starts it from its "Run security check" button. Progress goes to
the security-feed.jsonl the gate and the review write to; this script adds
the "review" phase events and the final verdict line.

The verdict comes from the run directory's verdict.json, not from what
`claude -p` prints. BranchLens judges a push on the same file. It counts
only when verdict.json says review_merged AND review_confirmed (the workflow
read its merge back from disk and it matched), and when the `claude -p`
session itself ended normally with a reply starting with DONE. Anything
else is "PIPELINE: INCONCLUSIVE — review not confirmed (<reason>)", unless
the run already carries a veto, which stands as DO NOT PUBLISH. The
override is also written into the run directory (verdict.py
distrust-review), so the files say what the terminal says.

The model of each review stage comes from three environment variables,
PREFLIGHT_MODEL_MECHANICAL, PREFLIGHT_MODEL_ANALYSIS and
PREFLIGHT_MODEL_VERIFY_HIGH, each one of sonnet, opus or fable. They are
checked before the gate runs, passed to the workflow as its "models"
argument, and recorded in run-meta.txt and in the feed.

Exit codes: 0 READY TO PUBLISH, 1 DO NOT PUBLISH, 2 INCONCLUSIVE (or the
gate's own FAILED/INCONCLUSIVE when phase 2 is not reached), 4 usage
(including a model variable with a value not in the list).
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys

import feed
# verdict.py: the allowed models, their defaults, and write_manifest
import verdict

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(TOOLKIT_DIR, "checks", "gate.py")
WORKFLOW = os.path.join("checks", "review", "review-diff.js")
REVIEW_TIMEOUT = int(os.environ.get("PREFLIGHT_REVIEW_TIMEOUT", "3600"))

# the tools the headless session and its agents may use without asking
REVIEW_TOOLS = "Workflow,Bash,Read,Grep,Glob"

# (key in the workflow's "models" argument, environment variable)
MODEL_VARIABLES = (
    ("mechanical", "PREFLIGHT_MODEL_MECHANICAL"),
    ("analysis", "PREFLIGHT_MODEL_ANALYSIS"),
    ("verify_high", "PREFLIGHT_MODEL_VERIFY_HIGH"),
)

running_child = None   # the subprocess to stop when the run is cancelled


def models_from_environment(environment):
    """The model of each review stage, from the PREFLIGHT_MODEL_* variables.
    Returns (models, error): models maps mechanical / analysis / verify_high
    to a model name, and error is a one-line message naming the first
    variable whose value is not allowed (models is then None). A variable
    that is unset or empty takes the default."""
    models = {}
    for key, variable in MODEL_VARIABLES:
        value = environment.get(variable, "").strip()
        if value == "":
            value = verdict.DEFAULT_MODELS[key]
        if value not in verdict.ALLOWED_MODELS:
            return None, ("%s=%r is not allowed: use %s"
                          % (variable, value,
                             ", ".join(verdict.ALLOWED_MODELS)))
        models[key] = value
    return models, None


def models_text(models):
    """'mechanical=sonnet analysis=opus verify_high=fable'"""
    return " ".join("%s=%s" % (key, models[key])
                    for key, _variable in MODEL_VARIABLES)


def record_models(run_dir, models):
    """Adds the models line to run-meta.txt, in the file's key=value form,
    and rewrites the manifest so it still matches the files on disk."""
    with open(os.path.join(run_dir, "run-meta.txt"), "a",
              encoding="utf-8") as f:
        f.write("models=%s\n" % models_text(models))
    verdict.write_manifest(run_dir)


def stop(_signal_number, _frame):
    raise KeyboardInterrupt()


def run_gate(repo, base):
    """Runs the gate, echoing its output. Returns (exit code, run
    directory, feed path)."""
    global running_child
    command = [sys.executable, GATE, "check", repo]
    if base:
        command.append(base)
    running_child = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        errors="replace", start_new_session=True)
    run_dir = feed_path = None
    for line in running_child.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        if line.startswith("report in: "):
            run_dir = line[len("report in: "):].strip()
        elif line.startswith("security feed: "):
            feed_path = line[len("security feed: "):].strip()
    code = running_child.wait()
    running_child = None
    return code, run_dir, feed_path


def workflow_arguments(repo, run_dir, feed_path, models):
    """The arguments the review workflow receives."""
    return {"repo": repo, "toolkit": TOOLKIT_DIR, "reportDir": run_dir,
            "feed": feed_path, "models": dict(models)}


def run_review(repo, run_dir, feed_path, models):
    """Runs the review workflow through a headless Claude Code session.
    Returns (claude exit code, timed out). The exit code is None when claude
    is not installed, and negative when the session was killed by a signal.
    The session's output is kept in the run directory as evidence."""
    global running_child
    if shutil.which("claude") is None:
        return None, False
    arguments = workflow_arguments(repo, run_dir, feed_path, models)
    # the reply is one word: the verdict is read from verdict.json, and
    # echoing the workflow's result would cost minutes of output
    prompt = ("Use the Workflow tool with scriptPath %s and these args: %s. "
              "Do nothing else. When it finishes, reply with only the word "
              "DONE." % (WORKFLOW, json.dumps(arguments)))
    log_path = os.path.join(run_dir, "review-session.json")
    # In `claude -p` the workflow runs as a background task, and the CLI stops
    # waiting for background tasks after CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS
    # (600 s by default), killing reviews that run longer. Raise it to our own
    # timeout so REVIEW_TIMEOUT is the limit that applies.
    environment = dict(os.environ)
    environment["CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS"] = str(
        REVIEW_TIMEOUT * 1000)
    timed_out = False
    with open(log_path, "w", encoding="utf-8") as log:
        # cwd: the toolkit, so the session may read the workflow script
        running_child = subprocess.Popen(
            ["claude", "-p", prompt, "--output-format", "json",
             "--allowedTools", REVIEW_TOOLS],
            cwd=TOOLKIT_DIR, env=environment, stdout=log,
            stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = running_child.wait(timeout=REVIEW_TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(running_child.pid, signal.SIGTERM)
            code = running_child.wait()
            timed_out = True
    running_child = None
    return code, timed_out


def read_verdict(run_dir):
    try:
        with open(os.path.join(run_dir, "verdict.json"),
                  encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def read_session(run_dir):
    """Reads review-session.json, which holds what `claude -p` printed.
    Returns (result, other_lines): result is the LAST line that parses as a
    JSON object (the session's final result) or None; other_lines are the
    lines that are not JSON. The CLI can print plain warnings before the
    result, such as 'Background tasks still running after 600s;
    terminating.', so the file as a whole is not JSON."""
    try:
        with open(os.path.join(run_dir, "review-session.json"),
                  encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None, []
    result = None
    other_lines = []
    for line in lines:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except ValueError:
            other_lines.append(line.strip())
            continue
        if isinstance(parsed, dict):
            result = parsed
    return result, other_lines


def short_text(text):
    return " ".join(str(text).split())[:200]


def session_problem(claude_code, timed_out, session, other_lines):
    """Why the `claude -p` session did not end normally, or None. Normal
    means: exit 0, not killed, a final result that is not an error, no
    warning that the CLI terminated the background workflow, and the reply
    DONE the prompt asks for."""
    if timed_out:
        return ("the review session ran past PREFLIGHT_REVIEW_TIMEOUT "
                "(%d s) and was stopped" % REVIEW_TIMEOUT)
    if claude_code is None:
        return "the review session did not run"
    if claude_code < 0:
        return "the review session was killed by signal %d" % -claude_code
    for line in other_lines:
        if "terminating" in line.lower():
            return "the claude CLI stopped the workflow: " + short_text(line)
    if session is None:
        if claude_code != 0:
            return "the review session exited with code %d" % claude_code
        return "review-session.json holds no session result"
    if session.get("is_error") or session.get("subtype") != "success":
        return ("the review session ended with an error: "
                + short_text(session.get("result", "")))
    if claude_code != 0:
        return "the review session exited with code %d" % claude_code
    # "DONE", "Done." or "Done, the workflow finished." all count; the
    # killed-run shape ("Workflow is still running...") does not
    reply = str(session.get("result", ""))
    if not re.match(r"\s*done\b", reply, re.IGNORECASE):
        return ("the review session did not report DONE: "
                + short_text(session.get("result", "")))
    return None


def first_line(run_dir):
    try:
        with open(os.path.join(run_dir, "verdict.txt"), encoding="utf-8",
                  errors="replace") as f:
            return f.readline().strip()
    except OSError:
        return ""


PIPELINE_WORDS = {0: "READY TO PUBLISH", 1: "DO NOT PUBLISH",
                  2: "INCONCLUSIVE"}


def review_decision(run_dir, claude_code, timed_out=False):
    """The pipeline's final line and exit code after phase 2, from the run
    directory and how the `claude -p` session ended. Returns (line, exit
    code, problem); problem is None when the review's verdict stands.

    The verdict in verdict.json counts only when the review was merged AND
    confirmed by the workflow's read-back, and the session ended normally:
    a killed or unfinished session cannot vouch for verdict.json. Without
    that, the result is INCONCLUSIVE (exit 2), except for a veto: when
    verdict.json says DO NOT PUBLISH, that stands (exit 1), since acting on
    a veto is safe even when the run cannot vouch for it."""
    verdict_json = read_verdict(run_dir)
    session, other_lines = read_session(run_dir)
    line = first_line(run_dir)
    code = verdict_json.get("exit_code")

    if claude_code is None and not timed_out:
        problem = "the claude CLI is not installed"
    else:
        problem = session_problem(claude_code, timed_out, session,
                                  other_lines)
    if problem is None:
        if verdict_json.get("review_distrusted"):
            problem = "the workflow could not verify its merge"
        elif verdict_json.get("review_merged") is not True:
            problem = "the review rows were not merged into verdict.json"
        elif verdict_json.get("review_confirmed") is not True:
            problem = "the read-back did not confirm the merge"
        elif code not in PIPELINE_WORDS:
            problem = "verdict.json carries no usable exit code"
        elif not line.startswith("PIPELINE: " + PIPELINE_WORDS[code]):
            problem = "verdict.txt and verdict.json disagree"
    if problem is not None:
        # a veto in verdict.json stands (record_override keeps it in the files)
        if code == 1:
            return ("PIPELINE: DO NOT PUBLISH — the veto in verdict.json "
                    "stands, but the review was not confirmed (%s)"
                    % problem), 1, problem
        return ("PIPELINE: INCONCLUSIVE — review not confirmed (%s)"
                % problem), 2, problem
    return line, code, None


def record_override(run_dir, problem, code, feed_path):
    """Writes the pipeline's override into the run directory, so that
    verdict.json and verdict.txt agree with what the pipeline printed: runs
    `verdict.py distrust-review`, which adds a NOT POSSIBLE row, sets
    review_confirmed to false and reports the new verdict to the feed.
    Floor 1 keeps a veto; floor 2 makes the result at best INCONCLUSIVE.
    Skipped when the workflow already marked the run distrusted, so its own
    reason stays on record. Returns False when the files could not be
    updated."""
    if read_verdict(run_dir).get("review_distrusted"):
        return True
    floor = "1" if code == 1 else "2"
    command = [sys.executable, os.path.join(TOOLKIT_DIR, "checks",
                                            "verdict.py"),
               "distrust-review", run_dir, "pipeline: " + problem, floor]
    if feed_path:
        command.append(feed_path)
    result = subprocess.run(command, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True,
                            errors="replace")
    # a refusal exits 2 like an INCONCLUSIVE verdict: read the file instead
    if not read_verdict(run_dir).get("review_distrusted"):
        print("WARNING: could not record the override in %s: %s"
              % (run_dir, short_text(result.stderr)), flush=True)
        return False
    return True


def main(argv):
    if not argv or argv[0].startswith("-"):
        print("usage: preflight.sh run <repository> [base-ref]",
              file=sys.stderr)
        return 4
    # checked before the gate runs, so a typo creates no run folder
    models, error = models_from_environment(os.environ)
    if error:
        print("preflight.sh run: " + error, file=sys.stderr)
        return 4
    repo = os.path.abspath(argv[0])
    base = argv[1] if len(argv) > 1 else None
    signal.signal(signal.SIGTERM, stop)
    feed_path = None
    try:
        gate_code, run_dir, feed_path = run_gate(repo, base)
        if gate_code == 4 or not run_dir:
            return 4 if gate_code == 4 else 2
        if gate_code != 0:
            # the gate's own verdict stands; the review is not started
            feed.phase(feed_path, "review", "done",
                       "not run: the mechanical gate did not pass")
            return gate_code

        record_models(run_dir, models)
        feed.phase(feed_path, "review", "running",
                   "LLM review of the diff (often 5 to 15 minutes) · models "
                   + models_text(models))
        print("\nstarting the LLM review of the diff (claude -p), models "
              "%s..." % models_text(models), flush=True)
        verdict_json = read_verdict(run_dir)
        repo_top = verdict_json.get("repository", {}).get("path", repo)
        claude_code, timed_out = run_review(repo_top, run_dir, feed_path,
                                            models)

        line, code, problem = review_decision(run_dir, claude_code,
                                              timed_out)
        # the viewer keeps only a phase's latest detail: repeat the models
        models_detail = " · models " + models_text(models)
        if problem is None:
            feed.phase(feed_path, "review", "done",
                       PIPELINE_WORDS[code] + models_detail)
        else:
            record_override(run_dir, problem, code, feed_path)
            feed.phase(feed_path, "review", "failed",
                       "review not confirmed: " + problem + models_detail)
            # the workflow may already have reported a verdict word (a
            # session killed after the confirm step); this one replaces it
            feed.phase(feed_path, "verdict", "done", PIPELINE_WORDS[code])
        feed.verdict(feed_path, line, PIPELINE_WORDS[code])
        print("\n" + line, flush=True)
        print("report in: %s" % run_dir, flush=True)
        return code
    except KeyboardInterrupt:
        if running_child is not None:
            try:
                os.killpg(running_child.pid, signal.SIGTERM)
            except OSError:
                pass
        if feed_path:
            feed.verdict(feed_path, "PIPELINE: INCONCLUSIVE — the run was "
                         "cancelled", "INCONCLUSIVE")
        print("\ncancelled", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
