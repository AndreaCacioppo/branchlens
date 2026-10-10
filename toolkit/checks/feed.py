#!/usr/bin/env python3
"""
feed.py — appends security-run progress events to a JSON-lines feed file.

The feed is TELEMETRY ONLY: it exists so a local viewer (BranchLens) can show
"security check running — file 4 of 12" while the pipeline works. Nothing in
the pipeline ever reads it back, and it has no influence on any verdict.
Because of that, this module must never break a run: every operation swallows
its own errors (a broken progress bar is acceptable, a broken gate is not).

One feed file per repository, at a STABLE path the viewer can be pointed at
before any run exists:

    <reports-root>/security-feed.jsonl
    (reports-root is $PREFLIGHT_REPORTS_DIR when set and not empty, else
    ~/preflight-reports/<folder name of the main repository>, shared by
    every linked worktree of that repository)

The file is append-only. Each run appends a "start" marker first; a reader
shows the events after the LAST marker. To keep the file from growing forever
it is truncated when a new run starts and the file is already over 1 MB —
readers only care about the latest run, so nothing of value is lost.

Events (one JSON object per line):

    {"event": "start",   "utc": ..., "run_id": ..., "base": ..., "files": [...]}
    {"event": "phase",   "utc": ..., "name": "gate", "status": "running"}
    {"event": "phase",   "utc": ..., "name": "gate", "status": "done",
                         "detail": "PASSED"}
    {"event": "file",    "utc": ..., "path": ..., "status": "checking"}
    {"event": "file",    "utc": ..., "path": ..., "status": "clean"}
    {"event": "file",    "utc": ..., "path": ..., "status": "findings", "count": 2}
    {"event": "file",    "utc": ..., "path": ..., "status": "skipped",
                         "reason": "no security skill for this file type"}
    {"event": "finding", "utc": ..., "file": ..., "line": 12, "severity": "high",
                         "title": ..., "entry": "REV-07", "outcome": "CONFIRMED",
                         "blocking": true}
    {"event": "area",    "utc": ..., "name": "Backend build (Maven)",
                         "status": "NOT POSSIBLE", "reason": "mvn absent"}
    {"event": "verdict", "utc": ..., "text": "PREFLIGHT: PASSED — ...",
                         "verdict": "PASSED"}
    {"event": "check",   "utc": ..., "stage": "gate", "name": "Semgrep",
                         "status": "running"}
    {"event": "check",   "utc": ..., "stage": "gate", "name": "Semgrep",
                         "status": "done", "result": "TESTED",
                         "blocking": false, "detail": ..., "seconds": 2.4,
                         "count": 0}

A gate check's "done" event carries "count": the new findings its rows
report (the sum of their critical/high/medium/low counts, blocking and
advisory alike), 0 when none.

Every field beyond "event" is optional to a reader: this format only ever
GROWS, and a reader that meets an event or a field it does not know must skip
it rather than fail. That is what lets an old viewer read a new feed and a new
viewer read an old one.

A run may emit MORE than one verdict event (the mechanical gate's own line,
then the combined pipeline line after the diff review). Readers must treat the
run as live again whenever a file or phase event arrives after a verdict.

Each event is written with a single write() call of one complete line, so
concurrent appenders (parallel review agents) cannot interleave mid-line.

Command line (used by the review workflow's agents; the gate imports the
module instead):

    feed.py <feed-file> start --run-id ID --base REF [--files a.py b.js ...]
    feed.py <feed-file> file <path> checking
    feed.py <feed-file> file <path> clean
    feed.py <feed-file> file <path> findings <count>
    feed.py <feed-file> verdict <text>
    feed.py <feed-file> event <percent-encoded JSON event> [...] [--count N]

The review workflow uses the last form for anything taken from the
repository under review (file paths, finding titles). It percent-encodes the
whole event, so the command line holds nothing a shell could expand.

The command always exits 0: telemetry must never fail the caller.
"""

import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone

# When a new run starts and the feed is already bigger than this, it is
# truncated instead of appended to (readers only use the latest run).
MAX_FEED_BYTES = 1000000


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def append_event(feed_path, event):
    """Appends one event as one JSON line. Never raises."""
    try:
        event = dict(event)
        event["utc"] = utc_now()
        line = json.dumps(event, ensure_ascii=False) + "\n"
        directory = os.path.dirname(feed_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        # One write() of one complete line: appends from parallel processes
        # land whole, never interleaved mid-line.
        with open(feed_path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass  # telemetry must never break the run


def start_run(feed_path, run_id, base_ref, changed_files):
    """Marks the start of a run; truncates an oversized feed first."""
    try:
        if (os.path.isfile(feed_path)
                and os.path.getsize(feed_path) > MAX_FEED_BYTES):
            with open(feed_path, "w", encoding="utf-8"):
                pass
    except Exception:
        pass
    append_event(feed_path, {
        "event": "start",
        "run_id": run_id,
        "base": base_ref,
        "files": list(changed_files),
    })


def file_status(feed_path, path, status, count=None, reason=None):
    """Reports one file as checking / clean / findings / skipped.

    'skipped' is not a failure: it is a file no per-file reviewer covers (no
    security skill for that extension). Saying so out loud is the point — a
    file silently absent from the results looks examined.
    """
    event = {"event": "file", "path": path, "status": status}
    if count is not None:
        event["count"] = count
    if reason is not None:
        event["reason"] = reason
    append_event(feed_path, event)


def phase(feed_path, name, status, detail=None):
    """Reports a phase of the run starting or ending.

    Durations are deliberately NOT reported: every event already carries a
    UTC stamp, so a reader derives them. Two different processes emit into
    this feed, and a duration computed on one side would silently encode
    whichever clock produced it.
    """
    event = {"event": "phase", "name": name, "status": status}
    if detail is not None:
        event["detail"] = detail
    append_event(feed_path, event)


def finding(feed_path, file_path, line, severity, title, entry=None,
            outcome=None, blocking=False):
    """Reports one finding, so a viewer can show WHAT was found and where."""
    event = {
        "event": "finding",
        "file": file_path,
        "severity": severity,
        "title": title,
        "blocking": bool(blocking),
    }
    if line is not None:
        event["line"] = line
    if entry is not None:
        event["entry"] = entry
    if outcome is not None:
        event["outcome"] = outcome
    append_event(feed_path, event)


def area(feed_path, name, status, reason):
    """Reports an area that could NOT be examined, and why.

    This is the half of a verdict a one-line summary always loses: 'only 16
    of 24 areas tested' does not say which eight, and those are exactly the
    rows a reader has to see before trusting anything green.
    """
    append_event(feed_path, {
        "event": "area", "name": name, "status": status, "reason": reason,
    })


def verdict(feed_path, text, word=None):
    """Reports a bottom line (the gate's own, or the combined pipeline one).

    `word` is the bare verdict (PASSED / FAILED / INCONCLUSIVE / READY TO
    PUBLISH / DO NOT PUBLISH) so a viewer can style the result without
    parsing the sentence.
    """
    event = {"event": "verdict", "text": text}
    if word is not None:
        event["verdict"] = word
    append_event(feed_path, event)


def check(feed_path, stage, name, status, result=None, blocking=None,
          detail=None, seconds=None, count=None):
    """One step of the run starting (status "running") or finishing
    (status "done", with the row's result such as TESTED or NOT POSSIBLE,
    whether it blocks, a one-line detail, its duration and its number of
    new findings). stage is "gate", "review", "dive" or "verify", so a
    viewer can group them."""
    event = {"event": "check", "stage": stage, "name": name,
             "status": status}
    for key, value in (("result", result), ("blocking", blocking),
                       ("detail", detail), ("seconds", seconds),
                       ("count", count)):
        if value is not None:
            event[key] = value
    append_event(feed_path, event)


KNOWN_EVENTS = ("start", "phase", "file", "finding", "area", "verdict",
                "check")


def append_encoded_event(feed_path, encoded, count=None):
    """Decodes one percent-encoded JSON object and appends it. Anything that
    is not an object with a known "event" name is dropped, never raised."""
    try:
        event = json.loads(urllib.parse.unquote(encoded))
    except ValueError:
        print("feed.py: undecodable event dropped", file=sys.stderr)
        return
    if not isinstance(event, dict) or event.get("event") not in KNOWN_EVENTS:
        print("feed.py: unknown event dropped", file=sys.stderr)
        return
    if count is not None:
        event["count"] = count
    append_event(feed_path, event)


def main(argv):
    # Deliberately forgiving: bad arguments print a usage note to stderr but
    # still exit 0 — a progress feed must never fail the process feeding it.
    usage = ("usage: feed.py <feed-file> start --run-id ID --base REF "
             "[--files F1 F2 ...] | file <path> checking|clean | "
             "file <path> findings <count> | file <path> skipped [reason] | "
             "phase <name> running|done|failed [detail] | "
             "finding <file> <line> <severity> <title> [entry] [outcome] "
             "[blocking] | area <name> <status> <reason> | verdict <text>")
    if len(argv) < 2:
        print("feed.py: " + usage, file=sys.stderr)
        return 0
    feed_path = argv[0]
    command = argv[1]
    rest = argv[2:]

    if command == "start":
        run_id = ""
        base_ref = ""
        files = []
        position = 0
        while position < len(rest):
            if rest[position] == "--run-id" and position + 1 < len(rest):
                run_id = rest[position + 1]
                position += 2
            elif rest[position] == "--base" and position + 1 < len(rest):
                base_ref = rest[position + 1]
                position += 2
            elif rest[position] == "--files":
                files = rest[position + 1:]
                break
            else:
                position += 1
        start_run(feed_path, run_id, base_ref, files)
    elif command == "file" and len(rest) >= 2:
        path, status = rest[0], rest[1]
        if status == "findings" and len(rest) >= 3:
            try:
                count = int(rest[2])
            except ValueError:
                count = 1
            file_status(feed_path, path, "findings", count)
        elif status == "skipped":
            reason = " ".join(rest[2:]) or "no per-file reviewer for this type"
            file_status(feed_path, path, "skipped", reason=reason)
        elif status in ("checking", "clean"):
            file_status(feed_path, path, status)
        else:
            print("feed.py: unknown file status: " + status, file=sys.stderr)
    elif command == "phase" and len(rest) >= 2:
        detail = " ".join(rest[2:]) or None
        phase(feed_path, rest[0], rest[1], detail)
    elif command == "finding" and len(rest) >= 4:
        try:
            line_number = int(rest[1])
        except ValueError:
            line_number = None
        entry = rest[4] if len(rest) > 4 else None
        outcome = rest[5] if len(rest) > 5 else None
        blocking = len(rest) > 6 and rest[6].lower() in ("yes", "true", "1")
        finding(feed_path, rest[0], line_number, rest[2], rest[3],
                entry, outcome, blocking)
    elif command == "area" and len(rest) >= 3:
        area(feed_path, rest[0], rest[1], " ".join(rest[2:]))
    elif command == "verdict" and len(rest) >= 1:
        verdict(feed_path, " ".join(rest))
    elif command == "event" and len(rest) >= 1:
        # One or more percent-encoded JSON events. Encoded, text from the
        # repository under review is only [A-Za-z0-9%._-], which no shell
        # expands. An optional trailing "--count N" sets the count of every
        # event in the call.
        count = None
        if len(rest) >= 2 and rest[-2] == "--count":
            try:
                count = int(rest[-1])
            except ValueError:
                count = None
            rest = rest[:-2]
        for encoded in rest:
            append_encoded_event(feed_path, encoded, count)
    else:
        print("feed.py: " + usage, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
