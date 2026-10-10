#!/usr/bin/env python3
"""
verdict.py — derives the verdict from the area table and renders every output.

preflight.sh collects one row per AREA the gate could in principle cover into
<run-dir>/areas.tsv; this script is the ONLY place that turns those rows into
a verdict, a verdict.txt, a verdict.json and the screen output. One place on
purpose: the bottom line, the table, the call-out and the JSON mirror are four
views of the same numbers, and four separate counting loops (worse: two in
bash and two here) would eventually disagree — and a disagreement in a gate is
read as "pick the greener one".

THE TABLE IS THE VERDICT. Every input that may influence the exit code must be
a row in areas.tsv; nothing outside the table is consulted. That is what makes
the bottom line "hard to argue with": you can re-derive it by hand from the
rows above it.

areas.tsv format — 9 tab-separated fields, written by record_area() in
preflight.sh (empty fields are written as "-", never as nothing: a tab is an
IFS whitespace character in bash 3.2, so empty fields would silently shift the
columns of every reader):

    area      the human question × the tool answering it
    status    TESTED | NOT APPLICABLE | NOT POSSIBLE | PARTIAL
    scope     what was actually examined: a count and a unit ("412 files");
              for PARTIAL always "X of Y unit", the shortfall must be visible
    reason    mandatory whenever status is not TESTED
    outcome   TESTED/PARTIAL only: "clean", or what was found; empty on a
              PARTIAL row that records a coverage gap rather than a scan
    severity  highest severity among the row's NEW findings, or "none"
    counts    critical/high/medium/low tally of the NEW findings ("0/1/2/0")
    blocking  yes|no: do this row's findings fail the run? Decided at the call
              site, where the policy lives (Trivy blocks HIGH+, Checkstyle is
              always advisory). Without this field the verdict would need a
              hidden policy table and would stop being derivable from the rows.
    evidence  the file inside the run directory that proves the claim

The status vocabulary is the heart of the report:
    TESTED         the tool ran to completion over the intended scope.
                   Only this status contributes confidence.
    NOT APPLICABLE the area genuinely does not exist here (no pom.xml, no
                   Python). Not a defect — but still a visible row, because an
                   absent row is indistinguishable from a forgotten one.
    NOT POSSIBLE   the area EXISTS but could not be examined: tool missing,
                   build failed, timeout, unreadable report.
                   This is the dangerous one; it is rendered with a "!!" sigil
                   and repeated in the NOT-EXAMINED call-out, because it is
                   exactly the row a reader skims past.
    PARTIAL        the tool ran over less than the intended scope. Never
                   presented as TESTED; the shortfall stays in the scope column.

Verdict derivation (mechanical, in this order):
    FAILED        (exit 1)  any row with blocking=yes
    INCONCLUSIVE  (exit 2)  otherwise, any NOT POSSIBLE or PARTIAL row outside
                            the best-effort tier, or the coverage floor not
                            met (see below)
    PASSED        (exit 0)  otherwise; when best-effort areas were not
                            examined in full (NOT POSSIBLE or PARTIAL), the
                            bottom line carries a CAVEAT naming them
Exit 4 (usage) never reaches this script: it is a pre-run refusal in the
collector — nothing was examined, so there is no table to show, and
pretending one would be theatre.

Coverage floor: the security-core areas (REQUIRED_CORE_AREAS) must be present
and actually measured (TESTED or PARTIAL), counted over the MECHANICAL areas
only. The LLM diff-review rows are deliberately excluded: the review may
veto, never approve, so its rows must not be able to satisfy the floor on a
run where no scanner looked at anything — that would re-open the audited bug
this floor exists to close (a repository nobody examined exiting 0).

Subcommands:
  render <run-dir>                 derive + write verdict.txt/verdict.json +
                                   print the screen report; exits 0/1/2
  merge-review <run-dir> <rows>    merge the REV rows produced by the LLM
                                   diff review (one per checklist entry) into
                                   the same table, veto-only, idempotently;
                                   re-renders; exits with the COMBINED code
  review-state <run-dir>           print the merged state as JSON, for the
                                   workflow's independent read-back
  confirm-review <run-dir> [feed]  record that the read-back matched the
                                   merge (review_confirmed: true) and report
                                   the verdict to the feed
  distrust-review <run-dir> <why> [floor] [feed]
                                   mark a merge the workflow could not
                                   verify: a NOT POSSIBLE row from then on

The review's verdict counts only once it is confirmed. merge-review writes
review_merged: true and review_confirmed: false and sends no verdict to the
feed; the workflow runs confirm-review only after its read-back of the files
on disk matched what it built. A run killed between the two steps keeps
review_confirmed: false, and pipeline.py and BranchLens treat it as not
reviewed.

Exit convention: any unexpected error exits 2 (INCONCLUSIVE), never 0 and
never 1 — a crash must not read as either "fine" or "you broke something".
"""

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

# as in gate.py: never load toolkit modules from cached bytecode, which a
# planted .pyc could replace
sys.dont_write_bytecode = True
sys.pycache_prefix = os.path.join(tempfile.gettempdir(),
                                  "preflight-no-bytecode-%d" % os.getpid())

# review_scope.py, beside this script (sys.path[0]): the same checklist
# parser and checksum the gate uses.
import review_scope
# feed.py, also beside this script: confirm-review and distrust-review
# report the verdict to the progress feed
import feed

TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKLIST_PATH = os.path.join(TOOLKIT_DIR, "checks", "review", "checklist.md")

STATUSES = ("TESTED", "NOT APPLICABLE", "NOT POSSIBLE", "PARTIAL")
SEVERITIES = ("critical", "high", "medium", "low", "none")
FIELDS = ("area", "status", "scope", "reason", "outcome", "severity",
          "counts", "blocking", "evidence")

# The SECURITY CORE: rows that must be present and actually measured
# (TESTED or PARTIAL) for any run to be green. They run with no build, no
# baseline and no network, so "could not run" here means something is really
# wrong — it makes the verdict INCONCLUSIVE.
REQUIRED_CORE_AREAS = (
    "Multi-language analysis (Semgrep)",
    "Secrets in the diff",
)

# The BEST-EFFORT tier: checks that need a working toolchain (a Maven build,
# a test run) or the network (robots.txt of the hosts an HTTP change talks
# to). When one of them runs and FAILS it still blocks like any other
# row — but when the MACHINE cannot run it (broken toolchain, no network for
# a build plugin) its NOT POSSIBLE status is reported loudly in the bottom
# line and the call-out WITHOUT forcing the whole verdict to INCONCLUSIVE.
# This is a deliberate policy choice: the old gate vetoed the run whenever
# the platform build failed for environmental reasons, which in practice
# meant it never completed at all — and a gate nobody can run protects
# nobody.
#
# "Code without scanner rules" is here too: it names changed code no local
# Semgrep rule examined, which the checklist reviewers of the LLM review
# are asked to read.
BEST_EFFORT_AREAS = (
    "Backend build (Maven)",
    "Backend tests (Surefire)",
    "Java security tests",
    "Python tests (pytest)",
    "Python security tests",
    "Python analysis (Bandit)",
    "Outbound HTTP in the diff",
    "Code without scanner rules",
)

# The outcome of a TESTED row that had nothing in its scope (Semgrep over a
# diff with no file its rules cover, "Security tests in the diff" over a
# diff that touches no security test): it is not counted as having examined
# code.
NOTHING_TO_SCAN = "nothing to scan"

REVIEW_PREFIX = "Diff review "

# The dead and redundant code rows of the diff review (REV-11, REV-12) are
# best effort too: their reviewers stop at a bound of symbols, and a diff
# with no code file gives them nothing to read, so otherwise every large or
# documentation-only change would be INCONCLUSIVE. A blocking finding in
# them still blocks. Matched by prefix: the stored area is the entry id
# followed by a title cut to the column width.
BEST_EFFORT_REVIEW_ENTRIES = ("REV-11", "REV-12")


def is_best_effort(area):
    if area in BEST_EFFORT_AREAS:
        return True
    for entry_id in BEST_EFFORT_REVIEW_ENTRIES:
        if area.startswith(REVIEW_PREFIX + entry_id + " "):
            return True
    return False


# Rows that check the GATE rather than the code under test. They still block
# when they fail (a weakened scanner or a mutated repository invalidates the
# whole run), but they must never be counted as "we examined the code".
SELF_CHECK_AREAS = (
    "Uncommitted changes",
    "Scanner integrity",
    "Exceptions file",
    "Toolkit integrity",
    "Gate self-check (read-only)",
)

# Fixed display order: the causal chain a reader debugs in (does it build ->
# do the tests pass -> are the dependencies clean -> what does static analysis
# say -> the gate's own integrity -> the human-shaped review). The TSV keeps
# execution order (which follows build dependencies instead); the rendering is
# where the reader's order matters.
AREA_ORDER = (
    "Uncommitted changes",
    "Backend build (Maven)",
    "Backend tests (Surefire)",
    "Java security tests",
    "Python tests (pytest)",
    "Python security tests",
    "Security tests in the diff",
    "Secrets in the diff",
    "Dependencies (Trivy)",
    "Outbound HTTP in the diff",
    "Multi-language analysis (Semgrep)",
    "Python analysis (Bandit)",
    "Code without scanner rules",
    "Scanner integrity",
    "Exceptions file",
    "Toolkit integrity",
    "Gate self-check (read-only)",
    "Coverage floor",
    "Table integrity",
)


def sort_rows(rows):
    """Canonical order; REV rows after the mechanical ones (their ids sort
    lexically, REV-01 < REV-10); anything unknown goes last, visible rather
    than lost."""
    def key(pair):
        index, row = pair
        if row["area"] in AREA_ORDER:
            return (0, AREA_ORDER.index(row["area"]), index)
        if row["area"].startswith(REVIEW_PREFIX):
            return (1, 0, row["area"])
        return (2, 0, index)
    return [row for _index, row in
            sorted(enumerate(rows), key=lambda pair: key(pair))]

# Column layout of the rendered table. The area names are a fixed vocabulary
# chosen to fit WIDTH_AREA, so truncation is impossible by construction; the
# RESULT column instead wraps onto indented continuation lines, because
# truncating a reason is how "trivy absent (brew install trivy)" becomes
# "trivy absent (brew insta…" and stops being actionable.
WIDTH_SIGIL = 3
WIDTH_AREA = 36
WIDTH_STATUS = 15
WIDTH_SCOPE = 17
WIDTH_TOTAL = 110


def fail(message):
    print("verdict.py ERROR: " + message, file=sys.stderr)
    sys.exit(2)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def undash(value):
    """The TSV writes '-' for an empty field (see the format note above);
    turn it back into an empty string for JSON and for rendering."""
    return "" if value == "-" else value


def row_is_valid(row):
    """Every field whose value the derivation depends on is checked, not just
    the status. `blocking` is the sharpest example: derive() asks whether it
    equals "yes", so a single edited byte ("yes" -> "yea") turns a blocking
    finding into an advisory one and FAILED into PASSED. A value we do not
    recognise is corruption, and corruption must never resolve to the milder
    reading."""
    if row["status"] not in STATUSES:
        return False
    if row["blocking"] not in ("yes", "no", "-"):
        return False
    if row["severity"] not in SEVERITIES and row["severity"] != "-":
        return False
    if row["counts"] != "-":
        parts = row["counts"].split("/")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
    return True


def read_areas(path):
    """Reads areas.tsv strictly. A malformed line is NOT skipped silently: a
    row that exists to keep the run out of exit 0 must not be able to
    disappear by being corrupted, so corruption becomes a synthetic NOT
    POSSIBLE row and the run cannot end green.

    Returns (rows, corrupted_count). The count matters to the caller: at
    render time a synthetic row is enough, but at merge time the file is
    REWRITTEN, and rewriting it would quietly launder the corrupted rows out
    of existence - so merge-review refuses instead."""
    if not os.path.isfile(path):
        fail("areas.tsv not found in the run directory: " + path)
    rows = []
    corrupted = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != len(FIELDS):
                corrupted += 1
                continue
            row = dict(zip(FIELDS, parts))
            if not row_is_valid(row):
                corrupted += 1
                continue
            rows.append(row)
    if corrupted:
        rows.append({
            "area": "Table integrity", "status": "NOT POSSIBLE", "scope": "-",
            "reason": "%d corrupted row(s) in areas.tsv: the table cannot be "
                      "trusted as written" % corrupted,
            "outcome": "-", "severity": "-", "counts": "-", "blocking": "-",
            "evidence": "areas.tsv",
        })
    if not rows:
        fail("areas.tsv is empty: no area was recorded at all")
    return rows, corrupted


def read_meta(run_dir):
    meta = {}
    path = os.path.join(run_dir, "run-meta.txt")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    meta[key] = value
    return meta


def read_notes(run_dir):
    """The gate's notes.txt, then review-notes.txt (what the diff review
    could not cover), which merge-review rewrites on every merge."""
    notes = []
    for name in ("notes.txt", "review-notes.txt"):
        path = os.path.join(run_dir, name)
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as f:
                notes.extend(line.rstrip("\n") for line in f if line.strip())
    return notes


DISTRUST_MARKER = "review-distrusted.txt"

# The models the review workflow may run each stage on, weakest first, and
# the defaults. review-diff.js and pipeline.py use the same three names.
ALLOWED_MODELS = ("sonnet", "opus", "fable")
DEFAULT_MODELS = {"mechanical": "sonnet", "analysis": "opus",
                  "verify_high": "fable"}
MODEL_STAGES = ("mechanical", "analysis", "verify_high")


def check_review_models(payload):
    """The models the workflow ran, from its rows file: an object with
    exactly the three stages, each an allowed model. Anything else refuses
    the merge: a missing or unknown model could hide a weaker run."""
    models = payload.get("models")
    if not isinstance(models, dict) or sorted(models) != sorted(MODEL_STAGES):
        fail("the review rows carry no models object (mechanical, analysis, "
             "verify_high): the review-diff workflow that produced them is "
             "older than this toolkit (run 'make install-skills', then "
             "/reload-skills)")
    for stage in MODEL_STAGES:
        if models[stage] not in ALLOWED_MODELS:
            fail("review rows: model %r for %s is not one of %s"
                 % (models[stage], stage, ", ".join(ALLOWED_MODELS)))
    return dict(models)


def settings_note(models):
    """'SETTINGS: models mechanical=... analysis=... verify_high=...' when
    at least one stage ran on a model weaker than its default, else None. A
    stronger model alone is not stamped."""
    if not isinstance(models, dict):
        return None
    weaker = False
    for stage in MODEL_STAGES:
        model = models.get(stage)
        if model not in ALLOWED_MODELS:
            continue
        if (ALLOWED_MODELS.index(model)
                < ALLOWED_MODELS.index(DEFAULT_MODELS[stage])):
            weaker = True
    if not weaker:
        return None
    return "SETTINGS: models " + " ".join(
        "%s=%s" % (stage, models.get(stage)) for stage in MODEL_STAGES)


def join_notes(*notes):
    """The bottom-line notes that are not None, joined with ' · '."""
    present = [note for note in notes if note]
    return " · ".join(present) if present else None


def add_review_trust_row(rows, run_dir):
    """Adds a synthetic NOT POSSIBLE row while review-distrusted.txt exists:
    the review workflow could not confirm its merge landed as built, so the
    REV rows in the table prove nothing. Like the coverage floor, it is
    re-derived on every render and never written to areas.tsv."""
    path = os.path.join(run_dir, DISTRUST_MARKER)
    if not os.path.isfile(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        reason = " ".join(f.read().split()) or "no reason recorded"
    return rows + [{
        "area": "Diff review trust", "status": "NOT POSSIBLE", "scope": "-",
        "reason": reason, "outcome": "-", "severity": "-", "counts": "-",
        "blocking": "-", "evidence": DISTRUST_MARKER,
    }]


def read_versions(run_dir):
    versions = {}
    path = os.path.join(run_dir, "runtime-versions.txt")
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    versions[key] = value
    return versions


def parse_counts(text):
    """'0/1/2/0' -> {'critical':0,'high':1,'medium':2,'low':0}; '-' -> zeros."""
    zeros = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if text in ("", "-"):
        return zeros
    parts = text.split("/")
    if len(parts) != 4:
        return zeros
    try:
        return {"critical": int(parts[0]), "high": int(parts[1]),
                "medium": int(parts[2]), "low": int(parts[3])}
    except ValueError:
        return zeros


def add_coverage_floor(rows):
    """Appends the synthetic 'Coverage floor' row when the security core is
    missing from the table. The core checks (Semgrep on the changed files,
    secrets in the added lines) need no build and no network, so if their
    rows are absent or unmeasured the collector itself failed — and a table
    without them must not be able to reach a green verdict. Synthetic and
    re-derived on every render (never written back to areas.tsv), so a later
    merge cannot duplicate it."""
    missing = []
    for required in REQUIRED_CORE_AREAS:
        measured = any(r["area"] == required
                       and r["status"] in ("TESTED", "PARTIAL")
                       for r in rows)
        if not measured:
            missing.append(required)
    if not missing:
        return rows
    return rows + [{
        "area": "Coverage floor", "status": "NOT POSSIBLE", "scope": "-",
        "reason": ("the security core was not measured: %s — without it "
                   "nothing about this change was actually examined"
                   % ", ".join(missing)),
        "outcome": "-", "severity": "-", "counts": "-",
        "blocking": "-", "evidence": "areas.tsv",
    }]


def derive(rows):
    """The mechanical fold over the table. Returns (verdict, exit_code,
    summary). No judgement calls: every input is a row field."""
    tested = sum(1 for r in rows if r["status"] == "TESTED")
    partial = sum(1 for r in rows if r["status"] == "PARTIAL")
    not_possible = sum(1 for r in rows if r["status"] == "NOT POSSIBLE")
    not_applicable = sum(1 for r in rows if r["status"] == "NOT APPLICABLE")

    blocking_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    advisory_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in rows:
        counts = parse_counts(r["counts"])
        target = blocking_counts if r["blocking"] == "yes" else advisory_counts
        for level in counts:
            target[level] += counts[level]

    # A NOT POSSIBLE / PARTIAL row forces INCONCLUSIVE unless the area is in
    # the best-effort tier (see BEST_EFFORT_AREAS and
    # BEST_EFFORT_REVIEW_ENTRIES for why). Best-effort rows
    # that DID run and found something still block through `blocking` below,
    # exactly like every other row.
    unverified_best_effort = [
        r["area"] for r in rows
        if is_best_effort(r["area"])
        and r["status"] in ("NOT POSSIBLE", "PARTIAL")]
    vetoing = sum(1 for r in rows
                  if r["status"] in ("NOT POSSIBLE", "PARTIAL")
                  and not is_best_effort(r["area"]))

    if any(r["blocking"] == "yes" for r in rows):
        verdict, exit_code = "FAILED", 1
    elif vetoing > 0:
        verdict, exit_code = "INCONCLUSIVE", 2
    else:
        verdict, exit_code = "PASSED", 0

    self_checks = sum(1 for r in rows
                      if r["status"] == "TESTED"
                      and r["area"] in SELF_CHECK_AREAS)
    nothing_to_scan = sum(1 for r in rows
                          if r["status"] == "TESTED"
                          and r["area"] not in SELF_CHECK_AREAS
                          and r["outcome"] == NOTHING_TO_SCAN)
    summary = {
        "unverified_best_effort": unverified_best_effort,
        "areas_total": len(rows),
        "tested": tested,
        # the tested rows that actually looked at the repository, i.e. minus
        # the gate's own hygiene checks and the rows that had nothing to
        # scan (see coverage_text)
        "tested_substantive": tested - self_checks - nothing_to_scan,
        "tested_self_checks": self_checks,
        "tested_nothing_to_scan": nothing_to_scan,
        "partial": partial,
        "not_possible": not_possible,
        "not_applicable": not_applicable,
        "new_blocking_findings": blocking_counts,
        "new_advisory_findings": advisory_counts,
    }
    return verdict, exit_code, summary


def tally_text(counts):
    """{'critical':1,'high':2,...} -> '1 critical, 2 high' (zeros omitted)."""
    pieces = ["%d %s" % (counts[level], level)
              for level in ("critical", "high", "medium", "low")
              if counts[level] > 0]
    return ", ".join(pieces)


def coverage_text(summary):
    text = "%d of %d areas tested" % (summary["tested"], summary["areas_total"])
    # Three of the rows check the GATE, not the code: that the scanners were
    # not weakened, that no exception expired, that the run touched nothing.
    # They are worth having, but counting them as coverage would let a run
    # that examined no code at all claim "3 areas tested". So whenever the two
    # numbers differ the line says how many of the tested rows actually looked
    # at the repository. A row with nothing to scan is named too: it ran,
    # but looked at no code.
    if summary["tested_substantive"] != summary["tested"]:
        pieces = ["%d of them examined code" % summary["tested_substantive"]]
        if summary["tested_self_checks"]:
            pieces.append("%d are the gate's own self-checks"
                          % summary["tested_self_checks"])
        if summary["tested_nothing_to_scan"]:
            pieces.append("%d had nothing to scan"
                          % summary["tested_nothing_to_scan"])
        text += " (%s)" % ", ".join(pieces)
    text += ", %d n/a" % summary["not_applicable"]
    # NOT POSSIBLE is spelled out loud even at zero, so its absence is a
    # statement and not a gap the reader has to notice
    text += ", %d NOT POSSIBLE" % summary["not_possible"]
    if summary["partial"]:
        text += ", %d PARTIAL" % summary["partial"]
    return text


def bottom_line(label, verdict, kind, summary, review_note):
    """The one line a 3-second reader gets. It must never be a bare yes: the
    verdict word always travels with the finding tally AND the coverage tally,
    because 'PASSED' over an unexamined repository and 'PASSED' over a fully
    examined one are different facts and must read differently.

    `kind` is the exit-code family of the verdict being shown (1 red, 2
    inconclusive, 0 green) — the words differ between the mechanical run
    (FAILED) and the merged pipeline (DO NOT PUBLISH), the shape of the line
    must not."""
    blocking = tally_text(summary["new_blocking_findings"])
    advisory = tally_text(summary["new_advisory_findings"])

    if kind == 1:
        # the fallback covers the case where the run is blocked by something
        # the finding tally does not count - today, an earlier veto that a
        # later merge cannot clear (see the NOTES block)
        text = ("new findings: " + blocking if blocking
                else "blocked — see the table and the notes below")
        if advisory:
            text += " (plus %s, advisory)" % advisory
        text += " · " + coverage_text(summary)
    elif kind == 2:
        # Coverage first AND last. "No blocking findings" opening the line
        # reads as reassurance, and this verdict exists precisely because
        # nothing here deserves reassurance yet; and since this same line is
        # reprinted right above the shell prompt, whatever ends it is what a
        # hurried reader actually takes away - so it ends with the warning,
        # never with the calm half of the sentence.
        text = "only %d of %d areas tested (%d NOT POSSIBLE, %d PARTIAL, %d n/a)" % (
            summary["tested"], summary["areas_total"],
            summary["not_possible"], summary["partial"],
            summary["not_applicable"])
        if summary["tested_substantive"] == 0:
            text += "; NOTHING about this code was actually measured"
        else:
            text += "; nothing blocking in the %d area(s) that examined code" % (
                summary["tested_substantive"],)
        if advisory:
            text += " (%s, advisory)" % advisory
        text += " — NOT a green light"
    else:
        text = "no new findings"
        if advisory:
            text = "no blocking findings (%s, advisory)" % advisory
        text += " · " + coverage_text(summary)
        # a green with unverified best-effort areas is a different fact from
        # a full green, and the difference must live in the same line
        unverified = summary.get("unverified_best_effort") or []
        if unverified:
            text += (" · CAVEAT: %d area(s) not examined in full (%s) — see "
                     "NOT EXAMINED below"
                     % (len(unverified), ", ".join(unverified)))

    line = "%s: %s — %s" % (label, verdict, text)
    if review_note:
        line += " · " + review_note
    return line


def sigil(status):
    """'!!' for NOT POSSIBLE, '~' for PARTIAL, nothing otherwise: the left
    margin carries ink ONLY on the dangerous rows, so a vertical eye-sweep
    down the first two columns finds every one of them. Two structurally
    different marks, not one repeated, because '!' vs '!!' blurs at reading
    speed."""
    if status == "NOT POSSIBLE":
        return "!!"
    if status == "PARTIAL":
        return "~"
    return ""


def row_result(row):
    """The RESULT cell: outcome+severity+evidence for TESTED rows, the reason
    for NOT APPLICABLE / NOT POSSIBLE rows (which have no outcome by
    definition). A PARTIAL row shows BOTH, reason first, and its outcome is
    qualified: a cell ending in a bare 'clean' is read as "tested, fine" no
    matter what the status column says, which is exactly the misreading this
    report exists to prevent."""
    outcome = undash(row["outcome"])
    reason = undash(row["reason"])
    severity = undash(row["severity"])
    evidence = undash(row["evidence"])

    if row["status"] in ("NOT APPLICABLE", "NOT POSSIBLE"):
        return reason or "(no reason recorded — this is itself a defect)"

    if row["status"] == "PARTIAL" and not outcome:
        # a coverage gap (Code without scanner rules): the reason is the
        # whole result
        text = reason or "(no reason recorded — itself a defect)"
        return text + (" · " + evidence if evidence else "")

    text = outcome or "(no outcome recorded)"
    if severity and severity != "none" and severity not in text:
        text += " (%s)" % severity
    if row["status"] == "PARTIAL":
        text += " IN THE PART EXAMINED ONLY"
        # the reason is mandatory for a PARTIAL row; if it is missing, say so
        # rather than rendering a cell that looks complete
        text = "%s — %s" % (reason or "(no reason recorded — itself a defect)",
                            text)
    if evidence:
        text += " · " + evidence
    return text


def render_table(rows):
    lines = []
    header = "%-*s %-*s %-*s %s" % (
        WIDTH_SIGIL + WIDTH_AREA, "   AREA", WIDTH_STATUS, "STATUS",
        WIDTH_SCOPE, "SCOPE", "RESULT")
    lines.append(header)
    lines.append("-" * WIDTH_TOTAL)
    indent = WIDTH_SIGIL + WIDTH_AREA + 1 + WIDTH_STATUS + 1 + WIDTH_SCOPE + 1
    result_width = WIDTH_TOTAL - indent
    for row in rows:
        left = "%-*s%-*s %-*s %-*s " % (
            WIDTH_SIGIL, sigil(row["status"]),
            WIDTH_AREA, row["area"],
            WIDTH_STATUS, row["status"],
            WIDTH_SCOPE, undash(row["scope"]) or "-")
        # wrap RESULT at word boundaries onto continuation lines aligned under
        # the column, instead of truncating (see the layout note at the top)
        words = row_result(row).split()
        current = ""
        emitted = False
        for word in words:
            candidate = (current + " " + word).strip()
            if len(candidate) > result_width and current:
                lines.append((left if not emitted else " " * indent) + current)
                emitted = True
                current = word
            else:
                current = candidate
        lines.append((left if not emitted else " " * indent) + current)
    return lines


def render_callout(rows):
    """The NOT-EXAMINED call-out: every NOT POSSIBLE and PARTIAL row, again,
    with its reason. Deliberate redundancy — these are the rows a skimming
    reader misses in the table, so they get a second, unmissable listing. The
    section always prints, even when empty: a section that only appears
    sometimes trains the reader not to look for it. Rows sharing a status and
    reason are grouped (a dozen REV rows failing for one upstream cause
    must not bury a distinct failure under a wall of repetition)."""
    lines = ["NOT EXAMINED (read these rows before trusting any green):"]
    grouped = []
    for row in rows:
        if row["status"] not in ("NOT POSSIBLE", "PARTIAL"):
            continue
        key = (row["status"], row["reason"])
        for entry in grouped:
            if entry["key"] == key:
                entry["areas"].append((row["area"], undash(row["scope"])))
                break
        else:
            grouped.append({"key": key,
                            "areas": [(row["area"], undash(row["scope"]))]})
    if not grouped:
        lines.append("  none — every applicable area was examined in full.")
        return lines
    for entry in grouped:
        status, reason = entry["key"]
        mark = "!!" if status == "NOT POSSIBLE" else "~ "
        # the shortfall is per area, so it is printed per area: showing one
        # group's first scope for all of them would misstate the others
        if status == "PARTIAL":
            names = ", ".join("%s (%s)" % (area, scope) if scope else area
                              for area, scope in entry["areas"])
        else:
            names = ", ".join(area for area, _scope in entry["areas"])
        lines.append("  %s %s — %s: %s" % (mark, names, status, undash(reason)))
    return lines


def build_verdict_txt(label, line, rows, meta, notes, run_dir):
    out = []
    out.append(line)
    out.append("")
    out.append("mode        : %s" % meta.get("mode", "?"))
    out.append("repository  : %s (%s)" % (meta.get("repo_path", "?"),
                                          meta.get("repo_remote", "?")))
    out.append("branch      : %s @ %s" % (meta.get("branch", "?"),
                                          meta.get("commit", "?")))
    out.append("base_ref    : %s" % meta.get("base_ref", "?"))
    out.append("analysed    : %s" % meta.get("scan_source", "?"))
    out.append("toolkit     : %s @ %s" % (meta.get("toolkit_path", "?"),
                                          meta.get("toolkit_commit", "?")))
    out.append("utc         : %s" % utc_now())
    out.append("")
    out.extend(render_table(rows))
    out.append("")
    out.extend(render_callout(rows))
    if notes:
        out.append("")
        out.append("NOTES")
        out.append("-----")
        out.extend(notes)
    out.append("")
    out.append("TOOL VERSIONS")
    out.append("-------------")
    versions_path = os.path.join(run_dir, "runtime-versions.txt")
    if os.path.isfile(versions_path):
        with open(versions_path, encoding="utf-8", errors="replace") as f:
            out.extend(line.rstrip("\n") for line in f)
    out.append("")
    out.append("Meaning of the verdict: a green here means no predictable problem")
    out.append("got worse compared to the base branch, over the areas the table")
    out.append("marks TESTED — and only those. It does NOT mean the code is")
    out.append("secure. The raw report of every tool is in this same directory and")
    out.append("can be re-examined independently.")
    return "\n".join(out) + "\n"


def build_verdict_json(verdict, exit_code, summary, rows, meta, notes,
                       run_dir, extra):
    areas = []
    for row in rows:
        areas.append({
            "area": row["area"],
            "status": row["status"],
            "scope": undash(row["scope"]),
            "reason": undash(row["reason"]),
            "outcome": undash(row["outcome"]),
            "severity": undash(row["severity"]) or "none",
            "severity_counts": (None if row["counts"] in ("", "-")
                                else parse_counts(row["counts"])),
            "blocking": (True if row["blocking"] == "yes"
                         else False if row["blocking"] == "no" else None),
            "evidence": undash(row["evidence"]),
        })
    payload = {
        "verdict": verdict,
        "exit_code": exit_code,
        "mode": meta.get("mode", "?"),
        "repository": {
            "path": meta.get("repo_path", "?"),
            "remote": meta.get("repo_remote", "?"),
            "branch": meta.get("branch", "?"),
            "commit": meta.get("commit", "?"),
        },
        "base_ref": meta.get("base_ref", "?"),
        "analysed_tree": {
            "path": meta.get("scan_dir", "?"),
            "source": meta.get("scan_source", "?"),
        },
        "baseline": ({"commit": meta.get("baseline_commit", ""),
                      "date": meta.get("baseline_date", "")}
                     if meta.get("baseline_commit") else None),
        "toolkit_path": meta.get("toolkit_path", "?"),
        "toolkit_commit": meta.get("toolkit_commit", "?"),
        "utc_timestamp": utc_now(),
        "summary": summary,
        "areas": areas,
        "notes": notes,
        "tool_versions": read_versions(run_dir),
    }
    payload.update(extra)
    return payload


def write_manifest(run_dir):
    """manifest.sha256, in the same format `shasum -a 256` writes, so a third
    party can verify it with `shasum -c`. Regenerated here because both render
    and merge-review change verdict files after preflight.sh has finished."""
    entries = []
    for root, _dirs, files in os.walk(run_dir):
        for name in files:
            if name == "manifest.sha256":
                continue
            path = os.path.join(root, name)
            # regular files only: a planted symlink or named pipe would
            # redirect the read or hang it
            if os.path.islink(path) or not os.path.isfile(path):
                entries.append("%s  ./%s" % ("-" * 64,
                                             os.path.relpath(path, run_dir)))
                continue
            digest = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    digest.update(chunk)
            rel = "./" + os.path.relpath(path, run_dir)
            entries.append("%s  %s" % (digest.hexdigest(), rel))
    entries.sort(key=lambda e: e.split("  ", 1)[1])
    with open(os.path.join(run_dir, "manifest.sha256"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(entries) + "\n")


def emit(run_dir, label, verdict, exit_code, kind, summary, rows, meta, notes,
         review_note, extra):
    """Writes verdict.txt + verdict.json + manifest and prints the screen
    report. The bottom line is printed ABOVE the table (the reader who reads
    top-down meets it first) and REPEATED as the last line (the reader who
    only glances at what sits next to the prompt meets it too — with a
    24-plus-row table, whatever is printed first has already scrolled away)."""
    line = bottom_line(label, verdict, kind, summary, review_note)
    summary = dict(summary)
    summary["review_included"] = any(r["area"].startswith(REVIEW_PREFIX)
                                     for r in rows)

    with open(os.path.join(run_dir, "verdict.txt"), "w", encoding="utf-8") as f:
        f.write(build_verdict_txt(label, line, rows, meta, notes, run_dir))
    payload = build_verdict_json(verdict, exit_code, summary, rows, meta,
                                 notes, run_dir, extra)
    with open(os.path.join(run_dir, "verdict.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    write_manifest(run_dir)

    print("")
    print("=" * WIDTH_TOTAL)
    print("  " + line)
    print("=" * WIDTH_TOTAL)
    for text in render_table(rows):
        print("  " + text)
    print("")
    for text in render_callout(rows):
        print("  " + text)
    print("")
    print("  Report (evidence record): %s" % run_dir)
    print("    verdict.txt / verdict.json  the table above, plus tool versions")
    print("    manifest.sha256             checksum of every file in this run")
    print("")
    print("  " + line)
    print("")


def command_render(run_dir):
    # Refuse on a run that already carries a PIPELINE verdict: render
    # recomputes from the table alone and would drop the floors merge-review
    # keeps (the gate's exit code, an earlier veto).
    try:
        with open(os.path.join(run_dir, "verdict.json"), encoding="utf-8",
                  errors="replace") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        previous = {}
    if previous.get("review_merged") or previous.get("review_distrusted") \
            or os.path.isfile(os.path.join(run_dir, DISTRUST_MARKER)):
        fail("this run already carries a PIPELINE verdict; render would "
             "replace it. Run the gate again for a fresh run directory.")
    rows, _corrupted = read_areas(os.path.join(run_dir, "areas.tsv"))
    meta = read_meta(run_dir)
    notes = read_notes(run_dir)

    rows = sort_rows(add_coverage_floor(rows))
    verdict, exit_code, summary = derive(rows)
    # Standalone mechanical runs say OUT LOUD that phase 2 is not in the
    # table, so their bottom line cannot be mistaken for the pipeline's.
    # Imperative, not descriptive: "not included" can be read as
    # "scheduled", and a reader who thinks phase 2 is coming will publish
    # on a verdict that never had it.
    review_note = (None if summary_has_review(rows)
                   else "LLM diff review NOT run — run security-pipeline "
                        "before publishing")
    if meta.get("mode") == "check-worktree":
        # --worktree judged uncommitted files that no commit records: say so
        # on the bottom line
        review_note = ("judged the UNCOMMITTED working tree, not a commit"
                       + (" · " + review_note if review_note else ""))
    emit(run_dir, "PREFLIGHT", verdict, exit_code, exit_code, summary, rows,
         meta, notes, review_note, {})
    return exit_code


def summary_has_review(rows):
    return any(r["area"].startswith(REVIEW_PREFIX) for r in rows)


def validate_review_rows(payload):
    """The review rows arrive from an LLM workflow, i.e. from the least
    trustworthy writer in the whole pipeline; everything is checked and any
    defect refuses the merge (the caller then reports INCONCLUSIVE — never a
    silently-dropped veto)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        fail("review rows: expected an object with a 'rows' list")
    rows = payload["rows"]
    # The expected rows come from checklist.md, never from the workflow, so
    # no agent can make one disappear.
    expected_ids = [entry["id"] for entry
                    in review_scope.parse_checklist(CHECKLIST_PATH)]
    if not expected_ids:
        fail("no '## REV-NN — title' entry found in " + CHECKLIST_PATH)
    seen_ids = []
    clean = []
    for row in rows:
        if not isinstance(row, dict):
            fail("review rows: every row must be an object")
        area = str(row.get("area", ""))
        matched = None
        for rev_id in expected_ids:
            if area.startswith(REVIEW_PREFIX + rev_id):
                matched = rev_id
                break
        if matched is None:
            fail("review rows: area %r does not name a checklist entry (%s)"
                 % (area, ", ".join(expected_ids)))
        if matched in seen_ids:
            fail("review rows: %s appears more than once" % matched)
        seen_ids.append(matched)
        status = str(row.get("status", ""))
        # NOT APPLICABLE is deliberately NOT accepted here, although it is a
        # valid status for a mechanical area. It is the only status that is
        # neutral in the derivation - it forces neither INCONCLUSIVE nor
        # FAILED - so REV rows all claiming "not applicable" would merge
        # cleanly and hand a mechanically-green run the pipeline's strongest
        # label while no reviewer had examined anything. The workflow never
        # emits it either: a reviewer that could not do its job is NOT
        # POSSIBLE, and whether a checklist entry applies is not the
        # reviewer's call to make.
        if status not in ("TESTED", "NOT POSSIBLE", "PARTIAL"):
            fail("review rows: %s has status %r; a review row may only be "
                 "TESTED, NOT POSSIBLE or PARTIAL" % (matched, status))
        reason = str(row.get("reason", "") or "")
        if status != "TESTED" and not reason.strip():
            fail("review rows: %s is %s but carries no reason" % (matched, status))
        # no default for severity or blocking: a missing field must not be
        # read as the milder value
        severity = str(row.get("severity", ""))
        if severity not in SEVERITIES:
            fail("review rows: %s has invalid severity %r" % (matched, severity))
        blocking = str(row.get("blocking", ""))
        if blocking not in ("yes", "no"):
            fail("review rows: %s has invalid blocking %r" % (matched, blocking))
        # Same format the table itself demands. Checked HERE, before anything
        # is written: without it a malformed value only fails on the read-back
        # after areas.tsv has already been rewritten, and the error then blames
        # "table corruption" instead of naming the review row that caused it.
        counts = str(row.get("counts", "") or "-")
        if counts != "-":
            parts = counts.split("/")
            if len(parts) != 4 or not all(p.isdigit() for p in parts):
                fail("review rows: %s has invalid counts %r (expected '-' or "
                     "critical/high/medium/low)" % (matched, counts))
        clean.append({
            "area": area[:WIDTH_AREA],
            "status": status,
            "scope": str(row.get("scope", "") or "-"),
            "reason": reason or "-",
            "outcome": str(row.get("outcome", "") or "-"),
            "severity": severity,
            "counts": counts,
            "blocking": blocking,
            "evidence": str(row.get("evidence", "") or "-"),
        })
    missing = [i for i in expected_ids if i not in seen_ids]
    if missing:
        fail("review rows: missing " + ", ".join(missing))
    incomplete = payload.get("incomplete_reason")
    if incomplete:
        clean.append({
            "area": "Diff review coverage", "status": "NOT POSSIBLE",
            "scope": "-", "reason": str(incomplete), "outcome": "-",
            "severity": "-", "counts": "-", "blocking": "-",
            "evidence": "review-rows.json",
        })
    return clean


def sanitize_field(value):
    """Same discipline as record_area in preflight.sh: no tabs or newlines
    survive into the TSV, and no field is ever empty."""
    text = " ".join(str(value).split())
    return text if text else "-"


def check_reviewed_scope(run_dir, payload):
    """The workflow's reviewed_scope (commit, file count and checksum, see
    review_scope.py) must equal what the gate wrote to review-scope.json for
    this run. The scope reaches the workflow through an agent; without this
    check, a file lost or swapped on the way would still yield clean rows."""
    try:
        gate_scope = review_scope.read_scope(run_dir)
    except (OSError, ValueError):
        fail("review-scope.json is missing or unreadable in %s: the review "
             "cannot be tied to the gate's diff; re-run the gate" % run_dir)
    reviewed = payload.get("reviewed_scope")
    if not isinstance(reviewed, dict):
        fail("the review rows carry no reviewed_scope: the review-diff "
             "workflow that produced them is older than this toolkit "
             "(run 'make install-skills', then /reload-skills)")
    if reviewed.get("head_commit") != gate_scope.get("head_commit"):
        fail("the review describes commit %s but the gate examined %s: run "
             "the gate again, then the review"
             % (reviewed.get("head_commit"), gate_scope.get("head_commit")))
    if (reviewed.get("file_count") != gate_scope.get("file_count")
            or reviewed.get("scope_checksum")
            != gate_scope.get("scope_checksum")):
        fail("the review covered a different scope than the gate computed "
             "(review: %s files, checksum %s; gate: %s files, checksum %s)"
             % (reviewed.get("file_count"), reviewed.get("scope_checksum"),
                gate_scope.get("file_count"),
                gate_scope.get("scope_checksum")))
    check_code_file_count(gate_scope, reviewed, payload)
    return gate_scope


def check_code_file_count(gate_scope, reviewed, payload):
    """The dead-code rows (REV-11, REV-12) report "N of M changed code
    files": M must be the number of code files the gate listed, and with
    none listed those rows cannot claim to have examined anything."""
    gate_code_files = gate_scope.get("code_files")
    if not isinstance(gate_code_files, list):
        fail("review-scope.json carries no code_files list: it was written "
             "by an older gate; re-run the gate")
    if not isinstance(reviewed.get("code_file_count"), int):
        fail("the review rows carry no code_file_count: the review-diff "
             "workflow that produced them is older than this toolkit "
             "(run 'make install-skills', then /reload-skills)")
    if reviewed["code_file_count"] != len(gate_code_files):
        fail("the review counted %d changed code files but the gate listed "
             "%d" % (reviewed["code_file_count"], len(gate_code_files)))
    if gate_code_files:
        return
    for row in payload.get("rows", []):
        area = str(row.get("area", ""))
        for entry_id in BEST_EFFORT_REVIEW_ENTRIES:
            if (area.startswith(REVIEW_PREFIX + entry_id + " ")
                    and row.get("status") in ("TESTED", "PARTIAL")):
                fail("review rows: %s is %s but the gate listed no changed "
                     "code file for it to examine"
                     % (entry_id, row.get("status")))


CHECKLIST_ONLY_TEXT = ("reviewed by the checklist only, no scanner rule and "
                       "no deep dive")
UNREAD_TEXT = ("not reported read by any reviewer, no scanner rule and no "
               "deep dive")


def file_names(entries):
    """'a.go (Go), b.pl (Perl)' for [{"path", "language"}]."""
    return ", ".join("%s (%s)" % (entry["path"], entry["language"])
                     for entry in entries)


def checklist_only_caveat(gate_scope, payload):
    """(caveat for the bottom line or None, checklist-only files, unread
    files), both [{"path", "language"}]: the changed code files that got
    neither a Semgrep rule (the gate's code_without_rules) nor a completed
    deep dive (the workflow's deep_dived), split by whether a checklist
    reviewer reported opening them (the workflow's examined_files).
    Wording only: it never changes the verdict."""
    lists = {}
    for key in ("deep_dived", "examined_files"):
        value = payload.get(key)
        if not isinstance(value, list) or not all(
                isinstance(path, str) for path in value):
            fail("the review rows carry no %s list: the review-diff "
                 "workflow that produced them is older than this toolkit "
                 "(run 'make install-skills', then /reload-skills)" % key)
        lists[key] = value
    files = review_scope.undived_code_without_rules(gate_scope,
                                                    lists["deep_dived"])
    examined = set(lists["examined_files"])
    checklist_only = [entry for entry in files if entry["path"] in examined]
    unread = [entry for entry in files if entry["path"] not in examined]
    parts = []
    for text, entries in ((CHECKLIST_ONLY_TEXT, checklist_only),
                          (UNREAD_TEXT, unread)):
        if not entries:
            continue
        names = file_names(entries[:10])
        if len(entries) > 10:
            names += " and %d more (see NOTES)" % (len(entries) - 10)
        parts.append("%s: %s" % (text, names))
    if not parts:
        return None, [], []
    return "CAVEAT: " + "; ".join(parts), checklist_only, unread


def command_merge_review(run_dir, rows_path):
    if not os.path.isfile(rows_path):
        fail("review rows file not found: " + rows_path)
    with open(rows_path, encoding="utf-8", errors="replace") as f:
        try:
            payload = json.load(f)
        except json.JSONDecodeError as e:
            fail("review rows file is not valid JSON: %s" % e)
    review_rows = validate_review_rows(payload)
    gate_scope = check_reviewed_scope(run_dir, payload)
    caveat, checklist_only, unread = checklist_only_caveat(gate_scope,
                                                           payload)
    models = check_review_models(payload)
    review_notes = payload.get("notes", [])
    if not isinstance(review_notes, list) or not all(
            isinstance(note, str) for note in review_notes):
        fail("review rows: 'notes' must be a list of strings")

    areas_path = os.path.join(run_dir, "areas.tsv")
    existing_rows, corrupted = read_areas(areas_path)
    if corrupted:
        # REFUSE rather than rewrite. This step rewrites areas.tsv, and a
        # rewrite drops every line that failed validation - including a
        # blocking row someone tampered with. The corruption would then be
        # gone from the file, from the re-derived verdict and from the
        # evidence, which is the most dangerous shape a bug can take here.
        fail("%d corrupted row(s) in areas.tsv: refusing to merge the review "
             "into a table that cannot be trusted. The mechanical verdict "
             "already reported this; re-run the gate." % corrupted)
    mechanical = [r for r in existing_rows
                  if not r["area"].startswith(REVIEW_PREFIX)
                  and r["area"] != "Table integrity"]

    # The mechanical verdict is the one preflight.sh already emitted; the
    # review may only make things worse. Read it back from verdict.json so the
    # veto-only rule is enforced against what was actually reported, not
    # against a recomputation that could drift.
    verdict_json_path = os.path.join(run_dir, "verdict.json")
    if not os.path.isfile(verdict_json_path):
        fail("verdict.json not found: run preflight.sh check first")
    with open(verdict_json_path, encoding="utf-8", errors="replace") as f:
        try:
            previous = json.load(f)
        except json.JSONDecodeError as e:
            fail("existing verdict.json unreadable: %s" % e)
    mechanical_exit = previous.get("mechanical_exit_code",
                                   previous.get("exit_code"))
    if mechanical_exit not in (0, 1, 2):
        fail("existing verdict.json carries no usable exit code")
    # A verdict this run has ALREADY published, if any. It is part of the
    # floor below: re-running the merge with a cleaner rows file must not be
    # able to erase a veto that was already recorded in the evidence. Without
    # this, two calls - first a blocking row, then an all-clean file - leave
    # verdict.txt reading READY TO PUBLISH with no trace of the veto, and the
    # rows file is written by the least trustworthy writer in the pipeline.
    previous_pipeline_exit = previous.get("pipeline_exit_code")
    if previous_pipeline_exit not in (0, 1, 2):
        previous_pipeline_exit = None

    # Idempotent by construction: existing REV rows were dropped above, so
    # running the merge twice replaces rather than duplicates.
    merged = mechanical + review_rows
    with open(areas_path, "w", encoding="utf-8") as f:
        for row in merged:
            f.write("\t".join(sanitize_field(row[field]) for field in FIELDS)
                    + "\n")

    # rewritten on every merge, like the REV rows themselves
    with open(os.path.join(run_dir, "review-notes.txt"), "w",
              encoding="utf-8") as f:
        for note in review_notes:
            f.write("REVIEW: " + " ".join(note.split()) + "\n")

    meta = read_meta(run_dir)
    notes = read_notes(run_dir)
    merged_rows, merged_corrupted = read_areas(areas_path)
    if merged_corrupted:
        fail("the table we just wrote does not read back cleanly (%d corrupted "
             "row(s)): refusing to publish a verdict from it" % merged_corrupted)
    rows = sort_rows(add_review_trust_row(add_coverage_floor(merged_rows),
                                          run_dir))
    _verdict, derived_exit, summary = derive(rows)

    # VETO-ONLY, enforced in code and not in a prompt: the combined outcome is
    # the WORSE of (what the mechanical gate said, what the full table says
    # now, and any verdict this run already published). Clean REV rows can
    # therefore never lift a FAILED, an INCONCLUSIVE, or an earlier veto — the
    # review's clean result is the absence of evidence, not evidence of
    # safety, and that holds across repeated merges as well as within one.
    badness = {0: 0, 2: 1, 1: 2}
    candidates = [mechanical_exit, derived_exit]
    if previous_pipeline_exit is not None:
        candidates.append(previous_pipeline_exit)
    combined_exit = max(candidates, key=lambda c: badness[c])
    if (previous_pipeline_exit is not None
            and badness[previous_pipeline_exit] > badness[derived_exit]):
        # say it out loud in the evidence: a reader must be able to see that
        # this run once carried a worse verdict, and why it still does
        notes.append("NOTE: a previous merge of the diff review had already "
                     "produced a worse verdict (exit %d); it stands - a later "
                     "review cannot clear it." % previous_pipeline_exit)
    pipeline_words = {0: "READY TO PUBLISH", 2: "INCONCLUSIVE",
                      1: "DO NOT PUBLISH"}
    verdict = pipeline_words[combined_exit]
    if checklist_only:
        notes.append("NOTE: reviewed by the checklist only (no Semgrep rule "
                     "for the language, no deep dive): "
                     + file_names(checklist_only))
    if unread:
        notes.append("NOTE: not reported read by any reviewer (no Semgrep "
                     "rule for the language, no deep dive, and no checklist "
                     "reviewer listed it among the files it opened): "
                     + file_names(unread))

    # exit_code carries the COMBINED code, not the mechanical one: a consumer
    # that reads verdict.json and finds {"verdict": "DO NOT PUBLISH",
    # "exit_code": 0} would be reading a contradiction, and would resolve it
    # in whichever direction its author happened to trust. The mechanical code
    # stays available beside it, and the idempotent re-merge above reads that
    # key in preference, so re-running the merge still compares against the
    # gate's own verdict rather than against the merged one.
    emit(run_dir, "PIPELINE", verdict, combined_exit, combined_exit,
         summary, rows, meta, notes,
         # the SETTINGS stamp goes last on the line
         join_notes(caveat, settings_note(models)),
         {"mechanical_exit_code": mechanical_exit,
          "pipeline_exit_code": combined_exit,
          "models": models,
          "review_merged": True,
          # set to true by confirm-review, after the workflow's read-back
          "review_confirmed": False,
          "checklist_only_code": checklist_only,
          "unread_code": unread})
    return combined_exit


PIPELINE_PREFIX = "PIPELINE: "


def default_feed_path(run_dir):
    """The feed the gate writes to: security-feed.jsonl in the folder that
    holds the run directory. The workflow uses the same default."""
    parent = os.path.dirname(os.path.abspath(run_dir))
    return os.path.join(parent, "security-feed.jsonl")


def verdict_word(first_line):
    """'PIPELINE: READY TO PUBLISH — ...' -> 'READY TO PUBLISH'."""
    text = first_line
    if text.startswith(PIPELINE_PREFIX):
        text = text[len(PIPELINE_PREFIX):]
    return text.split(" —")[0].strip()


def read_first_line(run_dir):
    try:
        with open(os.path.join(run_dir, "verdict.txt"), encoding="utf-8",
                  errors="replace") as f:
            return f.readline().strip()
    except OSError:
        return ""


def report_verdict_to_feed(run_dir, feed_path):
    """The two feed events a viewer takes the verdict from: the 'verdict'
    phase (BranchLens reads its word) and the verdict line itself."""
    first_line = read_first_line(run_dir)
    word = verdict_word(first_line)
    feed.phase(feed_path, "verdict", "done", word)
    feed.verdict(feed_path, first_line, word)


def command_confirm_review(run_dir, feed_path=None):
    """Called by the review workflow ONLY after its read-back of the run
    directory matched the rows it built: sets review_confirmed to true in
    verdict.json and reports the verdict to the feed. verdict.txt is left as
    it is, so its first line stays the one merge-review wrote. Refuses (exit
    2) on a run with no merged review or one already marked distrusted, so
    it cannot turn an unmerged or distrusted run into a confirmed one.
    Exits 0 when the confirmation was recorded, whatever the verdict."""
    verdict_json_path = os.path.join(run_dir, "verdict.json")
    try:
        with open(verdict_json_path, encoding="utf-8") as f:
            verdict = json.load(f)
    except (OSError, ValueError):
        fail("verdict.json missing or unreadable: nothing to confirm")
    if not isinstance(verdict, dict) or verdict.get("review_merged") is not True:
        fail("verdict.json carries no merged review: nothing to confirm")
    if verdict.get("review_distrusted") or os.path.exists(
            os.path.join(run_dir, DISTRUST_MARKER)):
        fail("this run is marked distrusted: it cannot be confirmed")
    if not read_first_line(run_dir).startswith(PIPELINE_PREFIX):
        fail("verdict.txt does not carry a PIPELINE verdict")
    verdict["review_confirmed"] = True
    with open(verdict_json_path, "w", encoding="utf-8") as f:
        json.dump(verdict, f, indent=2, ensure_ascii=False)
    write_manifest(run_dir)
    report_verdict_to_feed(run_dir, feed_path or default_feed_path(run_dir))
    print("review confirmed: " + read_first_line(run_dir))
    return 0


def command_distrust_review(run_dir, reason, floor=None, feed_path=None):
    """Called by the review workflow when it could NOT confirm that its merge
    landed as built (the read-back found other rows, or the merge step failed
    half-way): the REV rows in the table, and even a READY TO PUBLISH in
    verdict.txt, may come from a confused or manipulated agent. Writes a
    marker that adds a NOT POSSIBLE row to every later render, then
    re-renders. Veto-only, like merge-review: the result is never better
    than any verdict this run already carried, nor than `floor` (1 when the
    review itself found a blocking bug). Reports the new verdict to the
    feed: INCONCLUSIVE, or DO NOT PUBLISH when the floor is 1, never READY
    (the NOT POSSIBLE row rules it out)."""
    verdict_json_path = os.path.join(run_dir, "verdict.json")
    try:
        with open(verdict_json_path, encoding="utf-8", errors="replace") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        fail("verdict.json missing or unreadable: nothing to mark")
    with open(os.path.join(run_dir, DISTRUST_MARKER), "w",
              encoding="utf-8") as f:
        f.write(" ".join(str(reason).split()) + "\n")
    rows, _corrupted = read_areas(os.path.join(run_dir, "areas.tsv"))
    rows = sort_rows(add_review_trust_row(add_coverage_floor(rows), run_dir))
    _verdict, derived_exit, summary = derive(rows)
    badness = {0: 0, 2: 1, 1: 2}
    candidates = [derived_exit]
    if floor in (1, 2):
        candidates.append(floor)
    for key in ("mechanical_exit_code", "pipeline_exit_code", "exit_code"):
        if previous.get(key) in (0, 1, 2):
            candidates.append(previous[key])
    combined_exit = max(candidates, key=lambda c: badness[c])
    pipeline_words = {0: "READY TO PUBLISH", 2: "INCONCLUSIVE",
                      1: "DO NOT PUBLISH"}
    mechanical_exit = previous.get("mechanical_exit_code",
                                   previous.get("exit_code"))
    emit(run_dir, "PIPELINE", pipeline_words[combined_exit], combined_exit,
         combined_exit, summary, rows, read_meta(run_dir),
         read_notes(run_dir),
         # a distrusted run that was merged with weaker models keeps the stamp
         settings_note(previous.get("models")),
         {"mechanical_exit_code": mechanical_exit,
          "pipeline_exit_code": combined_exit,
          "models": previous.get("models"),
          "review_merged": False, "review_confirmed": False,
          "review_distrusted": True})
    report_verdict_to_feed(run_dir, feed_path or default_feed_path(run_dir))
    return combined_exit


def command_review_state(run_dir):
    """Prints, as one JSON object, what the review workflow needs to check
    that its merge happened: review-rows.json and what verdict.json now says
    (verdict, exit code, the "Diff review" rows). The workflow cannot read
    files, so an agent other than the merge agent runs this and returns the
    output verbatim for the workflow's code to compare. Read-only; always
    exits 0, with missing files as null."""
    state = {"rows_file": None, "verdict": None, "exit_code": None,
             "review_merged": None, "review_confirmed": None,
             "first_line": None, "review_areas": []}
    try:
        with open(os.path.join(run_dir, "review-rows.json"),
                  encoding="utf-8") as f:
            state["rows_file"] = json.load(f)
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(run_dir, "verdict.json"),
                  encoding="utf-8") as f:
            verdict = json.load(f)
        state["verdict"] = verdict.get("verdict")
        state["exit_code"] = verdict.get("exit_code")
        state["review_merged"] = verdict.get("review_merged", False)
        state["review_confirmed"] = verdict.get("review_confirmed", False)
        for area in verdict.get("areas", []):
            if area.get("area", "").startswith(REVIEW_PREFIX):
                state["review_areas"].append({
                    "area": area.get("area"), "status": area.get("status"),
                    "outcome": area.get("outcome"),
                    "blocking": area.get("blocking")})
    except (OSError, ValueError):
        pass
    try:
        with open(os.path.join(run_dir, "verdict.txt"),
                  encoding="utf-8", errors="replace") as f:
            state["first_line"] = f.readline().strip()
    except OSError:
        pass
    print(json.dumps(state, ensure_ascii=False))
    return 0


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "distrust-review":
        floor = None
        if len(sys.argv) >= 5 and sys.argv[4] in ("1", "2"):
            floor = int(sys.argv[4])
        feed_path = sys.argv[5] if len(sys.argv) >= 6 else None
        sys.exit(command_distrust_review(sys.argv[2], sys.argv[3], floor,
                                         feed_path))
    if len(sys.argv) >= 3 and sys.argv[1] == "confirm-review":
        feed_path = sys.argv[3] if len(sys.argv) >= 4 else None
        sys.exit(command_confirm_review(sys.argv[2], feed_path))
    if len(sys.argv) >= 3 and sys.argv[1] == "review-state":
        sys.exit(command_review_state(sys.argv[2]))
    if len(sys.argv) >= 3 and sys.argv[1] == "render":
        sys.exit(command_render(sys.argv[2]))
    if len(sys.argv) >= 4 and sys.argv[1] == "merge-review":
        sys.exit(command_merge_review(sys.argv[2], sys.argv[3]))
    print("usage: verdict.py render <run-dir> | "
          "merge-review <run-dir> <rows.json> | review-state <run-dir> | "
          "confirm-review <run-dir> [feed] | "
          "distrust-review <run-dir> <reason> [floor] [feed]",
          file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as unexpected:
        # never 0 (a crash is not a pass) and never 1 (it is not a finding
        # either): 2, the same convention delta.py uses
        fail("unexpected error: %r" % unexpected)
