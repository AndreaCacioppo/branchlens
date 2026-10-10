"""Tests for checks/review/review-diff.js without any LLM.

tests/workflow_harness.mjs runs the workflow script under Node with fake
agents. The mechanical ones (scope loader, merge, read-back, confirm,
distrust) read the run
directory and run verdict.py and feed.py through /bin/sh; the reviewers,
deep dives and verifiers return scripted findings. Each test starts from a
real gate run on a throwaway repository.

Needs `node` and `semgrep`; skipped when either is missing.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

from helpers import TOOLKIT_DIR, make_repo, run_gate, write

HARNESS = os.path.join(TOOLKIT_DIR, "tests", "workflow_harness.mjs")

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None or shutil.which("semgrep") is None,
    reason="node and semgrep are needed")

WEB_PY = '''from notes import store


def export_note(conn, request):
    note = store.export_note(conn, int(request["params"]["id"]))
    return 200, note
'''


GO_MAIN = "package main\n\nfunc main() {}\n"


def feature_change(repo):
    write(repo, "notes/web.py", WEB_PY)
    write(repo, "notes/café.py", "VALUE = 1\n")
    # configuration with no rule and no deep-dive skill: only the reviewers
    # can vouch for it
    write(repo, "config/app.yaml", "debug: false\n")
    # a file name that is a shell command: it must never run
    write(repo, "$(touch pwned-by-path).sh", "echo hello\n")
    # code with no Semgrep rule: Go has no deep dive either, Perl has one
    write(repo, "cmd/main.go", GO_MAIN)
    write(repo, "scripts/report.pl", 'print "ok\\n";\n')


@pytest.fixture(scope="module")
def gate_run():
    repo = make_repo({"notes/__init__.py": ""}, feature_change)
    code, _rows, run_dir = run_gate(repo)
    assert code == 0, "the fixture change should pass the mechanical gate"
    return repo, run_dir


def run_workflow(gate_run, scenario, extra_arguments=None):
    """Copies the run directory (each scenario merges into its own), runs
    the harness in a scratch working directory, returns its JSON output.
    extra_arguments are added to the workflow's arguments."""
    repo, run_dir = gate_run
    reports = tempfile.mkdtemp(prefix="workflow-test-")
    own_run_dir = os.path.join(reports, "run")
    shutil.copytree(run_dir, own_run_dir)
    scratch = tempfile.mkdtemp(prefix="workflow-cwd-")
    arguments = {
        "repo": repo,
        "toolkit": TOOLKIT_DIR,
        "reportDir": own_run_dir,
        "feed": os.path.join(reports, "security-feed.jsonl"),
        "pwnedPath": os.path.join(scratch, "pwned-by-title"),
    }
    arguments.update(extra_arguments or {})
    result = subprocess.run(["node", HARNESS, scenario, json.dumps(arguments)],
                            capture_output=True, text=True, cwd=scratch)
    assert result.returncode == 0, result.stderr
    output = json.loads(result.stdout)
    output["scratch"] = scratch
    output["feed"] = arguments["feed"]
    output["run_dir"] = own_run_dir
    return output


def test_clean_review_merges_ready_to_publish(gate_run):
    output = run_workflow(gate_run, "clean")
    result = output["result"]
    assert result["verdict"] == "NO BLOCKING FINDINGS"
    assert result["merged"] is True, result.get("merge_problems")
    assert result["combined_exit"] == 0
    assert result["pipeline_bottom_line"].startswith(
        "PIPELINE: READY TO PUBLISH")
    # every file was opened by a reviewer: no coverage agent needed
    assert not any(call.startswith("coverage") for call in output["calls"])
    # the Go file and the YAML configuration had no scanner rule and no deep
    # dive; the Perl file had its deep dive
    assert result["pipeline_bottom_line"].endswith(
        " · CAVEAT: reviewed by the checklist only, no scanner rule and no "
        "deep dive: cmd/main.go (Go), config/app.yaml (YAML config)")


def test_code_whose_only_deep_dive_failed_is_named(gate_run):
    output = run_workflow(gate_run, "perl-dive-dies")
    result = output["result"]
    # a failed dive alone does not change the verdict
    assert result["combined_exit"] == 0, result.get("merge_problems")
    assert result["pipeline_bottom_line"].endswith(
        "no scanner rule and no deep dive: cmd/main.go (Go), "
        "config/app.yaml (YAML config), scripts/report.pl (Perl)")
    verdict = read_json(output["run_dir"], "verdict.json")
    assert [entry["path"] for entry in verdict["checklist_only_code"]] \
        == ["cmd/main.go", "config/app.yaml", "scripts/report.pl"]
    assert verdict["unread_code"] == []


def test_code_no_reviewer_reported_reading_is_not_called_reviewed(gate_run):
    # no reviewer lists cmd/main.go, and the coverage agent judges that no
    # real gap: the review stays green, but the caveat must not claim that
    # the checklist reviewers read the file
    output = run_workflow(gate_run, "unread-go-file")
    result = output["result"]
    assert any(call.startswith("coverage") for call in output["calls"])
    assert result["combined_exit"] == 0, result.get("merge_problems")
    assert result["pipeline_bottom_line"].endswith(
        "reviewed by the checklist only, no scanner rule and no deep dive: "
        "config/app.yaml (YAML config); not reported read by any reviewer, "
        "no scanner rule and no deep dive: cmd/main.go (Go)")
    verdict = read_json(output["run_dir"], "verdict.json")
    assert [entry["path"] for entry in verdict["checklist_only_code"]] \
        == ["config/app.yaml"]
    assert [entry["path"] for entry in verdict["unread_code"]] \
        == ["cmd/main.go"]
    # the reviewers' "./notes/web.py" reaches the rows file as notes/web.py
    rows_file = read_json(output["run_dir"], "review-rows.json")
    assert "notes/web.py" in rows_file["examined_files"]
    assert "cmd/main.go" not in rows_file["examined_files"]


@pytest.mark.parametrize("scenario", ["no-deep-dived", "no-examined-files"])
def test_a_workflow_that_does_not_report_what_was_read_cannot_merge(
        gate_run, scenario):
    output = run_workflow(gate_run, scenario)
    assert output["result"]["merged"] is False
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        assert not f.readline().startswith("PIPELINE: READY")


def test_blocking_finding_vetoes(gate_run):
    result = run_workflow(gate_run, "blocking")["result"]
    assert result["verdict"] == "DO NOT PUBLISH"
    assert result["merged"] is True, result.get("merge_problems")
    assert result["combined_exit"] == 1


def test_a_verification_reports_its_outcome_to_the_feed(gate_run):
    output = run_workflow(gate_run, "blocking")
    with open(output["feed"], encoding="utf-8") as f:
        events = [json.loads(line) for line in f]
    verify_events = [event for event in events
                     if event.get("event") == "check"
                     and event.get("stage") == "verify"]
    assert [event["status"] for event in verify_events] == ["running", "done"]
    assert verify_events[1]["result"] == "CONFIRMED"


def test_a_merge_step_that_writes_clean_rows_is_not_trusted(gate_run):
    # the review found a blocking bug; the merge step writes all-clean rows
    result = run_workflow(gate_run, "lying-merge")["result"]
    assert result["verdict"] == "DO NOT PUBLISH"
    assert result["merged"] is False
    assert result["combined_exit"] is None


@pytest.mark.parametrize("scenario", ["loader-drops-file",
                                      "loader-marks-deleted",
                                      "loader-empties-dives",
                                      "loader-drops-a-code-file"])
def test_a_scope_changed_by_the_loader_refuses_the_merge(gate_run, scenario):
    output = run_workflow(gate_run, scenario)
    assert output["result"]["merged"] is False
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        assert not f.readline().startswith("PIPELINE: READY")


def test_a_verification_that_crashes_keeps_the_finding(gate_run):
    result = run_workflow(gate_run, "verifier-throws")["result"]
    # unverified and high: it still blocks
    assert result["verdict"] == "DO NOT PUBLISH"


def test_a_silent_reviewer_is_retried_then_named(gate_run):
    output = run_workflow(gate_run, "reviewer-dies")
    result = output["result"]
    assert "rev:REV-02 [opus]" in output["calls"]
    assert "rev:REV-02 (sonnet) [sonnet]" in output["calls"]
    assert result["verdict"] == "INCONCLUSIVE"
    assert "REV-02" in result["reason"]
    assert result["merged"] is True, result.get("merge_problems")
    assert result["combined_exit"] == 2


def read_json(run_dir, name):
    with open(os.path.join(run_dir, name), encoding="utf-8") as f:
        return json.load(f)


def test_a_blocking_and_incomplete_review_names_what_was_not_covered(
        gate_run):
    # REV-03 finds a blocking bug, the REV-02 reviewer never answers and the
    # deep dive of notes/web.py fails
    output = run_workflow(gate_run, "blocking-and-incomplete")
    result = output["result"]
    assert result["verdict"] == "DO NOT PUBLISH"
    assert result["merged"] is True, result.get("merge_problems")
    assert result["combined_exit"] == 1
    rows_file = read_json(output["run_dir"], "review-rows.json")
    incomplete = rows_file["incomplete_reason"]
    assert "no reviewer answered for REV-02" in incomplete
    assert "deep dive failed (no model answered) for notes/web.py" \
        in incomplete
    assert "blocking" not in incomplete
    areas = {area["area"]: area
             for area in read_json(output["run_dir"], "verdict.json")["areas"]}
    coverage = areas["Diff review coverage"]
    assert coverage["status"] == "NOT POSSIBLE"
    assert coverage["reason"] == incomplete


def test_a_failed_deep_dive_alone_does_not_make_the_review_incomplete(
        gate_run):
    output = run_workflow(gate_run, "dive-dies")
    result = output["result"]
    assert result["verdict"] == "NO BLOCKING FINDINGS"
    assert result["deep_dives"]["failed"] == ["notes/web.py"]
    assert "incomplete_reason" not in read_json(output["run_dir"],
                                                "review-rows.json")


def test_a_file_no_reviewer_opened_goes_to_the_coverage_agent(gate_run):
    output = run_workflow(gate_run, "unexamined-file")
    result = output["result"]
    assert any(call.startswith("coverage") for call in output["calls"])
    assert result["verdict"] == "INCONCLUSIVE"
    assert result["merged"] is True, result.get("merge_problems")


def test_the_same_bug_from_two_finders_is_verified_once(gate_run):
    output = run_workflow(gate_run, "shared-verification")
    result = output["result"]
    verifications = [call for call in output["calls"]
                     if call.startswith("ver:")]
    assert len(verifications) == 1
    assert len(result["blocking"]) == 1
    assert len(result["blocking"][0]["corroborations"]) == 1


def test_hostile_text_never_reaches_a_shell(gate_run):
    output = run_workflow(gate_run, "hostile-title")
    scratch = output["scratch"]
    assert not os.path.exists(os.path.join(scratch, "pwned-by-title"))
    assert not os.path.exists(os.path.join(scratch, "pwned-by-path"))
    with open(output["feed"], encoding="utf-8") as f:
        events = [json.loads(line) for line in f]
    titles = [event.get("title", "") for event in events
              if event.get("event") == "finding"]
    assert any("$(touch" in title for title in titles)
    paths = [event.get("path", "") for event in events
             if event.get("event") == "file"]
    assert "$(touch pwned-by-path).sh" in paths


def test_a_blocking_report_is_never_demoted_behind_a_weaker_one(gate_run):
    # same line: the reviewer's report is PLAUSIBLE/high (blocks), the
    # dive's is CONFIRMED/low (does not); the veto must survive grouping
    result = run_workflow(gate_run, "corroboration-veto")["result"]
    assert result["verdict"] == "DO NOT PUBLISH"
    assert len(result["blocking"]) == 1
    assert result["blocking"][0]["outcome"] == "PLAUSIBLE"


def test_an_unverified_medium_finding_is_not_a_green(gate_run):
    result = run_workflow(gate_run, "unverified-medium")["result"]
    assert result["verdict"] == "INCONCLUSIVE"
    assert "never verified" in result["reason"]
    assert result["combined_exit"] == 2


def feed_events(output):
    if not os.path.exists(output["feed"]):
        return []
    with open(output["feed"], encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def verdict_words(events):
    """The verdict words a viewer sees: from 'verdict' events and from the
    'verdict' phase, in order."""
    words = []
    for event in events:
        if event.get("event") == "verdict":
            words.append(event.get("verdict"))
        elif event.get("event") == "phase" and event.get("name") == "verdict":
            words.append(event.get("detail"))
    return words


def fake_session(run_dir):
    """The review-session.json a `claude -p` session that ended normally
    leaves behind."""
    with open(os.path.join(run_dir, "review-session.json"), "w") as f:
        f.write(json.dumps({"type": "result", "subtype": "success",
                            "is_error": False, "result": "DONE"}) + "\n")


def load_pipeline():
    """checks/pipeline.py as a module, for its decision function."""
    # it imports feed.py: keep their bytecode out of checks/
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.join(TOOLKIT_DIR, "checks"))
    import pipeline
    return pipeline


def test_a_merge_the_read_back_matched_is_confirmed(gate_run):
    output = run_workflow(gate_run, "clean")
    assert output["result"]["confirmed"] is True
    verdict = read_json(output["run_dir"], "verdict.json")
    assert verdict["review_merged"] is True
    assert verdict["review_confirmed"] is True
    # the verdict reaches the feed once, from the confirm step
    assert verdict_words(feed_events(output)) == ["READY TO PUBLISH",
                                                  "READY TO PUBLISH"]
    fake_session(output["run_dir"])
    line, code, problem = load_pipeline().review_decision(
        output["run_dir"], 0)
    assert problem is None
    assert code == 0
    assert line.startswith("PIPELINE: READY TO PUBLISH")


def test_a_missing_read_back_leaves_the_review_unconfirmed(gate_run):
    output = run_workflow(gate_run, "readback-null")
    result = output["result"]
    assert result["merged"] is False
    assert result["confirmed"] is False
    assert result["distrust_recorded"] is True
    assert not any(call.startswith("confirm") for call in output["calls"])
    verdict = read_json(output["run_dir"], "verdict.json")
    assert verdict["review_confirmed"] is False
    assert verdict["verdict"] == "INCONCLUSIVE"
    assert verdict_words(feed_events(output)) == ["INCONCLUSIVE",
                                                  "INCONCLUSIVE"]
    fake_session(output["run_dir"])
    _line, code, _problem = load_pipeline().review_decision(
        output["run_dir"], 0)
    assert code == 2


def test_a_run_killed_before_the_confirm_step_is_not_ready(gate_run):
    output = run_workflow(gate_run, "killed-before-confirm")
    assert output["killed"] is True
    verdict = read_json(output["run_dir"], "verdict.json")
    # merge-review ran and wrote its rows and a READY line...
    assert verdict["review_merged"] is True
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        assert f.readline().startswith("PIPELINE: READY TO PUBLISH")
    # ...but nothing confirmed it, and the feed carries no verdict
    assert verdict["review_confirmed"] is False
    assert verdict_words(feed_events(output)) == []
    # even a session that claims it finished cannot turn this into READY
    fake_session(output["run_dir"])
    line, code, _problem = load_pipeline().review_decision(
        output["run_dir"], 0)
    assert code == 2
    assert line == ("PIPELINE: INCONCLUSIVE — review not confirmed "
                    "(the read-back did not confirm the merge)")


def test_confirm_review_refuses_a_run_without_a_merged_review(gate_run):
    _repo, run_dir = gate_run
    own_run_dir = os.path.join(tempfile.mkdtemp(prefix="confirm-test-"),
                               "run")
    shutil.copytree(run_dir, own_run_dir)
    result = subprocess.run(
        ["python3", os.path.join(TOOLKIT_DIR, "checks", "verdict.py"),
         "confirm-review", own_run_dir], capture_output=True, text=True)
    assert result.returncode == 2
    assert "no merged review" in result.stderr
    assert "review_confirmed" not in read_json(own_run_dir, "verdict.json")


def test_a_confirm_step_that_fails_marks_the_run_distrusted(gate_run):
    output = run_workflow(gate_run, "confirm-fails")
    result = output["result"]
    assert result["merged"] is False
    assert result["confirmed"] is False
    assert result["distrust_recorded"] is True
    assert "the confirm step did not record the confirmation" \
        in result["merge_problems"]
    verdict = read_json(output["run_dir"], "verdict.json")
    assert verdict["review_confirmed"] is False
    assert verdict["review_distrusted"] is True
    assert verdict["verdict"] == "INCONCLUSIVE"


def run_pipeline_main(monkeypatch, output, session_lines):
    """Runs pipeline.main on a run directory the harness already filled, with
    the gate and the `claude -p` session replaced: the session leaves
    session_lines in review-session.json and exits 0."""
    pipeline = load_pipeline()

    def fake_gate(repo, base):
        return 0, output["run_dir"], output["feed"]

    def fake_review(repo, run_dir, feed_path, models):
        with open(os.path.join(run_dir, "review-session.json"), "w") as f:
            for line in session_lines:
                f.write((json.dumps(line) if isinstance(line, dict) else line)
                        + "\n")
        return 0, False

    monkeypatch.setattr(pipeline, "run_gate", fake_gate)
    monkeypatch.setattr(pipeline, "run_review", fake_review)
    for _key, variable in pipeline.MODEL_VARIABLES:
        monkeypatch.delenv(variable, raising=False)
    return pipeline.main([output["run_dir"]])


KILLED_SESSION = ["Background tasks still running after 600s; terminating.",
                  {"type": "result", "subtype": "success", "is_error": False,
                   "result": "Workflow is still running."}]


def test_the_pipeline_records_its_override_on_disk_and_in_the_feed(
        gate_run, monkeypatch):
    # the workflow confirmed READY, then the CLI killed the session
    output = run_workflow(gate_run, "clean")
    assert read_json(output["run_dir"], "verdict.json")["review_confirmed"]
    assert run_pipeline_main(monkeypatch, output, KILLED_SESSION) == 2
    verdict = read_json(output["run_dir"], "verdict.json")
    assert verdict["review_confirmed"] is False
    assert verdict["review_distrusted"] is True
    assert verdict["verdict"] == "INCONCLUSIVE"
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        assert f.readline().startswith("PIPELINE: INCONCLUSIVE")
    events = feed_events(output)
    # the pipeline's word comes last, after the workflow's READY
    assert verdict_words(events)[-2:] == ["INCONCLUSIVE", "INCONCLUSIVE"]
    review_events = [event for event in events
                     if event.get("event") == "phase"
                     and event.get("name") == "review"]
    assert review_events[-1]["status"] == "failed"
    assert review_events[-1]["detail"].endswith(
        " · models mechanical=sonnet analysis=opus verify_high=fable")


def test_an_unconfirmed_veto_stays_a_veto(gate_run, monkeypatch):
    # the workflow confirmed DO NOT PUBLISH, then the CLI killed the session
    output = run_workflow(gate_run, "blocking")
    assert run_pipeline_main(monkeypatch, output, KILLED_SESSION) == 1
    verdict = read_json(output["run_dir"], "verdict.json")
    assert verdict["review_distrusted"] is True
    assert verdict["verdict"] == "DO NOT PUBLISH"
    assert verdict_words(feed_events(output))[-2:] == ["DO NOT PUBLISH",
                                                       "DO NOT PUBLISH"]


def test_a_dead_code_row_cannot_claim_files_the_gate_did_not_list(
        docs_gate_run):
    # the gate listed no code file: a TESTED dead-code row is refused
    output = run_workflow(docs_gate_run, "clean")
    rows_file = read_json(output["run_dir"], "review-rows.json")
    for row in rows_file["rows"]:
        if row["area"].startswith("Diff review REV-11"):
            row["status"] = "TESTED"
            row["outcome"] = "CLEAN"
    rows_path = os.path.join(output["scratch"], "forged-rows.json")
    with open(rows_path, "w", encoding="utf-8") as f:
        json.dump(rows_file, f)
    result = subprocess.run(
        ["python3", os.path.join(TOOLKIT_DIR, "checks", "verdict.py"),
         "merge-review", output["run_dir"], rows_path],
        capture_output=True, text=True)
    assert result.returncode == 2
    assert "REV-11 is TESTED but the gate listed no changed code file" \
        in result.stderr


def test_an_unverified_merge_is_marked_on_disk(gate_run):
    output = run_workflow(gate_run, "lying-merge")
    assert output["result"]["distrust_recorded"] is True
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        first_line = f.readline()
    # the review found a blocking bug: the veto survives the distrust
    assert first_line.startswith("PIPELINE: DO NOT PUBLISH")
    assert read_json(output["run_dir"], "verdict.json")[
        "review_confirmed"] is False
    # the feed shows the distrusted verdict, never a READY
    assert verdict_words(feed_events(output)) == ["DO NOT PUBLISH",
                                                  "DO NOT PUBLISH"]


WEAKER_MODELS = {"mechanical": "opus", "analysis": "sonnet",
                 "verify_high": "opus"}
WEAKER_STAMP = (" · SETTINGS: models mechanical=opus analysis=sonnet "
                "verify_high=opus")


def test_default_models_leave_no_settings_stamp(gate_run):
    output = run_workflow(gate_run, "blocking")
    assert "SETTINGS" not in output["result"]["pipeline_bottom_line"]
    assert read_json(output["run_dir"], "verdict.json")["models"] == {
        "mechanical": "sonnet", "analysis": "opus", "verify_high": "fable"}
    # the high-severity finding went to the verify_high model
    assert "ver:REV-03 [fable]" in output["calls"]


def test_the_workflow_runs_each_stage_on_the_models_it_is_given(gate_run):
    output = run_workflow(gate_run, "blocking", {"models": WEAKER_MODELS})
    result = output["result"]
    assert result["merged"] is True, result.get("merge_problems")
    calls = output["calls"]
    assert "scope [opus]" in calls
    assert "merge [opus]" in calls
    assert "rev:REV-03 [sonnet]" in calls
    assert "ver:REV-03 [opus]" in calls
    assert not any("fable" in call for call in calls)
    # the effective models are on record, and stamped on the bottom line
    assert read_json(output["run_dir"], "verdict.json")["models"] \
        == WEAKER_MODELS
    assert result["pipeline_bottom_line"].startswith(
        "PIPELINE: DO NOT PUBLISH")
    assert result["pipeline_bottom_line"].endswith(WEAKER_STAMP)
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        assert f.readline().rstrip("\n").endswith(WEAKER_STAMP)
    # each verification names its model, in the feed and in the rows file
    verify_events = [event for event in feed_events(output)
                     if event.get("event") == "check"
                     and event.get("stage") == "verify"]
    assert [event["model"] for event in verify_events] == ["opus", "opus"]
    verifications = read_json(output["run_dir"],
                              "review-rows.json")["verifications"]
    assert [(v["entry"], v["file"], v["line"], v["outcome"], v["model"])
            for v in verifications] \
        == [("REV-03", "notes/web.py", 16, "CONFIRMED", "opus")]


def test_a_weaker_ready_carries_the_settings_stamp(gate_run):
    output = run_workflow(gate_run, "clean", {"models": WEAKER_MODELS})
    line = output["result"]["pipeline_bottom_line"]
    assert line.startswith("PIPELINE: READY TO PUBLISH")
    assert line.endswith(WEAKER_STAMP)


def test_only_a_weaker_model_is_stamped(gate_run):
    # mechanical=opus is stronger than its default: no stamp
    output = run_workflow(gate_run, "clean",
                          {"models": {"mechanical": "opus"}})
    line = output["result"]["pipeline_bottom_line"]
    assert line.startswith("PIPELINE: READY TO PUBLISH")
    assert "SETTINGS" not in line
    assert "scope [opus]" in output["calls"]


def test_a_distrusted_weaker_run_keeps_the_stamp(gate_run):
    output = run_workflow(gate_run, "lying-merge", {"models": WEAKER_MODELS})
    assert output["result"]["distrust_recorded"] is True
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        first_line = f.readline().rstrip("\n")
    assert first_line.startswith("PIPELINE: DO NOT PUBLISH")
    assert first_line.endswith(WEAKER_STAMP)


def test_an_unknown_model_stops_the_workflow_before_any_agent(gate_run):
    output = run_workflow(gate_run, "clean",
                          {"models": {"analysis": "gpt-4"}})
    result = output["result"]
    assert result["verdict"] == "INCONCLUSIVE"
    assert "analysis" in result["reason"]
    assert output["calls"] == []


# --- dead and redundant code (REV-11, REV-12) ---------------------------------

def area_rows(run_dir):
    """verdict.json's areas by entry id, for the REV-NN rows."""
    rows = {}
    for area in read_json(run_dir, "verdict.json")["areas"]:
        if area["area"].startswith("Diff review REV-"):
            rows[area["area"].split()[2]] = area
    return rows


def test_the_gate_lists_the_changed_code_files_for_the_review(gate_run):
    _repo, run_dir = gate_run
    code_files = read_json(run_dir, "review-scope.json")["code_files"]
    # README-like files are not code; the YAML configuration is
    assert sorted(code_files) == sorted([
        "notes/web.py", "notes/café.py", "config/app.yaml",
        "$(touch pwned-by-path).sh", "cmd/main.go", "scripts/report.pl"])


def test_the_dead_code_reviewers_run_beside_the_checklist_reviewers(
        gate_run):
    output = run_workflow(gate_run, "clean")
    calls = output["calls"]
    assert "abl:REV-11 [opus]" in calls
    assert "abl:REV-12 [opus]" in calls
    # no rev: reviewer for them, and no verification of a clean run
    assert not any(call.startswith("rev:REV-11") or call.startswith("rev:REV-12")
                   for call in calls)
    rows = area_rows(output["run_dir"])
    assert rows["REV-11"]["status"] == "TESTED"
    assert rows["REV-11"]["scope"] == \
        "6 of 6 changed code files, 3 symbols examined"
    assert rows["REV-11"]["outcome"] == "CLEAN"


def test_a_dead_code_read_is_not_a_security_read(gate_run):
    # no security reviewer lists cmd/main.go; the dead-code reviewers do,
    # and that must not count as the file having been reviewed
    output = run_workflow(gate_run, "unread-go-file")
    rows_file = read_json(output["run_dir"], "review-rows.json")
    assert "cmd/main.go" not in rows_file["examined_files"]
    assert any(call.startswith("coverage") for call in output["calls"])
    assert area_rows(output["run_dir"])["REV-11"]["scope"].startswith(
        "6 of 6 changed code files")


def test_a_low_dead_code_finding_is_advisory(gate_run):
    output = run_workflow(gate_run, "ablation-low")
    result = output["result"]
    assert result["verdict"] == "NO BLOCKING FINDINGS"
    assert result["merged"] is True, result.get("merge_problems")
    assert result["combined_exit"] == 0
    assert result["pipeline_bottom_line"].startswith(
        "PIPELINE: READY TO PUBLISH")
    # never verified
    assert not any(call.startswith("ver:REV-12") for call in output["calls"])
    [warning] = [w for w in result["warnings"] if w["entry"] == "REV-12"]
    assert warning["outcome"] == "ADVISORY"
    assert warning["kind"] == "leftover"
    assert warning["removal"] == "delete line 5"
    # in the feed, as a non-blocking finding
    [event] = [event for event in feed_events(output)
               if event.get("event") == "finding"
               and event.get("entry") == "REV-12"]
    assert event["blocking"] is False
    assert event["severity"] == "low"
    # in the rows file and the verdict notes, in fixed words
    rows_file = read_json(output["run_dir"], "review-rows.json")
    assert ("REV-12", "notes/web.py", 5, "ADVISORY") in [
        (v["entry"], v["file"], v["line"], v["outcome"])
        for v in rows_file["verifications"]]
    with open(os.path.join(output["run_dir"], "verdict.txt")) as f:
        text = f.read()
    assert ("REVIEW: advisory, dead or redundant code (low, not verified, "
            "does not block): REV-12 notes/web.py:5 (leftover)") in text
    row = area_rows(output["run_dir"])["REV-12"]
    assert row["status"] == "TESTED"
    assert row["blocking"] is False
    assert row["outcome"] == "1 finding(s) (non-blocking)"


def test_a_confirmed_high_dead_code_finding_blocks(gate_run):
    output = run_workflow(gate_run, "ablation-high-confirmed")
    result = output["result"]
    assert result["verdict"] == "DO NOT PUBLISH"
    assert result["merged"] is True, result.get("merge_problems")
    assert result["combined_exit"] == 1
    assert "ver:REV-11 [fable]" in output["calls"]
    [finding] = result["blocking"]
    assert finding["entry"] == "REV-11"
    assert finding["symbol"] == "export_note"
    row = area_rows(output["run_dir"])["REV-11"]
    assert row["blocking"] is True
    assert row["outcome"] == "1 blocking finding(s)"


def test_a_refuted_high_dead_code_finding_is_dropped(gate_run):
    output = run_workflow(gate_run, "ablation-high-refuted")
    result = output["result"]
    assert result["verdict"] == "NO BLOCKING FINDINGS"
    assert result["combined_exit"] == 0, result.get("merge_problems")
    assert [f["entry"] for f in result["rejected"]] == ["REV-11"]
    assert result["blocking"] == []
    row = area_rows(output["run_dir"])["REV-11"]
    assert row["outcome"] == "CLEAN"
    assert row["blocking"] is False


def test_dead_code_is_verified_after_every_security_finding(gate_run):
    # the harness makes the REV-03 reviewer answer last
    output = run_workflow(gate_run, "ablation-high-after-security")
    calls = output["calls"]
    assert calls.index("ver:REV-03 [fable]") < calls.index("ver:REV-11 [fable]")
    # the two findings sit near each other in notes/web.py but are never
    # grouped: each keeps its own row
    assert sorted(f["entry"] for f in output["result"]["blocking"]) \
        == ["REV-03", "REV-11"]
    rows = area_rows(output["run_dir"])
    assert rows["REV-03"]["blocking"] is True
    assert rows["REV-11"]["blocking"] is True


def test_a_dead_code_reviewer_that_hits_the_bound_is_partial(gate_run):
    output = run_workflow(gate_run, "ablation-partial")
    row = area_rows(output["run_dir"])["REV-11"]
    assert row["status"] == "PARTIAL"
    assert row["reason"] == "stopped at the bound of 40 symbols"
    assert row["outcome"] == "no findings in the part examined"
    # best effort: the verdict stays green and says so
    line = output["result"]["pipeline_bottom_line"]
    assert line.startswith("PIPELINE: READY TO PUBLISH")
    assert "Diff review REV-11" in line


def test_a_dead_code_reviewer_that_fails_is_not_possible(gate_run):
    output = run_workflow(gate_run, "ablation-dies")
    calls = output["calls"]
    assert "abl:REV-11 (sonnet) [sonnet]" in calls
    row = area_rows(output["run_dir"])["REV-11"]
    assert row["status"] == "NOT POSSIBLE"
    assert row["reason"] == "the reviewer for this entry did not answer"
    result = output["result"]
    assert result["dead_code"]["failed"] == ["REV-11"]
    # best effort, unlike a security reviewer that fails
    assert result["verdict"] == "NO BLOCKING FINDINGS"
    assert result["combined_exit"] == 0, result.get("merge_problems")
    assert "Diff review REV-11" in result["pipeline_bottom_line"]


def test_dead_code_never_takes_a_verification_from_a_security_finding(
        gate_run):
    # 20 security findings use up the ceiling of 20 verifications; the
    # dead-code finding comes after them and stays unverified
    output = run_workflow(gate_run, "ablation-after-ceiling")
    calls = output["calls"]
    assert len([call for call in calls if call.startswith("ver:REV-03")]) == 20
    assert not any(call.startswith("ver:REV-11") for call in calls)
    result = output["result"]
    assert len(result["rejected"]) == 20
    # unverified: it does not block, and the review is incomplete
    assert result["blocking"] == []
    [warning] = [w for w in result["warnings"] if w["entry"] == "REV-11"]
    assert warning["severity"] == "high"
    assert result["verdict"] == "INCONCLUSIVE"
    assert "never verified" in result["reason"]
    assert result["combined_exit"] == 2, result.get("merge_problems")


def test_a_dead_code_finding_the_verifier_is_unsure_of_is_rejected(gate_run):
    output = run_workflow(gate_run, "ablation-high-plausible")
    result = output["result"]
    assert "ver:REV-11 [fable]" in output["calls"]
    assert result["blocking"] == []
    assert [(f["entry"], f["outcome"]) for f in result["rejected"]] \
        == [("REV-11", "PLAUSIBLE")]
    assert result["verdict"] == "NO BLOCKING FINDINGS"
    assert result["combined_exit"] == 0, result.get("merge_problems")


def test_a_scope_without_code_files_stops_the_review(gate_run):
    # the loader lost the list: the workflow and the toolkit are out of step
    output = run_workflow(gate_run, "loader-drops-code-files")
    result = output["result"]
    assert result["verdict"] == "INCONCLUSIVE"
    assert "code_files" in result["reason"]
    assert result["merged"] is False
    assert output["calls"] == ["scope [sonnet]"]


def test_the_dead_code_entries_keep_their_numbers():
    # the workflow and verdict.py pick REV-11 and REV-12 by id alone
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.join(TOOLKIT_DIR, "checks"))
    import review_scope
    entries = review_scope.parse_checklist(
        os.path.join(TOOLKIT_DIR, "checks", "review", "checklist.md"))
    titles = {entry["id"]: entry["title"] for entry in entries}
    assert titles["REV-11"].startswith("Dead")
    assert titles["REV-12"].startswith("Redundant")


def docs_change(repo):
    write(repo, "docs/guide.md", "# Guide\n\nHow to use it.\n")


@pytest.fixture(scope="module")
def docs_gate_run():
    repo = make_repo({"notes/__init__.py": ""}, docs_change)
    code, _rows, run_dir = run_gate(repo)
    assert code == 0, "a documentation change should pass the gate"
    return repo, run_dir


def test_a_documentation_only_diff_has_no_dead_code_rows_to_fill(
        docs_gate_run):
    _repo, run_dir = docs_gate_run
    assert read_json(run_dir, "review-scope.json")["code_files"] == []
    output = run_workflow(docs_gate_run, "clean")
    # no agent is sent to read code that is not there
    assert not any(call.startswith("abl:") for call in output["calls"])
    rows = area_rows(output["run_dir"])
    for entry_id in ("REV-11", "REV-12"):
        assert rows[entry_id]["status"] == "NOT POSSIBLE"
        assert rows[entry_id]["reason"] == \
            "no changed code file in the scope: nothing to examine"
        assert rows[entry_id]["outcome"] != "CLEAN"
    result = output["result"]
    assert result["merged"] is True, result.get("merge_problems")
    # best effort: still green, with both rows named in the caveat
    line = result["pipeline_bottom_line"]
    assert line.startswith("PIPELINE: READY TO PUBLISH")
    assert "Diff review REV-11" in line and "Diff review REV-12" in line
