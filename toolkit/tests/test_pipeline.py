"""Tests for the decision checks/pipeline.py takes after the LLM review,
on fake run folders. No gate run, no claude, no node.

READY TO PUBLISH stands only when verdict.json says the review was merged
AND confirmed by the workflow's read-back, and the `claude -p` session ended
normally with a reply starting with DONE. Everything else is INCONCLUSIVE
with exit 2, except a DO NOT PUBLISH in verdict.json, which stands.
"""

import json
import os
import sys
import tempfile

from helpers import TOOLKIT_DIR

# pipeline.py imports feed.py: keep their bytecode out of checks/
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(TOOLKIT_DIR, "checks"))
import pipeline  # noqa: E402

READY_LINE = "PIPELINE: READY TO PUBLISH — no blocking findings"
VETO_LINE = "PIPELINE: DO NOT PUBLISH — 1 blocking finding"
DONE_SESSION = {"type": "result", "subtype": "success", "is_error": False,
                "result": "DONE"}


def fake_run(first_line=READY_LINE, exit_code=0, merged=True,
             confirmed=True, session_lines=None, extra=None):
    """A run folder holding verdict.txt, verdict.json and
    review-session.json. session_lines: the lines of review-session.json,
    each a dict (written as JSON) or a plain string."""
    run_dir = tempfile.mkdtemp(prefix="pipeline-test-")
    words = {0: "READY TO PUBLISH", 1: "DO NOT PUBLISH", 2: "INCONCLUSIVE"}
    verdict = {"verdict": words.get(exit_code), "exit_code": exit_code,
               "review_merged": merged, "review_confirmed": confirmed}
    verdict.update(extra or {})
    with open(os.path.join(run_dir, "verdict.json"), "w") as f:
        json.dump(verdict, f)
    with open(os.path.join(run_dir, "verdict.txt"), "w") as f:
        f.write(first_line + "\n\nthe table\n")
    if session_lines is None:
        session_lines = [DONE_SESSION]
    with open(os.path.join(run_dir, "review-session.json"), "w") as f:
        for line in session_lines:
            f.write((json.dumps(line) if isinstance(line, dict) else line)
                    + "\n")
    return run_dir


def test_a_confirmed_ready_is_ready():
    line, code, problem = pipeline.review_decision(fake_run(), 0)
    assert (line, code, problem) == (READY_LINE, 0, None)


def test_a_confirmed_veto_is_a_veto():
    run_dir = fake_run(first_line=VETO_LINE, exit_code=1)
    line, code, problem = pipeline.review_decision(run_dir, 0)
    assert (line, code, problem) == (VETO_LINE, 1, None)


def test_a_merge_the_read_back_never_confirmed_is_inconclusive():
    # the workflow was killed after merge-review, before confirm-review
    run_dir = fake_run(confirmed=False)
    line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert line == ("PIPELINE: INCONCLUSIVE — review not confirmed "
                    "(the read-back did not confirm the merge)")


def test_a_verdict_json_without_the_field_is_not_confirmed():
    run_dir = fake_run(confirmed=None)
    assert pipeline.review_decision(run_dir, 0)[1] == 2


def test_a_review_that_was_never_merged_is_inconclusive():
    run_dir = fake_run(merged=False, confirmed=False)
    _line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert "not merged" in problem


def test_a_distrusted_run_is_inconclusive():
    run_dir = fake_run(first_line="PIPELINE: INCONCLUSIVE — distrusted",
                       exit_code=2, merged=False, confirmed=False,
                       extra={"review_distrusted": True})
    line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert "could not verify" in problem
    assert line.startswith("PIPELINE: INCONCLUSIVE")


def test_a_distrusted_veto_stays_a_veto():
    # the workflow could not verify its merge, but its review found a
    # blocking bug: distrust-review kept DO NOT PUBLISH, and so does this
    run_dir = fake_run(first_line=VETO_LINE, exit_code=1, merged=False,
                       confirmed=False, extra={"review_distrusted": True})
    line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 1
    assert "could not verify" in problem
    assert line == ("PIPELINE: DO NOT PUBLISH — the veto in verdict.json "
                    "stands, but the review was not confirmed (the workflow "
                    "could not verify its merge)")


def test_a_killed_session_keeps_a_confirmed_veto():
    _line, code, problem = pipeline.review_decision(
        fake_run(first_line=VETO_LINE, exit_code=1), -15)
    assert code == 1
    assert "signal 15" in problem


def test_the_cli_killing_the_workflow_wins_over_a_confirmed_file():
    # the shape a real run left when the CLI's 600 s ceiling stopped it: a
    # plain warning line, then a "success" result that is not DONE
    session = ["Background tasks still running after 600s; terminating.",
               {"type": "result", "subtype": "success", "is_error": False,
                "result": "Workflow is still running. I'll reply when it "
                          "finishes."}]
    run_dir = fake_run(session_lines=session)
    _line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert problem.startswith("the claude CLI stopped the workflow")


def test_a_session_that_did_not_reply_done_is_not_trusted():
    session = [{"type": "result", "subtype": "success", "is_error": False,
                "result": "The workflow is still running in the background."}]
    run_dir = fake_run(session_lines=session)
    _line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert "did not report DONE" in problem


def test_a_reply_that_starts_with_done_is_enough():
    for reply in ("DONE", "Done.", "done", "Done, the workflow finished."):
        session = [{"type": "result", "subtype": "success",
                    "is_error": False, "result": reply}]
        line, code, problem = pipeline.review_decision(
            fake_run(session_lines=session), 0)
        assert (line, code, problem) == (READY_LINE, 0, None), reply


def test_a_reply_that_only_contains_done_is_not_enough():
    session = [{"type": "result", "subtype": "success", "is_error": False,
                "result": "Not done yet: the workflow is still running."}]
    _line, code, problem = pipeline.review_decision(
        fake_run(session_lines=session), 0)
    assert code == 2
    assert "did not report DONE" in problem


def test_only_the_last_json_line_is_the_result():
    earlier = {"type": "result", "subtype": "success", "is_error": False,
               "result": "DONE"}
    last = {"type": "result", "subtype": "success", "is_error": True,
            "result": "You've hit your session limit"}
    run_dir = fake_run(session_lines=[earlier, last])
    _line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert "session limit" in problem


def test_an_error_result_is_not_trusted():
    session = [{"type": "result", "subtype": "error_max_turns",
                "is_error": False, "result": "DONE"}]
    assert pipeline.review_decision(fake_run(session_lines=session), 0)[1] \
        == 2


def test_a_non_zero_exit_is_not_trusted():
    assert pipeline.review_decision(fake_run(), 1)[1] == 2


def test_a_killed_session_is_not_trusted():
    _line, code, problem = pipeline.review_decision(fake_run(), -15)
    assert code == 2
    assert "signal 15" in problem


def test_a_session_past_the_timeout_is_not_trusted():
    _line, code, problem = pipeline.review_decision(fake_run(), -15,
                                                    timed_out=True)
    assert code == 2
    assert "PREFLIGHT_REVIEW_TIMEOUT" in problem


def test_no_claude_cli_is_inconclusive():
    _line, code, problem = pipeline.review_decision(fake_run(), None)
    assert code == 2
    assert problem == "the claude CLI is not installed"


def test_an_empty_session_file_is_not_trusted():
    assert pipeline.review_decision(fake_run(session_lines=[]), 0)[1] == 2


def test_verdict_files_that_disagree_are_inconclusive():
    run_dir = fake_run(first_line=VETO_LINE, exit_code=0)
    _line, code, problem = pipeline.review_decision(run_dir, 0)
    assert code == 2
    assert "disagree" in problem


def test_the_review_session_gets_the_raised_background_ceiling(
        monkeypatch, tmp_path):
    # a stand-in for claude that records the variable it was given
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    recorded = tmp_path / "ceiling.txt"
    fake_claude = fake_bin / "claude"
    fake_claude.write_text(
        "#!/bin/sh\nprintf '%s' \"$CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS\" > "
        + str(recorded) + "\n")
    fake_claude.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin) + os.pathsep
                       + os.environ.get("PATH", ""))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    code, timed_out = pipeline.run_review("/nonexistent", str(run_dir),
                                          str(tmp_path / "feed.jsonl"),
                                          DEFAULT_MODELS)
    assert (code, timed_out) == (0, False)
    assert recorded.read_text() == str(pipeline.REVIEW_TIMEOUT * 1000)


DEFAULT_MODELS = {"mechanical": "sonnet", "analysis": "opus",
                  "verify_high": "fable"}


def test_unset_or_empty_model_variables_take_the_defaults():
    models, error = pipeline.models_from_environment(
        {"PREFLIGHT_MODEL_ANALYSIS": ""})
    assert error is None
    assert models == DEFAULT_MODELS


def test_model_variables_choose_the_model_of_each_stage():
    models, error = pipeline.models_from_environment({
        "PREFLIGHT_MODEL_MECHANICAL": "opus",
        "PREFLIGHT_MODEL_ANALYSIS": "sonnet",
        "PREFLIGHT_MODEL_VERIFY_HIGH": "opus"})
    assert error is None
    assert models == {"mechanical": "opus", "analysis": "sonnet",
                      "verify_high": "opus"}


def test_a_bad_model_value_is_a_usage_error_before_the_gate_runs(
        monkeypatch, capsys):
    monkeypatch.setenv("PREFLIGHT_MODEL_VERIFY_HIGH", "gpt-4")

    def gate_must_not_run(repo, base):
        raise AssertionError("the gate ran despite a bad model value")

    monkeypatch.setattr(pipeline, "run_gate", gate_must_not_run)
    assert pipeline.main(["/nonexistent"]) == 4
    message = capsys.readouterr().err.strip()
    assert len(message.splitlines()) == 1
    assert "PREFLIGHT_MODEL_VERIFY_HIGH" in message
    assert "'gpt-4'" in message
    assert "sonnet, opus, fable" in message


def test_the_workflow_receives_the_models():
    models = {"mechanical": "sonnet", "analysis": "sonnet",
              "verify_high": "opus"}
    arguments = pipeline.workflow_arguments("/repo", "/run", "/feed", models)
    assert arguments["models"] == models
    assert arguments["reportDir"] == "/run"


def test_the_models_are_recorded_in_run_meta(tmp_path):
    (tmp_path / "run-meta.txt").write_text("mode=check\n")
    pipeline.record_models(str(tmp_path), {"mechanical": "sonnet",
                                           "analysis": "opus",
                                           "verify_high": "opus"})
    assert (tmp_path / "run-meta.txt").read_text() == (
        "mode=check\n"
        "models=mechanical=sonnet analysis=opus verify_high=opus\n")
    # the manifest is rewritten to match
    assert "./run-meta.txt" in (tmp_path / "manifest.sha256").read_text()
