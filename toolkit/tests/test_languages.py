"""Which changed files are code, and what the gate says about code no
Semgrep rule covers: a best-effort row that names it (a caveat in the
bottom line, never a veto), and a Semgrep row that counts only the files
its rules apply to."""

import json
import os
import shutil
import sys

import pytest

from helpers import TOOLKIT_DIR, make_repo, run_gate, write

sys.path.insert(0, os.path.join(TOOLKIT_DIR, "checks"))
import gate  # noqa: E402
import review_scope  # noqa: E402

SEMGREP = "Multi-language analysis (Semgrep)"
UNCOVERED = "Code without scanner rules"

GO_HANDLER = (
    "package main\n\n"
    "import (\n\t\"database/sql\"\n\t\"net/http\"\n)\n\n"
    "func userHandler(db *sql.DB) http.HandlerFunc {\n"
    "\treturn func(w http.ResponseWriter, r *http.Request) {\n"
    "\t\tid := r.URL.Query().Get(\"id\")\n"
    "\t\trows, _ := db.Query(\"SELECT name FROM users WHERE id = \" + id)\n"
    "\t\tdefer rows.Close()\n"
    "\t}\n}\n")

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None,
                                   reason="semgrep is not installed")


def test_code_is_told_from_documentation_and_data():
    assert gate.code_language("cmd/handler.go") == "Go"
    assert gate.code_language("lib/Util.PY") == "Python"
    assert gate.code_language("jobs/train.sbatch") == "Shell"
    assert gate.code_language("jobs/train.slurm") == "Shell"
    assert gate.code_language("jobs/train.pbs") == "Shell"
    assert gate.code_language("t/basic.t") == "Perl"
    assert gate.code_language("cgi-bin/form.cgi") == "Perl"
    assert gate.code_language("app/build.gradle") == "Groovy"
    assert gate.code_language("src/engine.cxx") == "C++"
    assert gate.code_language("src/engine.hh") == "C++"
    assert gate.code_language("docker/Dockerfile") == "Dockerfile"
    assert gate.code_language("Dockerfile.prod") == "Dockerfile"
    assert gate.code_language("build/app.dockerfile") == "Dockerfile"
    assert gate.code_language("Containerfile") == "Dockerfile"
    assert gate.code_language("Jenkinsfile") == "Jenkinsfile (Groovy)"
    assert gate.code_language("src/Main.m") == "Objective-C or MATLAB"
    assert gate.code_language(".github/workflows/ci.yml") \
        == gate.WORKFLOW_LANGUAGE
    # GitHub reads workflows only from the top-level folder; below it a
    # workflow-looking file is plain YAML configuration
    assert gate.code_language(".github/workflows/sub/ci.yml") == "YAML config"
    assert gate.code_language("app/.github/workflows/ci.yml") == "YAML config"
    for path in ("README.md", "notes.txt", "data/rows.json",
                 "data/table.csv", "docs/logo.png", "LICENSE", ".gitignore",
                 "style/site.css", "go.sum", "paper/main.tex"):
        assert gate.code_language(path) is None, path


def test_configuration_is_treated_as_code():
    assert gate.code_language("config/app.yaml") == "YAML config"
    assert gate.code_language("conf/beans.xml") == "XML config"
    assert gate.code_language("pyproject.toml") == "TOML config"
    assert gate.code_language("deploy/irida.conf") == "config file (.conf)"
    assert gate.code_language("setup.cfg") == "INI config"
    assert gate.code_language("i18n/messages_en.properties") \
        == "Java properties"
    assert gate.code_language("deploy/app.service") == "systemd unit"
    assert gate.code_language(".env") == "env file"
    assert gate.code_language(".env.production") == "env file"
    assert gate.code_language("Makefile") == "Makefile"
    assert gate.code_language("build/rules.mk") == "Makefile"
    assert gate.code_language("CMakeLists.txt") == "CMake"
    assert gate.code_language(".bashrc") == "Shell"
    assert gate.code_language("tool.jl") == "Julia"
    assert gate.code_language(".gitlab-ci.yml") == gate.GITLAB_CI_LANGUAGE
    assert gate.code_language("ci/deploy.gitlab-ci.yml") \
        == gate.GITLAB_CI_LANGUAGE
    assert gate.code_language("docker-compose.yml") == gate.COMPOSE_LANGUAGE
    assert gate.code_language("compose.prod.yaml") == gate.COMPOSE_LANGUAGE
    assert gate.code_language("src/main/resources/application.properties") \
        == gate.SPRING_CONFIG_LANGUAGE
    assert gate.code_language("src/main/resources/application-dev.yml") \
        == gate.SPRING_CONFIG_LANGUAGE
    assert gate.code_language("app/src/main/AndroidManifest.xml") \
        == "Android manifest"
    assert gate.code_language("pom.xml") == "Maven POM"


def test_a_file_of_an_unknown_type_is_decided_by_its_bytes():
    assert gate.code_language("tool.weird") == gate.NEEDS_CONTENT
    assert gate.code_language("tool.weird", b"do something\n") \
        == "unknown type (.weird)"
    assert gate.code_language("model.weird", b"\x00\x01binary") is None
    assert gate.code_language("CONFIGURE", b"key = value\n") \
        == gate.UNKNOWN_NO_EXTENSION
    assert gate.code_language("blob", b"\x89PNG\x00\x00") is None


def test_a_script_without_extension_is_named_by_its_interpreter():
    assert gate.code_language("bin/deploy", b"#!/bin/bash\nls\n") == "Shell"
    assert gate.code_language("bin/run", b"#!/usr/bin/env python3.12\n") \
        == "Python"
    assert gate.code_language("bin/x", b"#!/usr/bin/env -S node --flag\n") \
        == "JavaScript"
    assert gate.code_language("bin/y", b"#!/usr/bin/perl -w\n") == "Perl"
    assert gate.code_language("bin/z", b"#!/usr/bin/awk -f\n") == "awk script"
    assert gate.code_language("bin/data", b"plain text\n") \
        == gate.UNKNOWN_NO_EXTENSION


def read_feed_checks(run_dir):
    """The gate's 'check' done events in the feed beside run_dir, by name."""
    feed_path = os.path.join(os.path.dirname(run_dir), "security-feed.jsonl")
    with open(feed_path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f]
    return {event["name"]: event for event in events
            if event.get("event") == "check" and event.get("stage") == "gate"
            and event.get("status") == "done"}


@needs_semgrep
def test_a_go_only_change_is_named_and_not_counted_as_scanned():
    # before: "Semgrep TESTED, 1 changed files" over a file no rule reads,
    # and "NOT EXAMINED: none"
    def change(repo):
        write(repo, "handler.go", GO_HANDLER)
    code, rows, run_dir = run_gate(make_repo({}, change))
    assert code == 0
    semgrep = rows[SEMGREP]
    assert semgrep["status"] == "TESTED"
    assert semgrep["scope"] == "0 code files"
    assert semgrep["outcome"] == "nothing to scan"
    uncovered = rows[UNCOVERED]
    assert uncovered["status"] == "PARTIAL"
    assert uncovered["scope"] == "0 of 1 code files"
    assert "handler.go (Go)" in uncovered["reason"]
    assert uncovered["blocking"] is False
    with open(os.path.join(run_dir, "verdict.txt"), encoding="utf-8") as f:
        text = f.read()
    bottom_line = text.splitlines()[0]
    assert bottom_line.startswith("PREFLIGHT: PASSED")
    assert "CAVEAT: 1 area(s) not examined in full (%s)" % UNCOVERED \
        in bottom_line
    # Secrets looked at the change; the Semgrep row and "Security tests in
    # the diff" had nothing to scan
    assert "(1 of them examined code, 5 are the gate's own self-checks, " \
        "2 had nothing to scan)" in bottom_line
    assert "handler.go (Go)" in text.split("NOT EXAMINED")[1]
    with open(os.path.join(run_dir, "code-files.txt"), encoding="utf-8") as f:
        assert "handler.go\tGo\tno Semgrep rule for this language" in f.read()
    done = read_feed_checks(run_dir)
    assert done[UNCOVERED]["result"] == "PARTIAL"
    assert done[UNCOVERED]["blocking"] is False
    assert "handler.go (Go)" in done[UNCOVERED]["detail"]


@needs_semgrep
def test_the_semgrep_row_counts_only_the_files_its_rules_read():
    def change(repo):
        write(repo, "handler.go", GO_HANDLER)
        write(repo, "lib/util.py", "def add(a, b):\n    return a + b\n")
    code, rows, _run_dir = run_gate(make_repo({}, change))
    assert code == 0
    assert rows[SEMGREP]["scope"] == "1 code files"
    assert rows[UNCOVERED]["scope"] == "1 of 2 code files"


@needs_semgrep
def test_config_and_unknown_types_are_named_and_binaries_skipped():
    # before: "Code without scanner rules: NOT APPLICABLE — no code file
    # changed" and "NOT EXAMINED: none" for all of these
    def change(repo):
        write(repo, "tool.jl", "run(`ls`)\n")
        write(repo, "config/app.yml", "retries: 3\n")
        write(repo, "notes.weird", "a text file of a type nobody lists\n")
        write(repo, "weights.weird2", b"\x00\x01\x02binary")
    code, rows, run_dir = run_gate(make_repo({}, change))
    assert code == 0
    uncovered = rows[UNCOVERED]
    assert uncovered["status"] == "PARTIAL"
    assert uncovered["scope"] == "0 of 3 code files"
    for named in ("tool.jl (Julia)", "config/app.yml (YAML config)",
                  "notes.weird (unknown type (.weird))"):
        assert named in uncovered["reason"], named
    assert "weights.weird2" not in uncovered["reason"]
    with open(os.path.join(run_dir, "verdict.txt"), encoding="utf-8") as f:
        assert "CAVEAT" in f.readline()


@needs_semgrep
def test_config_rules_reach_their_files_in_a_gate_run():
    def change(repo):
        write(repo, "docker-compose.yml",
              "services:\n  app:\n    image: app\n    privileged: true\n")
        write(repo, "src/main/resources/application.properties",
              "management.endpoints.web.exposure.include=*\n")
    code, rows, run_dir = run_gate(make_repo({}, change))
    assert code == 1
    assert rows[SEMGREP]["blocking"] is True
    with open(os.path.join(run_dir, "new-semgrep.txt"),
              encoding="utf-8") as f:
        text = f.read()
    assert "docker-compose.yml:4  [compose-privileged-container]" in text
    assert ("src/main/resources/application.properties:1  "
            "[spring-actuator-exposes-every-endpoint]") in text
    assert rows[UNCOVERED]["status"] == "NOT APPLICABLE"


@needs_semgrep
def test_documentation_and_data_are_not_listed_as_code():
    def change(repo):
        write(repo, "docs/guide.md", "# Guide\n")
        write(repo, "data/rows.json", "[1, 2, 3]\n")
    code, rows, run_dir = run_gate(make_repo({}, change))
    assert code == 0
    assert rows[UNCOVERED]["status"] == "NOT APPLICABLE"
    assert rows[UNCOVERED]["reason"] == \
        "no code or configuration file changed in this diff"
    assert rows[SEMGREP]["outcome"] == "nothing to scan"
    assert not os.path.exists(os.path.join(run_dir, "code-files.txt"))
    with open(os.path.join(run_dir, "verdict.txt"), encoding="utf-8") as f:
        assert "CAVEAT" not in f.readline()


def test_every_shell_script_gets_the_bash_deep_dive(tmp_path):
    for skill in ("security-bash", "security-python", "security-perl"):
        (tmp_path / skill).mkdir()
        (tmp_path / skill / "SKILL.md").write_text("catalog\n")
    files = [{"path": path, "status": "A", "changed_lines": 1}
             for path in ("jobs/train.sbatch", "jobs/array.slurm",
                          "jobs/batch.pbs", "lib/env.ksh", "bin/deploy",
                          "bin/report", "cgi-bin/form.cgi", "t/basic.t",
                          "bin/tool", "cmd/main.go")]
    languages = {"bin/deploy": "Shell", "bin/report": "Perl",
                 "bin/tool": "awk script"}
    plan = review_scope.dive_plan(files, str(tmp_path), languages)
    skills = dict((dive["path"], dive["skill"]) for dive in plan["planned"])
    assert skills == {"jobs/train.sbatch": "security-bash",
                      "jobs/array.slurm": "security-bash",
                      "jobs/batch.pbs": "security-bash",
                      "lib/env.ksh": "security-bash",
                      "bin/deploy": "security-bash",
                      "bin/report": "security-perl",
                      "cgi-bin/form.cgi": "security-perl",
                      "t/basic.t": "security-perl"}
    assert sorted(plan["no_matching_skill"]) == ["bin/tool", "cmd/main.go"]


@needs_semgrep
def test_the_review_scope_names_code_without_rules_and_plans_script_dives():
    def change(repo):
        write(repo, "handler.go", GO_HANDLER)
        write(repo, "bin/deploy", "#!/bin/sh\necho deploy\n")
    _code, _rows, run_dir = run_gate(make_repo({}, change))
    scope = review_scope.read_scope(run_dir)
    assert scope["code_without_rules"] == [{"path": "handler.go",
                                            "language": "Go"}]
    if os.path.isfile(os.path.join(review_scope.SKILLS_DIR, "security-bash",
                                   "SKILL.md")):
        assert {"path": "bin/deploy", "skill": "security-bash",
                "changed_lines": 2} in scope["dives"]["planned"]
