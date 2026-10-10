---
name: preflight-gate
description: >
  Runs the LOCAL mechanical security gate on a target repository: diff-scoped
  scanners (Semgrep with local rules, Bandit on changed Python files, secret
  patterns in every commit of the branch, dependency check when dependency
  files changed, scanner-suppression and security-test tampering detection)
  plus best-effort build and test runs (Maven for Java, pytest for Python),
  all judged against the base branch with no baseline to maintain. Judges
  uncommitted work too, with --worktree. Use it when the user wants just the
  scanners — a quick check mid-work, "did I introduce a vulnerability?", a
  re-run after fixing one finding. This is the mechanical half only — before
  actually publishing, use the skill `security-pipeline`, which adds the
  adversarial review of the diff and one combined verdict.
---

# preflight-gate

Phase 1 only. One command, one table, one exit code.

## Procedure

1. Resolve TOOLKIT (the directory containing `preflight.sh` and
   `checks/gate.py`) and TARGET (the repository to check — given by the
   user, or the enclosing git repository of the current directory). If
   TARGET stays ambiguous, ask.
2. Run `git -C <TARGET> status --porcelain`. If it lists anything
   (modified or untracked files), the work is not committed: add
   `--worktree`, which judges a snapshot of the working tree built in a
   temporary area, writing nothing to the repository or its `.git`.
   Without the flag the gate judges HEAD only and stops at INCONCLUSIVE
   with an "Uncommitted changes" row.
3. From TOOLKIT run:

   ```
   ./preflight.sh check <TARGET> [base-ref] [--worktree]
   ```

   Use the Bash tool's `timeout` at 600000 ms, or `run_in_background: true`
   when TARGET has a `pom.xml` at its root (the build and tests may take
   up to 35 minutes). Never interrupt it.

   `base-ref` defaults to origin/main (then origin/master, main, master).
   Pass it only if the user names a different base, or if the gate reports
   an empty diff (typically a first publish with no remote: ask the user
   which base to compare against).
4. Report, without softening:
   - the bottom line, verbatim. It carries the finding tally, the
     coverage counts and (on a green) the CAVEAT naming any best-effort
     area not examined in full: a check the machine could not run, or
     changed code no scanner rule covers. With --worktree it also says that
     the working tree, not a commit, was judged;
   - **every `NOT POSSIBLE` and `PARTIAL` row with its reason** (the
     `NOT EXAMINED` call-out lists them);
   - the blocking findings (file, line, rule), if any. A secret found "in
     commit <id>" is gone from the final version but still in the branch
     history, and a push publishes it: the history must be rewritten before
     pushing.
5. Exit codes:
   - `0` PASSED: green for the scanners only. Say that the LLM diff
     review is still missing.
   - `1` FAILED: do not publish. List the findings.
   - `2` INCONCLUSIVE: a required check could not run. Give the remedy the
     row names ("Uncommitted changes": commit or use --worktree; an empty
     diff: pass the base, or `empty-tree` on a first publish; "Toolkit
     integrity": toolkit files changed during the run, run it again).
   - `4` usage error: fix the invocation, do not work around it.
6. Point at the run directory the script printed (`report in:`):
   `verdict.txt`, `timings.txt` and the raw tool outputs are the evidence
   record of what was tested.

## What the gate covers

Security core (a core check that cannot run makes the verdict INCONCLUSIVE):
Semgrep over the changed code files of a language the local rules cover
(Python, JavaScript, TypeScript and Java; shell scripts, Dockerfiles,
Kotlin and GitHub Actions workflows as best effort); secret patterns
in the added lines of the diff and of every commit on the branch; security
tests deleted, renamed away, disabled or left out of test collection by the
diff; scanner suppression files; dependency vulnerabilities when a manifest
changed; the exceptions file; uncommitted work; the integrity of the
toolkit itself.

Best effort (a real failure still blocks, but "this machine cannot run it"
becomes a loud caveat instead of a veto): the Maven build and its tests for
Java repositories, `pytest` for repositories with Python tests, Bandit over
the changed Python files, outbound-HTTP hygiene, and "Code without scanner
rules", which names changed code no Semgrep rule examined in full (Go,
HTML, Perl, SQL..., or a best-effort file semgrep could only partly
parse). The build and the tests
run the repository's own code with the user's rights; `PREFLIGHT_SANDBOX=1`
runs them in a macOS sandbox that can only write to temporary directories
(off by default: some honest tests fail in it).

Name these gaps out loud, because they are otherwise silent: without
`pytest` and `bandit` installed, those rows read NOT POSSIBLE; a Semgrep
or Bandit row reading PARTIAL means some changed file was never examined,
not that it came back clean; and a "Code without scanner rules" row names
changed files, with their type, that no scanner rule read in full, so
only the LLM review will. Every changed file counts as code there except
documentation, data and binaries: configuration (YAML, XML, TOML, `.conf`,
`.properties`...) and unknown types (`unknown type (.x)`) are named too.

## Progress feed

The gate prints a `security feed:` line naming a JSON-lines file to which
it appends the run's start, each check's result, the files it will not
deep-dive, and its bottom line. It is telemetry for a local viewer
(BranchLens shows it live with `--security-feed <path>`); nothing reads it
back and it never influences a verdict. Mention it only if the user asks.

The file is `security-feed.jsonl` in the reports root, beside the run
folders: `$PREFLIGHT_REPORTS_DIR` when set and not empty, else
`~/preflight-reports/<name>`, where `<name>` is the main repository's
folder name (the parent of `git rev-parse --git-common-dir`). A linked
worktree reports into its repository's folder, not one named after the
worktree.

## Inviolable rules

- Never edit `checks/exceptions.txt` to make the check pass. A legitimate
  exception (a CVE with no fix) is proposed to the user with a reason and
  an expiry date; the user decides.
- Never report a green result if the check did not actually run.
- Read-only on the target repository: no commit, no push, no checkout, no
  reset. Reports live outside it (`PREFLIGHT_REPORTS_DIR` moves them).

## Installation

From the toolkit root, `make install-skills` copies this file to
`~/.claude/skills/preflight-gate/SKILL.md` (together with the other skills
and the review workflow). Run it after pulling, then `/reload-skills`: the
installed copy is what an agent reads, and nothing else keeps it in step
with this repository. `make skills-status` says whether yours has drifted.
