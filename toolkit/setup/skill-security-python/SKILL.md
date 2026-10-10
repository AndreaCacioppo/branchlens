---
name: security-python
description: >-
  Deep per-file security review of Python source: reads the whole target file,
  runs bandit / semgrep / pip-audit only if already installed, then works a
  Python vulnerability catalog class by class (injection, deserialization,
  missing authorization and IDOR, Flask/Jinja2 misconfig, weak crypto, supply
  chain), and closes with a pass for the mistakes AI-generated Python makes
  most. Use it when the user runs `/security-python <file>`, or asks to
  "security check this Python file" or similar. Report-only: it never modifies
  the target or any other file, never installs anything, never executes the
  code under review. Complements `security-pipeline` — that one is the
  repo-level, diff-scoped publication gate; this one is the single-file dive.
---

# security-python

One file at a time, read end to end, judged against a Python-specific
vulnerability catalog. The scanners are a bonus, not the method: the value is
the checklist pass a careful human would do, done exhaustively and with line
numbers.

The deliverable is a report. Nothing is fixed and nothing is edited — every
finding is handed to the user with a suggested fix, and the user decides.

## When to run it

- The user runs `/security-python <file.py> [more files...]`.
- The user asks to "security check this Python file", "review this module for
  vulnerabilities", "is this script safe?", "audit this Flask view".
- After generating or heavily editing a Python file with an LLM — that is
  exactly what step 5 exists for.
- Before publishing: run `security-pipeline` for the repo-level verdict, and
  this skill on the two or three files that actually carry the risk (auth
  views, upload handlers, subprocess wrappers, anything parsing user input).

This skill does not replace `security-pipeline` (diff-scoped, whole-repo,
gives a publish/do-not-publish verdict) nor `preflight-gate` (mechanical
scanners only). It goes deeper on one file than either of them ever will.

## Procedure

1. **Resolve the target file(s).** Take them from the arguments. If the user
   named no file, **ask which file to review** — never pick a directory or a
   whole repository yourself, and never expand a glob into a bulk scan on your
   own initiative. If several files are given, review each one separately and
   emit one report per file.

2. **Read the entire file, plus the minimum context needed to see the trust
   boundaries.** Read the file top to bottom — not a grep, not a skim: severity
   depends on where a value comes from, and that is only visible in full. Then
   collect just enough context to answer "what is untrusted here?":
   - the imports (framework detection: Flask, FastAPI, Django, SQLAlchemy,
     requests, pandas, subprocess, pickle/yaml, lxml);
   - how the file is invoked — a web route, a CLI entry point, a Celery task,
     an imported library, a notebook cell — since that decides what an attacker
     can reach;
   - the sibling files a symbol obviously comes from (an app factory, a config
     module, a `requirements.txt` next to the target), read only if a finding
     depends on them.

   **Never execute the code under review**, not even "just to see what it
   does": no `python file.py`, no import in a REPL, no running its tests. This
   is a static read.

3. **Mechanical pass — best effort, never mandatory.** Use these three tools,
   and only if they are *already* installed. Test each first with
   `command -v <tool>`:

   ```
   bandit -ll <file.py>
   semgrep --metrics=off --config p/python <file.py>   # add --config p/flask if step 2 found Flask
   pip-audit -r requirements.txt            # only if a requirements file sits next to the target
   ```

   **On semgrep and the no-network rule.** A `p/...` config is a *registry*
   name: semgrep fetches it from semgrep.dev unless it is already in the local
   cache, and a pack that has been renamed simply 404s. That collides with the
   no-network rule below, so the order is: prefer a local rules file
   (`--config <path/to/rules.yaml>`) when the project has one; otherwise run the
   `p/` config only if it resolves from cache. If it tries to fetch, or fails,
   report `semgrep: skipped: ruleset unavailable offline` and move on — do not
   retry, and never treat a fetch as permission to go online for anything else.
   When the project ships no rules file of its own, use the rule set in
   `checks/semgrep-rules/` of the BranchLens toolkit (`toolkit/`), if present
   (`--config <that directory>`). Fall back to a `p/` pack only if
   `ls ~/.semgrep/cache 2>/dev/null` shows it already cached; otherwise record
   it skipped and do not invoke semgrep at all.
   `pip-audit` queries an advisory service by design, so this skill never runs
   it: record `skipped: needs network` and suggest it to the author as their
   own next step.

   **Never install anything.** A tool that is not installed is reported as
   `skipped: not installed` — that is a line in the report, not an error and
   not a reason to stop. `pip-audit` with no requirements file next to the
   target is reported the same way: `skipped: no requirements file`.
   Treat every scanner hit as a candidate finding to confirm against the file
   yourself, and remember the scanners miss whole classes (authorization,
   IDOR, business logic) that step 4 is there to catch.

4. **Checklist review — this is the skill.** Open `references/catalog.md` and
   work it class by class, in order: it is sorted by severity, then by how
   often AI-generated code gets that class wrong. For each class, use its
   *detection hints* against the file you just read, and decide: present,
   absent, or not applicable (a class about Flask routes is not applicable to a
   file with no routes — say so once, do not pad the report).

   Rules for the pass:
   - **Every finding cites a real line number from the file you just read.**
     If you cannot point at a line, it is not a finding — at most it is a
     NEEDS-HUMAN note.
   - Severity is the catalog's severity adjusted for reachability: user-facing
     input reaching the sink keeps it, a hardcoded internal constant lowers it.
     State the adjustment when you make one.
   - Do not stop at the first hit in a class; the same file often repeats the
     same mistake.

5. **Vibe-coding second pass.** Re-scan the file specifically for the mistakes
   LLM-generated Python makes most, because they hide in code that reads clean:

   - a route or view added without `@login_required` / role check, or a record
     fetched by client-supplied id with no ownership filter (IDOR);
   - hardcoded secrets — API keys, DB passwords, a literal `SECRET_KEY`;
   - string-built SQL (f-string / `%` / `.format()`) and shell commands
     (`shell=True`, `os.system`) instead of parameters and argument lists;
   - hallucinated or typosquatted PyPI package names (slopsquatting) in the
     imports or in a freshly written `requirements.txt`;
   - weak or homemade crypto — `hashlib.md5()`/`sha1()` for passwords,
     `random` instead of `secrets`, `verify=False` on `requests` calls;
   - debug mode or verbose tracebacks reachable — `app.run(debug=True)`, or an
     `except` block returning `str(e)` to the client;
   - request values used directly as DB keys, filenames or subprocess
     arguments with no validator (WTForms / pydantic / explicit check);
   - permissive CORS copy-pasted from a tutorial — `CORS(app)` with no origin
     allowlist, worse with `supports_credentials=True`;
   - secrets or PII in "debug logging" — `logging.info(f"...{password}...")`;
   - example credentials or tokens copied from documentation and left
     functional.

   Anything found here goes into the same table as step 4, with its CWE from
   the catalog.

## Output format

One block per file. Header line with the absolute path, then the mechanical
pass result (one line per tool: findings count, or `skipped: ...`), then the
findings table:

```
| LINE | CWE | SEVERITY | FINDING | FIX |
|------|-----|----------|---------|-----|
| 42   | CWE-89 | CRITICAL | f-string SQL built from request.args['id'] | pass the value as a bound parameter: cursor.execute(sql, (user_id,)) |
```

Severity is one of CRITICAL / HIGH / MEDIUM / LOW. Sort the table by severity,
then by line. FIX is a concrete instruction, not "sanitize the input".

Then the verdict for that file, exactly one of:

- **CLEAN** — no finding from the catalog or the vibe-coding pass.
- **FINDINGS (n, max: SEVERITY)** — n findings, highest severity named.
- **NEEDS-HUMAN** — something a static single-file read cannot decide.
  **Name it explicitly**: which line, and what the missing knowledge is —
  e.g. "line 88: `run_report(path)` is safe only if callers never pass a
  user-supplied path; the callers are not in this file", or "line 15:
  `SECRET_KEY` comes from a config module not read here", or "line 203:
  whether `internal_api_url` is attacker-influenced depends on the deployment".
  A NEEDS-HUMAN verdict can coexist with findings — report both. And when
  there are **zero** table findings but at least one open undecidable item, the
  verdict is **NEEDS-HUMAN, not CLEAN**: CLEAN is reserved for a file where
  nothing was found *and* nothing was left open. Say "0 findings, n open
  items" so the reader sees both facts at once.

Close every report with the honest reminder, in these terms: **CLEAN means
"nothing found by a static single-file read"** — not that the file is secure.
This review cannot see cross-file data flow, runtime configuration,
infrastructure, or the file's callers; it never executed anything. For code
touching money, personal data or authorization, ask for human eyes too.

## Inviolable rules

- **Report-only.** Never edit the target file. Never edit any other file in
  the repository — no "quick fix", no reformatting, no adding a comment,
  even if the user says "go ahead and fix it" mid-review: finish the report
  first, then let them ask for the fix as a separate task.
- **Never install anything** — no pip install, no `pipx`, no package manager,
  not even in a virtualenv, to make a scanner available.
- **No network calls.** No fetching advisories, no querying PyPI, no
  downloading rulesets. Missing information is reported as missing.
- **Never execute the code under review**, nor its tests.
- **Never soften, merge away or omit a finding** because the file is "just a
  script", "internal only", or the user seems attached to it. Report every
  one, at its real severity.
- **Findings must cite lines that exist** in the file as read. Never invent a
  line number, never carry one over from another file, never cite a line you
  did not actually see.
- If a target file cannot be read (missing, binary, no permission), **say so
  and stop** for that file. Never review a file from its name, from memory, or
  from what a scanner said about it.

## Installation

Copy this directory to `~/.claude/skills/security-python/`.
