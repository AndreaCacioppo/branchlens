---
name: security-javascript
description: >-
  Deep per-file security review of JavaScript, tailored to the language and to
  React/JSX (plus self-contained HTML dashboards with inline vanilla JS, and
  webpack/babel config): a best-effort mechanical pass with already-installed
  tools, a 25-class catalog of JavaScript-specific weaknesses, and a second
  pass for the mistakes AI-generated code makes most. Trigger it when the user
  runs /security-javascript <file>, or asks to "security check this JavaScript
  file", "review this JSX/React component for vulnerabilities". Report-only: it
  NEVER modifies the target file or any other file in the repository, installs
  nothing, and never claims code is secure. It complements `security-pipeline`
  (repo-level, diff-scoped publication gate) — this is the single-file deep
  dive, not a gate.
---

# security-javascript

A slow, deliberate read of one JavaScript file at a time. The pipeline skills
answer "did this change make things worse?"; this one answers "what is wrong
with this file, line by line?". It reports, it never edits, and it never
declares code secure — the most it can say is that a careful static read of
this file found nothing.

## When to run it

- The user runs `/security-javascript <file> [more files...]`.
- The user asks for a security check, audit, or vulnerability review of a
  specific `.js`, `.jsx`, `.mjs`, `.html` (inline JS), or webpack/babel config
  file.
- A file was largely AI-generated or heavily copy-pasted and deserves a
  targeted look before it is reviewed by a human.
- After `preflight-gate` or `security-pipeline` flagged a file and the user
  wants to understand that one file properly.

Not for: whole repositories, diffs, or a publication decision. Those are
`preflight-gate` and `security-pipeline`.

## Procedure

1. **Resolve the target file(s)** from the arguments. Accept several. Verify
   each path exists and print the absolute path you are about to review. If no
   file was given, **ask which file** — never pick a directory, a repository,
   or a "most likely" file by yourself.

2. **Read the entire file**, top to bottom, before judging anything. Then read
   the minimal surrounding context needed to locate the trust boundaries:
   - the imports/requires at the top, and for a `.html` dashboard every
     `<script src>` tag;
   - the framework in use (React/JSX? plain DOM? webpack config? a bundled
     dashboard?) and the React version if a `package.json` sits nearby;
   - how the file is invoked — which component renders it, which route, which
     event handler, what data reaches it (URL params, `fetch`/`axios`
     responses, `postMessage`, storage, props).
   Mark, explicitly, where untrusted data enters. **Never execute the code
   under review**, never run its dev server, never open its URLs.

3. **Best-effort mechanical pass** — only with tools that are *already*
   installed. Test first, e.g. `command -v semgrep`. Never install anything.
   - `semgrep --metrics=off --config p/javascript <file>` (add `--config p/react`
     for JSX) if `semgrep` is on PATH. Note that a `p/...` config is a
     *registry* name: semgrep fetches it from semgrep.dev unless it is already
     cached, and a renamed pack simply 404s. That collides with the no-network
     rule below, so prefer a local rules file (`--config <path/to/rules.yaml>`)
     when the project has one; otherwise run the `p/` config only if it
     resolves from cache, and if it tries to fetch or fails, report
     `semgrep: skipped: ruleset unavailable offline` and move on — never treat
     a fetch as permission to go online for anything else.
     When the project ships no rules file of its own, use the rule set in
     `checks/semgrep-rules/` of the BranchLens toolkit (`toolkit/`), if present
     (`--config <that directory>`). Fall back to a `p/` pack only if
     `ls ~/.semgrep/cache 2>/dev/null` shows it already cached; otherwise record
     it skipped and do not invoke semgrep at all.
   - `npx --no-install eslint <file>` **only if the project already has an
     ESLint config** (`eslint.config.*`, `.eslintrc*`, or an `eslintConfig` key
     in `package.json`) **and** eslint is already present
     (`test -x node_modules/.bin/eslint` or `command -v eslint`) — run it with
     the project's own config, never with injected rules or plugins the project
     does not have. `--no-install` is what stops npx from downloading eslint.
   A tool that is absent, or that cannot fetch its public ruleset offline, is
   reported as `skipped: not installed` / `skipped: ruleset unavailable`. That
   is a note in the report, never an error and never a reason to stop. The
   checklist review in step 4 happens regardless.

4. **Checklist review — this is the core of the skill.** Open
   `references/catalog.md` in this skill's directory and work through it
   class by class, in order: the catalog is sorted by severity first and by
   vibe-coding frequency second, so the top of the file is where the real risk
   usually is. For each class, use its *detection hints* against the file you
   just read, and record a finding only when you can point at concrete code.
   **Every finding must cite a real line number from the file you read** — if
   you cannot name the line, you do not have a finding. Note in one line each
   class you checked and cleared, so the user can see the review was complete
   rather than lucky.

5. **Vibe-coding second pass.** Re-scan the file specifically for the mistakes
   AI-generated JavaScript makes most often. These overlap with step 4 on
   purpose — the second look catches what the class-by-class pass rationalised
   away:
   - API keys or tokens hardcoded in a component, or `.env` values inlined
     into the public webpack bundle (`process.env.REACT_APP_*_KEY`).
   - `dangerouslySetInnerHTML` / `ref.current.innerHTML` used to render API or
     user content quickly, with no sanitization.
   - A decoded-but-unverified JWT payload, or a hidden/disabled UI control,
     treated as the actual authorization check.
   - An imported npm package that is plausible but non-existent or a typosquat
     ("slopsquatting"), or a version pinned from stale training data.
   - Example/placeholder credentials copy-pasted straight out of docs or a
     tutorial into real code.
   - Errors swallowed with `console.log(err)`, or a raw error/stack trace
     rendered to the user instead of a generic message.
   - A missing CSRF header on a state-changing request — and the tell-tale
     "fix" of disabling CSRF server-side instead of sending the token.
   - `devtool: 'source-map'` and verbose debug logging left on in the
     production build.
   - HTML built by template-literal concatenation and injected via
     `innerHTML` instead of safe DOM APIs or JSX escaping.
   - `Math.random()` used for anything that functions as a token, id, or nonce.

## Output format

One block per file. Findings table first, sorted by severity:

```
FILE: /absolute/path/to/Component.jsx   (312 lines, React/JSX)
mechanical pass: semgrep 2 findings | eslint skipped: not installed

LINE | CWE      | SEVERITY | FINDING                          | FIX
-----|----------|----------|----------------------------------|---------------------------
 84  | CWE-79   | CRITICAL | dangerouslySetInnerHTML fed from | sanitize with DOMPurify or
     |          |          | the /api/notes response          | render as text/JSX
 27  | CWE-798  | CRITICAL | literal API key in the bundle    | proxy through the backend,
     |          |          |                                  | rotate the leaked key
119  | CWE-1022 | MEDIUM   | target="_blank", no rel=noopener | add rel="noopener noreferrer"
```

Then one verdict per file, exactly one of:

- **CLEAN** — no finding from the catalog could be tied to a line.
- **FINDINGS (n, max SEVERITY)** — n findings, highest severity named.
- **NEEDS-HUMAN** — name precisely what a static single-file read could not
  judge: e.g. "line 61 renders `props.html`; whether it is sanitized depends on
  the caller in `Dashboard.jsx`", "the role check at line 40 is only safe if
  the server authorizes the same endpoint", "the package `react-fast-tabler` at
  line 3 must be verified on the registry before it is trusted".
  When there are **zero** table findings but at least one open
  undecidable item, the verdict is **NEEDS-HUMAN, not CLEAN**: CLEAN is
  reserved for a file where nothing was found *and* nothing was left
  open. Say "0 findings, n open items" so both facts are visible.

Close every report with the honest reminder, verbatim in substance:

> CLEAN means nothing was found by a static single-file read. It does not mean
> the file is secure. Runtime behaviour, the caller's data, the server's
> authorization and the dependency tree were not verified here.

## Inviolable rules

- **Report-only.** Never edit the target file, and never edit any other file
  in the repository — not a config, not a lockfile, not an ESLint rule, not a
  suppression comment. Fixes are described in the table; the user applies them.
- **Never execute the code under review**, in any form.
- **No installs.** Missing tool means the pass is reported as skipped.
- **No network calls.** The file under review is never uploaded, pasted, or
  sent anywhere, and no dependency, ruleset, or advisory database is fetched to
  make the review "better". A scanner that cannot work offline is skipped.
- **Never soften, merge away, or omit a finding** to make a file look better,
  and never downgrade a severity because the fix looks inconvenient.
- **Every finding cites a line that exists** in the file as read. No
  speculative line numbers, no findings about code that is not in the file.
- **If a file cannot be read** (missing, binary, permission denied), say so
  plainly, do not guess its contents, and stop for that file.
- **Never state that a file is secure.** The vocabulary is CLEAN /
  FINDINGS / NEEDS-HUMAN, and CLEAN carries the reminder above.

## Installation

Copy this directory to `~/.claude/skills/security-javascript/`.
