---
name: security-bash
description: >-
  Per-file, Bash/POSIX-shell-tailored security review: reads a shell script
  (or the systemd unit or cron entry that launches it) end to end and reports
  every vulnerability class found, each with a real line number, a CWE and a
  concrete fix. Trigger when the user runs `/security-bash <file>` or asks to
  "security check this Bash / POSIX shell file". Report-only: never modifies
  the target or any other file, never installs anything, never executes the
  script under review. Complements `security-pipeline` (repo-level,
  diff-scoped publication gate) and `preflight-gate` (mechanical scanners) —
  this is the deep single-file dive. CLEAN means "nothing found by a static
  single-file read", never "this script is secure".
---

# security-bash

One shell file at a time, read from the first line to the last, judged
against the Bash / POSIX shell vulnerability catalog in
`references/catalog.md`. The output is a findings table and a per-file
verdict. Nothing is changed, anywhere.

Shell is the least forgiving language for this review: every line is an
argument list handed straight to an interpreter, so a single missing pair of
quotes is already a code-execution boundary. Most real findings live in that
gap, not in exotic constructs.

## When to run it

- The user runs `/security-bash <file>` — one or more `.sh`/`.bash` scripts, a
  `.service`/`.timer` unit, or a crontab fragment that drives them.
- The user asks to security check, audit, or review a shell script.
- Before a script is handed to a privileged runner (root cron, a systemd
  timer, a CI job), where the blast radius of one mistake is the whole host.
- Right after a shell script was generated or heavily edited by an LLM: step 5
  exists precisely for the mistakes that survive review because they look
  idiomatic.

This is not a substitute for `security-pipeline`. That skill decides whether a
change may be published; this one explains, in depth, what is wrong inside one
file.

## Procedure

1. **Resolve the target file(s)** from the arguments. Several are fine —
   review them one at a time and give each its own verdict. If the user gave
   no argument, ask which file: never pick a whole repository by yourself, and
   never widen the scope to "every .sh in this directory" on your own
   initiative. If a named path does not exist or cannot be read, say so and
   stop — do not review a neighbouring file instead.

2. **Read the entire file**, top to bottom, plus the minimum context needed to
   place the trust boundaries. Never execute the file, never source it, never
   run any command it contains — not even "just to see the usage output".
   Minimal context means:
   - every `source`/`.` include and every helper script it calls, at least
     enough to know what they define (especially if they set `IFS`, `PATH`, or
     credentials);
   - the shebang and the shell dialect (`#!/bin/bash` vs `#!/bin/sh` — arrays,
     `[[ ]]` and `pipefail` are not POSIX, and a POSIX script loses the safest
     fixes);
   - how the file is invoked: a systemd unit, a crontab line, a CI step, a
     `sudoers` entry, or a human shell. This decides the privilege level and
     therefore the severity of everything else.
   - where untrusted data enters: `$1..$9`/`$@`, environment variables, files
     in a shared or externally-fed directory, manifest/CSV fields, API and
     database responses, filenames produced by anyone but this script.

   Write down the trust boundaries before judging any line. A finding's
   severity is a function of who can reach the input and who the script runs
   as.

3. **Best-effort mechanical pass — `shellcheck` only, and only if it is
   already installed.** Test first, never install:

   ```
   command -v shellcheck >/dev/null 2>&1 && shellcheck -x --severity=style <file>
   ```

   `-x` follows `source`d files. If the test fails, record the line
   `shellcheck: skipped: not installed` and move on — a missing tool is never
   an error and never blocks the review. `shellcheck` does not apply to
   `.service`/`.timer` units or crontab fragments: record `not applicable`
   there. Treat the output as input to the review, not as the review: map
   every code onto a catalog class (SC2086/SC2046 → unquoted expansion, SC2064
   → trap quoting) and drop anything purely stylistic. Findings shellcheck
   cannot see — injection through `eval`, hardcoded secrets, missing input
   validation, `curl | bash` — are found in step 4, which stays mandatory even
   when shellcheck reports zero issues.

4. **Checklist review — this is the core of the skill.** Open
   `references/catalog.md` and work through it class by class, in order: it is
   sorted by severity and, within a severity, by how often the class appears
   in AI-generated shell. For each class, take its detection hints, apply them
   to the file you just read, and decide: present, absent, or undecidable from
   one file. Do not stop at the first finding — one script routinely carries
   four or five classes at once, and the interesting ones (an unquoted
   variable feeding an `rm -rf`) are combinations.

   Every finding must cite a real line number from the file you actually read
   and quote enough of that line to be unambiguous. Never cite a line you
   inferred, and never carry over a finding from a similar script. If a class
   depends on something outside the file — directory permissions, who owns the
   crontab, whether the unit runs as root — that is not a finding: it is a
   NEEDS-HUMAN item, named explicitly in the verdict.

5. **Vibe-coding second pass.** Re-scan the file specifically for the ten
   mistakes most common in LLM-generated shell, even if step 4 already
   reported clean. They are frequent, mechanical, and easy to read past:

   1. Unquoted `$var` / `$(cmd)` in almost every multi-word command
      (SC2086/SC2046) — word splitting and glob expansion.
   2. No `set -euo pipefail` at the top, so a failed dump, transfer or `cd` is
      ignored and the script continues on bad state.
   3. Hardcoded or copy-pasted example credentials — DB password, API token —
      in the script or in a systemd `Environment=` line.
   4. `curl ... | bash` / `wget ... | sh` provisioning, no checksum, no
      signature.
   5. No validation of arguments, filenames or manifest fields before they
      build a path or a command.
   6. `rm -rf` built from a variable that can be empty or unset, with no
      `${VAR:?}` guard and no `set -u`.
   7. Passwords passed as CLI flags (`mysqldump -p...`, `curl -u user:pass`),
      visible to every local user through `ps`.
   8. systemd units generated with zero hardening (no `NoNewPrivileges`, no
      `ProtectSystem`, no `PrivateTmp`, no dedicated `User=`).
   9. `set -x` or verbose debug flags left on, leaking secrets into cron mail,
      the journal or CI logs.
   10. A plausible-but-unverified package name installed during provisioning
       (slopsquatting), or an unpinned downloaded binary.

   Anything found here goes into the same table as step 4, with the same
   line-number requirement.

## Output format

One block per file. First the findings table, most severe first:

```
FILE: /abs/path/to/script.sh   (shellcheck: skipped: not installed)

LINE | CWE     | SEVERITY | FINDING                                  | FIX
-----|---------|----------|------------------------------------------|----------------------------------------
42   | CWE-78  | CRITICAL | `eval "$user_cmd"` executes a string built | Build an array and expand it:
     |         |          | from $1                                   | `cmd=(rsync -av -- "$src" "$dst"); "${cmd[@]}"`
17   | CWE-252 | HIGH     | No `set -euo pipefail`; the failed         | Add `set -euo pipefail` at line 2
     |         |          | `pg_dump` at 58 is not detected            |
```

`SEVERITY` is the catalog's, adjusted for this file's real privilege level and
reachability — say so when you adjust it, and adjust upward as readily as
down. `FIX` is the concrete edit for this line, not a principle.

Then the verdict for that file, exactly one of:

- **CLEAN** — no class from the catalog was found.
- **FINDINGS (n, max severity X)** — n findings, highest severity X.
- **NEEDS-HUMAN** — at least one class could not be judged from a static
  single-file read. Name each one precisely: what is unknown, and what would
  settle it. For example: whether `/srv/incoming` is writable by anyone
  outside the pipeline (settles the wildcard-injection class); whether the
  unit at line 3 runs as root (settles privilege separation and systemd
  hardening); whether the sourced `helpers.sh` sets `PATH` or `IFS`; whether
  the manifest is produced by a trusted party; the file permissions and owner
  of the script itself when it is launched by root cron. NEEDS-HUMAN can be
  reported alongside findings — both facts are true at once.
  When there are **zero** table findings but at least one open
  undecidable item, the verdict is **NEEDS-HUMAN, not CLEAN**: CLEAN is
  reserved for a file where nothing was found *and* nothing was left
  open. Say "0 findings, n open items" so both facts are visible.

Close with the honest reminder, every time, including on CLEAN:

> CLEAN means nothing was found by a static read of this file alone. It does
> not mean the script is secure. Runtime behaviour, file and directory
> permissions, the privilege of the caller, and everything the script calls
> were not verified here.

## Inviolable rules

- **Report-only.** Never edit the target file, and never edit any other file
  in the repository — no "quick fix", no reformat, no `shellcheck --format
  diff` applied. Fixes are shown as text for the user to apply.
- **Never execute the code under review**, in whole or in part, directly or
  through a helper, and never source it.
- **No installs.** If `shellcheck` is absent, report `skipped: not installed`
  and continue. Never install it, never suggest installing it as part of this
  run, never fall back to another tool that would have to be installed.
- **No network calls.** Everything needed is the file, its local context, and
  `references/catalog.md`.
- **Never soften or omit a finding**, and never downgrade one because the
  script "is only run internally" or "was working fine". If severity is
  reduced, state the reason on the row.
- **Findings must cite lines that exist** in the file just read. No inferred
  line numbers, no findings carried over from a similar script, no
  hypothetical examples in the table.
- **If the file cannot be read** — missing, binary, no permission — say so
  plainly and stop. Do not review a different file, and do not guess its
  content from its name.
- **Never claim the file is secure.** The strongest statement available is
  CLEAN, with the reminder attached.

## Installation

Copy this directory to `~/.claude/skills/security-bash/`.
