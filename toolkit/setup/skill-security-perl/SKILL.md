---
name: security-perl
description: >-
  Per-file, language-tailored security review of Perl source: reads one or more
  .pl/.pm/.cgi files end to end against a fixed catalog of Perl vulnerability
  classes — shell and SQL injection, two-argument open, stringy eval, taint
  mode, credentials, temp files, @INC — citing each finding at a real line
  number. Use when the user runs /security-perl <file>, asks to "security check
  this Perl file", "is this .pl safe?", or wants a deep read of a script before
  it goes on a shared machine. Report-only: never modifies the target or any
  other file, never installs anything, never makes network calls, and never
  executes the code under review. Complements `security-pipeline` — that one is
  the diff-scoped publication gate for a repository; this is the single-file dive.
---

# security-perl

A slow, complete read of one Perl file. Perl concentrates its danger in a few
constructs — `system`/backticks, two-argument `open`, stringy `eval`, `@INC`,
absent taint mode — that look unremarkable in a diff, so this skill reads whole
files rather than diffs, and works through a fixed catalog rather than trusting
an impression of the code.

## When to run it

- The user runs `/security-perl <file>` with one or more Perl files.
- "Security check this Perl script", "is this `.pl` safe?", "review this CGI for
  vulnerabilities", "what could an attacker do with this pipeline script?".
- Before a script goes onto a shared cluster, gets a web wrapper, or is handed
  to colleagues.
- After an assistant wrote or heavily edited a Perl file — step 5 exists for
  precisely that case.

Not this skill: a whole repository, or a change about to be published. Use
`preflight-gate` for the mechanical scanners, `security-pipeline` for the
diff-scoped gate with a publish / do-not-publish verdict.

## Procedure

1. **Resolve the target file(s) from the arguments.** Accept one or more paths
   and state the resolved list before starting. If no path is given, **ask
   which file** — never pick a directory or a whole repository on your own,
   never expand a glob into a repo-wide scan. If a given path is a directory,
   list the Perl files under it and ask which ones to review.

2. **Read each file in full, plus the minimal context that fixes the trust
   boundaries.** Read every line — not a grep sample. Then collect:
   - the `use`/`require` lines: they decide which catalog classes apply (CGI,
     Mojolicious::Lite, Dancer, DBI, LWP::UserAgent, IO::Socket::SSL, Storable,
     YAML, XML::Simple, XML::LibXML, Digest::*, File::Temp, IPC::*);
   - the shebang: is `-T` (taint mode) there? `-w`, `use strict`, `use warnings`?
   - how the file is invoked and what enters it: `@ARGV`, `%ENV`, `param()`,
     STDIN, files opened for reading, config files, cron/scheduler wrappers;
   - `ls -l` on the file for the setuid/setgid bit (class PERL-23) — read-only,
     allowed.

   Then name the trust boundaries out loud: which values come from outside the
   script (CLI arguments, environment, config files, sample sheets, spreadsheet
   cells, FASTA/VCF content, HTTP parameters, other users' files on a shared
   filesystem) and which sinks each one can reach.

   **Never execute the code under review** — not the script, not a snippet, not
   a single subroutine, not under a debugger, and not `perl -T file.pl` (that
   runs it).

3. **Best-effort mechanical pass — only with tools already installed.** Test
   each one with `command -v <tool>` first. Absent tool → record
   `skipped: not installed` and move on; that is never an error and never
   blocks the review. **Never install anything.**
   - `perlcritic --severity 1 --verbose 9 <file>` — static (PPI-based), does not
     execute the file. Skim for the security-relevant policies:
     `BuiltinFunctions::ProhibitStringyEval`, `InputOutput::ProhibitTwoArgOpen`,
     `InputOutput::ProhibitBacktickOperators`,
     `TestingAndDebugging::ProhibitNoStrict`. `--verbose 9` prints the policy
     name with each finding so you can filter to those.
   - `perl -c <file>` is **not** used: it runs every `use`, `require` and
     `BEGIN` block at compile time, so it executes code from the file under
     review. Record `skipped: perl -c executes compile-time code` and move on.
   - **Not part of this skill:** `perl -T <file>` on real input. It executes the
     script. Recommend it to the author as their own next step; never run it.

   Tool output is a hint, not the review: everything it flags is still confirmed
   by reading, everything it misses is still yours to find in step 4.

4. **Checklist review — the core.** Open `references/catalog.md` and work
   through it class by class, in the order given (severity first, then how often
   AI-generated Perl gets it wrong). For each class read the patterns and the
   detection hints, scan the file for them, and decide. Rules:
   - every finding cites a **real line number from the file you just read** —
     re-open the line and read it again before writing the row; if you cannot
     point at a line, it is not a finding;
   - take the severity from the catalog, then adjust for reachability in this
     file: a `system()` string built from a literal constant is a lower finding
     than the same line built from `$ARGV[0]`. State the adjustment and why;
   - do not stop at the first instance of a class — count every occurrence;
   - a class checked and found clean is not reported, except where the user
     would otherwise wonder ("no DBI usage, so SQL injection is out of scope
     for this file").

5. **Vibe-coding second pass.** Re-scan the file for the mistakes AI-generated
   Perl makes most often. This overlaps step 4 by design — the point is a second
   read with a different question: *what would a model have written here?*
   1. untrusted data interpolated into `system("…")`, backticks or `qx//`
      instead of list-form `system($cmd, @args)`;
   2. two-argument `open()` instead of three-argument with a literal mode;
   3. hardcoded database/API credentials in the script or a committed config;
   4. TLS verification disabled to silence an SSL error (`verify_hostname => 0`,
      `PERL_LWP_SSL_VERIFY_HOSTNAME`, `SSL_VERIFY_NONE`);
   5. no input validation and no taint mode on external data before it reaches a
      filesystem or shell sink;
   6. `use`/`require` of a CPAN module that may not exist, or is a near-miss of a
      real name (slopsquatting) — flag the exact name for the user to check on
      MetaCPAN; do not check the network yourself;
   7. verbose debug logging that prints whole data rows, connection strings or
      secrets;
   8. homegrown "encryption"/obfuscation, or MD5/SHA1 used as if it were a
      signature;
   9. predictable `/tmp` filenames built by hand instead of `File::Temp`;
   10. a new CGI/web wrapper around a previously CLI-only script with no
       authorization check.

## Output format

One section per file, headed by its absolute path, then the findings table:

```
| LINE | CWE | SEVERITY | FINDING | FIX |
|---|---|---|---|---|
| 42 | CWE-78 | CRITICAL | `system("samtools index $bam")` — $bam is a sample-sheet cell read at line 17, so `;` in that cell runs arbitrary commands | list form: `system('/usr/bin/samtools','index',$bam)`, after `$bam =~ /^([\w.-]+)$/ or die` |
| 17 | CWE-22 | HIGH | path built as `"$outdir/$sample.vcf"` with $sample unvalidated | whitelist `^[A-Za-z0-9_.-]+$`, then confirm `abs_path` stays under $outdir |
```

Sort by severity (CRITICAL, HIGH, MEDIUM, LOW), then by line number. FIX is the
concrete edit for that line, not a general principle — and the user applies it,
not you.

Then exactly one verdict line per file:

- `CLEAN` — no finding from any catalog class.
- `FINDINGS — <n>, max <SEVERITY>`.
- `NEEDS-HUMAN — <what>`: something this review could not judge from a static
  single-file read. Name it exactly; never leave it vague. Typical cases:
  whether a value reaching `system()` is really attacker-controlled at runtime;
  the actual permissions and ownership of a directory the script writes to;
  whether a `use`d module exists on CPAN and is the intended one; whether a CGI
  wrapper sits behind an authenticating proxy; whether the caller passes `-T`;
  what a `require`d local `.pm` actually does. NEEDS-HUMAN can accompany
  FINDINGS — report both.
  When there are **zero** table findings but at least one open
  undecidable item, the verdict is **NEEDS-HUMAN, not CLEAN**: CLEAN is
  reserved for a file where nothing was found *and* nothing was left
  open. Say "0 findings, n open items" so both facts are visible.

Close with this reminder every time, **including on CLEAN**:

> CLEAN means nothing was found by a static single-file read. It does not mean
> the file is secure: this review never ran the code, never saw the callers, the
> real input data or the filesystem permissions around it, and verified no
> module against CPAN.

## Inviolable rules

- **Report-only.** Never edit the target file, and never edit any other file in
  the repository — no fixes, no reformatting, nothing "while I was in there".
  The FIX column is a suggestion for the user to apply.
- **Never execute the code under review**, whole or in part: no `perl -T
  file.pl`, no debugger, no pasting a subroutine into a harness.
- **No installs.** A missing tool is reported as `skipped: not installed`. Never
  run `cpan`/`cpanm`/`brew`/`apt`, and never make installing one a precondition.
- **No network calls.** Not to MetaCPAN, not to a CVE database. A module name
  that needs verifying is reported as NEEDS-HUMAN with the exact name to check.
- **Never soften or omit a finding** — not because the script is "internal
  only", not because the user says the input is trusted, not to keep the table
  short. Report it, and put the mitigating context in the FINDING cell.
- **If a file cannot be read** (missing, unreadable, binary, not Perl), say so
  plainly and stop for that file. Never review from a filename, a guess, or a
  partial read.
- **Every cited line must exist** in the file as read. Re-check each line number
  against the file before emitting the table; one wrong line number discredits
  the whole report.

## Installation

Copy this directory to `~/.claude/skills/security-perl/`.
