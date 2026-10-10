---
name: security-sql
description: >-
  Per-file, language-tailored security review of SQL written for MariaDB/MySQL:
  schema and DDL, hand-written application queries, stored routines, Liquibase
  changesets, and ad-hoc analyst queries. Run it as `/security-sql <file>` (one or
  more files of this language), or when the user says "security check this SQL
  file", "review this migration for security", "is this schema safe?". It reads the
  whole file, walks a SQL-specific vulnerability catalog (injection at the
  host-language boundary, PREPARE/EXECUTE dynamic SQL, hardcoded credentials,
  destructive migrations, excessive GRANTs, PII exposure), then re-scans for the
  mistakes LLM-generated SQL makes most often. Report-only: it NEVER modifies the
  target file or any other file, never installs anything, never executes the SQL
  under review. It complements `security-pipeline` (repo-level, diff-scoped
  publication gate) and `preflight-gate` (mechanical scanners) — this skill is the
  deep single-file dive.
---

# security-sql

One file at a time, read end to end, judged against a SQL-specific catalog. The
output is a findings table and a per-file verdict. Nothing is fixed, nothing is
edited: the reviewer reports, the user decides.

The catalog lives in `references/catalog.md` next to this file. Open it during
step 4 — it is written to be read on demand, not memorised.

## When to run it

- The user runs `/security-sql <file>` (or names several SQL files).
- The user asks to security-check a schema, a migration/changeset, a stored
  routine, a query module, or an analyst query file.
- Before a migration is applied to a shared or production database.
- After an AI assistant generated or heavily rewrote SQL — that is what the
  vibe-coding pass in step 5 exists for.
- Not for a whole repository: for repo-level, diff-scoped review use
  `security-pipeline`; for the mechanical scanners alone use `preflight-gate`.

## Procedure

1. **Resolve the target file(s).** Take them from the arguments, as absolute
   paths. If no file was given, ask which file to review — never pick a
   directory or a whole repository yourself, and never expand a directory
   argument into "all SQL files" without the user saying so. If a named file
   does not exist or cannot be read, say exactly that and stop.

2. **Read the entire file, plus minimal context.** Read it in full before
   judging anything — findings must cite real line numbers, and a partial read
   produces invented ones. Then gather only the context needed to locate the
   trust boundaries:
   - what kind of file this is: DDL/schema, seed data, Liquibase changeset,
     stored routine, application query module, analyst script;
   - the host-language boundary: which driver or framework executes this SQL
     (`mysqlclient`/`PyMySQL`/`mysql-connector-python`, SQLAlchemy, Liquibase),
     and whether values arrive as bound parameters or as interpolated text;
   - how the file is invoked: an HTTP route, a migration runner, a notebook,
     a cron job — this decides whether input is attacker-controlled;
   - who the executing database account is, if the file or its neighbours say.

   Read neighbouring files only to answer those questions. **Never execute the
   SQL, the migration, or the surrounding code under review** — no `mysql`
   client, no `liquibase update`, no running the Python that calls it.

3. **Best-effort mechanical pass.** Only one tool, and only if it is already
   installed:

   **First, determine the dialect — do not assume MySQL.** The catalog is
   written for MariaDB/MySQL, but the file in front of you may be SQLite,
   PostgreSQL or something else. Tells: `INTEGER PRIMARY KEY AUTOINCREMENT`,
   `json_valid()`, triggers without `FOR EACH ROW`, or an `import sqlite3` in
   the calling code mean **SQLite**. State the detected dialect in the report
   header, and pass it to the linter:

   ```
   command -v sqlfluff && sqlfluff lint --dialect <detected-dialect> <file>
   ```

   On SQLite, several catalog classes are **structurally inapplicable** rather
   than absent-because-careful: there is no server-side privilege system (no
   `GRANT`, no `CREATE USER ... IDENTIFIED BY`), no stored procedures
   (`PREPARE`/`EXECUTE`), no `FILE`/`LOAD DATA INFILE`, no `bind-address` or
   anonymous accounts, and no native crypto (`AES_ENCRYPT`). Say so once, in a
   single line, and do not pad the report with those classes. The injection,
   constraint/validation, PII-exposure and audit-trail classes still apply in
   full — and note that in SQLite the *file permissions* of the database carry
   the access control the server-side classes would otherwise cover.

   It is a linter, not a security scanner: use it to surface malformed or
   inconsistently quoted dynamic-SQL fragments that are easy to misread by eye.
   If `command -v` finds nothing, record `sqlfluff: skipped (not installed)` and
   move on — a missing tool is a reported gap, never an error, and **never a
   reason to install anything**. Lint output is an input to your judgement, not
   a finding on its own: only report a lint line if it maps to a catalog class.

4. **Checklist review — this is the core of the skill.** Open
   `references/catalog.md` and work class by class, top down. The catalog is
   already ordered by severity and then by vibe-coding frequency, so the first
   sections are the ones most likely to be present and most damaging if they
   are. For each class, use its detection hints against the file you just read.
   For every hit, record: the line number, the CWE, the severity, what the code
   actually does, and the canonical fix. Two rules:
   - **Every finding cites a line number that exists in the file you read.**
     If you cannot point at a line, it is not a finding — it is a note or a
     NEEDS-HUMAN item.
   - A class you checked and did not find is not reported. Do not pad the
     table with absences.

5. **Vibe-coding second pass.** Re-scan the file specifically for the mistakes
   AI-generated SQL and SQL-adjacent code reproduce most reliably. Even if you
   already walked the catalog, walk these ten again — they are the ones a
   confident-looking generated file hides best:
   - missing row-level authorization (IDOR) on a query keyed by an externally
     supplied id — the query works, the ownership/role predicate is absent;
   - f-string / concatenated SQL instead of bound parameters, especially in
     short route handlers and notebook snippets;
   - hardcoded credentials: `IDENTIFIED BY 'literal'`, a `password="..."` in a
     connect call, a `SECRET_KEY` left in seed or example code;
   - raw SQL exception text returned to the client, plus debug mode left on;
   - dynamic `ORDER BY` / `LIMIT` / identifier interpolation with no allow-list,
     because those positions genuinely cannot be bound;
   - migration changesets with `DELETE`/`UPDATE` missing `WHERE`, or `DROP` with
     no rollback or precondition guard;
   - a typosquatted or hallucinated PyPI driver/migration package in the
     dependency list next to this file;
   - `GRANT ALL PRIVILEGES` / wildcard host for the application account, because
     it is the fastest way to make generated code work;
   - `MD5()`, `SHA1()`, `PASSWORD()` used to hash credentials, copied from
     outdated tutorials;
   - wildcard CORS combined with credentialed requests on the endpoints these
     queries back.

6. **Report** using the output format below, one block per file. Then stop —
   no fixes applied, no follow-up edits offered as actions taken.

## Output format

Per file, first the header line and the mechanical pass result:

```
FILE: /abs/path/to/schema.sql   (Liquibase changeset, 412 lines)
sqlfluff: skipped (not installed)
```

Then the findings table, most severe first:

| LINE | CWE | SEVERITY | FINDING | FIX |
|------|-----|----------|---------|-----|
| 87 | CWE-798 | critical | `CREATE USER 'app'@'%' IDENTIFIED BY 'ChangeMe123'` commits a live password | Source it from the environment at provision time; rotate this credential — it is in git history |
| 142 | CWE-1188 | critical | `DELETE FROM case_events;` has no WHERE clause and no `<rollback>` | Add the WHERE predicate, wrap in `<preConditions>`, write the explicit rollback SQL |
| 203 | CWE-269 | high | `GRANT ALL PRIVILEGES ON *.*` to the runtime account | Grant only SELECT/INSERT/UPDATE on the tables it uses, host-scoped |

Then the verdict, exactly one of:

- **CLEAN** — no finding from the catalog in this file.
- **FINDINGS (n, max severity: <critical|high|medium|low>)** — n rows above.
- **NEEDS-HUMAN** — something material could not be judged from a static
  single-file read. Name it concretely, never as a generic caveat. Real
  examples: the privileges this account actually holds live on the server, not
  in this file; the runtime value of `secure_file_priv` and `bind-address` is
  unknown; whether the caller binds these values as parameters is decided in a
  file not shown; whether the authorization check lives in a decorator defined
  elsewhere; whether a masking step runs between the production dump and the
  environment this seed data feeds; whether the application hashes the password
  before the INSERT. A file can be both FINDINGS and NEEDS-HUMAN — report both.
  When there are **zero** table findings but at least one open
  undecidable item, the verdict is **NEEDS-HUMAN, not CLEAN**: CLEAN is
  reserved for a file where nothing was found *and* nothing was left
  open. Say "0 findings, n open items" so both facts are visible.

Close with the honest reminder, every time, in the user's words not a slogan:

> CLEAN means nothing was found by a static read of this one file. It does not
> mean the file is secure, and it says nothing about the code that calls it, the
> privileges of the account that runs it, or the server it runs against.

## Inviolable rules

- **Report-only.** Never edit, reformat, or "fix while I'm here" the target
  file, and never edit any other file in the repository. Fixes are described in
  the table; applying them is the user's decision.
- **No installs.** Not `pip install`, not `brew install`, not a virtualenv, not
  a plugin — a missing tool is reported as `skipped (not installed)`.
- **No network calls.** No package-registry lookups, no CVE feeds, no fetching
  a changelog. The review is what this file plus its local context supports.
- **Never execute the code under review** — no database connection, no
  migration run, no invocation of the calling application.
- **Never soften, merge away, or omit a finding** because it is awkward, because
  the file is "just a dev fixture", or because the user pushed back. Severity is
  the catalog's, not the user's.
- **Every finding cites a line that exists** in the file as read. No inferred,
  approximate, or remembered line numbers.
- **If a file cannot be read, say so and stop** for that file. Do not review a
  guess, and do not substitute a similarly named file.
- Never claim the file, the schema, or the application is secure. The strongest
  statement available is CLEAN as defined above.

## Installation

Copy this directory to `~/.claude/skills/security-sql/`.
