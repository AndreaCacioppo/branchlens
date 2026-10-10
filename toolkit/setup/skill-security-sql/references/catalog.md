# security-sql — vulnerability catalog

Scope: SQL as it appears in this kind of stack — schema and DDL files, seed data,
hand-written application queries at a host-language boundary (typically
Python/Flask), stored routines, Liquibase changesets, and ad-hoc analyst queries
over epidemiological / health-adjacent data. Dialect: MariaDB/MySQL.

Ordered by severity, then by vibe-coding frequency inside each severity band.
Work top down. Each section gives: what the class is, the concrete patterns it
takes in this dialect, how to detect it while reading a single file, and the
canonical fix.

Severity ladder used here:

- **critical** — direct data compromise, credential exposure, or data
  destruction, with no further condition required.
- **high** — compromise given one plausible additional condition (a leaked
  credential, one injection point, one careless export).
- **medium** — meaningful weakening that usually needs to be chained with
  another issue, or a defence-in-depth gap.
- **low** — hygiene and incident-response gaps: they do not create the breach,
  they make it worse or unexplainable afterwards.

## Index

| # | Class | CWE | Severity | Vibe freq |
|---|-------|-----|----------|-----------|
| 1 | SQL injection via string-concatenated queries at the host-language boundary | CWE-89 | critical | very-high |
| 2 | Hardcoded credentials / secrets in schema, seed data, or connection code | CWE-798, CWE-259 | critical | very-high |
| 3 | Migration DELETE/UPDATE without WHERE, or unguarded DROP | CWE-1188, CWE-664 | critical | high |
| 4 | Dynamic SQL inside stored routines (PREPARE/EXECUTE injection) | CWE-89 | critical | medium |
| 5 | Missing authorization / row-level access control (IDOR) | CWE-639, CWE-862, CWE-863 | high | very-high |
| 6 | Excessive / wildcard database privileges | CWE-269, CWE-732 | high | high |
| 7 | Plaintext or weakly-hashed password storage | CWE-256, CWE-916, CWE-327 | high | high |
| 8 | Second-order SQL injection through stored, later-reused data | CWE-89 | high | medium |
| 9 | PII / health-data exposure through SELECT *, views, or dumps | CWE-200, CWE-359 | high | medium |
| 10 | Insecure MySQL/MariaDB server defaults left in place | CWE-1188, CWE-276, CWE-732 | high | medium |
| 11 | FILE privilege / LOAD DATA INFILE / SELECT INTO OUTFILE abuse | CWE-73, CWE-269 | high | low |
| 12 | Sensitive data logged or exposed via verbose SQL errors | CWE-209, CWE-532 | medium | high |
| 13 | Unsafe dynamic ORDER BY / LIMIT / identifier interpolation | CWE-89 | medium | high |
| 14 | Missing schema-level input validation / constraints | CWE-20, CWE-1287 | medium | medium |
| 15 | CORS / API-layer permissiveness exposing query endpoints | CWE-942 | medium | medium |
| 16 | Typosquatted / hallucinated DB driver or ORM package | CWE-1357, CWE-829 | medium | medium |
| 17 | CSV / report injection into spreadsheet formulas | CWE-1236 | medium | low |
| 18 | Weak transport and at-rest encryption for connections and backups | CWE-319, CWE-311 | medium | low |
| 19 | MySQL native AES_ENCRYPT/ENCRYPT with hardcoded or weak keys | CWE-321, CWE-798 | medium | low |
| 20 | Missing / weak audit trail for privileged or bulk operations | CWE-778 | low | low |
| 21 | Unbounded / overly broad analyst queries (resource exhaustion) | CWE-400 | low | low |

---

# Critical

## 1. SQL injection via string-concatenated queries at the host-language boundary — CWE-89 — A03:2021 Injection

**Severity:** critical  **Vibe-coding frequency:** very-high

User input (Flask request args/form/JSON, or values passed into SQL that
Liquibase executes) is concatenated, f-string-interpolated, or `.format()`-ed
directly into a SQL string instead of being bound as a parameter. The attacker
alters query *structure*, not just values: UNION-based exfiltration of patient
records, boolean/time-based blind extraction, authentication bypass.

**What it looks like**

- `cursor.execute(f"SELECT * FROM patients WHERE id = {pid}")`
- `cursor.execute("SELECT ... WHERE name = '" + user_input + "'")`
- `%`-formatting applied *before* execute: `cursor.execute(query % params)`
  instead of `cursor.execute(query, params)` — the two look almost identical and
  only the second binds.
- Table, column, `ORDER BY` or `LIMIT` fragments built from a request parameter
  with no allow-list (see also class 13).
- Analyst notebook queries built with `pandas.read_sql(f"...{value}...")`.

**Detecting it in a single file**

- Look for f-strings, `+`, `%`, or `.format(` immediately inside `.execute(`,
  `.executemany(`, `.executescript(`, or `read_sql(`.
- Flag any `.execute(` whose first argument is not a plain string literal (or a
  module-level constant) **and** which has no second `params` tuple/dict
  argument. No second argument means nothing was bound.
- Grep the file for `WHERE.*{` and `WHERE.*" +`.
- In a `.sql` file: a query fragment ending mid-string, or a comment saying the
  value is substituted by the caller, is the same finding one file away — record
  it as NEEDS-HUMAN if the caller is not visible.

**Canonical fix**

Always parameterize: `cursor.execute(sql, (val1, val2))` with `%s` placeholders
(MySQLdb / mysql-connector / PyMySQL all use `%s`, not `?`). For identifiers
that cannot be bound — table and column names — validate against a hardcoded
allow-list and never interpolate raw input.

---

## 2. Hardcoded credentials / secrets in schema, seed data, or connection code — CWE-798, CWE-259 — A07:2021 Identification and Authentication Failures

**Severity:** critical  **Vibe-coding frequency:** very-high

Database passwords, API keys, or a Flask `SECRET_KEY` embedded directly in
`.sql` seed files, Liquibase changelogs, or source. Usually a leftover from a
generated example or the first prototype that worked. Once committed, the
credential is in history and must be treated as compromised even after removal.

**What it looks like**

- `CREATE USER 'app'@'%' IDENTIFIED BY 'literal-password';` in a checked-in
  migration.
- `GRANT ... IDENTIFIED BY 'literal'` inside a Liquibase `<sql>` changeset.
- `mysql.connector.connect(host=..., user=..., password="changeme123")` with a
  string literal instead of `os.environ[...]`.
- Seed/fixture data carrying real-looking emails and passwords copied from an
  example rather than synthetic test values.

**Detecting it in a single file**

- Case-insensitive search for `identified by '` / `identified by "` across
  `.sql`, `.xml`, `.yaml` changelogs.
- Search for `password` followed by `=` and a quote, near a `connect(` call.
- Check seed data for credentials or personal-looking values that are not
  obviously synthetic.
- A value read from an environment variable *with a literal fallback*
  (`os.environ.get("DB_PASS", "devpass")`) is still this finding.

**Canonical fix**

Load credentials from environment variables or a secrets manager. Never commit
`IDENTIFIED BY 'literal'`. Rotate any credential found, including ones already
deleted from the working tree but present in history.

---

## 3. Migration DELETE/UPDATE without WHERE, or unguarded DROP, in Liquibase changesets — CWE-1188, CWE-664 — A04:2021 Insecure Design

**Severity:** critical  **Vibe-coding frequency:** high

A `<sql>` or raw-SQL changeset runs `DELETE FROM table;` or
`UPDATE table SET col = val;` with no WHERE clause, or drops a table/column with
no precondition and no backup step. One release silently wipes or corrupts an
entire table of epidemiological data in every environment the changelog runs
against. This is data destruction, not data disclosure — but the blast radius is
the same table.

**What it looks like**

- `DELETE FROM cases;` or `UPDATE cases SET status = 'closed';` with no trailing
  WHERE in a changeset.
- `DROP TABLE patients_old;` or `ALTER TABLE ... DROP COLUMN ...` with no
  preceding `<preConditions>` check and no matching `<rollback>` block.
- A changeset reusing an `id` across environments, so destructive logic can
  silently re-execute if checksum validation is bypassed.
- `runAlways="true"` or `runOnChange="true"` on a destructive changeset.

**Detecting it in a single file**

- Find every `DELETE FROM` and `UPDATE ... SET` and confirm a `WHERE` clause is
  present on that same statement — not on a neighbouring one. Statements split
  over several lines hide this; read to the terminating semicolon.
- Find every `DROP TABLE`, `DROP COLUMN`, `TRUNCATE` and check for a paired
  `<rollback>` or a precondition guard.
- Check the changeset attributes for `runAlways` / `runOnChange`.
- `WHERE 1=1` is not a WHERE clause. Flag it for review.

**Canonical fix**

Require a real WHERE on every DELETE/UPDATE, wrap destructive changes in
`<preConditions>`, write explicit `<rollback>` SQL for every changeset that can
lose data, and take a backup/snapshot step before any DROP in a changelog that
reaches production.

---

## 4. Dynamic SQL inside stored routines built from unvalidated input (PREPARE/EXECUTE injection) — CWE-89 — A03:2021 Injection

**Severity:** critical  **Vibe-coding frequency:** medium

A stored procedure or function concatenates one of its parameters into a string
and runs it through `PREPARE ... FROM @sql; EXECUTE stmt;`. This reintroduces
injection *inside* the database even when the outer call from the application
was correctly parameterized — a common blind spot, because the calling code
looks safe. Placeholders bound via `EXECUTE ... USING` are safe for values;
anything built with `CONCAT()` from a routine argument is not.

**What it looks like**

- `SET @sql = CONCAT('SELECT * FROM ', tbl_name); PREPARE stmt FROM @sql;`
  where `tbl_name` is an IN parameter of the routine.
- `ORDER BY` / `LIMIT` / table-name clauses assembled by string concatenation
  inside a procedure instead of bound with `EXECUTE ... USING`.
- `EXECUTE stmt;` with no `USING`, where the data values were baked into `@sql`.

**Detecting it in a single file**

- Search the schema/migration file for `PREPARE` and read backwards to the
  `SET @sql = CONCAT(` that built it; trace whether any routine parameter feeds
  the concatenation.
- Confirm every `EXECUTE stmt` has a matching `USING @var1, @var2` carrying the
  actual data values, rather than those values appearing inside the SQL text.
- Check whether the routine's `DEFINER`/`SQL SECURITY` setting means the dynamic
  statement runs with more privilege than the caller has.

**Canonical fix**

Use PREPARE/EXECUTE only when genuinely necessary (dynamic table or column
names). Bind every literal value through `EXECUTE ... USING`, and validate any
dynamic identifier against an allow-list of known table/column names before it
reaches `CONCAT`.

---

# High

## 5. Missing authorization / row-level access control on query endpoints (IDOR) — CWE-639, CWE-862, CWE-863 — A01:2021 Broken Access Control

**Severity:** high  **Vibe-coding frequency:** very-high

A route queries a case or patient by an ID taken straight from the URL or
request body, with no check that the caller is entitled to that row. The query
is syntactically perfect and fully parameterized — and returns anyone's record.
This is the single most reliable failure mode of generated code, because
generation optimises for "does the query run", not "is this row scoped to the
caller".

**What it looks like**

- `@app.route('/case/<int:case_id>')` whose handler runs
  `cursor.execute("SELECT * FROM cases WHERE id=%s", (case_id,))` with no
  ownership or role predicate and no preceding access check.
- A new CRUD endpoint copy-pasted from a sibling endpoint, with the
  auth decorator or the tenant/user filter dropped in the copy.
- A bulk export or report endpoint whose only check is "is logged in", with no
  per-row access filter.

**Detecting it in a single file**

- For each route taking an id or a filter parameter, check whether the SQL WHERE
  clause carries a user/role/ownership predicate, or whether an explicit
  authorization check precedes the query.
- Compare a new endpoint against its siblings in the same file: an auth
  decorator present on three handlers and absent on the fourth is the finding.
- Look for routes with path parameters (`<int:...>`) whose handler's first
  statement is the DB call, with no `@login_required` / `@require_role` above.
- In a pure `.sql` file, the equivalent is a view or query with no tenant/owner
  column in its WHERE clause — record NEEDS-HUMAN if the filter could be applied
  by the caller.

**Canonical fix**

Add an explicit ownership/role predicate to every query keyed by an externally
supplied ID, or an authorization check before it. Add a test asserting that a
second user's token cannot read the first user's row.

---

## 6. Excessive / wildcard database privileges (violates least privilege) — CWE-269, CWE-732 — A01:2021 Broken Access Control

**Severity:** high  **Vibe-coding frequency:** high

The application's DB user (or an analyst account) is granted `ALL PRIVILEGES ON
*.*` instead of the verbs it actually needs, and/or granted from `'%'` (any
host). One injection point or one leaked credential then yields full database or
host compromise, via `FILE`, `CREATE USER`, or `GRANT OPTION`.

**What it looks like**

- `GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';`
- The runtime connection user holding `SUPER`, `FILE`, `GRANT OPTION`, or
  `CREATE USER` that it never exercises.
- A "read-only" analyst account that also carries `INSERT`/`UPDATE`/`DELETE`/
  `DROP`.

**Detecting it in a single file**

- Search every `GRANT` for `ALL PRIVILEGES`, `*.*`, or `@'%'`.
- Check whether the application's connection user is the same as the
  schema-owning / migration user — it should not be.
- Check for `WITH GRANT OPTION` on any non-admin account.

**Canonical fix**

Create per-purpose accounts — app-runtime, migration, analyst-readonly — each
scoped to specific databases and tables and specific verbs, bound to specific
hosts, with no FILE, SUPER, or GRANT OPTION.

---

## 7. Plaintext or weakly-hashed password / PII storage — CWE-256, CWE-916, CWE-327 — A02:2021 Cryptographic Failures

**Severity:** high  **Vibe-coding frequency:** high

A `users` table stores passwords in plaintext, or hashed with MySQL's
`PASSWORD()`, `ENCRYPT()`, `MD5()`, or `SHA1()` — fast, unsalted, broken — rather
than an application-level slow hash (bcrypt/Argon2/scrypt) applied before the
value ever reaches the database. Typically copied from tutorials old enough that
the model trained on them.

**What it looks like**

- `password VARCHAR(32)` (MD5 length) or `VARCHAR(41)` (legacy `PASSWORD()`
  length) in a CREATE TABLE.
- `INSERT INTO users (..., password) VALUES (..., MD5(?))`, `SHA1(?)`, or
  `PASSWORD(?)` in a query or a migration.
- No salt column, plus a hash column too short for bcrypt (60 chars) or Argon2.

**Detecting it in a single file**

- In the schema, find any `password` / `pwd` / `passwd` column and check its
  declared length: `CHAR(32)`, `CHAR(40)`, `CHAR(41)` are MD5 / SHA1 / legacy
  `PASSWORD()` fingerprints.
- Search for `MD5(`, `SHA1(`, `PASSWORD(`, `ENCRYPT(` applied to anything that
  is a credential.
- Confirm the column is sized for the chosen algorithm's output and that hashing
  happens in the application (bcrypt / passlib / argon2), not in SQL. If the
  application side is not visible, that half is NEEDS-HUMAN.

**Canonical fix**

Hash in the application with bcrypt or Argon2 before storage. Never use MySQL's
`PASSWORD()`/`ENCRYPT()`/`MD5()`/`SHA1()` for credentials. Size the column for
the algorithm's real output.

---

## 8. Second-order SQL injection through stored, later-reused data — CWE-89 — A03:2021 Injection

**Severity:** high  **Vibe-coding frequency:** medium

Input is correctly parameterized on write, then a later query rebuilds SQL by
concatenating that already-stored value — a saved search fragment, a custom
report filter, a user-chosen label. The payload sits harmlessly in a column until
it is replayed into a second, unparameterized statement. Reviews miss it because
the write path looks textbook-correct.

**What it looks like**

- A `filter_expression` / `custom_label` / `saved_query` column later
  concatenated into a new SQL string for a report or a dynamically built view.
- Admin or analyst "saved search" features that persist raw SQL fragments and
  splice them into `WHERE` / `ORDER BY` later.

**Detecting it in a single file**

- Trace any column populated from user input that is later read back and
  concatenated into a fresh `.execute(f"...{stored_value}...")` or into a
  `CONCAT()` inside a stored routine.
- Look for saved-search / report-builder features and check whether the
  reconstruction step binds parameters or re-concatenates.
- Any column whose *name* suggests it holds an expression, filter, or clause is
  worth following even without a visible read path — flag as NEEDS-HUMAN.

**Canonical fix**

Re-parameterize on every reuse of stored data in SQL construction. Treat stored
values as exactly as untrusted as fresh request input.

---

## 9. PII / health-data exposure through overly broad SELECT *, views, or dumps — CWE-200, CWE-359 — A01:2021 Broken Access Control / A04:2021 Insecure Design

**Severity:** high  **Vibe-coding frequency:** medium

Views, API-backing queries, or exports return full patient/case rows — name,
address, diagnosis — to callers or environments that only need aggregates or
de-identified fields, because `SELECT *` replaced an explicit column list, or
because a production dump was reused unmasked to seed a dev, test, or analyst
environment.

**What it looks like**

- A route handler running `SELECT * FROM cases JOIN patients ...` and returning
  the raw row into a JSON response.
- A reporting `VIEW` defined as `SELECT *` over a PII-bearing table instead of an
  explicit, minimized column list.
- A `mysqldump` of production used to seed a non-production database or handed to
  an analyst, with no `--where` filter and no masking step.

**Detecting it in a single file**

- Search for `SELECT *` (and `SELECT t.*`) feeding a response or serializer.
- Find every `CREATE VIEW` and check whether the select list is explicit.
- Check whether a documented or scripted masking / pseudonymization step exists
  between any production dump and a non-production consumer. If the file is the
  dump or the seed, and the masking script is not visible, this is NEEDS-HUMAN.

**Canonical fix**

Enumerate the needed columns explicitly in every view and every query crossing a
trust boundary. Build a masking/pseudonymization step for any dump leaving the
production access-controlled boundary.

---

## 10. Insecure MySQL/MariaDB server defaults left in place — CWE-1188, CWE-276, CWE-732 — A05:2021 Security Misconfiguration

**Severity:** high  **Vibe-coding frequency:** medium

A freshly stood-up instance keeps its install-time state: empty or absent root
password, anonymous accounts, `bind-address` open on all interfaces paired with
`'%'` grants, the `test` database still present. The usual path is a
dev-convenience container config that later gets pointed at real data.

**What it looks like**

- `docker-compose.yml` or Dockerfile with `MYSQL_ALLOW_EMPTY_PASSWORD=yes`, or
  no `MYSQL_ROOT_PASSWORD` at all.
- A schema dump still showing anonymous (`''`) users, the `test` database, or
  `root@'%'` — no sign that `mysql_secure_installation` or an equivalent
  hardening step ever ran.
- `bind-address = 0.0.0.0` in `my.cnf` with no firewall/VPC restriction, next to
  a `'%'`-host grant.

**Detecting it in a single file**

- In compose/env files: search for `MYSQL_ALLOW_EMPTY_PASSWORD` and for a missing
  `MYSQL_ROOT_PASSWORD`.
- In a `mysql.user` dump, if present: anonymous users, or root with an empty
  `authentication_string`.
- In config files: read the `bind-address` value and cross-check it against the
  host scoping of the GRANTs in the schema. The live server value cannot be read
  from the file — say so as NEEDS-HUMAN.

**Canonical fix**

Put the `mysql_secure_installation` equivalents into the provisioning script.
Require a strong root password even in dev containers. Never let a
dev-convenience empty-password config reach a shared or production environment.

---

## 11. FILE privilege / LOAD DATA INFILE / SELECT INTO OUTFILE abuse — CWE-73, CWE-269 — A05:2021 Security Misconfiguration

**Severity:** high  **Vibe-coding frequency:** low

An account holds the `FILE` privilege, or `secure_file_priv` is empty/unset,
allowing arbitrary filesystem reads (`LOAD DATA INFILE`, `LOAD_FILE()`) and
writes (`SELECT ... INTO OUTFILE`). Combined with any injection point from class
1, 4, 8 or 13, this becomes remote file read/write on the database host.

**What it looks like**

- `GRANT FILE ON *.* TO ...` for an application or analyst user with no
  legitimate filesystem need.
- `secure_file_priv=''` in `my.cnf` (empty means unrestricted), or the variable
  absent/commented out entirely.
- Application or analyst code building a `LOAD DATA LOCAL INFILE` path from
  user-influenced input.

**Detecting it in a single file**

- Search every GRANT for the `FILE` privilege and note which accounts hold it.
- In config: find `secure_file_priv` and confirm it names a restricted
  directory, not an empty string. Absent means default — which varies by build,
  so report it as NEEDS-HUMAN rather than assuming.
- Search app code for `LOAD DATA`, `INTO OUTFILE`, `LOAD_FILE(` and check
  whether any part of the path or filename comes from a request.

**Canonical fix**

Never grant FILE to application or analyst accounts. Set `secure_file_priv` to a
dedicated, non-web-accessible directory. Never build LOAD DATA / OUTFILE paths
from request input.

---

# Medium

## 12. Sensitive data logged or exposed via verbose SQL errors — CWE-209, CWE-532 — A09:2021 Security Logging and Monitoring Failures / A05:2021 Security Misconfiguration

**Severity:** medium  **Vibe-coding frequency:** high

Debug mode, or a broad `except` that returns the exception text, hands raw MySQL
error output to the client — the failing query, table and column names,
sometimes the literal parameter values. Schema disclosure at minimum; PII
disclosure whenever the failing query carried patient data.

**What it looks like**

- `app.run(debug=True)` left in, or `FLASK_DEBUG=1` in a deployed config,
  exposing the interactive debugger and full tracebacks including SQL text.
- `except MySQLdb.Error as e: return jsonify(error=str(e))` returned straight to
  the HTTP client.
- `print(f"Query failed: {sql} with {params}")` into a shared or unrestricted log.

**Detecting it in a single file**

- Search for `debug=True` and `FLASK_DEBUG` in the entrypoint or config.
- In every `except` around a DB call, check whether `str(e)` / `repr(e)` /
  the traceback flows into a `jsonify`, `return`, or `render_template`.
- Check logging calls near `.execute(` for interpolated `sql` or `params`
  variables — bound parameters are the ones most likely to hold PII.

**Canonical fix**

Disable debug mode outside local development. Catch DB exceptions, return a
generic message to the client, and log full detail only to an access-controlled
store. Never log bound parameter values that may contain personal data.

---

## 13. Unsafe dynamic ORDER BY / LIMIT / identifier interpolation without allow-listing — CWE-89 — A03:2021 Injection

**Severity:** medium  **Vibe-coding frequency:** high

Sort column, sort direction, table name, or LIMIT/OFFSET arrive from the query
string and are interpolated directly — because these positions genuinely cannot
be bound as placeholders — with no validation against a fixed set of legal
values. Generators default to naive interpolation here precisely because the
safe pattern is not the obvious one.

**What it looks like**

- `cursor.execute(f"SELECT * FROM cases ORDER BY {sort_col} {sort_dir} LIMIT {limit}")`
  with all three from `request.args`.
- Pagination code interpolating `page * page_size` computed from user input
  straight into LIMIT/OFFSET with no bounds check.

**Detecting it in a single file**

- Search for `ORDER BY {`, `LIMIT {`, `OFFSET {`, and the concatenated
  equivalents, then trace the variable back to `request.args` / `request.form` /
  JSON body.
- Check whether sort column names pass through a hardcoded dict or list before
  use. A regex "sanitizer" is not an allow-list — flag it.

**Canonical fix**

Map incoming sort/limit parameters through a fixed allow-list dict
(`{'name': 'patients.name', ...}`) before interpolation, defaulting to a safe
value on a miss. Validate LIMIT/OFFSET as bounded integers.

---

## 14. Missing schema-level input validation / constraints (defense-in-depth gap) — CWE-20, CWE-1287 — A04:2021 Insecure Design

**Severity:** medium  **Vibe-coding frequency:** medium

Columns holding bounded categorical epidemiological data — status, region code,
test result — are declared as free `VARCHAR` with no `ENUM` or `CHECK`
constraint and no matching application-side validation. Malformed values reach
reports and downstream analyst queries, and the application ends up trusting DB
content to be well-formed when nothing enforces that.

**What it looks like**

- `status VARCHAR(50)` with no `CHECK (status IN (...))` and no allow-list check
  in the handler before INSERT.
- Foreign-key-like columns (`region_id`, `facility_id`) stored as free text
  instead of an INT FK to a lookup table.

**Detecting it in a single file**

- In CREATE TABLE statements, find VARCHAR columns whose name clearly denotes a
  small fixed category, and check for a CHECK/ENUM constraint.
- Check whether the corresponding insert/update path validates against the same
  allowed set. If that path is not in this file, record it as NEEDS-HUMAN.

**Canonical fix**

Add CHECK constraints or ENUM types for bounded categorical columns, and mirror
the same allow-list validation in the application layer — both, not either.

---

## 15. CORS / API-layer permissiveness exposing query endpoints — CWE-942 — A05:2021 Security Misconfiguration

**Severity:** medium  **Vibe-coding frequency:** medium

Not SQL itself, but the applications backing these queries are routinely
generated with wildcard CORS, so any authenticated session cookie or token can
be used cross-origin against endpoints returning health data. It widens the
blast radius of every other class in this catalog — especially IDOR (5) and
injection (1).

**What it looks like**

- `CORS(app)` with no explicit `origins` restriction, or `origins="*"` alongside
  `supports_credentials=True`.

**Detecting it in a single file**

- Search the app entrypoint or config for `CORS(` and read the `origins` value.
  Flag `"*"` whenever any cookie or session-based authentication is in use.

**Canonical fix**

Restrict CORS origins to the known frontend origin(s). Never combine a wildcard
origin with credentialed requests.

---

## 16. Typosquatted / hallucinated DB driver or ORM package (slopsquatting) — CWE-1357, CWE-829 — A06:2021 Vulnerable and Outdated Components

**Severity:** medium  **Vibe-coding frequency:** medium

An assistant suggests installing a MySQL connector or migration helper whose
package name does not exist, or is a near-miss of the real one. If an attacker
has registered that name, install-time code runs with full access to the
environment — including the database credentials sitting in it.

**What it looks like**

- A DB-related entry in `requirements.txt` / `Pipfile` / `pyproject.toml` that
  is not one of the well-known names (`mysqlclient`, `PyMySQL`,
  `mysql-connector-python`, `SQLAlchemy`), added without prior use.
- A dependency added on the strength of a suggestion, with no check of the
  project's real maintainer or download history.

**Detecting it in a single file**

- Read every DB-related dependency name in the manifest next to the file under
  review and compare it, character by character, against the canonical names.
- Treat a very recently first-published or very low-download package as
  suspicious — but note that confirming this requires a registry lookup, which
  this skill does not perform: report it as NEEDS-HUMAN with the exact package
  name to check.

**Canonical fix**

Verify any suggested package name against the official project page and its
maintainer/history before adding it. Prefer the well-known drivers.

---

## 17. CSV / report injection into spreadsheet formulas from query results — CWE-1236 — A03:2021 Injection

**Severity:** medium  **Vibe-coding frequency:** low

Analyst-facing exports built from SELECT results are written without escaping
cells that begin with `=`, `+`, `-`, or `@`. Opening the export in a spreadsheet
executes attacker-controlled formulas — the payload having been stored earlier
in an innocuous free-text field such as a case note.

**What it looks like**

- `csv.writer` or `to_csv` dumping a notes/comments/name column straight from a
  query result with no leading-character check.
- Report generation (`SELECT notes FROM cases`) piped directly into a `.csv`
  handed to analysts.

**Detecting it in a single file**

- Find `csv.writer` / `to_csv` fed directly by a DB result with no sanitization
  step on string columns.
- List the exported free-text columns and ask which of them a user can write.

**Canonical fix**

Prefix any exported cell value starting with `=`, `+`, `-`, or `@` with a single
quote before writing it to the CSV.

---

## 18. Weak / legacy transport and at-rest encryption for DB connections and backups — CWE-319, CWE-311 — A02:2021 Cryptographic Failures

**Severity:** medium  **Vibe-coding frequency:** low

The application or analyst tooling connects to MariaDB over an unencrypted
socket, or backups containing health data are written unencrypted to shared
storage. Personal data in transit or in an unprotected file.

**What it looks like**

- A `connect()` call or connection string with no `ssl` / `ssl_mode` parameter on
  a connection that crosses a network boundary — or with `ssl_disabled=True`.
- `mysqldump ... > backup.sql` writing to a shared or world-readable path with no
  subsequent encryption step.

**Detecting it in a single file**

- In connection setup, look for `ssl_mode` / `ssl_disabled` and confirm TLS is
  not explicitly disabled for a non-localhost host. Whether the host is really
  remote may not be visible in the file — say so.
- In deployment/backup scripts, find `mysqldump` and check whether the output is
  encrypted and permission-restricted.

**Canonical fix**

Require TLS (`ssl_mode=REQUIRED` or equivalent) for any non-localhost
connection. Encrypt backup files at rest and restrict their filesystem
permissions.

---

## 19. Use of MySQL native AES_ENCRYPT/ENCRYPT with hardcoded or weak keys for PII fields — CWE-321, CWE-798 — A02:2021 Cryptographic Failures

**Severity:** medium  **Vibe-coding frequency:** low

Sensitive fields are "encrypted" with `AES_ENCRYPT(col, 'literal-key')`, the key
embedded in the SQL text — and therefore in every query, migration, changelog,
slow-query log, and version-control revision. The encryption is decorative: the
key travels with the ciphertext.

**What it looks like**

- `AES_ENCRYPT(ssn, 'my-secret-key')` with the key as a string literal inside a
  query or a view definition.
- A fixed or absent IV across rows, so identical plaintexts produce identical
  ciphertexts and patterns leak.

**Detecting it in a single file**

- Search for `AES_ENCRYPT(`, `AES_DECRYPT(`, `ENCRYPT(` and inspect whether the
  key argument is a string literal.
- Check whether the same key literal recurs across queries or files — it should
  be a single externally-sourced parameter, not a repeated constant.

**Canonical fix**

Encrypt PII at the application layer with a key from a secrets manager or KMS,
never as a literal inside SQL text that ends up in logs, changelogs, and version
control. Vary the IV per row.

---

# Low

## 20. Missing / weak audit trail for privileged or bulk data operations — CWE-778 — A09:2021 Security Logging and Monitoring Failures

**Severity:** low  **Vibe-coding frequency:** low

Tables holding case data have no `created_by` / `updated_by` / timestamp
columns, and no server-side audit logging. A bulk UPDATE or DELETE — malicious,
accidental, or a bad migration from class 3 — leaves no record of who ran it or
what changed. It does not cause the incident; it makes the incident
unreconstructable.

**What it looks like**

- CREATE TABLE for personal/health data with no `updated_at` / `updated_by`, no
  trigger, and no companion audit table.
- No audit plugin or equivalent query logging enabled on the instance handling
  this data.

**Detecting it in a single file**

- Check CREATE TABLE statements for the absence of audit columns on tables
  holding personal or health data.
- In server config, look for audit-plugin or `general_log` settings. The live
  server state is not knowable from the file — report it as NEEDS-HUMAN.

**Canonical fix**

Add `updated_by` / `updated_at` — and ideally an append-only audit table or
trigger — to sensitive tables. Enable server-side audit logging for privileged
and bulk operations.

---

## 21. Unbounded / overly broad analyst queries risking resource exhaustion — CWE-400 — A05:2021 Security Misconfiguration

**Severity:** low  **Vibe-coding frequency:** low

Ad-hoc analyst queries or a report endpoint run unbounded joins and full-table
scans with no LIMIT and no statement timeout, against the same instance serving
the live application. A mild but real availability risk on a small deployment
where analysts and the application share one database.

**What it looks like**

- Analyst SQL with multi-table JOINs and no LIMIT over large case/event tables,
  run against the production instance.
- No `max_execution_time` or per-account resource limits configured for the
  analyst connection.

**Detecting it in a single file**

- Check whether the analyst-facing query or tooling enforces a default LIMIT and
  a timeout.
- In server/account config, look for `max_execution_time` or per-user limits
  such as `MAX_QUERIES_PER_HOUR`.

**Canonical fix**

Set a statement/execution timeout and a default LIMIT for analyst accounts.
Consider a read replica for ad-hoc analyst workloads so they cannot affect the
production application.

---

# Appendix A — vibe-coding top ten, mapped to classes

The mistakes AI-generated SQL and SQL-adjacent code reproduce most reliably, in
rough order of how often they appear. Step 5 of the skill re-scans for these
specifically, even after the full catalog walk.

1. Missing row-level authorization (IDOR) on newly generated CRUD/query
   endpoints — the query works, the ownership predicate is absent → class 5.
2. String-concatenated / f-string SQL instead of bound parameters, especially in
   short route handlers and analyst notebook snippets → class 1.
3. Hardcoded credentials: DB passwords, `GRANT ... IDENTIFIED BY` literals,
   `SECRET_KEY` left in example or seed code → class 2.
4. Verbose error handling returning raw SQL exception text to the client, plus
   debug mode left enabled → class 12.
5. Unsafe dynamic ORDER BY / LIMIT / identifier interpolation with no allow-list,
   because those positions genuinely cannot be parameterized → class 13.
6. Migration changesets with DELETE/UPDATE missing WHERE, or DROP with no
   rollback or precondition — especially from "write a migration to clean up X"
   → class 3.
7. Typosquatted or hallucinated package suggested for a DB driver or migration
   helper → class 16.
8. Excessive privileges for the application's DB user (GRANT ALL, wildcard host)
   because it is the fastest way to make generated code work → class 6.
9. Weak or legacy password hashing (MD5 / SHA1 / MySQL `PASSWORD()`) copied from
   outdated tutorials → class 7.
10. Permissive CORS (`origins="*"` with credentials) pasted as a generic fix for
    a cross-origin error during scaffolding → class 15.

# Appendix B — tooling beyond this skill's procedure

The skill's own mechanical pass uses **sqlfluff only**
(`sqlfluff lint --dialect mysql <file>`), and only if it is already installed.
The tools below are **not part of the procedure** and must not be run or
installed by it — they are listed so a finding's fix can name the right
follow-up for the user to run themselves:

- **Semgrep** (`p/sql-injection`, `p/flask` rulesets) — flags f-string/concat SQL
  execution and unsafe `cursor.execute` patterns on the application side.
  Already covered repo-wide by `preflight-gate`.
- **Bandit** — rule B608, "possible SQL injection via string-based query
  construction", on Python files.
- **Liquibase quality checks** (`liquibase checks run --changelog-file=...`) —
  catches missing rollbacks and some destructive-change patterns in a changelog.
- **MariaDB Audit Plugin** — not a scanner; it closes the class 20 gap by making
  bulk and privileged operations attributable server-side.
- **Percona Toolkit** (`pt-fingerprint`, `pt-query-digest`) — after-the-fact
  auditing of analyst query logs for unbounded or anomalous queries (class 21).

# Sources

- CISA / MITRE 2024 CWE Top 25 Most Dangerous Software Weaknesses.
- OWASP Top 10:2021, A03:2021 Injection.
- OWASP SQL Injection Prevention Cheat Sheet.
- MariaDB Knowledge Base: Prepared Statements, GRANT, `secure_file_priv`.
- MySQL 8.0/9.x Reference Manual: LOAD DATA, Password Hashing, Security in MySQL.
- Published analyses of stored-procedure SQL injection and MySQL/MariaDB
  hardening practice.
- Liquibase documentation and published guidance on rollbacks and bad database
  changes.
- 2025 research on SQL injection in LLM-generated queries, and empirical studies
  of security in LLM responses to programming questions.
- General knowledge of MySQL/MariaDB internals, Liquibase changelog semantics,
  and health-data pseudonymization practice, used where primary sources gave
  only summaries — noted per class where it affects the detection hints.
