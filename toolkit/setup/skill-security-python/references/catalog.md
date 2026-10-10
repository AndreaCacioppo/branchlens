# Python vulnerability catalog

The checklist for step 4 of `security-python`. One section per class, ordered
by severity (critical → high → medium → low) and, inside each tier, by how
often AI-generated Python gets that class wrong.

Each section gives: what the class is, what it looks like in Python, how to
spot it while reading a single file, and the canonical fix. Work top to bottom
and mark each class present / absent / not applicable.

Sources: CWE Top 25 (2024 and 2025 editions), OWASP Top 10:2021 (all `A0x`
labels below are the 2021 edition), Bandit and Semgrep rule documentation,
Veracode's 2025 GenAI Code Security Report, Cloud Security Alliance notes on
vibe-coding security debt, slopsquatting writeups (2025-2026), Sonar's Jupyter
notebook research, CVE-2007-4559 (tarfile), defusedxml/lxml guidance, and
flask-cors wildcard-origin advisories.

---

## CRITICAL

### 1. SQL injection via string-built queries — CWE-89 — A03:2021

**Severity:** critical · **Vibe-coding frequency:** very-high

User- or file-derived values are interpolated directly into SQL text (raw
`cursor.execute`, or pandas `read_sql`/`to_sql`) instead of being passed as
bound parameters, letting an attacker alter the query's structure.

**What it looks like in Python**

```python
cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
cursor.execute("... WHERE name = '%s'" % name)
db.session.execute(text(f"UPDATE t SET x={val}"))
pd.read_sql(f"SELECT * FROM {table} WHERE id={rid}", conn)
```

**Detecting it in a single file**

- `execute(f"` , or `execute("` with a `%` or `.format(` in the same call.
- `read_sql(f"` / `read_sql_query(f"`.
- Bandit `B608` hardcoded_sql_expressions.
- Watch for the table name being interpolated: parameters cannot bind an
  identifier, so that case needs an allowlist, not a placeholder.

**Fix:** parameterized queries — `cursor.execute(query, (params,))` — or the
SQLAlchemy ORM / expression language. Never build SQL text with f-strings,
`%` or `.format()` from request-derived data.

### 2. OS / shell command injection — CWE-78, CWE-77, CWE-88 — A03:2021

**Severity:** critical · **Vibe-coding frequency:** very-high

A shell command is assembled from user- or filename-derived strings and run
with `shell=True` or via `os.system`/`os.popen`; or a `subprocess` argument
list contains an attacker-influenced value that itself looks like a flag.
Common in wrapper scripts that shell out to CLI tools with sample or file
names.

**What it looks like in Python**

```python
subprocess.run(f"samtools view {bam_path}", shell=True)
os.system(f"gunzip {filename}")
subprocess.call(cmd_string, shell=True)
subprocess.run(["tool", user_supplied_flag_or_path])  # unsanitized: flag injection
```

**Detecting it in a single file**

- `shell=True` anywhere.
- `os.system(` / `os.popen(`.
- Any subprocess/os call whose argument contains an f-string or `+`
  concatenation with a request / CLI-arg / filename variable.
- Bandit `B602` subprocess_popen_with_shell_equals_true, `B605`
  start_process_with_a_shell.

**Fix:** call subprocess with `shell=False` and a list of arguments; validate
or allowlist any filename or parameter before use; use `shlex.quote` if a
shell is truly unavoidable. For CLI flags, use a `--` separator or reject
values starting with `-`.

### 3. Hardcoded credentials and secrets in source — CWE-798, CWE-259 — A07:2021 / A02:2021

**Severity:** critical · **Vibe-coding frequency:** very-high

API keys, database passwords or a literal Flask `SECRET_KEY` written straight
into source or default config instead of being loaded from the environment or
a secret store — including example credentials copied from documentation and
left functional.

**What it looks like in Python**

```python
app.config['SECRET_KEY'] = 'dev-secret-123'
API_KEY = 'sk-abc123...'
DATABASE_URL = 'postgresql://user:pass@host/db'
requests.post(url, auth=('admin', 'admin123'))
```

**Detecting it in a single file**

- Case-insensitive `(secret_key|api_key|password|token|passwd)\s*=\s*['"]`.
- Any `SECRET_KEY` / config assignment that is a string literal rather than
  `os.environ.get(...)` or a secrets-manager call.
- Bandit `B105`/`B106`/`B107` hardcoded_password_string / funcarg / default.
- A default argument like `def connect(pw="admin")` counts.

**Fix:** load every secret via `os.environ` / python-dotenv (with `.env`
gitignored) or a secrets manager; generate `SECRET_KEY` randomly per deploy
(`secrets.token_hex(32)`). Anything found hardcoded must be rotated — it is
compromised even after removal.

### 4. Broken or missing access control (IDOR, unprotected endpoints) — CWE-862, CWE-863, CWE-639, CWE-284 — A01:2021

**Severity:** critical · **Vibe-coding frequency:** very-high

A route is added or edited without an authentication/authorization decorator,
or a view fetches and edits a database row by an id taken from the request
without checking that `current_user` may access that object.

**What it looks like in Python**

```python
@app.route('/admin/users/<id>')          # no @login_required, no role check
def edit_user(id): ...

user = User.query.get(request.args['id'])  # no current_user ownership check

@app.route('/api/orders/<order_id>')
def get_order(order_id):
    return Order.query.get(order_id)       # no ownership filter
```

**Detecting it in a single file**

- For **every** `@app.route(...)` / `@bp.route(...)` definition, verify a
  matching `@login_required` / `@roles_required` / explicit `current_user`
  check exists — on the decorator stack or in the body.
- `.query.get(` or `filter_by(id=` right after a `request.args`/`form`/`json`
  read, with no `current_user.id` filter nearby.
- Compare sibling routes in the same file: one protected, one not, is the
  classic signature of a route added later by a model.

**Fix:** an auth decorator on every state-changing or data-returning route;
always scope ORM queries by `current_user.id` (or check ownership explicitly)
before returning or mutating a record. Never trust a client-supplied object id
alone (CWE-639, #24 in the 2025 CWE Top 25).

### 5. Server-side template injection (Jinja2) — CWE-94 — A03:2021

**Severity:** critical · **Vibe-coding frequency:** high

User-controlled text is used to build the *template source* rather than being
passed as render context, letting an attacker reach Python's object model
through Jinja2 syntax and achieve remote code execution.

**What it looks like in Python**

```python
render_template_string(f"Hello {name}")
render_template_string(request.args['tpl'])
jinja2.Template(user_controlled_string).render()
```

**Detecting it in a single file**

- `render_template_string(` — check whether the argument contains an f-string,
  `+`, or `.format()` with request data.
- `Template(` with a variable (not a literal) argument.

**Fix:** never construct template source from user input. Use
`render_template()` with a fixed `.html` file and pass all dynamic data as
context variables, which Jinja2 auto-escapes.

### 6. Insecure deserialization of untrusted data — CWE-502 — A08:2021

**Severity:** critical · **Vibe-coding frequency:** high

`pickle.load/loads`, `yaml.load` without a safe loader, or `joblib.load` called
on data originating outside the process (an uploaded file, a network response,
an unauthenticated cache). All three execute arbitrary Python during
deserialization — a real risk in model-loading and API-client scripts.

**What it looks like in Python**

```python
pickle.load(request.files['model'])
yaml.load(open(config_path), Loader=yaml.Loader)   # or no Loader argument at all
joblib.load(uploaded_file_path)
pd.read_pickle(url_or_uploaded_path)
```

**Detecting it in a single file**

- `pickle.load(` / `pickle.loads(`.
- `yaml.load(` — verify `Loader=yaml.SafeLoader`, or `yaml.safe_load` instead.
- `joblib.load(` / `read_pickle(` on any path or URL that is not a trusted,
  locally-generated file.
- Bandit `B301` pickle, `B506` yaml_load.

**Fix:** always `yaml.safe_load()`; never unpickle data you did not create
yourself; for model artifacts prefer safetensors or JSON, or verify a
signature/hash before loading.

### 7. Weak password hashing / weak authentication secrets — CWE-916, CWE-327 — A02:2021

**Severity:** critical · **Vibe-coding frequency:** high

Passwords hashed with a fast general-purpose digest (MD5, SHA-1, plain
SHA-256) with no salt and no work factor instead of a password-hashing
function; or auth tokens derived from weak material.

**What it looks like in Python**

```python
hashlib.md5(password.encode()).hexdigest()
hashlib.sha256(password.encode()).hexdigest()   # stored directly as the hash
# hand-rolled HMAC/salt scheme instead of werkzeug.security or passlib
```

**Detecting it in a single file**

- `hashlib.md5(` / `hashlib.sha1(` near a variable named `password`, `pwd`,
  `passwd`.
- Confirm the auth code actually calls
  `generate_password_hash` / `check_password_hash` (werkzeug.security), or
  passlib / bcrypt / argon2 — flag its *absence*.
- Bandit `B303`/`B324` weak hash function.

**Fix:** `werkzeug.security.generate_password_hash()` /
`check_password_hash()`, or passlib with bcrypt or argon2id. Never roll your
own password hashing scheme.

### 8. Flask debug mode / Werkzeug interactive debugger reachable — CWE-489, CWE-215 — A05:2021

**Severity:** critical · **Vibe-coding frequency:** high

`app.run(debug=True)`, `app.debug = True`, or `FLASK_DEBUG=1` in a deployed
unit/env file leaves the Werkzeug interactive debugger console reachable — a
well-known path to full remote code execution once the debugger PIN is derived
or leaked.

**What it looks like in Python**

```python
app.run(debug=True)      # in code that also serves in production
app.debug = True
# FLASK_DEBUG=1 or FLASK_ENV=development in a systemd unit or a deployed .env
```

**Detecting it in a single file**

- `debug=True` inside `app.run(...)` calls and app factories.
- `FLASK_DEBUG` / `app.debug` in code, and in any unit or env file shipped
  with the deploy.
- Bandit `B201` flask_debug_true.

**Fix:** `debug=False` (the default) in anything that reaches production;
drive debug mode from an environment-specific config object, and make sure the
deployed service's unit never sets `FLASK_DEBUG` / `FLASK_ENV=development`.

### 9. `eval()` / `exec()` on untrusted input — CWE-95, CWE-94 — A03:2021

**Severity:** critical · **Vibe-coding frequency:** medium

`eval()` or `exec()` called on a string coming from a request, a file, or any
other untrusted source — often to evaluate a "formula" or a config expression
— giving the attacker arbitrary Python execution.

**What it looks like in Python**

```python
eval(request.form['expr'])
exec(user_supplied_code)
eval(df['formula_column'])     # data-science script processing an uploaded CSV
```

**Detecting it in a single file**

- `eval(` / `exec(` — trace the argument back: does it reach `request.*`,
  `input()`, `sys.argv`, or file content?
- Bandit `B307` eval, `B102` exec_used.

**Fix:** replace `eval` on data with `ast.literal_eval()`; replace
exec-based "plugin" or config-expression patterns with a real parser or an
explicit allowlist of operations.

---

## HIGH

### 10. Slopsquatting — hallucinated or typosquatted PyPI dependency — CWE-1357, CWE-829 — A06:2021 (supply chain)

**Severity:** high · **Vibe-coding frequency:** high

An LLM-suggested `requirements.txt` line or `pip install` command references a
package name that sounds plausible but is a typo of a real package, or an
outright hallucination. Attackers pre-register these exact names on PyPI with
malicious payloads, so the install silently pulls attacker code.

**What it looks like in Python**

- `pip install <name>` where `<name>` was suggested by an AI assistant and has
  no prior usage anywhere in the codebase.
- `requirements.txt` gains a line for a niche-sounding "utility" package with
  no clear GitHub project or maintainer trail.

**Detecting it in a single file**

- For every newly-added import or requirements line, check it resolves to the
  well-known, actively-maintained PyPI project you actually intended — not a
  registered-last-week, near-zero-download namesake.
- Diff `requirements.txt` / `pyproject.toml` against the previous commit and
  manually vet any name you do not already recognize.
- Reading a single `.py` file: flag imports whose module name is a near-miss of
  a famous package, and any import that nothing else in the file uses.

**Fix:** verify package identity, maintainer, download history and release age
before adding it; pin exact versions with hashes
(`pip install --require-hashes`); run `pip-audit` after every dependency change.

### 11. Path traversal via user-controlled filename — CWE-22 — A01:2021

**Severity:** high · **Vibe-coding frequency:** high

A filename or path segment from the request is joined into a filesystem path
and passed to `send_file` / `send_from_directory` / `open()` without
normalization, letting `../` sequences escape the intended directory.

**What it looks like in Python**

```python
send_file(os.path.join(UPLOAD_DIR, request.args['filename']))
open(f"data/{request.form['name']}")
send_from_directory(base, request.view_args['path'])   # path not sanitized
```

**Detecting it in a single file**

- `send_file(` / `send_from_directory(` / `open(` where the path argument
  contains a `request.*` value.
- Absence of `werkzeug.utils.secure_filename()` or an explicit
  `os.path.realpath()`-under-root check.

**Fix:** `send_from_directory()` with `werkzeug.utils.secure_filename()` on the
user-controlled part, plus a verification that the resolved realpath stays
under the intended root before serving or opening it.

### 12. CSRF protection missing on state-changing routes — CWE-352 — A01:2021

**Severity:** high · **Vibe-coding frequency:** medium

A POST/PUT/DELETE route that changes state relies only on a session cookie for
authentication, with no Flask-WTF `CSRFProtect` and no `csrf_token` in the
form, letting a third-party page trigger the action through the victim's
authenticated browser.

**What it looks like in Python**

```python
@app.route('/transfer', methods=['POST'])   # plain HTML form, no {{ form.csrf_token }}
# app created without CSRFProtect(app) despite authenticated POST routes
# JSON API mutating state via cookie-based session auth, no CSRF token check
```

**Detecting it in a single file**

- `methods=[` containing POST / PUT / DELETE / PATCH — then confirm
  `CSRFProtect(app)` is initialized somewhere in the app factory.
- In templates: `<form method="post">` without a `csrf_token`.
- If the app factory is not in this file, this becomes a NEEDS-HUMAN note.

**Fix:** initialize `CSRFProtect(app)` globally (Flask-WTF), include
`{{ form.csrf_token }}` in every state-changing form, and set
`SESSION_COOKIE_SAMESITE='Lax'` as defense in depth.

### 13. XSS via disabled autoescape or `Markup()` / `|safe` misuse — CWE-79 — A03:2021

**Severity:** high · **Vibe-coding frequency:** medium

User-supplied data wrapped in `Markup()`, passed through Jinja2's `|safe`
filter, or rendered by an `Environment` created with `autoescape=False` —
reintroducing the XSS that Jinja2's default autoescaping prevents.

**What it looks like in Python**

```python
Markup(user_comment)
jinja2.Environment(autoescape=False)
# in a template:  {{ user_bio | safe }}
```

**Detecting it in a single file**

- `|safe` in templates.
- `Markup(` in Python with a non-constant argument.
- `autoescape=False` / `autoescape = False`.
- Bandit `B701` jinja2_autoescape_false.

**Fix:** keep autoescape on (the default for `.html`/`.jinja` templates); never
wrap user-controlled data in `Markup()` or `|safe`. If some HTML must be
allowed, sanitize with a library such as bleach.

### 14. Unrestricted file upload — CWE-434 — A05:2021

**Severity:** high · **Vibe-coding frequency:** medium

An uploaded file is saved under the client-supplied filename with no extension
or MIME allowlist, no size cap and no path sanitization — enabling path
traversal, disk exhaustion, or serving malicious content (an uploaded
`.html`/`.svg` causing stored XSS, an executable dropped into a served
directory).

**What it looks like in Python**

```python
file = request.files['f']
file.save(os.path.join(UPLOAD_DIR, file.filename))   # raw client filename
# no MAX_CONTENT_LENGTH in app.config, no extension/content-type check
```

**Detecting it in a single file**

- `.save(` following `request.files[` — check for `secure_filename(` in the
  same block.
- `app.config` for `MAX_CONTENT_LENGTH` — flag its absence in any app that
  handles uploads.

**Fix:** run the filename through `werkzeug.utils.secure_filename()`, allowlist
extensions and MIME types, set `MAX_CONTENT_LENGTH`, and store uploads outside
the webroot (or under randomized names) so they cannot be executed or served
directly.

### 15. Server-side request forgery (SSRF) — CWE-918 — A10:2021

**Severity:** high · **Vibe-coding frequency:** medium

A "fetch this URL" / webhook / link-preview feature passes a client-controlled
URL straight to `requests.get/post` with no host allowlist, letting an attacker
probe internal services (cloud metadata endpoints, internal admin panels) from
the server.

**What it looks like in Python**

```python
requests.get(request.args['url'])
requests.post(webhook_url_from_db, json=payload)   # user-submitted, never revalidated
url = request.json['image_url']; requests.get(url, stream=True)
```

**Detecting it in a single file**

- `requests.get(` / `requests.post(` (also `urllib`, `httpx`, `aiohttp`) where
  the URL traces back to `request.args`/`json`/`form`, or to a DB value the
  user controls.
- Check whether host and scheme are validated against an allowlist before the
  call.

**Fix:** allowlist destination hosts and schemes; resolve and reject internal,
link-local and loopback IP ranges — including after redirects; disable
redirects (`allow_redirects=False`) and re-validate manually.

### 16. Open redirect via unvalidated `next` parameter — CWE-601 — A01:2021

**Severity:** high · **Vibe-coding frequency:** medium

The classic Flask-Login post-login redirect: `request.args.get('next')` passed
straight to `redirect()` with no check that it is a relative, same-site path,
so a crafted login link sends the victim to a phishing site right after a
successful authentication.

**What it looks like in Python**

```python
return redirect(request.args.get('next'))
next_url = request.form.get('next'); return redirect(next_url)
```

**Detecting it in a single file**

- `redirect(request.` — check whether the value is validated as a local path
  (an `urllib.parse` / `is_safe_url`-style check) before use.

**Fix:** validate that `next` is a relative URL pointing back into the same app
(empty netloc, or netloc matching your host) before redirecting; otherwise fall
back to a fixed default page.

### 17. Permissive CORS configuration — CWE-346, CWE-942 — A05:2021

**Severity:** high · **Vibe-coding frequency:** medium

flask-cors initialized with no origin allowlist (`CORS(app)`, defaulting to
`*`), or explicitly reflecting the request's `Origin` header — sometimes
combined with `supports_credentials=True`, which lets any website read
authenticated API responses cross-origin.

**What it looks like in Python**

```python
CORS(app)                                        # no origins= argument at all
CORS(app, origins='*', supports_credentials=True)
resp.headers['Access-Control-Allow-Origin'] = request.headers['Origin']   # reflected
```

**Detecting it in a single file**

- `CORS(app)` with no `origins=` kwarg, or `origins="*"`.
- `supports_credentials=True` — check it is not paired with a wildcard or
  reflected origin.

**Fix:** pass an explicit `origins=` allowlist to `CORS()`; never combine a
wildcard or reflected origin with `supports_credentials=True`.

### 18. Weak / predictable randomness for security tokens — CWE-330, CWE-338 — A02:2021

**Severity:** high · **Vibe-coding frequency:** medium

The `random` module — a non-cryptographic Mersenne Twister PRNG — used to
generate password-reset tokens, API keys or session identifiers, making them
predictable to anyone who can observe enough outputs or knows the seed.

**What it looks like in Python**

```python
reset_token = str(random.randint(100000, 999999))
api_key = ''.join(random.choice(chars) for _ in range(32))
session_id = random.random()
```

**Detecting it in a single file**

- `import random` — then look for nearby token / reset / session / api_key
  generation.
- Confirm security-sensitive generation uses `secrets` instead.
- Bandit `B311` random.

**Fix:** use the `secrets` module (`secrets.token_urlsafe()`,
`secrets.token_hex()`) or `uuid.uuid4()` for anything that must be unguessable.

### 19. TLS certificate validation disabled — CWE-295 — A02:2021

**Severity:** high · **Vibe-coding frequency:** medium

`requests` calls made with `verify=False`, or urllib3 warnings globally
suppressed — disabling TLS certificate validation and opening the connection to
man-in-the-middle interception. Usually a copy-pasted "quick fix" for a
certificate error.

**What it looks like in Python**

```python
requests.get(url, verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ssl._create_unverified_context()
```

**Detecting it in a single file**

- `verify=False`.
- `disable_warnings(` / `_create_unverified_context`.
- Bandit `B501` request_with_no_cert_validation, `B323` unverified ssl context.

**Fix:** keep certificate verification on. If it fails because of an internal
CA, point requests at the correct CA bundle (`verify='/path/to/ca.pem'`)
instead of disabling verification.

### 20. Zip Slip / unsafe archive extraction — CWE-22 — A01:2021 / A08:2021

**Severity:** high · **Vibe-coding frequency:** medium

`tarfile.extractall()` / `zipfile.extractall()` called on a user-uploaded or
downloaded archive without validating each member's path, so a crafted entry
containing `../` writes files outside the target directory (CVE-2007-4559 and
its many descendants).

**What it looks like in Python**

```python
tarfile.open(uploaded_path).extractall(dest)     # no filter= argument
zipfile.ZipFile(uploaded_path).extractall(dest)  # no per-member path check
```

**Detecting it in a single file**

- `.extractall(` — check for `filter='data'` (Python 3.12+) or an explicit
  member-path validation loop.
- Flag any `extractall()` operating on a request-supplied or downloaded
  archive.
- Bandit `B202` tarfile_unsafe_members.

**Fix:** on Python 3.12+, `extractall(filter='data')`; otherwise iterate the
members and reject or skip any whose resolved path escapes the target
directory before extracting.

### 21. XML external entity (XXE) injection — CWE-611 — A05:2021

**Severity:** high · **Vibe-coding frequency:** low

`lxml.etree` or the stdlib `xml.etree.ElementTree` parses untrusted XML — an
uploaded file, or a tool's XML output an attacker could influence — with
default settings that resolve external entities, enabling local file
disclosure, SSRF, or denial of service through entity expansion.

**What it looks like in Python**

```python
lxml.etree.parse(uploaded_xml_path)        # default parser, entities resolved
xml.etree.ElementTree.parse(untrusted_file)
```

**Detecting it in a single file**

- `etree.parse(` / `etree.fromstring(` — is the source untrusted, and is
  defusedxml or an explicit no-entity parser configuration used?
- Bandit `B313`-`B320` xml_bad_* blacklist checks, `B411` import xml.

**Fix:** parse untrusted XML with defusedxml (`defusedxml.lxml`,
`defusedxml.ElementTree`), or build an explicit
`lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`.

---

## MEDIUM

### 22. Sensitive data or secrets leaked in logs or error responses — CWE-532, CWE-209, CWE-200 — A09:2021

**Severity:** medium · **Vibe-coding frequency:** very-high

Debug logging prints passwords, tokens or PII; or an `except` block returns
`str(e)` or a full traceback to the HTTP client, exposing internal paths, query
text or credentials. Extremely common when a model is asked to "add some
logging" or "improve error handling".

**What it looks like in Python**

```python
logging.info(f"login attempt user={user} password={password}")
except Exception as e:
    return jsonify({'error': str(e)}), 500
print(response.headers)     # includes the Authorization token, into a shared log
```

**Detecting it in a single file**

- `logging.` / `print(` within a few lines of a variable named `password`,
  `token`, `secret`, `api_key`, `authorization`.
- `except Exception as e` followed by `str(e)` or `e.args` being returned or
  serialized to the client.

**Fix:** never log secrets — redact before logging; return a generic message to
clients and log full stack traces server-side only, with sensitive fields
masked.

### 23. Missing input validation at trust boundaries — CWE-20 — A03:2021 / A04:2021

**Severity:** medium · **Vibe-coding frequency:** very-high

Values from `request.args`/`form`/`json`, or CLI arguments in a standalone
script, used directly as DB keys, filenames or numeric inputs with no type,
length or range check and no WTForms / pydantic validator — so malformed or
malicious input reaches downstream sinks unfiltered.

**What it looks like in Python**

```python
int(request.args.get('page'))        # no try/except, no range check
# WTForms field defined with no validators=[...]
# argparse argument fed straight into a file path or a DB query
```

**Detecting it in a single file**

- For each `request.args`/`form`/`json` access, check it feeds a WTForms
  validator, a marshmallow/pydantic schema, or an explicit check before
  reaching DB, filesystem or subprocess code.
- WTForms field definitions with an empty or missing `validators=` list.

**Fix:** validate every external input with WTForms validators or a
pydantic/marshmallow schema, reject on failure with a clear 4xx, and never
assume a client-declared type is accurate.

### 24. Outdated, vulnerable or unpinned dependencies — CWE-1104, CWE-937 — A06:2021

**Severity:** medium · **Vibe-coding frequency:** high

`requirements.txt` has no version pins, or pins a version of Flask / Jinja2 /
requests / urllib3 with a known CVE, so a fresh install can silently pull a
vulnerable or behavior-changed release.

**What it looks like in Python**

- requirements lines with no `==` pin.
- Flask / Jinja2 / urllib3 / requests pinned below the latest security release.

**Detecting it in a single file**

- `pip-audit -r requirements.txt` when the file is available; otherwise grep it
  for lines lacking `==`.
- Check the lockfile's age against the current date.

**Fix:** pin exact versions (ideally with hashes via
`pip-compile --generate-hashes`), run `pip-audit` in CI, and keep a
Dependabot/Renovate-style update cadence.

### 25. Insecure session / cookie configuration — CWE-614, CWE-1004 — A05:2021

**Severity:** medium · **Vibe-coding frequency:** medium

The app never sets `SESSION_COOKIE_SECURE` / `HTTPONLY` / `SAMESITE`, so the
session cookie can travel over plain HTTP, be read by JavaScript, or be
attached to cross-site requests.

**What it looks like in Python**

```python
# app config with none of SESSION_COOKIE_SECURE / _HTTPONLY / _SAMESITE set
app.run()   # served behind a reverse proxy, cookies at Flask's permissive defaults
```

**Detecting it in a single file**

- Search the app config or factory for `SESSION_COOKIE_SECURE`,
  `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE` — flag any that is
  absent in an app shipping to production over HTTPS.

**Fix:** set `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`
(the default, but worth being explicit), `SESSION_COOKIE_SAMESITE='Lax'`, and a
sane `PERMANENT_SESSION_LIFETIME`.

### 26. Mass assignment via `populate_obj` / unfiltered dict-to-model — CWE-915 — A08:2021

**Severity:** medium · **Vibe-coding frequency:** medium

A form's `populate_obj()` is called against a model that also has privileged
fields (`is_admin`, `role`, `balance`), or a raw client dict is unpacked
directly into an ORM constructor or a `setattr` loop, letting an attacker set
fields they were never meant to control.

**What it looks like in Python**

```python
form.populate_obj(user)      # form exposes an is_admin/role field bound to the model
User(**request.json)
for k, v in request.form.items():
    setattr(user, k, v)
```

**Detecting it in a single file**

- `populate_obj(` — check whether the corresponding form class exposes any
  privileged field.
- `**request.json` / `**request.form` feeding a model constructor, or a
  `setattr` loop over request data.

**Fix:** explicitly whitelist which fields a form or endpoint may set on a
model; never unpack a raw client dict into an ORM object's constructor or
attributes.

### 27. Jupyter notebook execution of untrusted shell / eval content — CWE-94, CWE-829 — ecosystem-specific

**Severity:** medium · **Vibe-coding frequency:** medium

A teaching or analysis notebook pipes a downloaded script straight into a shell
magic, or `eval()`/`exec()`s a value pulled from an externally-sourced dataset.
Because notebooks are routinely re-run and shared, this becomes arbitrary code
execution the moment someone opens a colleague's or a downloaded notebook.

**What it looks like in Python**

```python
!curl https://example.com/setup.sh | bash
%%bash                       # cell invoking a download-then-run pattern
eval(row['formula'])         # column loaded from pd.read_csv(external_url)
```

**Detecting it in a single file**

- In `.ipynb` files, read the JSON `source` arrays of the code cells and look
  for `!curl`, `!wget`, `| bash`, `eval(`, `exec(`, `os.system(` operating on
  data pulled from a URL or a shared/untrusted file.

**Fix:** never pipe downloaded content directly into a shell; review a shared
notebook before running it, and treat "run all cells" on an untrusted notebook
exactly like running an untrusted script.

### 28. Regex / algorithmic denial of service and uncontrolled resource consumption — CWE-1333, CWE-400, CWE-770 — A04:2021

**Severity:** medium · **Vibe-coding frequency:** low

A regex with nested quantifiers (catastrophic backtracking) applied to user- or
file-supplied text, or an upload endpoint reading an unbounded amount of data
into memory with no size cap — a small malicious input consuming
disproportionate CPU or memory.

**What it looks like in Python**

```python
re.compile(r'(a+)+b')            # applied to request-controlled text
pd.read_csv(request.files['f'])  # whole file into memory, no MAX_CONTENT_LENGTH
```

**Detecting it in a single file**

- Regex patterns with nested repetition — `(...+)+`, `(...*)*` — applied to
  request-derived strings.
- Check the app config for `MAX_CONTENT_LENGTH` on any upload-handling route.

**Fix:** use simple, anchored regexes (or the `regex` module / an re2-style
engine with backtracking limits); enforce `MAX_CONTENT_LENGTH` and stream or
chunk reads of user-supplied files.

---

## LOW

### 29. `assert` used for a security or authorization check — CWE-703 — A04:2021

**Severity:** low · **Vibe-coding frequency:** low

`assert` used as the only gate before a sensitive action. Asserts are stripped
entirely when Python runs with the `-O` flag, silently removing the check.

**What it looks like in Python**

```python
assert current_user.is_admin
assert user_id == session['uid']    # sole guard before a privileged operation
```

**Detecting it in a single file**

- `assert ` near auth / role / permission / admin / owner checks.
- Bandit `B101` assert_used.

**Fix:** replace security-relevant asserts with an explicit `if` / `raise` (or
Flask's `abort(403)`); reserve `assert` for debug-only invariants that are safe
to disable.

---

## Appendix — tooling reference

Reference only. The skill's mechanical pass uses the first three, and **only**
if they are already installed (`command -v`); nothing is ever installed.

| Tool | Command | What it adds |
|------|---------|--------------|
| Bandit | `bandit -ll -r path/to/file.py` | AST-based Python security linter, the closest thing to a canonical single-file scan. `B1xx` misc (B101 assert_used), `B2xx` framework misconfig (B201 flask_debug_true, B202 tarfile_unsafe_members), `B3xx` dangerous calls (B301 pickle, B303/B324 weak hash, B306 mktemp, B307 eval, B311 random, B323 unverified ssl context), `B4xx` blacklisted imports (B411 xml, B413 pycrypto), `B5xx` crypto/TLS (B501 no cert validation, B506 yaml_load, B507 ssh_no_host_key_verification), `B6xx` injection/process (B602 shell=True, B605 os.system, B608 hardcoded SQL), `B7xx` templating (B701 jinja2_autoescape_false). |
| Semgrep | `semgrep --config p/python --config p/flask path/to/file.py` | Dataflow-aware; catches what Bandit's AST rules miss — Jinja2 SSTI via `render_template_string`, `os.system` injection with tainted variables, reflected XSS in Flask responses. Overlaps Bandit only partially, so both are worth running. |
| pip-audit | `pip-audit -r requirements.txt` | Not single-file, but mandatory whenever `requirements.txt`/`pyproject.toml` changes: flags known-CVE dependency versions via the PyPA/OSV advisory database, and surfaces unpinned or newly-added packages worth checking manually against slopsquatting. |
| ruff (flake8-bandit rules) | `ruff check --select S path/to/file.py` | Reimplements a Bandit-like `S1xx`-`S6xx` ruleset inside the linter most Python projects already run on every save; cheap to keep on even when Bandit only runs in CI. |
| detect-secrets | `detect-secrets scan path/to/file.py` | Entropy + regex secret scanner. Catches hardcoded `SECRET_KEY`, API keys and DB connection strings that Bandit's `B105`-`B107` only partially cover — those need a variable named like a password. |

Scanner output is a candidate list, never a verdict: confirm each hit against
the file itself, and remember that no scanner here sees missing authorization,
IDOR, or business-logic flaws. That is what the checklist above is for.


### 28. Missing brute-force protection / rate limiting on authentication — CWE-307, CWE-799 — A07:2021

**Severity:** medium · **Vibe-coding frequency:** very-high

Generated login endpoints almost never include rate limiting: the happy path
works, so the missing control is invisible in review.

**What it looks like in Python**

- A `/login` route calling `check_password_hash` with no attempt counter, no
  lockout, no `flask-limiter` decorator, no CAPTCHA after N failures.
- No record of failed attempts per username or per source IP anywhere.

**Detecting it in a single file**

- Find the authentication route, then grep the same file for `limiter`,
  `Limiter`, `ratelimit`, `attempts`, `lockout`, `failed_login`. Absence on an
  otherwise complete login handler is the finding.

**Fix**

Add `flask-limiter` on the auth route (e.g. `@limiter.limit("5/minute")`), plus
per-account failed-attempt counting with a temporary lockout and an audit log
entry per failure.

---

### 29. Username enumeration via timing side channel — CWE-208, CWE-203 — A07:2021

**Severity:** low · **Vibe-coding frequency:** high

**What it looks like in Python**

- `if row and check_password_hash(row["password_hash"], password):` — when the
  username does not exist, `row` is falsy and the hash comparison is
  short-circuited, so the response returns measurably faster than for a real
  username with a wrong password. The flash message can be perfectly generic
  and the timing still leaks which usernames exist.

**Detecting it in a single file**

- Look for any `and`/early-`return` that skips the password-hash call when the
  user lookup fails. The tell is the hash function appearing on only one branch.

**Fix**

Always perform a hash comparison, against a dummy hash of the same cost when
the user is absent, so both branches take comparable time:
`check_password_hash(row["password_hash"] if row else DUMMY_HASH, password)`
and only then decide. Combine with the rate limiting in class 28, which is the
stronger control.

---
