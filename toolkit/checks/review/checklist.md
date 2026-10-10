# Adversarial diff review checklist

This checklist drives the **security review of the diff** before a merge
request (stage 4 of the pipeline, after `make check`). It is derived from
OWASP Top 10 / ASVS, with examples for Java/Spring, JavaScript and Python.

How it is used: the `review-diff.js` workflow assigns **one entry to one
reviewer agent**, which looks in the diff ONLY for problems **introduced or
made worse by the change** (delta mindset, like the rest of the gate). Every
finding is then attacked by an adversarial verifier: it survives only if a
**concrete attack path** exists (controllable input → sink), not a generic
"this could be dangerous".

REV-11 and REV-12 are not OWASP classes. They cover dead and redundant code
(CWE-561, CWE-1164): code nobody uses still ships, nobody reviews or
maintains it, and it hides the real change from the people reading the
diff.

Rules for modifying this file:
- every entry has an id `REV-NN` and a title on a `## ` line: the workflow
  reads them from here, so adding/removing entries does NOT require touching
  the workflow. The one exception is REV-11 and REV-12: the workflow
  recognises those two ids and gives them their own reviewers and verifier,
  and it stops if their titles no longer start with "Dead" and
  "Redundant", so do not renumber them;
- do NOT remove an entry to make a review pass: it is the equivalent of
  modifying the baseline (it bypasses the protection, it does not satisfy it);
- if an entry never applies to your stack, remove it in a dedicated commit,
  with the reason in the commit message.

---

## REV-01 — SQL injection (OWASP A03)

**What to look for in the diff:** queries built by concatenation or
formatting (`"SELECT ... " + variable`, `String.format`, template literal),
MyBatis with `${...}` instead of `#{...}`, `@Query(nativeQuery = true)` with
concatenated parameters, `Statement` instead of `PreparedStatement`, ORDER BY
/ column names taken from input. In Python: f-strings, `%` or `.format()`
building SQL passed to `cursor.execute()` / `executescript`, SQLAlchemy
`text()` or raw `engine.execute` with interpolated values instead of bound
parameters.

**Confirmed only if:** the concatenated value can be traced back to external
input (HTTP parameter, form field, data read from the DB that users can
write) and reaches the execution of the query.

**Typical false positives:** concatenation of literals or constants only;
correctly bound parameters; enums/whitelists checked before use.

## REV-02 — XSS, stored and reflected (OWASP A03)

**What to look for in the diff:** on the JS side: assignments to
`innerHTML`/`outerHTML`, `insertAdjacentHTML`, `document.write`, jQuery
`.html()`/`.append()` on jQuery objects, HTML built by interpolation and then
inserted into the DOM. On the server side: JSP with `<%= %>` without
escaping, Thymeleaf `th:utext`, JSON embedded in a page without safe
serialization, wrong `Content-Type` headers on responses that reflect input.
In Python: Jinja2 environments created with `autoescape=False`, the `| safe`
filter or `Markup()` applied to user data, HTML strings assembled by hand in
Flask responses.

**Confirmed only if:** the data that ends up in the sink can be modified by a
user (including ANOTHER user: stored XSS on metadata is the real case that
has already happened on this platform) and there is no escaping/sanitization
along the path.

**Typical false positives:** value that has already gone through an escaping
function; content coming only from static configuration.

## REV-03 — Authorization, IDOR, ownership (OWASP A01)

**What to look for in the diff:** new or modified endpoints that receive a
resource id: is there a check that the resource belongs to the user (or to
their organization), on top of the "you are authenticated" check? Service
methods that used to be internal and are now reachable; `@PreAuthorize`
removed or widened; queries by id without a filter on the owner; mass
assignment (binding a request body directly onto an entity with privileged
fields such as `role`, `orgId`). In Python: new Flask/FastAPI routes missing
the login/permission decorator the sibling routes have; lookups by id with no
owner filter; `**request.json` or `Model(**payload)` binding privileged
fields straight from the request body.

**Confirmed only if:** any authenticated user can read or modify data that is
not theirs by changing an id/parameter, or can elevate one of their own
privileged attributes. This is the most serious and most likely flaw on an
institutional platform: when in doubt between "plausible" and "confirmed",
stay strict.

**Typical false positives:** the ownership check lives in a layer that the
diff does not show (verify by opening the file, do not trust the diff alone).

## REV-04 — Authentication, session, CSRF (OWASP A07)

**What to look for in the diff:** new endpoints outside the authentication
chain (patterns excluded in SecurityConfig, `permitAll` added), new CSRF
exemptions (`csrf().disable()`, `ignoringAntMatchers`), handling of
passwords/credentials (logging, non constant-time comparisons, weak resets),
cookies without `HttpOnly`/`Secure`, open redirects driven by parameters.
In Python: a hardcoded or predictable Flask `SECRET_KEY`, password checks
with `==` instead of `check_password_hash`/`hmac.compare_digest`, CSRF
protection missing on state-changing routes, session cookies configured
without the secure flags.

**Confirmed only if:** the endpoint exposes non-public data or actions
without authentication, or the CSRF exemption covers a state-changing action.

## REV-05 — Path traversal and file handling (OWASP A01/A05)

**What to look for in the diff:** paths built from input (`new File(base,
input)`, `Paths.get` with parameters), new downloads/uploads, archive
extraction (zip slip), file names used exactly as they arrive, uploads
without an extension/type whitelist or saved under the web root. In Python:
`os.path.join(base, user_input)` — an absolute or `..` input silently
escapes the base —, `open()`/`send_file` on user-supplied paths,
`tarfile.extractall`/`zipfile.extractall` without member validation, uploads
saved without `secure_filename` or an equivalent.

**Confirmed only if:** the input can contain `..`/an absolute path and
reaches the filesystem without normalization + a containment check
(`getCanonicalPath().startsWith(base)` or equivalent).

## REV-06 — XXE and unsafe deserialization (OWASP A05/A08)

**What to look for in the diff:** new or reconfigured XML parsers
(`DocumentBuilderFactory`, `SAXParser`, `XMLInputFactory`) without
`disallow-doctype-decl`/external entities disabled; `ObjectInputStream` on
external data; Jackson with `enableDefaultTyping`/`@JsonTypeInfo` on input;
deserialization libraries known for gadget chains. In Python:
`pickle.loads`/`marshal.loads`/`shelve` on external data, `yaml.load`
without `SafeLoader`, `xml.etree`/`lxml`/`minidom` parsing untrusted XML
where `defusedxml` should be used, `jsonpickle.decode` on input. Note: a
scanner rule only matches the parser set-ups it was written for; this entry
covers the configurations it does not know.

**Confirmed only if:** the parser/deserializer processes content that comes
from outside and the safe configuration is missing on the actual path.

## REV-07 — Command injection and expression injection (OWASP A03)

**What to look for in the diff:** `Runtime.exec`, `ProcessBuilder` with
input; evaluation of expressions (SpEL, OGNL, script engine) on strings that
were built up; template engines with templates taken from input. In Python:
`os.system`/`os.popen` or `subprocess` with `shell=True` and interpolated
input, `eval`/`exec` on anything external, Jinja2
`render_template_string` with user data in the template itself (server-side
template injection). The scanners match known sinks; whether the input
that reaches them is controllable is decided here.

**Confirmed only if:** part of the executed argument is externally
controllable; with separate argument arrays (`new String[]{...}`) the input
must end up in the command, not just in the arguments.

## REV-08 — Secrets, sensitive data, weak cryptography (OWASP A02)

**What to look for in the diff:** hardcoded credentials/tokens/keys (in
config and test files too), passwords or PII written to the logs, `MD5`/`SHA-1`
for passwords, `ECB`, insecure randomness (`java.util.Random`) for tokens,
TLS disabled/loosened (permissive trust managers, `verify=false`). In
Python: the `random` module used for tokens or resets where `secrets`
belongs, `hashlib.md5`/`sha1` on passwords, `requests(..., verify=False)`,
credentials committed in `settings.py`/`.env`/notebooks.

**Confirmed only if:** the secret is real (not a documented test placeholder)
or the logged data really is sensitive. Note: the gate's secret patterns
catch known key formats; a generic cleartext password is usually left to
this review.

## REV-09 — SSRF and outbound requests (OWASP A10)

**What to look for in the diff:** URLs or hosts built from input and used for
server-side requests (`HttpClient`, `RestTemplate`, `URL.openConnection`),
webhooks/callbacks configurable by the user, fetching remote resources by id.
In Python: `requests.get`/`urllib.request.urlopen`/`httpx` on URLs assembled
from parameters, user-stored webhook URLs fetched later by the server.

**Confirmed only if:** the user controls enough of the URL to reach internal
hosts (cloud metadata, internal services) and there is no whitelist of
destinations.

## REV-10 — Business logic and trust boundaries

**What to look for in the diff:** validations done ONLY on the client side;
amounts, quantities, states that accept negative or inconsistent values;
multi-step operations where a step can be skipped or repeated (replay, double
submit on non-idempotent actions); "system" data recomputed by the client and
accepted by the server.

**Confirmed only if:** you can describe the concrete sequence of requests by
which a user obtains a result that the business rules forbid. This entry is
the hardest to automate: it is the reason human review remains necessary even
when the verdict is green.

## REV-11 — Dead and unreachable code

**What to look for in the diff:** functions, classes, methods, variables,
imports, routes, configuration keys, CSS rules and feature flags the diff
adds that nothing uses or reaches at HEAD; code after an unconditional
`return`, `raise`, `throw` or `exit`, or behind a condition that can never be
true (`if False:`, a constant flag, a check the line before already ruled
out); existing code the diff orphans by removing its last caller.

**Confirmed only if:** the finding carries the evidence. For an unused
symbol, the exact searches run over the whole repository at HEAD: the name
itself, its string forms where routes, configuration or reflection could
reach it, and the dynamic forms (`getattr`, `importlib`, `__import__`,
`require` with a variable, `Class.forName`, reflection), each with no
match outside the definition. For unreachable code, the argument that
the path cannot run. Every finding also says how to remove the code. Severity
is HIGH only when the removable code is attack surface or hides a security
decision: an unused but reachable HTTP route or CLI command, an
authentication or validation path that is bypassed or never reached, a
leftover debug or test backdoor, commented-out or leftover credentials.
Everything else is LOW.

**Typical false positives:** exported or public API and library entry
points; CLI entry points and console scripts; names a framework discovers
by itself (Spring beans, Flask and Django string routes, pytest fixtures
and conftest hooks, names in `__all__`, dunder methods, signal handlers);
symbols referenced from templates, HTML, configuration, build files or
documentation that promises them; use from tests only, which is still
use; code kept for a documented compatibility reason; and the diff's own
deletions.

## REV-12 — Redundant and leftover code

**What to look for in the diff:** added code that duplicates a helper the
repository or the standard library already has; new dependencies or
imports with no use; added files nothing imports, runs or references;
leftover debug output (`print`, `console.log`, `System.out.println`, dumps
of request data), test scaffolding, commented-out code, TODO stubs and
unused parameters; copies of an existing function with one line changed.

**Confirmed only if:** the finding carries the evidence: the existing
helper it duplicates (file and line), or the exact searches at HEAD that
show the dependency, import or file has no use, with no match from a
dynamic form either (`getattr`, `importlib`, `require` with a variable,
plugin or entry-point registration). Every finding also says how to remove
the code. Severity is HIGH only when the leftover is attack surface or hides
a security decision: a debug or test backdoor, a debug endpoint or flag
left on, commented-out or leftover credentials, an unused dependency that
pulls in native code or network access, or a copy of a validation or
authorization function whose one changed line weakens it. Everything else
is LOW.

**Typical false positives:** the same list as REV-11 (public API, entry
points, framework-discovered names, references from templates,
configuration, build files or documentation, use from tests, documented
compatibility); a dependency used only by a build or test tool the
project configures; logging through the project's logger at a debug level;
two similar functions whose difference is the point of the change.
