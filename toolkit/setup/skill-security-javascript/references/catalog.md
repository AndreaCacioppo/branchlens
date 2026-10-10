# JavaScript vulnerability catalog

Reference for the `security-javascript` skill. One section per vulnerability
class, ordered by **severity first, vibe-coding frequency second** — work top
to bottom and stop only when the file is exhausted, not when it looks fine.

Scope: JavaScript in the browser — React/JSX components, self-contained HTML
dashboards with inline vanilla JS, and webpack/babel tooling. Server-side
Node.js weaknesses are out of scope.

Each entry gives: what the class is, what it looks like in real JS/JSX code,
how to spot it **reading a single file**, and the canonical fix. A pattern is a
lead, not a verdict — trace the data back to its source before writing a
finding, and cite the line.

Sources: CISA/MITRE CWE Top 25 (2025 and 2024 editions), OWASP Top 10:2025 and
2021, MITRE CWE List v4.20, eslint-plugin-security v4 and
eslint-plugin-no-unsanitized rule docs, PortSwigger Web Security Academy
(DOM XSS, DOM clobbering, web messages), OWASP cheat sheets (reverse
tabnabbing, DOM clobbering, prototype pollution), CSA 2026 notes on
slopsquatting and vibe-coding security debt, the USENIX Security 2025 package
hallucination study (~19.7% hallucinated package names across 2.23M samples),
and the Veracode 2025 GenAI Code Security Report (AI-generated code carrying
~2.74x the vulnerabilities of human-written code).

---

## 1. DOM-based XSS via unsafe HTML sinks

- **CWE:** CWE-79 — **OWASP:** A05:2025 Injection (A03:2021 Injection)
- **Severity:** critical — **Vibe-coding frequency:** very-high

Untrusted data (URL params, API responses, `postMessage` payloads) is written
into the DOM through a sink that parses it as HTML/script, letting an attacker
execute arbitrary JavaScript in the victim's session.

**What it looks like in JavaScript**

```js
el.innerHTML = data.description;                       // sink
el.outerHTML = `<div>${params.get('name')}</div>`;     // template literal into a sink
document.write(location.hash.slice(1));
document.writeln(userText);
container.insertAdjacentHTML('beforeend', row.html);
iframe.srcdoc = apiResponse.body;
```

**Detecting it in a single file**

- Grep `innerHTML`, `outerHTML`, `document.write(`, `document.writeln(`,
  `insertAdjacentHTML(`, `.srcdoc` and trace the right-hand side backwards to a
  URL param, a prop, a `fetch`/`axios` response, or storage.
- A template literal built as an HTML string anywhere in the file is a strong
  lead — follow where the string ends up.
- Look for `eslint-disable` comments next to `no-unsanitized/property` or
  `no-unsanitized/method`: someone already knew.
- Data that has round-tripped through the server is still untrusted (stored XSS).

**Fix**

Never build HTML from untrusted strings. Render via JSX or text nodes
(`textContent`, `createElement` + `append`). Where raw HTML is genuinely
required, sanitize immediately before the sink with
`DOMPurify.sanitize(html)`, and enable `eslint-plugin-no-unsanitized`.

---

## 2. Hardcoded secrets baked into the client bundle

- **CWE:** CWE-798 — **OWASP:** A04:2025 Cryptographic Failures (A02:2021
  Cryptographic Failures / A07:2021 Identification and Authentication Failures)
- **Severity:** critical — **Vibe-coding frequency:** very-high

API keys, internal tokens, or credentials are written directly in source or
pulled from `process.env.REACT_APP_*` / webpack `DefinePlugin` variables, which
webpack inlines as plaintext into the shipped bundle — readable by anyone who
opens dev tools. There is no such thing as a client-side secret.

**What it looks like in JavaScript**

```js
const apiKey = "sk-live-9f2a...";
const SECRET = "hunter2";
headers: { Authorization: "Bearer eyJhbGciOi..." }
const key = process.env.REACT_APP_MAPS_API_KEY;   // inlined into the bundle
// webpack.config.js
new webpack.DefinePlugin({ 'process.env.API_SECRET': JSON.stringify('literal') })
```

**Detecting it in a single file**

- `grep -riE '(api[_-]?key|secret|token|password|passwd|credential)\s*[:=]\s*["\047]'`
  across `.js`/`.jsx`.
- Grep `REACT_APP_` and `process.env.` — **every** such variable webpack sees
  is baked into the public bundle, so any secret-sounding one is a finding.
- In `webpack.config.js`, read the `DefinePlugin` block for literal values.
- Long opaque string literals (base64-looking, `sk-`, `ghp_`, `glpat-`,
  `AKIA`, a JWT's three dot-separated segments) are leads even without a
  secret-sounding variable name.

**Fix**

Never ship secrets to the browser. Any credential the SPA needs must be proxied
through the server, which holds the secret and issues short-lived scoped
tokens. Anything already present in a built bundle must be treated as
compromised and rotated — removing the line is not enough.

---

## 3. React `dangerouslySetInnerHTML` / ref-based `innerHTML` bypassing JSX escaping

- **CWE:** CWE-79 — **OWASP:** A05:2025 Injection (A03:2021 Injection)
- **Severity:** critical — **Vibe-coding frequency:** high

React escapes interpolated values by default; `dangerouslySetInnerHTML` and a
DOM ref used to set `innerHTML` deliberately opt out of that escaping, so any
unsanitized user or API content passed through them executes as script.

**What it looks like in JavaScript**

```jsx
<div dangerouslySetInnerHTML={{ __html: note.body }} />
useEffect(() => { ref.current.innerHTML = props.html; }, [props.html]);
// component-library render callbacks are a common hiding place:
{ title: 'Note', render: (v) => <span dangerouslySetInnerHTML={{ __html: v }} /> }
```

**Detecting it in a single file**

- Grep `dangerouslySetInnerHTML` in every `.jsx` and trace `__html` back to its
  source; a value that came from `fetch`, props, or a route param is a finding.
- Grep `.innerHTML =` near a `useRef`/`createRef` usage.
- Check `render(...)`/`formatter(...)` callbacks passed to table, tooltip, and
  modal components — raw HTML frequently enters there.
- A `DOMPurify.sanitize` call in the same expression clears the finding; one
  elsewhere in the file does not.

**Fix**

Avoid `dangerouslySetInnerHTML` where plain text or JSX suffices. When rich
HTML is genuinely required, sanitize with
`DOMPurify.sanitize(html, { ALLOWED_TAGS: [...] })` inside **one** reusable
component, so every call site is reviewed once instead of never.

---

## 4. `javascript:` pseudo-protocol and unsanitized `href`/`src`

- **CWE:** CWE-79 — **OWASP:** A05:2025 Injection (A03:2021 Injection)
- **Severity:** critical — **Vibe-coding frequency:** high

A URL bound to `<a href>`, `<iframe src>`, `<img src>`, or a router `Link` is
taken from user/API input without checking its scheme, letting an attacker
supply `javascript:` or `data:` URIs that execute on click or load.

**What it looks like in JavaScript**

```jsx
<a href={item.website}>Site</a>                  // item.website = "javascript:fetch(...)"
<Link to={apiValue}>Open</Link>                  // react-router
<iframe src={params.get('embed')} />
onClick={() => window.open(userInput)}
window.location = untrustedString;
```

**Detecting it in a single file**

- Grep `href={` and `src={` in `.jsx`; for each, check the bound variable is
  allow-listed to `http`/`https` or a relative path *before* render.
- Grep `onClick` handlers doing `window.open(` or `window.location =` with an
  unvalidated variable.
- A `startsWith('http')` check is not enough on its own — `javascript:` is
  rejected, but so should `//evil.com` be for redirects (see class 17).

**Fix**

Validate the scheme before binding to `href`/`src`: allow only `http`,
`https`, or a relative path, and explicitly reject `javascript:`, `data:`, and
`vbscript:` (including whitespace/case tricks like `Java\tscript:`).

---

## 5. Client-side code injection via `eval` / `Function` / string timers

- **CWE:** CWE-94, CWE-95 — **OWASP:** A05:2025 Injection (A03:2021 Injection)
- **Severity:** critical — **Vibe-coding frequency:** high

`eval()`, `new Function(userString)`, or `setTimeout`/`setInterval` called with
a **string** argument execute attacker-influenced text as JavaScript — a common
shortcut when a generated dashboard needs to evaluate a user-entered formula or
compute a value dynamically.

**What it looks like in JavaScript**

```js
const result = eval(formulaField.value);
const fn = new Function('row', userExpression);
setTimeout("refresh()", 1000);          // string form
setInterval(userSuppliedCode, 500);
```

**Detecting it in a single file**

- Grep `eval(` and `new Function(` — `eslint-plugin-security`'s
  `detect-eval-with-expression` flags exactly the non-literal form.
- Grep `setTimeout("` and `setInterval("` for the string-argument form; also
  check the first argument is a function reference, not a string variable.
- `window['ev'+'al']` and `globalThis.eval` are the obfuscated variants.

**Fix**

Never evaluate untrusted strings as code. For genuine expression evaluation
(a dashboard formula field), use a sandboxed expression parser — e.g. mathjs's
restricted `evaluate` — instead of `eval`/`Function`.

---

## 6. Client-side-only authorization / trusting an unverified JWT

- **CWE:** CWE-602 — **OWASP:** A01:2025 Broken Access Control (A01:2021
  Broken Access Control)
- **Severity:** high — **Vibe-coding frequency:** very-high

The UI hides an admin button, disables a menu item, or reads a role claim out
of a JWT it decodes but never verifies, and treats that as the actual
access-control decision. The check runs entirely in the attacker's own browser,
so it is bypassed by editing state, calling the API directly, or forging the
decoded value.

**What it looks like in JavaScript**

```jsx
const { role } = jwtDecode(token);              // decode != verify
return role === 'admin' ? <AdminPanel /> : null;

if (localStorage.getItem('role') === 'admin') { enableDangerousAction(); }

{isAdmin && <DeleteAllButton />}                // isAdmin only ever set client-side
<button disabled={!isAdmin}>Delete</button>     // disabled is cosmetic
```

**Detecting it in a single file**

- Grep `jwt-decode` / `jwtDecode` and check whether the decoded value gates UI
  with no matching server-enforced check on the endpoint it calls.
- Grep `role`, `isAdmin`, `permission`, `canEdit` and see where the value comes
  from: `localStorage`/`sessionStorage`/a decoded JWT means client-only.
- Hidden, `disabled`, or unmounted controls are UX, never a security boundary.

**Fix**

Treat every client-side role/permission check as a UX convenience only. The
server must independently authorize every endpoint regardless of what the UI
shows or hides. This class is nearly always **NEEDS-HUMAN** from a single
frontend file: name the endpoint whose server-side authorization must be
confirmed.

---

## 7. Supply chain: hallucinated or typosquatted packages ("slopsquatting")

- **CWE:** CWE-1357 — **OWASP:** A03:2025 Software Supply Chain Failures
  (A06:2021 Vulnerable and Outdated Components)
- **Severity:** high — **Vibe-coding frequency:** very-high

An AI assistant suggests importing a package name that sounds plausible but
does not exist — attackers pre-register these hallucinated names to serve
malware — or a name that is a typosquat of a popular library. A 2025 study
found roughly **1 in 5** packages recommended by code-generating LLMs across
Python and JavaScript simply do not exist.

**What it looks like in JavaScript**

```js
import { fastTable } from 'react-fast-tabler';   // plausible, non-existent
import _ from 'lodahs';                          // typosquat of lodash
import axios from 'axios-http';                  // typosquat / hijacked name
```

Plus a `package.json` dependency with no matching, actively-maintained registry
listing, or an `npm install <name>` run without checking the registry first.

**Detecting it in a single file**

- List every import in the file that is not a relative path and not obviously
  well-known; each unfamiliar name needs registry verification (existence,
  download count, maintainer history, repository link) before it is trusted.
- Compare new dependencies added alongside AI-assisted code against what the
  code actually uses — an import nothing calls is suspicious twice over.
- Watch for near-misses of famous names (transposed letters, added/removed
  hyphen, singular/plural, missing `@scope`).
- `npm audit` / `osv-scanner` against `package.json` + `package-lock.json`
  covers known-bad, not hallucinated — the name check is manual.

**Note for this skill:** verification requires the registry, and this skill
makes no network calls. Report an unfamiliar package as **NEEDS-HUMAN**,
naming the exact package and line to verify.

**Fix**

Manually verify any newly-introduced package name and version before
installing; pin with a lockfile, run `npm audit` / `osv-scanner` in CI, and
prefer well-known scoped publishers.

---

## 8. Sensitive data persisted in `localStorage` / `sessionStorage`

- **CWE:** CWE-312, CWE-522 — **OWASP:** A04:2025 Cryptographic Failures
  (A02:2021 Cryptographic Failures)
- **Severity:** high — **Vibe-coding frequency:** high

JWTs, session identifiers, or personal data are stored in `localStorage` or
`sessionStorage` for convenience. Any XSS anywhere on the page — including a
third-party script — can read this storage directly, and `localStorage`
persists indefinitely, beyond logout and across tabs.

**What it looks like in JavaScript**

```js
localStorage.setItem('token', response.data.accessToken);
sessionStorage.setItem('refresh', refreshToken);
localStorage.setItem('user', JSON.stringify(user));   // name, email, fiscal id...
// later
headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
```

**Detecting it in a single file**

- Grep `localStorage.setItem` / `sessionStorage.setItem` and inspect exactly
  what is stored — a JWT, a session id, or any personal data is a finding.
- Grep `localStorage.getItem('token')` used later as an `Authorization` header:
  that confirms the token is client-readable.
- Check whether anything clears storage on logout; usually nothing does.

**Fix**

Keep short-lived access tokens in memory only (React state/context). Let the
server set the refresh token as an `HttpOnly`, `Secure`, `SameSite` cookie so
client-side JS can never read it. Never store personal data client-side without
a stated reason and a clear-on-logout path.

---

## 9. Vulnerable or stale pinned dependencies

- **CWE:** CWE-1395, CWE-1104 — **OWASP:** A03:2025 Software Supply Chain
  Failures (A06:2021 Vulnerable and Outdated Components)
- **Severity:** high — **Vibe-coding frequency:** high

`package.json` pins a version of a widely-used library carrying a disclosed CVE
— old lodash prototype-pollution advisories, old moment.js ReDoS, old axios
SSRF/redirect issues — often because the model's training data predates the fix.

**What it looks like in JavaScript**

```json
"lodash": "^4.17.15",     // pre-4.17.21 prototype pollution advisories
"axios": "0.21.1",        // pre-1.6 SSRF / redirect issues
"moment": "2.29.1",       // unmaintained; superseded by day.js / date-fns
"minimist": "^1.2.0",     // pre-1.2.6 prototype pollution
"jquery": "3.4.1"         // pre-3.5 HTML-parsing XSS
```

**Detecting it in a single file**

- `npm audit` / `osv-scanner` against `package.json` and `package-lock.json`
  (a dependency-file task, not a single-source-file one).
- Grep `package.json` for exact/caret versions of lodash, axios, moment,
  jquery, minimist, `serialize-javascript`, `node-forge` and cross-check
  against the advisory database.
- In a self-contained HTML dashboard, read the CDN URLs in `<script src>` —
  the version is right there in the path.

**Note for this skill:** cross-checking an advisory database needs the network.
Report a suspicious pin as **NEEDS-HUMAN** with the package and version named.

**Fix**

Run `npm audit` / Dependabot / `osv-scanner` in CI on every `package.json`
change and keep security-sensitive libraries on current minor versions.

---

## 10. Missing CSRF protection on state-changing requests

- **CWE:** CWE-352 — **OWASP:** A01:2025 Broken Access Control (A01:2021
  Broken Access Control)
- **Severity:** high — **Vibe-coding frequency:** medium

A `fetch`/`axios` call that changes server state omits the CSRF header the
server's CSRF filter expects (with Spring Security, `X-XSRF-TOKEN` read from
the `XSRF-TOKEN` cookie), or the action is wired to a `GET`. AI-generated code
hitting a 403 from a CSRF filter is prone to "fixing" it by disabling CSRF
server-side instead of sending the token.

**What it looks like in JavaScript**

```js
axios.post('/api/users', data);                    // no CSRF header, cookie auth
fetch('/api/items/42', { method: 'GET' });         // GET that deletes
fetch(url, { method: 'POST', credentials: 'include' });  // cookie sent, token not
// and the tell-tale server-side "fix": http.csrf().disable()
```

**Detecting it in a single file**

- Grep `axios.post|put|patch|delete` and `fetch(..., { method: 'POST'|'PUT'|
  'PATCH'|'DELETE' })` and check each attaches the CSRF header or that axios is
  configured with `xsrfCookieName`/`xsrfHeaderName`.
- Grep `withCredentials: true` / `credentials: 'include'` and confirm the CSRF
  cookie is actually read and forwarded.
- Any `GET` request that mutates state is a finding on its own.
- A token-in-`Authorization`-header scheme with no cookies is not CSRF-exposed
  the same way — say so rather than reporting a false finding.

**Fix**

Read the CSRF cookie the server sets and send it back as the expected header on
every state-changing request (axios does this automatically once
`xsrfCookieName`/`xsrfHeaderName` are configured). Never disable server-side
CSRF protection to work around a client bug.

---

## 11. Missing or incorrect origin validation on `postMessage`

- **CWE:** CWE-346 — **OWASP:** A01:2025 Broken Access Control (A05:2021
  Security Misconfiguration)
- **Severity:** high — **Vibe-coding frequency:** medium

A `window.addEventListener('message', handler)` callback acts on `event.data`
without checking `event.origin` against an allow-list — or checks `event.source`
instead, or uses a loose substring/regex match — letting any page that can open
or embed the app send it forged messages.

**What it looks like in JavaScript**

```js
window.addEventListener('message', (e) => { setState(e.data.payload); });     // no check
if (event.origin.indexOf('example.com') > -1) { ... }   // matches evil-example.com.attacker.tld
if (event.origin.match(/example\.com/)) { ... }         // unanchored regex
if (event.source === window.parent) { ... }             // source is not origin
target.postMessage(secret, '*');                        // sends to any origin
```

**Detecting it in a single file**

- Grep `addEventListener('message'` and verify the handler's **first** lines do
  a strict-equality allow-list check on `event.origin`.
- Grep `postMessage(` and check the `targetOrigin` argument is never `'*'`.
- Substring (`includes`, `indexOf`, `startsWith`) and unanchored regex checks
  on origin are findings, not mitigations.

**Fix**

Check `event.origin` with strict equality against an explicit allow-list before
touching `event.data`, validate the shape of `event.data` afterwards, and
always pass a specific `targetOrigin` when sending.

---

## 12. Prototype pollution via unguarded merge / clone / path-set

- **CWE:** CWE-1321 — **OWASP:** A05:2025 Injection (A03:2021 Injection)
- **Severity:** high — **Vibe-coding frequency:** medium

A hand-rolled deep-merge / deep-clone / `setValueByPath` helper (or an outdated
library) assigns object properties from attacker-controlled keys without
blocking `__proto__`, `constructor`, or `prototype`, letting an attacker
pollute `Object.prototype` for every object on the page — which can flip
unrelated boolean flags or feed a later DOM-XSS sink.

**What it looks like in JavaScript**

```js
function merge(target, source) {
  for (const key in source) {                      // no key denylist
    if (typeof source[key] === 'object') merge(target[key] ??= {}, source[key]);
    else target[key] = source[key];
  }
}
merge(config, JSON.parse(untrustedJson));

obj[userControlledKey] = value;                    // bracket-notation write
setPath(state, params.get('path'), params.get('v'));
```

**Detecting it in a single file**

- Find recursive `merge`/`clone`/`extend`/`setPath` helpers and check whether
  they skip `__proto__`, `constructor`, and `prototype`.
- Grep bracket-notation writes `obj[<param>] =` where the key comes from a
  function argument or user input — `eslint-plugin-security`'s
  `detect-object-injection` flags exactly this.
- Grep `__proto__` anywhere; legitimate uses are rare.
- `Object.assign` is shallow and safe here; the risk is in the recursive
  hand-written variants.

**Fix**

Use `Object.create(null)` or a `Map` for untrusted key/value data, add an
explicit denylist for `__proto__`/`constructor`/`prototype` in any merge
helper, or rely on a current, maintained library instead of a hand-written one.

---

## 13. Sensitive information leaked via `console.log` or raw error display

- **CWE:** CWE-209, CWE-532 — **OWASP:** A09:2025 Security Logging and Alerting
  Failures / A10:2025 Mishandling of Exceptional Conditions
- **Severity:** medium — **Vibe-coding frequency:** very-high

A `catch` block does `console.log(err)` or `console.error(err.response)` —
which can include tokens, request payloads, or full stack traces reachable via
dev tools — or renders the raw error/response object to the user, exposing
backend stack traces, internal hostnames, or query fragments.

**What it looks like in JavaScript**

```jsx
catch (err) { console.log(err); }
catch (err) { console.error('failed', err.response); }   // may contain the auth header
<div className="error">{error.message}</div>
<pre>{JSON.stringify(error, null, 2)}</pre>
alert(err.stack);
```

**Detecting it in a single file**

- Grep `console.log(err`, `console.error(err`, `console.log(error` inside
  `catch` blocks; check what the logged object can carry (`err.config.headers`
  on an axios error carries the `Authorization` header).
- Grep `error.message` / `error.response.data` rendered directly into JSX with
  no generic fallback.
- A swallowed error (`catch {}`) is a separate, smaller problem worth a note.

**Fix**

Log full error detail only to a controlled monitoring channel, not to a plain
console in production, and show the user a generic message. Never forward
`err.stack` or a raw backend error body into the DOM.

---

## 14. Missing input validation at trust boundaries

- **CWE:** CWE-20 — **OWASP:** A05:2025 Injection / A06:2025 Insecure Design
- **Severity:** medium — **Vibe-coding frequency:** very-high

Code trusts a URL query/hash param, a `postMessage` payload, or a third-party
API response to directly drive app logic, a fetch URL, or rendering without a
type/shape/allow-list check — including building request URLs by string
concatenation instead of `encodeURIComponent`/`URLSearchParams`, which can both
break the request and inject unexpected query structure.

**What it looks like in JavaScript**

```js
const id = new URLSearchParams(window.location.search).get('id');
fetch('/api/items?id=' + id);                  // concatenation, unvalidated
fetch(`/api/search?q=${query}&sort=${sort}`);  // template literal, unencoded
const state = JSON.parse(localStorage.getItem('state'));   // no shape check
setRows(state.rows);                                       // drives rendering
```

**Detecting it in a single file**

- Grep `URLSearchParams(window.location` and trace each `.get()` result forward
  to the first use — is there a check in between?
- Grep for `+` or template-literal interpolation immediately after `?` or `&`
  inside a `fetch(`/`axios(` URL.
- Grep `JSON.parse(` and check the result is shape-checked before it becomes
  props or state.
- A numeric id used unchecked is also an authorization question — see class 6.

**Fix**

Validate and allow-list every value crossing a trust boundary before using it in
logic, a URL, or a render. Always build query strings with `URLSearchParams` or
`encodeURIComponent` instead of concatenation.

---

## 15. Reverse tabnabbing: `target="_blank"` without `rel="noopener"`

- **CWE:** CWE-1022 — **OWASP:** A01:2025 Broken Access Control (no dedicated
  OWASP Top 10 category)
- **Severity:** medium — **Vibe-coding frequency:** high

A link or `window.open()` call opens an attacker-influenced URL in a new tab
without `rel="noopener noreferrer"`. The opened page can then use
`window.opener` to navigate the original tab to a phishing page. Modern
browsers default `target="_blank"` anchors to `noopener`, but `window.open()`
calls and older/transpiled code are not covered.

**What it looks like in JavaScript**

```jsx
<a href={row.externalUrl} target="_blank">Open</a>     // no rel
window.open(url);                                      // no 'noopener'
window.open(url, '_blank');                            // still no 'noopener'
```

**Detecting it in a single file**

- Grep `target="_blank"` / `target='_blank'` and check the same tag carries
  `rel="noopener` (`noreferrer` too, to drop the Referer header).
- Grep `window.open(` and check `'noopener'` appears in the features string
  (third argument).

**Fix**

Add `rel="noopener noreferrer"` to every `target="_blank"` link —
`eslint-plugin-react`'s `jsx-no-target-blank` enforces this — and pass
`'noopener'` in `window.open()`'s third argument.

---

## 16. Debug mode, source maps, or verbose logging left on in production

- **CWE:** CWE-489 — **OWASP:** A02:2025 Security Misconfiguration (A05:2021
  Security Misconfiguration)
- **Severity:** medium — **Vibe-coding frequency:** high

A production webpack build ships with `devtool: 'source-map'` (or unminified
output), leftover `debugger` statements, or a global `DEBUG` flag left `true`,
exposing original source, internal comments, and any secrets that were only
"hidden" by minification.

**What it looks like in JavaScript**

```js
// webpack.config.js
module.exports = { mode: 'production', devtool: 'source-map' };  // maps deployed
debugger;                                   // left in committed code
const DEBUG = true;
if (DEBUG || user.isAdmin) { showInternalPanel(); }   // debug flag gating a bypass
window.DEBUG = true;
```

**Detecting it in a single file**

- Grep `devtool` in `webpack.config*.js` and confirm it is disabled or hidden
  in the production branch and that maps are not deployed.
- Grep `debugger;` across `.js`/`.jsx`.
- Grep case-insensitively for `DEBUG`/`VERBOSE`/`TEST_MODE` flags and check
  none of them gate security-relevant behaviour.

**Fix**

Disable or exclude source maps from the deployed artifact for production
builds, strip `debugger` statements via the minifier, and remove any
DEBUG-gated bypass before shipping.

---

## 17. Open redirect via unchecked redirect target

- **CWE:** CWE-601 — **OWASP:** A01:2025 Broken Access Control (A01:2021
  Broken Access Control)
- **Severity:** medium — **Vibe-coding frequency:** medium

A "return to" or "next" URL taken from a query parameter is passed straight to
`window.location` or a router `navigate()` without checking it points back into
the app's own origin, letting an attacker craft a trusted-looking link that
ends on a phishing site.

**What it looks like in JavaScript**

```js
window.location = new URLSearchParams(location.search).get('redirect');
navigate(params.get('returnUrl'));
history.push(searchParams.get('next'));
window.location.href = `${base}${params.get('to')}`;
```

**Detecting it in a single file**

- Grep `window.location`, `navigate(`, `history.push(`, `router.push(` and
  trace whether the target comes from a URL param; if it does, is it checked to
  be a relative path or a same-origin absolute URL?
- `startsWith('/')` alone is insufficient: `//evil.com` also starts with `/`
  and is a protocol-relative absolute URL.

**Fix**

Allow only redirect targets that are relative paths within the app — reject
values containing `://` and values starting with `//` — or validate against an
explicit allow-list of destinations.

---

## 18. Weak client-side randomness for tokens, ids, or nonces

- **CWE:** CWE-338 — **OWASP:** A04:2025 Cryptographic Failures (A02:2021
  Cryptographic Failures)
- **Severity:** medium — **Vibe-coding frequency:** medium

`Math.random()` is used to generate something security-relevant — a nonce, a
reset/OTP-style code, a session or request id relied on for correlation, or a
"unique" key relied on to prevent collisions — even though it is not
cryptographically secure and is predictable from a few observed outputs.

**What it looks like in JavaScript**

```js
const id = Math.random().toString(36).substring(2);
const nonce = Math.random().toString(16);
const resetCode = String(Math.floor(Math.random() * 1000000));
const token = Date.now() + '-' + Math.random();
```

**Detecting it in a single file**

- Grep `Math.random(` and classify each use: pure UI randomness (animation
  jitter, sampling, placeholder colours) is fine; anything flowing into a
  variable named `token`, `nonce`, `secret`, `otp`, `resetCode`, `sessionId`,
  or used as a persisted key is a finding.

**Fix**

Use `crypto.getRandomValues()` — or `crypto.randomUUID()` for ids — for
anything with security relevance. Reserve `Math.random()` for non-security UI
randomness only.

---

## 19. Homemade or misapplied client-side cryptography

- **CWE:** CWE-321 — **OWASP:** A04:2025 Cryptographic Failures (A02:2021
  Cryptographic Failures)
- **Severity:** medium — **Vibe-coding frequency:** medium

Code implements its own "encryption" (XOR or base64 mistaken for encryption),
or uses a real crypto library with a hardcoded key/IV baked into the bundle, or
in ECB mode — giving a false sense of confidentiality for data that is fully
readable by anyone inspecting the shipped JS.

**What it looks like in JavaScript**

```js
CryptoJS.AES.encrypt(data, 'my-super-secret-key');        // key ships in the bundle
CryptoJS.AES.encrypt(data, key, { mode: CryptoJS.mode.ECB });
const hidden = btoa(password);                            // encoding, not encryption
const scrambled = [...text].map(c => c ^ 42);             // homemade XOR
```

**Detecting it in a single file**

- Grep `CryptoJS.` / `crypto-js` and check whether the key/IV is a literal
  string rather than derived per session from the server.
- Grep `btoa(` / `atob(` near variable names like `password`, `secret`,
  `token` — someone may be treating encoding as protection.
- Grep `mode.ECB`, and any hand-written `^`/`charCodeAt` "cipher".

**Fix**

Do not implement confidentiality in client JS — any key shipped in the bundle
is public. Move genuine encryption needs server-side; client-side crypto must
never be the sole protection for a secret.

---

## 20. Permissive CORS on client-configured cross-origin calls

- **CWE:** CWE-942 — **OWASP:** A02:2025 Security Misconfiguration (A05:2021
  Security Misconfiguration)
- **Severity:** medium — **Vibe-coding frequency:** medium

A `fetch`/`axios` call sets `credentials: 'include'` / `withCredentials: true`
against an endpoint — or the webpack devServer proxy — that pairs a wildcard
`Access-Control-Allow-Origin` with credentials. Browsers actually reject that
combination, but AI-generated config commonly attempts it, and its presence
signals the backend CORS policy is over-broad.

**What it looks like in JavaScript**

```js
axios.create({ withCredentials: true, baseURL: 'https://third-party.example' });
fetch(url, { credentials: 'include' });          // url from config, any origin
// webpack.config.js
devServer: { proxy: { '/api': { target: '...', changeOrigin: true, secure: false } } }
```

**Detecting it in a single file**

- Grep `withCredentials: true` / `credentials: 'include'` and check every
  target origin is the trusted API, not a configurable or third-party URL.
- In `webpack.config.js`, read `devServer.proxy` and any `cors(` config for
  wildcards or `secure: false` carried into a shared/staging config.

**Fix**

Send credentials only to your own API origin. Keep wildcard or relaxed CORS
proxy settings strictly inside local-dev-only webpack config, never merged into
a shared or production config.

---

## 21. ReDoS: catastrophic-backtracking regex on user input

- **CWE:** CWE-1333 — **OWASP:** A06:2025 Insecure Design
- **Severity:** medium — **Vibe-coding frequency:** medium

A regex with nested or overlapping quantifiers runs against user-controlled
input — a form field, a search box — client-side; a crafted string makes the
regex engine hang the tab. Covered by `eslint-plugin-security`'s
`detect-unsafe-regex`, and separately by `detect-non-literal-regexp` when the
pattern itself is built from a variable.

**What it looks like in JavaScript**

```js
const valid = /^(\w+)+$/.test(input);            // nested quantifier
/^([a-zA-Z]+)*$/.test(name);
/(a|aa)+$/.test(value);                          // overlapping alternation
new RegExp(userInput).test(text);                // pattern from user input
new RegExp(`^${prefix}.*`);                      // unescaped interpolation
```

**Detecting it in a single file**

- Look for a quantified group inside another quantified group: `+)+`, `*)*`,
  `+)*`, `*)+`, and alternations whose branches can match the same text.
- Grep `new RegExp(` and check the pattern argument is a literal, not
  user-controlled or interpolated without escaping.
- Mentally test each validation regex against a long run of matching characters
  followed by one non-matching character (`'aaaaaaaaaaaaaaaaaaaaaaaaa!'`).
  Do **not** actually execute the file to test this.

**Fix**

Rewrite ambiguous nested quantifiers as simpler, non-backtracking equivalents;
never build a `RegExp` pattern from untrusted input; run validation regexes
through a ReDoS linter (e.g. `safe-regex`) before merging.

---

## 22. Untrusted or unpinned third-party scripts loaded at runtime

- **CWE:** CWE-829 — **OWASP:** A08:2025 Software or Data Integrity Failures
  (A08:2021 Software and Data Integrity Failures)
- **Severity:** medium — **Vibe-coding frequency:** low

A `<script src>` pulled from a CDN — in an HTML dashboard's `<head>`, or
injected dynamically — has no Subresource Integrity hash, or its `src` URL is
built from a configurable/user-influenced value. If the CDN or the config is
compromised, the injected script runs with full page privileges.

**What it looks like in JavaScript**

```html
<script src="https://cdn.example.com/lib.js"></script>   <!-- no integrity= -->
```

```js
const s = document.createElement('script');
s.src = config.analyticsUrl;                             // src from config
document.head.appendChild(s);
```

**Detecting it in a single file**

- Grep `<script src=` in any `.html` dashboard and check for a matching
  `integrity="sha384-..."` and `crossorigin="anonymous"`.
- Grep `createElement('script')` and trace where `.src` is assigned from.
- A version-less CDN path (`/latest/`, `/dist/lib.js`) is unpinned even when an
  integrity hash is absent-by-necessity — flag it.

**Fix**

Add a Subresource Integrity hash and `crossorigin="anonymous"` to any
externally-hosted script tag, or vendor the library inline into the
self-contained HTML file.

---

## 23. CSV / Excel formula injection in data export

- **CWE:** CWE-1236 — **OWASP:** A05:2025 Injection (A03:2021 Injection)
- **Severity:** medium — **Vibe-coding frequency:** low

A "download as CSV/Excel" feature writes cell values straight from data, which
may include user-entered text, without checking for a leading `=`, `+`, `-`, or
`@`. Opening the exported file in Excel or Sheets can execute the cell as a
formula against whoever exported it or later opened it.

**What it looks like in JavaScript**

```js
const csv = rows.map(r => [r.name, r.note].join(',')).join('\n');
const blob = new Blob([csv], { type: 'text/csv' });      // r.note = "=cmd|'...'!A1"
```

**Detecting it in a single file**

- Grep CSV-building code (`join(',')`, `new Blob([`, `text/csv`,
  `application/vnd.ms-excel`) and check each cell value is inspected for a
  leading `=`, `+`, `-`, `@` (and tab/CR) before being written.
- Find the export/download button handler and read what sanitizes the row data.
- Quoting a cell for CSV correctness does **not** neutralise the formula.

**Fix**

Before writing any cell that could start with `=`, `+`, `-`, or `@`, prefix it
with a single quote (`'`) or a tab so spreadsheet apps treat it as text.

---

## 24. DOM clobbering via named HTML elements overriding globals

- **CWE:** CWE-79 (XSS-adjacent) — **OWASP:** A05:2025 Injection (no dedicated
  OWASP Top 10 category)
- **Severity:** low — **Vibe-coding frequency:** low

Browsers auto-create global references from elements with matching `id`/`name`
attributes (`form`, `img`, `embed`, `object`, `iframe`). If attacker-controlled
HTML can be injected anywhere on the page, it can override a global or DOM
property the app's own script relies on — commonly weaponized to redirect a
dynamic `<script src>` or a config lookup. There is no dedicated CWE; it is
typically chained into CWE-79.

**What it looks like in JavaScript**

```js
const url = someConfig.apiUrl;                   // someConfig never assigned in JS
script.src = window.CDN_BASE + '/lib.js';        // CDN_BASE clobberable
if (document.getElementById('x').value) { ... }  // element may be attacker's
```

The injected payload looks like
`<a id="someConfig"><a id="someConfig" name="apiUrl" href="https://evil/">`.

**Detecting it in a single file**

- Grep for global lookups (`window.X`, or a bare identifier) that are never
  explicitly assigned anywhere in the JS — likely relying on implicit DOM-id
  globals.
- In any HTML dashboard that echoes user content, check whether injected HTML
  could carry an `id`/`name` matching a variable the script later reads.
- Clobbering requires an HTML injection point, so class 1 findings on the same
  page raise this from theoretical to exploitable.

**Fix**

Never rely on implicit id/name-to-global binding; declare and assign
configuration and state explicitly in JS, and close the HTML injection point
(class 1), since clobbering requires one to begin with.

---

## 25. Hidden or invisible Unicode in copy-pasted or AI-generated code

- **CWE:** CWE-1007 — **OWASP:** A08:2025 Software or Data Integrity Failures
- **Severity:** low — **Vibe-coding frequency:** low

Bidirectional control characters or other invisible Unicode code points,
copy-pasted from an AI chat response or a compromised snippet source, can make
code render differently than it executes (Trojan Source-style) or silently
smuggle characters into a string literal that look identical to the visible
text but are not.

**What it looks like in JavaScript**

- A diff or PR showing a line with no visible change but a byte-level change.
- String literals containing zero-width or bidi-control code points: U+200B,
  U+202A–U+202E, U+2066–U+2069.
- A comparison or an allow-list entry that looks correct on screen but never
  matches at runtime.

**Detecting it in a single file**

- `grep -nP '[\x{200B}\x{202A}-\x{202E}\x{2066}-\x{2069}]' <file>` (requires a
  PCRE-capable grep; GNU grep with `-P`, or `rg` with the same class).
- `eslint-plugin-security`'s `detect-bidi-characters` rule flags these directly.
- A string comparison that "should work but doesn't" is the usual symptom.

**Fix**

Enable `eslint-plugin-security`'s `detect-bidi-characters` in CI and treat any
diff with invisible-looking changes as suspicious until confirmed.

---

## Remediation and tooling notes

- **DOMPurify** — `DOMPurify.sanitize(html)`. Not a scanner: the standard
  remediation library to wrap around any `dangerouslySetInnerHTML` /
  `innerHTML` sink this review turns up.
- **semgrep** — `semgrep --config p/javascript --config p/react <file>`. Public
  rulesets catch DOM XSS sinks, hardcoded secrets, insecure randomness, and
  React patterns with no project config needed.
- **ESLint plugins** — `eslint-plugin-security` (`detect-eval-with-expression`,
  `detect-object-injection`, `detect-unsafe-regex`, `detect-non-literal-regexp`,
  `detect-bidi-characters`), `eslint-plugin-no-unsanitized`
  (`no-unsanitized/property`, `no-unsanitized/method`), `eslint-plugin-react`
  (`react/no-danger`, `react/jsx-no-target-blank`). Recommend them for the
  project's config; do not inject rules the project has not installed.
- **gitleaks** — `gitleaks detect --no-git --source <file>`. Regex secret
  scanner over a single file, no repo history needed.
- **npm audit / osv-scanner** — `npm audit --omit=dev`, or
  `osv-scanner --lockfile=package-lock.json`. Scoped to dependency files, not a
  single source file; run whenever a dependency changes (classes 7 and 9).

The skill runs only tools that are already installed and makes no network
calls: anything requiring a registry or advisory lookup is reported as
**NEEDS-HUMAN** with the exact package, version, and line named.
