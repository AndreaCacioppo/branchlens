# Java vulnerability catalog

Opened on demand by the `security-java` skill, during step 4 of its procedure.
Thirty classes, ordered by **severity** first, then by **vibe-coding
frequency** (how often AI-generated Java gets this wrong). Work top to bottom:
the first fifteen entries cover almost everything found in practice.

Each entry gives: CWE and OWASP mapping, severity, vibe-coding frequency, what
the flaw looks like in Java (concrete patterns), how to spot it reading a
single file, and the canonical fix.

The examples lean on a data-platform flavour (projects, samples, sequencing
files, upload and import endpoints) because that is where these patterns show
up concretely — the classes themselves are general Java/Spring.

## Index

| # | Class | Severity | Vibe freq. |
|---|-------|----------|------------|
| 1 | Missing/Broken Function-Level Authorization & IDOR | critical | very-high |
| 2 | Hardcoded Credentials & Secrets | critical | very-high |
| 3 | SQL / HQL / JPQL Injection via String Concatenation | critical | high |
| 4 | Path Traversal & Archive Extraction (Zip Slip) | critical | high |
| 5 | Command Injection via External Process Invocation | critical | medium |
| 6 | Unrestricted Dangerous File Upload | critical | medium |
| 7 | Server-Side Request Forgery (SSRF) | critical | medium |
| 8 | XML External Entity (XXE) Injection | critical | low |
| 9 | Deserialization of Untrusted Data | critical | low |
| 10 | Permissive CORS Misconfiguration | high | very-high |
| 11 | XSS in Server-Rendered Views | high | very-high |
| 12 | Information Exposure via Error Messages / Stack Traces | high | high |
| 13 | Log Injection / CRLF Injection into Logs | high | high |
| 14 | Mass Assignment / Over-Posting via Data Binding | high | high |
| 15 | Weak or Broken Cryptography & Insecure Randomness | high | high |
| 16 | Actuator/Debug Endpoints & Debug Mode Left Enabled | high | high |
| 17 | CSRF Protection Disabled or Misconfigured | high | medium |
| 18 | Spring Security Matcher / Configuration Misordering | high | medium |
| 19 | Improper Authentication / Session & Token Validation | high | medium |
| 20 | Improper Input Validation at Trust Boundaries | medium | high |
| 21 | Vulnerable, Outdated, or Hallucinated Dependencies | medium | medium |
| 22 | Uncontrolled Resource Consumption (DoS) | medium | medium |
| 23 | Thymeleaf/SpEL Server-Side Template Injection | medium | low |
| 24 | Improper Privilege Management / Vertical Escalation | medium | low |
| 25 | Missing Rate Limiting / Brute-Force Protection | medium | low |
| 26 | Disabled TLS / Certificate Validation | medium | low |
| 27 | LDAP Injection | medium | low |
| 28 | Open Redirect | low | low |
| 29 | Session Fixation / Insufficient Session Expiration | low | low |
| 30 | Race Conditions / TOCTOU in File Handling | low | low |

---

## 1. Missing/Broken Function-Level Authorization & IDOR

- **CWE:** CWE-862, CWE-863, CWE-639
- **OWASP:** A01:2021 Broken Access Control
- **Severity:** critical — **Vibe-coding frequency:** very-high

New `@RestController`/`@Controller` endpoints or service methods are added
without `@PreAuthorize`/`@Secured` checks, or an endpoint checks
authentication but never resource ownership, letting one authenticated user
reach another user's projects, samples or files by changing an ID.

**What it looks like in Java**
- `@GetMapping`/`@PostMapping`/`@PutMapping`/`@DeleteMapping` method with no
  `@PreAuthorize` while sibling methods in the same controller have one.
- `repository.findById(id)` result returned or acted on with no
  ownership/permission check in between.
- `SecurityContextHolder.getAuthentication()` fetched but never compared
  against the resource's owner or project membership.
- `@EnableMethodSecurity` present globally, but a newly added controller
  method skips the annotation.

**Detecting it in a single file**
- Enumerate every `@*Mapping` method in the controller and check each has
  `@PreAuthorize`/`@Secured`, or a class-level equivalent.
- Look for `findById(` / repository lookups followed directly by `return`
  with no permission-service call in between.
- Compare a new controller method against its siblings in the same file: a
  missing `@PreAuthorize` among annotated peers is the tell.

**Fix** — Add `@PreAuthorize` expressing both authentication and object-level
ownership (e.g. `hasPermission(#id,'Project','canReadProject')`) to every
endpoint, and add a test asserting 403 for a non-owner.

---

## 2. Hardcoded Credentials & Secrets

- **CWE:** CWE-798, CWE-321, CWE-259
- **OWASP:** A02:2021 Cryptographic Failures / A07:2021 Identification and
  Authentication Failures
- **Severity:** critical — **Vibe-coding frequency:** very-high

DB passwords, JWT signing keys, SMTP/API credentials or migration-seeded admin
passwords are hardcoded in Java source, `application.properties`/`.yml` or
test fixtures, and often reused across dev, staging and production.

**What it looks like in Java**
- `String password = "...";` or `@Value("${prop:literalDefault}")` with a
  real-looking default.
- `spring.datasource.password=`, `jwt.secret=`, `smtp.password=` set to a
  plaintext literal in a tracked `application*.properties`/`.yml`.
- A Liquibase/Flyway changelog `INSERT` seeding an admin user with a hardcoded
  password or hash.
- `new SecretKeySpec("hardcoded-string".getBytes(), ...)`.

**Detecting it in a single file**
- `grep -rE 'password\s*=\s*"|secret\s*=\s*"|apiKey\s*=\s*"'` across `.java`.
- In `application.properties`/`.yml`, any `password=`/`secret=` assigned a
  literal instead of `${ENV_VAR}`.
- In changelogs, `INSERT INTO ...user... VALUES` with a literal password/hash.

**Fix** — Externalize every secret via environment variables or a secrets
manager, keep only `${ENV_VAR:}` placeholders in tracked config, and rotate
any credential ever committed to git history.

---

## 3. SQL / HQL / JPQL Injection via String Concatenation

- **CWE:** CWE-89, CWE-564
- **OWASP:** A03:2021 Injection
- **Severity:** critical — **Vibe-coding frequency:** high

HQL/JPQL/native SQL built by concatenating request parameters, most often in
dynamic search/filter/sort endpoints and admin report screens, or a raw
`ORDER BY`/column name arriving straight from the client into the query.

**What it looks like in Java**
- `entityManager.createQuery("... WHERE x = '" + input + "'")`.
- `session.createNativeQuery("SELECT * FROM " + tableName)`.
- `@Query(value = "..." + variable, nativeQuery = true)`.
- An unvalidated `sort`/`orderBy` request parameter concatenated into a query.

**Detecting it in a single file**
- `createQuery(` / `createNativeQuery(` / `createSQLQuery(` — inspect the
  argument for `+` concatenation or `String.format`.
- `@Query(` with `nativeQuery = true` near a `+` or `String.format`.
- A sort/filter request parameter passed into a query string rather than into
  an allow-list-mapped `Sort` object.

**Fix** — Use named or positional parameters (`:name`, `setParameter`) or the
JPA Criteria/Specification API; for dynamic sort/filter, map the client value
against an allow-list of column names before use.

---

## 4. Path Traversal in File-Serving Endpoints & Archive Extraction (Zip Slip)

- **CWE:** CWE-22, CWE-23, CWE-73
- **OWASP:** A01:2021 Broken Access Control
- **Severity:** critical — **Vibe-coding frequency:** high

Download/upload endpoints build a filesystem path from a request parameter or
an uploaded file's original name without normalizing or containing it. The
same flaw appears when extracting an uploaded archive (a multi-file bundle)
without checking each `ZipEntry` name for traversal.

**What it looks like in Java**
- `new File(baseDir, request.getParameter("file"))` or
  `Paths.get(baseDir, userInput)` with no `normalize()`/`startsWith()` check.
- `MultipartFile.getOriginalFilename()` used directly as the destination name.
- `ZipInputStream`/`ZipFile` writing each entry via
  `new File(outputDir, entry.getName())` with no check for `../` or an
  absolute path.
- `@GetMapping("/files/{filename:.+}")` resolving the filename straight to a
  `Path` with no canonicalization.

**Detecting it in a single file**
- `getOriginalFilename()` — check for sanitization nearby
  (`FilenameUtils.getName(`, `Path.normalize()` + `startsWith()`).
- `new File(` / `Paths.get(` with a variable built from a request or path
  parameter.
- `ZipEntry` / `ZipInputStream` — confirm `entry.getName()` is validated
  against the destination directory before extraction.

**Fix** — Resolve against the base directory, call `normalize()`, and verify
`startsWith(baseDir)` before use; for archive extraction, reject any entry
whose resolved path escapes the destination directory.

---

## 5. Command Injection via External Process Invocation

- **CWE:** CWE-78, CWE-77, CWE-88
- **OWASP:** A03:2021 Injection
- **Severity:** critical — **Vibe-coding frequency:** medium

Data pipelines commonly shell out to external tools (aligners, QC tools,
format converters). Building the command line by concatenating a filename or
sample name that originated from user input allows argument or command
injection.

**What it looks like in Java**
- `Runtime.getRuntime().exec("tool " + userInput)` or
  `new ProcessBuilder("sh","-c", command)` with a concatenated command.
- `ProcessBuilder(cmdString.split(" "))` built from `String.format` with a
  request parameter.
- An uploaded file's original filename passed directly as a CLI argument to an
  external converter.

**Detecting it in a single file**
- `Runtime.getRuntime().exec(` / `new ProcessBuilder(` — inspect whether any
  argument is built by concatenation or formatting from user input.
- `"sh", "-c"` or `"/bin/bash", "-c"` with a concatenated string.

**Fix** — Use `ProcessBuilder` with a fixed executable and each argument as a
separate array element (never through a shell), and validate/allow-list
filenames before they reach the argument list.

---

## 6. Unrestricted Dangerous File Upload

- **CWE:** CWE-434, CWE-646
- **OWASP:** A04:2021 Insecure Design / A05:2021 Security Misconfiguration
- **Severity:** critical — **Vibe-coding frequency:** medium

Upload endpoints trust the client-supplied content-type or extension, store
files inside the webroot, or allow archive/script content with no size, type
or count limits — enabling webshell upload or storage-exhaustion DoS.

**What it looks like in Java**
- `@RequestParam("file") MultipartFile` accepted with no extension or
  content-type allow-list before `transferTo()`.
- Upload destination inside a directory served statically by the app.
- No `spring.servlet.multipart.max-file-size` /
  `spring.servlet.multipart.max-request-size` configured, or set unbounded.

**Detecting it in a single file**
- `@RequestParam("file") MultipartFile` — check for an allow-list plus a
  max-size check before `transferTo()`.
- In `application.properties`, the two multipart size limits.
- Check the upload destination is not under a `ResourceHandler`-mapped or
  static webroot path.

**Fix** — Validate extension and actual content (magic-byte check, not just
the `Content-Type` header) against an allow-list, store outside the webroot
under a generated filename, and enforce file-size and request-size limits.

---

## 7. Server-Side Request Forgery (SSRF)

- **CWE:** CWE-918
- **OWASP:** A10:2021 SSRF (2025 draft: folded into A01 Broken Access Control)
- **Severity:** critical — **Vibe-coding frequency:** medium

Features that fetch a client-supplied URL — metadata import, webhook
registration, remote reference-file fetch — pass it straight to
`RestTemplate`/`WebClient`/`HttpClient` with no allow-list, letting an
attacker probe internal services or cloud metadata endpoints.

**What it looks like in Java**
- `restTemplate.getForObject(userSuppliedUrl, ...)` or
  `WebClient.get().uri(userSuppliedUrl)` with no host/scheme validation.
- `new URL(request.getParameter("url")).openConnection()` with no allow-list.
- A webhook/callback URL stored from user input and later invoked server-side
  by a scheduled job.

**Detecting it in a single file**
- `restTemplate.getForObject(` / `restTemplate.exchange(` / `WebClient` —
  trace the URI argument back to a request parameter.
- `new URL(` / `openConnection()` fed by user input with no scheme/host check
  nearby.

**Fix** — Validate the target against an allow-list of hosts and schemes,
resolve DNS and reject private/loopback/link-local ranges, and disable or
re-validate redirects.

---

## 8. XML External Entity (XXE) Injection

- **CWE:** CWE-611, CWE-827
- **OWASP:** A05:2021 Security Misconfiguration
- **Severity:** critical — **Vibe-coding frequency:** low

XML parsing left at library defaults for metadata import (sample-sheet or
submission XML) or legacy SOAP integration has external entity resolution
enabled by default in `DocumentBuilderFactory`/`SAXParserFactory`/
`XMLInputFactory`, permitting local file read or SSRF via a crafted `DOCTYPE`.

**What it looks like in Java**
- `DocumentBuilderFactory.newInstance()` parsing untrusted XML with no
  `setFeature(...disallow-doctype-decl...)` call.
- `SAXParserFactory`/`XMLInputFactory` instantiated without disabling
  external-general-entities and external-parameter-entities.
- A JAXB `Unmarshaller` fed untrusted XML directly.

**Detecting it in a single file**
- `DocumentBuilderFactory.newInstance()` / `SAXParserFactory.newInstance()` /
  `XMLInputFactory.newInstance()` — check for the disallow-doctype-decl and
  external-entities=false calls immediately after.
- `Unmarshaller` usage on a stream sourced from an upload or HTTP body.

**Fix** — Disable DOCTYPE declarations and external entity/parameter
resolution on every XML parser factory used for untrusted input, and set
`XMLConstants.ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_SCHEMA` to an empty string.

---

## 9. Deserialization of Untrusted Data

- **CWE:** CWE-502
- **OWASP:** A08:2021 Software and Data Integrity Failures
- **Severity:** critical — **Vibe-coding frequency:** low

Native Java deserialization (`ObjectInputStream`) of a session attribute,
cache entry, uploaded blob or cross-service payload lets an attacker with any
gadget class on the classpath achieve remote code execution. Jackson
polymorphic default typing on untrusted JSON is the modern equivalent.

**What it looks like in Java**
- `new ObjectInputStream(untrustedStream).readObject()` on data from an HTTP
  request, uploaded file or message queue.
- A distributed cache/session store deserializing arbitrary Java objects with
  no class allow-list.
- `ObjectMapper` with `enableDefaultTyping()`/`activateDefaultTyping()` fed
  untrusted JSON.

**Detecting it in a single file**
- `new ObjectInputStream(` — trace the source stream back to request, file or
  network input.
- `enableDefaultTyping` / `activateDefaultTyping` in `ObjectMapper` setup.

**Fix** — Avoid native Java deserialization of untrusted data; if unavoidable,
wrap `ObjectInputStream` with an `ObjectInputFilter` allow-list, and never
enable Jackson polymorphic default typing on input crossing a trust boundary.

---

## 10. Permissive CORS Misconfiguration

- **CWE:** CWE-942, CWE-346
- **OWASP:** A05:2021 Security Misconfiguration
- **Severity:** high — **Vibe-coding frequency:** very-high

The REST API's CORS policy is opened to `*` — often as a quick fix for a
blocked cross-origin request during development — while also allowing
credentials, or a `CorsConfiguration` is registered globally instead of scoped
to the actual frontend origin(s).

**What it looks like in Java**
- `config.addAllowedOrigin("*")` together with `config.setAllowCredentials(true)`.
- `@CrossOrigin(origins = "*")` on a controller relying on session/cookie auth.
- `allowedOriginPatterns("*")` left in place past local development.

**Detecting it in a single file**
- `addAllowedOrigin("*")` / `allowedOrigins("*")` / `allowedOriginPatterns("*")`
  — check whether `allowCredentials(true)` appears nearby.
- `@CrossOrigin` annotations carrying a wildcard origin.

**Fix** — Enumerate the exact allowed origins (env-configurable per
environment) instead of a wildcard, and never combine a wildcard origin with
`allowCredentials(true)`.

---

## 11. Cross-Site Scripting (XSS) in Server-Rendered Views

- **CWE:** CWE-79
- **OWASP:** A03:2021 Injection
- **Severity:** high — **Vibe-coding frequency:** very-high

JSP/Thymeleaf views echo user-controlled data (names, comments, descriptions)
via an unescaped output directive, or a controller builds an HTML/JS string by
concatenation and returns it as `ResponseEntity<String>`/`@ResponseBody`.

**What it looks like in Java**
- Thymeleaf `th:utext="${userValue}"` instead of `th:text`.
- JSP `<%= request.getParameter(...) %>` or `c:out escapeXml="false"`.
- A controller concatenating an HTML string (`"<div>" + userInput`) and
  returning it via `@ResponseBody`.

**Detecting it in a single file**
- `th:utext=` in `.html` templates.
- `escapeXml="false"` or raw `<%=` scriptlets in `.jsp` files.
- HTML string concatenation followed by `@ResponseBody`/`ResponseEntity<String>`.

**Fix** — Use the auto-escaping output form (`th:text`, default-escaping
`c:out`) everywhere user data reaches HTML, and add a Content-Security-Policy
header as defense in depth.

---

## 12. Information Exposure via Error Messages / Stack Traces

- **CWE:** CWE-209, CWE-200, CWE-756
- **OWASP:** A05:2021 Security Misconfiguration / A09:2021 Security Logging
  and Monitoring Failures
- **Severity:** high — **Vibe-coding frequency:** high

A generic `@ExceptionHandler` or catch block returns `e.getMessage()` or the
full stack trace to the client, leaking package names, SQL fragments or file
paths; often paired with `server.error.include-stacktrace=always` left on in
production.

**What it looks like in Java**
- `@ExceptionHandler(Exception.class)` returning
  `ResponseEntity.status(500).body(e.getMessage())` or `e.toString()`.
- `catch (Exception e) { return e.getMessage(); }` in a controller.
- `server.error.include-stacktrace=always` / `include-message=always` in a
  production profile.

**Detecting it in a single file**
- `@ExceptionHandler` methods — check whether the response body includes
  `e.getMessage()`, `e.toString()` or `printStackTrace`.
- `include-stacktrace` / `include-message` in `application*.properties`/`.yml`.

**Fix** — Return a generic, non-identifying error body to the client, log the
full exception server-side only, and set `server.error.include-stacktrace=never`
for production profiles.

---

## 13. Log Injection / CRLF Injection into Logs

- **CWE:** CWE-117, CWE-93
- **OWASP:** A09:2021 Security Logging and Monitoring Failures
- **Severity:** high — **Vibe-coding frequency:** high

Request parameters (usernames, filenames, sample IDs) are logged with a plain
SLF4J/Log4j2 call with no newline stripping, letting an attacker forge log
lines or, on unpatched Log4j2 versions, trigger JNDI-lookup RCE (Log4Shell) if
the logged string contains a `${jndi:...}` pattern.

**What it looks like in Java**
- `logger.info("User login: " + username)` or
  `logger.info("File requested: {}", filename)` with the value taken straight
  from a request parameter.
- A `log4j-core` version pinned below 2.17.1 in `pom.xml`.
- No CRLF/control-character stripping before a user-controlled value reaches a
  log statement.

**Detecting it in a single file**
- `log.info(` / `logger.info(` / `LOG.warn(` lines interpolating a request
  parameter or header value directly.
- In `pom.xml`, the `log4j-core` version compared against 2.17.1+.

**Fix** — Strip or encode newlines and control characters from any
user-controlled value before logging (or use a structured logging encoder that
does it automatically), and keep Log4j2 patched to the latest 2.x line.

---

## 14. Mass Assignment / Over-Posting via Data Binding

- **CWE:** CWE-915
- **OWASP:** A08:2021 Software and Data Integrity Failures
- **Severity:** high — **Vibe-coding frequency:** high

A controller binds the full request body or form directly onto a JPA entity
(via `@ModelAttribute`, or a `@RequestBody` DTO mirroring the entity 1:1)
instead of a purpose-built input DTO, letting a client set fields like `role`,
`enabled` or `ownerId` that were never meant to be client-writable.

**What it looks like in Java**
- `@PostMapping` taking the JPA `@Entity` class itself as the
  `@RequestBody`/`@ModelAttribute` parameter.
- No `@InitBinder` with `setAllowedFields`/`setDisallowedFields` restricting
  bindable properties on a form-backing entity.
- A DTO that includes an `isAdmin`/`role`/`id` field the endpoint should never
  let the caller set.

**Detecting it in a single file**
- `@RequestBody` / `@ModelAttribute` parameter types — check whether they are
  the same class annotated `@Entity`.
- Whether `@InitBinder` is present in controllers that bind entities directly.

**Fix** — Bind requests to a narrow input DTO containing only client-settable
fields, and map it explicitly onto the entity server-side rather than binding
the persistent entity directly. (See also Spring's CVE-2022-22968 data-binding
rules change.)

---

## 15. Weak or Broken Cryptography & Insecure Randomness

- **CWE:** CWE-327, CWE-326, CWE-330, CWE-759
- **OWASP:** A02:2021 Cryptographic Failures
- **Severity:** high — **Vibe-coding frequency:** high

Password hashing with MD5/SHA-1 or unsalted digests, symmetric encryption in
ECB mode or with a fixed IV/key, and use of `java.util.Random`/`Math.random()`
to generate reset tokens, API keys or session identifiers instead of
`SecureRandom`.

**What it looks like in Java**
- `MessageDigest.getInstance("MD5")` or `("SHA-1")` used for password hashing.
- `Cipher.getInstance("AES/ECB/...")` or a hardcoded/static IV.
- `new Random()` or `Math.random()` used to build a token, password-reset code
  or API key.

**Detecting it in a single file**
- `MessageDigest.getInstance("MD5"` / `("SHA-1"` near password or token hashing.
- `AES/ECB`, or `Cipher.getInstance(` with no explicit GCM/CBC + random IV.
- `new Random()` / `Math.random()` near names like `token`, `otp`,
  `resetCode`, `apiKey`.

**Fix** — Hash passwords with BCrypt/Argon2/PBKDF2 via Spring Security's
`PasswordEncoder`, use AES-GCM with a freshly generated IV per operation, and
generate all security-sensitive random values with `java.security.SecureRandom`.

---

## 16. Actuator/Debug Endpoints & Debug Mode Left Enabled

- **CWE:** CWE-489, CWE-215, CWE-1188
- **OWASP:** A05:2021 Security Misconfiguration
- **Severity:** high — **Vibe-coding frequency:** high

Spring Boot Actuator endpoints (`env`, `heapdump`, `beans`, `mappings`)
exposed without authentication in production reveal configuration and
environment variables (often including secrets); similarly
`spring.profiles.active=dev`, verbose SQL or template-cache-off settings left
on in a production deployment leak internals.

**What it looks like in Java**
- `management.endpoints.web.exposure.include=*` with no per-endpoint
  restriction and no dedicated security rule for `/actuator/**`.
- No `.requestMatchers("/actuator/**").authenticated()` (or equivalent) in the
  `SecurityFilterChain`.
- `spring.jpa.show-sql=true` or `spring.thymeleaf.cache=false` left in an
  `application-prod.properties`.

**Detecting it in a single file**
- `management.endpoints.web.exposure.include` in `application*.properties`/
  `.yml` with a `*` value.
- In the `SecurityFilterChain`, whether `/actuator/**` is matched and secured.

**Fix** — Expose only the actuator endpoints actually needed (health/info)
behind authentication on a separate management port, and keep debug flags and
verbose SQL logging out of production profiles.

---

## 17. CSRF Protection Disabled or Misconfigured

- **CWE:** CWE-352
- **OWASP:** A01:2021 Broken Access Control
- **Severity:** high — **Vibe-coding frequency:** medium

`http.csrf(csrf -> csrf.disable())` applied to the whole `SecurityFilterChain`
— a common quick fix for a blocked POST during development — rather than
scoped to stateless REST-API paths only, leaving the server-rendered,
session-cookie-authenticated parts of the app open to CSRF.

**What it looks like in Java**
- `http.csrf(csrf -> csrf.disable())` or `http.csrf().disable()` applied
  globally in `SecurityConfig`.
- `csrf.ignoringRequestMatchers("/**")` or another overly broad ignore pattern.
- A state-changing GET endpoint (e.g. `/delete?id=`) performing a mutation,
  bypassing CSRF protection entirely.

**Detecting it in a single file**
- `csrf(` combined with `.disable()`, or `.csrf().disable()` in `SecurityConfig`.
- `ignoringRequestMatchers` with a wildcard or overly broad pattern.
- `@GetMapping` methods calling a save/delete/update repository method.

**Fix** — Keep CSRF protection enabled for any endpoint reachable with
cookie/session auth from a browser, and scope any disabling narrowly to
genuinely stateless, token-authenticated API paths.

---

## 18. Spring Security Matcher / Configuration Misordering

- **CWE:** CWE-284, CWE-863
- **OWASP:** A01:2021 Broken Access Control
- **Severity:** high — **Vibe-coding frequency:** medium

`authorizeHttpRequests` rules are order-sensitive: a broad
`.anyRequest().permitAll()` or an early permissive matcher placed before a
more specific restrictive one silently opens paths meant to be protected.
Mixing `AntPathRequestMatcher` and `MvcRequestMatcher` inconsistently can also
create bypassable rules.

**What it looks like in Java**
- `.requestMatchers("/admin/**").hasRole("ADMIN")` placed **after** a
  `.anyRequest().permitAll()` — unreachable, so effectively unprotected.
- `.requestMatchers("/api/**").permitAll()` accidentally matching an endpoint
  meant to require auth, through overlapping patterns.
- `@PreAuthorize` used in controllers with no `@EnableMethodSecurity` /
  `@EnableGlobalMethodSecurity` present anywhere — silently ignored.

**Detecting it in a single file**
- Read the `authorizeHttpRequests` chain top to bottom and check that
  `permitAll()`/`anyRequest()` rules come last, not before specific
  `hasRole`/`authenticated` rules.
- When `@PreAuthorize` is used, confirm `@EnableMethodSecurity` or
  `@EnableGlobalMethodSecurity` exists somewhere in the configuration.

**Fix** — Order matchers from most-specific/most-restrictive to least, with
`anyRequest()` last, and confirm `@EnableMethodSecurity` is present whenever
`@PreAuthorize`/`@PostAuthorize` is relied on.

---

## 19. Improper Authentication / Session & Token Validation

- **CWE:** CWE-287, CWE-613, CWE-347
- **OWASP:** A07:2021 Identification and Authentication Failures
- **Severity:** high — **Vibe-coding frequency:** medium

Custom authentication filters or REST API token/JWT validation skip signature
verification, accept `alg:none`, do not check expiry, or do not invalidate the
session on logout or password change — relevant to OAuth2/JWT-secured REST
endpoints alongside a session-based server-rendered UI.

**What it looks like in Java**
- `Jwts.parser()` (jjwt) configured without `setSigningKey`/`verifyWith`, or
  accepting an unverified token.
- A custom `OncePerRequestFilter` extracting a token and trusting its claims
  without a verification call.
- No `session.invalidate()` / `SecurityContextHolder.clearContext()` on logout.

**Detecting it in a single file**
- `Jwts.parser` / `parseClaimsJwt` / `JwtParser` — confirm a signing-key
  verification call is present, not just parsing.
- A custom `AuthenticationFilter`/`OncePerRequestFilter` — check it validates
  signature and expiry, not merely the presence of a header.

**Fix** — Always verify JWT signature and expiry with a fixed,
server-controlled algorithm and key (reject `alg:none`), invalidate
sessions/tokens on logout, and prefer Spring Security's built-in OAuth2
resource-server support over hand-rolled parsing.

---

## 20. Improper Input Validation at Trust Boundaries

- **CWE:** CWE-20, CWE-1284
- **OWASP:** A03:2021 Injection / A04:2021 Insecure Design
- **Severity:** medium — **Vibe-coding frequency:** high

Request parameters, path variables and multipart metadata (names, coordinates,
numeric IDs) are used directly with no type/range/format validation — missing
`@Valid`/Bean Validation annotations on DTOs, or a `@PathVariable` used
downstream with no existence or format check.

**What it looks like in Java**
- A `@RequestBody` DTO with no `@Valid` on the controller parameter and no
  Bean Validation annotations (`@NotNull`, `@Size`, `@Pattern`) on its fields.
- `@PathVariable`/`@RequestParam` used directly in business logic with no
  bounds or format check.
- A declared file size or checksum trusted from the client instead of
  recomputed server-side.

**Detecting it in a single file**
- `@RequestBody` parameters — check the DTO class for Bean Validation
  annotations and whether the controller parameter has `@Valid`/`@Validated`.
- `@PathVariable`/`@RequestParam` feeding directly into a repository or
  service call with no validation in between.

**Fix** — Annotate DTOs with Bean Validation constraints, add `@Valid` to the
controller parameter, and re-derive any security-relevant value (file size,
checksum, type) server-side rather than trusting client-declared metadata.

---

## 21. Vulnerable, Outdated, or Hallucinated Dependencies (Supply Chain)

- **CWE:** CWE-1104, CWE-937, CWE-829
- **OWASP:** A06:2021 Vulnerable and Outdated Components (2025 draft: elevated
  as A03 Software Supply Chain Failures)
- **Severity:** medium — **Vibe-coding frequency:** medium

`pom.xml` is pinned to old versions of Spring Framework/Spring Security,
Jackson, Log4j2 or Commons libraries with known CVEs (the Log4Shell /
Spring4Shell class). Separately, an AI assistant may suggest a Maven
`groupId:artifactId` coordinate that does not actually exist on Maven Central
("slopsquatting"), which an attacker can pre-register with malicious code.

**What it looks like in Java**
- A `<dependency>` version far behind the current release line for
  `spring-core`, `spring-security-*`, `jackson-databind` or `log4j-core`.
- A newly added Maven coordinate copy-pasted from an AI suggestion, never
  independently verified to exist or to come from the intended publisher.
- No dependency-check / dependency-track step in the CI pipeline.

**Detecting it in a single file**
- In `pom.xml`, `<dependency>` versions for `spring-*`, `jackson-databind`,
  `log4j-core`, `commons-collections` compared against the latest patched line.
- For any dependency added in the current change, whether the
  `groupId:artifactId` is one a human has confirmed on the real registry.
  **This skill does not go online** — report it as unverified and say so.

**Fix** — Run OWASP Dependency-Check or an SCA tool in CI on every `pom.xml`
change, keep security-sensitive libraries on a maintained patch line, and
manually verify any newly introduced coordinate against the real registry.

---

## 22. Uncontrolled Resource Consumption (DoS)

- **CWE:** CWE-400, CWE-1333, CWE-770
- **OWASP:** A04:2021 Insecure Design
- **Severity:** medium — **Vibe-coding frequency:** medium

Endpoints that accept unbounded uploads, return an unpaged `findAll()` to a
REST client, or compile a regex built from user input (ReDoS) can exhaust
memory, DB connections or CPU with a single crafted request — worse on a
platform already handling very large files.

**What it looks like in Java**
- `repository.findAll()` returned directly from a REST endpoint with no
  `Pageable` or limit.
- `Pattern.compile(userSuppliedRegex)`, or a hand-written regex with nested
  quantifiers applied to user input.
- No `spring.servlet.multipart.max-file-size`/`max-request-size`, and no
  timeout on long-running jobs triggered synchronously from a request.

**Detecting it in a single file**
- `findAll()` return values feeding directly into a REST response.
- `Pattern.compile(` where the pattern string is built from a request parameter.
- Missing `max-file-size`/`max-request-size` in `application.properties`.

**Fix** — Paginate all list endpoints, validate or limit user-influenced
regexes, enforce upload size and rate limits, and run long jobs asynchronously
with a timeout rather than inline on the request thread.

---

## 23. Thymeleaf/SpEL Server-Side Template Injection

- **CWE:** CWE-1336, CWE-94
- **OWASP:** A03:2021 Injection
- **Severity:** medium — **Vibe-coding frequency:** low

Building a Thymeleaf template dynamically from user input, or evaluating
Spring Expression Language (SpEL) against untrusted input, lets an attacker
execute arbitrary Java code rather than merely inject markup.

**What it looks like in Java**
- `templateEngine.process(userSuppliedString, context)` instead of a fixed,
  developer-authored template name.
- `new SpelExpressionParser().parseExpression(userInput).getValue(...)`
  evaluating an attacker-controlled string.
- `@PreAuthorize`/`@PostAuthorize` expressions built by string concatenation
  of user input.

**Detecting it in a single file**
- `templateEngine.process(` — confirm the first argument is a fixed literal
  template name, not a variable derived from input.
- `ExpressionParser` / `SpelExpressionParser` / `parseExpression(` — trace the
  expression string back to user input.

**Fix** — Never pass user input as a template name or as a SpEL expression to
be evaluated; treat user data strictly as template variables.

---

## 24. Improper Privilege Management / Vertical Privilege Escalation

- **CWE:** CWE-269, CWE-266
- **OWASP:** A01:2021 Broken Access Control
- **Severity:** medium — **Vibe-coding frequency:** low

A self-service profile-update endpoint lets the authenticated user's own
request body include and change a role/authorities field, or a role check
compares strings ad hoc instead of going through Spring Security, allowing a
normal user to grant themselves elevated privileges.

**What it looks like in Java**
- A `/users/{id}` PUT/PATCH self-service endpoint mapping the full request DTO
  (including `role`) onto the `User` entity.
- `if (role.equals("ADMIN"))`-style checks scattered ad hoc instead of
  centralized through `hasRole`/`hasAuthority`.

**Detecting it in a single file**
- In self-service profile-update controllers, whether the bound DTO includes a
  `role`/`authorities`/`isAdmin` field.
- Manual role-string comparisons (`role.equals("ADMIN")`) outside the Spring
  Security authorization layer.

**Fix** — Exclude role and authority fields from any self-service update DTO,
and perform all role checks through Spring Security's authorization
mechanisms, never ad hoc string comparison in business logic.

---

## 25. Missing Rate Limiting / Brute-Force Protection on Auth Endpoints

- **CWE:** CWE-307, CWE-799
- **OWASP:** A07:2021 Identification and Authentication Failures
- **Severity:** medium — **Vibe-coding frequency:** low

Login, password-reset and API-token endpoints with no attempt-count lockout or
throttling let an attacker brute-force credentials or enumerate valid
usernames via response differences.

**What it looks like in Java**
- A login controller or `AuthenticationProvider` with no failed-attempt
  counter, lockout or CAPTCHA after N failures.
- A password-reset endpoint returning a different message for "user not found"
  than for "email sent".

**Detecting it in a single file**
- In the login controller/provider, any failed-attempt tracking (a lockout
  service, a `failedAttempts` field) — **absence is the finding**.
- On the password-reset endpoint, compare the response bodies and status codes
  for existing vs non-existing accounts.

**Fix** — Track failed login attempts per account/IP and apply lockout or
exponential backoff, and return an identical response regardless of account
existence on password-reset flows.

---

## 26. Disabled TLS / Certificate Validation

- **CWE:** CWE-295, CWE-296
- **OWASP:** A02:2021 Cryptographic Failures
- **Severity:** medium — **Vibe-coding frequency:** low

An outbound HTTP client (`RestTemplate`/`WebClient`/`HttpClient`) is
configured to trust all certificates or skip hostname verification — often
added "to fix an SSL error" while integrating with a self-signed-certificate
internal service — and then left in place.

**What it looks like in Java**
- A custom `TrustManager` whose `checkServerTrusted`/`checkClientTrusted`
  methods are empty (trust everything).
- A `HostnameVerifier` returning `true` unconditionally, or
  `NoopHostnameVerifier` used outside a clearly test-only profile.
- `SSLContextBuilder.loadTrustMaterial(TrustAllStrategy...)` reachable in a
  non-test code path.

**Detecting it in a single file**
- `TrustManager` implementations with an empty or no-op `checkServerTrusted`.
- `NoopHostnameVerifier` / `ALLOW_ALL_HOSTNAME_VERIFIER` / `TrustAllStrategy`.

**Fix** — Never disable certificate or hostname validation outside an isolated
test profile; import the specific internal CA into a dedicated truststore
instead of trusting everything.

---

## 27. LDAP Injection

- **CWE:** CWE-90
- **OWASP:** A03:2021 Injection
- **Severity:** medium — **Vibe-coding frequency:** low

Deployments authenticating against LDAP/Active Directory build the search
filter by concatenating the submitted username, letting a crafted username
alter the filter's logic and bypass authentication or enumerate directory
entries.

**What it looks like in Java**
- `String filter = "(uid=" + username + ")"` passed to `DirContext.search(...)`
  or an `LdapTemplate` query.
- Spring LDAP `FilterBuilder`/`EqualsFilter` bypassed in favour of manually
  string-built filters.

**Detecting it in a single file**
- `(uid=` / `(cn=` / `(sAMAccountName=` string concatenation feeding into
  `DirContext.search` or `LdapTemplate`.

**Fix** — Build LDAP filters with Spring LDAP's `FilterBuilder`/`EqualsFilter`
(which escape special characters) rather than by string concatenation.

---

## 28. Open Redirect

- **CWE:** CWE-601
- **OWASP:** A01:2021 Broken Access Control
- **Severity:** low — **Vibe-coding frequency:** low

A login/logout "return to" URL or an export/redirect endpoint takes a
`redirectUrl`/`next` request parameter and passes it straight to
`response.sendRedirect()` or a Spring `redirect:` view, letting an attacker
craft a link that redirects to a phishing site.

**What it looks like in Java**
- `response.sendRedirect(request.getParameter("redirectUrl"))` with no
  allow-list or relative-path check.
- `return "redirect:" + request.getParameter("next")` in a controller method.

**Detecting it in a single file**
- `sendRedirect(` or `"redirect:" +` — check whether the target is validated
  as a relative or allow-listed path.

**Fix** — Restrict redirect targets to a fixed allow-list or to relative paths
within the app; never echo an arbitrary client-supplied absolute URL into a
redirect.

---

## 29. Session Fixation / Insufficient Session Expiration

- **CWE:** CWE-384, CWE-613
- **OWASP:** A07:2021 Identification and Authentication Failures
- **Severity:** low — **Vibe-coding frequency:** low

A custom login flow that does not call `session.changeSessionId()` (or rely on
Spring Security's default session-fixation protection) lets an attacker fix a
victim's session ID before authentication and hijack it afterwards; sessions
with no or excessive timeout stay valid too long.

**What it looks like in Java**
- A custom `AuthenticationSuccessHandler` or manual login endpoint that never
  invokes `sessionStrategy.onAuthentication`/`changeSessionId`.
- `server.servlet.session.timeout` set unreasonably long, or unset.
- `sessionManagement().sessionFixation().none()` explicitly set, disabling the
  default protection.

**Detecting it in a single file**
- `sessionFixation()` configuration in `SecurityConfig` set to `.none()`.
- `server.servlet.session.timeout` in `application*.properties`.

**Fix** — Keep Spring Security's default session-fixation protection
(`migrateSession`/`newSession`) enabled, and set a reasonable, explicit
session timeout.

---

## 30. Race Conditions / TOCTOU in File Handling

- **CWE:** CWE-362, CWE-367
- **OWASP:** A04:2021 Insecure Design
- **Severity:** low — **Vibe-coding frequency:** low

Checking whether a file exists or validating its content, then acting on it in
a separate step, leaves a window in which a concurrent request changes the
file between the check and the use — relevant to concurrent uploads targeting
the same logical resource.

**What it looks like in Java**
- `if (file.exists()) { ... }` followed by a separate open/read/write call
  rather than an atomic operation.
- Two concurrent upload requests for the same target path with no locking and
  no unique-per-request naming.

**Detecting it in a single file**
- `File.exists()` / `Files.exists(` followed shortly after by a separate file
  open or write, with no synchronization or atomic move in between.

**Fix** — Use atomic file operations (`Files.move` with `ATOMIC_MOVE`, or a
unique-temp-name-then-rename pattern) instead of separate exists-then-act
steps, and serialize concurrent writes to the same logical resource.

---

## Appendix — tooling landscape

For context only. The `security-java` skill runs **at most** `semgrep` and a
read-only `mvn`/`pom.xml` inspection, and only when already installed. It
never installs, never builds, never uploads a file.

| Tool | Invocation | Note |
|------|-----------|------|
| Semgrep (java + spring packs) | `semgrep --config p/java --config p/spring-boot --config p/security-audit File.java` | Single-file, no build step. The spring pack covers CSRF-disable, permissive CORS and data-binding patterns. |
| SpotBugs + Find Security Bugs | `spotbugs -textui -pluginList findsecbugs-plugin.jar -low MyClass.class` | Needs compiled `.class` files, not `.java` source. ~150 security detectors (SQLi, XXE, hardcoded crypto/passwords, command injection). Out of scope for a single-file read; report only whether the project has it configured. |
| OWASP Dependency-Check | `mvn org.owasp:dependency-check-maven:check` | Operates on the resolved dependency graph, not one source file, and needs the network. Belongs in CI, not in this skill. |
| gitleaks | `gitleaks detect --source File.java --no-git` | Single-file secret scan; complements class 2. Only if already installed. |
| CodeQL | `codeql database analyze javadb java-security-and-quality.qls` | Needs a whole-program database; gives the data-flow depth a single-file read structurally cannot. The right escalation when a finding is marked NEEDS-HUMAN. |

## Sources

- CWE Top 25 (2024, CISA/MITRE ranking). Memory-safety CWEs (787, 125, 119,
  416, 476, 190, 362) are excluded as not applicable to managed-memory Java
  web code, except where CWE-362 appears as a file-handling TOCTOU.
- OWASP Top 10 — 2021 edition, and the 2025 release candidate (new Software
  Supply Chain Failures category, SSRF folded into Broken Access Control,
  Security Misconfiguration risen to #2).
- Find Security Bugs (SpotBugs plugin) bug-pattern catalog.
- Semgrep Registry `java/security` and `spring` rule packs; Trail of Bits
  Semgrep Java rules.
- Spring Security reference documentation (CSRF, method security, matchers).
- OWASP cheat sheets: Mass Assignment, XXE Prevention; OWASP WSTG.
- CWE-117 (log injection) and the CodeQL Java log-injection query help.
- Spring Framework data-binding rules, CVE-2022-22968.
- Reports on AI-generated-code failure rates and secret exposure in
  AI-assisted commits; slopsquatting / hallucinated-package coverage.
