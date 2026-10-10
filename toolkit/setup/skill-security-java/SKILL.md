---
name: security-java
description: >-
  Deep per-file security review of Java source, tailored to the language and
  its Spring/JPA stack: reads the whole file, maps its trust boundaries, then
  walks a 30-class Java vulnerability catalog plus a second pass for the
  mistakes AI-generated Java makes most. Triggers on /security-java <file>,
  "security check this Java file", "review this controller for
  vulnerabilities", "is this endpoint safe?". Report-only: it NEVER modifies
  the target or any other repository file, never installs anything, never
  executes the code under review. Complements `security-pipeline` (repo-level,
  diff-scoped publication gate) — this is the single-file deep dive. CLEAN
  means "nothing found by a static single-file read", never "secure".
---

# security-java

One file at a time, read in full, judged against a Java-specific catalog. The
output is a report handed to the user; nothing is fixed, staged or committed.

Scope, stated once so it is not confused with the other two skills:

- **security-java** (this one) — one file, deep, catalog-driven, report-only.
- **security-pipeline** — whole repository, diff-scoped, one publication verdict.
- **preflight-gate** — the mechanical scanners alone, diff-scoped.

## When to run it

- The user runs `/security-java <file> [more files...]`.
- The user asks to security-check, audit or "look for vulnerabilities in" a
  specific `.java` file, controller, service, filter or `SecurityConfig`.
- A file was just written or heavily edited by an AI assistant and needs a
  second, adversarial read before review.
- Something in the diff-scoped pipeline pointed at one file and the user wants
  to understand it properly rather than see a scanner rule name.

Do **not** use it as a publication gate, and do not use it to sweep a whole
repository — that is `security-pipeline`.

## Procedure

1. **Resolve the target file(s)** from the arguments. Accept several. If no
   argument was given, **ask which file** — never pick a file, a directory or
   a whole repository by yourself. Confirm each path exists and is readable;
   if a file cannot be read, say so plainly and stop for that file.

2. **Read the ENTIRE file**, top to bottom, plus the minimum context needed to
   place its trust boundaries — and nothing more:
   - the imports (they identify the stack: Spring MVC/WebFlux, JPA/Hibernate,
     Jackson, JJWT, Apache HttpClient, Thymeleaf/JSP, `java.io`/`java.nio`);
   - the class-level annotations (`@RestController`, `@Controller`,
     `@Service`, `@Configuration`, `@EnableMethodSecurity`, `@Entity`);
   - how the file is reached — which values arrive from outside
     (`@RequestParam`, `@PathVariable`, `@RequestBody`, `@RequestHeader`,
     `MultipartFile`, message-queue payloads, files on disk) and where they
     end up (query, filesystem path, process argument, template, log, HTTP
     client, deserializer);
   - for a Spring config file, the `SecurityFilterChain` in full, in order.

   You may open a sibling file (the `SecurityConfig`, the bound DTO/entity,
   `application*.properties`) when a judgement genuinely depends on it — say
   which and why. **Never execute the code under review**: no `java`, no
   `mvn test`, no running the app, no `main()`. Reading only.

3. **Best-effort mechanical pass — only with tools already installed.** Test
   each with `command -v <tool>` first, and never install anything:
   - `semgrep` → `semgrep --metrics=off --config p/java <file>`. A `p/...`
     config is a *registry* name: semgrep fetches it from semgrep.dev unless it
     is already cached, and a renamed pack simply 404s (`p/spring-boot` no
     longer resolves). That collides with the no-network rule below, so: prefer
     a local rules file (`--config <path/to/rules.yaml>`) when the project has
     one; otherwise run the `p/` config only if it resolves from cache. If it
     tries to fetch, or fails, report
     `semgrep: skipped: ruleset unavailable offline` and move on — never treat
     a fetch as permission to go online for anything else.
     When the project ships no rules file of its own, use the rule set in
     `checks/semgrep-rules/` of the BranchLens toolkit (`toolkit/`), if present
     (`--config <that directory>`). Fall back to a `p/` pack only if
     `ls ~/.semgrep/cache 2>/dev/null` shows it already cached; otherwise record
     it skipped and do not invoke semgrep at all.
   - `mvn` → **only** to locate an existing SpotBugs/Find Security Bugs
     configuration in the project (reading `pom.xml` directly is usually
     enough). Never `compile`, `package`, `test`, `install` or any goal that
     builds or downloads. SpotBugs needs compiled classes, so this skill never
     runs it — note whether the project has it wired, as context for the user.

   A missing tool is reported as `skipped: not installed`. It is **never** an
   error, never a reason to stop, and never a reason to install something. The
   checklist review in step 4 is the substance; this pass is corroboration.

4. **Checklist review — the core of the skill.** Open
   `references/catalog.md` and work through it class by class, in order: it is
   sorted by severity, then by how often AI-generated Java gets it wrong. For
   each class, use its *detection hints* against the file you just read, and
   decide: not applicable (the file has no such sink), present and safe (say
   what makes it safe), or a finding. Rules that hold without exception:
   - **every finding cites a real line number from the file you just read** —
     open the file again to confirm the number if unsure;
   - a finding needs the concrete path from an untrusted input to the
     dangerous sink, in one sentence — not a rule name;
   - if you cannot judge something from this file alone (the ownership check
     may live in a service you have not read, the parser may be hardened by a
     factory bean elsewhere), that is not a pass — it goes to **NEEDS-HUMAN**
     with the exact question that stayed open.

   **Before filing any missing-authorization finding, find out where this
   codebase puts authorization.** Many Spring applications annotate the
   *service* layer, not the controller, so a controller with no `@PreAuthorize`
   anywhere is the normal shape, not a vulnerability. Open the services this
   file calls and look for `@PreAuthorize`/`@PostFilter` with object-level
   `hasPermission(...)` expressions, and confirm method security is actually
   switched on (`@EnableGlobalMethodSecurity` / `@EnableMethodSecurity` in a
   config class) — annotations without it are silently unenforced. Only after
   that check comes back empty is a missing-authorization finding real.
   Reporting a CRITICAL IDOR on every endpoint of a service-layer-authorized
   controller is the single most likely false positive this skill can produce.

5. **Vibe-coding second pass.** Re-scan the file specifically for the mistakes
   AI-generated Java makes most often — these are missed on a first read
   because the surrounding code looks idiomatic:
   1. New endpoint with **no `@PreAuthorize`/`@Secured` and no ownership
      check** while sibling methods in the same controller have one — IDOR by
      default.
   2. **Hardcoded secrets** — passwords, JWT signing keys, API keys pasted
      into source or `application*.properties` instead of `${ENV_VAR}`.
   3. **Wildcard CORS** (`addAllowedOrigin("*")` / `@CrossOrigin(origins="*")`)
      combined with `allowCredentials(true)`, added to unblock a browser call.
   4. **Unescaped output** in server-rendered templates (`th:utext`,
      `escapeXml="false"`, raw `<%= %>`) — stored/reflected XSS.
   5. **Verbose exception handlers** returning `e.getMessage()` or a stack
      trace straight to the client.
   6. **String-concatenated SQL/HQL/native queries**, above all in generated
      search, filter and sort endpoints.
   7. **Mass assignment** — binding the JPA `@Entity` itself, or a DTO that
      mirrors it 1:1, directly to request input.
   8. **Weak crypto / insecure randomness** — MD5 or SHA-1 password hashing,
      `new Random()` or `Math.random()` for tokens, AES/ECB, fixed IV.
   9. **Debug and actuator exposure** — `management.endpoints.web.exposure.include=*`,
      `show-sql=true`, `include-stacktrace=always` reachable in production config.
   10. **Unverified Maven coordinates** — a `groupId:artifactId` that may not
       exist on Maven Central (AI-hallucinated, "slopsquatting" bait). Flag it
       for manual verification; do **not** go online to check.

   Then write the report.

## Output format

One block per file. Findings table first, ordered by severity:

```
FILE: <absolute path>  (<n> lines read)
TOOLS: semgrep <version|skipped: not installed|skipped: ruleset unavailable offline> · spotbugs <configured in pom|not configured|skipped: not installed>

LINE | CWE     | SEVERITY | FINDING                                   | FIX
-----|---------|----------|-------------------------------------------|---------------------------
 142 | CWE-862 | CRITICAL | @GetMapping /projects/{id} returns the     | Add @PreAuthorize with an
     |         |          | entity with no ownership check; any        | ownership expression and a
     |         |          | authenticated user reads any project      | 403 test for a non-owner
  58 | CWE-798 | HIGH     | JWT signing key hardcoded as a literal    | Move to ${JWT_SECRET}, rotate
```

Severity is the catalog's severity for that class, adjusted down only with a
stated reason (e.g. the sink is reachable only from an admin-only path — say
which line proves it). Never adjust up or down silently.

Then, per file, exactly one verdict line:

- `CLEAN` — no finding from this static single-file read.
- `FINDINGS: <count>, max severity <CRITICAL|HIGH|MEDIUM|LOW>`.
- `NEEDS-HUMAN` — plus the named questions a single-file static read cannot
  answer, one per line, each concrete: "line 91 calls
  `permissionService.canRead(id)` — this file cannot show whether that method
  actually compares the caller to the owner", "the `DocumentBuilderFactory` is
  injected; whether DOCTYPE is disabled depends on the bean definition".
  `NEEDS-HUMAN` can accompany findings — report both.
  When there are **zero** table findings but at least one open
  undecidable item, the verdict is **NEEDS-HUMAN, not CLEAN**: CLEAN is
  reserved for a file where nothing was found *and* nothing was left
  open. Say "0 findings, n open items" so both facts are visible.

Close every report with the honest reminder, in the user's words if they
prefer: **CLEAN means nothing was found by a static, single-file read.** It
does not mean the file is secure. Whole-program data flow, the runtime
configuration, the deployment, and every other file in the repository were not
examined; for code touching authorization, personal data or money, a human
reviewer is still warranted.

## Inviolable rules

- **Report-only.** Never edit, format, refactor or "fix" the target file or
  any other file in the repository. Findings are proposed as text; the user
  applies them.
- **Never execute the code under review**, nor build the project.
- **No installs.** Not semgrep, not a plugin, not a dependency, not "just this
  once". A missing tool is reported as skipped.
- **No network calls.** No CVE lookups, no package-registry queries, no
  uploading the file anywhere. An unverifiable dependency coordinate is
  reported as unverified, never resolved online.
- **Never soften or omit a finding**, and never drop one because the file is
  the user's own work, because it "is probably fine", or because a scanner
  stayed silent. A disagreement is reported with its reason, not by deletion.
- **If a file cannot be read** (missing, unreadable, binary, not the language
  claimed), say so explicitly and stop for that file. Never review from
  memory, from the filename, or from a guess about the content.
- **Every finding cites a line that exists** in the file as read. No invented
  line numbers, no invented code, no findings about code that is not there.
- Never claim the file, the endpoint or the application is secure. The
  strongest statement available is `CLEAN`, with its stated meaning.

## Installation

Copy this directory to `~/.claude/skills/security-java/`.
