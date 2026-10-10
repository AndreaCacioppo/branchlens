# Bash / POSIX shell vulnerability catalog

The checklist for step 4 of `security-bash`. One section per vulnerability
class, ordered by severity and, within a severity, by how often the class
appears in AI-generated shell. Work top to bottom; the ordering is the
prioritisation.

Each section gives: CWE and OWASP mapping, severity, vibe-coding frequency,
what the class looks like in real shell code, how to detect it while reading a
single file, and the canonical fix.

Severity here is the baseline. Adjust it for the file under review: the same
unquoted variable is a nuisance in a personal helper and a root compromise in a
script launched by a root cron entry. Reachability (can untrusted data reach
this line?) and privilege (who does this run as?) are the two multipliers.

## Contents

**Critical**

1. OS command injection via unsanitized input concatenated into shell commands
2. Unquoted variable / command-substitution expansion (SC2086 / SC2046)
3. `curl | bash` and unverified script or binary execution
4. Hardcoded credentials, API tokens and copy-pasted example secrets
5. `rm -rf` (or `mv`/`chmod -R`) driven by an unquoted or possibly-empty variable
6. Wildcard/glob argument injection into privileged file tools

**High**

7. Missing `set -euo pipefail` / unchecked exit codes
8. Missing input validation at trust boundaries
9. Secrets passed as command-line arguments, exposed via `ps` / `/proc`
10. systemd units shipped without sandboxing/hardening directives
11. Sensitive data written to logs via `set -x` / verbose output / cron mail
12. Path traversal via an unsanitized filename used to build a path
13. Insecure temporary file handling — predictable path, no `mktemp`, no trap
14. Backup/dump artifacts written with overly permissive permissions
15. SSH host-key verification disabled or weakened in automation
16. Cron/timer jobs pointing at a writable script or relying on a permissive PATH
17. `find -exec` / `xargs` without null-delimiting

**Medium**

18. Uncontrolled search path / PATH hijacking
19. TOCTOU race in check-then-act file/lock handling
20. Insufficient privilege separation — whole script run as root
21. Missing `--` separator lets a variable or glob be read as an option
22. Error handling that surfaces internal paths or raw stderr to outsiders
23. Slopsquatting — installing a hallucinated or unpinned package name

**Low**

24. Weak/predictable naming for temp files or tokens (`$RANDOM`, `$$`)
25. `trap` handlers defined with variables that expand at trap-set time (SC2064)
26. Unquoted `read` loops and unrestored `IFS` when parsing external data

---

# Critical

## 1. OS command injection via unsanitized input concatenated into shell commands

**CWE:** CWE-78, CWE-77 · **OWASP:** A03:2021 – Injection
**Severity:** critical · **Vibe-coding frequency:** very-high

**What it is.** Untrusted data — a filename from an inbox or manifest, a remote
hostname, a sequencer output name, a script argument, a value pulled from a
database or an API response — is interpolated into a command *string* which is
then executed, via `eval`, `sh -c`, `ssh host "..."`, or simply by running the
variable. The data can then supply shell metacharacters (`;`, `|`, `$()`,
backticks) and execute commands of its own choosing, with the script's
privileges.

**What it looks like**

```bash
eval "$user_supplied"

# remote command built by string concatenation
ssh "$host" "process_run $run_name"

bash -c "$input"

cmd="process $filename"
$cmd
```

**Detecting it in a single file**

- `grep -n 'eval ' script.sh` — every `eval` is a candidate; the question is
  only whether any part of its argument can come from outside.
- `grep -nE 'ssh .*"\$' script.sh` — check whether the remote command string
  embeds an unescaped variable. The remote side runs a *second* shell, so a
  value that is safely quoted locally is re-parsed there.
- `grep -nE '\$\(.*\$\{?[A-Za-z_]+' script.sh` — command substitution built
  out of variables.
- `sh -c`, `bash -c`, `xargs sh -c`, and any `$cmd` executed as a bare word.
- shellcheck flags several of these patterns directly (SC2116 and the SC2086
  family usually fire nearby).

**Canonical fix.** Never build command strings by concatenation. Pass data as
separate argv elements — an array in Bash:

```bash
cmd=(rsync -av -- "$src" "$dst")
"${cmd[@]}"
```

Use `printf %q` when a string genuinely has to cross a shell boundary (for
example into `ssh`), and avoid `eval` entirely.

## 2. Unquoted variable / command-substitution expansion (SC2086 / SC2046)

**CWE:** CWE-78, CWE-88 · **OWASP:** A03:2021 – Injection
**Severity:** critical · **Vibe-coding frequency:** very-high

**What it is.** An unquoted `$var` or `$(cmd)` is split on `IFS` and then
glob-expanded before the command ever sees it. In a pipeline that moves files
with externally-influenced names (spaces, `*`, a leading `-`, an embedded `;`),
one argument silently becomes several: files are dropped, duplicated, or a
crafted filename is parsed as a flag or a command by the invoked tool.

**What it looks like**

```bash
for f in $(ls $dir); do ...; done
rsync -av $SRC $DST
if [ $var = "x" ]; then ...; fi
cp $file /backup/
```

**Detecting it in a single file**

- `shellcheck script.sh` reports SC2086 (unquoted variable) and SC2046
  (unquoted command substitution) on every offending line — this is the single
  highest-yield mechanical check for shell.
- Reading manually: scan every command's argument list for a `$` that is not
  inside double quotes.
- `grep -n 'for .* in \$(' script.sh` — the classic word-splitting-over-`ls`
  antipattern.

**Canonical fix.** Double-quote every expansion: `"$var"`, `"$(cmd)"`. Iterate
files with `find ... -print0 | while IFS= read -r -d '' f` or with an array,
never with `for f in $(ls ...)`. Run shellcheck in CI and treat SC2086 as
build-breaking.

## 3. `curl | bash` and unverified script or binary execution

**CWE:** CWE-494, CWE-829 · **OWASP:** A08:2021 – Software and Data Integrity Failures
**Severity:** critical · **Vibe-coding frequency:** very-high

**What it is.** Provisioning and deploy scripts fetch and immediately execute
remote code, with no checksum, no signature, and sometimes with TLS
verification switched off. A compromised host, a DNS hijack, or a MITM on the
download path yields arbitrary code execution with the script's privileges —
usually root, since this runs at provisioning time.

**What it looks like**

```bash
curl -sSL https://example.com/install.sh | bash
wget -qO- https://example.com/setup | sudo sh
curl -k https://example.com/tool -o /usr/local/bin/tool     # TLS check disabled
curl -sSL https://get.example.io | sudo bash -
```

**Detecting it in a single file**

- `grep -nE 'curl.*\|\s*(sudo )?(ba)?sh' script.sh`
- `grep -nE 'wget.*\|\s*(sudo )?sh' script.sh`
- `grep -n 'curl -k\|curl --insecure\|wget --no-check-certificate' script.sh`
- Also flag downloads of a binary followed by `chmod +x` and execution with no
  checksum step in between, and any `latest` URL with no version pin.

**Canonical fix.** Download to a file first, verify a checksum or GPG signature
against a pinned value, then execute:

```bash
curl -fsSL -o installer.sh https://example.com/install.sh
sha256sum -c installer.sh.sha256
bash installer.sh
```

Never disable TLS verification. Pin versions rather than tracking `latest`.

## 4. Hardcoded credentials, API tokens and copy-pasted example secrets

**CWE:** CWE-798, CWE-259 · **OWASP:** A02:2021 – Cryptographic Failures
**Severity:** critical · **Vibe-coding frequency:** very-high

**What it is.** Database passwords, passphrase-less SSH key paths, cloud API
keys or webhook tokens are written literally into a deploy/backup script, into
a `.env` it sources, or into an `Environment=` line of a systemd unit — and
then committed. LLM-generated scripts reproduce plausible-looking placeholder
credentials from training data verbatim (well-known example AWS keys,
`admin:admin`), which are still real secrets once someone pastes a working
value over them and commits.

**What it looks like**

```bash
DB_PASSWORD="hunter2"
mysql -u root -pSuperSecret123 mydb
export AWS_SECRET_ACCESS_KEY=AKIA...
```

```ini
[Service]
Environment=API_KEY=sk-live-...
```

**Detecting it in a single file**

- `grep -nEi '(password|passwd|secret|token|api_key|apikey)\s*=\s*["\047][^"\047$]+["\047]' script.sh unit.service .env`
  — the `[^"\047$]` part is what separates a literal value from an indirection
  through another variable.
- `grep -n 'Environment=.*=' *.service` — inline secrets instead of
  `EnvironmentFile=` or `LoadCredential=`.
- A keyword grep misses high-entropy tokens with no label nearby; a dedicated
  secret scanner (gitleaks, trufflehog) is the complement — note this as a
  NEEDS-HUMAN item rather than running an uninstalled tool.

**Canonical fix.** Load secrets from a restricted file (`chmod 600`), a secrets
manager, or systemd `LoadCredential=` / `EnvironmentFile=` pointing outside the
repository. Never commit real or placeholder-shaped secrets. If one has
leaked, rotate it and scan the git history — removal from the working tree is
not remediation.

## 5. `rm -rf` (or `mv`/`chmod -R`) driven by an unquoted or possibly-empty variable

**CWE:** CWE-20, CWE-704 · **OWASP:** A01:2021 – Broken Access Control
**Severity:** critical · **Vibe-coding frequency:** high

**What it is.** A cleanup or backup-rotation step runs `rm -rf $DIR/*` or
`rm -rf "$1"`. If the variable is unset, empty, or resolves to `/` because an
earlier `cd` or computation failed unnoticed (no `set -u`, no exit-code check),
the command deletes far more than intended. This is a recurring and
catastrophic failure mode of AI-generated cleanup logic.

**What it looks like**

```bash
rm -rf $BUILD_DIR/*
rm -rf "$1"/
cd "$deploy_dir"; rm -rf ./*        # cd failure not checked
rm -rf ${TMPDIR:-}/                 # unsafe default expands to /
```

**Detecting it in a single file**

- `grep -nE 'rm -rf \$' script.sh` — flag every occurrence and trace backwards
  whether the variable can be empty or unset at that point.
- `grep -n 'cd \$' script.sh` followed by an `rm -rf` with no `&&` and no error
  check between them.
- Absence of `set -u` (or of explicit `${VAR:?msg}` guards) in a script that
  later deletes a variable path is itself the finding.
- The same reasoning applies to `mv`, `chmod -R`, `chown -R`, `find -delete`.

**Canonical fix.** Quote the variable, guard it, and chain after `cd`:

```bash
: "${BUILD_DIR:?BUILD_DIR must be set}"
cd "$deploy_dir" && rm -rf -- "$BUILD_DIR"/*
```

`--` blocks flag injection from an unexpected leading `-`; absolute paths
without `cd` are safer still.

## 6. Wildcard/glob argument injection into privileged file tools

**CWE:** CWE-88 · **OWASP:** A03:2021 – Injection
**Severity:** critical · **Vibe-coding frequency:** medium

**What it is.** A privileged script expands a bare `*` inside a directory an
untrusted party can write to — an incoming data drop folder, an upload
directory. A file named `-e sh shell.sh` or
`--checkpoint=1 --checkpoint-action=exec=...` is then handed to the tool as an
*option*, not a filename, smuggling flags — including remote-shell-execution
flags in `rsync` and `tar` — into a privileged invocation.

**What it looks like**

```bash
cd /srv/incoming
rsync -az * backup-host:/srv/          # a file named "-e sh evil.sh" is a flag
tar -czf out.tar.gz *
chown -R user:group *
chmod 644 *
```

**Detecting it in a single file**

- `grep -nE '(rsync|tar|chown|chmod|zip|7z) [^|]*\*' script.sh` — then check
  whether the glob is path-qualified (`/data/*`) or bare in a shared directory.
- Look for the absence of `--` before the glob: that absence is the tell.
- Whether the globbed directory is writable by anyone outside the pipeline is
  usually not answerable from the file — report it as NEEDS-HUMAN when the
  glob is otherwise unqualified.

**Canonical fix.** Always qualify globs with a full path and stop option
parsing before the data:

```bash
tar -czf out.tar.gz -- /srv/incoming/*
```

Restrict write access to the source directory to trusted producers.

---

# High

## 7. Missing `set -euo pipefail` / unchecked exit codes

**CWE:** CWE-252, CWE-703 · **OWASP:** A05:2021 – Security Misconfiguration
**Severity:** high · **Vibe-coding frequency:** very-high

**What it is.** Without `set -e`, a failed command — a database dump that
errored, an `scp` that transferred nothing, a `cd` into a directory that does
not exist — is ignored and the script continues as if it had succeeded. That
routinely means deleting a source file after a backup that never completed, or
running the rest of a deploy against a half-updated tree. Without `pipefail`, a
failure in an earlier pipeline stage is masked by the exit status of the last
one.

**What it looks like**

```bash
#!/bin/bash
# ...no set -e, no set -u, no set -o pipefail anywhere...

mysqldump -u backup mydb | gzip > backup.sql.gz   # auth failure ⇒ empty "successful" backup
cd $deploy_dir; rm -rf ./*                        # cd failed ⇒ rm runs in the wrong directory
```

**Detecting it in a single file**

- `grep -c 'set -e' script.sh` — zero hits in a script with any privileged or
  destructive step is a finding on its own.
- `grep -n 'set -o pipefail\|set -euo pipefail' script.sh` — absence combined
  with any `|` pipeline whose earlier stage can fail is a finding.
- Spot-check every `cd` for a following `|| exit` when `set -e` is absent.
- `set -u` deserves its own check: it is what turns class 5 from catastrophic
  into a clean abort.

**Canonical fix.** Start every script with `set -euo pipefail` (and
`IFS=$'\n\t'` when iterating over lines). Where a step is genuinely allowed to
fail, handle it explicitly — `cmd || true` with a logged reason — rather than
by omitting error checking for the whole file.

## 8. Missing input validation at trust boundaries

**CWE:** CWE-20 · **OWASP:** A03:2021 – Injection
**Severity:** high · **Vibe-coding frequency:** very-high

**What it is.** The script takes `$1`, an environment variable, or a field read
from a CSV/manifest and uses it directly to build a path, a command, or a
SQL/API call, with no allow-list, regex, or type check. This is the general
root cause behind several of the more specific classes here — injection, path
traversal, `rm -rf`. AI-generated scripts skip it routinely, because the
happy-path prompt never mentioned adversarial input.

**What it looks like**

```bash
target_host="$1"; ssh "$target_host" ...          # no check that $1 is a hostname
sample_id=$(cut -d, -f1 manifest.csv); mkdir "/data/$sample_id"
filename="$2"; cat "$filename"                    # no check for ".." or an absolute path
```

**Detecting it in a single file**

- `grep -n '\$1\|\$2\|\$@' script.sh` and check whether any validation
  (`case`, a regex `[[ =~ ]]`, a length/format test) appears *before* first
  use.
- `grep -n 'read ' script.sh` for loops over external files, and check whether
  fields are validated before being used in a path or a command.
- Absence of a usage/argument-count check (`if [ $# -lt 2 ]`) at the top of a
  script taking positional arguments.

**Canonical fix.** Validate every external input against an explicit allow-list
or regex before use, and fail closed:

```bash
[[ "$sample_id" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "bad sample id" >&2; exit 1; }
```

Reject anything containing `..`, `/`, or shell metacharacters where those are
not expected.

## 9. Secrets passed as command-line arguments, exposed via `ps` / `/proc`

**CWE:** CWE-200, CWE-214 · **OWASP:** A02:2021 – Cryptographic Failures
**Severity:** high · **Vibe-coding frequency:** high

**What it is.** `mysqldump -uroot -pMySecret db`, `curl -u user:pass`, or a
`postgresql://user:pass@host/db` URL put the credential directly into argv,
which every local user can read through `ps -ef` or `/proc/<pid>/cmdline` for
as long as the process lives. Very common on shared hosts and CI runners, and a
frequent AI suggestion because it works in a one-liner.

**What it looks like**

```bash
mysqldump -u root -pSecretPass dbname > dump.sql
curl -u admin:password https://api.example.com
psql "postgresql://user:password@host:5432/db"
```

**Detecting it in a single file**

- `grep -nE '\-p[A-Za-z0-9]+ ' script.sh` — the mysqldump/mysql inline-password
  form (note there is no space after `-p`).
- `grep -nE '\-u [A-Za-z0-9_.-]+:[^$[:space:]]+' script.sh` — `user:pass` for
  curl.
- `grep -n 'postgresql://.*:.*@' script.sh` — credential inside a connection
  string.
- A variable does not fix this: `-p"$DB_PASS"` still lands in argv.

**Canonical fix.** Use credential files with restrictive permissions:
`.my.cnf` (chmod 400) for MySQL, `.pgpass` (chmod 600) or `PGPASSFILE` for
Postgres, `.netrc` for curl. Environment variables set from a secrets manager
are the next best thing — still readable in `/proc/<pid>/environ` by the owner
and root, but not exposed to other users through `ps`.

## 10. systemd units shipped without sandboxing/hardening directives

**CWE:** CWE-250, CWE-732 · **OWASP:** A05:2021 – Security Misconfiguration
**Severity:** high · **Vibe-coding frequency:** high

**What it is.** A generated `.service`/`.timer` runs as root with no
`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, `ProtectHome`, and no
dedicated `User=`. If the script it launches is compromised through any of the
injection classes above, the blast radius is the whole host rather than a
sandboxed slice of it.

**What it looks like**

```ini
[Service]
Type=oneshot
ExecStart=/opt/app/run.sh
User=root
# ...and nothing else
```

Also: `ExecStart` lines containing shell metacharacters that rely on unit-file
expansion instead of a wrapper script; no `Restart=`/`WatchdogSec` on units
handling sensitive data pipelines.

**Detecting it in a single file**

- `grep -n 'NoNewPrivileges\|ProtectSystem\|PrivateTmp\|ProtectHome\|RestrictSUIDSGID' unit.service`
  — the finding is the empty result.
- `grep -n 'User=' unit.service` — `User=root`, or no `User=` at all (which
  means root), against a job that does not need it.
- `systemd-analyze security unit.service` scores the unit and lists every
  missing directive. This skill does not run it (no installs, no execution) —
  cite it as the human follow-up.

**Canonical fix.** Add `NoNewPrivileges=yes`, `ProtectSystem=strict`,
`ProtectHome=read-only` (or `tmpfs`), `PrivateTmp=yes`, `PrivateDevices=yes`,
`RestrictSUIDSGID=yes`, a dedicated non-root `User=`/`Group=`, and
`ReadWritePaths=` scoped to only the directories the job actually writes.

## 11. Sensitive data written to logs via `set -x` / verbose output / cron mail

**CWE:** CWE-532 · **OWASP:** A09:2021 – Security Logging and Monitoring Failures
**Severity:** high · **Vibe-coding frequency:** high

**What it is.** Debug tracing (`set -x`) or verbose tool flags left on in
production print full command lines — including any secret passed as an
argument or interpolated into a command — to stdout/stderr. cron mails that
out, systemd sends it to the journal, CI stores it in build logs; all three
typically have broader read access than the script's own credential store.

**What it looks like**

```bash
set -x                                   # active for the whole script
curl -v -H "Authorization: Bearer $TOKEN" https://api.example.com
echo "Connecting with password=$DB_PASS"
```

**Detecting it in a single file**

- `grep -n 'set -x' script.sh` — check whether it is bounded by a matching
  `set +x` around a non-sensitive section only.
- `grep -nE 'echo.*\$.*(PASS|SECRET|TOKEN|KEY)' script.sh`
- `grep -n 'curl -v\|curl --verbose' script.sh` near any `-u` or
  `Authorization` usage.
- Combine with class 9: a secret in argv plus `set -x` writes it to the log
  even if the command itself succeeds silently.

**Canonical fix.** Never combine a global `set -x` with a script that handles
secrets. If tracing is needed, bracket only the safe portion with
`set -x` / `set +x`, or redirect the trace to a file with restrictive
permissions (`exec 9>trace.log; BASH_XTRACEFD=9`). Strip `Authorization` and
password fields before logging tool output.

## 12. Path traversal via an unsanitized filename used to build a path

**CWE:** CWE-22 · **OWASP:** A01:2021 – Broken Access Control
**Severity:** high · **Vibe-coding frequency:** high

**What it is.** A pipeline reads a filename from a manifest, an upload
directory, or an argument, and builds a path with it (`"$base/$name"`) without
checking for `..` or a leading `/`. The input escapes the intended directory,
letting a crafted run name or manifest row read or overwrite any file reachable
with the script's privileges.

**What it looks like**

```bash
dest="/data/processed/$sample_name"; mv "$src" "$dest"   # sample_name unchecked
tar -xf "$upload" -C "$target_dir"                       # archive members unrestricted
cp "$incoming_dir/$user_supplied_name" "$archive_dir/"
```

Note that quoting does **not** fix this: `"../../etc/cron.d/evil"` is a single,
perfectly-quoted argument.

**Detecting it in a single file**

- Look for path construction by concatenation — `grep -n '\$base/\$\|\$dir/\$'`
  and any `"…/$var"` — and check for a preceding `..`/`/` rejection or a
  `realpath` canonicalisation.
- `grep -n 'tar -x\|unzip ' script.sh` — check for `--no-same-owner`, a
  validated extraction target, and whether the archive itself is trusted (the
  tar equivalent of zip-slip).
- Absolute-path inputs are the quiet case: `"$base/$name"` with
  `name=/etc/passwd` still traverses under some tools' semantics; reject a
  leading `/` explicitly.

**Canonical fix.** Reject any input path component containing `/` or `..`
before use, or canonicalise and verify containment:

```bash
resolved=$(realpath -e -- "$base/$name") || exit 1
case "$resolved" in "$base"/*) ;; *) echo "escape attempt" >&2; exit 1;; esac
```

Extract untrusted archives into an isolated directory and verify member paths
before moving anything.

## 13. Insecure temporary file handling — predictable path, no `mktemp`, no trap

**CWE:** CWE-377, CWE-367, CWE-379 · **OWASP:** A05:2021 – Security Misconfiguration
**Severity:** high · **Vibe-coding frequency:** high

**What it is.** The script writes to a fixed, guessable path such as
`/tmp/backup.sql` or `/tmp/$USER.lock` instead of using `mktemp`. On a
multi-user host this is both a race (another process or an attacker creates the
file, or a symlink pointing elsewhere, first) and an information disclosure
(default `/tmp` permissions may let other users read intermediate dump data
before it is moved or encrypted). Without an `EXIT` trap the file also survives
a crash instead of being cleaned up.

**What it looks like**

```bash
TMPFILE=/tmp/dump_$$.sql        # PID-based: predictable, not mktemp
echo "$data" > /tmp/output.txt  # fixed name, reused across runs
# ...and no `trap ... EXIT` anywhere
```

**Detecting it in a single file**

- `grep -n '/tmp/' script.sh` — for each hit, was the path produced by
  `mktemp`, or is it a literal or PID-based name?
- `grep -c 'mktemp' script.sh` — zero hits in a script that clearly stages
  intermediate data is a finding.
- `grep -n 'trap' script.sh` — check a cleanup trap exists for every temp path
  created (and see class 25 for how the trap itself is quoted).

**Canonical fix.**

```bash
TMPDIR_RUN=$(mktemp -d) || exit 1
trap 'rm -rf -- "$TMPDIR_RUN"' EXIT
```

`mktemp` creates with mode 0600 (0700 for `-d`) and an unpredictable name.
Prefer a private directory over loose files in shared `/tmp` when staging
sensitive dumps.

## 14. Backup/dump artifacts written with overly permissive permissions

**CWE:** CWE-732, CWE-276 · **OWASP:** A01:2021 – Broken Access Control
**Severity:** high · **Vibe-coding frequency:** medium

**What it is.** `mysqldump`, `pg_dump`, or a `tar` of sensitive data is written
to disk inheriting the process umask (often 022) with no explicit `chmod`,
leaving a file full of database contents, credentials, or person-linked data
group- or world-readable on a shared server.

**What it looks like**

```bash
pg_dump mydb > /backups/db.sql                  # ends up 0644
mysqldump ... > dump.sql && gzip dump.sql       # the .sql.gz is 0644 too
tar -czf /shared/data.tar.gz /data/runs/
```

**Detecting it in a single file**

- `grep -n 'umask' script.sh` — absence in a script that writes dumps or
  backups is the finding.
- After every `mysqldump`/`pg_dump`/`tar` redirection, look for a following
  `chmod 600` (or equivalent) *before* any step that might expose the file.
- The actual mode of the output directory used by a cron- or timer-invoked
  backup script cannot be read from the file — NEEDS-HUMAN.

**Canonical fix.** Set `umask 077` at the top of any script producing sensitive
output, or `chmod 600` the artifact immediately after creation and before any
further processing.

## 15. SSH host-key verification disabled or weakened in automation

**CWE:** CWE-295, CWE-322 · **OWASP:** A07:2021 – Identification and Authentication Failures
**Severity:** high · **Vibe-coding frequency:** medium

**What it is.** Deploy and backup scripts add
`-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null` so that
`ssh`/`scp`/`rsync -e ssh` "just work" non-interactively. Any host key is then
silently accepted, removing all MITM protection on the management network — a
very common shortcut in hand-written and AI-generated deploy tooling alike.

**What it looks like**

```bash
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null user@host
rsync -e 'ssh -o StrictHostKeyChecking=no' -av /data/ user@host:/srv/
scp -o StrictHostKeyChecking=no dump.sql.gz user@host:/backups/
```

**Detecting it in a single file**

- `grep -n 'StrictHostKeyChecking=no' script.sh`
- `grep -n 'UserKnownHostsFile=/dev/null' script.sh`
- Also check for the same options hidden in an `SSH_OPTS`-style variable
  assembled earlier in the file, and in `~/.ssh/config` fragments the script
  writes.

**Canonical fix.** Pre-populate `known_hosts` at provisioning time from a
trusted source (an `ssh-keyscan` result verified out of band, or a fingerprint
pinned in CI). Use at most `StrictHostKeyChecking=accept-new`, never `no`, so
unknown hosts are recorded but a *changed* key still fails closed.

## 16. Cron/timer jobs pointing at a writable script or relying on a permissive PATH

**CWE:** CWE-732, CWE-427 · **OWASP:** A05:2021 – Security Misconfiguration
**Severity:** high · **Vibe-coding frequency:** medium

**What it is.** A root cron entry or a timer's `ExecStart` runs a script that is
group- or world-writable, or the job's `PATH` contains a directory a
lower-privileged user can write to, or the script calls bare command names and
inherits an untrusted `PATH`. Anyone who can write to that script — or drop a
same-named binary earlier in `PATH` — gets code execution at the job's
privilege level.

**What it looks like**

```
*/5 * * * * root /opt/pipeline/run.sh          # run.sh is group-writable
PATH=/home/svc/bin:/usr/bin:/bin               # first entry writable by the service account
```

```bash
gzip "$file"        # bare name inside a root-run job
```

**Detecting it in a single file**

- For every script path referenced by a crontab, `/etc/cron.d/*` or an
  `ExecStart=`, the owner and mode of that file settle the question — and they
  cannot be read from the file's text. Report NEEDS-HUMAN with the exact
  command to run (`ls -la <path>`), flagging anything not owned and
  writable-only by root or the intended service account.
- `grep -n 'PATH=' crontab-or-unit` and check every directory listed for group
  or world write bits.
- Inside a root-executed script, bare command names cross-referenced against
  whichever `PATH` the job actually sets.

**Canonical fix.** Every script invoked by cron or systemd should be owned by
root (or the service account), mode 750/700, in a directory no other user can
write to. Set an explicit minimal `PATH` in the unit or crontab rather than
inheriting one, and call security-sensitive commands by absolute path.

## 17. `find -exec` / `xargs` without null-delimiting

**CWE:** CWE-78, CWE-88 · **OWASP:** A03:2021 – Injection
**Severity:** high · **Vibe-coding frequency:** medium

**What it is.** Enumerating files with `find ... | xargs cmd`, or building shell
lines from newline-delimited filenames, breaks on names containing spaces,
newlines, quotes, or a leading `-`. Where filenames are externally influenced
this reintroduces word-splitting and flag injection even though the script
"looks" careful for using `find` rather than a bare glob.

**What it looks like**

```bash
find . -name '*.fastq' | xargs rm
find /data -type f -exec cat {} \; | process
for f in $(find . -name '*.bam'); do ...; done
```

**Detecting it in a single file**

- `grep -n 'find ' script.sh` piped into `xargs` — a finding whenever `-print0`
  is missing on the `find` side or `-0` on the `xargs` side.
- `grep -n 'for .* in \$(find' script.sh` — the same word-splitting antipattern
  as with `ls`.
- `find ... -exec ... \;` is safe for the filename itself, but check whether
  the invoked command can misread a leading `-`.

**Canonical fix.** `find ... -print0 | xargs -0 cmd`, or `find ... -exec cmd {} +`,
and add `--` before the filename in the invoked command when it could start
with `-`.

---

# Medium

## 18. Uncontrolled search path / PATH hijacking

**CWE:** CWE-427, CWE-829 · **OWASP:** A05:2021 – Security Misconfiguration
**Severity:** medium · **Vibe-coding frequency:** medium

**What it is.** The script calls tools by bare name rather than absolute path,
or itself prepends a relative or writable directory to `PATH`. Any writable
directory ahead of the trusted system directories lets a locally-planted binary
of the same name run instead of the real one. This matters most for scripts run
by cron or systemd, where `PATH` is minimal, explicitly set, or inherited from
an untrusted caller.

**What it looks like**

```bash
PATH=.:$PATH
PATH=$PATH:/tmp/helpers
source ./helpers.sh          # resolved against the caller's CWD, not the script's
gzip "$file"                 # bare name in a script meant to run as root
```

**Detecting it in a single file**

- `grep -n 'PATH=' script.sh` — flag anything prepending `.` or a
  world-writable directory.
- `grep -nE '^\s*(source|\.) ' script.sh` — is the sourced path relative to the
  caller's CWD rather than to `$(dirname "$0")`?
- For privileged scripts, list the bare command invocations and check that none
  relies on an inherited `PATH`.

**Canonical fix.** Never add relative or world-writable directories to `PATH`.
Invoke security-sensitive binaries by absolute path (`/usr/bin/gzip`), and
source helpers from a path resolved from the script's own location:

```bash
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
. "$script_dir/helpers.sh"
```

## 19. TOCTOU race in check-then-act file/lock handling

**CWE:** CWE-367 · **OWASP:** A04:2021 – Insecure Design
**Severity:** medium · **Vibe-coding frequency:** medium

**What it is.** The script tests a condition (`[ -e "$lockfile" ]`,
`[ ! -f "$flag" ]`) and then acts on it in a separate step. Between the check
and the act, another process — or anyone who can write to that shared directory
— can change the filesystem state, defeating the lock or making the script
operate on something it no longer expects, including following a symlink
planted in that window.

**What it looks like**

```bash
if [ ! -e /tmp/job.lock ]; then touch /tmp/job.lock; ...; fi   # not atomic
[ -f "$flag" ] && rm "$flag"                                   # recreated in between
test -d "$outdir" || mkdir "$outdir"                           # in a world-writable parent
```

**Detecting it in a single file**

- `grep -n 'if \[ -e\|if \[ ! -e\|if \[ -f' script.sh`, then look a few lines
  down for a separate create/delete/write of the same path.
- Manual `[ -e lockfile ]` checks in a shared directory, where `mkdir` or
  `flock` should have been used, are the finding.
- Whether the lock/flag directory is world-writable is often NEEDS-HUMAN.

**Canonical fix.** Use an atomic primitive: `mkdir` (atomic, fails if it
exists), `ln -s`, or `flock` on a fixed descriptor:

```bash
exec 9>/var/lock/myjob.lock
flock -n 9 || { echo "already running" >&2; exit 0; }
```

Create working files in a private `mktemp -d` directory rather than a shared
one.

## 20. Insufficient privilege separation — whole script run as root

**CWE:** CWE-269, CWE-250 · **OWASP:** A01:2021 – Broken Access Control
**Severity:** medium · **Vibe-coding frequency:** medium

**What it is.** A deploy or backup script is invoked entirely under `sudo`, or
written assuming it always runs as root, when only one or two lines actually
need the privilege. Any injection bug anywhere else in the file — an unquoted
variable, an unsanitised filename — then executes as root instead of being
contained.

**What it looks like**

```bash
sudo ./deploy.sh     # downloads, parses input, and writes files, all as root
```

Or a passwordless sudoers entry that runs the entire multi-purpose script:
`svc ALL=(root) NOPASSWD: /opt/pipeline/run.sh`.

**Detecting it in a single file**

- `grep -n '^sudo ' script.sh` — `sudo` scattered across many lines suggests
  the script is (or will be) run with a broader privilege than needed.
- A script with no `sudo` at all but a root shebang comment, an install note,
  or a systemd `User=root`, is the same finding seen from the other side.
- Check whether the highest-risk code — network fetches, argument and file
  parsing — runs before or after privilege is narrowed.
- Whether a `NOPASSWD` sudoers entry exists for this script is NEEDS-HUMAN
  (`sudo -l`, `/etc/sudoers.d/*`).

**Canonical fix.** Perform privileged operations in the smallest possible
sudo-scoped step — a dedicated sudoers rule for one specific command, not a
whole script — and run argument parsing, downloading and file parsing as an
unprivileged user.

## 21. Missing `--` separator lets a variable or glob be read as an option

**CWE:** CWE-88 · **OWASP:** A03:2021 – Injection
**Severity:** medium · **Vibe-coding frequency:** medium

**What it is.** Commands like `cp "$src" "$dst"`, `find . -name "$pattern"`, or
`grep "$pattern" file` do not separate options from operands with `--`. If the
value can begin with `-` — an attacker-controlled filename, a sample ID echoed
back from user input — it is parsed as a flag rather than as data, ranging from
a broken run to genuine flag injection depending on the tool. Quoting does not
help here; only `--` does.

**What it looks like**

```bash
cp "$src" "$dst"
grep "$user_pattern" *.log
rm "$filename"
```

**Detecting it in a single file**

- `grep -nE '(cp|mv|rm|grep|find|tar|chmod|chown) [^-][^|;]*\$' script.sh` —
  then check whether `--` precedes the first variable or glob argument.
- shellcheck does not flag a missing `--` on its own (it covers the quoting
  side through SC2086), so this needs a manual pass over every command taking
  externally-influenced values.

**Canonical fix.** Add `--` before the first data argument whenever the value
comes from outside the script: `rm -- "$filename"`, `grep -- "$pattern" file`,
`cp -- "$src" "$dst"`.

## 22. Error handling that surfaces internal paths or raw stderr to outsiders

**CWE:** CWE-209 · **OWASP:** A09:2021 – Security Logging and Monitoring Failures
**Severity:** medium · **Vibe-coding frequency:** medium

**What it is.** On failure, the script forwards raw command output or stderr —
full file paths, internal hostnames, sometimes fragments of a connection string
— into a Slack or email notification, an externally readable log, or a
ticketing system, exposing internal topology and configuration that a careful
maintainer would have scrubbed.

**What it looks like**

```bash
curl -X POST "$SLACK_WEBHOOK" -d "$(pg_dump mydb 2>&1)"     # stderr may carry the DSN
cat error.log | mail -s 'backup failed' external-list@example.com
trap 'env > /var/log/job-debug.log' ERR                      # full environment, secrets included
```

**Detecting it in a single file**

- `grep -n '2>&1' script.sh` piped straight into a notification command (mail,
  curl, a webhook) rather than into a filtered summary.
- `grep -n 'mail \|slack\|webhook' script.sh` near error-handling blocks —
  check what exactly is interpolated into the message body.
- Check whether `ERR`/`EXIT` trap handlers dump the environment or the trace.

**Canonical fix.** Send a fixed, reviewed failure message plus a reference (a
job ID, the path of a log file that stays on the host), not raw command output.
Scrub known secret-bearing variables before anything leaves the machine.

## 23. Slopsquatting — installing a hallucinated or unpinned package name

**CWE:** CWE-1357, CWE-829 · **OWASP:** A08:2021 – Software and Data Integrity Failures
**Severity:** medium · **Vibe-coding frequency:** medium

**What it is.** A provisioning script installs a package name an AI assistant
suggested that does not exist upstream — and which an attacker may since have
registered specifically to catch this pattern, a documented and growing
supply-chain technique — or installs a real package with no version pin, so a
future compromised release is pulled in automatically on the next run.

**What it looks like**

```bash
pip install fastapi-middleware-auth      # plausible name, never verified to exist
npm install -g aws-helper-sdk            # no version, no lockfile
apt-get install -y sometool              # from a third-party repo added above, unverified key
```

**Detecting it in a single file**

- `grep -nE 'pip3? install ' script.sh` — is every package name a known,
  intentionally chosen dependency, or does it merely sound right?
- `grep -nE 'npm install (-g )?' script.sh` — missing `@version` pins.
- Cross-check every installed name against the project's real
  requirements/lockfile: a name appearing only in the provisioning script and
  nowhere else is suspicious.
- Also flag third-party apt repositories added in the same script with no GPG
  key verification.

**Canonical fix.** Pin exact versions and, where possible, hashes
(`pip install pkg==1.2.3 --require-hashes`); install from a lockfile checked
into the repository rather than from ad hoc names typed inline; and verify that
any AI-suggested package actually exists and comes from the expected maintainer
before it enters a provisioning script.

---

# Low

## 24. Weak/predictable naming for temp files or tokens (`$RANDOM`, `$$`)

**CWE:** CWE-330 · **OWASP:** —
**Severity:** low · **Vibe-coding frequency:** medium

**What it is.** The script generates a "unique" filename or a short-lived token
with `$RANDOM` (a weak, small-period PRNG) or the PID (`$$`, guessable and
observable through `ps`) instead of `mktemp` or a CSPRNG, making the name
predictable enough to pre-create or collide with in a shared-directory race.
Pairs with class 13 and class 19.

**What it looks like**

```bash
tmpname="/tmp/job_$RANDOM.tmp"
session_id=$$
token=$(date +%s)          # used as a security-relevant identifier
```

**Detecting it in a single file**

- `grep -n '\$RANDOM' script.sh` — is the result used for anything
  security-relevant (a filename in a shared directory, a token), or only for
  test data?
- `grep -n 'tmp.*\$\$' script.sh` — PID-based temp naming instead of `mktemp`.
- Timestamps (`date +%s`) used as identifiers are the same class.

**Canonical fix.** `mktemp` / `mktemp -d` for filenames; `openssl rand -hex 16`
or a read from `/dev/urandom` for any token that has to be hard to guess.

## 25. `trap` handlers defined with variables that expand at trap-set time (SC2064)

**CWE:** CWE-78 · **OWASP:** —
**Severity:** low · **Vibe-coding frequency:** low

**What it is.** `trap "rm -f $tmpfile" EXIT` expands `$tmpfile` immediately,
when the trap is registered, not when the signal fires. Usually this is a
correctness bug — the cleanup removes the wrong or an empty path if the
variable changes later — but if the value can be influenced between
registration and delivery, or if the double-quoted body embeds any other
externally-influenced variable, it becomes an injection evaluated at an
unexpected moment.

**What it looks like**

```bash
trap "rm -f $tmpfile" EXIT
trap "echo cleanup for $var" EXIT INT TERM
```

**Detecting it in a single file**

- shellcheck flags this directly as SC2064.
- `grep -n 'trap "' script.sh` — any double-quoted trap body containing a `$`
  is a candidate. The single-quoted form, which expands at signal time, is the
  safe one.

**Canonical fix.** Single-quote the trap body so expansion happens when the
signal fires:

```bash
trap 'rm -f -- "$tmpfile"' EXIT
```

## 26. Unquoted `read` loops and unrestored `IFS` when parsing external data

**CWE:** CWE-20 · **OWASP:** —
**Severity:** low · **Vibe-coding frequency:** low

**What it is.** The script reads a manifest or CSV with
`while read line; do ...; done < manifest.csv` — unquoted, default `IFS`
splitting on whitespace inside a field — or sets `IFS=,` for the parse and
never restores it, so a field containing a space, a comma, or a backslash is
mis-parsed. The malformed value then feeds a downstream path or command
construction, compounding with the injection and traversal classes above.

**What it looks like**

```bash
while read line; do process $line; done < manifest.csv   # unquoted downstream
IFS=','                                                  # set globally, never restored
cut -d, -f2 manifest.csv | while read val; do ...        # no -r: backslashes mangled
```

**Detecting it in a single file**

- `grep -n 'while read' script.sh` — check for `-r` and for proper quoting of
  the variable downstream.
- `grep -n 'IFS=' script.sh` — is it scoped to the `read` on the same line, or
  saved and restored, or just left changed for the rest of the file?
- shellcheck flags the unquoted read variable when it is used later (the SC2086
  family, in this context).

**Canonical fix.**

```bash
while IFS=, read -r sample_id file_path; do
  ...use "$sample_id" and "$file_path", always quoted...
done < manifest.csv
```

Scope `IFS` to the `read` itself, always pass `-r`, and quote every field
downstream.

---

## Appendix — tools referenced above

This skill runs **only** `shellcheck`, and only if it is already installed
(step 3). Nothing here is ever installed, and none of the following is executed
by the review. They are listed so a finding can name the human follow-up that
would settle it.

| Tool | Command | What it adds |
|---|---|---|
| ShellCheck | `shellcheck -x script.sh` | The primary single-file static analyzer for shell: unquoted expansions (SC2086), unquoted command substitution (SC2046), unsafe trap quoting (SC2064) and dozens of correctness issues. `-x` follows `source`d files; `--severity=style` shows everything, `--severity=warning` is the usual CI gate. |
| bash syntax check | `bash -n script.sh` | Parse-only sanity check, no execution. Not a security scanner, but a cheap first gate. |
| Semgrep | `semgrep --config p/bash script.sh` | Pattern-based scanning for `eval` usage and command construction from variables — injection shapes ShellCheck does not target. Results need manual triage. |
| systemd-analyze | `systemd-analyze security myunit.service` | Scores one unit against the full set of sandboxing directives and lists exactly which are missing. Directly answers class 10. |
| gitleaks | `gitleaks detect --source script.sh --no-git -v` | Entropy- and pattern-based secret detection; catches high-entropy credentials a keyword grep misses. Complements class 4. |

## Sources

- CWE Top 25 Most Dangerous Software Weaknesses, 2025 edition (cwe.mitre.org).
- OWASP Top 10:2021, in particular A03 Injection.
- ShellCheck rule documentation and community write-ups on SC2086, SC2046,
  SC2064 (2025–2026).
- `systemd.exec(5)` hardening directives; Fedora SystemdSecurityHardening wiki
  and community hardening guides (2025–2026).
- HackTricks "Wildcards Spare tricks" and cron/PATH privilege-escalation pages;
  insinuator.net "Revisiting an Old Friend: Shell Globbing" (rsync `-e`
  wildcard injection).
- Write-ups on secrets exposed through `ps` / `/proc/<pid>/cmdline`, and on
  `.my.cnf` / `.pgpass` versus command-line database passwords.
- Cloud Security Alliance research notes on AI-generated code vulnerability
  debt; Veracode 2025 GenAI Code Security Report; Escape.tech and Tenzai
  vibe-coding vulnerability scan studies (2025–2026).
- Snyk, Trend Micro and PSF coverage of slopsquatting — AI-hallucinated package
  names in supply-chain attacks (2025–2026).
- GitHub Docs and GitHub Security Lab on script injection through untrusted
  input in Actions `run:` blocks, which applies directly to shell steps in CI.
