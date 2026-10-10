# Perl vulnerability catalog

The checklist for step 4 of `security-perl`. One section per class, ordered by
severity, then by how often AI-generated Perl gets it wrong. Work top to bottom:
the ordering is the priority. Each section gives the concrete Perl shapes, what
to look for when all you have is the one file, and the canonical fix.

Class ids (`PERL-01` …) are for navigation inside this file. The findings table
still reports the **CWE**, not the class id.

| # | Class | Severity | Vibe-coding frequency |
|---|---|---|---|
| PERL-01 | OS command injection via `system`/`exec`/backticks | CRITICAL | very-high |
| PERL-02 | Two-argument `open()` injection | CRITICAL | high |
| PERL-03 | SQL injection via interpolated DBI statements | CRITICAL | high |
| PERL-04 | Code injection via stringy `eval` / `s///ee` | CRITICAL | medium |
| PERL-05 | Hardcoded credentials and API keys | HIGH | very-high |
| PERL-06 | TLS certificate verification disabled | HIGH | high |
| PERL-07 | Untrusted search path for external tools | HIGH | high |
| PERL-08 | Slopsquatting / hallucinated CPAN modules | HIGH | high |
| PERL-09 | Path traversal via unsanitized filenames | HIGH | medium |
| PERL-10 | Missing input validation / no taint mode | HIGH | medium |
| PERL-11 | Insecure deserialization (Storable / YAML) | HIGH | low |
| PERL-12 | Weak or homegrown cryptography/hashing | MEDIUM | high |
| PERL-13 | Sensitive data written to logs | MEDIUM | high |
| PERL-14 | Missing authorization on new script wrappers | MEDIUM | medium |
| PERL-15 | Verbose errors leaking internal information | MEDIUM | medium |
| PERL-16 | Predictable temp files / race conditions | MEDIUM | medium |
| PERL-17 | Insecure file permissions on output data | MEDIUM | medium |
| PERL-18 | ReDoS / uncontrolled resource consumption | MEDIUM | low |
| PERL-19 | XXE in XML tool-output parsing | MEDIUM | low |
| PERL-20 | `@INC` / `require` path manipulation | MEDIUM | low |
| PERL-21 | CGI output/header injection (XSS, CRLF) | LOW | low |
| PERL-22 | Format string misuse in `sprintf`/`printf` | LOW | low |
| PERL-23 | Setuid/setgid privilege mismanagement | LOW | low |

---

## PERL-01 — OS command injection via system/exec/backticks

**CWE-77, CWE-78 · OWASP A03:2021 – Injection · Severity: CRITICAL · Vibe-coding frequency: very-high**

Untrusted data (sample IDs, filenames, FASTA headers, spreadsheet cells) is
interpolated into a single-string `system()`/`exec()` call or a backtick/`qx//`
block. Perl hands that single string to `/bin/sh -c`, so shell metacharacters in
the data run arbitrary commands with the script's privileges.

**What it looks like in Perl**

```perl
system("samtools index $bamfile");            # $bamfile from a sample-sheet column
my $hits = `blastn -query $infile -db $db`;   # $infile from a user-supplied accession
system("gzip -c $outdir/$sample.vcf > $outdir/$sample.vcf.gz");   # $sample may hold ; or `
open(my $fh, "gunzip -c $file |");            # pipe-open with an unsanitized filename
```

**Detecting it in a single file**

- `system("...$var...")`, or any backtick / `qx//` block containing a `$`.
- Single-string `system()`/`exec()` calls — built by interpolation or `.`
  concatenation — as opposed to the list form.
- No use of list-form `system($cmd, @args)`, `IPC::System::Simple` or `IPC::Run`
  anywhere in the file.
- Trace each interpolated variable back to its origin: a value that came from
  `<$fh>`, `split`, `$ARGV[…]`, `%ENV` or `param()` makes this CRITICAL; a value
  assigned from a literal in the same file is a lower-severity code-smell.

**Canonical fix**

Use the list form `system($cmd, @args)` — it bypasses the shell entirely — or
`IPC::Run`/`IPC::System::Simple`. Never build a shell string by interpolating
external data. Whitelist-validate IDs and filenames (`^[\w.-]+$`) before they
touch any command line, and run the script under taint mode (`-T`) so Perl
refuses tainted data at these sinks.

---

## PERL-02 — Two-argument open() injection

**CWE-78, CWE-73 · OWASP A03:2021 – Injection · Severity: CRITICAL · Vibe-coding frequency: high**

The two-argument form of `open()` reads the mode out of the filename string: a
name starting or ending with `|` runs a shell command, and one starting with `>`
or `>>` truncates or appends to an arbitrary path. A classic trap when a
filename column from a sample sheet or a CLI argument is opened directly.

**What it looks like in Perl**

```perl
open(my $fh, $filename) or die;      # $filename = "| rm -rf ~ |"  →  runs a command
open(FH, "<$path")      or die;      # $path from user input
open(FH, ">$outpath")   or die;      # $outpath from user input
open(my $in, "gunzip -c $file |");   # pipe-open combined with an unsanitized $file
```

**Detecting it in a single file**

- `open\s*\(` calls with only two arguments — no literal mode as its own,
  separate argument.
- The shapes `open(FH, "<$`, `open(FH, ">$`, `open(FH, "$`.
- `perlcritic` flags these as `InputOutput::ProhibitTwoArgOpen`; still confirm by
  reading, and still report ones the tool missed.

**Canonical fix**

Always three-argument `open()` with a literal mode:
`open(my $fh, '<', $filename) or die "…: $!";`. This is a mechanical, low-risk
change worth applying everywhere in the file, including for filenames that look
trusted today.

---

## PERL-03 — SQL injection via interpolated DBI statements

**CWE-89 · OWASP A03:2021 – Injection · Severity: CRITICAL · Vibe-coding frequency: high**

Scripts that log results into a LIMS, SQLite or MySQL database build SQL text by
interpolating sample IDs, gene names or rsIDs instead of using DBI placeholders
and bind values.

**What it looks like in Perl**

```perl
$dbh->do("INSERT INTO results VALUES ('$sample_id', '$genotype')");
my $sql = "SELECT * FROM snps WHERE rsid = '$rsid'";  $dbh->do($sql);
my $in  = join(',', @gene_symbols);                   # user-supplied, straight into WHERE
$dbh->prepare("SELECT * FROM genes WHERE symbol IN ($in)");
```

**Detecting it in a single file**

- `$dbh->do("` or `->prepare("` followed by `$` interpolation inside the string.
- Absence of `?` placeholders paired with a later `execute($…)` call.
- A `join(',', @something)` spliced into a `WHERE … IN (…)` clause.
- Also flag interpolation into table/column names — placeholders cannot bind
  identifiers, so those need a whitelist instead.

**Canonical fix**

`$dbh->prepare('… WHERE rsid = ?')` then `execute($rsid)`. Never interpolate
variables into SQL text, including for "internal" pipeline databases. For
identifiers that genuinely must vary, match them against a fixed whitelist of
allowed names before building the statement.

---

## PERL-04 — Code injection via stringy eval / regex /ee

**CWE-94, CWE-95 · OWASP A03:2021 – Injection · Severity: CRITICAL · Vibe-coding frequency: medium**

`eval "STRING"` executes arbitrary Perl when the string carries
attacker-influenced data (a config-driven formula, for instance). The `s///ee`
double-eval modifier evaluates the replacement text as code, and an explicit
`use re 'eval'` re-enables `(?{ … })` inside interpolated patterns, which Perl
blocks by default.

**What it looks like in Perl**

```perl
eval "\$result = $formula;";          # $formula from a config-file cell
$text =~ s/(\w+)/$hash{$1}/ee;        # second /e evaluates the replacement as code
use re 'eval';  ...  (?{ system($1) })  # pattern assembled from an external string
```

**Detecting it in a single file**

- `eval\s*"` or `eval\s*qq` — the **stringy** form. Distinguish it from the safe
  block form `eval { … }` used for exception handling; only the stringy form is
  this finding.
- The `/ee` modifier on any `s///` substitution.
- `use re ['"]eval['"]` or a literal `(?{` in the source.
- `perlcritic` policy: `BuiltinFunctions::ProhibitStringyEval`.

**Canonical fix**

Never use the string form of `eval` on externally-influenced data; keep
`eval { }` (block form) for exception handling only. Replace dynamic-formula
evaluation with a hash-based dispatch table. Avoid `/ee` and `use re 'eval'`
entirely — since Perl already blocks `(?{…})` in interpolated patterns by
default, finding it deliberately re-enabled is itself the signal to trace where
the pattern comes from.

---

## PERL-05 — Hardcoded credentials and API keys

**CWE-798, CWE-259 · OWASP A07:2021 – Identification and Authentication Failures · Severity: HIGH · Vibe-coding frequency: very-high**

Database passwords, LIMS API tokens or reference-database API keys sit as
literal strings in the `.pl` script or a committed config file — often
copy-pasted from a tutorial, or left in place by an assistant asked to "add a
database connection".

**What it looks like in Perl**

```perl
my $dbh = DBI->connect("dbi:mysql:db=results;host=…", "root", "password123");
my $api_key = "AIzaSy…";
$req->header(Authorization => "Bearer sk-…");
# or: a config.pm committed beside the script holding a plaintext password constant
```

**Detecting it in a single file**

- `->connect\(.*,\s*["'].*["']\s*,\s*["'].*["']\)` — literal user/pass in
  `DBI->connect`.
- `password\s*=`, `passwd\s*=`, `api_key\s*=`, `token\s*=`, `secret\s*=`
  followed by a quoted literal.
- Leftover example/placeholder credentials: `admin`/`password`, `changeme`,
  `test123`, `sk-…`. A placeholder is still a finding — it is what ships.
- An empty-string password is a separate finding (an account with no password),
  not an exemption.

**Canonical fix**

Load credentials from environment variables, or from a config file excluded from
version control and `chmod 600`. Never accept a suggestion that inlines a
literal secret, even "as a placeholder". Anything already committed must be
treated as compromised and rotated.

---

## PERL-06 — TLS certificate verification disabled

**CWE-295 · OWASP A02:2021 – Cryptographic Failures · Severity: HIGH · Vibe-coding frequency: high**

Scripts that fetch reference sequences or annotations over HTTPS disable
certificate verification to silence an SSL error — usually through
`LWP::UserAgent`'s `ssl_opts` or the `PERL_LWP_SSL_VERIFY_HOSTNAME` environment
variable. It is a very common assistant "fix" for a cert-chain error, and it
removes MITM protection from every download the script makes.

**What it looks like in Perl**

```perl
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;      # set before a get()/getstore() call
IO::Socket::SSL->new(..., SSL_verify_mode => SSL_VERIFY_NONE);
```

**Detecting it in a single file**

- `verify_hostname\s*=>\s*0`.
- `PERL_LWP_SSL_VERIFY_HOSTNAME` anywhere, including a `$ENV{…}` assignment far
  from the actual request.
- `SSL_VERIFY_NONE`, or `SSL_verify_mode => 0`.
- A nearby comment along the lines of "workaround for cert error" is
  corroboration, not an excuse.

**Canonical fix**

Never disable hostname or certificate verification. Fix the actual cause:
install or update `Mozilla::CA`, point `SSL_ca_file` at a valid CA bundle, or
update the system CA store.

---

## PERL-07 — Untrusted search path for external tools

**CWE-426, CWE-427 · OWASP A05:2021 – Security Misconfiguration · Severity: HIGH · Vibe-coding frequency: high**

Pipeline scripts invoke external tools (`samtools`, `bwa`, `blastn`) by bare name
and rely on the inherited `$ENV{PATH}`. On a shared login node, or when the
script runs from cron or under a modified environment, a writable directory
earlier in `PATH` substitutes a malicious binary for the real tool.

**What it looks like in Perl**

```perl
system("samtools", "index", $bam);      # correct list form, but no absolute path
my $ver = `bwa 2>&1`;                   # resolved through whatever PATH the caller had
# and: no local reset of $ENV{PATH} anywhere, in a script also run from cron
```

**Detecting it in a single file**

- Bare tool names inside `system(`/`exec(`/backticks with no `/usr/bin/`-style
  prefix, and no `$ENV{PATH}` reset nearby.
- Absence of an explicit `$ENV{PATH} = '/usr/bin:/bin';` (or similar) near the
  top of the script.
- Note this is orthogonal to PERL-01: switching to the list form fixes the shell
  metacharacter problem but not the PATH problem.

**Canonical fix**

Call external tools by absolute path, or set a minimal trusted `$ENV{PATH}`
before any `system()`/`exec()` call. Taint mode (`-T`) forces the issue: it
refuses to run an external command with a tainted `PATH`.

---

## PERL-08 — Slopsquatting / hallucinated CPAN modules

**CWE-829 · OWASP A06:2021 – Vulnerable and Outdated Components · Severity: HIGH · Vibe-coding frequency: high**

An assistant asked to add functionality suggests `use Some::Plausible::Module;`
for a module that does not exist on CPAN, or that is a near-miss of a real name.
If an attacker later registers that name, a routine `cpanm` install on a shared
machine pulls attacker-controlled code that runs at install and import time.

**What it looks like in Perl**

```perl
use Bio::VCF::FastParser;    # plausible, but does it resolve on MetaCPAN?
use Text::CSV::Simple2;      # near-miss of the real Text::CSV
# and: a cpanfile/README telling the reader to cpanm a package nobody verified
```

**Detecting it in a single file**

- List every `use`/`require Module::Name;` that is not core Perl and not an
  obviously well-known distribution (BioPerl, DBI, Text::CSV, LWP, JSON::PP…).
- Treat a name that is one token away from a famous module as suspect
  (`::Simple2`, `::Fast`, a pluralized namespace, a swapped word order).
- **This skill does not check the network.** Report the exact module name under
  NEEDS-HUMAN for the user to verify on MetaCPAN or with `cpanm --info`.

**Canonical fix**

Verify every suggested module name against MetaCPAN before running
`cpanm`/`cpan install`. Pin dependencies with versions in a
`cpanfile`/`Makefile.PL` reviewed by a human, and prefer well-known
distributions over obscure or newly-suggested ones.

---

## PERL-09 — Path traversal via unsanitized filenames

**CWE-22, CWE-73 · OWASP A01:2021 – Broken Access Control · Severity: HIGH · Vibe-coding frequency: medium**

A filename or output path built from a sample-sheet cell, a FASTA header or a
CLI argument goes straight into `open()`/`unlink()`/`rename()` with no check for
`../` or a leading `/`, so a crafted identifier writes or deletes files outside
the intended output directory.

**What it looks like in Perl**

```perl
open(my $out, '>', "$outdir/$sample.vcf");   # $sample could be "../../etc/cron.d/x"
unlink("$workdir/$name.tmp");                # $name taken from a FASTA '>' header
my $report = "$reportdir/" . param('sample') . ".html";   # CGI wrapper
```

**Detecting it in a single file**

- String-concatenated paths (`"$dir/$var"`) passed to `open`, `unlink`, `rename`,
  `mkdir`, `opendir` where `$var` originated from a file, a column or an
  argument read earlier in the script.
- Absence of a whitelist check (`$name =~ /^[\w.-]+$/`) or canonicalization via
  `Cwd::abs_path` / `File::Spec` before the filesystem call.
- A check that only strips `../` textually is still a finding — it misses
  absolute paths, `....//`, and symlinks.

**Canonical fix**

Whitelist-validate any external string used to build a path
(`$name =~ /^[A-Za-z0-9_.-]+$/ or die`), then canonicalize with
`Cwd::abs_path` and confirm the result is still inside the intended output
directory before using it.

---

## PERL-10 — Missing input validation / no taint mode

**CWE-20 · OWASP A04:2021 – Insecure Design · Severity: HIGH · Vibe-coding frequency: medium**

Data read from spreadsheets, VCF INFO fields or CLI arguments flows downstream —
into file paths, shell commands, numeric contexts — with no validation, and the
script does not run under taint mode, so Perl offers no automatic backstop
against tainted data reaching a dangerous sink.

**What it looks like in Perl**

```perl
#!/usr/bin/perl                 # no -T, yet the script builds shell commands and paths
my $chr = $row[0];
system("tabix $vcf $chr:$start-$end");        # no check that $chr/$start/$end are sane
my $val = $fields[$idx];                      # $idx straight from an input column
```

**Detecting it in a single file**

- Check the shebang for `-T` on any script that ingests external files and later
  calls `system`/`open`/DBI. If it is absent, note whether the file could
  plausibly be invoked as `perl -T script.pl` instead.
- Values from `split` or `<$fh>` that reach `system(`, `open(` or SQL text within
  a few lines, with no intervening regex match or range check.
- Array/hash indexes taken directly from an input column with no bounds check.
- `-T` cannot be enabled mid-script: adding it later, or via `-M`, does nothing
  and Perl errors "Too late for -T". It must be on the shebang or the actual
  invocation.

**Canonical fix**

Run scripts that ingest external files under taint mode (`-T`), and untaint every
value with an explicit regex match before it reaches a file, command or SQL
sink:

```perl
if ($val =~ /^([\w.-]+)$/) { $val = $1 } else { die "rejected: $val" }
```

---

## PERL-11 — Insecure deserialization (Storable / YAML)

**CWE-502 · OWASP A08:2021 – Software and Data Integrity Failures · Severity: HIGH · Vibe-coding frequency: low**

Cache or checkpoint files written by one run and reloaded by a later one — or
shared between users on a cluster filesystem — are deserialized with
`Storable::thaw`/`retrieve` or `YAML::Load`. If another user or process can
replace that file, and CODE-ref freezing or object loading is enabled,
deserializing it runs attacker-controlled Perl or triggers destructor side
effects.

**What it looks like in Perl**

```perl
my $cache = retrieve("$workdir/checkpoint.dat");   # on world-writable shared scratch
local $Storable::Eval = 1;                         # enables CODE-ref evaluation on thaw
my $cfg = YAML::Load($config_text);                # YAML editable by other cluster users
```

**Detecting it in a single file**

- `Storable::thaw(`, `retrieve(`, `YAML::Load(` — then trace the source path back
  to where it was built: `/tmp`, a shared scratch directory, or anything under a
  path the script did not create itself is the finding.
- `\$Storable::Eval\s*=\s*1`.
- `YAML::Load` vs `YAML::LoadFile` on untrusted text; prefer `JSON::PP` where the
  data is plain.

**Canonical fix**

Only deserialize cache/checkpoint files the same process wrote, in a directory
writable only by that user. Never enable `$Storable::Eval`. For cross-run caches
prefer a plain-text/JSON format with no code-execution surface.

---

## PERL-12 — Weak or homegrown cryptography/hashing

**CWE-327, CWE-328 · OWASP A02:2021 – Cryptographic Failures · Severity: MEDIUM · Vibe-coding frequency: high**

MD5/SHA1 is used as if it provided tamper-evidence for result files, or a
homegrown XOR/Caesar "obfuscation" masks sample or patient identifiers before
writing them somewhere shared. Neither provides real integrity or
confidentiality.

**What it looks like in Perl**

```perl
my $checksum = md5_hex($vcf_content);   # "verify the file wasn't tampered with"
my $obfuscated = $id ^ $key;            # "anonymize" an identifier before logging
my $safe = encode_base64($genotypes);   # described in a comment as "encrypted"
```

**Detecting it in a single file**

- `Digest::MD5` or `Digest::SHA1` combined with the words *verify*, *integrity*,
  *tamper* or *sign* in nearby comments or variable names. (MD5 purely as a cache
  key or a dedup fingerprint is not this finding — say so rather than inflating
  it.)
- A bitwise XOR (`^`) applied to an identifier variable.
- `encode_base64` described as encryption in a comment.

**Canonical fix**

Use SHA-256 or better (`Digest::SHA::sha256_hex`) for integrity checks. Never
invent encryption: use a keyed HMAC for pseudonymization, or a vetted crypto
module for real confidentiality — not bitwise tricks.

---

## PERL-13 — Sensitive data written to logs

**CWE-532 · OWASP A09:2021 – Security Logging and Monitoring Failures · Severity: MEDIUM · Vibe-coding frequency: high**

Verbose `warn`/`print STDERR`/debug statements — often added wholesale for
"better observability" — dump full data rows, identifiers or connection strings
including passwords into shared log files or scheduler-captured stdout.

**What it looks like in Perl**

```perl
warn "Connecting with $dsn user=$user pass=$pass";
print STDERR "Processing sample $id: @genotype_row\n";   # identifiable data, group-readable log
print STDERR Dumper($config);                            # config includes embedded credentials
```

**Detecting it in a single file**

- `warn` / `print STDERR` / `Dumper(` lines containing variables named `pass`,
  `passwd`, `token`, `key`, `dsn`, or a whole per-record data row.
- `Data::Dumper` on a config or connection object.
- Cross-check against the log destination: an append `open` to a path under a
  shared directory raises the severity (see PERL-17).

**Canonical fix**

Log identifiers and operational status only, never credentials or full
personal/genotype rows. Redact or hash identifiers that must appear, and
restrict log file permissions to the users who need them.

---

## PERL-14 — Missing authorization on new script wrappers

**CWE-862, CWE-863 · OWASP A01:2021 – Broken Access Control · Severity: MEDIUM · Vibe-coding frequency: medium**

A formerly command-line-only analysis script gets wrapped in a small CGI or web
dashboard — often an assistant-written "quick web UI" — so colleagues can trigger
runs or download reports. The wrapper is given no access control, so anyone who
reaches the URL can run the pipeline or read other people's results.

**What it looks like in Perl**

```perl
# report.cgi
my $sample = param('sample');
system("/opt/pipeline/run.pl", $sample) if param('run');   # no session, no auth check
open(my $fh, '<', "$results/$sample.html");                # no ownership check either
# or: a Mojolicious::Lite / Dancer "quick app" with routes keyed by a bare id
```

**Detecting it in a single file**

- In a `.cgi`, `Mojolicious::Lite` or `Dancer` file: route handlers that call
  `system(` or open a result file with no preceding auth/session check.
- A `param(` or path-segment value used directly as a file or sample selector,
  with no ACL lookup — that is IDOR even when authentication exists.
- Whether an authenticating reverse proxy sits in front cannot be seen from this
  file: report the finding and add it to NEEDS-HUMAN.

**Canonical fix**

Any script exposed over HTTP, even on an internal network, needs an explicit
access-control check before it acts, and an ownership check on every
id-addressed resource. "Internal only" is not a substitute for authorization.

---

## PERL-15 — Verbose errors leaking internal information

**CWE-209, CWE-497 · OWASP A05:2021 – Security Misconfiguration · Severity: MEDIUM · Vibe-coding frequency: medium**

Unhandled `die`/`Carp::confess` output — full file paths, DB DSNs, stack traces —
reaches the invoking user or a world-readable log. Common where "better error
messages" were added that print `$@` or a whole exception object unfiltered.

**What it looks like in Perl**

```perl
die "Connection failed: $dsn / $DBI::errstr";       # later shared with all pipeline users
local $SIG{__DIE__} = \&Carp::confess;              # left enabled in production
print "Error: $@";                                  # in a CGI, straight to the browser
```

**Detecting it in a single file**

- `die "` / `warn "` strings interpolating `$dsn`, `$DBI::errstr`, absolute paths
  or connection details.
- `Carp::confess` outside a clearly marked debug/dev code path.
- In a web wrapper, any `$@` or `$!` printed into the response body.

**Canonical fix**

Send detailed errors (with paths and DSNs) only to a restricted-access log; show
a generic message to any less-trusted consumer of the script's output.

---

## PERL-16 — Predictable temp files / race conditions

**CWE-377, CWE-367 · OWASP A01:2021 – Broken Access Control · Severity: MEDIUM · Vibe-coding frequency: medium**

Temp filenames are built by hand instead of with `File::Temp`, leaving a
predictable path another user on a shared node can pre-create, symlink, or race
between the existence check and the `open`.

**What it looks like in Perl**

```perl
my $tmp = "/tmp/blast_$$.out";    open(my $fh, '>', $tmp);
my $tmpdir = "/tmp/run_" . time();  mkdir $tmpdir;      # reused for a whole job
if (! -e $tmp) { open(my $fh, '>', $tmp) }              # TOCTOU window between the two
```

**Detecting it in a single file**

- `"/tmp/` followed by `$$`, `time()`, or a sample name, with no `File::Temp`
  used anywhere in the file.
- Absence of `use File::Temp` despite manual temp-path construction.
- An `-e`/`-f` existence test followed by an `open`/`mkdir` on the same path —
  the classic check-then-use race.

**Canonical fix**

Use `File::Temp::tempfile()` / `tempdir()` (with `UNLINK => 1` where
appropriate). They create the file atomically, with an unpredictable name and no
TOCTOU window.

---

## PERL-17 — Insecure file permissions on output data

**CWE-732, CWE-276 · OWASP A01:2021 – Broken Access Control · Severity: MEDIUM · Vibe-coding frequency: medium**

Result files containing identifiable data are written under the default umask
(often 022 or looser on shared systems), leaving them group- or world-readable
to every other user of the machine; output directories are created with a plain
`mkdir` at default permissions.

**What it looks like in Perl**

```perl
open(my $out, '>', "$outdir/$sample.results.vcf");   # shared filesystem, no chmod after
mkdir($outdir);                                      # no mode argument
```

**Detecting it in a single file**

- Writes of clearly identifiable per-record data with no following `chmod`.
- `mkdir(` with no mode argument for a directory that will hold such files.
- Whether the script calls `umask` or `chmod` at all — if it never does, and it
  handles identifiable data, that absence is the finding.
- The real permissions of the target directory cannot be read from this file:
  note it under NEEDS-HUMAN.

**Canonical fix**

`chmod 0640` (or stricter) on result files, `mkdir($dir, 0750)` for directories
holding identifiable data, and a restrictive `umask` set at the top of the
script rather than relying on system defaults.

---

## PERL-18 — ReDoS / uncontrolled resource consumption

**CWE-1333, CWE-400 · OWASP A05:2021 – Security Misconfiguration · Severity: MEDIUM · Vibe-coding frequency: low**

Regexes with nested quantifiers or ambiguous alternation, applied to
attacker-influenced text (a large or crafted FASTA header, VCF INFO field or
spreadsheet cell), trigger catastrophic backtracking. Separately, slurping an
entire externally-supplied file with no size check exhausts memory on a shared
node.

**What it looks like in Perl**

```perl
if ($header =~ /^(.+\s+)+description:/) { … }   # run over every header in a large file
{ local $/; my $content = <$fh>; }              # slurp of an unchecked-size file
```

**Detecting it in a single file**

- Nested quantifier shapes applied to loop-read external lines: `(\w+)+`,
  `(.*)+`, `(a+)+`, `(\s*\w+)*`.
- `local $/;` (slurp mode) followed by a read with no prior `-s` size check.
- Unbounded `while (<$fh>)` accumulation into an array or hash with no cap.

**Canonical fix**

Avoid nested or ambiguous quantifiers on untrusted text — rewrite as a single
unambiguous match. Check file size before slurping and process line by line for
large inputs.

---

## PERL-19 — XXE in XML tool-output parsing

**CWE-611 · OWASP A05:2021 – Security Misconfiguration · Severity: MEDIUM · Vibe-coding frequency: low**

XML output from external tools is parsed with `XML::Simple` or a permissively
configured `XML::LibXML`, leaving external entity expansion enabled. A crafted
XML result file then reads arbitrary local files, or causes SSRF and DoS through
entity expansion.

**What it looks like in Perl**

```perl
my $xml = XMLin($blast_xml_path);                  # XML::Simple, externally-sourced file
XML::LibXML->load_xml(location => $file);          # no expand_entities/no_network flags
```

**Detecting it in a single file**

- `XML::Simple` / `XMLin(` on any externally-sourced XML file.
- `XML::LibXML` parser construction with no `expand_entities`, `load_ext_dtd` or
  `no_network` flags set nearby.
- Trace the XML path: a file the script itself generated locally is far lower
  risk than one that arrived with the input data — say which.

**Canonical fix**

Parse untrusted XML with `XML::LibXML` configured to refuse external entities and
DTD loading (`load_ext_dtd => 0`, `expand_entities => 0`, `no_network => 1`).
Keep `XML::Simple` for fully trusted, locally generated files only.

---

## PERL-20 — @INC / require path manipulation

**CWE-427, CWE-829 · OWASP A08:2021 – Software and Data Integrity Failures · Severity: MEDIUM · Vibe-coding frequency: low**

A script does `push @INC, $some_dir;` or `require $module_from_config;` where the
directory or module name is influenced by an environment variable, a config file
or a CLI flag. A writable directory earlier in the search path — or, on old
Perls, `.` implicitly in `@INC` — lets someone else's file be loaded and executed
as trusted code.

**What it looks like in Perl**

```perl
push @INC, $ENV{PIPELINE_LIB} if $ENV{PIPELINE_LIB};       # no check on the directory
require "$config{module_dir}/$config{plugin}.pm";          # both from a user-editable config
use lib "$FindBin::Bin/../lib";                            # fine — but check who can write there
```

**Detecting it in a single file**

- `push\s*@INC` / `unshift\s*@INC` with a variable (not a literal) argument.
- `require` whose argument is a variable or an interpolated string rather than a
  bareword module name.
- `use lib` with a path derived from `%ENV`.
- Whether the resulting directory is world-writable cannot be judged here: report
  it under NEEDS-HUMAN.

**Canonical fix**

Never add a directory to `@INC` from untrusted input. Whitelist plugin names
against a fixed list and load only from a directory the script's own owner
controls. Confirm `.` is not implicitly in `@INC` (removed by default since Perl
5.26, but verify on older installations).

---

## PERL-21 — CGI output/header injection (XSS, CRLF)

**CWE-79, CWE-113 · OWASP A03:2021 – Injection · Severity: LOW · Vibe-coding frequency: low**

Legacy `CGI.pm`-based report pages — still common as a thin web front-end for a
pipeline — print `param()` values or record data straight into an HTML report or
an HTTP header with no escaping. That gives stored or reflected XSS in the
report, and, via unescaped newlines in a header value (CVE-2012-5526), HTTP
response splitting.

**What it looks like in Perl**

```perl
print "Sample: " . param('sample') . "<br>";               # no HTML escaping
print header(-cookie => $c, -location => param('redirect'));  # newline → response splitting
```

**Detecting it in a single file**

- `param(` used directly inside a `print`/HTML string with no
  `HTML::Entities::encode_entities` (or template auto-escaping) nearby.
- `header(` / `redirect(` calls built from `param(` values with no sanitization.
- Data read from an input file and printed into HTML counts too — stored XSS does
  not need an HTTP parameter.

**Canonical fix**

HTML-escape every external value before writing it into a report
(`HTML::Entities::encode_entities`), and strip or reject embedded CR/LF in any
value used to build an HTTP header.

---

## PERL-22 — Format string misuse in sprintf/printf

**CWE-134 · OWASP A03:2021 – Injection · Severity: LOW · Vibe-coding frequency: low**

An externally-supplied string (a config template, a value from an input file) is
passed as the *format* argument to `sprintf`/`printf` rather than as data, so a
crafted value containing `%`-directives crashes the script or reads unintended
values off the argument stack.

**What it looks like in Perl**

```perl
printf($user_supplied_template, $value);   # template comes from a config-file column
my $line = sprintf($row[2], @row[3..5]);   # a spreadsheet cell used as the format
```

**Detecting it in a single file**

- `sprintf(\s*\$` or `printf(\s*\$` — first argument a variable, not a literal
  format string.
- The same shape with a variable format assembled by concatenation just above the
  call.

**Canonical fix**

Never use externally-supplied data as a format string. Pass a literal format and
supply external data only as the substituted arguments: `sprintf('%s', $value)`.

---

## PERL-23 — Setuid/setgid privilege mismanagement

**CWE-269, CWE-732 · OWASP A05:2021 – Security Misconfiguration · Severity: LOW · Vibe-coding frequency: low**

A script installed setgid to a shared group (so any group member can write shared
output) keeps the elevated privilege for its whole lifetime instead of dropping
it after the privileged operation, and often works around the taint mode Perl
auto-enables whenever real and effective IDs differ. Any bug elsewhere in the
script now runs with that privilege.

**What it looks like in Perl**

```perl
# script.pl has the setgid bit (chmod g+s) and never restores $) after the shared write
eval { open(my $fh, '<', $tainted_path) };   # swallowing "Insecure dependency" instead of fixing it
```

**Detecting it in a single file**

- `ls -l` the script for the setuid/setgid bit, then grep for any explicit
  privilege drop (`$) =`, `$( =`, `POSIX::setgid`). On a setgid script, the
  absence of a drop is the finding.
- Taint errors suppressed rather than fixed — a tainted call wrapped in `eval` to
  swallow "Insecure dependency".
- On a script with no setuid/setgid bit this class does not apply; say so rather
  than reporting it.

**Canonical fix**

Drop elevated privilege immediately after the operation that needs it
(`$) = $real_gid;`), keep taint mode enabled instead of working around its
errors, and prefer a shared-group output directory with correct default
permissions over a setgid script wherever possible.

---

## Sources

CWE Top 25 (2024 edition, CISA advisory; 2025 edition methodology and trends);
OWASP Top 10:2021; `perlsec` and perldoc.perl.org, including taint mode (`-T`);
SEI CERT Perl Coding Standard (IDS00/IDS30/IDS31/IDS32/IDS33-PL); Perl::Critic
policy documentation (`BuiltinFunctions::ProhibitStringyEval`,
`InputOutput::ProhibitTwoArgOpen`, `InputOutput::ProhibitBacktickOperators`,
`TestingAndDebugging::ProhibitNoStrict`); security.metacpan.org, "Are you still
using the 2-argument open?" (2025); write-ups on the Storable deserialization
problem and `YAML::Load` object loading (masteringperl.org, blogs.perl.org);
kb.cert.org VU#246409 and CVE-2012-5526 (CGI.pm XSS / header injection); Veracode
2025 GenAI Code Security Report; GitGuardian State of Secrets Sprawl 2026;
slopsquatting research and coverage (2025).
