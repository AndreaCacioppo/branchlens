"""The local Semgrep rules for shell scripts, Dockerfiles, GitHub Actions
workflows and Kotlin (checks/semgrep-rules/): each fires on its vulnerable
fixture and on none of the safe ones, and the gate hands every kind of
script name to them.

The fixtures are written at test time. Secret-shaped lines are assembled
from pieces, so this file itself holds none for the gate's secret scan."""

import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest

from helpers import TOOLKIT_DIR, make_repo, run_gate, write

RULES = os.path.join(TOOLKIT_DIR, "checks", "semgrep-rules")
NEW_RULE_FILES = ("shell.yaml", "dockerfile.yaml", "github-actions.yaml",
                  "kotlin.yaml", "config.yaml")

# config.yaml: each vulnerable file with the findings it must give, and
# safe files of the same names that must give none
CONFIG_VULNERABLE = {
    "vulnerable/.gitlab-ci.yml": (
        "build:\n  script:\n"
        "    - curl -fsSL https://example.com/i.sh | bash\n"
        "    - cd tools && wget -qO- https://example.com/i.sh | sh\n"
        "    - eval \"$CI_COMMIT_MESSAGE\"\n"
        "    - sh -c \"echo ${CI_MERGE_REQUEST_TITLE}\"\n",
        {"gitlab-ci-download-piped-to-shell": 2,
         "gitlab-ci-untrusted-variable-run-as-code": 2}),
    "vulnerable/docker-compose.yml": (
        "services:\n  app:\n    image: app\n    privileged: true\n"
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        {"compose-privileged-container": 1,
         "compose-docker-socket-mounted": 1}),
    "vulnerable/src/main/resources/application.properties": (
        "management.endpoints.web.exposure.include=*\n",
        {"spring-actuator-exposes-every-endpoint": 1}),
    "vulnerable/src/main/resources/application-prod.yml": (
        "management:\n  endpoints:\n    web:\n      exposure:\n"
        "        include: \"*\"\n",
        {"spring-actuator-exposes-every-endpoint": 1}),
    "vulnerable/app/AndroidManifest.xml": (
        "<manifest><application android:debuggable=\"true\"\n"
        "  android:usesCleartextTraffic=\"true\"/></manifest>\n",
        {"android-debuggable-build": 1, "android-cleartext-traffic": 1}),
    "vulnerable/pom.xml": (
        "<project><repositories><repository><id>old</id>\n"
        "<url>http://repo.example.com/maven</url></repository>"
        "</repositories></project>\n",
        {"maven-repository-over-http": 1}),
    "vulnerable/Makefile": (
        "install:\n\tcurl -fsSL https://example.com/i.sh | sh\n",
        {"makefile-download-piped-to-shell": 1}),
}
CONFIG_SAFE = {
    "safe/.gitlab-ci.yml": (
        "build:\n  script:\n"
        "    - curl -fsSLo i.sh https://example.com/i.sh\n"
        "    - echo \"$CI_COMMIT_MESSAGE\"\n"
        "    - eval \"$(ssh-agent -s)\"\n"
        "    - ./notify --title \"$CI_MERGE_REQUEST_TITLE\"\n"
        "    # curl https://example.com | sh, in a comment\n"
        "    # eval $CI_COMMIT_MESSAGE, in a comment\n"),
    "safe/docker-compose.yml": (
        "services:\n  app:\n    image: app\n    privileged: false\n"
        "    cap_add: [NET_ADMIN]\n    volumes:\n      - ./data:/data\n"
        "    # privileged: true would be bad\n"),
    "safe/src/main/resources/application.properties": (
        "management.endpoints.web.exposure.include=health,info\n"),
    "safe/src/main/resources/application-prod.yml": (
        "management:\n  endpoints:\n    web:\n      exposure:\n"
        "        include: health,info\n"),
    "safe/app/AndroidManifest.xml": (
        "<manifest><application android:debuggable=\"false\"\n"
        "  android:usesCleartextTraffic=\"false\"/></manifest>\n"),
    "safe/pom.xml": (
        "<project><url>http://example.com/project-site</url>\n"
        "<repositories><repository><id>ok</id>"
        "<url>https://repo.example.com/maven</url></repository>"
        "<repository><id>local</id><url>http://localhost:8081/repo</url>"
        "</repository></repositories></project>\n"),
    "safe/Makefile": (
        "install:\n\tcurl -fsSLo i.sh https://example.com/i.sh\n"
        "\t@echo \"curl x | sh is bad\"\n"),
    # privileged: true outside a compose file is not read by these rules
    "safe/values.yml": "privileged: true\n",
}
SEMGREP = "Multi-language analysis (Semgrep)"
UNCOVERED = "Code without scanner rules"

pytestmark = pytest.mark.skipif(shutil.which("semgrep") is None,
                                reason="semgrep is not installed")

# the name words the secret rules look for, split in two
PW_NAME = "PASS" "WORD"
SEC_NAME = "SEC" "RET"


def lines(*texts):
    return "\n".join(texts) + "\n"


SHELL_VULNERABLE = {
    "shell-download-piped-to-shell": (5, lines(
        "#!/bin/bash",
        "curl -fsSL https://example.com/install.sh | sh",
        "wget -qO- https://example.com/i.sh | sudo bash",
        "bash <(curl -s https://example.com/i.sh)",
        'sh -c "$(curl -fsSL https://example.com/i.sh)"',
        'eval "$(curl -s https://example.com/env)"')),
    "shell-eval-of-variable": (6, lines(
        "#!/bin/bash",
        'eval "$CMD"',
        "eval $CMD",
        'eval "ls $DIR"',
        'eval "$(tool --dir "$DIR")"',
        'eval "${ARGS[@]}"',
        # conda's variable, but more than conda's line
        'eval "$__conda_setup; $EXTRA"')),
    "shell-rm-rf-variable-path": (10, lines(
        "#!/bin/bash",
        'rm -rf "$DIR/"*',
        'rm -rf "$DIR"/*',
        "rm -rf $DIR",
        'rm -fr "$BUILD/"',
        'sudo rm -r -f "$PREFIX/lib"',
        "cd /tmp && rm -rf $WORK/*",
        'rm -rf "$1/"*',
        "rm -rf $1/*",
        "rm --recursive --force $WORKDIR",
        'rm --force -r "${2}/"')),
    "shell-chmod-world-writable": (7, lines(
        "#!/bin/bash",
        "chmod 777 /srv/data",
        'chmod -R 777 "$DIR"',
        "chmod 0777 run.sh",
        "chmod a+rwx run.sh",
        "if true; then chmod 777 /srv/share; fi",
        "find /srv -type d -exec chmod 777 {} +",
        "sudo chmod --recursive ugo+rwx /srv/share")),
    "shell-hardcoded-secret": (8, lines(
        "#!/bin/bash",
        'DB_%s="hunter2hunter2"' % PW_NAME,
        "export API_TOKEN=abcd1234efgh",
        "local %s='s3cr3t-value'" % SEC_NAME.lower(),
        "%s_KEY=abcd1234efgh" % SEC_NAME,
        "DB_PASS=hunter2hunter2",
        "export AWS_%s_ACCESS_KEY=abcd1234efgh5678" % SEC_NAME,
        # a switch word at the start of a longer value is still a value
        "API_TOKEN=nonesuch1234",
        "USER_TOKEN='true-value-99'")),
}

# the block conda init writes into a job script or ~/.bashrc
CONDA_INIT = (
    "# >>> conda initialize >>>",
    "__conda_setup=\"$('/opt/miniconda3/bin/conda' 'shell.bash' 'hook' "
    "2> /dev/null)\"",
    "if [ $? -eq 0 ]; then",
    '    eval "$__conda_setup"',
    "else",
    '    export PATH="/opt/miniconda3/bin:$PATH"',
    "fi",
    "unset __conda_setup",
    "# <<< conda initialize <<<")

SHELL_SAFE = lines(
    "#!/bin/bash",
    "curl -s https://example.com/data.json | jq .name",
    "curl -fsSLo install.sh https://example.com/i.sh",
    "echo hi | sh",
    'eval "$(ssh-agent -s)"',
    'eval "$(conda shell.bash hook)"',
    'eval "set -- $(printf %s "$OPTS" | xargs -n1)"',
    'eval "echo hello"',
    '# eval "$CMD" in a comment',
    *CONDA_INIT,
    'eval "$("$CONDA_EXE" shell.bash hook)"',
    'eval "$__mamba_setup"',
    'eval "$("$MAMBA_EXE" shell hook --shell bash --root-prefix '
    '"$MAMBA_ROOT_PREFIX" 2> /dev/null)"',
    'rm -rf "${DIR:?}/"*',
    'rm -rf "$DIR"',
    'rm -rf -- "$TMP"',
    "rm -rf /tmp/build",
    'rm -f "$DIR/file.txt"',
    'rm -rf "$HOME/.cache/tool"',
    'rm -rf "$@"',
    'rm -rf "${1:?}/"*',
    'rm --force "$1"',
    "rm -f $1",
    "chmod 755 run.sh",
    "chmod +x run.sh",
    "chmod 0700 ~/.ssh",
    "# never chmod 777 anything here",
    'echo "do not chmod 777"',
    '%s="$1"' % PW_NAME,
    '%s="${%s:-}"' % (PW_NAME, PW_NAME),
    'RUN_TOKEN=$(make_token "$X")',
    'TOKEN_REPO="$FIXTURE/repo"',
    'token="na"',
    'DB_%s="changeme"' % PW_NAME,
    "USE_TOKEN=true",
    "REQUIRE_%s=false" % PW_NAME,
    "API_KEY=none",
    'export USE_TOKEN="yes"',
    "%s_KEY='null'" % SEC_NAME,
    "SKIP_TOKEN=empty; echo done",
    # a test value as the whole value is a placeholder
    "DATABASE_%s=test" % PW_NAME,
    "API_TOKEN='fake'",
    "BYPASS=enabled1",
    "COMPASS=north-west")

DOCKERFILE_VULNERABLE = lines(
    "FROM alpine:3.20",
    "RUN curl -fsSL https://example.com/i.sh | sh",
    "RUN apk add curl && wget -qO- https://example.com/i.sh | bash -s",
    "ADD https://example.com/tool.tar.gz /opt/",
    "ADD --chown=app:app https://example.com/tool.tar.gz /opt/",
    "ENV DB_%s=hunter2hunter2" % PW_NAME,
    "ENV API_TOKEN abcd1234efgh",
    "ARG NPM_TOKEN=abcd1234efgh",
    'ENV A=1 JWT_%s="s3cr3t-value"' % SEC_NAME,
    # a switch or a placeholder earlier on the line leaves the next pair
    # judged on its own
    "ENV USE_TOKEN=true DB_%s=hunter2hunter2" % PW_NAME,
    "ENV A=example API_TOKEN=abcd1234efgh",
    "ARG %s_KEY=abcd1234efgh" % SEC_NAME,
    "ENV DB_PASS=hunter2hunter2",
    "ENV AWS_%s_ACCESS_KEY=abcd1234efgh5678" % SEC_NAME)
DOCKERFILE_COUNTS = {"dockerfile-download-piped-to-shell": 2,
                     "dockerfile-add-from-url": 2,
                     "dockerfile-secret-in-env-or-arg": 9}
DOCKERFILE_SAFE = lines(
    "FROM alpine:3.20",
    "RUN curl -fsSLo /tmp/i.sh https://example.com/i.sh && sha256sum -c /tmp/i.sum",
    "RUN curl -s https://example.com/data.json | jq .",
    "ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d "
    "https://example.com/tool.tar.gz /opt/",
    "ADD ./local.tar.gz /opt/",
    "ARG NPM_TOKEN",
    "ENV DB_%s=$DB_%s" % (PW_NAME, PW_NAME),
    "ENV TOKEN_FILE=/run/secrets/token",
    "ENV DB_%s=changeme" % PW_NAME,
    "ENV USE_TOKEN=true",
    "ARG REQUIRE_%s=false" % PW_NAME,
    "ENV API_KEY=none",
    "ENV USE_TOKEN true",
    "ENV CACHE_TOKEN=\"off\" DEBUG=1",
    'ENV API_TOKEN="${API_TOKEN}"',
    "ENV DB_%s=test" % PW_NAME,
    "ENV BYPASS=enabled1")

WORKFLOW_VULNERABLE = lines(
    "name: triage",
    "on:",
    "  issues:",
    "    types: [opened]",
    "  pull_request_target:",
    "    types: [opened, synchronize]",
    "jobs:",
    "  greet:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    '      - run: echo "New issue - ${{ github.event.issue.title }}"',
    "      - name: branch",
    "        run: |",
    '          echo "building"',
    '          git checkout "${{ github.head_ref }}"',
    "      - name: body",
    "        run: >",
    "          echo ${{ github.event.pull_request.body }}",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - run: make test")
WORKFLOW_COUNTS = {"github-actions-script-injection": 3,
                   "github-actions-pull-request-target-checkout": 1}


def workflow_echoing(fields):
    """A workflow with one run: step per field, each echoing ${{ field }}."""
    steps = ['      - run: echo "${{ %s }}"' % field for field in fields]
    return lines("name: fields",
                 "on: [issues, issue_comment, discussion, push]",
                 "jobs:",
                 "  echo:",
                 "    runs-on: ubuntu-latest",
                 "    steps:",
                 *steps)


# free text someone without write access sets: one finding each
UNTRUSTED_FIELDS = (
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.pull_request.title",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.commits[0].message",
    "github.event.commits[0].author.name",
    "join(github.event.commits.*.message, ' ')",
    "github.event.pages[0].page_name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message")
# fields no outsider can put shell code in
TRUSTED_FIELDS = (
    "github.event.repository.name",
    "github.event.action",
    "github.event.sender.login",
    "github.event.pull_request.head.repo.full_name",
    "github.event.repository.default_branch",
    "github.event.issue.number",
    "github.event.pull_request.head.sha",
    "github.event.inputs.fast",
    "github.event_name",
    "github.ref_name")
WORKFLOW_TARGET_LIST = lines(
    "name: build",
    "on: [push, pull_request_target]",
    "jobs:",
    "  build:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          fetch-depth: 0",
    "          ref: ${{ github.event.pull_request.head.ref }}")
WORKFLOW_SAFE = lines(
    "name: ci",
    "on:",
    "  pull_request:",
    "  workflow_dispatch:",
    "    inputs:",
    "      fast:",
    "        type: boolean",
    "jobs:",
    "  test:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "        with:",
    "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - name: title through env",
    "        env:",
    "          TITLE: ${{ github.event.pull_request.title }}",
    '        run: echo "Title - $TITLE"',
    '      - run: echo "PR ${{ github.event.pull_request.number }} at '
    '${{ github.event.pull_request.head.sha }}"',
    '      - run: echo "${{ github.event.inputs.fast }} ${{ github.repository }}"')
WORKFLOW_TARGET_SAFE = lines(
    "name: label",
    "on: pull_request_target",
    "jobs:",
    "  label:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "      - uses: actions/labeler@v5")
# YAML outside .github/workflows/ is never read by the workflow rules, even
# when it would match and does not parse
NOT_A_WORKFLOW = lines(
    "steps:",
    '  - run: echo "${{ github.event.issue.title }}"',
    "broken: [")

KOTLIN_VULNERABLE = lines(
    "package probe",
    "",
    "import android.database.sqlite.SQLiteDatabase",
    "import android.webkit.WebView",
    "import java.net.URL",
    "import java.security.MessageDigest",
    "import okhttp3.Request",
    "",
    "class Vulnerable {",
    "    fun run(dir: String) {",
    '        Runtime.getRuntime().exec("ls " + dir)',
    '        Runtime.getRuntime().exec("ls $dir")',
    '        Runtime.getRuntime().exec("ls ${dir}/x")',
    "    }",
    "",
    "    fun query(db: SQLiteDatabase, id: String, name: String) {",
    '        db.rawQuery("SELECT * FROM users WHERE id = " + id, null)',
    "        db.rawQuery(\"SELECT * FROM users WHERE name = '$name'\", null)",
    '        db.execSQL("DELETE FROM users WHERE id = $id")',
    '        db.execSQL("DELETE FROM users WHERE id = " + id)',
    "        // a constant beside a variable",
    '        db.rawQuery("SELECT * FROM " + TABLE + " WHERE id = " + id, null)',
    '        db.rawQuery("SELECT * FROM $TABLE WHERE id = $id", null)',
    "    }",
    "",
    "    fun web(webView: WebView) {",
    "        webView.settings.javaScriptEnabled = true",
    '        webView.addJavascriptInterface(Bridge(), "Android")',
    "    }",
    "",
    "    fun hash(data: ByteArray) {",
    '        MessageDigest.getInstance("MD5").digest(data)',
    '        MessageDigest.getInstance("SHA-1").digest(data)',
    '        MessageDigest.getInstance("SHA1").digest(data)',
    "    }",
    "",
    "    fun fetch() {",
    '        URL("http://example.com/data").readText()',
    '        Request.Builder().url("http://example.com/data").build()',
    "    }",
    "}")
KOTLIN_COUNTS = {"kotlin-command-from-string": 3,
                 "kotlin-sql-from-string": 6,
                 "kotlin-webview-javascript-interface": 1,
                 "kotlin-weak-hash": 3,
                 "kotlin-cleartext-http-url": 2}
KOTLIN_SAFE = lines(
    "package probe",
    "",
    "import android.database.sqlite.SQLiteDatabase",
    "import android.webkit.WebView",
    "import java.net.URL",
    "import java.security.MessageDigest",
    "import okhttp3.Request",
    "",
    "class Safe {",
    "    fun run(dir: String) {",
    '        Runtime.getRuntime().exec(arrayOf("ls", dir))',
    '        Runtime.getRuntime().exec("ls -la")',
    '        ProcessBuilder("ls", dir).start()',
    "    }",
    "",
    "    fun query(db: SQLiteDatabase, id: String) {",
    '        db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(id))',
    '        db.execSQL("DELETE FROM users WHERE id = ?", arrayOf(id))',
    '        db.execSQL("CREATE TABLE t (id INTEGER)")',
    "    }",
    "",
    "    // SQL built only from literals and UPPER_SNAKE_CASE constants",
    "    fun onCreate(db: SQLiteDatabase) {",
    '        db.execSQL("CREATE TABLE " + TABLE_NAME + " (id INTEGER PRIMARY '
    'KEY, name TEXT)")',
    '        db.execSQL("CREATE TABLE " + FeedEntry.TABLE_NAME + " (" +',
    '            BaseColumns._ID + " INTEGER PRIMARY KEY, " +',
    '            FeedEntry.COLUMN_NAME_TITLE + " TEXT)")',
    '        db.execSQL("DROP TABLE IF EXISTS ${FeedEntry.TABLE_NAME}")',
    '        db.execSQL("CREATE TABLE t " + "(id INTEGER)")',
    '        db.rawQuery("SELECT count(*) FROM " + TABLE, null)',
    '        db.rawQuery("SELECT * FROM $TABLE", null)',
    "    }",
    "",
    "    fun web(webView: WebView) {",
    "        webView.settings.javaScriptEnabled = true",
    '        webView.loadUrl("https://example.com")',
    "    }",
    "",
    "    fun web2(webView: WebView) {",
    '        webView.addJavascriptInterface(Bridge(), "Android")',
    "    }",
    "",
    "    fun hash(data: ByteArray) {",
    '        MessageDigest.getInstance("SHA-256").digest(data)',
    "    }",
    "",
    "    fun fetch() {",
    '        URL("https://example.com/data").readText()',
    '        Request.Builder().url("https://example.com/data").build()',
    '        URL("http://localhost:8080/health").readText()',
    '        URL("http://10.0.2.2:8000/dev").readText()',
    "    }",
    "}")


def semgrep_results(tree):
    """{(relative path, rule id): count} and the errors, for one semgrep run
    of the whole local rule set over tree, run the way the gate runs it."""
    with open(os.path.join(tree, ".semgrepignore"), "w"):
        pass
    environment = dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0",
                       SEMGREP_SEND_METRICS="off")
    result = subprocess.run(
        ["semgrep", "scan", "--metrics=off", "--disable-nosem",
         "--no-git-ignore", "--config", RULES, "--json", tree],
        capture_output=True, text=True, env=environment)
    data = json.loads(result.stdout)
    counts = {}
    for item in data["results"]:
        key = (os.path.relpath(item["path"], tree),
               item["check_id"].rsplit(".", 1)[-1])
        counts[key] = counts.get(key, 0) + 1
    return counts, data["errors"]


def test_each_new_rule_fires_on_its_vulnerable_fixture_only():
    tree = tempfile.mkdtemp(prefix="rules-test-")
    expected = {}
    for rule, (count, text) in SHELL_VULNERABLE.items():
        write(tree, "vulnerable/%s.sh" % rule, text)
        expected[("vulnerable/%s.sh" % rule, rule)] = count
    write(tree, "vulnerable/Dockerfile", DOCKERFILE_VULNERABLE)
    for rule, count in DOCKERFILE_COUNTS.items():
        expected[("vulnerable/Dockerfile", rule)] = count
    write(tree, ".github/workflows/vulnerable.yml", WORKFLOW_VULNERABLE)
    for rule, count in WORKFLOW_COUNTS.items():
        expected[(".github/workflows/vulnerable.yml", rule)] = count
    write(tree, ".github/workflows/target-list.yaml", WORKFLOW_TARGET_LIST)
    expected[(".github/workflows/target-list.yaml",
              "github-actions-pull-request-target-checkout")] = 1
    write(tree, ".github/workflows/untrusted.yml",
          workflow_echoing(UNTRUSTED_FIELDS))
    expected[(".github/workflows/untrusted.yml",
              "github-actions-script-injection")] = len(UNTRUSTED_FIELDS)
    write(tree, "vulnerable/Vulnerable.kt", KOTLIN_VULNERABLE)
    for rule, count in KOTLIN_COUNTS.items():
        expected[("vulnerable/Vulnerable.kt", rule)] = count
    for path, (text, rule_counts) in CONFIG_VULNERABLE.items():
        write(tree, path, text)
        for rule, count in rule_counts.items():
            expected[(path, rule)] = count
    safe_files = dict(CONFIG_SAFE)
    safe_files.update({"safe/safe.sh": SHELL_SAFE,
                  "safe/Dockerfile": DOCKERFILE_SAFE,
                  ".github/workflows/safe.yml": WORKFLOW_SAFE,
                  ".github/workflows/target-safe.yml": WORKFLOW_TARGET_SAFE,
                  ".github/workflows/trusted.yml":
                      workflow_echoing(TRUSTED_FIELDS),
                  "docs/not-a-workflow.yml": NOT_A_WORKFLOW,
                  "safe/Safe.kt": KOTLIN_SAFE})
    for path, text in safe_files.items():
        write(tree, path, text)

    counts, errors = semgrep_results(tree)
    assert errors == []
    for key, count in sorted(expected.items()):
        assert counts.get(key, 0) == count, key
    for path in safe_files:
        fired = [key for key in counts if key[0] == path]
        assert fired == [], fired
    # every rule of the new rule files has a vulnerable fixture above
    rule_ids = set()
    for name in NEW_RULE_FILES:
        with open(os.path.join(RULES, name), encoding="utf-8") as f:
            rule_ids.update(re.findall(r"(?m)^  - id: (\S+)$", f.read()))
    assert rule_ids == set(rule for _path, rule in expected)


def new_findings(run_dir):
    """[(path, rule)] from the gate's new-semgrep.txt."""
    path = os.path.join(run_dir, "new-semgrep.txt")
    if not os.path.exists(path):
        return []
    findings = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            match = re.match(r"^(.*):\d+  \[([^\]]+)\]", line)
            if match:
                findings.append((match.group(1), match.group(2)))
    return findings


def test_scripts_and_dockerfiles_named_any_way_reach_their_rules():
    eval_line = 'eval "$CMD"\n'
    old_job = "#!/bin/bash\n" + eval_line

    def change(repo):
        # a sink already at the base, in a file with another name in the
        # scan tree: it stays old
        write(repo, "jobs/old.sbatch", "#!/bin/bash\n# still the same\n"
              + eval_line)
        write(repo, "jobs/train.sbatch", "#!/bin/bash\n" + eval_line)
        write(repo, "jobs/array.slurm", "#!/bin/bash\n" + eval_line)
        write(repo, "bin/deploy", "#!/bin/bash\nchmod 777 /srv/data\n")
        write(repo, "tools/env.zsh", "rm -rf $BUILD_DIR/*\n")
        write(repo, "lib/run.ksh", eval_line)
        write(repo, "Dockerfile.prod", "FROM alpine\n"
              "RUN curl -fsSL https://example.com/i.sh | sh\n")
        write(repo, "Containerfile", "FROM alpine\n"
              "ADD https://example.com/tool.tar.gz /opt/\n")
        write(repo, ".github/workflows/ci.yml", WORKFLOW_VULNERABLE)
        write(repo, "app/src/Main.kt",
              "fun run(dir: String) {\n"
              '    Runtime.getRuntime().exec("ls " + dir)\n}\n')
    code, rows, run_dir = run_gate(make_repo({"jobs/old.sbatch": old_job},
                                             change))
    assert code == 1
    assert rows[SEMGREP]["status"] == "TESTED"
    assert rows[SEMGREP]["scope"] == "10 code files"
    assert rows[UNCOVERED]["status"] == "NOT APPLICABLE"
    found = set(new_findings(run_dir))
    for path, rule in (
            ("jobs/train.sbatch", "shell-eval-of-variable"),
            ("jobs/array.slurm", "shell-eval-of-variable"),
            ("bin/deploy", "shell-chmod-world-writable"),
            ("tools/env.zsh", "shell-rm-rf-variable-path"),
            ("lib/run.ksh", "shell-eval-of-variable"),
            ("Dockerfile.prod", "dockerfile-download-piped-to-shell"),
            ("Containerfile", "dockerfile-add-from-url"),
            (".github/workflows/ci.yml", "github-actions-script-injection"),
            (".github/workflows/ci.yml",
             "github-actions-pull-request-target-checkout"),
            ("app/src/Main.kt", "kotlin-command-from-string")):
        assert (path, rule) in found, (path, rule)
    assert not any(path == "jobs/old.sbatch" for path, _rule in found)


def test_a_script_semgrep_cannot_fully_parse_is_a_caveat_not_a_veto():
    # zsh syntax read by the bash parser, beside a Helm template that is
    # not valid YAML (and not a workflow)
    def change(repo):
        write(repo, "tools/list.zsh", "print -l ${(j:,:)names}\n")
        write(repo, "charts/app/templates/deploy.yaml",
              "a: {{ .Values.x }}\n  b: [\n")
    code, rows, _run_dir = run_gate(make_repo({}, change))
    assert code == 0
    semgrep = rows[SEMGREP]
    assert semgrep["status"] == "TESTED"
    assert semgrep["scope"] == "1 code files"
    assert "1 file(s) not fully scanned" in semgrep["outcome"]
    uncovered = rows[UNCOVERED]
    assert uncovered["status"] == "PARTIAL"
    assert uncovered["scope"] == "0 of 2 code files"
    assert "tools/list.zsh (Shell): semgrep could not parse all of it" \
        in uncovered["reason"]
    # the template is configuration no rule reads: named, not parsed
    assert "charts/app/templates/deploy.yaml (YAML config)" \
        in uncovered["reason"]


def test_a_script_that_is_not_utf8_is_a_caveat():
    # one Latin-1 byte: semgrep lists the file as scanned, but its text
    # rules can miss what is in it. The workflow rules still match in such a
    # file, so a Latin-1 workflow is not named.
    workflow = (b"name: ci\n# caf\xe9\non: push\njobs:\n  a:\n"
                b"    runs-on: ubuntu-latest\n    steps:\n"
                b"      - run: echo ok\n")

    def change(repo):
        write(repo, "jobs/run.sh", b"#!/bin/bash\n# caf\xe9\necho ok\n")
        write(repo, "jobs/ok.sh", "#!/bin/bash\necho ok\n")
        write(repo, ".github/workflows/ci.yml", workflow)
    code, rows, _run_dir = run_gate(make_repo({}, change))
    assert code == 0
    assert rows[SEMGREP]["scope"] == "3 code files"
    assert "1 file(s) not fully scanned" in rows[SEMGREP]["outcome"]
    uncovered = rows[UNCOVERED]
    assert uncovered["status"] == "PARTIAL"
    assert uncovered["scope"] == "2 of 3 code files"
    assert uncovered["reason"] == (
        "Semgrep rules applied only in part to: jobs/run.sh (Shell): not "
        "UTF-8, so semgrep's text rules can miss lines in it")
