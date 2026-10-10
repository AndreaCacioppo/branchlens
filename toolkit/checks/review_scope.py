#!/usr/bin/env python3
"""
review_scope.py — the scope of the phase-2 review, computed without an LLM.

The gate writes <run-dir>/review-scope.json with what the review needs to
start: the files the change touches with their changed-line counts, the
checklist entries, and which files get a language deep dive. The review
workflow only loads it.

Two things keep that hand-over honest:
  - the checklist entries are parsed here from checklist.md, and verdict.py
    parses the same file again when it merges the review rows, so the set of
    REV rows is fixed by the checklist, never by an agent;
  - `scope_checksum` covers every changed path with its status and every
    planned deep dive with its skill. The workflow recomputes it over the
    scope it used, and verdict.py refuses the merge when the two differ, so
    a dropped file, a file marked deleted or an emptied dive plan is caught.

The checksum is 32-bit FNV-1a over the UTF-16 code units of those lines,
sorted and joined by newlines. review-diff.js computes the same value in
plain JavaScript (no hashing library), so the two must stay identical. It
detects accidents and tampering by an agent, not a cryptographic attack.
"""

import json
import os
import re

# 3: code_files added, which the review needs (must match review-diff.js)
SCOPE_FORMAT = 3

# Per-file deep dives: file extension -> skill in ~/.claude/skills/. The
# JavaScript skill also covers HTML pages with inline scripts; the bash
# skill covers ksh and batch job scripts (.sbatch, .slurm, .pbs).
DIVE_SKILL_BY_EXTENSION = {
    "py": "security-python",
    "java": "security-java",
    "js": "security-javascript", "jsx": "security-javascript",
    "ts": "security-javascript", "tsx": "security-javascript",
    "mjs": "security-javascript", "cjs": "security-javascript",
    "html": "security-javascript", "htm": "security-javascript",
    "sh": "security-bash", "bash": "security-bash", "zsh": "security-bash",
    "ksh": "security-bash", "sbatch": "security-bash",
    "slurm": "security-bash", "pbs": "security-bash",
    "sql": "security-sql",
    "pl": "security-perl", "pm": "security-perl", "t": "security-perl",
    "cgi": "security-perl",
}

# A script without an extension, by the language its #! line names (the
# gate's shebang_language).
DIVE_SKILL_BY_SCRIPT_LANGUAGE = {
    "Python": "security-python",
    "JavaScript": "security-javascript",
    "Shell": "security-bash",
    "Perl": "security-perl",
}

# Largest changes are dived first; files beyond the cap are listed in the
# scope and the feed, not dropped silently.
MAX_DIVES = 12

CHECKLIST_HEADING = re.compile(r"^## (REV-\d{2}) — (.+?)\s*$")


def parse_checklist(path):
    """Returns [{"id", "title"}] for every '## REV-NN — title' heading, in
    file order."""
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            match = CHECKLIST_HEADING.match(line.rstrip("\n"))
            if match:
                entries.append({"id": match.group(1),
                                "title": match.group(2)})
    return entries


def paths_checksum(paths):
    """32-bit FNV-1a of the sorted strings joined by newlines, over UTF-16
    code units, as 8 hex digits (see the module note)."""
    # UTF-16 code-unit order, as JavaScript's sort() uses; code-point order
    # differs for characters beyond U+FFFF
    ordered = sorted(paths, key=lambda path: path.encode("utf-16-be"))
    text = "\n".join(ordered)
    units = text.encode("utf-16-le")
    value = 0x811C9DC5
    for index in range(0, len(units), 2):
        value ^= units[index] | (units[index + 1] << 8)
        value = (value * 0x01000193) & 0xFFFFFFFF
    return "%08x" % value


def scope_checksum(files, dives):
    """The checksum of the lines 'file<TAB>status<TAB>path' and
    'dive<TAB>skill<TAB>path' (see the module note)."""
    lines = ["file\t%s\t%s" % (f["status"], f["path"]) for f in files]
    lines += ["dive\t%s\t%s" % (d["skill"], d["path"])
              for d in dives["planned"]]
    return paths_checksum(lines)


def dive_skill_for(path, script_language=None):
    """The deep-dive skill for a file: by its extension, or for a name
    without one by script_language, the language its #! line names."""
    name = os.path.basename(path)
    if "." not in name:
        return DIVE_SKILL_BY_SCRIPT_LANGUAGE.get(script_language)
    extension = name.rsplit(".", 1)[1].lower()
    return DIVE_SKILL_BY_EXTENSION.get(extension)


SKILLS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "skills")


def dive_plan(files, skills_dir=SKILLS_DIR, script_language=None):
    """Splits the changed files into dived / beyond the cap / no skill.
    Deleted files are skipped. A skill that is not installed counts as no
    skill, so no agent is sent to review without its catalog.
    script_language: {path: language} for the scripts without an
    extension."""
    candidates = []
    no_skill = []
    for entry in files:
        if entry["status"] == "D":
            continue
        skill = dive_skill_for(entry["path"],
                               (script_language or {}).get(entry["path"]))
        if skill and not os.path.isfile(os.path.join(skills_dir, skill,
                                                     "SKILL.md")):
            skill = None
        if skill:
            candidates.append({"path": entry["path"], "skill": skill,
                               "changed_lines": entry["changed_lines"]})
        else:
            no_skill.append(entry["path"])
    # largest change first; the path breaks ties so the order is stable
    candidates.sort(key=lambda item: (-item["changed_lines"], item["path"]))
    return {
        "planned": candidates[:MAX_DIVES],
        "dropped_beyond_cap": [item["path"] for item in candidates[MAX_DIVES:]],
        "no_matching_skill": no_skill,
        "cap": MAX_DIVES,
    }


def parse_numstat(output):
    """`git diff --numstat -z` -> {new path: (added, deleted)}. Binary files
    report '-' for both counts, read here as 0."""
    counts = {}
    fields = output.split("\0")
    position = 0
    while position < len(fields) and fields[position]:
        parts = fields[position].split("\t", 2)  # a path may hold a tab
        added = int(parts[0]) if parts[0].isdigit() else 0
        deleted = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if len(parts) >= 3 and parts[2]:
            counts[parts[2]] = (added, deleted)
            position += 1
        else:
            # rename/copy: an empty path field, then old and new paths
            if position + 2 < len(fields):
                counts[fields[position + 2]] = (added, deleted)
            position += 3
    return counts


def build_scope(base_ref, fork_commit, head_commit, changed, numstat_output,
                checklist_path, script_language=None, code_without_rules=None,
                code_files=None):
    """changed: [(status letter, path)] as the gate computed it.
    script_language: {path: language} for the scripts without an extension.
    code_without_rules: [{"path", "language"}], the changed code files in a
    language no local Semgrep rule covers; verdict.py names the ones no deep
    dive read either when it merges the review.
    code_files: the paths of every changed file the gate treats as code
    (deleted files excluded). The dead-code reviewers (REV-11, REV-12)
    report how many of them they examined."""
    counts = parse_numstat(numstat_output)
    files = []
    for status, path in changed:
        added, deleted = counts.get(path, (0, 0))
        files.append({"path": path, "status": status, "added": added,
                      "deleted": deleted, "changed_lines": added + deleted})
    entries = parse_checklist(checklist_path)
    dives = dive_plan(files, script_language=script_language)
    return {
        "scope_format": SCOPE_FORMAT,
        "base_ref": base_ref,
        "fork_commit": fork_commit,
        "head_commit": head_commit,
        "file_count": len(files),
        "scope_checksum": scope_checksum(files, dives),
        "touched_files": files,
        "entries": entries,
        "dives": dives,
        "code_without_rules": list(code_without_rules or []),
        "code_files": list(code_files or []),
    }


def undived_code_without_rules(scope, deep_dived):
    """The entries of scope["code_without_rules"] that no deep dive read
    either. deep_dived: the paths whose dive completed, as the review
    workflow reports them; a path the gate did not plan a dive for does not
    count."""
    planned = set(dive["path"] for dive in scope["dives"]["planned"])
    dived = set(path for path in deep_dived if path in planned)
    return [entry for entry in scope.get("code_without_rules", [])
            if entry["path"] not in dived]


def write_scope(run_dir, scope):
    with open(os.path.join(run_dir, "review-scope.json"), "w",
              encoding="utf-8") as f:
        json.dump(scope, f, indent=1, ensure_ascii=False)


def read_scope(run_dir):
    with open(os.path.join(run_dir, "review-scope.json"),
              encoding="utf-8") as f:
        return json.load(f)
