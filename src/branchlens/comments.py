"""Where the comments are in a file, for the page's comments toggle.

A small lexical scan per language skips strings, so a '#' or '//' inside
one is no comment. It reads the whole file, so a comment or docstring that
opens above the lines the diff shows is still found. Nothing here runs code
from the inspected repository.
"""

import bisect
import re

from branchlens import gitops


def make_language(
    name,
    line_markers=(),
    block_pairs=(),
    quotes=(),
    long_quotes=(),
    raw_quotes=(),
    word_start_only=False,
    escapable_marker=False,
    marker_lookalikes=(),
    char_literals=False,
    docstrings=False,
    regex_literals=False,
    line_start_blocks=(),
    markup=False,
):
    """The comment syntax of one language, as a dictionary.

    name               what the page calls the language
    line_markers       start a comment that runs to the end of the line
    block_pairs        (opener, closer) of a comment that may span lines
    quotes             open a string that ends on its own line at the latest
    long_quotes        open a string that may span lines (Python's \"\"\")
    raw_quotes         the quotes, of either kind, whose strings read a
                       backslash as an ordinary character (shell's ')
    word_start_only    a line marker counts only first on its line or after
                       a space or ';', as '#' in shell and YAML
    escapable_marker   a backslash just before a line marker cancels it, as
                       in LaTeX's \\%
    marker_lookalikes  code that starts like a line marker: PHP's #[...]
    char_literals      ' opens a character literal ('a', '\\n') only when it
                       closes right after, so Rust's 'a lifetimes stay code
    docstrings         Python: a string standing alone as a statement
                       counts as a comment
    regex_literals     JavaScript: /.../ literals, which may hold quotes
    line_start_blocks  (opener, closer) regular expressions of a comment
                       whose first and last lines start with them: Ruby's
                       =begin and =end
    markup             HTML: <!-- --> comments, and the JavaScript and CSS
                       inside <script> and <style>
    """
    return {
        "name": name,
        "line_markers": list(line_markers),
        "block_pairs": list(block_pairs),
        "quotes": list(quotes),
        "long_quotes": list(long_quotes),
        "raw_quotes": list(raw_quotes),
        "word_start_only": word_start_only,
        "escapable_marker": escapable_marker,
        "marker_lookalikes": list(marker_lookalikes),
        "char_literals": char_literals,
        "docstrings": docstrings,
        "regex_literals": regex_literals,
        "line_start_blocks": list(line_start_blocks),
        "markup": markup,
    }


def c_family(name, long_quotes=()):
    """// and /* */ comments, "..." strings and 'x' character literals."""
    return make_language(
        name,
        line_markers=["//"],
        block_pairs=[("/*", "*/")],
        quotes=['"'],
        long_quotes=long_quotes,
        char_literals=True,
    )


PYTHON = make_language(
    "Python",
    line_markers=["#"],
    quotes=['"', "'"],
    long_quotes=['"""', "'''"],
    docstrings=True,
)
JAVASCRIPT = make_language(
    "JavaScript",
    line_markers=["//"],
    block_pairs=[("/*", "*/")],
    quotes=['"', "'"],
    long_quotes=["`"],
    regex_literals=True,
)
TYPESCRIPT = dict(JAVASCRIPT, name="TypeScript")
JSONC = make_language(
    "JSON with comments", line_markers=["//"], block_pairs=[("/*", "*/")], quotes=['"', "'"]
)
JSON = make_language("JSON", quotes=['"'])  # JSON has no comments
JAVA = c_family("Java", long_quotes=['"""'])
KOTLIN = c_family("Kotlin", long_quotes=['"""'])
SCALA = c_family("Scala", long_quotes=['"""'])
CSHARP = c_family("C#", long_quotes=['"""'])
SWIFT = c_family("Swift", long_quotes=['"""'])
C = c_family("C")
CPP = c_family("C++")
OBJECTIVE_C = c_family("Objective-C")
RUST = c_family("Rust")
GO = make_language(
    "Go",
    line_markers=["//"],
    block_pairs=[("/*", "*/")],
    quotes=['"'],
    long_quotes=["`"],
    raw_quotes=["`"],
    char_literals=True,
)
DART = make_language(
    "Dart",
    line_markers=["//"],
    block_pairs=[("/*", "*/")],
    quotes=['"', "'"],
    long_quotes=['"""', "'''"],
)
GROOVY = make_language(
    "Groovy",
    line_markers=["//"],
    block_pairs=[("/*", "*/")],
    quotes=['"', "'"],
    long_quotes=['"""', "'''"],
)
PHP = make_language(
    "PHP",
    line_markers=["//", "#"],
    block_pairs=[("/*", "*/")],
    quotes=['"', "'"],
    marker_lookalikes=["#["],
)
CSS = make_language("CSS", block_pairs=[("/*", "*/")], quotes=['"', "'"])
SCSS = make_language(
    "SCSS", line_markers=["//"], block_pairs=[("/*", "*/")], quotes=['"', "'"]
)
LESS = dict(SCSS, name="Less")
SHELL = make_language(
    "Shell", line_markers=["#"], quotes=['"', "'"], raw_quotes=["'"], word_start_only=True
)
POWERSHELL = make_language(
    "PowerShell", line_markers=["#"], block_pairs=[("<#", "#>")], quotes=['"', "'"]
)
PERL = make_language(
    "Perl",
    line_markers=["#"],
    quotes=['"', "'"],
    raw_quotes=["'"],
    word_start_only=True,  # so $#array, the last index, stays code
    line_start_blocks=[(r"=[A-Za-z]", r"=cut\b")],  # POD documentation
)
RUBY = make_language(
    "Ruby",
    line_markers=["#"],
    quotes=['"', "'"],
    line_start_blocks=[(r"=begin\b", r"=end\b")],
)
R = make_language("R", line_markers=["#"], quotes=['"', "'"])
JULIA = make_language(
    "Julia",
    line_markers=["#"],
    block_pairs=[("#=", "=#")],
    quotes=['"'],
    long_quotes=['"""'],
)
SQL = make_language(
    "SQL",
    line_markers=["--", "#"],  # '#' is MySQL and MariaDB
    block_pairs=[("/*", "*/")],
    quotes=["'", '"', "`"],
)
LUA = make_language(
    "Lua", line_markers=["--"], block_pairs=[("--[[", "]]")], quotes=['"', "'"]
)
HASKELL = make_language(
    "Haskell", line_markers=["--"], block_pairs=[("{-", "-}")], quotes=['"']
)
LISP = make_language("Lisp", line_markers=[";"], quotes=['"'])
LATEX = make_language("LaTeX", line_markers=["%"], escapable_marker=True)
MAKEFILE = make_language("Makefile", line_markers=["#"], escapable_marker=True)
DOCKERFILE = make_language(
    "Dockerfile", line_markers=["#"], quotes=['"', "'"], word_start_only=True
)
YAML = make_language("YAML", line_markers=["#"], quotes=['"', "'"], word_start_only=True)
TOML = make_language(
    "TOML", line_markers=["#"], quotes=['"', "'"], long_quotes=['"""', "'''"], raw_quotes=["'", "'''"]
)
INI = make_language("INI", line_markers=["#", ";"], word_start_only=True)
CONFIG = make_language("config", line_markers=["#"], word_start_only=True)
TERRAFORM = make_language(
    "Terraform", line_markers=["#", "//"], block_pairs=[("/*", "*/")], quotes=['"']
)
HTML = make_language("HTML", markup=True)
XML = make_language("XML", block_pairs=[("<!--", "-->")])
MARKDOWN = make_language("Markdown", block_pairs=[("<!--", "-->")])

LANGUAGES_BY_EXTENSION = {
    ".py": PYTHON, ".pyi": PYTHON, ".pyw": PYTHON,
    ".js": JAVASCRIPT, ".jsx": JAVASCRIPT, ".mjs": JAVASCRIPT, ".cjs": JAVASCRIPT,
    ".ts": TYPESCRIPT, ".tsx": TYPESCRIPT, ".mts": TYPESCRIPT, ".cts": TYPESCRIPT,
    ".json": JSON, ".jsonc": JSONC, ".json5": JSONC,
    ".java": JAVA, ".kt": KOTLIN, ".kts": KOTLIN, ".scala": SCALA, ".sc": SCALA,
    ".cs": CSHARP, ".swift": SWIFT, ".go": GO, ".rs": RUST, ".dart": DART,
    ".groovy": GROOVY, ".gradle": GROOVY,
    ".c": C, ".h": C, ".cc": CPP, ".cpp": CPP, ".cxx": CPP, ".hh": CPP, ".hpp": CPP,
    ".hxx": CPP, ".m": OBJECTIVE_C, ".mm": OBJECTIVE_C,
    ".php": PHP,
    ".css": CSS, ".scss": SCSS, ".sass": SCSS, ".less": LESS,
    ".sh": SHELL, ".bash": SHELL, ".zsh": SHELL, ".ksh": SHELL, ".fish": SHELL,
    ".ps1": POWERSHELL, ".psm1": POWERSHELL,
    ".pl": PERL, ".pm": PERL, ".t": PERL, ".cgi": PERL,
    ".rb": RUBY, ".rake": RUBY, ".gemspec": RUBY,
    ".r": R, ".jl": JULIA,
    ".sql": SQL, ".lua": LUA, ".hs": HASKELL,
    ".lisp": LISP, ".el": LISP, ".clj": LISP, ".cljs": LISP, ".scm": LISP,
    ".tex": LATEX, ".sty": LATEX, ".cls": LATEX,
    ".mk": MAKEFILE,
    ".dockerfile": DOCKERFILE, ".containerfile": DOCKERFILE,
    ".yml": YAML, ".yaml": YAML, ".toml": TOML,
    ".ini": INI, ".cfg": INI, ".editorconfig": INI,
    ".conf": CONFIG, ".properties": CONFIG, ".env": CONFIG,
    ".tf": TERRAFORM, ".hcl": TERRAFORM,
    ".html": HTML, ".htm": HTML, ".xhtml": HTML, ".vue": HTML, ".svelte": HTML,
    ".xml": XML, ".svg": XML, ".xsd": XML, ".xsl": XML, ".plist": XML,
    ".md": MARKDOWN, ".markdown": MARKDOWN,
}

# Whole file names, lowercased, for files whose name says the language.
LANGUAGES_BY_FILE_NAME = {
    "makefile": MAKEFILE, "gnumakefile": MAKEFILE,
    "dockerfile": DOCKERFILE, "containerfile": DOCKERFILE,
    "rakefile": RUBY, "gemfile": RUBY,
    "cmakelists.txt": CONFIG,
    ".bashrc": SHELL, ".bash_profile": SHELL, ".zshrc": SHELL, ".zprofile": SHELL,
    ".profile": SHELL, ".envrc": SHELL,
    ".gitignore": CONFIG, ".gitattributes": CONFIG, ".dockerignore": CONFIG,
}

# The program a "#!" first line names, with any version digits taken off.
LANGUAGES_BY_INTERPRETER = {
    "python": PYTHON, "sh": SHELL, "bash": SHELL, "zsh": SHELL, "ksh": SHELL,
    "dash": SHELL, "perl": PERL, "ruby": RUBY, "node": JAVASCRIPT,
    "deno": TYPESCRIPT, "rscript": R,
}

# A character literal: one character or one escape between single quotes.
CHAR_LITERAL = re.compile(r"'(?:\\u\{[0-9A-Fa-f]{1,6}\}|\\.|[^\\'\n])'")

# The characters before a line marker that let it start a comment in a
# word_start_only language.
WORD_START_BEFORE_MARKER = " \t\r\n;"

# Python's string prefixes, such as the r of r"\d" or the f of f"{x}".
PYTHON_STRING_PREFIX_LETTERS = "rRuUbBfF"

HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

MARKUP_SECTION = re.compile(r"<!--|<(script|style)\b[^>]*>", re.IGNORECASE)

# One token pattern per language, built the first time it is needed.
token_patterns = {}


def language_for(path, first_line):
    """The language of a file, from its name or its "#!" line, or None."""
    file_name = path.rsplit("/", 1)[-1].lower()
    if file_name in LANGUAGES_BY_FILE_NAME:
        return LANGUAGES_BY_FILE_NAME[file_name]
    if file_name.startswith("dockerfile.") or file_name.startswith("containerfile."):
        return DOCKERFILE
    dot_at = file_name.rfind(".")
    if dot_at != -1 and file_name[dot_at:] in LANGUAGES_BY_EXTENSION:
        return LANGUAGES_BY_EXTENSION[file_name[dot_at:]]
    return language_from_shebang(first_line)


def language_from_shebang(first_line):
    """The language a "#!/usr/bin/env python3" style first line names, or None."""
    if not first_line.startswith("#!"):
        return None
    for word in first_line[2:].split():
        program = word.rsplit("/", 1)[-1]
        if program == "env" or program.startswith("-"):
            continue  # /usr/bin/env -S python3: the program comes later
        program = program.rstrip("0123456789.").lower()  # python3.12 -> python
        return LANGUAGES_BY_INTERPRETER.get(program)
    return None


def token_pattern_for(language):
    """One regular expression that finds the next marker, quote or bracket.

    Returns (pattern, kinds): each alternative is a named group, and
    kinds maps the group's name to (kind, detail), such as ("block", "*/")
    for "/*". The pattern is built once per language.
    """
    if language["name"] in token_patterns:
        return token_patterns[language["name"]]
    alternatives = []
    for opener, closer in language["line_start_blocks"]:
        closer_pattern = re.compile("^" + closer, re.MULTILINE)
        alternatives.append(("^" + opener, "line_start_block", closer_pattern))
    literal_tokens = []
    for marker in language["line_markers"]:
        literal_tokens.append((marker, "line", marker))
    for opener, closer in language["block_pairs"]:
        literal_tokens.append((opener, "block", closer))
    for quote in language["long_quotes"] + language["quotes"]:
        literal_tokens.append((quote, "string", quote))
    if language["char_literals"]:
        literal_tokens.append(("'", "char", None))
    if language["regex_literals"]:
        literal_tokens.append(("/", "regex", None))
    if language["docstrings"]:
        # Python: the bracket depth tells a docstring from a string argument
        for bracket in "([{":
            literal_tokens.append((bracket, "open_bracket", None))
        for bracket in ")]}":
            literal_tokens.append((bracket, "close_bracket", None))
    # A regular expression takes the first alternative that matches, so
    # '"""' must come before '"' and '/*' before '/'.
    literal_tokens.sort(key=lambda token: len(token[0]), reverse=True)
    for token, kind, detail in literal_tokens:
        alternatives.append((re.escape(token), kind, detail))

    pattern_parts = []
    kinds = {}
    for index, (pattern_text, kind, detail) in enumerate(alternatives):
        group_name = "t" + str(index)
        pattern_parts.append("(?P<" + group_name + ">" + pattern_text + ")")
        kinds[group_name] = (kind, detail)
    if len(pattern_parts) == 0:
        pattern = None  # a language with no comments and no strings
    else:
        pattern = re.compile("|".join(pattern_parts), re.MULTILINE)
    token_patterns[language["name"]] = (pattern, kinds)
    return pattern, kinds


def line_end(text, position):
    """The offset of the newline that ends the line holding position."""
    newline_at = text.find("\n", position)
    if newline_at == -1:
        return len(text)
    return newline_at


def find_comment_spans(text, language):
    """Every comment in the text as a (start, end) pair of offsets, in order."""
    if language["markup"]:
        return find_markup_comment_spans(text)
    pattern, kinds = token_pattern_for(language)
    if pattern is None:
        return []
    spans = []
    bracket_depth = 0
    position = 0
    length = len(text)
    while position < length:
        match = pattern.search(text, position)
        if match is None:
            break
        start = match.start()
        kind, detail = kinds[match.lastgroup]
        if kind == "line":
            if line_marker_opens_comment(text, start, language):
                end = line_end(text, start)
                spans.append((start, end))
                position = end
            else:
                position = match.end()
        elif kind == "block":
            closer_at = text.find(detail, match.end())
            if closer_at == -1:
                end = length  # never closed: it runs to the end of the file
            else:
                end = closer_at + len(detail)
            spans.append((start, end))
            position = end
        elif kind == "line_start_block":
            closer = detail.search(text, match.end())
            if closer is None:
                end = length
            else:
                end = line_end(text, closer.start())  # the closing line is part of it
            spans.append((start, end))
            position = end
        elif kind == "string":
            end = find_string_end(text, match.end(), detail, language)
            if language["docstrings"] and string_is_docstring(text, start, end, bracket_depth):
                spans.append((start, end))
            position = end
        elif kind == "char":
            literal = CHAR_LITERAL.match(text, start)
            if literal is None:
                position = start + 1  # a lone quote, such as a Rust lifetime
            else:
                position = literal.end()
        elif kind == "regex":
            position = find_regex_end(text, start)
        elif kind == "open_bracket":
            bracket_depth += 1
            position = match.end()
        else:  # close_bracket
            if bracket_depth > 0:
                bracket_depth -= 1
            position = match.end()
    return spans


def line_marker_opens_comment(text, marker_at, language):
    """Whether the line marker at marker_at starts a comment, given its neighbours."""
    for lookalike in language["marker_lookalikes"]:
        if text.startswith(lookalike, marker_at):
            return False
    if marker_at == 0:
        return True
    character_before = text[marker_at - 1]
    if language["escapable_marker"] and character_before == "\\":
        return False
    if language["word_start_only"] and character_before not in WORD_START_BEFORE_MARKER:
        return False
    return True


def find_string_end(text, position, quote, language):
    """The offset just past the string whose opening quote ends at position.

    A string that may not span lines ends with its line if nothing closes
    it sooner, so a stray quote hides one line at most.
    """
    may_span_lines = quote in language["long_quotes"]
    reads_backslash = quote not in language["raw_quotes"]
    length = len(text)
    while position < length:
        character = text[position]
        if character == "\\" and reads_backslash:
            position += 2  # the escaped character cannot close the string
            continue
        if text.startswith(quote, position):
            return position + len(quote)
        if character == "\n" and not may_span_lines:
            return position
        position += 1
    return length


def string_is_docstring(text, quote_at, string_end, bracket_depth):
    """Python: whether a string stands alone as a statement, as a docstring does.

    It has to open its line (after its prefix letters), lie outside every
    bracket, and have nothing but a comment after it. So \"\"\"...\"\"\".format(x)
    or a string argument is not one.
    """
    if bracket_depth > 0:
        return False
    line_start = text.rfind("\n", 0, quote_at) + 1
    before = text[line_start:quote_at].rstrip(PYTHON_STRING_PREFIX_LETTERS)
    if before.strip() != "":
        return False
    after = text[string_end:line_end(text, string_end)].strip()
    return after == "" or after.startswith("#")


def find_regex_end(text, slash_at):
    """JavaScript: the offset just past the regex literal opening at slash_at.

    Returns slash_at + 1 when the slash divides, or when no closing slash
    follows on its line.
    """
    if not gitops.js_slash_starts_regex(text, slash_at):
        return slash_at + 1
    position = slash_at + 1
    inside_class = False  # a '/' inside [...] does not close the literal
    length = len(text)
    while position < length:
        character = text[position]
        if character == "\\":
            position += 2
            continue
        if character == "\n":
            break
        if character == "[":
            inside_class = True
        elif character == "]":
            inside_class = False
        elif character == "/" and not inside_class:
            return position + 1
        position += 1
    return slash_at + 1


def find_markup_comment_spans(text):
    """HTML: the <!-- --> comments, and the comments inside <script> and <style>."""
    spans = []
    position = 0
    while True:
        match = MARKUP_SECTION.search(text, position)
        if match is None:
            return spans
        if match.group(1) is None:  # "<!--"
            closer_at = text.find("-->", match.end())
            if closer_at == -1:
                end = len(text)
            else:
                end = closer_at + len("-->")
            spans.append((match.start(), end))
            position = end
            continue
        tag_name = match.group(1).lower()
        closing_tag = re.compile(r"</" + tag_name + r"\s*>", re.IGNORECASE)
        closing_match = closing_tag.search(text, match.end())
        body_start = match.end()
        if closing_match is None:
            body_end = len(text)
        else:
            body_end = closing_match.start()
        if tag_name == "script":
            inner_language = JAVASCRIPT
        else:
            inner_language = CSS
        for span_start, span_end in find_comment_spans(text[body_start:body_end], inner_language):
            spans.append((body_start + span_start, body_start + span_end))
        position = body_end


def shown_lines(patch_text):
    """The lines a patch shows, as two {line number: text} dictionaries.

    The first holds the old side's deleted lines, the second the new side's
    added and context lines (the page marks a context line by the new file).
    Each hunk ends where its header's line counts say.
    """
    old_lines = {}
    new_lines = {}
    old_left = 0
    new_left = 0
    old_number = 0
    new_number = 0
    for line in patch_text.split("\n"):
        if old_left > 0 or new_left > 0:
            if line.startswith("\\"):
                continue  # "\ No newline at end of file"
            prefix = line[:1]
            if prefix == "-":
                old_lines[old_number] = line[1:]
                old_number += 1
                old_left -= 1
            elif prefix == "+":
                new_lines[new_number] = line[1:]
                new_number += 1
                new_left -= 1
            elif prefix == " " or line == "":
                new_lines[new_number] = line[1:]
                old_number += 1
                new_number += 1
                old_left -= 1
                new_left -= 1
            else:
                old_left = 0  # not a patch line: the page stops the hunk here too
                new_left = 0
            continue
        header = HUNK_HEADER.match(line)
        if header is not None:
            # A count left out of the header means one line.
            old_number = int(header.group(1))
            old_left = int(header.group(2)) if header.group(2) is not None else 1
            new_number = int(header.group(3))
            new_left = int(header.group(4)) if header.group(4) is not None else 1
    return old_lines, new_lines


def utf16_length(text):
    """The length of text as JavaScript counts it.

    JavaScript counts a character outside the Basic Multilingual Plane, such
    as most emoji, as two units; Python counts it as one.
    """
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def comment_ranges_for_lines(text, language, wanted_lines):
    """The comment ranges on the wanted lines of one side of the file.

    wanted_lines maps a line number to the text the patch shows for it. A
    line whose text differs from the file's (the file changed between the
    two reads) gets no ranges. Returns
    {line number as a string: [[start, end], ...]} in UTF-16 units.
    """
    if len(wanted_lines) == 0:
        return {}
    lines = text.split("\n")
    line_starts = []
    offset = 0
    for line in lines:
        line_starts.append(offset)
        offset += len(line) + 1
    ranges = {}
    for span_start, span_end in find_comment_spans(text, language):
        line_index = bisect.bisect_right(line_starts, span_start) - 1
        while line_index < len(lines) and line_starts[line_index] < span_end:
            line_number = line_index + 1
            line_text = lines[line_index]
            if wanted_lines.get(line_number) == line_text:
                piece_start = max(span_start - line_starts[line_index], 0)
                if span_start < line_starts[line_index]:
                    # a line inside a comment opened above: its indentation is not marked
                    piece_start = len(line_text) - len(line_text.lstrip())
                piece_end = min(span_end - line_starts[line_index], len(line_text))
                if piece_end > piece_start:
                    start_units = utf16_length(line_text[:piece_start])
                    end_units = start_units + utf16_length(line_text[piece_start:piece_end])
                    ranges.setdefault(str(line_number), []).append([start_units, end_units])
            line_index += 1
    return ranges


def find_patch_comments(path, patch_text, file_sides):
    """Where the comments are on the lines a patch shows, for /api/file?comments=1.

    file_sides is (old_text, new_text) from gitops.get_file_sides(), or None
    when the file is too large to read whole. Returns a dictionary:
      language  the language's name, or None when BranchLens does not know it
      note      a sentence for the page when no comments could be looked for
      old       {old line number: ranges} for the deleted lines
      new       {new line number: ranges} for the added and context lines
    A range is [start, end] in UTF-16 units, as JavaScript counts a string.
    """
    answer = {"language": None, "note": None, "old": {}, "new": {}}
    if file_sides is None:
        answer["note"] = "This file is too large for BranchLens to look for its comments."
        return answer
    old_text, new_text = file_sides
    if new_text != "":
        first_line = new_text[:line_end(new_text, 0)]
    else:
        first_line = old_text[:line_end(old_text, 0)]
    language = language_for(path, first_line)
    if language is None:
        answer["note"] = "BranchLens does not know how comments are written in this kind of file."
        return answer
    answer["language"] = language["name"]
    old_lines, new_lines = shown_lines(patch_text)
    answer["old"] = comment_ranges_for_lines(old_text, language, old_lines)
    answer["new"] = comment_ranges_for_lines(new_text, language, new_lines)
    return answer
