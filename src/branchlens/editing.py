"""Reading and saving one file of a worktree, for the page's editor.

Apart from a push, this is the only place BranchLens writes. It writes files
of a checked-out branch only; no git command runs here and .git is never
touched.

read_editable_file() returns the file's text and a hash of its bytes.
save_editable_file() takes that hash back and refuses to save when the file
on disk no longer matches it, because someone else changed it meanwhile.
"""

import hashlib
import os
import stat
import tempfile

# Larger files are not opened in the editor.
MAX_EDIT_FILE_BYTES = 2 * 1024 * 1024


class EditRefused(Exception):
    """The file cannot be opened or saved; the message says why, for the page."""


class EditConflict(Exception):
    """The file changed on disk after the editor opened it."""


def hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def resolve_editable_path(worktree_path, path):
    """The absolute path of a file named relative to a worktree, checked for editing.

    path is the name the page shows, with "/" between folders. Refused: an
    absolute name, "..", ".", empty parts, anything inside a .git folder, a
    symbolic link anywhere along the way, and anything that is not an
    existing regular file.
    """
    if not isinstance(path, str) or path == "" or "\x00" in path or "\\" in path:
        raise EditRefused("This is not a file name BranchLens can edit.")
    if path.startswith("/"):
        raise EditRefused("Only files inside the worktree can be edited.")
    parts = path.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise EditRefused("Only files inside the worktree can be edited.")
        # macOS and Windows file systems ignore case, so .GIT is .git there.
        if part.lower() == ".git":
            raise EditRefused("Files inside .git cannot be edited.")

    # No folder along the way, and not the file itself, may be a symbolic link.
    current = worktree_path
    for part in parts:
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise EditRefused("Symbolic links cannot be edited, nor files reached through one.")
    full_path = current

    # The file must resolve to a place inside the worktree. Both sides are
    # resolved, since the worktree's own path may go through a link (/tmp on macOS).
    expected = os.path.join(os.path.realpath(worktree_path), *parts)
    if os.path.realpath(full_path) != expected:
        raise EditRefused("Only files inside the worktree can be edited.")

    if not os.path.exists(full_path):
        raise EditRefused("This file is not on disk in the branch's worktree.")
    if not os.path.isfile(full_path):
        raise EditRefused("This is not a regular file, so it cannot be edited.")
    return full_path


def read_file_bytes(full_path):
    """The bytes of a file, refusing one larger than MAX_EDIT_FILE_BYTES."""
    with open(full_path, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if size > MAX_EDIT_FILE_BYTES:
            raise EditRefused("This file is too large to edit here (over 2 MB).")
        # Read one byte more than the limit, in case the file grew meanwhile.
        data = handle.read(MAX_EDIT_FILE_BYTES + 1)
    if len(data) > MAX_EDIT_FILE_BYTES:
        raise EditRefused("This file is too large to edit here (over 2 MB).")
    return data


def decode_text(data):
    """The file's bytes as text, or EditRefused for a binary or non-UTF-8 file."""
    if b"\x00" in data:
        raise EditRefused("This looks like a binary file, so it cannot be edited as text.")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise EditRefused("This file is not UTF-8 text, so it cannot be edited here.")


def read_editable_file(worktree_path, path):
    """The file's text and the hash of its bytes, for opening it in the editor."""
    full_path = resolve_editable_path(worktree_path, path)
    data = read_file_bytes(full_path)
    text = decode_text(data)
    return {"path": path, "text": text, "sha256": hash_bytes(data)}


def save_editable_file(worktree_path, path, text, expected_sha256):
    """Write the editor's text over the file, if the file is still the one opened.

    Browsers send every line ending as "\\n"; a file that had "\\r\\n" endings
    gets them back. The text goes to a temporary file next to the original,
    which then replaces it in one step, keeping the original's permissions.
    """
    full_path = resolve_editable_path(worktree_path, path)
    old_data = read_file_bytes(full_path)
    if hash_bytes(old_data) != expected_sha256:
        raise EditConflict(
            "The file changed on disk after you opened it, so your text was not "
            "saved. Copy what you typed, then reopen the file."
        )
    decode_text(old_data)  # refuses to write over a binary file

    if b"\r\n" in old_data and "\r" not in text:
        text = text.replace("\n", "\r\n")
    new_data = text.encode("utf-8")
    if len(new_data) > MAX_EDIT_FILE_BYTES:
        raise EditRefused("The new text is too large to save here (over 2 MB).")

    old_mode = stat.S_IMODE(os.stat(full_path).st_mode)
    folder = os.path.dirname(full_path)
    handle, temporary_path = tempfile.mkstemp(
        dir=folder, prefix="." + os.path.basename(full_path) + ".", suffix=".branchlens-save"
    )
    try:
        with os.fdopen(handle, "wb") as temporary_file:
            temporary_file.write(new_data)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_path, old_mode)
        os.replace(temporary_path, full_path)
    except BaseException:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise
    return {"path": path, "sha256": hash_bytes(new_data), "saved": True}
