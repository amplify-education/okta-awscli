"""Cross-process advisory locking and atomic writes for dotfiles."""

import os
import tempfile
from contextlib import contextmanager

from filelock import FileLock

LOCK_TIMEOUT_SECONDS = 60
INTERACTIVE_LOCK_TIMEOUT_SECONDS = 300


def locked(path, timeout=LOCK_TIMEOUT_SECONDS):
    """Return a FileLock guarding `path`, using `<path>.lock` as the lock file."""
    return FileLock(f"{path}.lock", timeout=timeout)


@contextmanager
def atomic_write(path):
    """Yield a write file handle that replaces `path` atomically on clean exit.

    The temp file is created next to `path` so the final rename stays on the
    same filesystem (POSIX guarantees same-FS rename is atomic). If the with
    block raises, the temp file is removed and `path` is left untouched.
    """
    parent = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(
        dir=parent,
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w") as tmp:
            yield tmp
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
