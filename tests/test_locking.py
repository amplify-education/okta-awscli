"""Tests for oktaawscli._locking."""
import multiprocessing
import os
import shutil
import tempfile
import time
import unittest


def _hold_lock(lock_file_path, ready_path, hold_seconds):
    """Subprocess entry: acquire lock, signal ready by touching `ready_path`, hold."""
    from filelock import FileLock

    with FileLock(lock_file_path):
        open(ready_path, "w").close()
        time.sleep(hold_seconds)


class TestLockedHelper(unittest.TestCase):
    """Tests for `locked(path, timeout=...)`."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.target = os.path.join(self.tempdir, "data.txt")

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_returns_FileLock_pointed_at_path_dot_lock(self):
        from filelock import FileLock

        from oktaawscli._locking import locked

        result = locked(self.target)

        self.assertIsInstance(result, FileLock)
        self.assertEqual(str(result.lock_file), self.target + ".lock")

    def test_default_timeout_is_60_seconds(self):
        from oktaawscli._locking import LOCK_TIMEOUT_SECONDS, locked

        self.assertEqual(LOCK_TIMEOUT_SECONDS, 60)
        self.assertEqual(locked(self.target).timeout, 60)

    def test_accepts_custom_timeout(self):
        from oktaawscli._locking import locked

        self.assertEqual(locked(self.target, timeout=5).timeout, 5)


class TestLockingTimeout(unittest.TestCase):
    """`locked()` raises filelock.Timeout when another process holds the lock."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_raises_Timeout_when_lock_held_by_another_process(self):
        from filelock import Timeout

        from oktaawscli._locking import locked

        target = os.path.join(self.tempdir, "data.txt")
        ready = os.path.join(self.tempdir, "ready")
        ctx = multiprocessing.get_context("fork")
        proc = ctx.Process(target=_hold_lock, args=(target + ".lock", ready, 3))
        proc.start()
        try:
            deadline = time.time() + 5
            while not os.path.exists(ready):
                if time.time() > deadline:
                    self.fail("child process never signaled ready")
                time.sleep(0.05)

            with self.assertRaises(Timeout):
                with locked(target, timeout=0.5):
                    pass
        finally:
            proc.join(10)


class TestAtomicWrite(unittest.TestCase):
    """`atomic_write(path)` replaces `path` only if the with-block exits cleanly."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.target = os.path.join(self.tempdir, "data.txt")

    def tearDown(self):
        shutil.rmtree(self.tempdir)

    def test_replaces_target_on_clean_exit(self):
        from oktaawscli._locking import atomic_write

        with atomic_write(self.target) as f:
            f.write("new content")

        with open(self.target) as f:
            self.assertEqual(f.read(), "new content")

    def test_preserves_existing_content_when_writer_raises(self):
        from oktaawscli._locking import atomic_write

        with open(self.target, "w") as f:
            f.write("original")

        with self.assertRaises(RuntimeError):
            with atomic_write(self.target) as f:
                f.write("partial")
                raise RuntimeError("boom")

        with open(self.target) as f:
            self.assertEqual(f.read(), "original")

    def test_does_not_leave_temp_files_behind_on_failure(self):
        from oktaawscli._locking import atomic_write

        with self.assertRaises(RuntimeError):
            with atomic_write(self.target) as f:
                f.write("partial")
                raise RuntimeError("boom")

        leftovers = [n for n in os.listdir(self.tempdir) if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])
