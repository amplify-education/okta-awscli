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


def _child_write_sts(home_dir, profile_name):
    """Subprocess entry: set HOME, build AwsAuth, call write_sts_token."""
    import logging

    os.environ["HOME"] = home_dir
    from oktaawscli.aws_auth import AwsAuth

    auth = AwsAuth(
        profile=profile_name,
        okta_profile="default",
        account=None,
        verbose=False,
        logger=logging.getLogger(profile_name),
        region="us-east-1",
        reset=False,
    )
    auth.write_sts_token(
        profile_name, "AKIA_TEST", "secret_TEST", "session_TEST",
    )


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


class TestWriteStsTokenLocking(unittest.TestCase):
    """`AwsAuth.write_sts_token` acquires a lock on the credentials file."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self._real_home = os.environ.get("HOME")
        os.environ["HOME"] = self.tempdir
        os.makedirs(os.path.join(self.tempdir, ".aws"))

    def tearDown(self):
        if self._real_home is not None:
            os.environ["HOME"] = self._real_home
        else:
            os.environ.pop("HOME", None)
        shutil.rmtree(self.tempdir)

    def _make_auth(self):
        import logging

        from oktaawscli.aws_auth import AwsAuth

        return AwsAuth(
            profile="test_profile",
            okta_profile="default",
            account=None,
            verbose=False,
            logger=logging.getLogger("test"),
            region="us-east-1",
            reset=False,
        )

    def test_acquires_lock_on_credentials_file(self):
        from unittest import mock

        from oktaawscli import _locking as locking_module

        auth = self._make_auth()
        with mock.patch(
            "oktaawscli.aws_auth.locked", wraps=locking_module.locked
        ) as mock_locked:
            auth.write_sts_token(
                "test_profile", "AKIA_TEST", "secret_TEST", "session_TEST",
            )
        mock_locked.assert_called_once_with(auth.creds_file)

    def test_two_parallel_writes_preserve_both_profiles(self):
        from configparser import ConfigParser

        ctx = multiprocessing.get_context("fork")
        procs = [
            ctx.Process(target=_child_write_sts, args=(self.tempdir, f"profile_{i}"))
            for i in range(2)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
        for p in procs:
            self.assertEqual(p.exitcode, 0, f"child exited {p.exitcode}")

        config = ConfigParser()
        config.read(os.path.join(self.tempdir, ".aws", "credentials"))
        self.assertIn("profile_0", config.sections())
        self.assertIn("profile_1", config.sections())
        self.assertEqual(config.get("profile_0", "aws_access_key_id"), "AKIA_TEST")
        self.assertEqual(config.get("profile_1", "aws_access_key_id"), "AKIA_TEST")


class TestCopyToDefaultLocking(unittest.TestCase):
    """`AwsAuth.copy_to_default` acquires a lock on the credentials file."""

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self._real_home = os.environ.get("HOME")
        os.environ["HOME"] = self.tempdir
        os.makedirs(os.path.join(self.tempdir, ".aws"))
        # Pre-populate a profile so copy_to_default has something to copy
        creds_path = os.path.join(self.tempdir, ".aws", "credentials")
        with open(creds_path, "w") as f:
            f.write(
                "[source]\n"
                "output = json\n"
                "region = us-east-1\n"
                "aws_access_key_id = AKIA_SRC\n"
                "aws_secret_access_key = secret_SRC\n"
                "aws_session_token = session_SRC\n"
                "aws_security_token = session_SRC\n"
            )

    def tearDown(self):
        if self._real_home is not None:
            os.environ["HOME"] = self._real_home
        else:
            os.environ.pop("HOME", None)
        shutil.rmtree(self.tempdir)

    def _make_auth(self):
        import logging

        from oktaawscli.aws_auth import AwsAuth

        return AwsAuth(
            profile="source",
            okta_profile="default",
            account=None,
            verbose=False,
            logger=logging.getLogger("test"),
            region="us-east-1",
            reset=False,
        )

    def test_acquires_lock_on_credentials_file(self):
        from configparser import ConfigParser
        from unittest import mock

        from oktaawscli import _locking as locking_module

        auth = self._make_auth()
        with mock.patch(
            "oktaawscli.aws_auth.locked", wraps=locking_module.locked
        ) as mock_locked:
            auth.copy_to_default("source")

        mock_locked.assert_called_once_with(auth.creds_file)
        config = ConfigParser()
        config.read(os.path.join(self.tempdir, ".aws", "credentials"))
        self.assertEqual(config.get("default", "aws_access_key_id"), "AKIA_SRC")

    def test_creates_default_section_when_missing(self):
        """copy_to_default works against a file lacking a pre-existing [default] section."""
        from configparser import ConfigParser

        auth = self._make_auth()
        # The setUp credentials file has only [source], no [default] — verify that.
        pre = ConfigParser()
        pre.read(os.path.join(self.tempdir, ".aws", "credentials"))
        self.assertNotIn("default", pre.sections())

        auth.copy_to_default("source")

        config = ConfigParser()
        config.read(os.path.join(self.tempdir, ".aws", "credentials"))
        self.assertIn("default", config.sections())
        self.assertEqual(config.get("default", "aws_access_key_id"), "AKIA_SRC")
        self.assertEqual(config.get("default", "aws_security_token"), "session_SRC")
