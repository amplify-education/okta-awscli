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


class _HomeIsolatedTestCase(unittest.TestCase):
    """Base class for tests that need an isolated $HOME pointing at a tempdir.

    Subclasses must call `super().setUp()` and `super().tearDown()` if they
    override either method. The tempdir path is available as `self.tempdir`.
    """

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self._real_home = os.environ.get("HOME")
        os.environ["HOME"] = self.tempdir

    def tearDown(self):
        if self._real_home is not None:
            os.environ["HOME"] = self._real_home
        else:
            os.environ.pop("HOME", None)
        shutil.rmtree(self.tempdir)


class TestWriteStsTokenLocking(_HomeIsolatedTestCase):
    """`AwsAuth.write_sts_token` acquires a lock on the credentials file."""

    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.tempdir, ".aws"))

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


class TestCopyToDefaultLocking(_HomeIsolatedTestCase):
    """`AwsAuth.copy_to_default` acquires a lock on the credentials file."""

    def setUp(self):
        super().setUp()
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


class TestGetRoleInfoLocking(_HomeIsolatedTestCase):
    """`AwsAuth.__get_role_info` acquires a lock on the okta-alias-info file."""

    def setUp(self):
        import json
        from datetime import date

        super().setUp()
        os.makedirs(os.path.join(self.tempdir, ".aws"))

        # Pre-populate fresh cached aliases so the AWS-call branch is skipped.
        info_path = os.path.join(self.tempdir, ".okta-alias-info")
        with open(info_path, "w") as f:
            json.dump(
                {
                    "arn:aws:iam::111:role/r1": {
                        "alias": "acct-one",
                        "last_updated": date.today().isoformat(),
                    },
                    "arn:aws:iam::222:role/r2": {
                        "alias": "acct-two",
                        "last_updated": date.today().isoformat(),
                    },
                },
                f,
                default=str,
            )
        self.info_path = info_path

    def test_acquires_lock_on_alias_info_file(self):
        from collections import namedtuple
        import logging
        from unittest import mock

        from oktaawscli.aws_auth import AwsAuth
        from oktaawscli import _locking as locking_module

        RoleTuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
        roles = [
            RoleTuple("arn:aws:iam::111:saml-provider/p", "arn:aws:iam::111:role/r1"),
            RoleTuple("arn:aws:iam::222:saml-provider/p", "arn:aws:iam::222:role/r2"),
        ]
        auth = AwsAuth(
            profile="test",
            okta_profile="default",
            account=None,
            verbose=False,
            logger=logging.getLogger("test"),
            region="us-east-1",
            reset=False,
        )

        with mock.patch(
            "oktaawscli.aws_auth.locked", wraps=locking_module.locked
        ) as mock_locked:
            # Name-mangled access to the private method.
            auth._AwsAuth__get_role_info(roles, b"unused-because-cache-is-fresh")

        mock_locked.assert_called_once_with(self.info_path)

    def test_lock_is_held_across_get_account_alias_call(self):
        """The lock spans __get_account_alias so parallel runs serialize cold-cache fetches."""
        import json
        import logging
        from collections import namedtuple
        from unittest import mock

        from filelock import Timeout

        from oktaawscli import _locking as locking_module
        from oktaawscli.aws_auth import AwsAuth

        # Overwrite setUp's fresh entries with a STALE one to force the AWS branch.
        with open(self.info_path, "w") as f:
            json.dump(
                {
                    "arn:aws:iam::333:role/r3": {
                        "alias": "old-alias",
                        "last_updated": "2000-01-01",
                    },
                },
                f,
                default=str,
            )

        RoleTuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
        roles = [
            RoleTuple("arn:aws:iam::333:saml-provider/p", "arn:aws:iam::333:role/r3"),
        ]
        auth = AwsAuth(
            profile="test",
            okta_profile="default",
            account=None,
            verbose=False,
            logger=logging.getLogger("test"),
            region="us-east-1",
            reset=False,
        )

        timed_out = []

        def fake_alias(*args, **kwargs):
            # Inside __get_role_info's locked block; try to grab the same lock.
            # If the outer lock is held, this attempt times out — proof of invariant.
            try:
                with locking_module.locked(self.info_path, timeout=0.2):
                    timed_out.append(False)
            except Timeout:
                timed_out.append(True)
            return "fresh-alias"

        with mock.patch.object(
            auth, "_AwsAuth__get_account_alias", side_effect=fake_alias
        ):
            result = auth._AwsAuth__get_role_info(roles, b"unused")

        self.assertEqual(timed_out, [True])
        self.assertEqual(
            result,
            [
                (
                    "arn:aws:iam::333:role/r3",
                    "arn:aws:iam::333:saml-provider/p",
                    "fresh-alias",
                )
            ],
        )


class TestSaveConfigValueMerge(_HomeIsolatedTestCase):
    """`OktaAuthConfig._save_config_value` merges concurrent saves instead of overwriting."""

    def setUp(self):
        super().setUp()
        # Seed the okta-aws config so both instances see the same baseline.
        config_path = os.path.join(self.tempdir, ".okta-aws")
        with open(config_path, "w") as f:
            f.write("[default]\nbase-url = example.okta.com\n")
        self.config_path = config_path

    def test_two_instances_saving_different_keys_both_persist(self):
        import logging
        from configparser import ConfigParser

        from oktaawscli.okta_auth_config import OktaAuthConfig

        logger = logging.getLogger("test")
        # Two instances both read the same baseline at construction.
        config_a = OktaAuthConfig(logger=logger, reset=False)
        config_b = OktaAuthConfig(logger=logger, reset=False)

        # A saves a role; B's in-memory state is now stale relative to disk.
        config_a.save_chosen_role_for_profile("default", "arn:aws:iam::111:role/role_a")
        # B saves a factor — must merge with A's role on disk, not clobber it.
        config_b.save_chosen_factor_for_profile("default", "push")

        parser = ConfigParser(default_section="default")
        parser.read(self.config_path)
        self.assertEqual(parser.get("default", "role"), "arn:aws:iam::111:role/role_a")
        self.assertEqual(parser.get("default", "factor"), "push")
        self.assertEqual(parser.get("default", "base-url"), "example.okta.com")
