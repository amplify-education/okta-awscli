"""Tests for oktaawscli._locking."""
import multiprocessing
import os
import tempfile
import time
import unittest
from unittest import mock


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


class TestLockingTimeout(unittest.TestCase):
    """`locked()` raises filelock.Timeout when another process holds the lock."""

    def setUp(self):
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())

    def test_raises_timeout_when_lock_held_by_another_process(self):
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
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.target = os.path.join(self.tempdir, "data.txt")

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
    """Base class for tests needing an isolated $HOME. Provides `self.tempdir`."""

    def setUp(self):
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(mock.patch.dict(os.environ, {"HOME": self.tempdir}))

    def _make_okta_auth(self):
        """Build a minimally-wired OktaAuth bypassing __init__ for unit tests."""
        import logging
        from oktaawscli.okta_auth import OktaAuth

        auth = OktaAuth.__new__(OktaAuth)
        auth.logger = logging.getLogger("test")
        auth.https_base_url = "https://example.okta.com"
        auth.app = None
        auth.okta_auth_config = None
        auth.okta_profile = "default"
        auth.totp_token = None
        auth.factor = ""
        auth.verbose = False
        auth.debug = False
        auth.token_path = os.path.join(self.tempdir, ".okta-token")
        return auth

    def _make_aws_auth(self, profile):
        """Build a real AwsAuth pointed at the isolated $HOME."""
        import logging
        from oktaawscli.aws_auth import AwsAuth

        return AwsAuth(
            profile=profile,
            okta_profile="default",
            account=None,
            verbose=False,
            logger=logging.getLogger("test"),
            region="us-east-1",
            reset=False,
        )


class TestWriteStsTokenLocking(_HomeIsolatedTestCase):
    """`AwsAuth.write_sts_token` acquires a lock on the credentials file."""

    def setUp(self):
        super().setUp()
        os.makedirs(os.path.join(self.tempdir, ".aws"))

    def test_acquires_lock_on_credentials_file(self):
        from oktaawscli import _locking as locking_module

        auth = self._make_aws_auth("test_profile")
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

    def test_acquires_lock_on_credentials_file(self):
        from configparser import ConfigParser

        from oktaawscli import _locking as locking_module

        auth = self._make_aws_auth("source")
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

        auth = self._make_aws_auth("source")
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

        from oktaawscli import _locking as locking_module

        RoleTuple = namedtuple("RoleTuple", ["principal_arn", "role_arn"])
        roles = [
            RoleTuple("arn:aws:iam::111:saml-provider/p", "arn:aws:iam::111:role/r1"),
            RoleTuple("arn:aws:iam::222:saml-provider/p", "arn:aws:iam::222:role/r2"),
        ]
        auth = self._make_aws_auth("test")

        with mock.patch(
            "oktaawscli.aws_auth.locked", wraps=locking_module.locked
        ) as mock_locked:
            auth._AwsAuth__get_role_info(roles, b"unused-because-cache-is-fresh")

        mock_locked.assert_called_once_with(self.info_path)

    def test_lock_is_held_across_get_account_alias_call(self):
        """The lock spans __get_account_alias so parallel runs serialize cold-cache fetches."""
        import json
        from collections import namedtuple

        from filelock import Timeout

        from oktaawscli import _locking as locking_module

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
        auth = self._make_aws_auth("test")

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
        config_a = OktaAuthConfig(logger=logger, reset=False)
        config_b = OktaAuthConfig(logger=logger, reset=False)

        config_a.save_chosen_role_for_profile("default", "arn:aws:iam::111:role/role_a")
        config_b.save_chosen_factor_for_profile("default", "push")

        parser = ConfigParser(default_section="default")
        parser.read(self.config_path)
        self.assertEqual(parser.get("default", "role"), "arn:aws:iam::111:role/role_a")
        self.assertEqual(parser.get("default", "factor"), "push")
        self.assertEqual(parser.get("default", "base-url"), "example.okta.com")


class TestCacheSessionIdAtomicWrite(_HomeIsolatedTestCase):
    """`OktaAuth.cache_session_id` writes ~/.okta-token atomically."""

    def test_writes_session_id_atomically_on_clean_exit(self):
        import json

        auth = self._make_okta_auth()
        auth.cache_session_id("sess_abc", "2099-01-01T00:00:00.000Z")

        token_path = os.path.join(self.tempdir, ".okta-token")
        with open(token_path) as f:
            data = json.load(f)
        self.assertEqual(data["session_id"], "sess_abc")
        self.assertEqual(data["expiration_date"], "2099-01-01T00:00:00.000Z")

    def test_preserves_existing_token_when_writer_raises(self):
        from unittest import mock

        token_path = os.path.join(self.tempdir, ".okta-token")
        with open(token_path, "w") as f:
            f.write('{"session_id": "original", "expiration_date": "2099-01-01T00:00:00.000Z"}')

        auth = self._make_okta_auth()
        with mock.patch("oktaawscli.okta_auth.json.dumps", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                auth.cache_session_id("new_sess", "2099-01-01T00:00:00.000Z")

        with open(token_path) as f:
            self.assertIn("original", f.read())


class TestCliTimeoutHandling(unittest.TestCase):
    """The CLI catches filelock.Timeout and exits with a friendly message."""

    def test_filelock_timeout_produces_friendly_error_and_exit_1(self):
        from unittest import mock

        from click.testing import CliRunner
        from filelock import Timeout

        from oktaawscli.okta_awscli import main

        runner = CliRunner()
        with mock.patch(
            "oktaawscli.okta_awscli.get_credentials",
            side_effect=Timeout("/tmp/.aws/credentials.lock"),
        ):
            result = runner.invoke(main, ["--profile", "p"])

        self.assertEqual(result.exit_code, 1)
        self.assertIn("/tmp/.aws/credentials.lock", result.output)
        self.assertNotIn("Traceback", result.output)


class TestOktaApiErrorHandling(_HomeIsolatedTestCase):
    """Okta API call sites handle error responses with clear messages, not TypeError."""

    def test_get_apps_exits_cleanly_on_error_response(self):
        from unittest import mock

        auth = self._make_okta_auth()
        error_response = {
            "errorCode": "E0000011",
            "errorSummary": "Invalid token provided",
            "errorLink": "E0000011",
            "errorId": "oae123",
            "errorCauses": [],
        }
        mock_resp = mock.MagicMock()
        mock_resp.json.return_value = error_response
        mock_resp.status_code = 401
        with mock.patch("oktaawscli.okta_auth.requests.request", return_value=mock_resp):
            with self.assertRaises(SystemExit) as cm:
                auth.get_apps("stale_sid")
        self.assertEqual(cm.exception.code, 1)

    def test_get_session_exits_cleanly_on_error_response(self):
        from unittest import mock

        auth = self._make_okta_auth()
        error_response = {
            "errorCode": "E0000004",
            "errorSummary": "Authentication failed",
            "errorLink": "E0000004",
            "errorId": "oae456",
            "errorCauses": [],
        }
        mock_resp = mock.MagicMock()
        mock_resp.json.return_value = error_response
        mock_resp.status_code = 401
        with mock.patch("oktaawscli.okta_auth.requests.request", return_value=mock_resp):
            with self.assertRaises(SystemExit) as cm:
                auth.get_session("bad_session_token")
        self.assertEqual(cm.exception.code, 1)


class TestPrimaryAuthLocking(_HomeIsolatedTestCase):
    """`OktaAuth.primary_auth` locks the auth flow so parallel runs serialize."""

    def test_fast_path_skips_lock_when_cached_session_valid(self):
        from unittest import mock

        auth = self._make_okta_auth()
        with mock.patch.object(auth, "get_cached_session_id", return_value="cached_sid"), \
             mock.patch.object(auth, "check_for_desync", return_value=False), \
             mock.patch("oktaawscli.okta_auth.locked") as mock_locked:
            result = auth.primary_auth()
        self.assertEqual(result, "cached_sid")
        mock_locked.assert_not_called()

    def test_slow_path_acquires_lock_when_cache_is_empty(self):
        from unittest import mock

        from oktaawscli import _locking as locking_module
        from oktaawscli._locking import INTERACTIVE_LOCK_TIMEOUT_SECONDS

        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        auth.okta_auth_config.username_for.return_value = "user"
        auth.okta_auth_config.password_for.return_value = "pw"

        fake_resp = mock.MagicMock()
        fake_resp.json.return_value = {"status": "SUCCESS", "sessionToken": "stoken"}
        fake_resp.status_code = 200

        with mock.patch.object(auth, "get_cached_session_id", return_value=None), \
             mock.patch.object(auth, "get_session", return_value="fresh_sid") as mock_get_session, \
             mock.patch(
                 "oktaawscli.okta_auth.locked",
                 wraps=locking_module.locked,
             ) as mock_locked, \
             mock.patch("oktaawscli.okta_auth.requests.request", return_value=fake_resp):
            result = auth.primary_auth()

        self.assertEqual(result, "fresh_sid")
        mock_locked.assert_called_once_with(
            auth.token_path, timeout=INTERACTIVE_LOCK_TIMEOUT_SECONDS
        )
        mock_get_session.assert_called_once_with("stoken")

    def test_slow_path_uses_session_refreshed_by_peer_while_waiting(self):
        """If another process refreshed the cached session while we waited for the lock, use it."""
        from unittest import mock

        from oktaawscli import _locking as locking_module
        from oktaawscli._locking import INTERACTIVE_LOCK_TIMEOUT_SECONDS

        auth = self._make_okta_auth()
        with mock.patch.object(
                auth, "get_cached_session_id", side_effect=[None, "peer_refreshed_sid"],
             ) as mock_get_cached, \
             mock.patch.object(auth, "check_for_desync") as mock_desync, \
             mock.patch(
                 "oktaawscli.okta_auth.locked",
                 wraps=locking_module.locked,
             ) as mock_locked, \
             mock.patch("oktaawscli.okta_auth.requests.request") as mock_post:
            result = auth.primary_auth()

        self.assertEqual(result, "peer_refreshed_sid")
        mock_locked.assert_called_once_with(
            auth.token_path, timeout=INTERACTIVE_LOCK_TIMEOUT_SECONDS
        )
        self.assertEqual(mock_get_cached.call_count, 2)
        mock_post.assert_not_called()
        mock_desync.assert_not_called()


class TestOktaRateLimitRetry(_HomeIsolatedTestCase):
    """Okta API call sites retry on E0000047 with backoff before exiting."""

    def _rate_limit_response(self):
        from unittest import mock

        resp = mock.MagicMock()
        resp.json.return_value = {
            "errorCode": "E0000047",
            "errorSummary": "API call exceeded rate limit due to too many requests.",
            "errorId": "oae_rate_limit",
        }
        resp.status_code = 429
        return resp

    def _success_apps_response(self):
        from unittest import mock

        resp = mock.MagicMock()
        resp.json.return_value = [
            {
                "appName": "amazon_aws",
                "label": "AWS Prod",
                "linkUrl": "https://example.okta.com/aws-prod",
                "sortOrder": 1,
            }
        ]
        resp.status_code = 200
        return resp

    def test_get_apps_retries_on_rate_limit_then_succeeds(self):
        from unittest import mock

        auth = self._make_okta_auth()
        # Pre-select the app so get_apps doesn't prompt for input.
        auth.app = "AWS Prod"

        responses = [
            self._rate_limit_response(),
            self._rate_limit_response(),
            self._success_apps_response(),
        ]

        with mock.patch("oktaawscli.okta_auth.requests.request", side_effect=responses) as mock_get, \
             mock.patch("oktaawscli.okta_auth.time.sleep") as mock_sleep:
            label, link = auth.get_apps("sid")

        self.assertEqual(label, "AWS Prod")
        self.assertEqual(link, "https://example.okta.com/aws-prod")
        self.assertEqual(mock_get.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)

    def test_get_apps_exits_after_exhausting_retries(self):
        from unittest import mock

        auth = self._make_okta_auth()
        auth.app = "AWS Prod"

        with mock.patch(
                "oktaawscli.okta_auth.requests.request",
                return_value=self._rate_limit_response(),
             ) as mock_get, \
             mock.patch("oktaawscli.okta_auth.time.sleep"):
            with self.assertRaises(SystemExit) as cm:
                auth.get_apps("sid")

        self.assertEqual(cm.exception.code, 1)
        from oktaawscli.okta_auth import MAX_OKTA_RATE_LIMIT_RETRIES
        self.assertEqual(mock_get.call_count, MAX_OKTA_RATE_LIMIT_RETRIES)

    def test_get_session_retries_on_rate_limit_then_succeeds(self):
        from unittest import mock

        auth = self._make_okta_auth()
        success = mock.MagicMock()
        success.json.return_value = {
            "id": "fresh_sid",
            "expiresAt": "2099-01-01T00:00:00.000Z",
        }
        success.status_code = 200

        responses = [self._rate_limit_response(), success]

        with mock.patch("oktaawscli.okta_auth.requests.request", side_effect=responses) as mock_post, \
             mock.patch.object(auth, "cache_session_id"), \
             mock.patch("oktaawscli.okta_auth.time.sleep"):
            sid = auth.get_session("stoken")

        self.assertEqual(sid, "fresh_sid")
        self.assertEqual(mock_post.call_count, 2)

    def test_non_rate_limit_error_exits_without_retry(self):
        """Non-E0000047 errors should not trigger the retry loop."""
        from unittest import mock

        auth = self._make_okta_auth()
        non_rate_limit_resp = mock.MagicMock()
        non_rate_limit_resp.json.return_value = {
            "errorCode": "E0000011",
            "errorSummary": "Invalid token provided",
            "errorId": "oae_invalid",
        }
        non_rate_limit_resp.status_code = 401

        with mock.patch(
                "oktaawscli.okta_auth.requests.request",
                return_value=non_rate_limit_resp,
             ) as mock_get, \
             mock.patch("oktaawscli.okta_auth.time.sleep") as mock_sleep:
            with self.assertRaises(SystemExit):
                auth.get_apps("sid")

        self.assertEqual(mock_get.call_count, 1)
        mock_sleep.assert_not_called()
