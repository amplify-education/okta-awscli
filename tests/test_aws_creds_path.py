"""Tests for AWS_SHARED_CREDENTIALS_FILE env-var support in AwsAuth."""

import os
import tempfile
import unittest
from configparser import ConfigParser
from unittest import mock

from tests._helpers import make_aws_auth


def _make_aws_auth(profile="test_profile"):
    return make_aws_auth(profile)


class TestCredsPathDefault(unittest.TestCase):
    """When AWS_SHARED_CREDENTIALS_FILE is unset, fall back to ~/.aws/credentials."""

    def setUp(self):
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        env = {"HOME": self.tempdir}
        # Ensure the override env var is not present.
        self.enterContext(mock.patch.dict(os.environ, env, clear=False))
        os.environ.pop("AWS_SHARED_CREDENTIALS_FILE", None)

    def test_creds_file_defaults_to_home_dot_aws_credentials(self):
        auth = _make_aws_auth()
        self.assertEqual(
            auth.creds_file, os.path.join(self.tempdir, ".aws", "credentials")
        )
        self.assertEqual(auth.creds_dir, os.path.join(self.tempdir, ".aws"))


class TestCredsPathEnvOverride(unittest.TestCase):
    """When AWS_SHARED_CREDENTIALS_FILE is set, AwsAuth uses it for reads and writes."""

    def setUp(self):
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.override_dir = os.path.join(self.tempdir, "custom", "aws")
        self.override_path = os.path.join(self.override_dir, "creds-file")
        self.enterContext(
            mock.patch.dict(
                os.environ,
                {
                    "HOME": self.tempdir,
                    "AWS_SHARED_CREDENTIALS_FILE": self.override_path,
                },
            )
        )

    def test_creds_file_honors_env_var(self):
        auth = _make_aws_auth()
        self.assertEqual(auth.creds_file, self.override_path)

    def test_creds_dir_is_derived_from_overridden_creds_file(self):
        """creds_dir must be the parent of the overridden creds_file, not ~/.aws."""
        auth = _make_aws_auth()
        self.assertEqual(auth.creds_dir, self.override_dir)
        self.assertNotEqual(auth.creds_dir, os.path.join(self.tempdir, ".aws"))

    def test_write_sts_token_writes_to_overridden_path(self):
        auth = _make_aws_auth(profile="p1")
        auth.write_sts_token("p1", "AKIA_X", "secret_X", "session_X")

        self.assertTrue(os.path.isfile(self.override_path))
        # Default ~/.aws/credentials should NOT have been created.
        self.assertFalse(
            os.path.exists(os.path.join(self.tempdir, ".aws", "credentials"))
        )

        config = ConfigParser()
        config.read(self.override_path)
        self.assertIn("p1", config.sections())
        self.assertEqual(config.get("p1", "aws_access_key_id"), "AKIA_X")
        self.assertEqual(config.get("p1", "aws_session_token"), "session_X")

    def test_write_sts_token_creates_parent_directory_for_overridden_path(self):
        """The override may point inside a directory tree that does not yet exist."""
        self.assertFalse(os.path.exists(self.override_dir))
        auth = _make_aws_auth(profile="p1")
        auth.write_sts_token("p1", "AKIA_X", "secret_X", "session_X")
        self.assertTrue(os.path.isdir(self.override_dir))

    def test_copy_to_default_uses_overridden_path(self):
        auth = _make_aws_auth(profile="source")
        auth.write_sts_token("source", "AKIA_SRC", "secret_SRC", "session_SRC")
        auth.copy_to_default("source")

        config = ConfigParser()
        config.read(self.override_path)
        self.assertIn("default", config.sections())
        self.assertEqual(config.get("default", "aws_access_key_id"), "AKIA_SRC")

    def test_check_sts_token_returns_false_when_overridden_file_missing(self):
        """check_sts_token must consult the overridden path, not ~/.aws/credentials."""
        # Seed a credentials file at the DEFAULT location to prove it's ignored.
        default_dir = os.path.join(self.tempdir, ".aws")
        os.makedirs(default_dir)
        with open(os.path.join(default_dir, "credentials"), "w") as f:
            f.write("[p1]\naws_access_key_id = AKIA_DEFAULT\n")

        auth = _make_aws_auth(profile="p1")
        # Override path does not exist; should short-circuit to False.
        self.assertFalse(auth.check_sts_token("p1"))


if __name__ == "__main__":
    unittest.main()
