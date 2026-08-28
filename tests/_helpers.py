"""Shared test helpers (not collected by unittest discovery — leading underscore)."""

import logging
import os
import tempfile
import unittest
from unittest import mock


def make_aws_auth(profile, *, okta_profile="default", region="us-east-1"):
    """Construct an AwsAuth wired for tests against the current $HOME."""
    from oktaawscli.aws_auth import AwsAuth

    return AwsAuth(
        profile=profile,
        okta_profile=okta_profile,
        account=None,
        verbose=False,
        logger=logging.getLogger("test"),
        region=region,
        reset=False,
    )


class HomeIsolatedTestCase(unittest.TestCase):
    """Base class for tests needing an isolated $HOME. Provides `self.tempdir`."""

    def setUp(self):
        self.tempdir = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(mock.patch.dict(os.environ, {"HOME": self.tempdir}))

    def _make_okta_auth(self):
        """Build a minimally-wired OktaAuth bypassing __init__ for unit tests."""
        from oktaawscli.okta_auth import OktaAuth

        auth = OktaAuth.__new__(OktaAuth)
        auth.logger = logging.getLogger("test")
        auth.https_base_url = "https://example.okta.com"
        auth.app = None
        auth.okta_auth_config = None
        auth.okta_profile = "default"
        auth.totp_token = None
        auth.factor_id = None
        auth.legacy_factor_provider = None
        auth.had_legacy_factor_key = False
        auth.reset_factor = False
        auth.verbose = False
        auth.debug = False
        auth.token_path = os.path.join(self.tempdir, ".okta-token")
        return auth

    def _make_aws_auth(self, profile):
        """Build a real AwsAuth pointed at the isolated $HOME."""
        return make_aws_auth(profile)
