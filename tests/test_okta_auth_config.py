"""Tests for oktaawscli.okta_auth_config MFA factor-id storage."""

import logging
import os
from configparser import ConfigParser

from tests._helpers import HomeIsolatedTestCase


class TestFactorIdFor(HomeIsolatedTestCase):
    """`OktaAuthConfig.factor_id_for` reads the `factor-id` key."""

    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.tempdir, ".okta-aws")

    def _write_config(self, body):
        with open(self.config_path, "w") as f:
            f.write(body)

    def test_returns_none_when_unset(self):
        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        self.assertIsNone(config.factor_id_for("default"))

    def test_returns_stored_value(self):
        self._write_config("[default]\nfactor-id = opf1dee51odtET6AO2p8\n")
        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        self.assertEqual(config.factor_id_for("default"), "opf1dee51odtET6AO2p8")

    def test_returns_none_when_reset(self):
        self._write_config("[default]\nfactor-id = opf1dee51odtET6AO2p8\n")
        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=True)
        self.assertIsNone(config.factor_id_for("default"))

    def test_returns_none_when_reset_factor(self):
        self._write_config("[default]\nfactor-id = opf1dee51odtET6AO2p8\n")
        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False, reset_factor=True)
        self.assertIsNone(config.factor_id_for("default"))


class TestFactorForResetFactor(HomeIsolatedTestCase):
    """`--reset-factor` also forces the legacy `factor` getter to None, so a forced
    re-prompt can't be short-circuited by the provider-based migration path."""

    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.tempdir, ".okta-aws")

    def test_legacy_factor_for_returns_none_when_reset_factor(self):
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = OKTA\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False, reset_factor=True)
        self.assertIsNone(config.factor_for("default"))


class TestSaveChosenFactorIdForProfile(HomeIsolatedTestCase):
    """`OktaAuthConfig.save_chosen_factor_id_for_profile` writes `factor-id`."""

    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.tempdir, ".okta-aws")

    def test_writes_factor_id_key_without_touching_legacy_factor_key(self):
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = OKTA\nbase-url = example.okta.com\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        config.save_chosen_factor_id_for_profile("default", "opf1dee51odtET6AO2p8")

        parser = ConfigParser(default_section="default")
        parser.read(self.config_path)
        self.assertEqual(parser.get("default", "factor-id"), "opf1dee51odtET6AO2p8")
        self.assertEqual(parser.get("default", "factor"), "OKTA")
        self.assertEqual(parser.get("default", "base-url"), "example.okta.com")

    def test_provider_kwarg_updates_legacy_factor_key_too(self):
        """When a provider is supplied, both the new factor-id key and the
        legacy factor key get written -- so an older okta-awscli reading the
        same config file (or a config-tool round-trip) sees a consistent
        choice, not a stale provider next to a fresh id."""
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = GOOGLE\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        config.save_chosen_factor_id_for_profile("default", "opfNewPush123", provider="OKTA")

        parser = ConfigParser(default_section="default")
        parser.read(self.config_path)
        self.assertEqual(parser.get("default", "factor-id"), "opfNewPush123")
        self.assertEqual(parser.get("default", "factor"), "OKTA")

    def test_omitting_provider_leaves_legacy_factor_key_untouched(self):
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = GOOGLE\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        config.save_chosen_factor_id_for_profile("default", "opfNewPush123")

        parser = ConfigParser(default_section="default")
        parser.read(self.config_path)
        self.assertEqual(parser.get("default", "factor-id"), "opfNewPush123")
        self.assertEqual(parser.get("default", "factor"), "GOOGLE")


class TestFactorKeyExistsFor(HomeIsolatedTestCase):
    """`factor_key_exists_for` is a raw, reset-independent check -- unlike
    `factor_for`, it must not be suppressed by --reset/--reset-factor, since
    it's used to decide whether to keep an existing legacy key in sync."""

    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.tempdir, ".okta-aws")

    def test_true_when_factor_key_present(self):
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = OKTA\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        self.assertTrue(config.factor_key_exists_for("default"))

    def test_false_when_factor_key_absent(self):
        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False)
        self.assertFalse(config.factor_key_exists_for("default"))

    def test_true_under_reset_factor_when_key_present(self):
        """The whole point: unlike factor_for, reset_factor must not mask this."""
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = OKTA\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False, reset_factor=True)
        self.assertTrue(config.factor_key_exists_for("default"))

    def test_true_under_reset_when_key_present(self):
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = OKTA\n")

        from oktaawscli.okta_auth_config import OktaAuthConfig

        config = OktaAuthConfig(logger=logging.getLogger("test"), reset=True)
        self.assertTrue(config.factor_key_exists_for("default"))


class TestResetFactorPreservesLegacySync(HomeIsolatedTestCase):
    """End-to-end repro of the adversarial-review finding: under
    --reset-factor, a profile that already has a legacy `factor` value must
    still get that value re-synced to the newly chosen factor, not left
    stale next to a freshly-written factor-id."""

    def setUp(self):
        super().setUp()
        self.config_path = os.path.join(self.tempdir, ".okta-aws")
        with open(self.config_path, "w") as f:
            f.write("[default]\nfactor = OKTA\nbase-url = example.okta.com\nusername = jdoe\n")

    def test_reset_factor_resyncs_existing_legacy_key_to_new_choice(self):
        from unittest import mock

        from oktaawscli.okta_auth import OktaAuth
        from oktaawscli.okta_auth_config import OktaAuthConfig

        okta_auth_config = OktaAuthConfig(logger=logging.getLogger("test"), reset=False, reset_factor=True)
        auth = OktaAuth("default", False, logging.getLogger("test"), None, okta_auth_config)

        factors = [
            {
                "id": "google_totp",
                "factorType": "token:software:totp",
                "provider": "GOOGLE",
                "profile": {"credentialId": "jdoe"},
                "_links": {"verify": {"href": "https://example.okta.com/verify/google_totp"}},
            },
            {
                "id": "okta_push",
                "factorType": "push",
                "provider": "OKTA",
                "profile": {"credentialId": "jdoe"},
                "_links": {"verify": {"href": "https://example.okta.com/verify/okta_push"}},
            },
        ]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1"),
        ):
            auth.verify_mfa(factors, "state_tok")

        parser = ConfigParser(default_section="default")
        parser.read(self.config_path)
        self.assertEqual(parser.get("default", "factor-id"), "google_totp")
        # Must be re-synced to the newly chosen provider, not left at the
        # stale "OKTA" value from before this run.
        self.assertEqual(parser.get("default", "factor"), "GOOGLE")
