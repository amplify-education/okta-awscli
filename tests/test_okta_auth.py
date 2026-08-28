"""Tests for oktaawscli.okta_auth MFA factor selection (verify_mfa)."""

from unittest import mock

from tests._helpers import HomeIsolatedTestCase


def _push_factor(factor_id, device_name=None, device_type=None):
    profile = {"credentialId": "jconstance@amplify.com"}
    if device_name:
        profile["name"] = device_name
    if device_type:
        profile["deviceType"] = device_type
    return {
        "id": factor_id,
        "factorType": "push",
        "provider": "OKTA",
        "profile": profile,
        "_links": {"verify": {"href": "https://example.okta.com/verify/%s" % factor_id}},
    }


def _totp_factor(factor_id, provider="OKTA"):
    return {
        "id": factor_id,
        "factorType": "token:software:totp",
        "provider": provider,
        "profile": {"credentialId": "jconstance@amplify.com"},
        "_links": {"verify": {"href": "https://example.okta.com/verify/%s" % factor_id}},
    }


class TestVerifyMfaFactorIdSelection(HomeIsolatedTestCase):
    """A stored factor-id selects the matching factor without prompting."""

    def test_stored_factor_id_match_skips_prompt(self):
        auth = self._make_okta_auth()
        auth.factor_id = "push_new"
        factors = [_push_factor("push_old"), _push_factor("push_new")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok") as verify_single,
            mock.patch("oktaawscli.okta_auth.input") as fake_input,
        ):
            result = auth.verify_mfa(factors, "state_tok")

        fake_input.assert_not_called()
        verify_single.assert_called_once_with(factors[1], "state_tok")
        self.assertEqual(result, "session_tok")

    def test_stored_factor_id_no_longer_enrolled_falls_back_to_prompt(self):
        auth = self._make_okta_auth()
        auth.factor_id = "push_removed"
        auth.okta_auth_config = mock.MagicMock()
        # Two factors, so the len==1 short-circuit doesn't mask factor-id resolution.
        factors = [_push_factor("push_new"), _totp_factor("totp_a")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1") as fake_input,
        ):
            result = auth.verify_mfa(factors, "state_tok")

        fake_input.assert_called_once()
        # No legacy_factor_provider was ever set on this profile, so the sync
        # must not spontaneously create one.
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "push_new", provider=None
        )
        self.assertEqual(result, "session_tok")


class TestVerifyMfaLegacyMigration(HomeIsolatedTestCase):
    """A legacy provider-keyed factor migrates silently only when unambiguous."""

    def test_single_matching_provider_and_type_migrates_silently(self):
        auth = self._make_okta_auth()
        auth.legacy_factor_provider = "GOOGLE"
        auth.okta_auth_config = mock.MagicMock()
        factors = [_totp_factor("google_totp", provider="GOOGLE"), _push_factor("okta_push")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok") as verify_single,
            mock.patch("oktaawscli.okta_auth.input") as fake_input,
        ):
            auth.verify_mfa(factors, "state_tok")

        fake_input.assert_not_called()
        verify_single.assert_called_once_with(factors[0], "state_tok")
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "google_totp", provider="GOOGLE"
        )

    def test_legacy_provider_matching_both_push_and_totp_migrates_to_push(self):
        """Reproduces pre-fix behavior exactly: (provider, factorType) sort puts
        push before totp, and a single push match is unambiguous -- no prompt."""
        auth = self._make_okta_auth()
        auth.legacy_factor_provider = "OKTA"
        auth.okta_auth_config = mock.MagicMock()
        factors = [_totp_factor("okta_totp"), _push_factor("okta_push")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok") as verify_single,
            mock.patch("oktaawscli.okta_auth.input") as fake_input,
        ):
            auth.verify_mfa(factors, "state_tok")

        fake_input.assert_not_called()
        verify_single.assert_called_once_with(factors[1], "state_tok")
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "okta_push", provider="OKTA"
        )

    def test_legacy_provider_matching_two_push_factors_prompts_once(self):
        """The genuinely ambiguous case (two OKTA push factors, e.g. old + new
        phone): the tool must prompt instead of silently guessing."""
        auth = self._make_okta_auth()
        auth.legacy_factor_provider = "OKTA"
        auth.had_legacy_factor_key = True
        auth.okta_auth_config = mock.MagicMock()
        push_old = _push_factor("push_old")
        push_new = _push_factor("push_new")

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok") as verify_single,
            mock.patch("oktaawscli.okta_auth.input", return_value="1") as fake_input,
        ):
            auth.verify_mfa([push_old, push_new], "state_tok")

        fake_input.assert_called_once()
        # sorted by (provider, factorType, id): "push_new" < "push_old" lexically.
        verify_single.assert_called_once_with(push_new, "state_tok")
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "push_new", provider="OKTA"
        )

    def test_legacy_provider_no_longer_enrolled_warns_and_prompts(self):
        """Mirrors the stored-factor-id-not-found path: no enrolled factor
        matches the legacy provider (e.g. Google Authenticator was dropped),
        so the user is warned and re-prompted instead of silently guessing."""
        auth = self._make_okta_auth()
        auth.legacy_factor_provider = "GOOGLE"
        auth.had_legacy_factor_key = True
        auth.okta_auth_config = mock.MagicMock()
        factors = [_push_factor("push_a"), _push_factor("push_b")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1") as fake_input,
        ):
            auth.verify_mfa(factors, "state_tok")

        # Original provider (GOOGLE) is no longer enrolled, but a legacy key
        # already existed -- it must be re-synced to the newly chosen
        # factor's provider (OKTA), not left stale at "GOOGLE".
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "push_a", provider="OKTA"
        )

        fake_input.assert_called_once()


class TestVerifyMfaPrompt(HomeIsolatedTestCase):
    """Interactive prompting: single-factor short-circuit, labels, and disambiguation."""

    def test_single_supported_factor_skips_prompt_and_saves_nothing(self):
        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        factors = [_push_factor("only_one")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok") as verify_single,
            mock.patch("oktaawscli.okta_auth.input") as fake_input,
        ):
            result = auth.verify_mfa(factors, "state_tok")

        fake_input.assert_not_called()
        verify_single.assert_called_once_with(factors[0], "state_tok")
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_not_called()
        self.assertEqual(result, "session_tok")

    def test_no_stored_preference_with_multiple_factors_prompts(self):
        """End-to-end equivalent of --reset-factor: with factor_id and
        legacy_factor_provider both unset (as OktaAuthConfig.factor_id_for/
        factor_for return None when reset_factor=True), a forced re-prompt
        actually reaches the user instead of being short-circuited."""
        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        factors = [_push_factor("push_a"), _push_factor("push_b")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1") as fake_input,
        ):
            auth.verify_mfa(factors, "state_tok")

        fake_input.assert_called_once()
        # A profile that never had a legacy `factor` value must not have one
        # created as a side effect of syncing -- that would spread the
        # deprecated key to installs that never used it.
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "push_a", provider=None
        )

    def test_prompt_syncs_legacy_factor_key_only_when_it_already_existed(self):
        """A profile with a pre-existing legacy `factor` value keeps it synced
        on every interactive re-selection, even if the newly chosen factor's
        provider differs from what was originally stored (here: the stored
        provider is no longer enrolled at all, so migration can't match and
        falls through to the prompt)."""
        auth = self._make_okta_auth()
        auth.legacy_factor_provider = "GOOGLE"
        auth.had_legacy_factor_key = True
        auth.okta_auth_config = mock.MagicMock()
        factors = [_totp_factor("google_totp", provider="MICROSOFT"), _push_factor("push_a")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1") as fake_input,
        ):
            auth.verify_mfa(factors, "state_tok")

        fake_input.assert_called_once()
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_called_once_with(
            "default", "google_totp", provider="MICROSOFT"
        )

    def test_unsupported_factor_type_is_filtered_out_and_logged(self):
        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        webauthn_factor = {"id": "wa1", "factorType": "webauthn", "provider": "FIDO"}
        factors = [webauthn_factor, _push_factor("only_push")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok"),
            mock.patch("oktaawscli.okta_auth.input") as fake_input,
        ):
            auth.verify_mfa(factors, "state_tok")

        fake_input.assert_not_called()

    def test_prompt_shows_device_name_for_push_factors(self):
        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        factors = [
            _push_factor("push_a", device_name="Pixel 11 Pro XL"),
            _totp_factor("totp_a"),
        ]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1"),
            mock.patch("builtins.print") as fake_print,
        ):
            auth.verify_mfa(factors, "state_tok")

        printed = "\n".join(str(call.args[0]) for call in fake_print.call_args_list)
        self.assertIn("Okta Verify - Push (Pixel 11 Pro XL)", printed)

    def test_prompt_disambiguates_identical_device_labels_with_factor_id(self):
        """Two push factors with the same device name/model must still be
        distinguishable in the prompt, or the user is picking blind again."""
        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        factors = [
            _push_factor("push_old_123456", device_name="iPhone"),
            _push_factor("push_new_789012", device_name="iPhone"),
        ]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="tok"),
            mock.patch("oktaawscli.okta_auth.input", return_value="1"),
            mock.patch("builtins.print") as fake_print,
        ):
            auth.verify_mfa(factors, "state_tok")

        printed_lines = [str(call.args[0]) for call in fake_print.call_args_list]
        factor_lines = [line for line in printed_lines if "iPhone" in line]
        self.assertEqual(len(factor_lines), 2)
        self.assertNotEqual(factor_lines[0], factor_lines[1])

    def test_no_supported_factors_exits(self):
        auth = self._make_okta_auth()
        auth.okta_auth_config = mock.MagicMock()
        webauthn_factor = {"id": "wa1", "factorType": "webauthn", "provider": "FIDO"}

        with self.assertRaises(SystemExit):
            auth.verify_mfa([webauthn_factor], "state_tok")

    def test_single_supported_factor_ignores_stale_stored_factor_id(self):
        """Documents current behavior: the len==1 short-circuit in verify_mfa
        picks the sole remaining factor before _resolve_factor_choice runs, so
        a stale self.factor_id from a removed device is silently ignored --
        no mismatch warning, no config update, no prompt."""
        auth = self._make_okta_auth()
        auth.factor_id = "push_removed"
        auth.okta_auth_config = mock.MagicMock()
        factors = [_push_factor("only_one")]

        with (
            mock.patch.object(auth, "verify_single_factor", return_value="session_tok") as verify_single,
            mock.patch("oktaawscli.okta_auth.input") as fake_input,
        ):
            result = auth.verify_mfa(factors, "state_tok")

        fake_input.assert_not_called()
        verify_single.assert_called_once_with(factors[0], "state_tok")
        auth.okta_auth_config.save_chosen_factor_id_for_profile.assert_not_called()
        self.assertEqual(result, "session_tok")


def _mock_response(body):
    resp = mock.MagicMock()
    resp.json.return_value = body
    return resp


class TestVerifySingleFactorPushPolling(HomeIsolatedTestCase):
    """verify_single_factor's push-challenge poll loop must not crash on a
    malformed/rate-limited response missing the usual status/factorResult keys."""

    def test_success_on_first_poll(self):
        auth = self._make_okta_auth()
        factor = _push_factor("push_a")

        challenge = _mock_response(
            {
                "status": "MFA_CHALLENGE",
                "_links": {"next": {"href": "https://example.okta.com/poll"}},
            }
        )
        success = _mock_response({"status": "SUCCESS", "sessionToken": "sess_tok"})

        with mock.patch(
            "oktaawscli.okta_auth.requests.request",
            side_effect=[challenge, success],
        ):
            result = auth.verify_single_factor(factor, "state_tok")

        self.assertEqual(result, "sess_tok")

    def test_poll_response_missing_factor_result_does_not_crash(self):
        """A poll response with no factorResult key (e.g. an unexpected/error
        body) must not raise KeyError; it should be treated as still pending."""
        auth = self._make_okta_auth()
        factor = _push_factor("push_a")

        challenge = _mock_response(
            {
                "status": "MFA_CHALLENGE",
                "_links": {"next": {"href": "https://example.okta.com/poll"}},
            }
        )
        pending_no_factor_result = _mock_response(
            {
                "status": "MFA_CHALLENGE",
                "_links": {"next": {"href": "https://example.okta.com/poll"}},
            }
        )
        success = _mock_response({"status": "SUCCESS", "sessionToken": "sess_tok"})

        with (
            mock.patch(
                "oktaawscli.okta_auth.requests.request",
                side_effect=[challenge, pending_no_factor_result, success],
            ),
            mock.patch("oktaawscli.okta_auth.time.sleep"),
        ):
            result = auth.verify_single_factor(factor, "state_tok")

        self.assertEqual(result, "sess_tok")

    def test_poll_timeout_exits_cleanly(self):
        auth = self._make_okta_auth()
        factor = _push_factor("push_a")

        challenge = _mock_response(
            {
                "status": "MFA_CHALLENGE",
                "_links": {"next": {"href": "https://example.okta.com/poll"}},
            }
        )
        timeout = _mock_response({"status": "MFA_CHALLENGE", "factorResult": "TIMEOUT"})

        with mock.patch(
            "oktaawscli.okta_auth.requests.request",
            side_effect=[challenge, timeout],
        ):
            with self.assertRaises(SystemExit):
                auth.verify_single_factor(factor, "state_tok")

    def test_poll_rejected_exits_cleanly(self):
        auth = self._make_okta_auth()
        factor = _push_factor("push_a")

        challenge = _mock_response(
            {
                "status": "MFA_CHALLENGE",
                "_links": {"next": {"href": "https://example.okta.com/poll"}},
            }
        )
        rejected = _mock_response({"status": "MFA_CHALLENGE", "factorResult": "REJECTED"})

        with mock.patch(
            "oktaawscli.okta_auth.requests.request",
            side_effect=[challenge, rejected],
        ):
            with self.assertRaises(SystemExit):
                auth.verify_single_factor(factor, "state_tok")


class TestOktaJsonRequestUrlResolution(HomeIsolatedTestCase):
    """_okta_json_request must resolve a relative path against https_base_url
    but pass an already-absolute URL through unchanged."""

    def test_relative_path_is_joined_with_base_url(self):
        auth = self._make_okta_auth()
        response = _mock_response({"status": "SUCCESS"})

        with mock.patch("oktaawscli.okta_auth.requests.request", return_value=response) as mock_request:
            auth._okta_json_request("POST", "/api/v1/sessions", "get_session")

        called_method, called_url = mock_request.call_args.args
        self.assertEqual(called_method, "POST")
        self.assertEqual(called_url, "https://example.okta.com/api/v1/sessions")

    def test_absolute_url_is_used_unchanged(self):
        auth = self._make_okta_auth()
        response = _mock_response({"status": "SUCCESS"})
        absolute_url = "https://example.okta.com/verify/push_a"

        with mock.patch("oktaawscli.okta_auth.requests.request", return_value=response) as mock_request:
            auth._okta_json_request("POST", absolute_url, "verify_single_factor")

        called_method, called_url = mock_request.call_args.args
        self.assertEqual(called_method, "POST")
        self.assertEqual(called_url, absolute_url)


class TestPrimaryAuthResetFactor(HomeIsolatedTestCase):
    """--reset-factor (auth.reset_factor) must force a fresh authn flow -- and
    therefore a fresh MFA prompt -- even when a cached Okta session is valid."""

    def test_reset_factor_bypasses_valid_cached_session(self):
        auth = self._make_okta_auth()
        auth.reset_factor = True
        auth.okta_auth_config = mock.MagicMock()

        with (
            mock.patch.object(auth, "get_cached_session_id", return_value="cached_sid"),
            mock.patch.object(auth, "check_for_desync", return_value=False),
            mock.patch.object(auth, "_run_authn_flow", return_value="fresh_token") as fake_authn,
            mock.patch.object(auth, "get_session", return_value="fresh_sid") as fake_get_session,
        ):
            result = auth.primary_auth()

        fake_authn.assert_called_once()
        fake_get_session.assert_called_once_with("fresh_token")
        self.assertEqual(result, "fresh_sid")

    def test_reset_factor_ignores_peer_refreshed_session_too(self):
        """Even the in-lock 'another process refreshed it' shortcut must not
        short-circuit a --reset-factor run -- the point is to always reach
        the MFA prompt, not just to avoid the outer fast path."""
        auth = self._make_okta_auth()
        auth.reset_factor = True
        auth.okta_auth_config = mock.MagicMock()

        with (
            mock.patch.object(auth, "get_cached_session_id", side_effect=["sid_before_lock", "sid_from_peer"]),
            mock.patch.object(auth, "check_for_desync", return_value=False),
            mock.patch.object(auth, "_run_authn_flow", return_value="fresh_token") as fake_authn,
            mock.patch.object(auth, "get_session", return_value="fresh_sid") as fake_get_session,
        ):
            result = auth.primary_auth()

        fake_authn.assert_called_once()
        fake_get_session.assert_called_once_with("fresh_token")
        self.assertEqual(result, "fresh_sid")

    def test_without_reset_factor_valid_cached_session_still_short_circuits(self):
        """Regression guard: the fix must not disable the fast path generally."""
        auth = self._make_okta_auth()
        auth.reset_factor = False

        with (
            mock.patch.object(auth, "get_cached_session_id", return_value="cached_sid"),
            mock.patch.object(auth, "check_for_desync", return_value=False),
            mock.patch.object(auth, "_run_authn_flow") as fake_authn,
        ):
            result = auth.primary_auth()

        fake_authn.assert_not_called()
        self.assertEqual(result, "cached_sid")
