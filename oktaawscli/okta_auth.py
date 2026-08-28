"""Handles auth to Okta and returns SAML assertion"""

import json
import os
import random
import sys
import time
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup as bs

from oktaawscli._locking import INTERACTIVE_LOCK_TIMEOUT_SECONDS, atomic_write, locked

MAX_OKTA_RATE_LIMIT_RETRIES = 5
OKTA_RATE_LIMIT_BACKOFF_BASE_SECONDS = 1.0
OKTA_REQUEST_TIMEOUT_SECONDS = 30
# Okta's own push challenge times out around 5 minutes; match that so we don't
# fail faster than a human tapping "approve" on their device.
PUSH_POLL_TIMEOUT_SECONDS = 300

try:
    input = input
except NameError:
    pass


class OktaAuth:
    """Handles auth to Okta and returns SAML assertion"""

    def __init__(self, okta_profile, verbose, logger, totp_token, okta_auth_config, debug=False):
        self.okta_profile = okta_profile
        self.totp_token = totp_token
        self.logger = logger
        self.verbose = verbose
        self.okta_auth_config = okta_auth_config
        self.https_base_url = "https://%s" % okta_auth_config.base_url_for(okta_profile)
        self.factor_id = okta_auth_config.factor_id_for(okta_profile)
        self.legacy_factor_provider = okta_auth_config.factor_for(okta_profile)
        self.had_legacy_factor_key = okta_auth_config.factor_key_exists_for(okta_profile)
        self.reset_factor = okta_auth_config.reset_factor
        self.app = okta_auth_config.app_for(okta_profile)
        self.debug = debug

        self.token_path = os.path.join(os.path.expanduser("~"), ".okta-token")
        if not os.path.isfile(self.token_path):
            open(self.token_path, "a").close()

    def primary_auth(self):
        """Performs primary auth against Okta, serializing parallel runs through a lock."""
        session_id = self.get_cached_session_id()
        if session_id is not None and not self.reset_factor and not self.check_for_desync(session_id):
            return session_id

        # 300s timeout accommodates interactive MFA in the holding process.
        with locked(self.token_path, timeout=INTERACTIVE_LOCK_TIMEOUT_SECONDS):
            refreshed = self.get_cached_session_id()
            if refreshed is not None and refreshed != session_id and not self.reset_factor:
                self.logger.info("Cached Okta session was refreshed by another process; using it.")
                return refreshed
            # --reset-factor must always force a fresh authn flow (and thus MFA
            # re-selection) even if a cached or peer-refreshed session is valid.
            return self.get_session(self._run_authn_flow())

    def _run_authn_flow(self):
        """Runs the Okta authn POST and returns a sessionToken. Caller holds the lock."""
        self.logger.warning("Cached Okta session is missing or invalid. Authenticating now...")
        auth_data = {
            "username": self.okta_auth_config.username_for(self.okta_profile),
            "password": self.okta_auth_config.password_for(self.okta_profile),
        }
        # https://developer.okta.com/docs/reference/api/authn/
        resp_json = self._okta_json_request("POST", "/api/v1/authn", "_run_authn_flow", json=auth_data)
        if "status" in resp_json:
            status = resp_json["status"]
            if status == "MFA_REQUIRED":
                return self.verify_mfa(resp_json["_embedded"]["factors"], resp_json["stateToken"])
            if status == "SUCCESS":
                return resp_json["sessionToken"]
            if status == "MFA_ENROLL":
                self.logger.warning(
                    "MFA not enrolled. Cannot continue. Please enroll an MFA factor in the Okta Web UI first!"
                )
                sys.exit(2)
            if status == "LOCKED_OUT":
                self.logger.error(
                    "Account is locked. Cannot continue. "
                    "Please contact you administrator in order to unlock the account!"
                )
                sys.exit(1)
            self.logger.error(f"Unknown authentication status: {status}")
            sys.exit(1)
        self.logger.error("Unexpected authn response: %s" % self._safe_error_summary(resp_json))
        exit(1)

    def verify_mfa(self, factors_list, state_token):
        """Performs MFA auth against Okta"""

        supported_factor_types = ["token:software:totp", "push"]
        supported_factors = []
        for factor in factors_list:
            if factor["factorType"] in supported_factor_types:
                supported_factors.append(factor)
            else:
                self.logger.info("Unsupported factorType: %s" % (factor["factorType"],))

        supported_factors = sorted(
            supported_factors,
            key=lambda factor: (factor["provider"], factor["factorType"], factor["id"]),
        )

        if not supported_factors:
            print("MFA required, but no supported factors enrolled! Exiting.")
            sys.exit(1)

        if len(supported_factors) == 1:
            index = 0
        else:
            index = self._resolve_factor_choice(supported_factors)
        chosen = supported_factors[index]

        self.logger.info(
            "Performing secondary authentication using: %s" % self._factor_labels(supported_factors)[index]
        )
        return self.verify_single_factor(chosen, state_token)

    def _resolve_factor_choice(self, supported_factors):
        """Picks which enrolled factor to use, prompting only when genuinely ambiguous."""
        if self.factor_id:
            for index, factor in enumerate(supported_factors):
                if factor["id"] == self.factor_id:
                    self.logger.info(
                        "Using pre-selected factor choice from ~/.okta-aws: %s"
                        % self._factor_labels(supported_factors)[index]
                    )
                    return index
            self.logger.warning("Previously selected MFA factor is no longer enrolled; please choose again.")
        elif self.legacy_factor_provider:
            migrated = self._migrate_legacy_factor_choice(supported_factors)
            if migrated is not None:
                return migrated

        return self._prompt_for_factor_choice(supported_factors)

    def _migrate_legacy_factor_choice(self, supported_factors):
        """Reproduces the pre-factor-id selection (first provider match in
        (provider, factorType) sort order) and adopts it silently if, and only
        if, exactly one enrolled factor shares that (provider, factorType)."""
        first_match = next(
            ((i, f) for i, f in enumerate(supported_factors) if f["provider"] == self.legacy_factor_provider),
            None,
        )
        if first_match is None:
            self.logger.warning("Previously selected MFA provider is no longer enrolled; please choose again.")
            return None
        index, factor = first_match

        group = [
            f
            for f in supported_factors
            if (f["provider"], f["factorType"]) == (factor["provider"], factor["factorType"])
        ]
        if len(group) > 1:
            return None

        self.logger.info("Migrating MFA factor choice from ~/.okta-aws to factor id %s" % factor["id"])
        self.okta_auth_config.save_chosen_factor_id_for_profile(
            self.okta_profile, factor["id"], provider=factor["provider"]
        )
        return index

    def _prompt_for_factor_choice(self, supported_factors):
        """Interactively prompts, then persists the choice by factor id."""
        print("Registered MFA factors:")
        for index, label in enumerate(self._factor_labels(supported_factors)):
            print("%d: %s" % (index + 1, label))
        while True:
            try:
                factor_choice = int(input("Please select the MFA factor: ")) - 1
            except ValueError:
                print("Please enter a number.")
                continue
            if 0 <= factor_choice < len(supported_factors):
                break
            print("Please enter a number between 1 and %d." % len(supported_factors))
        # Only sync the legacy `factor` key for a profile that already had one
        # on disk -- otherwise a brand-new install would have the deprecated
        # key created from scratch as a side effect of this prompt. Gated on
        # had_legacy_factor_key (a raw, reset-independent check), NOT
        # legacy_factor_provider -- the latter is forced to None under
        # --reset/--reset-factor specifically so a stale value can't
        # short-circuit the forced prompt, which would wrongly read here as
        # "never had a legacy key" and leave an existing one to go stale.
        provider = supported_factors[factor_choice]["provider"] if self.had_legacy_factor_key else None
        self.okta_auth_config.save_chosen_factor_id_for_profile(
            self.okta_profile, supported_factors[factor_choice]["id"], provider=provider
        )
        return factor_choice

    def _factor_labels(self, supported_factors):
        """Builds display labels, disambiguating duplicates with a factor id suffix."""
        labels = [self._factor_label(factor) for factor in supported_factors]
        counts = {label: labels.count(label) for label in labels}
        return [
            label if counts[label] == 1 else "%s [id ...%s]" % (label, factor["id"][-6:])
            for label, factor in zip(labels, supported_factors)
        ]

    def _factor_label(self, factor):
        """Builds a human-readable label, including the device name when Okta sends one."""
        provider = factor["provider"]
        factor_type = factor["factorType"]
        if provider == "GOOGLE":
            label = "Google Authenticator"
        elif provider == "OKTA":
            label = "Okta Verify - Push" if factor_type == "push" else "Okta Verify"
        else:
            label = "Unsupported factor type: %s" % provider

        profile = factor.get("profile") or {}
        device_name = profile.get("name") or profile.get("deviceType")
        if device_name:
            label = "%s (%s)" % (label, device_name)
        return label

    def verify_single_factor(self, factor, state_token):
        """Verifies a single MFA factor"""
        req_data = {"stateToken": state_token}

        self.logger.debug(factor)

        if factor["factorType"] == "token:software:totp":
            if self.totp_token:
                self.logger.debug("Using TOTP token from command line arg")
                req_data["answer"] = self.totp_token
            else:
                req_data["answer"] = input("Enter MFA token: ")

        post_url = factor["_links"]["verify"]["href"]
        # retry_on_rate_limit=False: this POST dispatches the push/answer, so an
        # automatic retry on rate-limit could resend it and double-push the user.
        resp_json = self._okta_json_request(
            "POST", post_url, "verify_single_factor", retry_on_rate_limit=False, json=req_data
        )

        if resp_json.get("status") == "SUCCESS":
            return resp_json["sessionToken"]

        if resp_json.get("status") != "MFA_CHALLENGE":
            self.logger.error("Unexpected MFA verification response: %s" % self._safe_error_summary(resp_json))
            sys.exit(1)

        print("Waiting for push verification...")
        deadline = time.monotonic() + PUSH_POLL_TIMEOUT_SECONDS
        while True:
            next_link = (resp_json.get("_links") or {}).get("next") or {}
            poll_url = next_link.get("href")
            if not poll_url:
                self.logger.error("Poll response missing next link; cannot continue polling.")
                sys.exit(1)
            resp_json = self._okta_json_request(
                "POST",
                poll_url,
                "verify_single_factor_poll",
                json=req_data,
            )
            if resp_json.get("status") == "SUCCESS":
                return resp_json["sessionToken"]
            factor_result = resp_json.get("factorResult")
            if factor_result == "TIMEOUT":
                print("Verification timed out")
                sys.exit(1)
            elif factor_result == "REJECTED":
                print("Verification was rejected")
                sys.exit(1)
            else:
                if time.monotonic() >= deadline:
                    self.logger.error(
                        "Still waiting on MFA push verification after %ds; giving up.",
                        PUSH_POLL_TIMEOUT_SECONDS,
                    )
                    sys.exit(1)
                self.logger.debug("Still waiting for push verification response...")
                time.sleep(0.5)

    def get_session(self, session_token):
        """Gets a session cookie from a session token"""
        data = {"sessionToken": session_token}
        # https://developer.okta.com/docs/guides/ie-limitations/main/#sessions-apis
        resp = self._okta_json_request("POST", "/api/v1/sessions", "get_session", json=data)
        self.cache_session_id(resp["id"], resp["expiresAt"])
        return resp["id"]

    def cache_session_id(self, session_id, expiration_date):
        """Stores Okta session id in ~/.okta-token"""
        session_info = {"session_id": session_id, "expiration_date": expiration_date}
        self.logger.info("Cacheing Okta session id to ~/.okta-token")
        with atomic_write(self.token_path) as session_file:
            session_file.write(
                json.dumps(
                    session_info,
                    sort_keys=True,
                    indent=4,
                    separators=(",", ": "),
                    default=str,
                )
            )

    def get_cached_session_id(self):
        """Gets Okta session id from ~/.okta-token if valid"""
        with open(self.token_path, "r") as session_file:
            session_info = session_file.read()
        if session_info == "":
            session_info = {}
        else:
            session_info = json.loads(session_info)

        expiration_date = datetime.min
        if session_info.get("expiration_date"):
            expiration_date = datetime.strptime(session_info.get("expiration_date"), "%Y-%m-%dT%H:%M:%S.%fZ")

        current_time = datetime.utcnow()
        if max([current_time, expiration_date]) == expiration_date:
            self.logger.info("Using cached Okta session id from ~/.okta-token")
            return session_info.get("session_id")
        return None

    def check_for_desync(self, session_id):
        """Returns True if there's a desync between the local and remote token state, False otherwise"""
        try:
            sid = "sid=%s" % session_id
            headers = {"Cookie": sid}
            # https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/getUser
            raw_resp = requests.get(self.https_base_url + "/api/v1/users/me", headers=headers)
            raw_resp.raise_for_status()
            return False
        except requests.HTTPError as e:
            if e.response is None or e.response.status_code != 403 or "Invalid session" not in e.response.text:
                raise e
            message = "Okta session invalidated. Refreshing token now..."
            self.logger.error(message)
            return True

    def _okta_json_request(self, method, path_or_url, context, retry_on_rate_limit=True, **kwargs):
        """Issue an HTTP request against https_base_url + path_or_url (or, if
        path_or_url is already an absolute URL, against that URL directly --
        Okta's factor `_links.verify`/`_links.next` hrefs are absolute),
        retrying on Okta rate-limit unless retry_on_rate_limit is False (for
        non-idempotent calls, e.g. the initial MFA-verify POST that can dispatch
        a push, where a retry would resend it).

        Returns parsed JSON for non-error responses. Exits 1 on a non-rate-limit
        Okta error body or after exhausting retries.
        """
        url = urljoin(self.https_base_url, path_or_url)
        kwargs.setdefault("timeout", OKTA_REQUEST_TIMEOUT_SECONDS)
        attempts = MAX_OKTA_RATE_LIMIT_RETRIES if retry_on_rate_limit else 1
        for attempt in range(attempts):
            resp = requests.request(method, url, **kwargs)
            body = resp.json()
            if retry_on_rate_limit and isinstance(body, dict) and body.get("errorCode") == "E0000047":
                delay = OKTA_RATE_LIMIT_BACKOFF_BASE_SECONDS * (2**attempt)
                delay += random.uniform(0, delay)
                self.logger.warning(
                    "Okta rate-limited in %s; retrying in %.1fs (attempt %d/%d)",
                    context,
                    delay,
                    attempt + 1,
                    MAX_OKTA_RATE_LIMIT_RETRIES,
                )
                time.sleep(delay)
                continue
            self._exit_on_okta_error(body, context)
            return body
        self.logger.error(
            "Okta API still rate-limited in %s after %d retries; giving up.",
            context,
            MAX_OKTA_RATE_LIMIT_RETRIES,
        )
        sys.exit(1)

    def _exit_on_okta_error(self, resp_body, context):
        """Exit cleanly if the parsed JSON body is an Okta error response.

        Okta error bodies are dicts with an `errorCode` key. List-shaped responses
        (the success shape for endpoints like appLinks) skip the check.
        """
        if isinstance(resp_body, dict) and resp_body.get("errorCode"):
            self.logger.error(
                "Okta API error in %s: %s (errorCode=%s, errorId=%s)",
                context,
                resp_body.get("errorSummary", "<no summary>"),
                resp_body["errorCode"],
                resp_body.get("errorId", "<no id>"),
            )
            sys.exit(1)

    @staticmethod
    def _safe_error_summary(resp_body):
        """Renders an Okta response body for logging without its stateToken or
        _embedded user PII -- status and any error fields only."""
        if not isinstance(resp_body, dict):
            return "<non-dict response body of type %s>" % type(resp_body).__name__
        return {key: resp_body[key] for key in ("status", "errorSummary", "errorCode", "errorId") if key in resp_body}

    def get_apps(self, session_id):
        """Gets apps for the user"""
        sid = "sid=%s" % session_id
        headers = {"Cookie": sid}
        # https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserResources/#tag/UserResources/operation/listAppLinks
        resp = self._okta_json_request("GET", "/api/v1/users/me/appLinks", "get_apps", headers=headers)

        aws_apps = []
        for app in resp:
            if app["appName"] == "amazon_aws":
                aws_apps.append(app)
        if not aws_apps:
            self.logger.error("No AWS apps are available for your user. Exiting.")
            sys.exit(1)

        aws_apps = sorted(aws_apps, key=lambda app: app["sortOrder"])
        app_choice = None
        for index, app in enumerate(aws_apps):
            if self.app and app["label"] == self.app:
                app_choice = index
                break
            print("%d: %s" % (index + 1, app["label"]))
        if app_choice is None:
            app_choice = int(input("Please select AWS app: ")) - 1
            self.okta_auth_config.save_chosen_app_for_profile(self.okta_profile, aws_apps[app_choice]["label"])

        return aws_apps[app_choice]["label"], aws_apps[app_choice]["linkUrl"]

    def get_saml_assertion(self, html):
        """Returns the SAML assertion from HTML"""
        soup = bs(html.text, "html.parser")
        assertion = ""

        for input_tag in soup.find_all("input"):
            if input_tag.get("name") == "SAMLResponse":
                assertion = input_tag.get("value")

        if not assertion:
            self.logger.error("SAML assertion not valid: " + assertion)
            exit(-1)
        return assertion

    def get_assertion(self):
        """Main method to get SAML assertion from Okta"""
        session_id = self.primary_auth()
        app_name, app_link = self.get_apps(session_id)
        sid = "sid=%s" % session_id
        headers = {"Cookie": sid}
        resp = requests.get(app_link, headers=headers)
        assertion = self.get_saml_assertion(resp)
        return app_name, assertion
