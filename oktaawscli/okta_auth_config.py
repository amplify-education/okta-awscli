""" Config helper """

import os
from configparser import ConfigParser
from getpass import getpass, getuser

try:
    input = raw_input
except NameError:
    pass


DEFAULT_SECTION = "default"


class OktaAuthConfig:
    """Config helper class"""

    def __init__(self, logger, reset):
        self.logger = logger
        self.reset = reset
        self.config_path = os.path.expanduser("~") + "/.okta-aws"
        self._value = ConfigParser(default_section=DEFAULT_SECTION)
        self._value.read(self.config_path)

    def base_url_for(self, okta_profile):
        """Gets base URL from config"""
        base_url = self._value.get(okta_profile, "base-url", fallback=None)
        if self.reset or not base_url:
            entered_base_url = input(
                'Enter Okta Base URL in form of "%s" [%s]: '
                % (
                    "<your_okta_org>.okta.com",
                    base_url or "",
                )
            )
            base_url = entered_base_url or base_url
            self._save_config_value(
                section=okta_profile,
                key="base-url",
                value=base_url,
            )
        self.logger.info("Authenticating to: %s" % base_url)
        return base_url

    def username_for(self, okta_profile):
        """Gets username from config"""
        username = self._value.get(okta_profile, "username", fallback=None)
        if self.reset or not username:
            username = getuser()
            entered_username = input("Enter username [%s]: " % username)
            username = entered_username or username
        self.logger.info("Authenticating as: %s" % username)
        return username

    def password_for(self, okta_profile):
        """Gets password from config"""
        password = self._value.get(okta_profile, "password", fallback=None)
        if not password:
            password = getpass("Enter password: ")
        return password

    def factor_for(self, okta_profile):
        """Gets factor from config"""
        if self.reset:
            return None

        factor = self._value.get(okta_profile, "factor", fallback=None)
        self.logger.debug("Setting MFA factor to %s" % factor)
        return factor

    def app_for(self, okta_profile):
        """Gets app from config"""
        if self.reset:
            return None

        app = self._value.get(okta_profile, "app", fallback=None)
        self.logger.debug("Setting app to %s" % app)
        return app

    def region_for(self, okta_profile, default="us-east-1"):
        """Gets region from config"""
        region = self._value.get(okta_profile, "region", fallback=default)
        self.logger.debug("Setting region=%s from section=%s", region, okta_profile)
        return region

    def get_check_valid_creds(self, okta_profile):
        """Gets if should check if AWS creds are valid from config"""
        check_valid_creds = self._value.get(
            okta_profile, "check-valid-creds", fallback="True"
        )
        self.logger.info("Check if credentials are valid: %s" % check_valid_creds)
        return check_valid_creds

    def get_store_role(self, okta_profile):
        """Gets if should store role to okta-profile from config"""
        store_role = self._value.get(okta_profile, "store-role", fallback="True")
        self.logger.info("Should store role: %s" % store_role)
        return store_role

    def get_auto_write_profile(self, okta_profile):
        """Gets if should auto write aws creds to ~/.aws/credentials from config"""
        auto_write_profile = self._value.get(
            okta_profile, "auto-write-profile", fallback=True
        )
        self.logger.info(
            "Should write profile to ~/.aws/credentials: %s" % auto_write_profile
        )
        return auto_write_profile

    def get_session_duration(self, okta_profile):
        """Gets STS session duration from config as an int"""
        # AWS docs say default duration is 1 hour (3600 seconds)
        session_duration = int(
            self._value.get(okta_profile, "session-duration", fallback="3600")
        )

        if session_duration > 43200 or session_duration < 3600:
            self.logger.info(
                "Invalid session duration specified, defaulting to 1 hour."
            )
            session_duration = 3600

        self.logger.info("Configured session duration: %s seconds" % session_duration)
        return session_duration

    def save_chosen_role_for_profile(self, okta_profile, role_arn):
        """Saves role to config"""
        self._save_config_value(
            section=okta_profile,
            key="role",
            value=role_arn,
        )

    def save_chosen_factor_for_profile(self, okta_profile, factor):
        """Saves factor to config"""
        self._save_config_value(
            section=okta_profile,
            key="factor",
            value=factor,
        )

    def save_chosen_app_for_profile(self, okta_profile, app):
        """Saves app to config"""
        self._save_config_value(
            section=okta_profile,
            key="app",
            value=app,
        )

    def _save_config_value(self, section, key, value):
        # has_section explicitly doesn't check for the default section, so only ask if the section exists if
        # its not the default section
        if section != DEFAULT_SECTION and not self._value.has_section(section):
            self._value.add_section(section)

        self._value.set(section, key, value)

        with open(self.config_path, "w+") as configfile:
            self._value.write(configfile)
