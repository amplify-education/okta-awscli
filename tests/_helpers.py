"""Shared test helpers (not collected by unittest discovery — leading underscore)."""

import logging


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
