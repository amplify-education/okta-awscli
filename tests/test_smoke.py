"""Smoke test confirming the test harness wires up correctly."""
import unittest

from oktaawscli import version


class TestSmoke(unittest.TestCase):
    """Trivial harness check."""

    def test_package_version_is_a_string(self):
        self.assertIsInstance(version.__version__, str)
