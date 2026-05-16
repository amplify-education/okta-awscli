import os
import re

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "oktaawscli/version.py"), encoding="utf-8") as f:
    match = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
if match is None:
    raise RuntimeError("Could not parse __version__ from oktaawscli/version.py")
version = match.group(1)

setup(
    name="amplify-okta-awscli",
    version=version,
    description="Provides a wrapper for Okta authentication to awscli",
    packages=find_packages(),
    license="Apache License 2.0",
    author="James Hale",
    author_email="james@jameshale.me",
    url="https://github.com/amplify-education/okta-awscli",
    entry_points={
        "console_scripts": [
            "okta-awscli=oktaawscli.okta_awscli:main",
        ],
    },
    install_requires=[
        "requests",
        "click",
        "bs4",
        "boto3",
        "ConfigParser",
        "filelock",
    ],
)
