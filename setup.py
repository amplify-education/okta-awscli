from setuptools import find_packages, setup

from oktaawscli.version import __version__

setup(
    name="amplify-okta-awscli",
    version=__version__,
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
