from setuptools import find_packages, setup

from oktaawscli.version import __version__


def get_requirements():
    with open("requirements.txt") as reqfile:
        return [line for line in reqfile.read().splitlines() if line and not line.startswith(("#", "-"))]


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
    install_requires=get_requirements(),
)
