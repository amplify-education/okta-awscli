# Changelog

## [0.4.13] 2026-05-11
### Changed
- Cross-process file locking and atomic-rename writes for `~/.aws/credentials`, `~/.okta-aws`, and `~/.okta-alias-info`. Multiple `okta-awscli` processes can now run in parallel against the same dotfiles without clobbering each other.
- `OktaAuth.primary_auth` now acquires a 300-second lock around the Okta authentication flow. Parallel runs serialize through a single MFA prompt; the rest pick up the freshly-cached session and skip auth entirely.
- Okta API error responses (`errorCode` dicts) surface as a one-line exit message with the error code and id, instead of `TypeError: string indices must be integers, not 'str'`.
- Okta rate-limit responses (`errorCode: E0000047`) are retried with proportional-jitter exponential backoff (up to 5 attempts, ~62s worst case).
- `~/.okta-token` is written atomically; partial-file corruption from a process killed mid-write no longer breaks the cached-session reader path.
- `filelock.Timeout` from the locking helpers is caught at the CLI entry point and surfaces as a one-line error message instead of a stack trace.
- Latent `NoSectionError` in `copy_to_default` (raised against a credentials file with a populated source profile but no pre-existing `[default]` section) is fixed.

### Added
- `oktaawscli/_locking.py` exposing `locked(path, timeout=...)` and `atomic_write(path)` primitives, plus `LOCK_TIMEOUT_SECONDS` (60s default) and `INTERACTIVE_LOCK_TIMEOUT_SECONDS` (300s for auth flow) constants.
- `tox.ini` and a `tests/` unittest-based test suite covering the locking, atomic-write, merge-on-write, and rate-limit behaviors.
- `filelock` runtime dependency.

## [0.4.8] 2024-05-02
### Changed
- Log exception when encountering unknown ClientError error while listing AWS account aliases.

## [0.4.5] 2023-03-10
### Changed
- Added handling of Okta authentication status for `MFA_ENROLL` and `LOCKED_OUT`
- Added handling of unknown Okta authentication status
- Formatted code with Python black

## [0.4.0] 2019-05-02
### Changed
- Added region override parameter for write_sts_token method
- Export Profile usage message will not print if using account (-a) argument

## [0.3.6] 2018-12-07
### Changed
- Sorted role options by role name after sorting by account alias

## [0.3.5] 2018-09-28
### Changed
- Fixed exception that would break program when OKTA was configured with accounts that did not give OKTA permissions to login

## [0.3.4] 2018-09-18
### Changed:
- Fixed exception handling of missing credentials exception for Python 3

## [0.3.3] 2018-09-12
### Added:
- Add parameter `-a, --account` to okta-awscli
        - Filters and lists or chooses AWS roles for account
        - Creates/updates Okta profile and AWS profile named from account

- Add parameter `-w, --write-default` to okta-awscli
        - When authenticating with AWS role, the STS credentials will be written to both the AWS account and default profiles

### Changed:
- Fix input requirement of user credentials when Okta token is still valid

## [0.3.2] 2018-08-31
### Changed:
- Fix datetime parsing of expiration date for Okta token

## [0.3.1] 2018-08-23
### Changed:
- Better error handling for selection of roles

## [0.3.0] 2018-08-16
### Added:
- Select app specified by `app` field in config if `app` field exists
- Graciously reprompt for role index on bad selection
- Add export flag to print creds to console
- Add reset flag to reset fields in `~/.okta-aws` for current okta-profile
- Stores factor for default okta profiles
- Add usage message when storing credentials in `/.aws/credentials`
- Use system username if `username` not set in `~/.okta-aws` and no username given when prompted

- Display account aliases when prompting for role selection
	- create a `~/.okta-alias-info` file to store account aliases
	- fetch account aliases to display in list of roles
	- cache account aliases in `~/.okta-alias-info` along with time last updated
	- refresh account alias if last updated over a week ago

- Add config option `auto-write-profile` to `~/.okta-aws`
	- if "True" and no `--profile` specified, will write aws creds to profile named for the account alias for the chosen role
		- if account alias for the chosen role is unknown, will write to `default` aws profile
	- modifies existing functionality if `--profile` specified - will write to the specified profile unless `--export` flag set
	- if `--export` flag set, will not write aws creds, will only display to console
	- defaults to "False" to maintain existing functionality if option not set

- Add config option `store-role` to `~/.okta-aws`
	- if "False", will not store role upon selection for the chosen `okta-profile`
	- Will use `role` is already defined for the chosen `okta-profile`
	- defaults to "True" to maintain existing functionality if option not set

- Add config option `check-valid-creds` to `~/.okta-aws`
	- if "False", will skip making sure credentials are valid and automatically get new credentials
	- if "True", will refresh credentials only if `--profile` and `--force` are both specified
	- Defaults to True to maintain existing behavior

- Cache okta session id to avoid re-authenticating with Okta when switching token
	- stores session id and expiration timestamp in `~/.okta-token`
	- if session id is expired, will re-authenticate

- Add config option `session-duration` to `~/.okta-aws`
	- takes in session duration in seconds
	- to be valid, must be between 3600 and 43200 (1 hour to 12 hours)
	- if invalid or not specified, defaults to 3600 (1 hour)

- Add config option `region` to `~/.okta-aws`
	- specifies the region to access resources in
	- defaults to `us-east-1`

### Changed:
- Exports `aws_security_token` variable as well in order to supportM with `boto` library calls
- Update RESUME

## [0.2.3] 2018-07-21
### Added:
- Travis CI builds to run linting tests for branches and PRs.

### Fixed:
- Python3 Compatibility issues.

## [0.2.2] 2018-07-18
### Fixed:
- Python3 Compatibility. (#38)

## [0.2.1] 2018-02-14
### Fixed:
- Issue where secondary auth would fail when only a single factor is enrolled for the user. (#27)

## [0.2.0] 2018-02-11
### Added:
- Ability to store MFA factor choice in `~/.okta-aws`. (#3)
- Flag to output the version.
- Ability to store AWS Role choice in `~/.okta-aws`. (#4)
- Ability to pass in TOTP token as a command-line argument. (#13)
- Support for MFA push notifications. Thanks Justin! (#10)
- Support for caching credentials to use in other sessions. Thanks Justin! (#6, #7)

### Fixed:
- Issue #14. Fixed a bug where okta-awscli wasn't connecting to the STS API endpoint in us-gov-west-1 when trying to obtain credential for GovCloud.
- Improved sorting in the app list to be more consistent. Thanks Justin!
- Cleaned up README to improve clarity. Thanks Justin!

## [0.1.5] 2017-11-15
### Fixed:
- Issue #8. Another pass at trying to fix the MFA list. Factor chosen was being pulled from list which included unsupported factors.

## [0.1.4] 2017-08-27
### Added:
- This CHANGELOG!

### Fixed:
- Issue #1. Bug where MFA factor selected isn't always the one passed to Okta for verification.

## [0.1.3] 2017-08-17
### Added:
- Prompts for a username and password if omitted from `.okta-aws`

### Changed:
- Spelling fix
- Change `--okta_profile` flag to be `--okta-profile` instead.

## [0.1.2] 2017-07-25
### Added:
- Support for flag to force new credentials.

### Changed
- Handles no profile provided.
- Handles no awscli args provided (authenticate only).

## [0.1.1] 2017-07-25
- Initial release. Updated for PyPi.
