Unreleased
----------
- Switched to using GitHub Actions as CI provider
- Bumped minimum required Rust version to `1.70.0`
- Bumped `dirs` dependency to `5.0`
- Bumped `gpgme` dependency to `0.11`
- Bumped `ring` dependency to `0.17`


0.1.4
-----
- Switched from using `ssh-agent` to `ssh-agent-lib`
- Bumped minimum required Rust version to `1.56.0`


0.1.3
-----
- Bumped minimum required Rust version to `1.46.0`
- Bumped `ring` dependency to `0.16`
  - Removed direct `untrusted` dependency
- Bumped `dirs` dependency to `4.0`


0.1.2
-----
- Use `anyhow` for providing context to errors
- Downgraded `deny` crate-level lints to `warn`
- Bumped minimum required Rust version to `1.34.0`
- Bumped `env_logger` dependency to `0.7`
- Bumped `dirs` dependency to `2.0`


0.1.1
-----
- Load public keys on demand instead of caching them
- Decreased binary size by disabling default features for `env_logger`
- Added badge showing the license to `README.md`


0.1.0
-----
- Initial release
