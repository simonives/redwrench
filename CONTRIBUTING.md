# Contributing to RedWrench

## Before you start

Read `ARCHITECTURE.md` first, it's short and explains the four layers
and where new code belongs.

## Development environment

RedWrench wraps Linux-specific facilities (`systemctl`, `dnf`,
`journalctl`, the systemd journal) that cannot be meaningfully built or
tested on a non-Linux machine. You need access to a real Fedora box to
run `cargo test` or `cargo run` meaningfully; editing on another
machine and running `cargo test` over SSH against that box is a
supported and expected workflow (see `justfile`'s `remote-test`
recipe).

## Testing expectations

- **Any change to `src/policy/`** must include unit tests. This is the
  security-critical core of the project; a policy engine change without
  a test covering the specific behaviour changed will not be merged.
  Include at least one test attempting to construct an argument that
  looks like it could smuggle a second command past a deny rule (see
  the existing tests in `src/policy/mod.rs` for the pattern), and
  confirm it's still denied.
- **Any new tool** (`src/tools/*.rs`) should have its manual smoke test
  documented in `docs/uat/v1-uat-scenarios.md`, in addition to whatever
  automated tests make sense for it.
- Run `cargo test` before opening a PR. CI runs the same suite inside a
  Fedora container.

## Commit style

Small, focused commits. One logical change per commit. Commit messages
describe what changed and, where it's not obvious, why.

## License

By contributing, you agree your contribution is licensed under both
MIT and Apache-2.0, matching the rest of the project (see `LICENSE-MIT`
and `LICENSE-APACHE`).
