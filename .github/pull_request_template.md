## What does this change?

<!-- One or two sentences. Link the issue it closes, if any. -->

## Testing checklist

- [ ] `cargo test` passes (this crate targets Fedora specifically, `systemctl`/`dnf`/`journalctl` integration tests need a real Fedora host, see `CONTRIBUTING.md`'s development-environment section)
- [ ] `cargo clippy --all-targets -- -D warnings` is clean
- [ ] `cargo fmt --check` is clean
- [ ] If this touches `src/policy/`: a test covers the specific behaviour changed, including at least one test attempting to smuggle a second command or flag-injection payload past a deny rule (see `CONTRIBUTING.md`'s testing expectations)
- [ ] If this adds or changes a tool in `src/tools/`: the manual smoke test is documented in `docs/uat/v1-uat-scenarios.md`

## Security considerations

<!-- If this touches command execution, argument parsing, or the policy engine: what happens if a
     prompt-injected agent controlled every input this code sees? See AGENTS.md's rules on
     argument-injection hardening before assuming a `--` separator or similar is sufficient. -->
