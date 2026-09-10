# Roadmap

This is the narrative version of RedWrench's release plan. The mechanical version lives in two places kept consistent with this document: [GitHub Milestones](https://github.com/simonives/redwrench/milestones) (issue-level tracking per version) and the [RedWrench Roadmap project board](https://github.com/users/simonives/projects/10) (a release-window view across all open and closed work). If any of the three ever disagree, this file and the Milestones are the source of truth, the board is a view onto them.

## Shipped

**v1.0** ([CHANGELOG](CHANGELOG.md#100---2026-09-10)): the policy engine, four tiers, streaming execution, the audit trail, and capability/policy discovery. Everything the original design spec committed to for a first release, plus the developer tier and the discovery tools, which were added after the initial spec in response to real deployment feedback.

## Planned

Each version below has a theme, a reason several issues belong together, not just a bucket of whatever was open. Ordering follows severity and complexity, not issue number.

### v1.0.1, security patch

Found by an independent tier-charter audit ([docs/superpowers/specs/2026-09-10-tier-charter-audit.md](docs/superpowers/specs/2026-09-10-tier-charter-audit.md)) run against every tier's actual behaviour, not just its documented claims. These undercut guarantees v1.0.0 shipped hours earlier, and two of them (journalctl, top) affect every tier except `unrestricted`, since every tier inherits `safe`'s rules. Ships ahead of v1.1 rather than folded into it, given the severity and how recently v1.0.0 landed.

- [#38](https://github.com/simonives/redwrench/issues/38): `journalctl`'s `+` disjunction bypasses the safe-tier unit-scope requirement, reopens #26
- [#39](https://github.com/simonives/redwrench/issues/39): `top -b -c` at safe tier discloses every process's full command line, system-wide, as root
- [#40](https://github.com/simonives/redwrench/issues/40): `standard` tier can reboot, power off, or drop the host to single-user mode
- [#41](https://github.com/simonives/redwrench/issues/41): `dnf -c`/`--config` bypasses the trust-bypass deny, enabling a developer-tier root escalation
- [#42](https://github.com/simonives/redwrench/issues/42): `custom_rules` can grant unrestricted-equivalent root RCE without `--i-understand-the-risk`

### v1.1, policy engine polish

Coverage and completeness work on an already-functional system, no new capability, closing gaps. Extended with the tier-charter audit's remaining findings (medium and low severity, plus documentation drift), alongside the pre-existing polish items, and with the surviving findings from an independent cross-model review (#65-#69, an external agy/GPT-OSS pass over the whole repo; most of that pass's higher-severity security claims didn't survive verification against the actual code and aren't included, only the test-coverage and packaging gaps that checked out).

- [#22](https://github.com/simonives/redwrench/issues/22): hardware inventory commands (`lscpu`, `uname`, `free`, `lsblk`, `df`) added to `safe` tier
- [#25](https://github.com/simonives/redwrench/issues/25): `run_command` shouldn't silently block for the full timeout on an unbounded command when no streaming client is attached
- [#35](https://github.com/simonives/redwrench/issues/35): an end-to-end test proving a `ROOT_REQUIRED_TOOLS` member actually stays root under `developer` tier
- [#43](https://github.com/simonives/redwrench/issues/43): `ping`'s abuse-flag deny misses broadcast (`-b`), `-r`, `-d`, and every long-option form except `--flood`
- [#44](https://github.com/simonives/redwrench/issues/44): `safe` tier's outbound network reach (ping payload plus hostname) is undocumented as an egress channel
- [#45](https://github.com/simonives/redwrench/issues/45): `journalctl --root` is allowed at safe while the equivalent `systemctl --root` is denied
- [#46](https://github.com/simonives/redwrench/issues/46): `sar`'s clustered `-o` flag may permit an arbitrary root file write at safe tier (needs live verification)
- [#47](https://github.com/simonives/redwrench/issues/47): README's safe-tier row omits the journalctl unit-scope requirement and the `--image`/`--image-policy` denial
- [#48](https://github.com/simonives/redwrench/issues/48): `dnf install` of a local RPM may bypass signature verification depending on dnf's `localpkg_gpgcheck` default (needs live verification)
- [#49](https://github.com/simonives/redwrench/issues/49): `dnf`/`systemctl` subcommand allows use prefix matching instead of exact matching
- [#50](https://github.com/simonives/redwrench/issues/50): `rpm-ostree status` is misclassified as a standard-tier action, belongs in `safe`
- [#51](https://github.com/simonives/redwrench/issues/51): the `dnf` trust-bypass deny survives only due to rule ordering, not a structural guarantee
- [#52](https://github.com/simonives/redwrench/issues/52): `ROOT_REQUIRED_TOOLS` may be broader than necessary (`vmstat`/`sar`/`top`/`ping` likely don't need root, needs live verification)
- [#53](https://github.com/simonives/redwrench/issues/53): developer tier's README claim about "account permissions bound the risk" is wrong in both directions
- [#54](https://github.com/simonives/redwrench/issues/54): startup doesn't validate `developer_user` against a NOPASSWD sudoers bypass
- [#55](https://github.com/simonives/redwrench/issues/55): developer tier's charter doesn't state that `cargo`/`npm` execute untrusted network content
- [#56](https://github.com/simonives/redwrench/issues/56): ARCHITECTURE.md describes the pre-#27 `DEVELOPER_TOOLS` gating model, not the current `ROOT_REQUIRED_TOOLS` model
- [#57](https://github.com/simonives/redwrench/issues/57): `no_tier_rule_has_an_empty_description` test skips the Developer tier
- [#58](https://github.com/simonives/redwrench/issues/58): a `custom_rules` allow silently disables that command's tier-hardening denies with no warning
- [#59](https://github.com/simonives/redwrench/issues/59): `custom_rules` command values with surrounding whitespace load successfully but are permanently inert
- [#60](https://github.com/simonives/redwrench/issues/60): `additional_rules`' description-based deduplication could collide across tiers
- [#65](https://github.com/simonives/redwrench/issues/65): test coverage for `systemctl_control` unit-name case-sensitivity
- [#66](https://github.com/simonives/redwrench/issues/66): test coverage for malformed bind-address handling
- [#67](https://github.com/simonives/redwrench/issues/67): test coverage for an unknown top-level `config.toml` field
- [#68](https://github.com/simonives/redwrench/issues/68): evaluate `ProtectSystem=full`/`PrivateTmp=yes` for the systemd unit
- [#69](https://github.com/simonives/redwrench/issues/69): post-install reminder to set a bearer token

### v1.2, packaging and distribution

Builds directly on v1.0's RPM packaging work. Low-to-medium complexity, mostly process and metadata, not new code.

- [#3](https://github.com/simonives/redwrench/issues/3): `systemd-sysext` packaging for immutable Fedora variants
- [#4](https://github.com/simonives/redwrench/issues/4): COPR repository submission

### v2.0, white-hat researcher tier

A fifth policy tier above `developer`, permitting security research and penetration-testing tools (network recon and scanning, password-cracking, web/app testing, wireless tooling, scope confirmed broad and not yet finalised). This is a direct extension of the existing tier ladder itself, which is why it takes the v2.0 slot ahead of the identity/authorisation-layer work below: it's the more natural next step from `developer`, and the tier-charter audit's findings need to inform its design directly rather than being inherited as fresh assumptions.

- [#62](https://github.com/simonives/redwrench/issues/62): the white-hat researcher tier itself, not yet designed, this issue captures the requirement and open questions (tool list, privilege model for raw-socket tools) a design pass needs to resolve
- [#61](https://github.com/simonives/redwrench/issues/61): tier composition can only add capability, never subtract, a hard structural constraint this tier's design needs to either accept or solve first

### v3.0, authorisation depth

Both issues here are labelled `security`, a genuinely new trust and authorisation layer beyond the static, pre-configured tier model, not an extension of it.

- [#5](https://github.com/simonives/redwrench/issues/5): real-time interactive approval workflow (a pending-request-to-phone model)
- [#6](https://github.com/simonives/redwrench/issues/6): deeper Tailscale-specific integration (per-device identity in authorisation)

### v4.0, GUI applications

High complexity (two native apps, KDE and GNOME), lower severity than v2.0/v3.0's tier and authorisation work since this is a convenience layer, not a security boundary. Per the earlier decision on live tier changes: the GUI never gains a live-reload capability of its own, it triggers the headless service to restart and polls to confirm the new tier took effect, the same restart-required security posture v1.0 already established.

- [#30](https://github.com/simonives/redwrench/issues/30): GUI configuration app (toolbar/tray applet), separate from the core server, for both KDE and GNOME

## How this gets maintained

When a new issue is triaged, it gets assigned to a Milestone and the project board's `Release` field with the same version name, and a line added here under the matching theme (or a new theme, if it doesn't fit an existing one). This is a manual habit, not automated tooling, on the view that a roadmap kept by hand stays honest in a way a generated one doesn't.
