# Roadmap

This is the narrative version of RedWrench's release plan. The mechanical version lives in two places kept consistent with this document: [GitHub Milestones](https://github.com/simonives/redwrench/milestones) (issue-level tracking per version) and the [RedWrench Roadmap project board](https://github.com/users/simonives/projects/10) (a release-window view across all open and closed work). If any of the three ever disagree, this file and the Milestones are the source of truth, the board is a view onto them.

## Shipped

**v1.0** ([CHANGELOG](CHANGELOG.md#100---2026-09-10)): the policy engine, four tiers, streaming execution, the audit trail, and capability/policy discovery. Everything the original design spec committed to for a first release, plus the developer tier and the discovery tools, which were added after the initial spec in response to real deployment feedback.

## Planned

Each version below has a theme, a reason several issues belong together, not just a bucket of whatever was open. Ordering follows severity and complexity, not issue number, which is why the GUI theme, floated early as an example of "what a themed release could look like," ended up third rather than second: the authorisation-depth work is more severe (it changes RedWrench's actual trust model) even though the GUI work is comparably complex.

### v1.1, policy engine polish

Low severity, low complexity, coverage and completeness work on an already-functional system. No new capability, just closing gaps.

- [#22](https://github.com/simonives/redwrench/issues/22): hardware inventory commands (`lscpu`, `uname`, `free`, `lsblk`, `df`) added to `safe` tier
- [#35](https://github.com/simonives/redwrench/issues/35): an end-to-end test proving a `ROOT_REQUIRED_TOOLS` member actually stays root under `developer` tier
- [#25](https://github.com/simonives/redwrench/issues/25): `run_command` shouldn't silently block for the full timeout on an unbounded command when no streaming client is attached

### v1.2, packaging and distribution

Builds directly on v1.0's RPM packaging work. Low-to-medium complexity, mostly process and metadata, not new code.

- [#3](https://github.com/simonives/redwrench/issues/3): `systemd-sysext` packaging for immutable Fedora variants
- [#4](https://github.com/simonives/redwrench/issues/4): COPR repository submission

### v2.0, authorisation depth

Both issues here are labelled `security`, a genuinely new trust and authorisation layer beyond the static, pre-configured tier model, not an extension of it. Higher severity and complexity than v3.0's GUI theme, which is why it comes first.

- [#5](https://github.com/simonives/redwrench/issues/5): real-time interactive approval workflow (a pending-request-to-phone model)
- [#6](https://github.com/simonives/redwrench/issues/6): deeper Tailscale-specific integration (per-device identity in authorisation)

### v3.0, GUI applications

High complexity (two native apps, KDE and GNOME), lower severity than v2.0's authorisation work since this is a convenience layer, not a security boundary. Per the earlier decision on live tier changes: the GUI never gains a live-reload capability of its own, it triggers the headless service to restart and polls to confirm the new tier took effect, the same restart-required security posture v1.0 already established.

- [#30](https://github.com/simonives/redwrench/issues/30): GUI configuration app (toolbar/tray applet), separate from the core server, for both KDE and GNOME

## How this gets maintained

When a new issue is triaged, it gets assigned to a Milestone and the project board's `Release` field with the same version name, and a line added here under the matching theme (or a new theme, if it doesn't fit an existing one). This is a manual habit, not automated tooling, on the view that a roadmap kept by hand stays honest in a way a generated one doesn't.
