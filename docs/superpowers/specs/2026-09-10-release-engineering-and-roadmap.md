# RedWrench Release Engineering and Roadmap, Design Spec

**Date:** 2026-09-10
**Status:** Approved for implementation

## Summary

RedWrench has no version history, no packaged releases, and no visible roadmap. `Cargo.toml` is still `0.1.0`, there are no git tags and no GitHub Releases, the release pipeline (`release.yml`) produces only a `.tar.gz`, and the "RedWrench Roadmap" GitHub Project board exists but is stale (missing four of the seven currently open issues, none of its items have a `Release` value set, and its `Release` field has no `v1.0` option). This spec makes the project's release state legible, both to Simon and to anyone else looking at the repository: what version it is, what's already shipped, what's coming next, and roughly when.

## Decisions

**Version policy.** Cut `v1.0.0` now. The functional work for a v1.0 is complete: the original design spec's own v1.0 non-goals (Tailscale identity, interactive approval, `systemd-sysext` packaging, COPR submission, a GUI) are exactly the items still open in the backlog, deliberately deferred from day one, not gaps in what was promised. The three other open issues at the time of this decision (#22, #25, #35) are enhancements and coverage gaps on an already-functional system, not missing v1.0 functionality, and do not block the tag. From `v1.0.0` onward, standard semver: a breaking change to the MCP tool surface, the config schema, or the CLI requires a major bump; internal refactors do not.

**Changelog.** `CHANGELOG.md` in Keep-a-Changelog format, backfilled with a `v1.0.0` entry summarising what shipped. Maintained going forward as part of each release's checklist.

**RPM packaging.** `cargo-generate-rpm` added to `release.yml`, producing a real `.rpm` from `Cargo.toml` metadata (a new `[package.metadata.generate-rpm]` section), uploaded alongside the existing tarball on every tagged release. A real `.spec` file (needed for COPR/SRPM builds) is separate, later work under issue #4, not built now.

**Roadmap, kept consistent across three surfaces.** GitHub Milestones and the "RedWrench Roadmap" Project board's `Release` single-select field use identical version names. `ROADMAP.md` gives the narrative (why this grouping, what each version's theme is) and links to both. Concretely:

- The board's `Release` field gains `v1.0` and `v3.0` options (currently only has `v1.1`, `v1.2`, `v2.0`).
- The board's five already-closed items (#2, #7, #8, #9, #10, all pre-v1.0 hardening work) get `Release: v1.0` and `Status: Done`.
- The four issues currently missing from the board (#22, #25, #30, #35) are added.
- GitHub Milestones are created matching every board `Release` value (`v1.0`, `v1.1`, `v1.2`, `v2.0`, `v3.0`); every issue, open and closed, gets assigned to the milestone matching its board `Release` value.

**Version-to-issue mapping**, grouped by theme, ordered by severity and complexity rather than issue number:

| Version | Theme | Issues | Why |
|---|---|---|---|
| v1.0 | (already shipped) | #2, #7, #8, #9, #10 (closed) | Retroactive, for a complete history |
| v1.1 | Policy engine polish | #22, #35, #25 | Low severity, low complexity, coverage/completeness work on an already-functional system |
| v1.2 | Packaging and distribution | #3, #4 | Low-to-medium complexity, extends the RPM work this spec adds |
| v2.0 | Authorisation depth | #5, #6 | Both `security`-labelled: a genuinely new trust/authorisation layer beyond static tiers, higher severity and complexity than the GUI theme |
| v3.0 | GUI applications | #30 | High complexity (two native apps), but lower severity than v2.0's security-labelled work, so it sits behind it despite being named first as an illustrative example during design |

**Repo page clarity.** A version badge in `README.md` reading the latest GitHub Release (`https://img.shields.io/github/v/release/simonives/redwrench`), a prominent link to the Releases page, and the install section updated to offer the `.rpm` download alongside build-from-source once it exists.

## Non-goals

- **The COPR submission itself** (issue #4) and **a real `.spec` file**. This spec only adds a `.rpm` artifact to GitHub Releases; COPR is separate, later work.
- **Re-litigating the version-to-issue mapping's theme groupings** beyond what's decided above. If a future issue doesn't cleanly fit an existing theme, that's a call for whoever triages it then, not something this spec tries to anticipate.
- **Automating the Milestone/Project-board sync.** This is a one-time manual reconciliation plus a going-forward habit (assign both fields when triaging a new issue), not a bot or CI job.

## Implementation notes

- Cargo.toml version bump and the `[package.metadata.generate-rpm]` section, `CHANGELOG.md`, `ROADMAP.md`, and the README changes are code/doc changes, going through the normal branch-PR-CI-merge flow.
- The GitHub Milestone creation, Project board field/item updates, and issue-to-milestone assignments are direct GitHub API/CLI operations, not code changes, executed directly rather than through a PR.
- Actually cutting the `v1.0.0` tag (which triggers `release.yml` and produces the first public release) is a distinct, separate step from merging the above changes, and needs explicit confirmation before it happens: it is genuinely public and harder to cleanly undo than a branch merge.
