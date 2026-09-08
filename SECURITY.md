# Security Policy

RedWrench exists to gate arbitrary command execution behind a policy
engine. A bypass of that gate, an argument-injection path into a
structured tool, a way to reach the `unrestricted` tier without
`--i-understand-the-risk`, or anything else that lets a caller do more
than the active tier permits, is a security vulnerability, not an
ordinary bug.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security vulnerability.**

Use [GitHub's private vulnerability reporting](https://github.com/simonives/redwrench/security/advisories/new)
for this repository. This opens a private draft security advisory
visible only to the maintainer until a fix is ready, the standard
coordinated-disclosure path GitHub provides.

If private reporting is ever unavailable, open a regular issue asking
for a private contact channel, without describing the vulnerability
itself, and a way to reach the maintainer directly will be provided.

Please include:

- The specific MCP tool call (tool name and parameters) or config that
  triggers the issue.
- The active policy tier and any custom rules in the config.
- What you expected the policy engine to do, and what it actually did.
- Whether the issue is reachable under `safe`/`standard`, or only under
  `unrestricted` (which is documented as "everything, no filtering", so
  a report there needs a different framing, e.g. an unintended way to
  *reach* `unrestricted` without the risk flag, not "unrestricted allows
  destructive commands", which is its documented, intended behaviour).

## Supported versions

RedWrench is a young project without a formal LTS policy yet. Security
fixes land on the `main` branch; there is no backport policy for older
tagged releases at this stage. This will be revisited once the project
has a release cadence worth maintaining multiple supported versions
against.

## Scope

In scope: the policy engine (`src/policy/`), the executor
(`src/executor.rs`), the MCP transport and auth layer (`src/auth.rs`,
`src/tools/mod.rs`'s `dispatch()`), and every structured tool handler
(`src/tools/*.rs`) for argument-injection, flag-abbreviation bypass, or
policy-evaluation gaps.

Out of scope: vulnerabilities in `dnf`, `systemctl`, `journalctl`, `ping`,
or any other binary RedWrench invokes, report those upstream to the
relevant project. Vulnerabilities that require the `unrestricted` tier
to already be active and acknowledged (that tier's entire purpose is
unfiltered execution) are out of scope unless they demonstrate a way to
reach that tier without the documented gate.

## Disclosure

Once a fix is available, the advisory will be published along with the
release that contains it, credited to the reporter unless anonymity is
requested.
