# Tier Charter (draft), independent audit, 2026-09-10

Read-only audit of RedWrench's four policy tiers against their own stated
claims. Nothing in the codebase was modified. Sources read in full:
`src/policy/tiers.rs`, `src/policy/mod.rs`, `src/policy/introspection.rs`,
`src/config.rs`, `src/main.rs`, `src/tools/mod.rs`, `src/tools/run_command.rs`,
`src/executor.rs` (privilege-drop path), `README.md`, `ARCHITECTURE.md`,
`packaging/`.

This document has two jobs. First, state what each tier's boundary *actually*
is, so a new tier planned above `developer` is designed against reality rather
than against the README. Second, list where the implementation and the claim
disagree.

Findings are ranked **CONFIRMED** (the code, regex, or rule ordering was
traced and the gap verified by inspection) or **PLAUSIBLE** (a real concern
whose exploitability depends on the behaviour of an external binary or a
distro default that this audit could not execute; flagged for a live-test
pass, not guessed at).

---

## How the engine actually behaves (facts that govern every tier)

These are properties of `PolicyEngine::evaluate` and `Config::effective_rules`,
not of any one tier. Every charter below depends on them.

1. **First match wins over one flat ordered list.** `evaluate` walks the list
   and returns on the first rule whose command matches exactly and whose
   `arg_pattern` matches. No rule after that one is consulted.
2. **Command matching is exact string equality.** `/usr/bin/ping` matches no
   rule for `ping` and is denied. This fails closed, and it is load-bearing:
   it is the only thing stopping a path-form invocation of a restricted
   binary. It also means a `ROOT_REQUIRED_TOOLS` entry cannot be matched in
   path form (already noted in that constant's doc comment).
3. **Args are joined with a single space and matched as one string.** Token
   boundaries in the joined string always correspond to real argv
   boundaries, so `(?:^|\s)`-anchored denies cannot be evaded by argument
   splitting. The converse is not true: one argv entry containing a space
   presents two apparent tokens to the regex.
4. **A rule with an empty `command` is a wildcard** (`!rule.command.is_empty()`
   guard at `src/policy/mod.rs:40`). Only the `Unrestricted` arm constructs
   one. `Config::load` rejects an empty or whitespace-only `custom_rules`
   command outright (`r.command.trim().is_empty()`), so the hypothesised
   "empty custom rule equals a wildcard under a lower tier" path is **closed**.
5. **Custom rules are prepended ahead of every tier rule**
   (`effective_rules_for`). A custom rule therefore wins against any tier
   rule for the same command, allow or deny.
6. **Tier composition is `lower_rules(); rules.extend(added)`.** Added rules
   land at the *end* of the list. Under first-match-wins this means a higher
   tier can only ever *add allows*; a deny it appends is inert for anything an
   inherited allow already matches.
7. **The privilege drop exists only under `developer`.** `developer_identity`
   is `Some` only when the active tier is exactly `Developer` and startup
   validation passed; `developer_tier_run_as` drops for every command *not* in
   `ROOT_REQUIRED_TOOLS`. Under `safe`, `standard`, and `unrestricted`,
   everything runs as whatever RedWrench runs as (the shipped unit sets
   `User=root`).
8. **The dropped child has no supplementary groups at all.**
   `executor.rs` calls `setgroups(&[])`, then `setgid`, then `setuid`. It never
   calls `initgroups`, so the child carries neither root's groups nor
   `developer_user`'s own. This is stronger isolation than the README claims
   (`docker` or `wheel` membership does not transfer) and simultaneously a
   functional surprise: group-granted access the account has at a normal login
   silently does not apply.

---

## `safe`

### Charter (as implemented)

> **`safe` is local telemetry plus outbound network reach: it may read the
> machine's state and emit packets onto the network, and it may not change
> persistent state on this machine.** It is not a confidentiality boundary,
> and it is not a "no side effects" boundary. Everything it permits runs as
> root, and two of its allowances (`top`, `ping`) reach data and networks
> well outside the machine's own diagnostics.

The honest one-line version for the README: *safe cannot break the box. It can
still read most of what is on it, and it can still talk to the network.*

### Actual rule list, in evaluation order

| # | Effect | Command | Pattern |
|---|---|---|---|
| 1 | deny | `systemctl` | `SYSTEMCTL_HOST_REDIRECT_FLAGS` (`--ho`/`--mac`/`--ro`/`--im` prefixes, `-H`/`-M`) |
| 2 | allow | `systemctl` | `^status` |
| 3 | allow | `systemctl` | `^is-active` |
| 4 | allow | `systemctl` | `^is-enabled` |
| 5 | deny | `journalctl` | `JOURNALCTL_MUTATION_FLAGS` |
| 6 | deny | `journalctl` | `JOURNALCTL_GLOB_UNIT_FLAGS` |
| 7 | allow | `journalctl` | `(?:^|\s)(?:-u\s*\S|--unit(?:=|\s+)\S)` |
| 8 | deny | `ping` | `PING_ABUSE_FLAGS` |
| 9 | allow | `ping` | *(none, unconditional)* |
| 10 | allow | `ip` | `^(addr|route|link)(\s+(show|list|get)(\s.*)?)?$` |
| 11 | allow | `vmstat` | *(none)* |
| 12 | deny | `sar` | `(?:^|\s)-o` |
| 13 | allow | `sar` | *(none)* |
| 14 | allow | `top` | `^-b` |

### Findings

**S1, CONFIRMED. `journalctl`'s unit-scope requirement is satisfiable while
still reading the entire journal, via journalctl's `+` disjunction.**
Rule 7 requires only that a `-u <value>` or `--unit=<value>` appear somewhere in
the joined argument string, and rule 6 rejects only values containing `*`, `?`,
or `[`. `journalctl` treats a bare `+` as an OR between match groups
(journalctl(1), "Matches"), so
`journalctl -u sshd.service + PRIORITY=0 + PRIORITY=1 ... + PRIORITY=7`
carries a literal, glob-free unit scope, passes both denies, matches the allow,
and returns the union, effectively the whole journal. The same shape works with
`_TRANSPORT=` enumerated across its handful of values. This reopens exactly the
exposure issue #26 was filed to close (whole-system journal read at the lowest,
always-on tier), by a different route than the `-u '*'` glob. Regex tracing is
certain; the journalctl `+` semantics are documented but were not executed here,
so confirm the payload live before designing the fix. A structural fix is
probably "the joined argument string must contain no bare `+` token", or better,
stop trying to express journal scoping in a regex at all and have the safe tier
reach `journalctl` only through the structured tool.

**S2, CONFIRMED. `ping -b` (broadcast) is not in `PING_ABUSE_FLAGS`.**
The constant covers `-f`, `--flood`, zero intervals, `-A`, `-l`, `-s`. It does
not cover `-b`, which permits pinging a broadcast address. `ping -b 10.0.0.255`
solicits a reply from every host on the segment per packet, an amplification
DoS in precisely the class `-f` and `-l` were added to close, reachable from the
lowest tier. `-r` (bypass the routing table) and `-d` (`SO_DEBUG`) are likewise
uncovered, though both are far less consequential.

**S3, CONFIRMED (regex) and PLAUSIBLE (exploitability). `PING_ABUSE_FLAGS`
covers exactly one long-option form, and its short-option alternatives cannot
match a long option.** Every alternative except `--flood` has the shape
`(?:^|\s)-[A-Za-z]*X`. Against `--interval 0`, the `(?:^|\s)-` anchor consumes
the first hyphen, `[A-Za-z]*` cannot consume the second, and no match starts at
the second hyphen because it is preceded by `-` rather than whitespace. So
`--interval`, `--preload`, `--size`, and `--adaptive` all bypass the deny while
`--flood` is caught. Whether this is exploitable depends on the installed
`ping`: stock Fedora iputils does not currently accept those long options
(which is presumably why only `--flood` was listed), but busybox `ping`, a
future iputils, or a `ping` shimmed by another package would. The asymmetry
is a latent regression waiting on an upstream change. **Live-test item:** run
`ping --interval 0 127.0.0.1` on the target host and record whether it is
accepted.

**S4, CONFIRMED. `safe` permits arbitrary outbound network contact, which is
a data-egress capability, not a read-only one.** `ping` is allowed
unconditionally against any destination, and `-p <pattern>` (16 bytes of
caller-chosen ICMP payload, not denied) plus caller-chosen destination
hostnames give a low-bandwidth but real exfiltration channel. DNS resolution of
a constructed hostname alone is sufficient. "No mutation of system state" is
true and beside the point; the tier's charter should say what it permits
*outward*, not only what it refuses to change inward.

**S5, CONFIRMED. `top -b -c` at `safe` discloses every process's full command
line, system-wide, as root.** Rule 14 requires only that the argument string
start with `-b`; everything after is unconstrained. `-c` switches to full
command-line display, and credentials passed in argv (a classic and common
mistake) are visible to anyone who can read `/proc`. This is the same
confidentiality class as issue #26, an unscoped whole-system read at the
always-on tier, and it received none of the scoping treatment `journalctl`
did. Note that unlike `journalctl`, root is not required for this:
`/proc/*/cmdline` is world-readable, so the exposure exists regardless of the
run-as identity.

**S6, CONFIRMED. `journalctl --root=<path>` and `--file <path>` are
explicitly allowed at `safe`, while the equivalent `systemctl --root` is
explicitly denied.** `safe_tier_denies_abbreviated_journalctl_mutation_flags`
asserts `--root=/mnt/other -u sshd` is *allowed*. Both flags are reads, so this
is not a mutation gap, but the two commands are governed by opposite policies
for the same concept ("operate against a filesystem tree that is not this
running system"). Either the systemctl deny is over-broad or the journalctl
allow is under-scoped; they cannot both be right. Decide deliberately and
document it, because a new tier will inherit whichever answer stands.

**S7, PLAUSIBLE. `SAR_FILE_OUTPUT_FLAG` may miss a clustered `-o`.** The
pattern is `(?:^|\s)-o`, which requires `o` to be the first character after the
hyphen. `sar` accepts clustered activity letters (`sar -bBdH`), so whether
`sar -uo /tmp/evil.dat 1 1` is parsed as `-u -o file` depends on sysstat's
hand-rolled parser, which appears to special-case `-o` with a token-level
comparison before the clustering loop. If it does cluster, this is an
arbitrary-file-write-as-root primitive at `safe`. **Live-test item.**
Related: `sar -f <file>` (read an arbitrary sa datafile) is allowed and
unremarkable, but should be named in the charter rather than discovered later.

**S8, CONFIRMED (documentation). The README's `safe` row does not mention
the unit-scope requirement for `journalctl`.** It still reads "`journalctl`
reads", which is the pre-issue-#26 behaviour. An operator reading only the
README will be surprised when a bare `journalctl -n 50` is denied at `safe`.
The same row also omits `--image`/`--image-policy` from the listed systemctl
denials, which the constant does cover.

**Checked and clean:** `ip`'s allow is anchored to `^(addr|route|link)`, which
is what prevents `ip -batch <file>` (a full mutation primitive) and every other
pre-subcommand global option from ever reaching a match. This anchoring is
load-bearing and should be commented as such. `ip`'s abbreviated forms (`ip a`,
`ip addr sh`) fail closed. `vmstat`'s option surface is genuinely
report-only, as its comment claims. `top`'s deliberately loose `^-b` is
non-exploitable for the reason its comment gives (argv-only execution, no
shell).

---

## `standard`

### Charter (as implemented)

> **`standard` is root-equivalent code execution with a provenance
> requirement.** It permits changing what runs on the machine now
> (`systemctl` lifecycle verbs) and what is installed on it
> (`dnf`/`rpm-ostree`), and both of those are arbitrary-root-code primitives by
> construction: RPM scriptlets run as root, and systemd units run whatever they
> name. The tier's real guarantee is not "no arbitrary code" but "the code came
> from a signed package in a configured repository, or from a unit file already
> present on this machine."

That reframing matters for the new tier. `standard` is not a small step above
`safe`. It is already the largest single jump in the ladder, and `developer`'s
added shell is arguably a *smaller* increment than `safe` to `standard`.

### Actual rule list (additions, appended after all fourteen `safe` rules)

| # | Effect | Command | Pattern |
|---|---|---|---|
| 15 | allow | `systemctl` | `^(start|stop|restart|enable|disable)` |
| 16 | deny | `dnf` | `DNF_TRUST_BYPASS_FLAGS` (`--nog`/`--repof`/`--set`) |
| 17 | allow | `dnf` | `^(install|remove|upgrade)` |
| 18 | allow | `rpm-ostree` | `^(install|upgrade|status|uninstall)` |
| 19 | allow | `journalctl` | *(none, restores the unscoped read)* |

### Findings

**T1, CONFIRMED. `standard` can reboot, power off, or drop the host to
single-user mode, because targets are units.** `systemctl start reboot.target`,
`poweroff.target`, `halt.target`, `emergency.target`, and `rescue.target` all
match `^start` and are all ordinary service-lifecycle syntax. `systemctl kill`
and `systemctl isolate` were correctly excluded from the verb list, but
`start` reaches the same outcomes. Severity is high and the fix is not obvious
in a regex (a unit-name denylist is brittle); the charter should at minimum
state plainly that `standard` includes "reboot and halt this machine".
Related and cheaper to state: `systemctl stop` or `disable --now` against
`sshd`, `tailscaled`, or `redwrench` itself severs the operator's and the
agent's own access.

**T2, CONFIRMED. `dnf -c`/`--config <file>` is not denied, and defeats the
entire package-trust model that `DNF_TRUST_BYPASS_FLAGS` exists to protect.**
The deny covers `--nog`, `--repof`, and `--set` prefixes only. An alternate
config file can set `gpgcheck=0` and declare arbitrary repositories, achieving
`--nogpgcheck` and `--repofrompath` together. The same applies to
`--installroot=` (operate against another filesystem tree, the exact thing
`systemctl --root` is denied for) and to `--destdir=`/`--downloaddir=` with
`--downloadonly` (write caller-chosen files to a caller-chosen path as
root). At `standard` alone this requires the config file to already exist, so
it is latent. See D2 for why it is not latent at `developer`.
The `^(install|remove|upgrade)` anchor means these flags must appear *after*
the subcommand. dnf accepts global options in that position (argparse,
two-pass), but confirm live. **Live-test item.**

**T3, PLAUSIBLE. `dnf install /path/to/local.rpm` may bypass signature
verification with no denied flag at all.** dnf4's `localpkg_gpgcheck` defaults
to `False`; dnf5 tightened this. On a host where the default is off, installing
a local RPM runs its scriptlets as root with no signature check, and
`^install` matches. Whether this is live depends on the target's dnf major
version and config. **Live-test item:** `dnf config-manager --dump | grep
localpkg_gpgcheck` on the target host.

**T4, CONFIRMED. The `dnf` and `systemctl` allows are prefix matches on
subcommands, not exact matches.** `^(install|remove|upgrade)` matches any
first token *beginning* with those strings (`upgrade-minimal`, and anything a
future dnf adds under those prefixes); `^(start|stop|restart|enable|disable)`
likewise. No currently-shipping verb exploits this, so it is a latent
maintenance hazard rather than a live bug. It does mean the tier's boundary
moves whenever dnf or systemd adds a verb, without anyone editing this
repository. Anchor to `^(install|remove|upgrade)(\s|$)`.

**T5, CONFIRMED. `rpm-ostree status` is a read verb living in a mutation
tier.** It belongs in `safe` by the charter of both tiers. Harmless, but it is
the kind of drift that makes the ladder incoherent over time, and `safe` has no
rpm-ostree allowance at all, which is itself a gap for an ostree host where
`rpm-ostree status` is the primary read-only system-state query.

**T6, CONFIRMED. The `dnf` trust-bypass deny at rule 16 is sound only by
luck of ordering.** It is appended *after* all fourteen `safe` rules, and works
only because `safe` defines no `dnf` allow. Had `safe` allowed `dnf list`
(an entirely reasonable read-only addition someone will eventually propose),
that allow would sit at position 11 or so and the trust-bypass deny at 16 would
become unreachable for any argument string the `safe` allow matched. See X1.

---

## `developer`

### Charter (as implemented)

> **`developer` adds unfiltered code execution as a specific non-root
> account, while leaving every inherited root capability reachable from the
> same session.** The privilege drop bounds what the *nine added tools* can do
> directly. It does not bound what the tier as a whole can do, because the
> agent can freely interleave a dropped `bash` call with a root `dnf` or
> `systemctl` call in the very next MCP request. The correct mental model is
> not "root capabilities plus a sandbox". It is "root capabilities plus a
> writable staging area under an account that root-run tools will happily
> read from."

### Actual rule list (additions, appended after all nineteen `standard` rules)

Nine allows, each `allow(tool, None, ...)`: `bash`, `sh`, `python3`, `gcc`,
`cc`, `node`, `npm`, `cargo`, `make`.

Privilege routing: `developer_tier_run_as` drops to `developer_identity` for
every command **not** in `ROOT_REQUIRED_TOOLS` = { `systemctl`, `journalctl`,
`ping`, `ip`, `vmstat`, `sar`, `top`, `dnf`, `rpm-ostree` }.

### Findings

**D1, CONFIRMED. `ROOT_REQUIRED_TOOLS` is complete but over-inclusive
against its own stated rationale.** Completeness first: the set of commands any
`safe` or `standard` rule names is exactly those nine, so no inherited command
is missing from the list. The doc comment then claims "every one of these needs
real system privilege to do anything useful," which is not true of at least
three. `vmstat`, `sar`, and `top` read world-readable `/proc` and `/var/log/sa`
and work fine unprivileged, and on Fedora `net.ipv4.ping_group_range` defaults
to permitting unprivileged ICMP sockets for all groups, so `ping` typically
does not need root either. Keeping them root is unnecessary privilege for no
functional gain, and it is `top -b -c` running as root that makes S5 worse than
it needs to be. `journalctl` is a partial case (`systemd-journal` group
membership suffices, but the drop clears supplementary groups, see fact 8,
so the group route is unavailable here). **Live-test item:** run each of
`vmstat 1 1`, `sar -u 1 1`, `top -b -n 1`, `ping -c 1 127.0.0.1` as the
configured `developer_user` and record which actually require root.

**D2, CONFIRMED. A root-privilege escalation chain exists from
`developer_user` back to root, using only tier-allowed calls.** Step one: a
dropped `bash` or `python3` call writes a dnf config file anywhere
`developer_user` can write (its own home suffices) declaring a
caller-controlled repo with `gpgcheck=0`. Step two: `run_command dnf install
-c /home/dev/evil.conf pkg`. `dnf` is in `ROOT_REQUIRED_TOOLS`, so it runs as
**root**, `-c` is matched by no deny (T2), and the package's `%post` scriptlet
executes as root. The privilege drop is bypassed entirely, without ever
violating a policy rule. This is the direct answer to the audit question "can
these tools re-invoke a `ROOT_REQUIRED_TOOLS` command in a way that bypasses the
tier's own gating": yes, and the general form is *any root-run tool that accepts
a file path whose contents the dropped user controls*. `dnf -c` is the sharpest
instance; `dnf --installroot`, `journalctl --file`/`--root`, and
`sar -f` are the same shape with lesser payoffs. Closing T2 closes the sharp
edge; the *class* needs a stated rule, for example "no root-run tool may accept
a caller-supplied path argument under `developer`."

**D3, CONFIRMED. The tier's claim that "that account's own Unix permissions
are what bound the risk" is wrong in both directions.** Too generous: D2 shows
root is reachable, and the dropped account can read every world-readable file
on the system, which on a normal Fedora host includes `/etc/passwd`,
`/etc/machine-id`, `/etc/hostname`, all of `/proc/*/cmdline` (see S5), and any
carelessly-permissioned application config. (Checked and clean:
`/etc/redwrench/config.toml` ships `0600 root:root` per `redwrench.spec`, so the
bearer token itself is not readable by the dropped account.) Too restrictive:
because `executor.rs` calls `setgroups(&[])` without `initgroups`, the child has
*no* supplementary groups, so the account's group-granted access, whether a
shared project directory, `systemd-journal`, or `docker`, does not apply. The
README should state both halves. The second half is a security win worth
advertising (`docker` group membership on `developer_user` does not become
root), and a functional caveat operators will otherwise debug the hard way.

**D4, CONFIRMED. Startup validation checks only `uid != 0`.** A
`developer_user` with a *user-named* `NOPASSWD` sudoers entry defeats the tier
completely, and nothing at startup notices. Group-based sudoers rules
(`%wheel`) happen to be neutralised by the `setgroups(&[])` behaviour above,
but that is incidental, not designed. At minimum, warn at startup if
`sudo -l -U <user>` reports anything, or document the requirement explicitly.

**D5, CONFIRMED (an inherent property, not a bug). `cargo` and `npm`
fetch and execute untrusted network content as part of ordinary operation.**
`cargo build` runs `build.rs` from every dependency; `npm install` runs
`preinstall`/`install`/`postinstall` lifecycle scripts. Both execute as
`developer_user` with network access. This is not fixable at the policy layer
and should not be treated as a defect. It does mean the tier's real charter is
"arbitrary code from the public package ecosystems, running as
`developer_user`", which is a materially stronger statement than "a shell and a
compiler" and belongs in the README verbatim.

**D6, CONFIRMED (documentation). `ARCHITECTURE.md` still describes the
pre-issue-#27 gating.** Lines 68 and 69 read: "`dispatch` decides when to pass
it (a `DEVELOPER_TOOLS` command on a server with a resolved identity)". The
code inverted this to a `ROOT_REQUIRED_TOOLS` stays-root allowlist, which is
the whole point of the fix. `ARCHITECTURE.md`'s "Adding a new tool" step 5
repeats the stale model ("needs its name in that file's `DEVELOPER_TOOLS` list
too, that list, not the rule itself, is what `dispatch` matches"), which will
lead the next contributor to reintroduce the original bug's premise.

**D7, CONFIRMED (trivial). `no_tier_rule_has_an_empty_description` iterates
`[Safe, Standard, Unrestricted]` and skips `Developer`.**

---

## `unrestricted`

### Charter (as implemented)

> **`unrestricted` is remote code execution as root, with an audit log.** It
> is one wildcard rule and no privilege drop. Its gate is a deliberateness
> gate, not a security control.

Rule list: one `Rule { command: "", arg_pattern: None, effect: Allow }`.

### Findings

**U1, CONFIRMED. The `--i-understand-the-risk` gate itself is complete for
the tier, and the empty-command bypass is closed.** Both paths that can select
the tier are gated: writing it (`main.rs`, the `Config::SetTier` arm) and
loading it at startup (`run_server`, checked after `Config::load` and before
the server is constructed). `Config::load` rejects an empty or whitespace-only
custom-rule command, so the hypothesised "layer an empty-command wildcard under
`safe`" path does not exist. The specific question the audit brief raised
resolves in the code's favour.

**U2, CONFIRMED. The tier's *behaviour* is nonetheless reachable without the
flag, via `custom_rules`.** `tier = "safe"` plus a single
`[[custom_rules]] command = "bash", effect = "allow"` yields unfiltered root
code execution: custom rules are prepended ahead of every tier rule, `bash`
with no `arg_pattern` matches any argv, and `developer_identity` is `None` under
`safe`, so it runs as root with no privilege drop. No warning is printed, no
flag is required, and the server reports its tier as `safe`. The same holds for
`sudo`, `env`, `find`, `perl`, or any other interpreter-shaped binary. The
`--i-understand-the-risk` flag guards the *word* `unrestricted`, not the
capability. If the flag is meant to guarantee anything, startup needs to warn
(or refuse) when a custom allow grants a shell-class command under a tier whose
charter excludes it, and the same check would catch the more common operator
error of a custom allow silently neutralising a tier hardening deny (X2).

**U3, CONFIRMED. `unrestricted` does not inherit `developer`'s privilege
drop, by design, and the ladder is therefore not monotonic in one respect.**
Moving from `developer` to `unrestricted` *adds* commands and simultaneously
*removes* the only isolation mechanism in the system. This is documented in the
config comment and the design spec's non-goals, and it is defensible, but it is
the single most important fact for anyone designing a fifth tier: capability
order (`tier_order()`) and privilege order are not the same axis, and
`introspection`'s "would be allowed at: <tier>" suggestion reasons only about
the former.

---

## Cross-tier composition

**X1, CONFIRMED. The extend-and-append composition means a higher tier can
never constrain a lower tier's allow.** `standard_rules()` is
`safe_rules()` then `extend`; `developer_rules()` is `standard_rules()` then
`extend`. Because evaluation is first-match-wins, any deny a higher tier
appends is unreachable for argument strings an inherited allow already matches.
Today this is latent, since no tier appends a deny that overlaps an inherited
allow (T6 explains why the `dnf` deny survives), but it is a hard structural
constraint on the planned fifth tier: **a tier above `developer` can add
capabilities and cannot subtract any.** If the new tier needs to narrow
anything below it (a plausible requirement for, say, a "release" or "CI" tier
that adds container control but removes the ability to halt the host), the
composition model has to change first. Either denies get prepended rather than
appended, or the engine gets an explicit priority ordering, or tiers stop being
strictly nested.

**X2, CONFIRMED. A custom `allow` silently disables every tier hardening
deny for that command.** `effective_rules_for` prepends custom rules, so
`[[custom_rules]] command = "ping", effect = "allow"` at `safe` reinstates
`ping -f`, `-A`, `-l`, `-s`, and every zero-interval form that
`PING_ABUSE_FLAGS` exists to block. The prepend order is correct and
deliberate (it is what makes custom *denies* work at all, see the Critical fix
note in `config.rs`), but the consequence for custom *allows* is documented
nowhere. An operator writing "allow ping" means "let the agent ping". They get
"let the agent flood-ping".

**X3, CONFIRMED (minor). A `custom_rules` command with surrounding
whitespace loads successfully and is permanently inert.** `Config::load`
validates with `r.command.trim().is_empty()` but stores `r.command` untrimmed,
and `evaluate` compares with exact equality. `command = " ping"` therefore
passes validation and never matches anything. It fails closed, so it is a
usability bug rather than a security one, but it is the same "a security
control silently disappears" failure mode that `deny_unknown_fields` was added
to prevent.

**X4, CONFIRMED (minor). `additional_rules` deduplicates by description
string.** Two rules with identical descriptions across tiers would collapse in
the capability-discovery output. No current pair collides; a new tier that
copies a description verbatim would.

---

## Overall assessment

The four tiers' actual behaviour matches their stated guarantees at the level
the guarantees are written, and diverges once the guarantees are read the way
an operator would read them. `safe` genuinely does not mutate local state, and
every finding against it (S1 to S7) is either a confidentiality gap, an
outbound side effect, or a flag class the abuse-flag constants did not
anticipate, which is to say the tier's charter is stated on the wrong axis:
it describes what the tier cannot write rather than what it can read and emit.
`standard` is described as service and package management and is in fact
root-equivalent code execution with a provenance requirement, with a reachable
reboot and halt primitive (T1) and a trust-model hole (`-c`, T2) sitting beside
the flags that were carefully closed. `developer`'s central claim, that the
dropped account's own permissions bound the risk, is the one that does not
survive contact: the privilege drop is correctly implemented and genuinely
strong at the process level (fact 8), but the tier leaves root-run tools
reachable in the same session that accept paths the dropped user controls,
giving a clean escalation back to root (D2). `unrestricted`'s flag gate is
complete for the tier name and irrelevant to the capability, which
`custom_rules` grants without it (U2). None of this reads as carelessness; the
codebase's comment density and its history of closed bypasses show real
adversarial effort. The pattern in what remains is consistent and worth naming
for the next tier's design: the hardening has been argument-shaped (deny the
dangerous flag) where the boundaries are actually capability-shaped (this tool,
run as root, accepts a caller-controlled path). Regex denies over the full flag
surface of general-purpose Unix binaries are a treadmill, and three of the
findings here are simply the next flag nobody had reached yet. A fifth tier
will be more defensible if its boundary is drawn at which identity a command
runs as and which paths it may be handed, rather than at which flags it may not
receive. And whatever that tier is, X1 says it can only add.
