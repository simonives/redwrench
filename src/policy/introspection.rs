use super::tiers::{rules_for_tier, TierName};
use super::{Decision, Effect, PolicyEngine, Rule};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RuleDescription {
    pub command: String,
    pub effect: Effect,
    pub description: String,
}

pub fn describe_rules(rules: &[Rule]) -> Vec<RuleDescription> {
    rules
        .iter()
        .map(|r| RuleDescription {
            command: r.command.clone(),
            effect: r.effect.clone(),
            description: r.description.clone(),
        })
        .collect()
}

/// Tiers in strictly increasing capability order. Hand-maintained, same as
/// `rules_for_tier`'s match arm: both need updating together when a tier is
/// added. `Developer` sits between `Standard` and `Unrestricted` because
/// `developer_rules()` extends `standard_rules()` (see `tiers.rs`).
pub fn tier_order() -> &'static [TierName] {
    &[
        TierName::Safe,
        TierName::Standard,
        TierName::Developer,
        TierName::Unrestricted,
    ]
}

/// The full rule set a tier would evaluate against, including custom rules
/// from config (custom rules apply regardless of tier).
pub fn effective_rules_for(tier: &TierName, custom_rules: &[Rule]) -> Vec<Rule> {
    let mut rules = custom_rules.to_vec();
    rules.extend(rules_for_tier(tier));
    rules
}

/// Rules present in `higher`'s effective set whose description does not
/// already appear in `lower`'s.
pub fn additional_rules(lower: &[Rule], higher: &[Rule]) -> Vec<RuleDescription> {
    let lower_descriptions: std::collections::HashSet<&str> =
        lower.iter().map(|r| r.description.as_str()).collect();
    higher
        .iter()
        .filter(|r| !lower_descriptions.contains(r.description.as_str()))
        .map(|r| RuleDescription {
            command: r.command.clone(),
            effect: r.effect.clone(),
            description: r.description.clone(),
        })
        .collect()
}

/// The first (lowest) tier strictly above `from` whose effective rule set
/// (custom rules included) would allow `command`/`args`. `None` means no
/// tier above `from` would allow it either (e.g. a custom `deny` rule
/// blocking the command everywhere, including `unrestricted`).
pub fn lowest_tier_that_would_allow(
    command: &str,
    args: &[String],
    custom_rules: &[Rule],
    from: &TierName,
) -> Option<TierName> {
    let from_index = tier_order().iter().position(|t| t == from)?;
    tier_order()
        .iter()
        .skip(from_index + 1)
        .find(|tier| {
            let engine = PolicyEngine::new(effective_rules_for(tier, custom_rules));
            matches!(engine.evaluate(command, args), Decision::Allowed)
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tiers::{safe_rules, standard_rules};

    #[test]
    fn tier_order_matches_rules_for_tier_variants() {
        assert_eq!(
            tier_order(),
            &[
                TierName::Safe,
                TierName::Standard,
                TierName::Developer,
                TierName::Unrestricted,
            ]
        );
    }

    #[test]
    fn effective_rules_for_layers_custom_rules_before_tier_rules() {
        let custom = vec![Rule {
            command: "rm".to_string(),
            arg_pattern: None,
            effect: Effect::Deny,
            description: "custom: never allow rm".to_string(),
        }];
        let rules = effective_rules_for(&TierName::Unrestricted, &custom);
        // The custom deny must be evaluated before unrestricted's
        // catch-all allow, first-match-wins.
        let engine = PolicyEngine::new(rules);
        assert!(matches!(
            engine.evaluate("rm", &["-rf".to_string(), "/".to_string()]),
            Decision::Denied(_)
        ));
    }

    #[test]
    fn additional_rules_reports_exactly_what_standard_adds_over_safe() {
        let safe = safe_rules();
        let standard = standard_rules();
        let added = additional_rules(&safe, &standard);
        let added_descriptions: std::collections::HashSet<&str> =
            added.iter().map(|r| r.description.as_str()).collect();
        // (issue #26) standard_rules() also restores the unscoped
        // journalctl read safe_rules() no longer allows. (issue #40) it
        // further adds a deny rejecting systemctl start/restart against
        // any .target unit (a structural fix, not a hardcoded name list,
        // after a reopen found eight more shipped equivalents the
        // original five-name list missed), ahead of the existing
        // systemctl start/stop/... allow. So standard adds six rules over
        // safe, not five.
        assert_eq!(added.len(), 6);
        assert!(added_descriptions.contains(
            "reject start/restart against any .target unit (targets group units and can represent boot/shutdown/runlevel states a literal name list cannot fully enumerate; standard tier's lifecycle verbs are scoped to actual services, not targets)"
        ));
        assert!(added_descriptions.contains("start, stop, restart, enable, or disable a unit"));
        assert!(added_descriptions.contains(
            "reject --nogpgcheck/--no-gpgchecks/--repofrompath/--setopt/-c (incl. clustered)/--config/--installroot/--destdir/--downloaddir, including their shortest unambiguous prefixes (bypasses package signature and repository trust, or operates against a different filesystem tree)"
        ));
        assert!(added_descriptions.contains("install, remove, or upgrade a package via dnf"));
        assert!(added_descriptions
            .contains("install, upgrade, check status, or uninstall a package via rpm-ostree"));
        assert!(added_descriptions.contains("read the system journal, unscoped"));
    }

    #[test]
    fn additional_rules_is_empty_between_identical_rule_sets() {
        let safe = safe_rules();
        assert!(additional_rules(&safe, &safe).is_empty());
    }

    #[test]
    fn lowest_tier_that_would_allow_finds_standard_when_safe_denies() {
        // dnf is not in safe_rules() at all.
        let result = lowest_tier_that_would_allow(
            "dnf",
            &["install".to_string(), "htop".to_string()],
            &[],
            &TierName::Safe,
        );
        assert_eq!(result, Some(TierName::Standard));
    }

    #[test]
    fn lowest_tier_that_would_allow_returns_none_when_a_custom_deny_blocks_every_tier() {
        let custom = vec![Rule {
            command: "rm".to_string(),
            arg_pattern: None,
            effect: Effect::Deny,
            description: "custom: never allow rm".to_string(),
        }];
        let result = lowest_tier_that_would_allow(
            "rm",
            &["-rf".to_string(), "/".to_string()],
            &custom,
            &TierName::Safe,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn lowest_tier_that_would_allow_returns_none_when_already_allowed_at_the_highest_tier() {
        // Nothing is above Unrestricted, so scanning "from" Unrestricted
        // finds no candidate tier regardless of what the command is.
        let result = lowest_tier_that_would_allow("anything", &[], &[], &TierName::Unrestricted);
        assert_eq!(result, None);
    }
}
