//! Lookup structures built on top of a parsed [`MagiskPolicy`].

use std::collections::{BTreeSet, HashMap, HashSet};

use selinux_parser::{
    android::{AccessVector, MagiskPolicy},
    common::{AccessVectorKind, SELinuxContext},
};

/// Mount points of pseudo filesystems labeled through `genfscon`, most specific first.
const GENFS_MOUNTS: &[(&str, &str)] = &[
    ("/sys/kernel/debug/tracing", "tracefs"),
    ("/sys/kernel/tracing", "tracefs"),
    ("/sys/kernel/debug", "debugfs"),
    ("/sys/fs/selinux", "selinuxfs"),
    ("/sys/fs/bpf", "bpf"),
    ("/sys/fs/pstore", "pstore"),
    ("/sys/fs/fuse/connections", "fusectl"),
    ("/sys/fs/cgroup", "cgroup2"),
    ("/sys", "sysfs"),
    ("/proc", "proc"),
    ("/config", "configfs"),
    ("/dev/binderfs", "binder"),
    ("/dev/cpuset", "cgroup"),
    ("/dev/memcg", "cgroup"),
];

/// Side of an access vector: the source domain or the target object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Side {
    Source,
    Target,
}

/// Which side(s) of an access vector the queried name must be on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Direction {
    Source,
    Target,
    Both,
}

impl Direction {
    fn includes(self, side: Side) -> bool {
        matches!(
            (self, side),
            (Self::Both, _) | (Self::Source, Side::Source) | (Self::Target, Side::Target)
        )
    }
}

/// Which access vector kinds a query accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct KindFilter {
    pub(crate) allow: bool,
    pub(crate) auditallow: bool,
    pub(crate) dontaudit: bool,
}

impl Default for KindFilter {
    fn default() -> Self {
        Self {
            allow: true,
            auditallow: true,
            dontaudit: true,
        }
    }
}

impl KindFilter {
    fn accepts(self, kind: AccessVectorKind) -> bool {
        match kind {
            AccessVectorKind::Allow => self.allow,
            AccessVectorKind::AuditAllow => self.auditallow,
            AccessVectorKind::DontAudit => self.dontaudit,
        }
    }
}

/// Parameters of a rule lookup.
#[derive(Debug)]
pub(crate) struct RuleQuery<'q> {
    /// Type or attribute name.
    pub(crate) subject: &'q str,
    pub(crate) direction: Direction,
    /// Also match rules written on the attributes of `subject`.
    pub(crate) expand_subject: bool,
    /// Expand attributes on the other side of the rule into their concrete types.
    pub(crate) expand_other: bool,
    pub(crate) kinds: KindFilter,
    /// Accepted classes, matched with [`term_matches`]; empty means any.
    pub(crate) classes: &'q [&'q str],
    /// Required permissions (any of them), matched with [`term_matches`]; empty means any.
    pub(crate) perms: &'q [&'q str],
}

impl RuleQuery<'_> {
    fn accepts(&self, rule: &AccessVector<'_>) -> bool {
        self.kinds.accepts(rule.kind)
            && (self.classes.is_empty() || self.classes.iter().any(|c| term_matches(c, rule.class)))
            && (self.perms.is_empty()
                || self
                    .perms
                    .iter()
                    .any(|p| rule.perms.iter().any(|perm| term_matches(p, perm))))
    }
}

/// Matches a user search term against a class or permission name.
///
/// A term matches names starting with it (`exec` matches `execute` and
/// `execute_no_trans`); a trailing `$` requires an exact match (`file$`).
pub(crate) fn term_matches(term: &str, name: &str) -> bool {
    match term.strip_suffix('$') {
        Some(exact) => name == exact,
        None => name.starts_with(term),
    }
}

/// A name on one side of a [`RuleHit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HitName {
    pub(crate) name: &'static str,
    /// Attribute the rule is actually written on, when it differs from `name`.
    pub(crate) via: Option<&'static str>,
}

/// A rule matching a [`RuleQuery`], with both sides resolved for display.
#[derive(Clone, Debug)]
pub(crate) struct RuleHit {
    pub(crate) rule: &'static AccessVector<'static>,
    /// Side of the rule on which the queried subject was found.
    pub(crate) side: Side,
    pub(crate) source: HitName,
    pub(crate) target: HitName,
}

impl RuleHit {
    fn new(
        rule: &'static AccessVector<'static>,
        side: Side,
        subject: HitName,
        other: HitName,
    ) -> Self {
        let (source, target) = match side {
            Side::Source => (subject, other),
            Side::Target => (other, subject),
        };
        Self {
            rule,
            side,
            source,
            target,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameKind {
    Type,
    Attribute,
    Unknown,
}

/// A `type_transition` rule.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Transition {
    pub(crate) source: &'static str,
    pub(crate) target: &'static str,
    pub(crate) class: &'static str,
    pub(crate) default: &'static str,
    pub(crate) name: Option<&'static str>,
}

/// A `genfscon` statement.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Genfs {
    pub(crate) fs: &'static str,
    pub(crate) path: &'static str,
    pub(crate) context: &'static SELinuxContext<'static>,
}

pub(crate) struct PolicyIndex {
    policy: &'static MagiskPolicy<'static>,
    /// Access vectors by source name.
    by_source: HashMap<&'static str, Vec<&'static AccessVector<'static>>>,
    /// Access vectors by target name.
    by_target: HashMap<&'static str, Vec<&'static AccessVector<'static>>>,
    /// attribute -> sorted concrete types
    attribute_types: HashMap<&'static str, Vec<&'static str>>,
    /// Every attribute name, sorted.
    pub(crate) attributes: Vec<&'static str>,
    /// Every type and attribute name, sorted.
    pub(crate) names: Vec<&'static str>,
    /// Every object class used in access vectors, sorted.
    pub(crate) classes: Vec<&'static str>,
    pub(crate) rule_count: usize,
}

impl PolicyIndex {
    pub(crate) fn new(policy: &'static MagiskPolicy<'static>) -> Self {
        let mut by_source: HashMap<_, Vec<_>> = HashMap::new();
        let mut by_target: HashMap<_, Vec<_>> = HashMap::new();
        let mut classes = BTreeSet::new();
        let mut rule_count = 0;
        for rule in policy.access_vectors.values().flatten() {
            by_source.entry(rule.source).or_default().push(rule);
            by_target.entry(rule.target).or_default().push(rule);
            classes.insert(rule.class);
            rule_count += 1;
        }

        let mut attribute_types: HashMap<_, Vec<_>> = HashMap::new();
        for (ty, attributes) in &policy.types {
            for attribute in attributes {
                attribute_types.entry(*attribute).or_default().push(*ty);
            }
        }
        for types in attribute_types.values_mut() {
            types.sort_unstable();
        }

        let mut attributes: Vec<_> = policy.attributes.iter().copied().collect();
        attributes.sort_unstable();
        let mut names: Vec<_> = policy
            .types
            .keys()
            .chain(&policy.attributes)
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        names.sort_unstable();

        Self {
            policy,
            by_source,
            by_target,
            attribute_types,
            attributes,
            names,
            classes: classes.into_iter().collect(),
            rule_count,
        }
    }

    pub(crate) fn policy(&self) -> &'static MagiskPolicy<'static> {
        self.policy
    }

    pub(crate) fn name_kind(&self, name: &str) -> NameKind {
        if self.policy.attributes.contains(name) {
            NameKind::Attribute
        } else if self.policy.types.contains_key(name) {
            NameKind::Type
        } else {
            NameKind::Unknown
        }
    }

    /// Attributes of a concrete type (empty for attributes and unknown names).
    pub(crate) fn attributes_of(&self, ty: &str) -> impl Iterator<Item = &'static str> + '_ {
        self.policy
            .types
            .get(ty)
            .into_iter()
            .flat_map(|attributes| attributes.iter().copied())
    }

    /// Concrete types carrying `attribute`.
    pub(crate) fn types_of(&self, attribute: &str) -> &[&'static str] {
        self.attribute_types
            .get(attribute)
            .map_or(&[], Vec::as_slice)
    }

    pub(crate) fn is_permissive(&self, ty: &str) -> bool {
        self.policy.permissives.contains(ty)
    }

    /// The `'static` version of a known type or attribute name.
    fn intern(&self, name: &str) -> Option<&'static str> {
        self.policy
            .types
            .get_key_value(name)
            .map(|(k, _)| *k)
            .or_else(|| self.policy.attributes.get(name).copied())
    }

    /// Names rules may be written on to apply to `subject`: itself, then its
    /// attributes when `expand` is set.
    fn rule_names(
        &self,
        subject: &'static str,
        expand: bool,
    ) -> impl Iterator<Item = &'static str> + '_ {
        std::iter::once(subject).chain(
            expand
                .then(|| self.attributes_of(subject))
                .into_iter()
                .flatten(),
        )
    }

    /// `name` itself, or its concrete types when it is an attribute and `expand` is set.
    fn expand(&self, name: &'static str, expand: bool) -> Vec<HitName> {
        if expand && self.policy.attributes.contains(name) {
            self.types_of(name)
                .iter()
                .map(|ty| HitName {
                    name: ty,
                    via: Some(name),
                })
                .collect()
        } else {
            vec![HitName { name, via: None }]
        }
    }

    /// Access vectors having `name` on `side`.
    fn rules_with(&self, side: Side, name: &str) -> &[&'static AccessVector<'static>] {
        let index = match side {
            Side::Source => &self.by_source,
            Side::Target => &self.by_target,
        };
        index.get(name).map_or(&[], Vec::as_slice)
    }

    /// Access vectors matching `query`, sorted by side, source, target and class.
    pub(crate) fn query(&self, query: &RuleQuery<'_>) -> Vec<RuleHit> {
        let Some(subject) = self.intern(query.subject) else {
            return Vec::new();
        };
        let mut hits = Vec::new();
        for side in [Side::Source, Side::Target] {
            if !query.direction.includes(side) {
                continue;
            }
            for rule_name in self.rule_names(subject, query.expand_subject) {
                let subject = HitName {
                    name: subject,
                    via: (rule_name != subject).then_some(rule_name),
                };
                for rule in self
                    .rules_with(side, rule_name)
                    .iter()
                    .filter(|r| query.accepts(r))
                {
                    let other = match side {
                        Side::Source => rule.target,
                        Side::Target => rule.source,
                    };
                    hits.extend(
                        self.expand(other, query.expand_other)
                            .into_iter()
                            .map(|other| RuleHit::new(rule, side, subject, other)),
                    );
                }
            }
        }
        hits.sort_by_key(|h| (h.side, h.source.name, h.target.name, h.rule.class));
        hits
    }

    /// `type_transition` rules where `name` (or one of its attributes) appears anywhere.
    pub(crate) fn transitions_involving(&self, name: &str) -> Vec<Transition> {
        let Some(subject) = self.intern(name) else {
            return Vec::new();
        };
        let names: HashSet<&str> = self.rule_names(subject, true).collect();
        let mut transitions: Vec<_> = self
            .policy
            .type_transitions
            .values()
            .flatten()
            .map(|t| Transition {
                source: t.source,
                target: t.target,
                class: t.class,
                default: t.default,
                name: t.name,
            })
            .filter(|t| {
                [t.source, t.target, t.default]
                    .iter()
                    .any(|n| names.contains(n))
            })
            .collect();
        transitions.sort_by_key(|t| (t.source, t.target, t.class, t.default));
        transitions
    }

    /// `genfscon` statements labeling with `ty`.
    pub(crate) fn genfs_for_type(&self, ty: &str) -> Vec<Genfs> {
        let mut entries: Vec<_> = self.genfs().filter(|g| g.context.r#type == ty).collect();
        entries.sort_by_key(|g| (g.fs, g.path));
        entries
    }

    /// `genfscon` statements applying to the on-device `path`, most specific first.
    pub(crate) fn genfs_resolve(&self, path: &str) -> Vec<Genfs> {
        let Some((fs, relative)) =
            GENFS_MOUNTS
                .iter()
                .find_map(|(mount, fs)| match path.strip_prefix(mount)? {
                    "" => Some((*fs, "/")),
                    rest if rest.starts_with('/') => Some((*fs, rest)),
                    _ => None,
                })
        else {
            return Vec::new();
        };
        let mut entries: Vec<_> = self
            .genfs()
            .filter(|g| g.fs == fs && relative.starts_with(g.path))
            .collect();
        entries.sort_by_key(|g| std::cmp::Reverse(g.path.len()));
        entries
    }

    fn genfs(&self) -> impl Iterator<Item = Genfs> + '_ {
        self.policy.fs_con.iter().map(|g| Genfs {
            fs: g.fs,
            path: g.path,
            context: &g.context,
        })
    }
}

#[cfg(test)]
mod tests {
    use selinux_parser::{ParserExt, android::MagiskPolicyParser};

    use super::{Direction, HitName, KindFilter, PolicyIndex, RuleQuery, Side, term_matches};

    const POLICY: &str = "\
attribute domain
attribute exec_type
type shell { domain }
type app { domain }
type shell_exec { exec_type }
allow shell shell_exec file { execute read }
allow domain exec_type file { getattr }
dontaudit app shell_exec file { execute }
type_transition shell shell_exec process app
";

    fn index() -> PolicyIndex {
        let policy = MagiskPolicyParser::parse(POLICY.as_bytes()).expect("invalid test policy");
        PolicyIndex::new(Box::leak(Box::new(policy)))
    }

    fn query(subject: &str, direction: Direction) -> RuleQuery<'_> {
        RuleQuery {
            subject,
            direction,
            expand_subject: true,
            expand_other: false,
            // Only `allow` rules, unless a test opts into the other kinds.
            kinds: KindFilter {
                allow: true,
                auditallow: false,
                dontaudit: false,
            },
            classes: &[],
            perms: &[],
        }
    }

    fn named(name: &'static str, via: Option<&'static str>) -> HitName {
        HitName { name, via }
    }

    #[test]
    fn target_query_follows_subject_attributes() {
        let hits = index().query(&query("shell_exec", Direction::Target));
        let sides: Vec<_> = hits.iter().map(|h| (h.source, h.target)).collect();
        assert_eq!(
            sides,
            [
                (
                    named("domain", None),
                    named("shell_exec", Some("exec_type"))
                ),
                (named("shell", None), named("shell_exec", None)),
            ]
        );
    }

    #[test]
    fn subject_attributes_can_be_ignored() {
        let mut q = query("shell_exec", Direction::Target);
        q.expand_subject = false;
        let hits = index().query(&q);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source, named("shell", None));
    }

    #[test]
    fn other_side_attributes_expand_to_types() {
        let mut q = query("shell_exec", Direction::Target);
        q.expand_other = true;
        let sources: Vec<_> = index().query(&q).iter().map(|h| h.source).collect();
        assert_eq!(
            sources,
            [
                named("app", Some("domain")),
                named("shell", None),
                named("shell", Some("domain")),
            ]
        );
    }

    #[test]
    fn filters_apply_to_kind_class_and_perms() {
        let index = index();
        let mut q = query("shell_exec", Direction::Target);
        q.perms = &["exec"];
        assert_eq!(index.query(&q).len(), 1);

        q.kinds.dontaudit = true;
        assert_eq!(index.query(&q).len(), 2);

        q.classes = &["process"];
        assert!(index.query(&q).is_empty());
    }

    #[test]
    fn source_query_includes_rules_on_attributes() {
        let hits = index().query(&query("shell", Direction::Both));
        let targets: Vec<_> = hits.iter().map(|h| (h.side, h.target.name)).collect();
        assert_eq!(
            targets,
            [(Side::Source, "exec_type"), (Side::Source, "shell_exec")]
        );
    }

    #[test]
    fn unknown_subject_has_no_rules() {
        assert!(index().query(&query("nope", Direction::Both)).is_empty());
    }

    #[test]
    fn transitions_involve_every_position() {
        let index = index();
        assert_eq!(index.transitions_involving("shell").len(), 1);
        assert_eq!(index.transitions_involving("shell_exec").len(), 1);
        assert_eq!(index.transitions_involving("app").len(), 1);
        // An attribute only matches statements written on itself.
        assert!(index.transitions_involving("domain").is_empty());
    }

    #[test]
    fn term_is_a_prefix() {
        assert!(term_matches("cre", "create"));
        assert!(term_matches("exec", "execute_no_trans"));
        assert!(term_matches("file", "filesystem"));
        assert!(!term_matches("trans", "execute_no_trans"));
    }

    #[test]
    fn dollar_forces_exact_match() {
        assert!(term_matches("file$", "file"));
        assert!(!term_matches("file$", "filesystem"));
    }
}
