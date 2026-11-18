//! Rules of a `magiskpolicy` policy.

use std::collections::BTreeSet;

use crate::common::{AccessVectorKind, SELinuxContext};

/// `<allow|auditallow|dontaudit> <source> <target> <class> { <perms> }`
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct AccessVector<'a> {
    pub kind: AccessVectorKind,
    pub source: &'a str,
    pub target: &'a str,
    pub class: &'a str,
    /// Sorted and deduplicated.
    pub perms: BTreeSet<&'a str>,
}

/// `<allowxperm|auditallowxperm|dontauditxperm> <source> <target> <class> <op> { <values> }`
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct Xperm<'a> {
    pub kind: AccessVectorKind,
    pub source: &'a str,
    pub target: &'a str,
    pub class: &'a str,
    /// Operation the values apply to, e.g. `ioctl`.
    pub op: &'a str,
    /// Values or ranges, e.g. `0x5401-0x5402`; sorted and deduplicated.
    pub values: BTreeSet<&'a str>,
}

/// `type_transition <source> <target> <class> <default> [<name>]`
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct TypeTransition<'a> {
    pub source: &'a str,
    pub target: &'a str,
    pub class: &'a str,
    /// Type of the new object or process.
    pub default: &'a str,
    /// Name of the created object, for name-based transitions.
    pub name: Option<&'a str>,
}

/// `<type_change|type_member> <source> <target> <class> <default>`
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct TypeRule<'a> {
    pub source: &'a str,
    pub target: &'a str,
    pub class: &'a str,
    /// Type of the relabeled or member object.
    pub default: &'a str,
}

/// `genfscon <fs> <path> <context>`
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct Genfscon<'a> {
    pub fs: &'a str,
    /// Path relative to the root of `fs`.
    pub path: &'a str,
    pub context: SELinuxContext<'a>,
}
