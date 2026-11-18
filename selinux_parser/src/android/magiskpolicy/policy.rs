use std::collections::{BTreeSet, HashMap, HashSet};

use crate::android::magiskpolicy::rules::{
    AccessVector, Genfscon, TypeRule, TypeTransition, Xperm,
};

/// A policy printed by `magiskpolicy --print-rules`.
///
/// Rules are indexed by their source.
#[derive(Debug, Default)]
pub struct MagiskPolicy<'a> {
    /// Declared attributes.
    pub attributes: HashSet<&'a str>,
    /// Every type of the policy, mapped to its attributes.
    ///
    /// `magiskpolicy --print-rules` never declares types without attributes:
    /// those are inferred from the rules using them, and map to an empty set.
    pub types: HashMap<&'a str, BTreeSet<&'a str>>,
    /// `allow`, `auditallow` and `dontaudit` rules.
    pub access_vectors: HashMap<&'a str, HashSet<AccessVector<'a>>>,
    /// `allowxperm`, `auditallowxperm` and `dontauditxperm` rules.
    pub xperms: HashMap<&'a str, HashSet<Xperm<'a>>>,
    pub type_transitions: HashMap<&'a str, HashSet<TypeTransition<'a>>>,
    pub type_changes: HashMap<&'a str, HashSet<TypeRule<'a>>>,
    pub type_members: HashMap<&'a str, HashSet<TypeRule<'a>>>,
    /// Permissive domains.
    pub permissives: HashSet<&'a str>,
    /// `genfscon` statements.
    pub fs_con: HashSet<Genfscon<'a>>,
}
