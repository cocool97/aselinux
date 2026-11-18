use std::collections::BTreeSet;

use crate::android::magiskpolicy::rules::{
    AccessVector, Genfscon, TypeRule, TypeTransition, Xperm,
};

/// A single line of a `magiskpolicy` policy.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum MagiskPolicyEntry<'a> {
    Attribute(&'a str),
    Type {
        name: &'a str,
        attributes: BTreeSet<&'a str>,
    },
    Permissive(&'a str),
    AccessVector(AccessVector<'a>),
    Xperm(Xperm<'a>),
    TypeTransition(TypeTransition<'a>),
    TypeChange(TypeRule<'a>),
    TypeMember(TypeRule<'a>),
    Genfscon(Genfscon<'a>),
}
