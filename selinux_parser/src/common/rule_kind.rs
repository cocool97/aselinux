/// Kind of an access vector rule.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum AccessVectorKind {
    Allow,
    AuditAllow,
    DontAudit,
}

/// Kind of a type rule, computing the type of a new object or process.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum TypeRuleKind {
    Transition,
    Member,
    Change,
}
