use std::collections::HashMap;

use crate::common::SELinuxContext;

/// Entries of a `property_contexts` file, keyed by property name or prefix.
#[derive(Debug, Default)]
pub struct PropertyContexts<'a>(pub HashMap<&'a str, PropertyContext<'a>>);

/// `<name> <context> [<exact|prefix> [<type> [<values>]]]`
#[derive(Debug, PartialEq, Eq)]
pub struct PropertyContext<'a> {
    pub context: SELinuxContext<'a>,
    /// Whether the entry only matches the exact property name, rather than every
    /// property starting with it (the default).
    pub exact: bool,
    /// Type of the property value, when given.
    pub value_type: Option<PropertyType<'a>>,
}

/// Type of a property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyType<'a> {
    String,
    Bool,
    Int,
    Uint,
    Double,
    Size,
    /// One of the listed values, in file order.
    Enum(Vec<&'a str>),
}
