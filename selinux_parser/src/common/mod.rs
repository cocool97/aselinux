//! Formats and structures shared by Android and Linux policies.

mod file_contexts;
mod rule_kind;
mod selinux_context;

pub use file_contexts::{FileContexts, FileContextsParser, FileType};
pub use rule_kind::{AccessVectorKind, TypeRuleKind};
pub use selinux_context::SELinuxContext;

pub(crate) use selinux_context::parse_selinux_context;
