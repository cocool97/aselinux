pub mod android;
pub mod common;
mod error;
mod parser_ext;

/// Internal module offering a collection of basic parsers.
pub(crate) mod parsers;

pub use error::{ParserError, Result};
pub use parser_ext::ParserExt;
