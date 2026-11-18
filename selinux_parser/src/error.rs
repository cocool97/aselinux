use nom::Offset;

/// Main Result type used all over the crate
pub type Result<T> = std::result::Result<T, ParserError>;

const SNIPPET_MAX_CHARS: usize = 80;

/// Custom error type, wrapping all underlying errors
#[derive(Debug, thiserror::Error)]
pub enum ParserError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("syntax error line {line}:{column} ({kind:?}) : {snippet:?}")]
    Syntax {
        /// 1-based line number.
        line: usize,
        /// 1-based column, counted in characters (not bytes).
        column: usize,
        kind: nom::error::ErrorKind,
        /// The offending line, or for long lines, a window of at most
        /// 80 characters around the error, with `…` marking truncated ends.
        snippet: String,
    },
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
}

impl ParserError {
    /// Builds a [`ParserError::Syntax`] from a nom error raised while parsing `line`.
    pub(crate) fn syntax(line_index: usize, line: &str, error: &nom::error::Error<&str>) -> Self {
        let byte_offset = line.offset(error.input).min(line.len());
        let char_index = line
            .get(..byte_offset)
            .map_or(0, |before| before.chars().count());

        Self::Syntax {
            line: line_index + 1,
            column: char_index + 1,
            kind: error.code,
            snippet: snippet_around(line, char_index),
        }
    }
}

/// Returns `line` as-is if it is short enough, otherwise a window of
/// [`SNIPPET_MAX_CHARS`] characters containing `char_index`.
fn snippet_around(line: &str, char_index: usize) -> String {
    let len = line.chars().count();
    if len <= SNIPPET_MAX_CHARS {
        return line.to_owned();
    }

    let end = (char_index + SNIPPET_MAX_CHARS / 2)
        .max(SNIPPET_MAX_CHARS)
        .min(len);
    let start = end - SNIPPET_MAX_CHARS;

    let mut snippet = String::with_capacity(SNIPPET_MAX_CHARS + 2 * '…'.len_utf8());
    if start > 0 {
        snippet.push('…');
    }
    snippet.extend(line.chars().skip(start).take(end - start));
    if end < len {
        snippet.push('…');
    }
    snippet
}

#[cfg(test)]
mod tests {
    use super::{SNIPPET_MAX_CHARS, snippet_around};

    #[test]
    fn short_line_is_kept_whole() {
        assert_eq!(snippet_around("allow a b c { r }", 3), "allow a b c { r }");
    }

    #[test]
    fn long_line_error_at_start() {
        let line = "x".repeat(200);
        let snippet = snippet_around(&line, 0);

        assert!(!snippet.starts_with('…'));
        assert!(snippet.ends_with('…'));
        assert_eq!(snippet.chars().count(), SNIPPET_MAX_CHARS + 1);
    }

    #[test]
    fn long_line_error_at_end_is_visible() {
        let line = format!("{}ERR", "x".repeat(200));
        let snippet = snippet_around(&line, 200);

        assert!(snippet.starts_with('…'));
        assert!(snippet.ends_with("ERR"));
        assert_eq!(snippet.chars().count(), SNIPPET_MAX_CHARS + 1);
    }

    #[test]
    fn long_line_error_in_middle_is_centered() {
        let line = format!("{}ERR{}", "a".repeat(100), "b".repeat(100));
        let snippet = snippet_around(&line, 100);

        assert!(snippet.starts_with('…') && snippet.ends_with('…'));
        assert!(snippet.contains("ERR"));
    }
}
