use nom::{
    Finish, IResult, Parser,
    bytes::complete::{take_till1, take_while1},
    character::complete::{char, multispace1, space1},
    multi::separated_list1,
    sequence::{delimited, preceded},
};

use crate::{ParserError, Result};

/// Parses every meaningful line of a text file with `parse_line`.
///
/// Blank lines and `#` comments are skipped. Lines are trimmed before being
/// parsed, while errors are still located in the original line.
pub(crate) fn parse_lines<'a, T>(
    input: &'a str,
    mut parse_line: impl FnMut(&'a str) -> IResult<&'a str, T>,
) -> impl Iterator<Item = Result<T>> {
    input.lines().enumerate().filter_map(move |(index, line)| {
        let content = line.trim();
        if content.is_empty() || content.starts_with('#') {
            return None;
        }
        Some(
            parse_line(content)
                .finish()
                .map(|(_, entry)| entry)
                .map_err(|e| ParserError::syntax(index, line, &e)),
        )
    })
}

pub(crate) fn parse_word(input: &str) -> IResult<&str, &str> {
    take_till1(char::is_whitespace).parse(input)
}

/// Parse a word preceded by at least one space
pub(crate) fn parse_space1_word(input: &str) -> IResult<&str, &str> {
    preceded(space1, parse_word).parse(input)
}

/// `{ a b c }`
pub(crate) fn parse_words_set(input: &str) -> IResult<&str, Vec<&str>> {
    delimited(
        char('{'),
        delimited(
            multispace1,
            separated_list1(
                multispace1,
                take_while1(|c: char| !c.is_whitespace() && c != '}'),
            ),
            multispace1,
        ),
        char('}'),
    )
    .parse(input)
}
