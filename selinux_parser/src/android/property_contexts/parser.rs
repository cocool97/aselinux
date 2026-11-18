use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::space1,
    combinator::{all_consuming, opt, value},
    multi::many1,
    sequence::preceded,
};

use crate::{
    ParserExt, Result,
    android::{PropertyContext, PropertyContexts, PropertyType},
    common::parse_selinux_context,
    parsers::{parse_lines, parse_space1_word, parse_word},
};

/// A parser of Android `property_contexts` files.
pub struct PropertyContextsParser;

impl ParserExt for PropertyContextsParser {
    type Output<'a> = PropertyContexts<'a>;

    fn parse(input: &[u8]) -> Result<Self::Output<'_>> {
        parse_property_contexts(str::from_utf8(input)?)
    }
}

fn parse_property_contexts(input: &str) -> Result<PropertyContexts<'_>> {
    let mut property_contexts = PropertyContexts::default();
    for entry in parse_lines(input, parse_single_property_context) {
        let (property, context) = entry?;
        property_contexts.0.insert(property, context);
    }

    Ok(property_contexts)
}

/// `<name> <context> [<exact|prefix> [<type> [<values>]]]`
fn parse_single_property_context(input: &str) -> IResult<&str, (&str, PropertyContext<'_>)> {
    all_consuming((
        parse_word,
        preceded(space1, parse_selinux_context),
        opt((
            preceded(space1, parse_match),
            opt(preceded(space1, parse_property_type)),
        )),
    ))
    .map(|(property, context, rest)| {
        let (exact, value_type) = rest.unwrap_or_default();
        (
            property,
            PropertyContext {
                context,
                exact,
                value_type,
            },
        )
    })
    .parse(input)
}

/// `exact` or `prefix`: whether the entry only matches the exact name.
fn parse_match(input: &str) -> IResult<&str, bool> {
    alt((value(true, tag("exact")), value(false, tag("prefix")))).parse(input)
}

fn parse_property_type(input: &str) -> IResult<&str, PropertyType<'_>> {
    alt((
        preceded(tag("enum"), many1(parse_space1_word)).map(PropertyType::Enum),
        value(PropertyType::String, tag("string")),
        value(PropertyType::Bool, tag("bool")),
        value(PropertyType::Int, tag("int")),
        value(PropertyType::Uint, tag("uint")),
        value(PropertyType::Double, tag("double")),
        value(PropertyType::Size, tag("size")),
    ))
    .parse(input)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use nom::error::ErrorKind;

    use crate::{
        ParserError,
        android::{PropertyContext, PropertyType},
        common::SELinuxContext,
    };

    use super::{parse_property_contexts, parse_single_property_context};

    fn context(r#type: &str) -> SELinuxContext<'_> {
        SELinuxContext {
            user: "u",
            role: "object_r",
            r#type,
            level: Some("s0"),
        }
    }

    fn parse(line: &str) -> PropertyContext<'_> {
        let (rest, (_, entry)) = parse_single_property_context(line).expect("cannot parse line");
        assert_eq!(rest, "");
        entry
    }

    #[test]
    fn match_and_type_are_optional() {
        assert_eq!(
            parse("log.tag u:object_r:log_tag_prop:s0"),
            PropertyContext {
                context: context("log_tag_prop"),
                exact: false,
                value_type: None,
            }
        );
        assert_eq!(
            parse("ro.adb. u:object_r:adb_prop:s0 prefix"),
            PropertyContext {
                context: context("adb_prop"),
                exact: false,
                value_type: None,
            }
        );
    }

    #[test]
    fn parse_exact_typed_entry() {
        assert_eq!(
            parse("ro.build.version.sdk u:object_r:build_prop:s0 exact int"),
            PropertyContext {
                context: context("build_prop"),
                exact: true,
                value_type: Some(PropertyType::Int),
            }
        );
    }

    #[test]
    fn parse_enum_values() {
        assert_eq!(
            parse("fastbootd.protocol    u:object_r:fastbootd_protocol_prop:s0 exact enum usb tcp")
                .value_type,
            Some(PropertyType::Enum(vec!["usb", "tcp"]))
        );
    }

    #[test]
    fn file_skips_comments_and_indentation() {
        let contexts = parse_property_contexts(
            "# comment\n  # indented comment\n\n  ro.x u:object_r:x_prop:s0 exact bool  \n",
        )
        .expect("cannot parse file");

        assert_eq!(contexts.0.len(), 1);
        assert_eq!(contexts.0["ro.x"].value_type, Some(PropertyType::Bool));
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        for line in [
            "ro.x u:object_r:x_prop:s0 nimportequoi",
            "ro.x u:object_r:x_prop:s0 exact float",
            "ro.x u:object_r:x_prop:s0 exact enum",
            "ro.x u:object_r:x_prop:s0 exact int extra",
        ] {
            assert_matches!(
                parse_property_contexts(line),
                Err(ParserError::Syntax {
                    line: 1,
                    kind: ErrorKind::Eof,
                    ..
                }),
                "`{line}` should be rejected"
            );
        }
    }
}
