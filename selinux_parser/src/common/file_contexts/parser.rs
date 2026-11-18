use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::tag,
    character::complete::space1,
    combinator::{all_consuming, opt, value},
    sequence::preceded,
};

use crate::{
    ParserExt, Result,
    common::{FileContexts, FileType, SELinuxContext, parse_selinux_context},
    parsers::{parse_lines, parse_word},
};

pub struct FileContextsParser;

impl ParserExt for FileContextsParser {
    type Output<'a> = FileContexts<'a>;

    fn parse(input: &[u8]) -> crate::Result<Self::Output<'_>> {
        parse_file_contexts(str::from_utf8(input)?)
    }
}

fn parse_file_contexts(input: &str) -> Result<FileContexts<'_>> {
    let mut file_contexts = FileContexts::default();
    for rule in parse_lines(input, parse_single_file_context) {
        let (path, file_type, context) = rule?;
        file_contexts.0.insert(path, (file_type, context));
    }

    Ok(file_contexts)
}

fn parse_file_type(input: &str) -> IResult<&str, FileType> {
    alt((
        value(FileType::Regular, tag("--")),
        value(FileType::Directory, tag("-d")),
        value(FileType::CharDevice, tag("-c")),
        value(FileType::BlockDevice, tag("-b")),
        value(FileType::Symlink, tag("-l")),
        value(FileType::NamedPipe, tag("-p")),
        value(FileType::Socket, tag("-s")),
    ))
    .parse(input)
}

fn parse_single_file_context(
    input: &str,
) -> IResult<&str, (&str, Option<FileType>, SELinuxContext<'_>)> {
    all_consuming((
        parse_word,
        opt(preceded(space1, parse_file_type)),
        preceded(space1, parse_selinux_context),
    ))
    .parse(input)
}

#[cfg(test)]
mod tests {
    use crate::common::{SELinuxContext, file_contexts::parser::parse_single_file_context};

    #[test]
    fn parse_plat_file_contexts_line() {
        let line = "/second_stage_resources u:object_r:tmpfs:s0";

        let (remaining, (path, file_type, context)) =
            parse_single_file_context(line).expect("cannot parse single line");

        assert_eq!(remaining, "");
        assert_eq!(path, "/second_stage_resources");
        assert!(file_type.is_none());
        assert_eq!(
            context,
            SELinuxContext {
                user: "u",
                role: "object_r",
                r#type: "tmpfs",
                level: Some("s0")
            }
        );
    }
}
