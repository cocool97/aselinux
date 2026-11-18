use nom::{
    IResult, Parser, bytes::complete::take_while1, character::complete::char, combinator::opt,
    sequence::preceded,
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SELinuxContext<'a> {
    pub user: &'a str,
    pub role: &'a str,
    pub r#type: &'a str,
    pub level: Option<&'a str>,
}

pub(crate) fn parse_selinux_context(input: &str) -> IResult<&str, SELinuxContext<'_>> {
    (
        parse_ctx_part,
        preceded(char(':'), parse_ctx_part),
        preceded(char(':'), parse_ctx_part),
        opt(preceded(char(':'), parse_level)),
    )
        .map(|(user, role, r#type, level)| SELinuxContext {
            user,
            role,
            r#type,
            level,
        })
        .parse(input)
}

fn parse_ctx_part(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c != ':' && !c.is_whitespace()).parse(input)
}

fn parse_level(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_ascii_alphanumeric() || matches!(c, ':' | ',' | '.' | '-'))
        .parse(input)
}

#[cfg(test)]
mod tests {
    use crate::common::{SELinuxContext, parse_selinux_context};

    #[test]
    fn test_parse_selinux_context() {
        let input = "u:object_r:binderfs_logs_transaction_history:s0";

        let (remaining, ctx) = parse_selinux_context(input).expect("cannot parse context");
        assert_eq!(remaining, "");
        assert_eq!(
            ctx,
            SELinuxContext {
                user: "u",
                role: "object_r",
                r#type: "binderfs_logs_transaction_history",
                level: Some("s0")
            }
        );
    }

    #[test]
    fn test_parse_selinux_context_stops_at_whitespace() {
        // Context without MLS level followed by extra fields (e.g. property_contexts):
        // the type must not swallow the trailing words.
        let input = "u:object_r:x exact bool";

        let (remaining, ctx) = parse_selinux_context(input).expect("cannot parse context");
        assert_eq!(remaining, " exact bool");
        assert_eq!(ctx.r#type, "x");
        assert_eq!(ctx.level, None);
    }

    #[test]
    fn test_parse_selinux_context_rejects_leading_garbage() {
        let input = "-d  u:object_r:x:s0";

        assert!(parse_selinux_context(input).is_err());
    }

    #[test]
    #[should_panic]
    fn test_parse_missing_context_fields() {
        let input = "u:object_r:";

        let _ = parse_selinux_context(input).expect("cannot parse context");
    }
}
