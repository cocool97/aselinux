use nom::{
    IResult, Parser,
    character::complete::{space0, space1},
    combinator::{all_consuming, opt},
    error::ErrorKind,
    sequence::preceded,
};

use crate::{
    ParserExt, Result,
    android::{
        MagiskPolicy,
        magiskpolicy::{
            entry::MagiskPolicyEntry,
            rules::{AccessVector, Genfscon, TypeRule, TypeTransition, Xperm},
        },
    },
    common::{AccessVectorKind, parse_selinux_context},
    parsers::{parse_lines, parse_space1_word, parse_word, parse_words_set},
};

/// A parser of textual `magiskpolicy`-generated policies.
pub struct MagiskPolicyParser;

impl ParserExt for MagiskPolicyParser {
    type Output<'r> = MagiskPolicy<'r>;

    fn parse(input: &[u8]) -> Result<Self::Output<'_>> {
        parse_magiskpolicy(str::from_utf8(input)?)
    }
}

fn parse_magiskpolicy(input: &str) -> Result<MagiskPolicy<'_>> {
    let mut policy = MagiskPolicy::default();

    for entry in parse_lines(input, parse_single_magiskpolicy_rule) {
        match entry? {
            MagiskPolicyEntry::Attribute(name) => {
                policy.attributes.insert(name);
            }
            MagiskPolicyEntry::Type { name, attributes } => {
                policy.types.insert(name, attributes);
            }
            MagiskPolicyEntry::Permissive(domain) => {
                policy.permissives.insert(domain);
            }
            MagiskPolicyEntry::AccessVector(rule) => {
                policy
                    .access_vectors
                    .entry(rule.source)
                    .or_default()
                    .insert(rule);
            }
            MagiskPolicyEntry::Xperm(rule) => {
                policy.xperms.entry(rule.source).or_default().insert(rule);
            }
            MagiskPolicyEntry::TypeTransition(rule) => {
                policy
                    .type_transitions
                    .entry(rule.source)
                    .or_default()
                    .insert(rule);
            }
            MagiskPolicyEntry::TypeChange(rule) => {
                policy
                    .type_changes
                    .entry(rule.source)
                    .or_default()
                    .insert(rule);
            }
            MagiskPolicyEntry::TypeMember(rule) => {
                policy
                    .type_members
                    .entry(rule.source)
                    .or_default()
                    .insert(rule);
            }
            MagiskPolicyEntry::Genfscon(statement) => {
                policy.fs_con.insert(statement);
            }
        }
    }

    add_undeclared_types(&mut policy);

    Ok(policy)
}

/// Registers types used in rules but never declared, with no attribute.
///
/// `magiskpolicy --print-rules` declares every attribute, but only the types
/// having at least one attribute. Any name used in a rule that is not a
/// declared attribute is therefore a type.
///
/// Done as a final pass so that it does not depend on the order of the lines.
fn add_undeclared_types<'a>(policy: &mut MagiskPolicy<'a>) {
    let mut used: Vec<&'a str> = Vec::new();

    used.extend(policy.permissives.iter().copied());
    for rule in policy.access_vectors.values().flatten() {
        used.extend([rule.source, rule.target]);
    }
    for rule in policy.xperms.values().flatten() {
        used.extend([rule.source, rule.target]);
    }
    for rule in policy.type_transitions.values().flatten() {
        used.extend([rule.source, rule.target, rule.default]);
    }
    for rule in policy
        .type_changes
        .values()
        .chain(policy.type_members.values())
        .flatten()
    {
        used.extend([rule.source, rule.target, rule.default]);
    }
    used.extend(policy.fs_con.iter().map(|g| g.context.r#type));

    for name in used {
        if !policy.attributes.contains(name) {
            policy.types.entry(name).or_default();
        }
    }
}

fn parse_single_magiskpolicy_rule(input: &str) -> IResult<&str, MagiskPolicyEntry<'_>> {
    // Dispatch on the keyword first, so that a syntax error is reported by the
    // parser of the actual rule kind (with an accurate position), instead of by
    // the last branch of an `alt`.
    let (body, keyword) = parse_word(input)?;
    let (rest, entry) = match keyword {
        "attribute" => parse_attribute_body(body),
        "type" => parse_type_body(body),
        "permissive" => parse_permissive_body(body),
        "allow" => parse_access_vector_body(body, AccessVectorKind::Allow),
        "auditallow" => parse_access_vector_body(body, AccessVectorKind::AuditAllow),
        "dontaudit" => parse_access_vector_body(body, AccessVectorKind::DontAudit),
        "allowxperm" => parse_xperm_body(body, AccessVectorKind::Allow),
        "auditallowxperm" => parse_xperm_body(body, AccessVectorKind::AuditAllow),
        "dontauditxperm" => parse_xperm_body(body, AccessVectorKind::DontAudit),
        "type_transition" => parse_type_transition_body(body),
        "type_change" => parse_type_rule_body
            .map(MagiskPolicyEntry::TypeChange)
            .parse(body),
        "type_member" => parse_type_rule_body
            .map(MagiskPolicyEntry::TypeMember)
            .parse(body),
        "genfscon" => parse_genfscon_body(body),
        // Unknown keyword: report it at the start of the line.
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                ErrorKind::Tag,
            )));
        }
    }?;
    let (rest, _) = all_consuming(space0).parse(rest)?;

    Ok((rest, entry))
}

/// `attribute <name>`
fn parse_attribute_body(input: &str) -> IResult<&str, MagiskPolicyEntry<'_>> {
    parse_space1_word
        .map(MagiskPolicyEntry::Attribute)
        .parse(input)
}

/// `type <name> { <attributes> }`
fn parse_type_body(input: &str) -> IResult<&str, MagiskPolicyEntry<'_>> {
    (parse_space1_word, preceded(space1, parse_words_set))
        .map(|(name, attributes)| MagiskPolicyEntry::Type {
            name,
            attributes: attributes.into_iter().collect(),
        })
        .parse(input)
}

/// `permissive <domain>`
fn parse_permissive_body(input: &str) -> IResult<&str, MagiskPolicyEntry<'_>> {
    parse_space1_word
        .map(MagiskPolicyEntry::Permissive)
        .parse(input)
}

/// `<allow|auditallow|dontaudit> <source> <target> <class> { <perms> }`
fn parse_access_vector_body(
    input: &str,
    kind: AccessVectorKind,
) -> IResult<&str, MagiskPolicyEntry<'_>> {
    (
        parse_space1_word,
        parse_space1_word,
        parse_space1_word,
        preceded(space1, parse_words_set),
    )
        .map(|(source, target, class, perms)| {
            MagiskPolicyEntry::AccessVector(AccessVector {
                kind,
                source,
                target,
                class,
                perms: perms.into_iter().collect(),
            })
        })
        .parse(input)
}

/// `<allowxperm|auditallowxperm|dontauditxperm> <source> <target> <class> <op> { <values> }`
fn parse_xperm_body(input: &str, kind: AccessVectorKind) -> IResult<&str, MagiskPolicyEntry<'_>> {
    (
        parse_space1_word,
        parse_space1_word,
        parse_space1_word,
        parse_space1_word,
        preceded(space1, parse_words_set),
    )
        .map(|(source, target, class, op, values)| {
            MagiskPolicyEntry::Xperm(Xperm {
                kind,
                source,
                target,
                class,
                op,
                values: values.into_iter().collect(),
            })
        })
        .parse(input)
}

/// `<source> <target> <class> <default>`, common to `type_transition`,
/// `type_change` and `type_member`.
fn parse_type_rule_body(input: &str) -> IResult<&str, TypeRule<'_>> {
    (
        parse_space1_word,
        parse_space1_word,
        parse_space1_word,
        parse_space1_word,
    )
        .map(|(source, target, class, default)| TypeRule {
            source,
            target,
            class,
            default,
        })
        .parse(input)
}

/// `type_transition <source> <target> <class> <default> [<name>]`
fn parse_type_transition_body(input: &str) -> IResult<&str, MagiskPolicyEntry<'_>> {
    (parse_type_rule_body, opt(parse_space1_word))
        .map(|(rule, name)| {
            MagiskPolicyEntry::TypeTransition(TypeTransition {
                source: rule.source,
                target: rule.target,
                class: rule.class,
                default: rule.default,
                name,
            })
        })
        .parse(input)
}

/// `genfscon <fs> <path> <context>`
fn parse_genfscon_body(input: &str) -> IResult<&str, MagiskPolicyEntry<'_>> {
    (
        parse_space1_word,
        parse_space1_word,
        preceded(space1, parse_selinux_context),
    )
        .map(|(fs, path, context)| MagiskPolicyEntry::Genfscon(Genfscon { fs, path, context }))
        .parse(input)
}

#[cfg(test)]
mod tests {
    use std::{
        assert_matches,
        collections::{BTreeSet, HashSet},
    };

    use nom::error::ErrorKind;

    use crate::{
        ParserError,
        android::magiskpolicy::{
            entry::MagiskPolicyEntry,
            parser::{parse_magiskpolicy, parse_single_magiskpolicy_rule},
            rules::{AccessVector, TypeRule, Xperm},
        },
        common::AccessVectorKind,
    };

    #[test]
    fn parse_single_attribute() {
        let attribute = "attribute hal_remoteaccess_server";
        let (remaining, entry) =
            parse_single_magiskpolicy_rule(attribute).expect("cannot parse single attribute");

        assert_eq!(remaining, "");
        assert_matches!(
            entry,
            MagiskPolicyEntry::Attribute("hal_remoteaccess_server")
        );
    }

    #[test]
    fn parse_multiple_attribute() {
        let attribute = r"attribute hal_authsecret_server
attribute vndservice_manager_type";
        let policy =
            parse_magiskpolicy(attribute).expect("cannot parse multiple-attributes policy");

        assert_eq!(policy.attributes.len(), 2);
    }

    #[test]
    fn parse_single_type() {
        let attribute = "type aocdump { domain }";
        let (remaining, entry) =
            parse_single_magiskpolicy_rule(attribute).expect("cannot parse single type");

        assert_eq!(remaining, "");
        assert_eq!(
            entry,
            MagiskPolicyEntry::Type {
                name: "aocdump",
                attributes: BTreeSet::from_iter(["domain"])
            }
        );
    }

    #[test]
    fn parse_single_type_multiple_attributes() {
        let attribute = "type mediaserver { domain mlstrustedsubject netdomain binderservicedomain coredomain gpu_sphal_domain }";
        let (remaining, entry) = parse_single_magiskpolicy_rule(attribute)
            .expect("cannot parse single type multiple attributes");

        assert_eq!(remaining, "");
        assert_eq!(
            entry,
            MagiskPolicyEntry::Type {
                name: "mediaserver",
                attributes: BTreeSet::from_iter([
                    "domain",
                    "mlstrustedsubject",
                    "netdomain",
                    "binderservicedomain",
                    "coredomain",
                    "gpu_sphal_domain"
                ])
            }
        );
    }

    #[test]
    fn parse_multiple_types() {
        let attribute = r"type ctl_sigstop_prop { property_type system_property_type system_internal_property_type }
type virtual_camera_exec { file_type exec_type system_file_type }";
        let policy = parse_magiskpolicy(attribute).expect("cannot parse multiple-types policy");

        assert_eq!(policy.types.len(), 2);
    }

    #[test]
    fn parse_single_allow_attribute() {
        let attribute = "allow system_server hal_frp_service service_manager { find }";
        let (remaining, entry) = parse_single_magiskpolicy_rule(attribute)
            .expect("cannot parse single type multiple attributes");

        assert_eq!(remaining, "");
        assert_eq!(
            entry,
            MagiskPolicyEntry::AccessVector(AccessVector {
                kind: AccessVectorKind::Allow,
                source: "system_server",
                target: "hal_frp_service",
                class: "service_manager",
                perms: BTreeSet::from(["find"])
            })
        );
    }

    #[test]
    fn access_vector_perms_are_order_insensitive() {
        let policy = parse_magiskpolicy(
            "allow a b c { read write }\nallow a b c { write read }\nallow a b c { read read write }",
        )
        .expect("cannot parse access vectors");

        let rules = &policy.access_vectors["a"];
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules.iter().next().map(|av| &av.perms),
            Some(&BTreeSet::from(["read", "write"]))
        );
    }

    #[test]
    fn parse_xperm_kinds() {
        for (keyword, expected_kind) in [
            ("allowxperm", AccessVectorKind::Allow),
            ("auditallowxperm", AccessVectorKind::AuditAllow),
            ("dontauditxperm", AccessVectorKind::DontAudit),
        ] {
            let rule = format!("{keyword} untrusted_app device chr_file ioctl {{ 0x5401-0x5402 }}");
            let (remaining, entry) =
                parse_single_magiskpolicy_rule(&rule).expect("cannot parse xperm rule");

            assert_eq!(remaining, "");
            assert_eq!(
                entry,
                MagiskPolicyEntry::Xperm(Xperm {
                    kind: expected_kind,
                    source: "untrusted_app",
                    target: "device",
                    class: "chr_file",
                    op: "ioctl",
                    values: BTreeSet::from_iter(["0x5401-0x5402"]),
                }),
                "wrong kind for `{keyword}`"
            );
        }
    }

    /// Returns `(line, column, kind)` of the syntax error raised by `input`.
    fn syntax_error(input: &str) -> (usize, usize, ErrorKind) {
        match parse_magiskpolicy(input) {
            Err(ParserError::Syntax {
                line, column, kind, ..
            }) => (line, column, kind),
            other => panic!("expected a syntax error, got {other:?}"),
        }
    }

    #[test]
    fn error_points_inside_the_rule_not_at_keyword() {
        // `{` must be followed by a space: the error is on `r`, not on `allow`.
        assert_eq!(
            syntax_error("allow a b c {read}"),
            (1, 14, ErrorKind::MultiSpace)
        );
        // Missing closing brace: reported at end of line.
        assert_eq!(
            syntax_error("attribute ok\nallow a b c { read"),
            (2, 19, ErrorKind::MultiSpace)
        );
    }

    #[test]
    fn error_on_unknown_keyword_and_trailing_garbage() {
        assert_eq!(syntax_error("alow a b c { r }"), (1, 1, ErrorKind::Tag));
        assert_eq!(syntax_error("attribute foo bar"), (1, 15, ErrorKind::Eof));
    }

    #[test]
    fn error_column_counts_chars_not_bytes() {
        // `é` is 2 bytes: a byte-based column would be 14.
        assert_eq!(syntax_error("attribute é x"), (1, 13, ErrorKind::Eof));
    }

    #[test]
    fn parse_type_change_and_type_member() {
        let policy = parse_magiskpolicy(
            "type_change sshd devpts chr_file sshd_devpts\ntype_member a b dir c",
        )
        .expect("cannot parse type_change / type_member");

        assert_eq!(
            policy.type_changes["sshd"],
            HashSet::from([TypeRule {
                source: "sshd",
                target: "devpts",
                class: "chr_file",
                default: "sshd_devpts",
            }])
        );
        assert_eq!(
            policy.type_members["a"],
            HashSet::from([TypeRule {
                source: "a",
                target: "b",
                class: "dir",
                default: "c",
            }])
        );
    }

    #[test]
    fn type_change_has_no_file_name() {
        // Only `type_transition` accepts a trailing file name.
        assert_eq!(
            syntax_error("type_change a b c d name"),
            (1, 21, ErrorKind::Eof)
        );
    }

    #[test]
    fn undeclared_types_are_inferred_from_rules() {
        let policy = parse_magiskpolicy(
            r"attribute domain
type declared { domain }
allow av_source domain file { read }
allowxperm x_source x_target chr_file ioctl { 0x0001 }
type_transition tt_source tt_target file tt_default
type_change tc_source tc_target file tc_default
permissive perm_domain
genfscon proc /x u:object_r:genfs_type:s0",
        )
        .expect("cannot parse policy");

        // Declared attributes are never turned into types.
        assert!(!policy.types.contains_key("domain"));
        assert_eq!(policy.types["declared"], BTreeSet::from(["domain"]));

        for inferred in [
            "av_source",
            "x_source",
            "x_target",
            "tt_source",
            "tt_target",
            "tt_default",
            "tc_source",
            "tc_target",
            "tc_default",
            "perm_domain",
            "genfs_type",
        ] {
            assert_eq!(
                policy.types.get(inferred),
                Some(&BTreeSet::new()),
                "`{inferred}` should be an attribute-less type"
            );
        }
        assert_eq!(policy.types.len(), 12);
    }
}
