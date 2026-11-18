//! Resolution of on-device file paths and property names to `SELinux` contexts.

use regex::Regex;
use selinux_parser::{
    android::PropertyContexts,
    common::{FileContexts, FileType, SELinuxContext},
};

/// Characters making a `file_contexts` path specification a regular expression.
const REGEX_META_CHARS: &[char] = &['.', '^', '$', '?', '*', '+', '|', '[', '(', '{'];

/// Specificity of a `file_contexts` entry, mirroring `fc_sort`: greater is more specific.
///
/// The parser does not keep the file order, so the "last match wins" rule of
/// `libselinux` is approximated by the ordering `fc_sort` applies at build time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Specificity {
    /// No regex meta character at all.
    exact: bool,
    /// Length of the literal prefix before the first meta character.
    stem_len: usize,
    /// Length of the whole specification.
    len: usize,
    /// The entry is restricted to a file type.
    typed: bool,
}

impl Specificity {
    fn of(pattern: &str, file_type: Option<FileType>) -> Self {
        let mut stem_len = 0;
        let mut exact = true;
        let mut chars = pattern.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                chars.next();
            } else if REGEX_META_CHARS.contains(&c) {
                exact = false;
                break;
            }
            stem_len += 1;
        }
        Self {
            exact,
            stem_len,
            len: pattern.len(),
            typed: file_type.is_some(),
        }
    }
}

pub(crate) struct FileContextEntry {
    pub(crate) pattern: &'static str,
    regex: Regex,
    pub(crate) file_type: Option<FileType>,
    pub(crate) context: &'static SELinuxContext<'static>,
    pub(crate) specificity: Specificity,
}

/// Compiled `file_contexts` of a single file.
pub(crate) struct FileContextsIndex {
    pub(crate) entries: Vec<FileContextEntry>,
    /// Patterns the `regex` crate could not compile.
    pub(crate) errors: Vec<String>,
}

impl FileContextsIndex {
    pub(crate) fn new(file_contexts: &'static FileContexts<'static>) -> Self {
        let mut entries = Vec::with_capacity(file_contexts.0.len());
        let mut errors = Vec::new();
        for (pattern, (file_type, context)) in &file_contexts.0 {
            match Regex::new(&format!("^(?:{pattern})$")) {
                Ok(regex) => entries.push(FileContextEntry {
                    pattern,
                    regex,
                    file_type: *file_type,
                    context,
                    specificity: Specificity::of(pattern, *file_type),
                }),
                Err(e) => errors.push(format!("{pattern}: {e}")),
            }
        }
        entries.sort_by_key(|e| e.pattern);
        Self { entries, errors }
    }

    /// Entries matching `path`, restricted to `file_type` when given.
    pub(crate) fn matches<'s>(
        &'s self,
        path: &'s str,
        file_type: Option<FileType>,
    ) -> impl Iterator<Item = &'s FileContextEntry> + 's {
        self.entries.iter().filter(move |e| {
            let type_ok = match (file_type, e.file_type) {
                (Some(wanted), Some(entry)) => wanted == entry,
                _ => true,
            };
            type_ok && e.regex.is_match(path)
        })
    }

    pub(crate) fn for_type<'s>(
        &'s self,
        ty: &'s str,
    ) -> impl Iterator<Item = &'s FileContextEntry> + 's {
        self.entries.iter().filter(move |e| e.context.r#type == ty)
    }
}

/// `property_contexts` of a single file.
pub(crate) struct PropertyContextsIndex {
    /// Sorted by property prefix.
    pub(crate) entries: Vec<(&'static str, &'static SELinuxContext<'static>)>,
}

/// How a `property_contexts` entry matched a property name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PropertyMatch {
    /// The `*` catch-all entry.
    Wildcard,
    Prefix,
    Exact,
}

impl PropertyContextsIndex {
    pub(crate) fn new(property_contexts: &'static PropertyContexts<'static>) -> Self {
        let mut entries: Vec<_> = property_contexts
            .0
            .iter()
            .map(|(k, v)| (*k, &v.context))
            .collect();
        entries.sort_by_key(|(k, _)| *k);
        Self { entries }
    }

    /// Entries matching `property`, with how they matched.
    ///
    /// The `exact` flag is not used yet: every entry is treated as a prefix.
    pub(crate) fn matches<'s>(
        &'s self,
        property: &'s str,
    ) -> impl Iterator<
        Item = (
            PropertyMatch,
            &'static str,
            &'static SELinuxContext<'static>,
        ),
    > + 's {
        self.entries.iter().filter_map(move |(key, context)| {
            let how = if *key == property {
                PropertyMatch::Exact
            } else if *key == "*" {
                PropertyMatch::Wildcard
            } else if property.starts_with(key) {
                PropertyMatch::Prefix
            } else {
                return None;
            };
            Some((how, *key, *context))
        })
    }

    pub(crate) fn for_type<'s>(
        &'s self,
        ty: &'s str,
    ) -> impl Iterator<Item = (&'static str, &'static SELinuxContext<'static>)> + 's {
        self.entries
            .iter()
            .filter(move |(_, c)| c.r#type == ty)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::Specificity;

    #[test]
    fn exact_beats_regex() {
        assert!(
            Specificity::of("/system/bin/sh", None) > Specificity::of("/system/bin(/.*)?", None)
        );
    }

    #[test]
    fn longer_stem_beats_shorter() {
        assert!(Specificity::of("/system/bin/.*", None) > Specificity::of("/system/.*", None));
    }

    #[test]
    fn escaped_chars_are_literal() {
        let s = Specificity::of(r"/build\.prop", None);
        assert!(s.exact);
        assert_eq!(s.stem_len, "/build.prop".len());
    }
}
