//! A project: one policy and any number of `*_contexts` files.
//!
//! Parsed structures borrow their source text, so file contents (and the parsed
//! structures) are leaked to get `'static` data. Removing a file from the
//! project therefore does not free its memory.

use std::path::{Path, PathBuf};

use anyhow::Context;
use selinux_parser::{
    ParserExt,
    android::{MagiskPolicyParser, PropertyContextsParser},
    common::{FileContextsParser, FileType, SELinuxContext},
};

use crate::{
    policy_index::{Genfs, PolicyIndex},
    resolve::{FileContextEntry, FileContextsIndex, PropertyContextsIndex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileKind {
    MagiskPolicy,
    FileContexts,
    PropertyContexts,
}

impl FileKind {
    pub(crate) const ALL: [Self; 3] = [
        Self::MagiskPolicy,
        Self::FileContexts,
        Self::PropertyContexts,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::MagiskPolicy => "magisk_policy",
            Self::FileContexts => "file_contexts",
            Self::PropertyContexts => "property_contexts",
        }
    }

    /// Guesses the kind of a file from its name.
    pub(crate) fn detect(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if name.contains("file_contexts") {
            Some(Self::FileContexts)
        } else if name.contains("property_contexts") {
            Some(Self::PropertyContexts)
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("te"))
            || name.contains("magisk")
            || name.contains("rules")
        {
            Some(Self::MagiskPolicy)
        } else {
            None
        }
    }
}

/// Name of a file as shown to the user: its file name, or the whole path if it has none.
pub(crate) fn display_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Where a loaded file comes from.
pub(crate) struct SourceFile {
    pub(crate) path: PathBuf,
    /// [`display_name`] of `path`, leaked so that it can be referenced by [`Origin`].
    pub(crate) name: &'static str,
}

impl SourceFile {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            name: Box::leak(display_name(path).into_boxed_str()),
        }
    }
}

pub(crate) struct LoadedPolicy {
    pub(crate) source: SourceFile,
    pub(crate) index: PolicyIndex,
}

pub(crate) struct LoadedFileContexts {
    pub(crate) source: SourceFile,
    pub(crate) index: FileContextsIndex,
}

pub(crate) struct LoadedPropertyContexts {
    pub(crate) source: SourceFile,
    pub(crate) index: PropertyContextsIndex,
}

/// A parsed and indexed file, ready to be added to a [`Project`].
pub(crate) enum LoadedFile {
    Policy(LoadedPolicy),
    FileContexts(LoadedFileContexts),
    PropertyContexts(LoadedPropertyContexts),
}

impl LoadedFile {
    /// Short description of the file content, for logs.
    pub(crate) fn summary(&self) -> String {
        match self {
            Self::Policy(p) => format!(
                "{}: {} types, {} attributes, {} rules",
                p.source.name,
                p.index.policy().types.len(),
                p.index.policy().attributes.len(),
                p.index.rule_count
            ),
            Self::FileContexts(fc) => format!(
                "{}: {} entries, {} invalid regex",
                fc.source.name,
                fc.index.entries.len(),
                fc.index.errors.len()
            ),
            Self::PropertyContexts(pc) => {
                format!("{}: {} entries", pc.source.name, pc.index.entries.len())
            }
        }
    }
}

/// Reads, parses and indexes `path` as `kind`. Meant to run off the UI thread.
pub(crate) fn load_file(path: &Path, kind: FileKind) -> anyhow::Result<LoadedFile> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    parse(
        kind,
        SourceFile::new(path),
        Box::leak(content.into_boxed_str()),
    )
    .with_context(|| format!("{} is not a valid {}", path.display(), kind.label()))
}

/// Parses and indexes `content` as `kind`.
fn parse(kind: FileKind, source: SourceFile, content: &'static str) -> anyhow::Result<LoadedFile> {
    Ok(match kind {
        FileKind::MagiskPolicy => {
            let policy = MagiskPolicyParser::parse(content.as_bytes())?;
            LoadedFile::Policy(LoadedPolicy {
                source,
                index: PolicyIndex::new(Box::leak(Box::new(policy))),
            })
        }
        FileKind::FileContexts => {
            let parsed = FileContextsParser::parse(content.as_bytes())?;
            LoadedFile::FileContexts(LoadedFileContexts {
                source,
                index: FileContextsIndex::new(Box::leak(Box::new(parsed))),
            })
        }
        FileKind::PropertyContexts => {
            let parsed = PropertyContextsParser::parse(content.as_bytes())?;
            LoadedFile::PropertyContexts(LoadedPropertyContexts {
                source,
                index: PropertyContextsIndex::new(Box::leak(Box::new(parsed))),
            })
        }
    })
}

/// Where a resolved context comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Origin {
    FileContexts(&'static str),
    PropertyContexts(&'static str),
    /// `genfscon` of the given filesystem.
    Genfscon(&'static str),
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileContexts(name) | Self::PropertyContexts(name) => f.write_str(name),
            Self::Genfscon(fs) => write!(f, "genfscon ({fs})"),
        }
    }
}

/// A labeling entry (`file_contexts`, `property_contexts` or `genfscon`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Candidate {
    pub(crate) origin: Origin,
    /// Regex, property prefix or genfs path of the entry.
    pub(crate) pattern: &'static str,
    pub(crate) file_type: Option<FileType>,
    pub(crate) context: &'static SELinuxContext<'static>,
}

impl Candidate {
    fn file(source: &SourceFile, entry: &FileContextEntry) -> Self {
        Self {
            origin: Origin::FileContexts(source.name),
            pattern: entry.pattern,
            file_type: entry.file_type,
            context: entry.context,
        }
    }

    fn property(
        source: &SourceFile,
        key: &'static str,
        context: &'static SELinuxContext<'static>,
    ) -> Self {
        Self {
            origin: Origin::PropertyContexts(source.name),
            pattern: key,
            file_type: None,
            context,
        }
    }

    fn genfs(genfs: Genfs) -> Self {
        Self {
            origin: Origin::Genfscon(genfs.fs),
            pattern: genfs.path,
            file_type: None,
            context: genfs.context,
        }
    }
}

#[derive(Default)]
pub(crate) struct Project {
    policy: Option<LoadedPolicy>,
    file_contexts: Vec<LoadedFileContexts>,
    property_contexts: Vec<LoadedPropertyContexts>,
    /// Bumped on every change, so that views can invalidate cached results.
    generation: u64,
}

impl Project {
    pub(crate) fn policy(&self) -> Option<&LoadedPolicy> {
        self.policy.as_ref()
    }

    /// Index of the loaded policy, if any.
    pub(crate) fn index(&self) -> Option<&PolicyIndex> {
        self.policy.as_ref().map(|p| &p.index)
    }

    pub(crate) fn file_contexts(&self) -> &[LoadedFileContexts] {
        &self.file_contexts
    }

    pub(crate) fn property_contexts(&self) -> &[LoadedPropertyContexts] {
        &self.property_contexts
    }

    /// Changes whenever the project content changes.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Adds a loaded file, replacing the current policy if it is one.
    pub(crate) fn insert(&mut self, file: LoadedFile) {
        match file {
            LoadedFile::Policy(policy) => self.policy = Some(policy),
            LoadedFile::FileContexts(fc) => self.file_contexts.push(fc),
            LoadedFile::PropertyContexts(pc) => self.property_contexts.push(pc),
        }
        self.generation += 1;
    }

    pub(crate) fn remove_policy(&mut self) {
        self.policy = None;
        self.generation += 1;
    }

    pub(crate) fn remove_file_contexts(&mut self, index: usize) {
        self.file_contexts.remove(index);
        self.generation += 1;
    }

    pub(crate) fn remove_property_contexts(&mut self, index: usize) {
        self.property_contexts.remove(index);
        self.generation += 1;
    }

    /// Contexts applying to an on-device file `path`, winner first.
    ///
    /// `genfscon` statements take precedence over `file_contexts` on pseudo filesystems.
    pub(crate) fn resolve_path(&self, path: &str, file_type: Option<FileType>) -> Vec<Candidate> {
        let mut from_fc: Vec<_> = self
            .file_contexts
            .iter()
            .flat_map(|fc| {
                fc.index
                    .matches(path, file_type)
                    .map(|e| (e.specificity, Candidate::file(&fc.source, e)))
            })
            .collect();
        from_fc.sort_by_key(|(specificity, _)| std::cmp::Reverse(*specificity));

        self.index()
            .into_iter()
            .flat_map(|index| index.genfs_resolve(path))
            .map(Candidate::genfs)
            .chain(from_fc.into_iter().map(|(_, c)| c))
            .collect()
    }

    /// Contexts applying to a property `name`, winner first.
    pub(crate) fn resolve_property(&self, name: &str) -> Vec<Candidate> {
        let mut matches: Vec<_> = self
            .property_contexts
            .iter()
            .flat_map(|pc| {
                pc.index.matches(name).map(|(how, key, context)| {
                    (
                        (how, key.len()),
                        Candidate::property(&pc.source, key, context),
                    )
                })
            })
            .collect();
        matches.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
        matches.into_iter().map(|(_, c)| c).collect()
    }

    /// `file_contexts` entries more specific than `input`, i.e. whose specification
    /// (with regex escapes removed) starts with it, sorted.
    pub(crate) fn path_completions(&self, input: &str) -> Vec<Candidate> {
        let mut completions: Vec<_> = self
            .file_contexts
            .iter()
            .flat_map(|fc| {
                fc.index
                    .entries
                    .iter()
                    .filter(|e| extends(&e.pattern.replace('\\', ""), input))
                    .map(|e| Candidate::file(&fc.source, e))
            })
            .collect();
        completions.sort_by_key(|c| c.pattern);
        completions
    }

    /// Property entries more specific than `input`, i.e. starting with it, sorted.
    pub(crate) fn property_completions(&self, input: &str) -> Vec<Candidate> {
        let mut completions: Vec<_> = self
            .property_contexts
            .iter()
            .flat_map(|pc| {
                pc.index
                    .entries
                    .iter()
                    .filter(|(key, _)| extends(key, input))
                    .map(|(key, context)| Candidate::property(&pc.source, key, context))
            })
            .collect();
        completions.sort_by_key(|c| c.pattern);
        completions
    }

    /// Every file, property and genfs entry labeled with `ty`.
    pub(crate) fn labels_of_type(&self, ty: &str) -> Vec<Candidate> {
        let files = self.file_contexts.iter().flat_map(|fc| {
            fc.index
                .for_type(ty)
                .map(|e| Candidate::file(&fc.source, e))
        });
        let properties = self.property_contexts.iter().flat_map(|pc| {
            pc.index
                .for_type(ty)
                .map(|(key, context)| Candidate::property(&pc.source, key, context))
        });
        let genfs = self
            .index()
            .into_iter()
            .flat_map(|index| index.genfs_for_type(ty))
            .map(Candidate::genfs);
        files.chain(properties).chain(genfs).collect()
    }
}

/// Whether `entry` strictly extends `input`.
fn extends(entry: &str, input: &str) -> bool {
    entry.len() > input.len() && entry.starts_with(input)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use selinux_parser::common::FileType;

    use super::{Candidate, FileKind, Origin, Project, SourceFile, load_file, parse};

    const POLICY: &str = "\
attribute domain
attribute proc_type
type shell { domain }
type proc_meminfo { proc_type }
genfscon proc / u:object_r:proc:s0
genfscon proc /meminfo u:object_r:proc_meminfo:s0
";

    const FILE_CONTEXTS: &str = r"
/system(/.*)?           u:object_r:system_file:s0
/system/bin/sh      --  u:object_r:shell_exec:s0
/system/bin(/.*)?       u:object_r:system_bin_file:s0
/build\.prop            u:object_r:rootfs:s0
";

    const PROPERTY_CONTEXTS: &str = "
*               u:object_r:default_prop:s0
log.            u:object_r:log_prop:s0
log.tag         u:object_r:log_tag_prop:s0
logd.           u:object_r:logd_prop:s0
";

    fn project() -> Project {
        let mut project = Project::default();
        for (kind, content) in [
            (FileKind::MagiskPolicy, POLICY),
            (FileKind::FileContexts, FILE_CONTEXTS),
            (FileKind::PropertyContexts, PROPERTY_CONTEXTS),
        ] {
            let source = SourceFile::new(Path::new(kind.label()));
            project.insert(parse(kind, source, content).expect("invalid test data"));
        }
        project
    }

    fn types(candidates: &[Candidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.context.r#type).collect()
    }

    fn patterns(candidates: &[Candidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.pattern).collect()
    }

    #[test]
    fn most_specific_file_context_wins() {
        let project = project();
        assert_eq!(
            types(&project.resolve_path("/system/bin/sh", None)),
            ["shell_exec", "system_bin_file", "system_file"]
        );
        assert_eq!(
            types(&project.resolve_path("/system/bin/ls", None))[0],
            "system_bin_file"
        );
    }

    #[test]
    fn file_type_filters_typed_entries() {
        let project = project();
        let candidates = project.resolve_path("/system/bin/sh", Some(FileType::Directory));
        assert_eq!(types(&candidates)[0], "system_bin_file");
    }

    #[test]
    fn genfscon_wins_on_pseudo_filesystems() {
        let project = project();
        let candidates = project.resolve_path("/proc/meminfo", None);
        assert_eq!(candidates[0].origin, Origin::Genfscon("proc"));
        assert_eq!(types(&candidates), ["proc_meminfo", "proc"]);
    }

    #[test]
    fn longest_property_prefix_wins_and_wildcard_comes_last() {
        let project = project();
        assert_eq!(
            types(&project.resolve_property("log.tag.Foo")),
            ["log_tag_prop", "log_prop", "default_prop"]
        );
        assert_eq!(
            types(&project.resolve_property("unknown")),
            ["default_prop"]
        );
    }

    #[test]
    fn completions_list_more_specific_entries() {
        let project = project();
        assert_eq!(
            patterns(&project.property_completions("log")),
            ["log.", "log.tag", "logd."]
        );
        assert_eq!(patterns(&project.property_completions("log.tag")), [""; 0]);
        // Regex escapes are ignored.
        assert_eq!(
            patterns(&project.path_completions("/build.")),
            [r"/build\.prop"]
        );
    }

    #[test]
    fn labels_of_type_include_genfscon() {
        let project = project();
        assert_eq!(
            patterns(&project.labels_of_type("proc_meminfo")),
            ["/meminfo"]
        );
    }

    #[test]
    fn every_change_bumps_the_generation() {
        let mut project = project();
        let before = project.generation();
        project.remove_file_contexts(0);
        assert!(project.generation() > before);
    }

    /// Loads the sample files of the repository, if present.
    fn sample_project() -> Option<Project> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let files = [
            ("rules.te", FileKind::MagiskPolicy),
            ("selinux/plat_file_contexts", FileKind::FileContexts),
            ("selinux/plat_property_contexts", FileKind::PropertyContexts),
        ];
        if !files.iter().all(|(f, _)| root.join(f).exists()) {
            return None;
        }
        let mut project = Project::default();
        for (file, kind) in files {
            project.insert(load_file(&root.join(file), kind).expect("cannot load sample"));
        }
        Some(project)
    }

    /// Smoke test on real device files, skipped when they are absent.
    #[test]
    fn sample_files_resolution() {
        let Some(project) = sample_project() else {
            return;
        };
        assert_eq!(
            types(&project.resolve_path("/system/bin/init", None))[0],
            "init_exec"
        );
        assert_eq!(
            types(&project.resolve_property("ro.build.version.sdk"))[0],
            "build_prop"
        );
    }
}
