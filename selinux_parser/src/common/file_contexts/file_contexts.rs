use std::collections::HashMap;

use crate::common::SELinuxContext;

#[derive(Debug, Default)]
pub struct FileContexts<'a>(pub HashMap<&'a str, (Option<FileType>, SELinuxContext<'a>)>);

/// Optional file type restriction of a `file_contexts` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// `--`
    Regular,
    /// `-d`
    Directory,
    /// `-c`
    CharDevice,
    /// `-b`
    BlockDevice,
    /// `-l`
    Symlink,
    /// `-p`
    NamedPipe,
    /// `-s`
    Socket,
}
