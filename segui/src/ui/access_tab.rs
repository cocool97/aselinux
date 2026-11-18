//! "Path → access" and "Property → access" tabs: which domains can access an
//! on-device object.

use eframe::egui::{self, RichText};
use selinux_parser::common::FileType;

use super::{
    Nav, WARN_COLOR,
    query::{Cached, HitsKey, QueryOptions},
    widgets::{candidates_grid, file_type_label, options_ui, rules_table, scroll_area, type_link},
};
use crate::{
    policy_index::{Direction, RuleHit},
    project::{Candidate, Project},
};

/// What a tab resolves: on-device file paths or property names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Mode {
    Path,
    Property,
}

/// Class and permission filters answering a common question.
struct Preset {
    label: &'static str,
    classes: &'static str,
    perms: &'static str,
}

const PATH_PRESETS: &[Preset] = &[
    Preset {
        label: "read",
        classes: "file, dir, lnk_file, chr_file, blk_file",
        perms: "read, open",
    },
    Preset {
        label: "write",
        classes: "file, dir, chr_file, blk_file",
        perms: "write, append, add_name, create",
    },
    Preset {
        label: "execute",
        classes: "file",
        perms: "execute, execute_no_trans, entrypoint",
    },
];

const PROPERTY_PRESETS: &[Preset] = &[
    Preset {
        label: "read",
        classes: "file",
        perms: "read, open",
    },
    Preset {
        label: "write (set)",
        classes: "property_service",
        perms: "set",
    },
];

/// File type filter choices, `None` meaning any type.
const FILE_TYPES: [Option<FileType>; 8] = [
    None,
    Some(FileType::Regular),
    Some(FileType::Directory),
    Some(FileType::CharDevice),
    Some(FileType::BlockDevice),
    Some(FileType::Symlink),
    Some(FileType::NamedPipe),
    Some(FileType::Socket),
];

impl Mode {
    fn prompt(self) -> &'static str {
        match self {
            Self::Path => "Path on the device:",
            Self::Property => "Property name:",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Path => "/system/bin/logcat",
            Self::Property => "ro.build.version.sdk",
        }
    }

    fn presets(self) -> &'static [Preset] {
        match self {
            Self::Path => PATH_PRESETS,
            Self::Property => PROPERTY_PRESETS,
        }
    }

    /// Message explaining why nothing can be resolved, if so.
    fn missing_files(self, project: &Project) -> Option<&'static str> {
        match self {
            Self::Path if project.file_contexts().is_empty() && project.index().is_none() => {
                Some("No file_contexts or policy loaded.")
            }
            Self::Property if project.property_contexts().is_empty() => {
                Some("No property_contexts loaded.")
            }
            _ => None,
        }
    }

    /// Entries applying to `input`, winner first.
    fn resolve(
        self,
        project: &Project,
        input: &str,
        file_type: Option<FileType>,
    ) -> Vec<Candidate> {
        match self {
            Self::Path => project.resolve_path(input, file_type),
            Self::Property => project.resolve_property(input),
        }
    }

    /// Entries more specific than `input`.
    fn completions(self, project: &Project, input: &str) -> Vec<Candidate> {
        match self {
            Self::Path => project.path_completions(input),
            Self::Property => project.property_completions(input),
        }
    }
}

/// Name of a file type filter, with its `file_contexts` flag.
fn file_type_choice_label(file_type: Option<FileType>) -> &'static str {
    match file_type {
        None => "any type",
        Some(FileType::Regular) => "file (--)",
        Some(FileType::Directory) => "directory (-d)",
        Some(FileType::CharDevice) => "character device (-c)",
        Some(FileType::BlockDevice) => "block device (-b)",
        Some(FileType::Symlink) => "symlink (-l)",
        Some(FileType::NamedPipe) => "named pipe (-p)",
        Some(FileType::Socket) => "socket (-s)",
    }
}

/// Key of cached resolutions: project generation, input and file type filter.
type ResolveKey = (u64, String, Option<FileType>);

pub(crate) struct AccessTab {
    mode: Mode,
    input: String,
    file_type: Option<FileType>,
    /// Index of the candidate whose type is looked up.
    selected: usize,
    options: QueryOptions,
    text_filter: String,
    candidates: Cached<ResolveKey, Vec<Candidate>>,
    /// Entries more specific than the input.
    completions: Cached<ResolveKey, Vec<Candidate>>,
    hits: Cached<HitsKey, Vec<RuleHit>>,
}

impl AccessTab {
    pub(crate) fn new(mode: Mode) -> Self {
        Self {
            mode,
            input: String::new(),
            file_type: None,
            selected: 0,
            // The resolved file or property is always the target of the rules.
            options: QueryOptions::new(Direction::Target),
            text_filter: String::new(),
            candidates: Cached::default(),
            completions: Cached::default(),
            hits: Cached::default(),
        }
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui, project: &Project, nav: &mut Nav) {
        // Both tabs use the same widget ids: keep their states (scroll, columns) apart.
        ui.push_id(self.mode, |ui| self.show_inner(ui, project, nav));
    }

    fn show_inner(&mut self, ui: &mut egui::Ui, project: &Project, nav: &mut Nav) {
        self.input_bar(ui);
        let input = self.input.trim().to_owned();
        if input.is_empty() {
            return;
        }
        if let Some(missing) = self.mode.missing_files(project) {
            ui.colored_label(WARN_COLOR, missing);
            return;
        }

        let mode = self.mode;
        let key = (project.generation(), input, self.file_type);
        self.completions.update(key.clone(), |(_, input, _)| {
            mode.completions(project, input)
        });
        let completions = (self.completions.value().as_slice(), self.completions.key());
        if let Some(picked) = completions_section(ui, mode, completions, nav) {
            self.input = picked;
        }

        if self.candidates.update(key, |(_, input, file_type)| {
            mode.resolve(project, input, *file_type)
        }) {
            self.selected = 0;
        }
        let Some(ty) = self.candidates_section(ui, nav) else {
            return;
        };

        let Some(index) = project.index() else {
            ui.colored_label(WARN_COLOR, "Load a policy to see the rules.");
            return;
        };
        ui.separator();
        self.presets_ui(ui);
        options_ui(
            ui,
            &mut self.options,
            &mut self.text_filter,
            &index.classes,
            false,
        );
        self.hits.update(
            (project.generation(), ty.to_owned(), self.options.clone()),
            |(_, subject, options)| options.run(index, subject),
        );
        rules_table(
            ui,
            "access_rules",
            self.hits.value(),
            self.hits.key(),
            &self.text_filter,
            nav,
        );
    }

    fn input_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(self.mode.prompt());
            ui.add(
                egui::TextEdit::singleline(&mut self.input)
                    .hint_text(self.mode.hint())
                    .desired_width(420.0),
            );
            if self.mode == Mode::Path {
                egui::ComboBox::from_id_salt("file_type")
                    .selected_text(file_type_choice_label(self.file_type))
                    .show_ui(ui, |ui| {
                        for file_type in FILE_TYPES {
                            ui.selectable_value(
                                &mut self.file_type,
                                file_type,
                                file_type_choice_label(file_type),
                            );
                        }
                    });
            }
        });
    }

    /// Shows the entries applying to the input; returns the type of the selected one.
    fn candidates_section(&mut self, ui: &mut egui::Ui, nav: &mut Nav) -> Option<&'static str> {
        let candidates = self.candidates.value();
        if candidates.is_empty() {
            ui.colored_label(WARN_COLOR, "No matching entry.");
            return None;
        }
        ui.label(format!(
            "{} matching entry(ies), the first one is the one used on the device:",
            candidates.len()
        ));
        candidates_grid(
            ui,
            "access_candidates",
            candidates,
            self.candidates.key(),
            Some(&mut self.selected),
            nav,
        );
        Some(candidates.get(self.selected)?.context.r#type)
    }

    fn presets_ui(&mut self, ui: &mut egui::Ui) {
        let options = &mut self.options;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Who can").strong());
            // A preset is highlighted while the filters still match it.
            for preset in self.mode.presets() {
                let active = options.classes == preset.classes && options.perms == preset.perms;
                if ui.selectable_label(active, preset.label).clicked() {
                    preset.classes.clone_into(&mut options.classes);
                    preset.perms.clone_into(&mut options.perms);
                }
            }
            let all = options.classes.trim().is_empty() && options.perms.trim().is_empty();
            if ui.selectable_label(all, "anything").clicked() {
                options.classes.clear();
                options.perms.clear();
            }
        });
    }
}

/// Lists the entries more specific than the input; returns a new input if one was clicked.
fn completions_section(
    ui: &mut egui::Ui,
    mode: Mode,
    (completions, content): (&[Candidate], Option<&ResolveKey>),
    nav: &mut Nav,
) -> Option<String> {
    if completions.is_empty() {
        return None;
    }
    let mut picked = None;
    egui::CollapsingHeader::new(format!(
        "{} more specific entry(ies) starting with the input",
        completions.len()
    ))
    .id_salt("access_completions")
    .default_open(true)
    .show(ui, |ui| {
        scroll_area(ui, "access_completions_scroll", content)
            .max_height(160.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("access_completions_grid")
                    .striped(true)
                    .num_columns(4)
                    .show(ui, |ui| {
                        for title in ["Origin", "Pattern", "File type", "Type"] {
                            ui.strong(title);
                        }
                        ui.end_row();
                        for c in completions {
                            ui.label(c.origin.to_string());
                            // Property prefixes are valid inputs, path regexes are not.
                            if mode == Mode::Property {
                                if ui
                                    .link(RichText::new(c.pattern).monospace())
                                    .on_hover_text("Search this property")
                                    .clicked()
                                {
                                    picked = Some(c.pattern.to_owned());
                                }
                            } else {
                                ui.monospace(c.pattern);
                            }
                            ui.monospace(file_type_label(c.file_type));
                            type_link(ui, c.context.r#type, nav);
                            ui.end_row();
                        }
                    });
            });
    });
    picked
}
