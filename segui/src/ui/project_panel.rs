//! Side panel listing the project files.

use std::path::PathBuf;

use eframe::egui::{self, RichText};

use super::WARN_COLOR;
use crate::project::{FileKind, Project, SourceFile, display_name};

/// A file picked or dropped by the user, waiting for its kind to be confirmed.
pub(crate) struct PendingFile {
    pub(crate) path: PathBuf,
    pub(crate) kind: Option<FileKind>,
}

impl PendingFile {
    /// A pending file whose kind is guessed from its name.
    pub(crate) fn detect(path: PathBuf) -> Self {
        let kind = FileKind::detect(&path);
        Self { path, kind }
    }
}

/// A file that failed to load.
pub(crate) struct LoadError {
    pub(crate) path: PathBuf,
    pub(crate) message: String,
}

/// Background work in progress.
#[derive(Default)]
pub(crate) struct Status {
    /// The file picker is open.
    pub(crate) picking: bool,
    /// Number of files being loaded.
    pub(crate) loading: usize,
}

/// What the user asked for in the project panel.
pub(crate) enum ProjectAction {
    /// Open the file picker.
    PickFiles,
    Load(Vec<PendingFile>),
    RemovePolicy,
    RemoveFileContexts(usize),
    RemovePropertyContexts(usize),
}

pub(crate) fn show(
    ui: &mut egui::Ui,
    project: &Project,
    pending: &mut Vec<PendingFile>,
    errors: &mut Vec<LoadError>,
    status: &Status,
) -> Option<ProjectAction> {
    ui.heading("Project");
    let mut action = add_files_section(ui, status);
    errors_section(ui, errors);
    if !pending.is_empty()
        && let Some(files) = pending_section(ui, pending)
    {
        action = Some(ProjectAction::Load(files));
    }
    loaded_files_section(ui, project).or(action)
}

fn add_files_section(ui: &mut egui::Ui, status: &Status) -> Option<ProjectAction> {
    let mut action = None;
    ui.horizontal(|ui| {
        let button = egui::Button::new("➕ Add files…");
        if ui.add_enabled(!status.picking, button).clicked() {
            action = Some(ProjectAction::PickFiles);
        }
        if status.picking {
            ui.spinner();
        }
    });
    ui.weak("…or drag and drop files into the window.");
    if status.loading > 0 {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(format!("Loading {} file(s)…", status.loading));
        });
    }
    action
}

/// Shows load errors, each dismissible.
fn errors_section(ui: &mut egui::Ui, errors: &mut Vec<LoadError>) {
    let mut dismissed = None;
    let error_color = ui.visuals().error_fg_color;
    for (i, error) in errors.iter().enumerate() {
        egui::Frame::group(ui.style())
            .stroke(egui::Stroke::new(1.0, error_color))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let title = format!("Failed: {}", display_name(&error.path));
                    ui.colored_label(error_color, RichText::new(title).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✖").on_hover_text("Dismiss").clicked() {
                            dismissed = Some(i);
                        }
                    });
                });
                ui.label(&error.message);
                ui.weak(
                    "The file was moved back to \"To load\": check its type and load it again.",
                );
            });
    }
    if let Some(i) = dismissed {
        errors.remove(i);
    }
}

/// Lists the files waiting to be loaded; returns them once the user confirms.
fn pending_section(ui: &mut egui::Ui, pending: &mut Vec<PendingFile>) -> Option<Vec<PendingFile>> {
    ui.separator();
    ui.strong("To load");
    let mut cancelled = None;
    for (i, file) in pending.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            if ui.small_button("✖").on_hover_text("Cancel").clicked() {
                cancelled = Some(i);
            }
            ui.label(RichText::new(display_name(&file.path)).monospace())
                .on_hover_text(file.path.display().to_string());
        });
        ui.indent(("pending", i), |ui| {
            egui::ComboBox::from_id_salt(("pending_kind", i))
                .selected_text(file.kind.map_or("type?", FileKind::label))
                .show_ui(ui, |ui| {
                    for kind in FileKind::ALL {
                        ui.selectable_value(&mut file.kind, Some(kind), kind.label());
                    }
                });
        });
    }
    if let Some(i) = cancelled {
        pending.remove(i);
    }
    let ready = pending.iter().all(|f| f.kind.is_some());
    let load = ui
        .add_enabled(ready, egui::Button::new("Load"))
        .on_disabled_hover_text("Choose the type of each file")
        .clicked();
    load.then(|| std::mem::take(pending))
}

fn loaded_files_section(ui: &mut egui::Ui, project: &Project) -> Option<ProjectAction> {
    let mut action = None;

    ui.separator();
    ui.strong("Policy");
    match project.policy() {
        Some(policy) => {
            let p = policy.index.policy();
            let detail = format!(
                "{} types, {} attributes, {} rules, {} permissive",
                p.types.len(),
                p.attributes.len(),
                policy.index.rule_count,
                p.permissives.len()
            );
            if file_row(ui, &policy.source, &detail) {
                action = Some(ProjectAction::RemovePolicy);
            }
        }
        None => {
            ui.weak("none");
        }
    }

    ui.separator();
    ui.strong("file_contexts");
    for (i, fc) in project.file_contexts().iter().enumerate() {
        let detail = format!("{} entries", fc.index.entries.len());
        if file_row(ui, &fc.source, &detail) {
            action = Some(ProjectAction::RemoveFileContexts(i));
        }
        if !fc.index.errors.is_empty() {
            ui.indent(("fc_errors", i), |ui| {
                let message = format!("{} invalid regex(es)", fc.index.errors.len());
                ui.colored_label(WARN_COLOR, message)
                    .on_hover_text(fc.index.errors.join("\n"));
            });
        }
    }
    if project.file_contexts().is_empty() {
        ui.weak("none");
    }

    ui.separator();
    ui.strong("property_contexts");
    for (i, pc) in project.property_contexts().iter().enumerate() {
        let detail = format!("{} entries", pc.index.entries.len());
        if file_row(ui, &pc.source, &detail) {
            action = Some(ProjectAction::RemovePropertyContexts(i));
        }
    }
    if project.property_contexts().is_empty() {
        ui.weak("none");
    }

    action
}

/// A loaded file with its details; returns whether the user asked to remove it.
fn file_row(ui: &mut egui::Ui, source: &SourceFile, detail: &str) -> bool {
    let mut remove = false;
    ui.horizontal(|ui| {
        remove = ui
            .small_button("✖")
            .on_hover_text("Remove from the project")
            .clicked();
        ui.label(RichText::new(source.name).monospace())
            .on_hover_text(source.path.display().to_string());
    });
    ui.indent(source.name, |ui| ui.weak(detail));
    remove
}
