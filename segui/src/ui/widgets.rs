//! Formatting helpers and widgets shared by the search tabs.

use std::hash::Hash;

use eframe::egui::{self, Label, RichText};
use egui_extras::{Column, TableBuilder};
use selinux_parser::{
    android::AccessVector,
    common::{AccessVectorKind, FileType, SELinuxContext},
};

use super::{Goto, Nav, WARN_COLOR, query::QueryOptions, spacing::ROW_PADDING};
use crate::{
    policy_index::{Direction, HitName, RuleHit},
    project::Candidate,
};

/// Tooltip of the class and permission filters.
const TERM_HELP: &str = "Matches word prefixes: \"exec\" finds execute and execute_no_trans.\nEnd a word with $ for an exact match (e.g. file$).";

/// Whether `content` differs from the one shown last frame by the widget `id`.
///
/// Scroll areas keep their offset across frames: this lets them restart from the
/// top when they show something new rather than keeping the previous offset.
pub(crate) fn content_changed(ui: &egui::Ui, id: &str, content: impl Hash) -> bool {
    let id = ui.scope_id().with(id).with("shown_content");
    let hash = egui::util::hash(content);
    ui.data_mut(|data| {
        let changed = data.get_temp::<u64>(id) != Some(hash);
        data.insert_temp(id, hash);
        changed
    })
}

/// Vertical scroll area restarting from the top whenever `content` changes.
pub(crate) fn scroll_area(ui: &egui::Ui, id: &str, content: impl Hash) -> egui::ScrollArea {
    let area = egui::ScrollArea::vertical().id_salt(id);
    if content_changed(ui, id, content) {
        area.vertical_scroll_offset(0.0)
    } else {
        area
    }
}

pub(crate) fn kind_label(kind: AccessVectorKind) -> &'static str {
    match kind {
        AccessVectorKind::Allow => "allow",
        AccessVectorKind::AuditAllow => "auditallow",
        AccessVectorKind::DontAudit => "dontaudit",
    }
}

pub(crate) fn file_type_label(file_type: Option<FileType>) -> &'static str {
    match file_type {
        None => "",
        Some(FileType::Regular) => "--",
        Some(FileType::Directory) => "-d",
        Some(FileType::CharDevice) => "-c",
        Some(FileType::BlockDevice) => "-b",
        Some(FileType::Symlink) => "-l",
        Some(FileType::NamedPipe) => "-p",
        Some(FileType::Socket) => "-s",
    }
}

pub(crate) fn context_string(context: &SELinuxContext<'_>) -> String {
    match context.level {
        Some(level) => format!(
            "{}:{}:{}:{level}",
            context.user, context.role, context.r#type
        ),
        None => format!("{}:{}:{}", context.user, context.role, context.r#type),
    }
}

fn perms_string(rule: &AccessVector<'_>) -> String {
    rule.perms.iter().copied().collect::<Vec<_>>().join(" ")
}

fn rule_string(rule: &AccessVector<'_>) -> String {
    format!(
        "{} {} {} {} {{ {} }}",
        kind_label(rule.kind),
        rule.source,
        rule.target,
        rule.class,
        perms_string(rule)
    )
}

/// A clickable type name, opening it in the type tab.
pub(crate) fn type_link(ui: &mut egui::Ui, name: &str, nav: &mut Nav) {
    if ui.link(name).on_hover_text("Open").clicked() {
        *nav = Some(Goto::Name(name.to_owned()));
    }
}

fn name_cell(ui: &mut egui::Ui, hit_name: HitName, nav: &mut Nav) {
    type_link(ui, hit_name.name, nav);
    if let Some(via) = hit_name.via {
        ui.weak("via");
        type_link(ui, via, nav);
    }
}

/// Edits rule lookup options. `classes` feeds the class picker.
pub(crate) fn options_ui(
    ui: &mut egui::Ui,
    options: &mut QueryOptions,
    text_filter: &mut String,
    classes: &[&str],
    show_direction: bool,
) {
    ui.horizontal_wrapped(|ui| {
        if show_direction {
            ui.label("Role:");
            ui.selectable_value(&mut options.direction, Direction::Source, "source");
            ui.selectable_value(&mut options.direction, Direction::Target, "target");
            ui.selectable_value(&mut options.direction, Direction::Both, "both");
            ui.separator();
        }
        ui.checkbox(&mut options.kinds.allow, "allow");
        ui.checkbox(&mut options.kinds.auditallow, "auditallow");
        ui.checkbox(&mut options.kinds.dontaudit, "dontaudit");
        ui.separator();
        ui.checkbox(&mut options.expand_subject, "via attributes")
            .on_hover_text("Include rules written on the attributes of the searched type");
        ui.checkbox(&mut options.expand_other, "expand the other side")
            .on_hover_text(
                "Replace the attributes on the other side of the rule with their concrete types",
            );
    });
    ui.horizontal_wrapped(|ui| {
        ui.label("Classes:");
        ui.add(
            egui::TextEdit::singleline(&mut options.classes)
                .hint_text("file, dir…")
                .desired_width(180.0),
        )
        .on_hover_text(TERM_HELP);
        egui::ComboBox::from_id_salt("class_picker")
            .selected_text("+")
            .width(40.0)
            .show_ui(ui, |ui| {
                for class in classes {
                    if ui.selectable_label(false, *class).clicked() {
                        if !options.classes.trim().is_empty() {
                            options.classes.push_str(", ");
                        }
                        // Exact match: picking `file` must not also select `filesystem`.
                        options.classes.push_str(class);
                        options.classes.push('$');
                    }
                }
            });
        ui.label("Permissions (any of):");
        ui.add(
            egui::TextEdit::singleline(&mut options.perms)
                .hint_text("read, exec…")
                .desired_width(220.0),
        )
        .on_hover_text(TERM_HELP);
        ui.separator();
        ui.label("🔍");
        ui.add(
            egui::TextEdit::singleline(text_filter)
                .hint_text("filter results")
                .desired_width(180.0),
        );
    });
}

fn hit_matches(hit: &RuleHit, needle: &str) -> bool {
    [
        Some(hit.source.name),
        hit.source.via,
        Some(hit.target.name),
        hit.target.via,
        Some(hit.rule.class),
    ]
    .into_iter()
    .flatten()
    .chain(hit.rule.perms.iter().copied())
    .any(|s| s.contains(needle))
}

/// Virtualized table of rules, scrolled back to the top when `content` changes.
pub(crate) fn rules_table(
    ui: &mut egui::Ui,
    id: &str,
    hits: &[RuleHit],
    content: impl Hash,
    text_filter: &str,
    nav: &mut Nav,
) {
    let needle = text_filter.trim();
    let rows: Vec<&RuleHit> = hits
        .iter()
        .filter(|h| needle.is_empty() || hit_matches(h, needle))
        .collect();
    // Only the text filter hides rules: the other filters are part of the query.
    ui.label(if needle.is_empty() {
        format!("{} rule(s)", hits.len())
    } else {
        format!(
            "{} rule(s) out of {} containing \"{needle}\"",
            rows.len(),
            hits.len()
        )
    });

    let row_height = ui.text_style_height(&egui::TextStyle::Body) + ROW_PADDING;
    let changed = content_changed(ui, id, (content, needle));
    let mut table = TableBuilder::new(ui);
    if changed {
        table = table.vertical_scroll_offset(0.0);
    }
    table
        .id_salt(id)
        .striped(true)
        .resizable(true)
        .auto_shrink(false)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto().at_least(70.0))
        .column(Column::initial(260.0).at_least(80.0).clip(true))
        .column(Column::initial(260.0).at_least(80.0).clip(true))
        .column(Column::initial(120.0).at_least(60.0).clip(true))
        .column(Column::remainder().clip(true))
        .header(row_height, |mut header| {
            for title in ["Rule", "Source", "Target", "Class", "Permissions"] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let hit = rows[row.index()];
                row.col(|ui| {
                    let label = kind_label(hit.rule.kind);
                    if hit.rule.kind == AccessVectorKind::Allow {
                        ui.label(label);
                    } else {
                        ui.label(RichText::new(label).color(WARN_COLOR));
                    }
                });
                row.col(|ui| name_cell(ui, hit.source, nav));
                row.col(|ui| name_cell(ui, hit.target, nav));
                row.col(|ui| {
                    ui.label(hit.rule.class);
                });
                row.col(|ui| {
                    // A truncated label already shows its full text on hover.
                    ui.add(Label::new(perms_string(hit.rule)).truncate())
                        .context_menu(|ui| {
                            if ui.button("Copy rule").clicked() {
                                ui.ctx().copy_text(rule_string(hit.rule));
                                ui.close();
                            }
                        });
                });
            });
        });
}

/// Grid of labeling entries (file/property contexts, genfscon).
///
/// With `selected`, a radio button lets the user pick one of the candidates.
/// The grid scrolls back to the top when `content` changes.
pub(crate) fn candidates_grid(
    ui: &mut egui::Ui,
    id: &str,
    candidates: &[Candidate],
    content: impl Hash,
    mut selected: Option<&mut usize>,
    nav: &mut Nav,
) {
    scroll_area(ui, id, content)
        .hscroll(true)
        .max_height(180.0)
        .auto_shrink([false, true])
        .show(ui, |ui| {
            egui::Grid::new(id)
                .striped(true)
                .num_columns(5)
                .show(ui, |ui| {
                    if selected.is_some() {
                        ui.strong("");
                    }
                    for title in ["Origin", "Pattern", "File type", "Type"] {
                        ui.strong(title);
                    }
                    ui.end_row();
                    for (i, candidate) in candidates.iter().enumerate() {
                        if let Some(selected) = selected.as_deref_mut() {
                            ui.radio_value(selected, i, "");
                        }
                        ui.label(candidate.origin.to_string());
                        ui.monospace(candidate.pattern);
                        ui.monospace(file_type_label(candidate.file_type));
                        let ty = candidate.context.r#type;
                        if ui
                            .link(ty)
                            .on_hover_text(context_string(candidate.context))
                            .clicked()
                        {
                            *nav = Some(Goto::Name(ty.to_owned()));
                        }
                        ui.end_row();
                    }
                });
        });
}
