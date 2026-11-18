//! "Type / rules" tab: everything related to a type or attribute.

use eframe::egui::{self, RichText};

use super::{
    Nav, WARN_COLOR,
    query::{Cached, HitsKey, QueryOptions},
    subject_of,
    widgets::{candidates_grid, options_ui, rules_table, scroll_area, type_link},
};
use crate::{
    policy_index::{Direction, NameKind, PolicyIndex, RuleHit, Transition},
    project::{Candidate, Project},
};

/// Maximum number of names suggested for an unknown input.
const MAX_SUGGESTIONS: usize = 40;

/// Key of cached per-subject results: project generation and subject.
type SubjectKey = (u64, String);

pub(crate) struct TypeTab {
    pub(crate) input: String,
    options: QueryOptions,
    text_filter: String,
    labels: Cached<SubjectKey, Vec<Candidate>>,
    transitions: Cached<SubjectKey, Vec<Transition>>,
    hits: Cached<HitsKey, Vec<RuleHit>>,
}

impl Default for TypeTab {
    fn default() -> Self {
        Self {
            input: String::new(),
            options: QueryOptions::new(Direction::Both),
            text_filter: String::new(),
            labels: Cached::default(),
            transitions: Cached::default(),
            hits: Cached::default(),
        }
    }
}

impl TypeTab {
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, project: &Project, nav: &mut Nav) {
        let generation = project.generation();
        ui.horizontal(|ui| {
            ui.label("Type, attribute or context:");
            ui.add(
                egui::TextEdit::singleline(&mut self.input)
                    .hint_text("system_server or u:object_r:logcat_exec:s0")
                    .desired_width(420.0),
            );
        });

        let subject = subject_of(&self.input).to_owned();
        if subject.is_empty() {
            return;
        }

        self.labels.update((generation, subject.clone()), |(_, s)| {
            project.labels_of_type(s)
        });

        let Some(index) = project.index() else {
            ui.colored_label(WARN_COLOR, "No policy loaded: only labels are shown.");
            labels_section(ui, self.labels.value(), &subject, nav);
            return;
        };

        match index.name_kind(&subject) {
            NameKind::Unknown => {
                ui.colored_label(
                    WARN_COLOR,
                    format!("\"{subject}\" is unknown to the policy."),
                );
                suggestions(ui, index, &subject, nav);
                labels_section(ui, self.labels.value(), &subject, nav);
                return;
            }
            NameKind::Type => type_header(ui, index, &subject, nav),
            NameKind::Attribute => attribute_header(ui, index, &subject, nav),
        }

        self.transitions
            .update((generation, subject.clone()), |(_, s)| {
                index.transitions_involving(s)
            });
        // Side by side: both grids are narrow and would leave the right half empty.
        ui.columns(2, |columns| {
            labels_section(&mut columns[0], self.labels.value(), &subject, nav);
            transitions_section(&mut columns[1], self.transitions.value(), &subject, nav);
        });
        ui.separator();

        options_ui(
            ui,
            &mut self.options,
            &mut self.text_filter,
            &index.classes,
            true,
        );
        self.hits.update(
            (generation, subject, self.options.clone()),
            |(_, subject, options)| options.run(index, subject),
        );
        rules_table(
            ui,
            "type_rules",
            self.hits.value(),
            self.hits.key(),
            &self.text_filter,
            nav,
        );
    }
}

fn suggestions(ui: &mut egui::Ui, index: &PolicyIndex, partial: &str, nav: &mut Nav) {
    let mut found: Vec<&str> = index
        .names
        .iter()
        .copied()
        .filter(|n| n.contains(partial))
        .collect();
    if found.is_empty() {
        return;
    }
    // Names starting with the input first.
    found.sort_by_key(|n| !n.starts_with(partial));
    ui.horizontal_wrapped(|ui| {
        ui.label(format!("Suggestions ({}) :", found.len()));
        for name in found.iter().take(MAX_SUGGESTIONS) {
            type_link(ui, name, nav);
        }
        if found.len() > MAX_SUGGESTIONS {
            ui.weak("…");
        }
    });
}

fn type_header(ui: &mut egui::Ui, index: &PolicyIndex, ty: &str, nav: &mut Nav) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("type {ty}")).strong().monospace());
        if index.is_permissive(ty) {
            ui.label(RichText::new("permissive").color(WARN_COLOR).strong());
        }
        ui.separator();
        ui.label("attributes:");
        let mut any = false;
        for attribute in index.attributes_of(ty) {
            type_link(ui, attribute, nav);
            any = true;
        }
        if !any {
            ui.weak("none");
        }
    });
}

fn attribute_header(ui: &mut egui::Ui, index: &PolicyIndex, attribute: &str, nav: &mut Nav) {
    let types = index.types_of(attribute);
    ui.label(
        RichText::new(format!("attribute {attribute}"))
            .strong()
            .monospace(),
    );
    egui::CollapsingHeader::new(format!("{} type(s) with this attribute", types.len()))
        .id_salt("attribute_types")
        .show(ui, |ui| {
            scroll_area(ui, "attribute_types_scroll", attribute)
                .max_height(150.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for ty in types {
                            type_link(ui, ty, nav);
                        }
                    });
                });
        });
}

fn labels_section(ui: &mut egui::Ui, labels: &[Candidate], subject: &str, nav: &mut Nav) {
    egui::CollapsingHeader::new(format!(
        "Labels: files, properties, genfscon ({})",
        labels.len()
    ))
    .id_salt("type_labels")
    .default_open(true)
    .show(ui, |ui| {
        if labels.is_empty() {
            ui.weak("No entry in the loaded *_contexts.");
        } else {
            candidates_grid(ui, "type_labels_grid", labels, subject, None, nav);
        }
    });
}

fn transitions_section(
    ui: &mut egui::Ui,
    transitions: &[Transition],
    subject: &str,
    nav: &mut Nav,
) {
    egui::CollapsingHeader::new(format!("type_transition ({})", transitions.len()))
        .id_salt("type_transitions")
        .default_open(!transitions.is_empty())
        .show(ui, |ui| {
            scroll_area(ui, "type_transitions_scroll", subject)
                .hscroll(true)
                .max_height(180.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    egui::Grid::new("type_transitions_grid")
                        .striped(true)
                        .num_columns(5)
                        .show(ui, |ui| {
                            for title in ["Source", "Target", "Class", "New type", "Name"] {
                                ui.strong(title);
                            }
                            ui.end_row();
                            for t in transitions {
                                type_link(ui, t.source, nav);
                                type_link(ui, t.target, nav);
                                ui.label(t.class);
                                type_link(ui, t.default, nav);
                                ui.monospace(t.name.unwrap_or(""));
                                ui.end_row();
                            }
                        });
                });
        });
}
