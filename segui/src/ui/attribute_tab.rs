//! "Attributes" tab: browse attributes and the types carrying them.

use eframe::egui::{self, RichText};

use super::{
    Goto, Nav, WARN_COLOR,
    spacing::{self, PANEL_MARGIN, ROW_PADDING},
    widgets::{scroll_area, type_link},
};
use crate::{policy_index::PolicyIndex, project::Project};

#[derive(Default)]
pub(crate) struct AttributeTab {
    /// Filter of the attribute list.
    filter: String,
    pub(crate) selected: Option<String>,
    /// Filter of the member list.
    member_filter: String,
}

impl AttributeTab {
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, project: &Project, nav: &mut Nav) {
        let Some(index) = project.index() else {
            ui.colored_label(WARN_COLOR, "Load a policy to browse its attributes.");
            return;
        };

        egui::Panel::left("attribute_list")
            .frame(spacing::side_panel_frame(ui.style()))
            .default_size(320.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("filter attributes (e.g. appdomain)")
                        .desired_width(f32::INFINITY),
                );
                let needle = self.filter.trim();
                let attributes: Vec<&str> = index
                    .attributes
                    .iter()
                    .copied()
                    .filter(|a| a.contains(needle))
                    .collect();
                ui.weak(format!("{} attribute(s)", attributes.len()));

                let row_height = ui.text_style_height(&egui::TextStyle::Body) + ROW_PADDING;
                scroll_area(ui, "attribute_list_scroll", needle)
                    .auto_shrink(false)
                    .show_rows(ui, row_height, attributes.len(), |ui, range| {
                        for attribute in &attributes[range] {
                            let selected = self.selected.as_deref() == Some(*attribute);
                            let label =
                                format!("{attribute}  ({})", index.types_of(attribute).len());
                            if ui.selectable_label(selected, label).clicked() {
                                self.selected = Some((*attribute).to_owned());
                                self.member_filter.clear();
                            }
                        }
                    });
            });

        egui::Frame::new()
            // The central panel already has a margin on the other sides.
            .inner_margin(egui::Margin {
                left: PANEL_MARGIN,
                top: PANEL_MARGIN,
                ..egui::Margin::ZERO
            })
            .show(ui, |ui| self.members_ui(ui, index, nav));
    }

    /// Right part: the types carrying the selected attribute.
    fn members_ui(&mut self, ui: &mut egui::Ui, index: &PolicyIndex, nav: &mut Nav) {
        let Some(attribute) = self.selected.as_deref() else {
            ui.centered_and_justified(|ui| {
                ui.label("Select an attribute to see the types carrying it.");
            });
            return;
        };
        let members = index.types_of(attribute);

        ui.horizontal(|ui| {
            ui.label(RichText::new(attribute).heading().strong());
            ui.label(format!("— {} type(s)", members.len()));
        });
        ui.horizontal(|ui| {
            if ui.button("Show rules of this attribute").clicked() {
                *nav = Some(Goto::Rules(attribute.to_owned()));
            }
            if ui.button("Copy list").clicked() {
                ui.ctx().copy_text(members.join("\n"));
            }
            ui.separator();
            ui.label("🔍");
            ui.add(
                egui::TextEdit::singleline(&mut self.member_filter)
                    .hint_text("filter types")
                    .desired_width(220.0),
            );
        });
        ui.separator();

        let needle = self.member_filter.trim();
        let shown: Vec<&str> = members
            .iter()
            .copied()
            .filter(|t| t.contains(needle))
            .collect();
        if shown.is_empty() {
            ui.weak("No type.");
            return;
        }
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + ROW_PADDING;
        scroll_area(ui, "attribute_members", (attribute, needle))
            .auto_shrink(false)
            .show_rows(ui, row_height, shown.len(), |ui, range| {
                for ty in &shown[range] {
                    ui.horizontal(|ui| {
                        type_link(ui, ty, nav);
                        if index.is_permissive(ty) {
                            ui.label(RichText::new("permissive").color(WARN_COLOR));
                        }
                    });
                }
            });
    }
}
