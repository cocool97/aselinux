//! "Settings" and "About" windows.

use eframe::egui::{self, RichText, TextStyle};

/// Storage key of the body text size.
pub(crate) const TEXT_SIZE_KEY: &str = "text_size";

/// Body text size used until the user changes it.
const DEFAULT_TEXT_SIZE: f32 = 15.0;
/// egui default body text size, which the other default text styles are relative to.
const EGUI_BODY_SIZE: f32 = 13.0;
/// egui default zoom factor.
const DEFAULT_ZOOM: f32 = 1.0;

pub(crate) struct Settings {
    pub(crate) open: bool,
    pub(crate) text_size: f32,
}

impl Settings {
    /// Restores the text size from `storage` and applies it.
    pub(crate) fn new(ctx: &egui::Context, storage: Option<&dyn eframe::Storage>) -> Self {
        let text_size = storage
            .and_then(|s| s.get_string(TEXT_SIZE_KEY))
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TEXT_SIZE);
        apply_text_size(ctx, text_size);
        Self {
            open: false,
            text_size,
        }
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context) {
        let mut open = self.open;
        modal(ctx, "settings", "⚙ Settings", &mut open, |ui| {
            egui::Grid::new("settings_grid")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Text size");
                    if ui
                        .add(
                            egui::Slider::new(&mut self.text_size, 8.0..=28.0)
                                .step_by(0.5)
                                .suffix(" pt"),
                        )
                        .changed()
                    {
                        apply_text_size(ctx, self.text_size);
                    }
                    ui.end_row();

                    ui.label("Interface zoom")
                        .on_hover_text("Scales everything: text, buttons, margins (Ctrl +/-/0)");
                    let mut zoom = ctx.zoom_factor();
                    if ui
                        .add(
                            egui::Slider::new(&mut zoom, 0.5..=3.0)
                                .step_by(0.05)
                                .suffix("×"),
                        )
                        .changed()
                    {
                        ctx.set_zoom_factor(zoom);
                    }
                    ui.end_row();

                    ui.label("Theme");
                    egui::widgets::global_theme_preference_buttons(ui);
                    ui.end_row();
                });
            ui.separator();
            if ui.button("Reset").clicked() {
                self.text_size = DEFAULT_TEXT_SIZE;
                apply_text_size(ctx, self.text_size);
                ctx.set_zoom_factor(DEFAULT_ZOOM);
            }
        });
        self.open = open;
    }
}

/// Sets the body text size, scaling the other text styles like egui's defaults.
fn apply_text_size(ctx: &egui::Context, size: f32) {
    ctx.all_styles_mut(|style| {
        for (text_style, font) in &mut style.text_styles {
            font.size = match text_style {
                TextStyle::Small => size * 9.0 / EGUI_BODY_SIZE,
                TextStyle::Heading => size * 18.0 / EGUI_BODY_SIZE,
                _ => size,
            };
        }
    });
}

#[derive(Default)]
pub(crate) struct About {
    pub(crate) open: bool,
}

impl About {
    pub(crate) fn show(&mut self, ctx: &egui::Context, logo: &egui::TextureHandle) {
        modal(ctx, "about", "About segui", &mut self.open, |ui| {
            ui.vertical_centered(|ui| {
                ui.add(egui::Image::new(logo).fit_to_exact_size(egui::vec2(96.0, 96.0)));
                ui.label(RichText::new(env!("CARGO_PKG_NAME")).heading().strong());
                ui.label(format!("version {}", env!("CARGO_PKG_VERSION")));
                ui.add_space(4.0);
                ui.label(env!("CARGO_PKG_DESCRIPTION"));
            });
            ui.separator();
            egui::Grid::new("about_grid")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.strong("Author(s)");
                    ui.label(env!("CARGO_PKG_AUTHORS").replace(':', ", "));
                    ui.end_row();

                    ui.strong("UI");
                    ui.label("egui / eframe 0.37");
                    ui.end_row();

                    ui.strong("Build");
                    ui.label(if cfg!(debug_assertions) {
                        "debug"
                    } else {
                        "release"
                    });
                    ui.end_row();
                });
            ui.separator();
            ui.weak("R&D tool to explore Android SELinux policies.");
        });
    }
}

/// Shows a centered modal with a title bar and a close button when `open` is set.
///
/// The modal also closes with `Escape` or a click outside of it.
fn modal(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    open: &mut bool,
    add_contents: impl FnOnce(&mut egui::Ui),
) {
    if !*open {
        return;
    }
    let response = egui::Modal::new(egui::Id::unique(id)).show(ctx, |ui| {
        let mut close = false;
        ui.horizontal(|ui| {
            ui.heading(title);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button("✖").on_hover_text("Close (Esc)").clicked();
            });
        });
        ui.separator();
        add_contents(ui);
        close
    });
    if response.inner || response.should_close() {
        *open = false;
    }
}

/// Icon-only toggle button showing an "information" icon, with `tooltip` on hover.
///
/// The icon is painted with shapes rather than the `ℹ` glyph, which egui's
/// bundled fonts lack and system fonts render inconsistently.
pub(crate) fn info_toggle(ui: &mut egui::Ui, open: &mut bool, tooltip: &str) {
    let icon = egui::IdSalt::new("info_icon");
    let size = ui.text_style_height(&TextStyle::Button);
    let response =
        egui::Button::selectable(*open, egui::Atom::custom(icon, egui::Vec2::splat(size)))
            .atom_ui(ui);
    if let Some(rect) = response.rect(icon) {
        let color = ui
            .style()
            .interact_selectable(&response.response, *open)
            .text_color();
        paint_info_icon(ui.painter(), rect, color);
    }
    if response.response.on_hover_text(tooltip).clicked() {
        *open = !*open;
    }
}

/// Paints a circled "i" inside `rect`.
fn paint_info_icon(painter: &egui::Painter, rect: egui::Rect, color: egui::Color32) {
    let center = rect.center();
    let radius = rect.width().min(rect.height()) * 0.45;
    painter.circle_stroke(center, radius, egui::Stroke::new(radius * 0.14, color));
    // Dot of the "i".
    painter.circle_filled(
        center + egui::vec2(0.0, -radius * 0.45),
        radius * 0.13,
        color,
    );
    // Stem of the "i".
    painter.line_segment(
        [
            center + egui::vec2(0.0, -radius * 0.12),
            center + egui::vec2(0.0, radius * 0.55),
        ],
        egui::Stroke::new(radius * 0.2, color),
    );
}
