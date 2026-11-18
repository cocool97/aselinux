//! Spacing of the interface, roomier than egui's compact defaults.

use eframe::egui::{self, Margin, vec2};

/// Space between the panel edges and their content.
pub(crate) const PANEL_MARGIN: i8 = 12;
/// Extra height of table and list rows, on top of the text height.
pub(crate) const ROW_PADDING: f32 = 8.0;

/// Applies the spacing to every theme.
pub(crate) fn apply(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        let spacing = &mut style.spacing;
        spacing.item_spacing = vec2(10.0, 6.0);
        spacing.button_padding = vec2(10.0, 4.0);
        spacing.interact_size.y = 22.0;
        spacing.indent = 20.0;
        spacing.window_margin = Margin::same(14);
        // Also the margin of modals and combo box popups.
        spacing.menu_margin = Margin::same(10);
    });
}

/// Frame of side panels, with room around their content.
pub(crate) fn side_panel_frame(style: &egui::Style) -> egui::Frame {
    egui::Frame::side_top_panel(style).inner_margin(PANEL_MARGIN)
}

/// Frame of the central panel, with room around its content.
pub(crate) fn central_panel_frame(style: &egui::Style) -> egui::Frame {
    egui::Frame::central_panel(style).inner_margin(PANEL_MARGIN)
}
