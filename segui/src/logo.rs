//! Application logo, embedded in the binary.
//!
//! `assets/logo.png` (at the repository root) is rendered from `assets/logo.svg`:
//! `magick -background none -density 192 logo.svg -resize 256x256 -depth 8 logo.png`

use eframe::egui;

const PNG: &[u8] = include_bytes!("../../assets/logo.png");

/// The logo as raw RGBA pixels.
pub(crate) fn icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(PNG).expect("the embedded logo is a valid PNG")
}

/// Uploads the logo as a texture, e.g. to show it with [`egui::Image`].
pub(crate) fn texture(ctx: &egui::Context) -> egui::TextureHandle {
    let icon = icon();
    let size = [icon.width as usize, icon.height as usize];
    let image = egui::ColorImage::from_rgba_unmultiplied(size, &icon.rgba);
    ctx.load_texture("segui-logo", image, egui::TextureOptions::LINEAR)
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_logo_decodes() {
        let icon = super::icon();
        assert_eq!((icon.width, icon.height), (256, 256));
    }
}
