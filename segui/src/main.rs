//! `segui`: a GUI to explore Android `SELinux` policies along with the
//! `*_contexts` files dumped from a device.
//!
//! Files given on the command line are loaded at startup when their kind can be
//! guessed from their name.

mod app;
mod logo;
mod policy_index;
mod project;
mod resolve;
mod ui;

use eframe::egui;

use crate::app::SeguiApp;

const fn build_window_title() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), " v", env!("CARGO_PKG_VERSION"))
}

fn main() -> eframe::Result {
    env_logger::init();

    let files: Vec<_> = std::env::args_os()
        .skip(1)
        .map(std::path::PathBuf::from)
        .collect();

    eframe::run_native(
        "segui",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title(build_window_title())
                .with_app_id("segui")
                .with_icon(logo::icon())
                .with_drag_and_drop(true),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(SeguiApp::new(cc, files)))),
    )
}
