//! Application state and top-level layout.

use std::{
    path::PathBuf,
    sync::mpsc::{Receiver, Sender, channel},
};

use eframe::egui;

use crate::{
    logo,
    policy_index::NameKind,
    project::{self, FileKind, LoadedFile, Project},
    ui::{
        Goto, Nav,
        access_tab::{AccessTab, Mode},
        attribute_tab::AttributeTab,
        project_panel::{self, LoadError, PendingFile, ProjectAction, Status},
        spacing,
        type_tab::TypeTab,
        windows::{About, Settings, TEXT_SIZE_KEY, info_toggle},
    },
};

/// Storage key of the last directory opened in the file picker.
const LAST_DIR_KEY: &str = "last_dir";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Path,
    Property,
    Type,
    Attributes,
}

impl Tab {
    const ALL: [Self; 4] = [Self::Path, Self::Property, Self::Type, Self::Attributes];

    fn label(self) -> &'static str {
        match self {
            Self::Path => "Search by path",
            Self::Property => "Search by property",
            Self::Type => "Type / rules mapping",
            Self::Attributes => "Attributes / types mapping",
        }
    }
}

/// Results of background work, sent back to the UI thread.
enum Message {
    Picked(Vec<PathBuf>),
    Loaded {
        path: PathBuf,
        kind: FileKind,
        // Boxed: a loaded file is much larger than the other variants.
        result: Box<anyhow::Result<LoadedFile>>,
    },
}

pub(crate) struct SeguiApp {
    ctx: egui::Context,
    project: Project,
    pending: Vec<PendingFile>,
    /// Files that failed to load, shown until dismissed.
    errors: Vec<LoadError>,
    /// Directory the file picker opens in.
    last_dir: Option<PathBuf>,
    status: Status,
    tx: Sender<Message>,
    rx: Receiver<Message>,
    tab: Tab,
    path_tab: AccessTab,
    property_tab: AccessTab,
    type_tab: TypeTab,
    attribute_tab: AttributeTab,
    settings: Settings,
    about: About,
    logo: egui::TextureHandle,
}

impl SeguiApp {
    /// Creates the app, loading `files` whose kind can be detected from their name.
    pub(crate) fn new(
        cc: &eframe::CreationContext<'_>,
        files: impl IntoIterator<Item = PathBuf>,
    ) -> Self {
        let last_dir = cc
            .storage
            .and_then(|s| s.get_string(LAST_DIR_KEY))
            .map(PathBuf::from)
            .filter(|d| d.is_dir());
        spacing::apply(&cc.egui_ctx);
        let (tx, rx) = channel();
        let mut app = Self {
            ctx: cc.egui_ctx.clone(),
            project: Project::default(),
            pending: Vec::new(),
            errors: Vec::new(),
            last_dir,
            status: Status::default(),
            tx,
            rx,
            tab: Tab::Path,
            path_tab: AccessTab::new(Mode::Path),
            property_tab: AccessTab::new(Mode::Property),
            type_tab: TypeTab::default(),
            attribute_tab: AttributeTab::default(),
            settings: Settings::new(&cc.egui_ctx, cc.storage),
            about: About::default(),
            logo: logo::texture(&cc.egui_ctx),
        };
        let (ready, unknown): (Vec<_>, Vec<_>) = files
            .into_iter()
            .map(PendingFile::detect)
            .partition(|f| f.kind.is_some());
        app.load(ready);
        app.pending = unknown;
        app
    }

    /// Runs `job` on a background thread and sends its result to the UI thread.
    fn spawn(&self, job: impl FnOnce() -> Message + Send + 'static) {
        let tx = self.tx.clone();
        let ctx = self.ctx.clone();
        std::thread::spawn(move || {
            // The receiver lives as long as the app: a send error means it is closing.
            let _ = tx.send(job());
            ctx.request_repaint();
        });
    }

    /// Loads `files` in parallel, each on its own thread.
    fn load(&mut self, files: Vec<PendingFile>) {
        for PendingFile { path, kind } in files {
            let Some(kind) = kind else { continue };
            self.status.loading += 1;
            // A new attempt replaces the previous error for this file.
            self.errors.retain(|e| e.path != path);
            self.spawn(move || {
                let result = Box::new(project::load_file(&path, kind));
                Message::Loaded { path, kind, result }
            });
        }
    }

    fn pick_files(&mut self) {
        self.status.picking = true;
        let dir = self.last_dir.clone();
        self.spawn(move || {
            let mut dialog = rfd::FileDialog::new().set_title("Add files to the project");
            if let Some(dir) = dir {
                dialog = dialog.set_directory(dir);
            }
            Message::Picked(dialog.pick_files().unwrap_or_default())
        });
    }

    /// Queues `paths` for loading and remembers their directory for the file picker.
    fn add_pending(&mut self, paths: Vec<PathBuf>) {
        if let Some(dir) = paths.first().and_then(|f| f.parent()) {
            self.last_dir = Some(dir.to_path_buf());
        }
        self.pending
            .extend(paths.into_iter().map(PendingFile::detect));
    }

    fn handle_messages(&mut self) {
        while let Ok(message) = self.rx.try_recv() {
            match message {
                Message::Picked(paths) => {
                    self.status.picking = false;
                    self.add_pending(paths);
                }
                Message::Loaded { path, kind, result } => {
                    self.status.loading -= 1;
                    match *result {
                        Ok(file) => {
                            log::info!("{}", file.summary());
                            self.project.insert(file);
                        }
                        Err(e) => {
                            let message = format!("{e:#}");
                            log::error!("{message}");
                            self.errors.push(LoadError {
                                path: path.clone(),
                                message,
                            });
                            // Back to the pending list, to fix its kind and retry.
                            self.pending.push(PendingFile {
                                path,
                                kind: Some(kind),
                            });
                        }
                    }
                }
            }
        }
    }

    fn apply(&mut self, action: ProjectAction) {
        match action {
            ProjectAction::PickFiles => self.pick_files(),
            ProjectAction::Load(files) => self.load(files),
            ProjectAction::RemovePolicy => self.project.remove_policy(),
            ProjectAction::RemoveFileContexts(i) => self.project.remove_file_contexts(i),
            ProjectAction::RemovePropertyContexts(i) => self.project.remove_property_contexts(i),
        }
    }

    /// Attributes open in the attribute tab, everything else in the type tab.
    fn navigate(&mut self, goto: Goto) {
        let is_attribute = |name: &str| {
            self.project
                .index()
                .is_some_and(|index| index.name_kind(name) == NameKind::Attribute)
        };
        match goto {
            Goto::Name(name) if is_attribute(&name) => {
                self.attribute_tab.selected = Some(name);
                self.tab = Tab::Attributes;
            }
            Goto::Name(name) | Goto::Rules(name) => {
                self.type_tab.input = name;
                self.tab = Tab::Type;
            }
        }
    }

    fn project_panel(&mut self, ui: &mut egui::Ui) {
        let action = egui::Panel::left("project_panel")
            .frame(spacing::side_panel_frame(ui.style()))
            .default_size(260.0)
            .show(ui, |ui| {
                brand(ui, &self.logo);
                ui.separator();
                egui::ScrollArea::vertical()
                    .show(ui, |ui| {
                        project_panel::show(
                            ui,
                            &self.project,
                            &mut self.pending,
                            &mut self.errors,
                            &self.status,
                        )
                    })
                    .inner
            })
            .inner;
        if let Some(action) = action {
            self.apply(action);
        }
    }

    fn central_panel(&mut self, ui: &mut egui::Ui) {
        let mut nav: Nav = None;
        egui::CentralPanel::default()
            .frame(spacing::central_panel_frame(ui.style()))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for tab in Tab::ALL {
                        ui.selectable_value(&mut self.tab, tab, tab.label());
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        info_toggle(ui, &mut self.about.open, "About");
                        ui.toggle_value(&mut self.settings.open, "⚙")
                            .on_hover_text("Settings");
                    });
                });
                ui.separator();
                let project = &self.project;
                match self.tab {
                    Tab::Path => self.path_tab.show(ui, project, &mut nav),
                    Tab::Property => self.property_tab.show(ui, project, &mut nav),
                    Tab::Type => self.type_tab.show(ui, project, &mut nav),
                    Tab::Attributes => self.attribute_tab.show(ui, project, &mut nav),
                }
            });
        if let Some(goto) = nav {
            self.navigate(goto);
        }
    }
}

impl eframe::App for SeguiApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if let Some(dir) = &self.last_dir {
            storage.set_string(LAST_DIR_KEY, dir.display().to_string());
        }
        storage.set_string(TEXT_SIZE_KEY, self.settings.text_size.to_string());
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.handle_messages();
        let dropped: Vec<PathBuf> = ui.ctx().input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if !dropped.is_empty() {
            self.add_pending(dropped);
        }

        // Side panels must be added before the central panel.
        self.project_panel(ui);
        self.central_panel(ui);
        self.settings.show(ui.ctx());
        self.about.show(ui.ctx(), &self.logo);
    }
}

/// Logo, centered at the top of the project panel.
fn brand(ui: &mut egui::Ui, logo: &egui::TextureHandle) {
    ui.vertical_centered(|ui| {
        ui.add_space(8.0);
        ui.add(egui::Image::new(logo).fit_to_exact_size(egui::vec2(96.0, 96.0)));
        ui.add_space(4.0);
    });
}
