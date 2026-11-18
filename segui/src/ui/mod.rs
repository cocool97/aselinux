//! User interface: tabs, side panel and windows.

pub(crate) mod access_tab;
pub(crate) mod attribute_tab;
pub(crate) mod project_panel;
pub(crate) mod query;
pub(crate) mod spacing;
pub(crate) mod type_tab;
pub(crate) mod widgets;
pub(crate) mod windows;

use eframe::egui::Color32;

pub(crate) const WARN_COLOR: Color32 = Color32::from_rgb(230, 160, 60);

/// Navigation request, set by clickable widgets.
pub(crate) enum Goto {
    /// Open a name: attributes in the attribute tab, types in the type tab.
    Name(String),
    /// Open the rules of a name in the type tab, even for an attribute.
    Rules(String),
}

pub(crate) type Nav = Option<Goto>;

/// Extracts the type from a full context (`u:object_r:type:s0`), or returns the trimmed input.
pub(crate) fn subject_of(input: &str) -> &str {
    let input = input.trim();
    input.split(':').nth(2).unwrap_or(input)
}

#[cfg(test)]
mod tests {
    use super::subject_of;

    #[test]
    fn subject_is_the_type_of_a_context() {
        assert_eq!(subject_of(" u:object_r:logcat_exec:s0 "), "logcat_exec");
        assert_eq!(subject_of("u:r:init"), "init");
        assert_eq!(subject_of(" system_server "), "system_server");
    }
}
