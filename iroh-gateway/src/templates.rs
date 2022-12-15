use phf::{phf_set, Set};
use std::{ffi::OsStr, path::Path};

pub const DIR_LIST_TEMPLATE: &str = include_str!("../assets/dir_list.html");
pub const NOT_FOUND_TEMPLATE: &str = include_str!("../assets/404.html");
pub const STYLESHEET: &str = include_str!("../assets/style.css");
pub const ICONS_STYLESHEET: &str = include_str!("../assets/icons.css");

static KNOWN_ICONS: Set<&'static str> = phf_set! {
    ".aac", ".aiff", ".ai", ".avi", ".bmp", ".c", ".cpp", ".css", ".dat", ".dmg", ".doc",
        ".dotx", ".dwg", ".dxf", ".eps", ".exe", ".flv", ".gif", ".h", ".hpp", ".html", ".ics",
        ".iso", ".java", ".jpg", ".jpeg", ".js", ".key", ".less", ".mid", ".mkv", ".mov", ".mp3",
        ".mp4", ".mpg", ".odf", ".ods", ".odt", ".otp", ".ots", ".ott", ".pdf", ".php", ".png",
        ".ppt", ".psd", ".py", ".qt", ".rar", ".rb", ".rtf", ".sass", ".scss", ".sql", ".tga",
        ".tgz", ".tiff", ".txt", ".wav", ".wmv", ".xls", ".xlsx", ".xml", ".yml", ".zip",
};

pub fn icon_class_name(path: &str) -> String {
    let ext = Path::new(path)
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or("");
    let icon = if KNOWN_ICONS.contains(ext) {
        ext
    } else {
        "_blank"
    };
    format!("icon-{icon}")
}
