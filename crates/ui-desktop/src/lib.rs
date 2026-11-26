//! Desktop UI host primitives for Phoenix (Windows / macOS / Linux).
//!
//! Desktop Phoenix renders natively in Rust with GPUI rather than Android's
//! serialized UI-op bridge (`phoenix-ui-mobile`). This crate owns the
//! desktop-side UI interactions: clipboard, opening URLs / standalone settings
//! window, system tray + global hotkey (`Ctrl+Shift+U`) + native notifications,
//! and the self-contained Desktop Settings dashboard served over localhost.
//!
//! Each OS implements [`DesktopHost`]; everything above it is shared here.

#[cfg(target_os = "linux")] mod linux;
#[cfg(target_os = "macos")] mod macos;
#[cfg(windows)] mod webview;
#[cfg(windows)] mod windows;

use std::{
   path::PathBuf,
   process::Command,
   sync::{
      Arc,
      OnceLock,
   },
   thread,
};

#[cfg(target_os = "linux")] use linux::Host as Os;
#[cfg(target_os = "macos")] use macos::Host as Os;
#[cfg(target_os = "macos")]
pub use macos::{
   PanelAction,
   PanelButton,
   PanelSection,
   close_panel,
   panel_text,
   redraw_windows,
   set_panel_status,
   show_panel,
};
#[cfg(windows)] use windows::Host as Os;

/// Self-contained HTML/JS/CSS companion dashboard for Desktop settings,
/// plugin management, catalog installs, OTA updates, and JS console.
pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");

#[derive(Debug, flub::Error)]
pub enum Error {
   #[error("desktop ui: {message}")]
   Platform { message: String },
   #[error("desktop ui: unsupported on this target")]
   Unsupported,
}

/// Configuration and runtime callbacks for the desktop system tray.
pub struct TrayConfig {
   pub dashboard_url:    String,
   pub plugins_dir:      PathBuf,
   pub on_reload_all:    Option<Arc<dyn Fn() + Send + Sync>>,
   pub on_check_updates: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// What the tray menu offers, the same on every OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
   not(any(windows, target_os = "linux", target_os = "macos")),
   allow(dead_code, reason = "no tray backend on this target")
)]
enum TrayAction {
   OpenSettings,
   OpenDevtools,
   ReloadAll,
   CheckUpdates,
   CopyUrl,
   OpenPlugins,
}

impl TrayAction {
   /// The menu in order, `None` for a separator.
   #[cfg_attr(
      not(any(target_os = "linux", target_os = "macos", test)),
      expect(
         dead_code,
         reason = "the Windows menu has its own labels with hotkey hints"
      )
   )]
   const MENU: [Option<Self>; 8] = [
      Some(Self::OpenSettings),
      Some(Self::OpenDevtools),
      None,
      Some(Self::ReloadAll),
      Some(Self::CheckUpdates),
      None,
      Some(Self::CopyUrl),
      Some(Self::OpenPlugins),
   ];

   #[cfg_attr(
      not(any(target_os = "linux", target_os = "macos", test)),
      expect(
         dead_code,
         reason = "the Windows menu has its own labels with hotkey hints"
      )
   )]
   const fn label(self) -> &'static str {
      match self {
         Self::OpenSettings => "Open Sunbird Settings",
         Self::OpenDevtools => "Open DevTools (Console)",
         Self::ReloadAll => "Reload All Plugins",
         Self::CheckUpdates => "Check for Updates",
         Self::CopyUrl => "Copy Dashboard URL",
         Self::OpenPlugins => "Open Plugins Folder",
      }
   }

   #[cfg_attr(
      not(any(windows, target_os = "linux", target_os = "macos")),
      allow(dead_code, reason = "no tray backend on this target")
   )]
   fn run(self) {
      let Some(config) = config() else {
         return;
      };
      match self {
         Self::OpenSettings => open_settings(),
         Self::OpenDevtools => open_devtools(),
         Self::ReloadAll => {
            if let Some(reload) = &config.on_reload_all {
               reload();
            }
         },
         Self::CheckUpdates => {
            if let Some(check) = &config.on_check_updates {
               check();
            }
         },
         Self::CopyUrl => {
            if copy(&config.dashboard_url).is_ok() {
               Os::notify("Sunbird", &format!("Copied {}", config.dashboard_url));
            }
         },
         Self::OpenPlugins => {
            let _ = std::fs::create_dir_all(&config.plugins_dir);
            if let Err(err) = Os::open(&config.plugins_dir.to_string_lossy()) {
               log::warn!("tray: could not open the plugins folder: {err}");
            }
         },
      }
   }
}

/// The OS primitives a desktop backend provides. The defaults are what a
/// target without a backend gets.
trait DesktopHost {
   fn copy(_text: &str) -> Result<(), Error> {
      Err(Error::Unsupported)
   }

   /// Opens a URL or local path with the system handler. Callers have
   /// already checked the URL scheme.
   fn open(_target: &str) -> Result<(), Error> {
      Err(Error::Unsupported)
   }

   /// Opens a URL inside a native in-process webview window if the backend
   /// provides one. Returning `false` falls back to an app browser or `open`.
   fn open_window(_url: &str, _width: u32, _height: u32) -> bool {
      false
   }

   /// A Chromium-family browser that takes `--app=<url>`, if one is installed.
   fn app_browser() -> Option<Command> {
      None
   }

   /// Asks for a `.js` file with the native picker.
   fn pick_js_path() -> Option<PathBuf> {
      None
   }

   fn notify(_title: &str, _body: &str) {}

   /// Starts the tray and hotkeys after [`config`] is set.
   fn start_tray() {}
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
struct Os;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
impl DesktopHost for Os {}

static CONFIG: OnceLock<TrayConfig> = OnceLock::new();

fn config() -> Option<&'static TrayConfig> {
   CONFIG.get()
}

/// Starts the desktop system tray icon and `Ctrl+Shift+U` global hotkey
/// pointing at `config.dashboard_url`.
pub fn start_tray(config: TrayConfig) {
   let _ = CONFIG.set(config);
   Os::start_tray();
}

/// Opens the Sunbird Settings dashboard in a standalone chromeless app window
/// (a Chromium `--app` window when available, else the system browser).
pub fn open_settings() {
   if let Some(config) = config() {
      open_app_window(&config.dashboard_url, 1020, 740);
   }
}

/// The `DevTools` shortcut as Sunbird's pages name it: Command on macOS, where
/// Control-Shift-I would be out of place, Control elsewhere.
pub const DEVTOOLS_SHORTCUT: &str = if cfg!(target_os = "macos") {
   "Cmd+Shift+I"
} else {
   "Ctrl+Shift+I"
};

/// Opens the Sunbird `DevTools` / Runtime Console directly in a standalone
/// window ([`DEVTOOLS_SHORTCUT`] while Discord Phoenix is focused).
pub fn open_devtools() {
   if let Some(config) = config() {
      open_app_window(&format!("{}#console", config.dashboard_url), 960, 680);
   }
}

fn open_app_window(url: &str, width: u32, height: u32) {
   let Some(config) = config() else {
      return;
   };
   if Os::open_window(url, width, height) {
      return;
   }
   if let Some(mut browser) = Os::app_browser() {
      let profile_dir = config
         .plugins_dir
         .parent()
         .unwrap_or(&config.plugins_dir)
         .join("app-ui");
      browser
         .arg(format!("--app={url}"))
         .arg(format!("--window-size={width},{height}"))
         .arg(format!("--user-data-dir={}", profile_dir.display()));
      if spawn_reaped(&mut browser).is_ok() {
         return;
      }
   }
   if let Err(err) = open_url(url) {
      log::warn!("desktop ui: could not open {url}: {err}");
   }
}

/// Spawns `command` and waits for it on a background thread, so it never
/// lingers as a zombie on Unix.
fn spawn_reaped(command: &mut Command) -> Result<(), Error> {
   let mut child = command.spawn().map_err(|err| {
      Error::Platform {
         message: format!("{}: {err}", command.get_program().display()),
      }
   })?;
   let _ = thread::Builder::new()
      .name("sunbird-reap".to_owned())
      .spawn(move || child.wait());
   Ok(())
}

/// Copies `text` to the system clipboard.
pub fn copy(text: &str) -> Result<(), Error> {
   Os::copy(text)
}

/// Opens the native OS file picker for choosing a `.js` plugin bundle to
/// install (`(file_name, bytes)`).
#[must_use]
pub fn pick_js_file() -> Option<(String, Vec<u8>)> {
   let path = Os::pick_js_path()?;
   let name = path.file_name()?.to_string_lossy().into_owned();
   let bytes = std::fs::read(&path).ok()?;
   Some((name, bytes))
}

/// Opens `url` in the system's default browser / handler.
pub fn open_url(url: &str) -> Result<(), Error> {
   if !url.starts_with("https://") && !url.starts_with("http://") && !url.starts_with("discord://")
   {
      return Err(Error::Platform {
         message: format!("refusing to open non-web URL: {url}"),
      });
   }
   Os::open(url)
}

/// Shows a short desktop toast / notification message.
pub fn toast(message: &str) {
   log::info!("[toast] {message}");
   Os::notify("Sunbird", message);
}

/// Shows a titled desktop notification.
pub fn notify(title: &str, body: Option<&str>) {
   match body {
      Some(body) if !body.is_empty() => {
         log::info!("[notify] {title}: {body}");
         Os::notify(title, body);
      },
      _ => {
         log::info!("[notify] {title}");
         Os::notify("Sunbird", title);
      },
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn rejects_unsafe_url_schemes() {
      assert!(open_url("file:///C:/Windows/notepad.exe").is_err());
      assert!(open_url("javascript:alert(1)").is_err());
   }

   #[test]
   fn tray_menu_lists_every_action_once() {
      let actions = TrayAction::MENU.iter().flatten().collect::<Vec<_>>();
      assert_eq!(actions.len(), 6);
      for (at, action) in actions.iter().enumerate() {
         assert!(!actions[at + 1..].contains(action));
         assert_ne!(action.label(), "");
      }
   }

   #[test]
   fn dashboard_html_is_embedded() {
      assert!(DASHBOARD_HTML.contains("<title>Sunbird"));
      assert!(DASHBOARD_HTML.contains("/plugins"));
      assert!(DASHBOARD_HTML.contains("/catalog"));
   }
}
