//! macOS desktop backend. Clipboard, links, notifications and the file picker
//! go through the system's own command-line tools, and the tray is an
//! `NSStatusItem` made through the Objective-C runtime on Discord's main
//! thread, so the crate links nothing beyond libSystem.

use std::{
   ffi::{CStr, CString, c_char, c_void},
   io::Write as _,
   path::PathBuf,
   process::{Command, Stdio},
   ptr,
   sync::{
      Once,
      atomic::{AtomicUsize, Ordering},
      mpsc,
   },
   thread,
};

use crate::{DesktopHost, Error, TrayAction, config, spawn_reaped};

/// Chromium-family browsers that take `--app=<url>`, by bundle and binary.
const APP_BROWSERS: [(&str, &str); 4] = [
   ("Google Chrome.app", "Google Chrome"),
   ("Chromium.app", "Chromium"),
   ("Brave Browser.app", "Brave Browser"),
   ("Microsoft Edge.app", "Microsoft Edge"),
];

pub struct Host;

impl DesktopHost for Host {
   fn copy(text: &str) -> Result<(), Error> {
      if copy_pasteboard(text) {
         return Ok(());
      }
      let fail = |message: String| Error::Platform { message };
      let mut child = Command::new("/usr/bin/pbcopy")
         .stdin(Stdio::piped())
         .stdout(Stdio::null())
         .stderr(Stdio::null())
         .spawn()
         .map_err(|err| fail(format!("pbcopy: {err}")))?;
      let written = child
         .stdin
         .take()
         .is_some_and(|mut stdin| stdin.write_all(text.as_bytes()).is_ok());
      if child.wait().is_ok_and(|status| status.success()) && written {
         Ok(())
      } else {
         Err(fail("pbcopy failed".to_owned()))
      }
   }

   fn open(target: &str) -> Result<(), Error> {
      spawn_reaped(Command::new("/usr/bin/open").arg("--").arg(target))
   }

   fn open_window(url: &str, width: u32, height: u32) -> bool {
      open_webview(url, width, height)
   }

   fn app_browser() -> Option<Command> {
      let home = std::env::var_os("HOME").map(PathBuf::from);
      let roots = [
         Some(PathBuf::from("/Applications")),
         home.map(|home| home.join("Applications")),
      ];
      APP_BROWSERS
         .into_iter()
         .flat_map(|(bundle, binary)| {
            roots
               .iter()
               .flatten()
               .map(move |root| root.join(bundle).join("Contents/MacOS").join(binary))
         })
         .find(|path| path.is_file())
         .map(Command::new)
   }

   fn pick_js_path() -> Option<PathBuf> {
      let (tx, rx) = mpsc::channel();
      on_main_with(move || {
         let picked = unsafe { pick_js_open_panel() };
         let _ = tx.send(picked);
      });
      rx.recv().ok().flatten()
   }

   fn notify(title: &str, body: &str) {
      // The text travels as arguments, never inside the script, so a plugin's
      // quote can't change what runs.
      let mut script = Command::new("/usr/bin/osascript");
      script.args([
         "-e",
         "on run argv",
         "-e",
         "display notification (item 2 of argv) with title (item 1 of argv)",
         "-e",
         "end run",
         "--",
         title,
         body,
      ]);
      if let Err(err) = spawn_reaped(&mut script) {
         log::debug!("notify: {err}");
      }
   }

   fn start_tray() {
      static STARTED: Once = Once::new();
      STARTED.call_once(|| {
         on_main(start_status_item);
         on_main(start_shortcuts);
      });
   }
}

/// Marks every window's content view and GPUI subview layers dirty, from any
/// thread. `GPUIView` uses `RedrawDuringViewResize`, so only invalidating its
/// `CALayer` triggers `displayLayer:`.
pub fn redraw_windows() {
   on_main(|| {
      // SAFETY: on the main thread, where AppKit may be used; every object is
      // checked for nil before it is messaged.
      unsafe {
         let app = send(class(c"NSApplication"), sel(c"sharedApplication"));
         let windows = send(app, sel(c"windows"));
         if windows.is_null() {
            return;
         }
         let count = send_usize(windows, sel(c"count"));
         for at in 0..count {
            let window = send_index(windows, sel(c"objectAtIndex:"), at);
            let view = send(window, sel(c"contentView"));
            if view.is_null() {
               continue;
            }
            send_bool(view, sel(c"setNeedsDisplay:"), true);
            let layer = send(view, sel(c"layer"));
            if !layer.is_null() {
               send_void(layer, sel(c"setNeedsDisplay"));
            }
            let subviews = send(view, sel(c"subviews"));
            if subviews.is_null() {
               continue;
            }
            let sub_count = send_usize(subviews, sel(c"count"));
            for sub_at in 0..sub_count {
               let sub = send_index(subviews, sel(c"objectAtIndex:"), sub_at);
               let sub_layer = send(sub, sel(c"layer"));
               if !sub_layer.is_null() {
                  send_void(sub_layer, sel(c"setNeedsDisplay"));
               }
            }
         }
      }
   });
}

type Id = *mut c_void;
type Sel = *const c_void;

#[link(name = "objc")]
unsafe extern "C" {
   fn objc_getClass(name: *const c_char) -> Id;
   fn sel_registerName(name: *const c_char) -> Sel;
   fn objc_msgSend();
   fn objc_allocateClassPair(superclass: Id, name: *const c_char, extra: usize) -> Id;
   fn objc_registerClassPair(class: Id);
   fn class_addMethod(class: Id, name: Sel, imp: *const c_void, types: *const c_char) -> bool;
}

unsafe extern "C" {
   fn dlopen(path: *const c_char, mode: std::ffi::c_int) -> *mut c_void;
   static _dispatch_main_q: c_void;
   fn dispatch_async_f(
      queue: *const c_void,
      context: *mut c_void,
      work: extern "C" fn(*mut c_void),
   );
}

fn class(name: &CStr) -> Id {
   // SAFETY: a lookup by NUL-terminated name, nil when missing.
   unsafe { objc_getClass(name.as_ptr()) }
}

fn sel(name: &CStr) -> Sel {
   // SAFETY: registers or finds a selector by NUL-terminated name.
   unsafe { sel_registerName(name.as_ptr()) }
}

/// `objc_msgSend` cast to one method's exact signature, which arm64 needs
/// since it passes variadic arguments differently.
macro_rules! msg_send {
   ($name:ident ($($arg:ident: $ty:ty),*) -> $ret:ty) => {
      /// # Safety
      ///
      /// `object` is nil or responds to `selector` with this signature.
      unsafe fn $name(object: Id, selector: Sel $(, $arg: $ty)*) -> $ret {
         // SAFETY: the caller matches the method's signature.
         unsafe {
            let send: unsafe extern "C" fn(Id, Sel $(, $ty)*) -> $ret =
               std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send(object, selector $(, $arg)*)
         }
      }
   };
}

msg_send!(send() -> Id);
msg_send!(send_void() -> ());
msg_send!(send_id(arg: Id) -> Id);
msg_send!(send_id2(a: Id, b: Id) -> bool);
msg_send!(send_bool(arg: bool) -> ());
msg_send!(send_usize() -> usize);
msg_send!(send_usize_unit(arg: usize) -> ());
msg_send!(send_index(at: usize) -> Id);
msg_send!(send_isize(arg: isize) -> ());
msg_send!(send_f64(arg: f64) -> Id);
msg_send!(send_str(arg: *const c_char) -> Id);
msg_send!(send_cstr() -> *const c_char);
msg_send!(send_monitor(mask: u64, handler: *const Block) -> Id);
msg_send!(send_symbol(name: Id, description: Id) -> Id);
msg_send!(send_item(title: Id, action: Sel, key: Id) -> Id);
msg_send!(send_tag() -> isize);
msg_send!(send_modal() -> isize);
msg_send!(send_window_init(rect: Rect, style: usize, backing: usize, defer: bool) -> Id);
msg_send!(send_webview_init(frame: Rect, config: Id) -> Id);

#[repr(C)]
#[derive(Clone, Copy)]
struct Rect {
   x: f64,
   y: f64,
   width: f64,
   height: f64,
}

fn copy_pasteboard(text: &str) -> bool {
   // SAFETY: NSPasteboard is safe to message when AppKit is loaded.
   unsafe {
      let cls = class(c"NSPasteboard");
      if cls.is_null() {
         return false;
      }
      let pb = send(cls, sel(c"generalPasteboard"));
      if pb.is_null() {
         return false;
      }
      let _ = send_tag(pb, sel(c"clearContents"));
      let value = ns_string(text);
      if value.is_null() {
         return false;
      }
      send_id2(
         pb,
         sel(c"setString:forType:"),
         value,
         ns_string("public.utf8-plain-text"),
      )
   }
}

/// Opens a native `NSOpenPanel` filtered to `.js` files on the main thread.
///
/// # Safety
///
/// Must run on the main thread inside an autorelease pool.
unsafe fn pick_js_open_panel() -> Option<PathBuf> {
   const MODAL_OK: isize = 1;
   unsafe {
      let cls = class(c"NSOpenPanel");
      if cls.is_null() {
         return None;
      }
      let panel = send(cls, sel(c"openPanel"));
      if panel.is_null() {
         return None;
      }
      send_id(panel, sel(c"setTitle:"), ns_string("Install Sunbird Plugin (.js)"));
      send_bool(panel, sel(c"setCanChooseFiles:"), true);
      send_bool(panel, sel(c"setCanChooseDirectories:"), false);
      send_bool(panel, sel(c"setAllowsMultipleSelection:"), false);
      let types = send_id(class(c"NSArray"), sel(c"arrayWithObject:"), ns_string("js"));
      if !types.is_null() {
         send_id(panel, sel(c"setAllowedFileTypes:"), types);
      }
      let app = send(class(c"NSApplication"), sel(c"sharedApplication"));
      if !app.is_null() {
         send_bool(app, sel(c"activateIgnoringOtherApps:"), true);
      }
      if send_modal(panel, sel(c"runModal")) != MODAL_OK {
         return None;
      }
      let url = send(panel, sel(c"URL"));
      if url.is_null() {
         return None;
      }
      let path = send(url, sel(c"path"));
      if path.is_null() {
         return None;
      }
      let utf8 = send_cstr(path, sel(c"UTF8String"));
      if utf8.is_null() {
         return None;
      }
      let text = CStr::from_ptr(utf8).to_str().ok()?;
      (!text.is_empty()).then(|| PathBuf::from(text))
   }
}

/// Loads `WebKit.framework` once and returns whether `WKWebView` is available.
fn ensure_webkit() -> bool {
   static LOADED: Once = Once::new();
   LOADED.call_once(|| {
      const PATH: &CStr = c"/System/Library/Frameworks/WebKit.framework/WebKit";
      // RTLD_LAZY (1) | RTLD_LOCAL (4) on Darwin
      // SAFETY: dlopen loads a system framework by constant path.
      unsafe {
         dlopen(PATH.as_ptr(), 0x5);
      }
   });
   !class(c"WKWebView").is_null() && !class(c"NSWindow").is_null()
}

/// Opens or reuses a native `WKWebView` window pointing at `url`.
fn open_webview(url: &str, width: u32, height: u32) -> bool {
   if !ensure_webkit() {
      return false;
   }
   let url = url.to_owned();
   let (tx, rx) = mpsc::channel();
   on_main_with(move || {
      // SAFETY: runs on the main thread inside an autorelease pool.
      let ok = unsafe { show_webview(&url, width, height) };
      let _ = tx.send(ok);
   });
   rx.recv().unwrap_or(false)
}

static WEBVIEW_WIN: AtomicUsize = AtomicUsize::new(0);
static WEBVIEW_VIEW: AtomicUsize = AtomicUsize::new(0);

/// # Safety
///
/// Runs on the main thread.
unsafe fn show_webview(url: &str, width: u32, height: u32) -> bool {
   const STYLE: usize = 1 | 2 | 4 | 8;
   const BUFFERED: usize = 2;

   unsafe {
      let ns_url = send_id(class(c"NSURL"), sel(c"URLWithString:"), ns_string(url));
      if ns_url.is_null() {
         return false;
      }
      let req = send_id(class(c"NSURLRequest"), sel(c"requestWithURL:"), ns_url);
      if req.is_null() {
         return false;
      }

      let mut win = WEBVIEW_WIN.load(Ordering::Acquire) as Id;
      let mut view = WEBVIEW_VIEW.load(Ordering::Acquire) as Id;
      if win.is_null() || view.is_null() {
         let frame = Rect {
            x: 0.0,
            y: 0.0,
            width: f64::from(width),
            height: f64::from(height),
         };
         win = send_window_init(
            send(class(c"NSWindow"), sel(c"alloc")),
            sel(c"initWithContentRect:styleMask:backing:defer:"),
            frame,
            STYLE,
            BUFFERED,
            false,
         );
         let cfg = send(send(class(c"WKWebViewConfiguration"), sel(c"alloc")), sel(c"init"));
         view = send_webview_init(
            send(class(c"WKWebView"), sel(c"alloc")),
            sel(c"initWithFrame:configuration:"),
            frame,
            cfg,
         );
         if win.is_null() || view.is_null() {
            return false;
         }
         send_bool(win, sel(c"setReleasedWhenClosed:"), false);
         send_id(win, sel(c"setTitle:"), ns_string("Sunbird"));
         let dark = send_id(
            class(c"NSAppearance"),
            sel(c"appearanceNamed:"),
            ns_string("NSAppearanceNameDarkAqua"),
         );
         if !dark.is_null() {
            send_id(win, sel(c"setAppearance:"), dark);
         }
         send_id(win, sel(c"setContentView:"), view);
         send(win, sel(c"center"));
         WEBVIEW_WIN.store(win as usize, Ordering::Release);
         WEBVIEW_VIEW.store(view as usize, Ordering::Release);
      }

      let _ = send_id(view, sel(c"loadRequest:"), req);
      send_id(win, sel(c"makeKeyAndOrderFront:"), ptr::null_mut());
      let app = send(class(c"NSApplication"), sel(c"sharedApplication"));
      if !app.is_null() {
         send_bool(app, sel(c"activateIgnoringOtherApps:"), true);
      }
      true
   }
}

mod panel;

pub use panel::{
   Action as PanelAction, PanelButton, PanelSection, close_panel, panel_text, set_panel_status,
   show_panel,
};

/// An autoreleased `NSString`, nil for text with a NUL.
///
/// # Safety
///
/// On the main thread, inside its autorelease pool.
unsafe fn ns_string(text: &str) -> Id {
   let Ok(text) = CString::new(text) else {
      return ptr::null_mut();
   };
   // SAFETY: forwarded from the caller; `text` outlives the call, which copies
   // it.
   unsafe {
      send_str(
         class(c"NSString"),
         sel(c"stringWithUTF8String:"),
         text.as_ptr(),
      )
   }
}

/// Runs `work` on the main thread, where `AppKit` lives, through its dispatch
/// queue, which GPUI's `NSApplication` run loop drains.
fn on_main(work: fn()) {
   extern "C" fn run(context: *mut c_void) {
      // SAFETY: `context` is the `fn()` `on_main` passed.
      let work = unsafe { std::mem::transmute::<*mut c_void, fn()>(context) };
      work();
   }
   // SAFETY: the main queue lives as long as the process, and `run` reads
   // `context` back as the `fn()` it is.
   unsafe { dispatch_async_f(&raw const _dispatch_main_q, work as *mut c_void, run) };
}

/// [`on_main`] for a closure, which may own what it moves to the main thread.
fn on_main_with(work: impl FnOnce() + Send + 'static) {
   type Work = Box<dyn FnOnce() + Send>;
   extern "C" fn run(context: *mut c_void) {
      // SAFETY: `context` is the `Box<Work>` `on_main_with` leaked, read back
      // once.
      let work = unsafe { Box::from_raw(context.cast::<Work>()) };
      work();
   }
   let work: Box<Work> = Box::new(Box::new(work));
   // SAFETY: the main queue lives as long as the process, and `run` takes
   // back the box exactly once.
   unsafe {
      dispatch_async_f(&raw const _dispatch_main_q, Box::into_raw(work).cast(), run);
   }
}

/// The status item's menu calls this with the clicked item, whose tag is its
/// index in [`TrayAction::MENU`]. Actions may block, so they run elsewhere.
extern "C" fn tray_clicked(_this: Id, _selector: Sel, sender: Id) {
   // SAFETY: AppKit passes the `NSMenuItem` that was clicked.
   let tag = unsafe { send_tag(sender, sel(c"tag")) };
   let Some(action) = usize::try_from(tag)
      .ok()
      .and_then(|at| TrayAction::MENU.get(at).copied().flatten())
   else {
      return;
   };
   let _ = thread::Builder::new()
      .name("sunbird-tray".to_owned())
      .spawn(move || action.run());
}

/// The target object for the menu's items: an `NSObject` subclass answering
/// `sunbirdTray:`.
///
/// # Safety
///
/// On the main thread.
unsafe fn tray_target() -> Id {
   const NAME: &CStr = c"SunbirdTrayTarget";
   let mut target = class(NAME);
   if target.is_null() {
      // SAFETY: registers a new subclass with one `v@:@` method, which is
      // `tray_clicked`'s signature.
      unsafe {
         target = objc_allocateClassPair(class(c"NSObject"), NAME.as_ptr(), 0);
         if target.is_null() {
            return ptr::null_mut();
         }
         class_addMethod(
            target,
            sel(c"sunbirdTray:"),
            tray_clicked as *const c_void,
            c"v@:@".as_ptr(),
         );
         objc_registerClassPair(target);
      }
   }
   // SAFETY: a fresh instance of an `NSObject` subclass, owned forever.
   unsafe { send(send(target, sel(c"alloc")), sel(c"init")) }
}

fn start_status_item() {
   /// `NSVariableStatusItemLength`.
   const VARIABLE_LENGTH: f64 = -1.0;

   // SAFETY: on the main thread; every object is checked for nil before
   // anything depends on it, and the item, menu and target are kept for the
   // life of the process.
   unsafe {
      let bar = send(class(c"NSStatusBar"), sel(c"systemStatusBar"));
      let target = tray_target();
      if bar.is_null() || target.is_null() {
         log::info!(
            "tray: AppKit is not available, Sunbird Settings is at {}",
            config().map_or("", |config| &config.dashboard_url)
         );
         return;
      }
      let item = send(
         send_f64(bar, sel(c"statusItemWithLength:"), VARIABLE_LENGTH),
         sel(c"retain"),
      );
      let button = send(item, sel(c"button"));
      let image = send_symbol(
         class(c"NSImage"),
         sel(c"imageWithSystemSymbolName:accessibilityDescription:"),
         ns_string("bird"),
         ns_string("Sunbird"),
      );
      if image.is_null() {
         send_id(button, sel(c"setTitle:"), ns_string("Sunbird"));
      } else {
         send_id(button, sel(c"setImage:"), image);
      }
      send_id(button, sel(c"setToolTip:"), ns_string("Sunbird"));

      let menu = send_id(
         send(class(c"NSMenu"), sel(c"alloc")),
         sel(c"initWithTitle:"),
         ns_string("Sunbird"),
      );
      for (at, entry) in TrayAction::MENU.iter().enumerate() {
         let menu_item = entry.map_or_else(
            || send(class(c"NSMenuItem"), sel(c"separatorItem")),
            |action| {
               let (key, mask) = match action {
                  TrayAction::OpenSettings => ("u", Some(CONTROL_SHIFT)),
                  TrayAction::OpenDevtools => ("I", None),
                  _ => ("", None),
               };
               let menu_item = send_item(
                  send(class(c"NSMenuItem"), sel(c"alloc")),
                  sel(c"initWithTitle:action:keyEquivalent:"),
                  ns_string(action.label()),
                  sel(c"sunbirdTray:"),
                  ns_string(key),
               );
               if let Some(mask) = mask {
                  send_usize_unit(menu_item, sel(c"setKeyEquivalentModifierMask:"), mask);
               }
               send_id(menu_item, sel(c"setTarget:"), target);
               send_isize(menu_item, sel(c"setTag:"), at.cast_signed());
               menu_item
            },
         );
         send_id(menu, sel(c"addItem:"), menu_item);
      }
      send_id(item, sel(c"setMenu:"), menu);
   }
}

/// Sunbird's shortcuts while Discord is focused: Control-Shift-U opens
/// Sunbird's settings, since Command-Shift-U is Discord's own Upload File, and
/// Command-Shift-I its `DevTools`, which Discord leaves free.
const SHORTCUTS: [(usize, &str, fn()); 2] = [
   (CONTROL_SHIFT, "u", crate::open_settings),
   (COMMAND_SHIFT, "i", crate::open_devtools),
];

// shift, control, option, command (ignore caps lock, numpad, fn)
const CONTROL_SHIFT: usize = (1 << 17) | (1 << 18);
const COMMAND_SHIFT: usize = (1 << 17) | (1 << 20);
const MODIFIERS: usize = (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20);

/// An Objective-C block, laid out as the runtime reads one.
#[repr(C)]
struct Block {
   isa: *const c_void,
   flags: i32,
   reserved: i32,
   invoke: extern "C" fn(*const Self, Id) -> Id,
   descriptor: *const BlockDescriptor,
}

#[repr(C)]
struct BlockDescriptor {
   reserved: usize,
   size: usize,
}

unsafe extern "C" {
   static _NSConcreteGlobalBlock: c_void;
}

/// `NSEvent *(^)(NSEvent *)`: runs a shortcut and swallows its key, or hands
/// every other key on.
extern "C" fn key_down(_block: *const Block, event: Id) -> Id {
   // SAFETY: AppKit passes the `NSEvent` being dispatched.
   let (chars, flags) = unsafe {
      (
         send(event, sel(c"charactersIgnoringModifiers")),
         send_usize(event, sel(c"modifierFlags")),
      )
   };
   let pressed = flags & MODIFIERS;
   if chars.is_null() {
      return event;
   }
   // SAFETY: `chars` is a non-nil `NSString` whose `UTF8String` lives for this autorelease pool.
   let key = unsafe {
      let ptr = send_cstr(chars, sel(c"UTF8String"));
      if ptr.is_null() {
         return event;
      }
      CStr::from_ptr(ptr).to_str().unwrap_or("")
   };
   let Some(&(_, matched, run)) = SHORTCUTS
      .iter()
      .find(|&&(modifiers, wanted, _)| modifiers == pressed && key.eq_ignore_ascii_case(wanted))
   else {
      return event;
   };
   log::info!("shortcuts: key {matched}");
   // Opening spawns a browser, which must not block the main thread.
   let _ = thread::Builder::new()
      .name("sunbird-shortcut".to_owned())
      .spawn(run);
   ptr::null_mut()
}

fn start_shortcuts() {
   /// `NSEventMaskKeyDown`.
   const KEY_DOWN: u64 = 1 << 10;
   /// `BLOCK_IS_GLOBAL`: the runtime never copies or frees it.
   const IS_GLOBAL: i32 = 1 << 28;
   static DESCRIPTOR: BlockDescriptor = BlockDescriptor {
      reserved: 0,
      size: size_of::<Block>(),
   };

   // Leaked, since the monitor keeps it for the life of the process.
   let block = Box::leak(Box::new(Block {
      isa: &raw const _NSConcreteGlobalBlock,
      flags: IS_GLOBAL,
      reserved: 0,
      invoke: key_down,
      descriptor: &raw const DESCRIPTOR,
   }));
   // SAFETY: on the main thread; the block has the handler's signature and
   // outlives the monitor, which AppKit retains.
   let monitor = unsafe {
      send_monitor(
         class(c"NSEvent"),
         sel(c"addLocalMonitorForEventsMatchingMask:handler:"),
         KEY_DOWN,
         block,
      )
   };
   if monitor.is_null() {
      log::info!("shortcuts: AppKit refused the key monitor");
   } else {
      log::info!("shortcuts: Control-Shift-U opens settings, Command-Shift-I DevTools");
   }
}
