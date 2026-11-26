//! Desktop Discord HTTP transport and request/response interception.
//!
//! Desktop Phoenix routes all Discord REST traffic through
//! `libdiscord/crates/http`'s `dyn Transport` (`ReqwestTransport::send(&self,
//! req) -> Pin<Box<dyn Future>>`). [`install`] locates `Transport::send` and
//! the `SendFuture::poll` vtable slots (build-independently via
//! [`DesktopHttpTransport::locate`]). The API client calls `send` directly, so
//! `send` gets an inline jump to its detour with a trampoline back, and the
//! poll slots are swapped with [`Image::swap_words`].
//!
//! Captured session headers stay in memory only and `authorization` is never
//! logged or persisted.

use std::{
   borrow::Cow,
   ffi::c_void,
   panic::{
      self,
      AssertUnwindSafe,
   },
   ptr,
   slice,
   str,
   sync::{
      Arc,
      OnceLock,
      atomic::{
         AtomicPtr,
         Ordering,
      },
   },
};

use phoenix_hook::image::Image;
use phoenix_runtime::{
   discord::{
      Authorization,
      DiscordError,
      RequestAction,
      api_path,
      observe_request,
      run_response_hooks,
      session_request,
      take_response,
      track_response,
      watch_response,
   },
   fetch::{
      self,
      Request,
      Response,
   },
};
use phoenix_sigs::{
   desktop,
   http::DesktopHttpTransport,
};

/// Standard HTTP/1.x `http::header::StandardHeader` names in discriminant
/// order (`0..=80`), matching `Discord.exe`'s compiled `http` crate.
const STANDARD_HEADERS: [&str; 81] = [
   "accept",
   "accept-charset",
   "accept-encoding",
   "accept-language",
   "accept-ranges",
   "access-control-allow-credentials",
   "access-control-allow-headers",
   "access-control-allow-methods",
   "access-control-allow-origin",
   "access-control-expose-headers",
   "access-control-max-age",
   "access-control-request-headers",
   "access-control-request-method",
   "age",
   "allow",
   "alt-svc",
   "authorization",
   "cache-control",
   "cache-status",
   "cdn-cache-control",
   "connection",
   "content-disposition",
   "content-encoding",
   "content-language",
   "content-length",
   "content-location",
   "content-range",
   "content-security-policy",
   "content-security-policy-report-only",
   "content-type",
   "cookie",
   "dnt",
   "date",
   "etag",
   "expect",
   "expires",
   "forwarded",
   "from",
   "host",
   "if-match",
   "if-modified-since",
   "if-none-match",
   "if-range",
   "if-unmodified-since",
   "last-modified",
   "link",
   "location",
   "max-forwards",
   "origin",
   "pragma",
   "proxy-authenticate",
   "proxy-authorization",
   "public-key-pins",
   "public-key-pins-report-only",
   "range",
   "referer",
   "referrer-policy",
   "refresh",
   "retry-after",
   "sec-websocket-accept",
   "sec-websocket-extensions",
   "sec-websocket-key",
   "sec-websocket-protocol",
   "sec-websocket-version",
   "server",
   "set-cookie",
   "strict-transport-security",
   "te",
   "trailer",
   "transfer-encoding",
   "user-agent",
   "upgrade",
   "upgrade-insecure-requests",
   "vary",
   "via",
   "warning",
   "www-authenticate",
   "x-content-type-options",
   "x-dns-prefetch-control",
   "x-frame-options",
   "x-xss-protection",
];

const STANDARD_METHODS: [&str; 10] = [
   "OPTIONS", "GET", "POST", "PUT", "DELETE", "HEAD", "TRACE", "CONNECT", "PATCH", "QUERY",
];

// ---------------------------------------------------------------------------
// ABI mirror of Desktop Phoenix's `libdiscord/crates/http` transport types
// (verified against Windows x86_64 `Discord.exe`). These are Rust layouts, so
// the same rustc and crates lay them out alike on Linux x86_64.
// ---------------------------------------------------------------------------

#[repr(C)]
struct RawVec {
   cap: usize,
   ptr: *mut u8,
   len: usize,
}

#[repr(C)]
struct RawBytesVtable {
   clone:     unsafe extern "C" fn(&AtomicPtr<()>, *const u8, usize) -> RawBytes,
   to_vec:    unsafe extern "C" fn(*mut (), *const u8, usize) -> RawVec,
   to_mut:    unsafe extern "C" fn(*mut (), *const u8, usize) -> RawBytes,
   is_unique: unsafe extern "C" fn(&AtomicPtr<()>) -> bool,
   drop:      unsafe extern "C" fn(*mut (), *const u8, usize),
}

#[repr(C)]
struct RawBytes {
   vtable: *const RawBytesVtable,
   ptr:    *const u8,
   len:    usize,
   data:   AtomicPtr<()>,
}

#[repr(C)]
struct RawHeaderBucket {
   tag:   u64,
   _pad0: [u64; 2],
   value: RawBytes,
   _sens: u64,
   name:  RawBytes,
   _pad1: u64,
}
const _: () = assert!(size_of::<RawHeaderBucket>() == 0x68);

#[repr(C)]
struct RawHeaderMap {
   _head:       [u64; 3],
   entries_cap: usize,
   entries_ptr: *const RawHeaderBucket,
   entries_len: usize,
   _tail:       [u64; 6],
}
const _: () = assert!(size_of::<RawHeaderMap>() == 0x60);

#[repr(C)]
struct RawBody {
   tag:   u64,
   bytes: RawBytes,
   _rest: [u64; 2],
}
const _: () = assert!(size_of::<RawBody>() == 0x38);

#[repr(C)]
struct RawMethod {
   bytes: [u8; 24],
}
const _: () = assert!(size_of::<RawMethod>() == 0x18);

#[repr(C)]
struct RawTransportRequest {
   headers:  RawHeaderMap,
   body:     RawBody,
   url:      RawVec,
   _timeout: [u64; 2],
   method:   RawMethod,
   _extra:   [u64; 3],
}
const _: () = assert!(size_of::<RawTransportRequest>() == 0xF0);

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPinnedFuture {
   data:   *mut c_void,
   vtable: *const c_void,
}

#[repr(C)]
struct RawPollResult {
   headers: [u64; 12],
   body:    RawVec,
   status:  u16,
   _pad:    [u8; 6],
}
const _: () = assert!(size_of::<RawPollResult>() == 0x80);

impl RawPollResult {
   const PENDING_TAG: u64 = u64::MAX - 1;
   const ERR_TAG: u64 = u64::MAX;

   const fn is_pending(&self) -> bool {
      self.headers[0] == Self::PENDING_TAG
   }

   const fn is_ok(&self) -> bool {
      self.headers[0] != Self::PENDING_TAG && self.headers[0] != Self::ERR_TAG
   }
}

// `send` and `poll` are Rust-ABI trait methods, declared Rust ABI here so the
// same lowering applies on Win64 and SysV: `send` returns its pointer pair
// (`Pin<Box<dyn Future>>`) in RAX:RDX, and `poll` returns the 128-byte
// `RawPollResult` through a hidden sret pointer in the first argument register.
type SendFn = unsafe fn(*const c_void, *mut RawTransportRequest) -> RawPinnedFuture;
type PollFn = unsafe fn(*mut c_void, *mut c_void) -> RawPollResult;
type HostAllocFn = unsafe extern "C" fn(usize, usize) -> *mut u8;
type HostDeallocFn = unsafe extern "C" fn(*mut u8, usize, usize);

struct Installed {
   send:         SendFn,
   poll:         PollFn,
   host_alloc:   Option<HostAllocFn>,
   host_dealloc: Option<HostDeallocFn>,
}

static INSTALLED: OnceLock<Installed> = OnceLock::new();

// ---------------------------------------------------------------------------
// Allocator-isolated `bytes::Bytes` vtable for replaced request bodies.
// ---------------------------------------------------------------------------

static OWNED_BYTES_VTABLE: RawBytesVtable = RawBytesVtable {
   clone:     owned_bytes_clone,
   to_vec:    owned_bytes_to_vec,
   to_mut:    owned_bytes_to_mut,
   is_unique: owned_bytes_is_unique,
   drop:      owned_bytes_drop,
};

fn make_owned_bytes(data: Vec<u8>) -> RawBytes {
   let arc = Arc::new(data);
   let ptr = arc.as_ptr();
   let len = arc.len();
   let raw = Arc::into_raw(arc).cast_mut().cast::<()>();
   RawBytes {
      vtable: &raw const OWNED_BYTES_VTABLE,
      ptr,
      len,
      data: AtomicPtr::new(raw),
   }
}

unsafe extern "C" fn owned_bytes_clone(
   data: &AtomicPtr<()>,
   ptr: *const u8,
   len: usize,
) -> RawBytes {
   let raw = data.load(Ordering::Relaxed);
   if !raw.is_null() {
      // SAFETY: `raw` came from `Arc::into_raw` in `make_owned_bytes`.
      unsafe { Arc::increment_strong_count(raw.cast::<Vec<u8>>()) };
   }
   RawBytes {
      vtable: &raw const OWNED_BYTES_VTABLE,
      ptr,
      len,
      data: AtomicPtr::new(raw),
   }
}

unsafe extern "C" fn owned_bytes_to_vec(data: *mut (), ptr: *const u8, len: usize) -> RawVec {
   let out = if len > 0
      && !ptr.is_null()
      && let Some(alloc) = INSTALLED.get().and_then(|inst| inst.host_alloc)
   {
      // SAFETY: allocate using the host's own `__rust_alloc(len, 1)`.
      let dst = unsafe { alloc(len, 1) };
      if dst.is_null() {
         RawVec {
            cap: 0,
            ptr: ptr::null_mut(),
            len: 0,
         }
      } else {
         // SAFETY: `ptr` is valid for `len` bytes and `dst` is freshly
         // allocated.
         unsafe { ptr::copy_nonoverlapping(ptr, dst, len) };
         RawVec {
            cap: len,
            ptr: dst,
            len,
         }
      }
   } else {
      RawVec {
         cap: 0,
         ptr: ptr::null_mut(),
         len: 0,
      }
   };
   // SAFETY: `to_vec` consumes the `Bytes` instance.
   unsafe { owned_bytes_drop(data, ptr, len) };
   out
}

unsafe extern "C" fn owned_bytes_to_mut(data: *mut (), ptr: *const u8, len: usize) -> RawBytes {
   // Fallback: keep our owned bytes intact; callers only invoke `to_mut` if
   // they try to mutate a request body after `send`, which `reqwest` does not.
   RawBytes {
      vtable: &raw const OWNED_BYTES_VTABLE,
      ptr,
      len,
      data: AtomicPtr::new(data),
   }
}

const unsafe extern "C" fn owned_bytes_is_unique(_data: &AtomicPtr<()>) -> bool {
   false
}

unsafe extern "C" fn owned_bytes_drop(data: *mut (), _ptr: *const u8, _len: usize) {
   if !data.is_null() {
      // SAFETY: matches the `Arc::into_raw` / `increment_strong_count` pair.
      drop(unsafe { Arc::from_raw(data.cast::<Vec<u8>>()) });
   }
}

// ---------------------------------------------------------------------------
// Vtable installation & detours
// ---------------------------------------------------------------------------

/// Locates Desktop Phoenix's `ReqwestTransport` and `SendFuture` vtable slots
/// and installs request/response interception.
pub fn install(image: &Image<'static>) {
   let located = if crate::X86_CODE {
      DesktopHttpTransport::locate(image)
   } else {
      phoenix_sigs::macos::http_transport(image)
   };
   let mut found = match located {
      Ok(found) => found,
      Err(err) => {
         log::warn!("discord desktop: HTTP transport: {err}");
         return;
      },
   };
   if !crate::X86_CODE
      && found.host_alloc.is_none()
      && let Some(alloc_or_oom) = crate::gpui::alloc_or_oom_addr()
   {
      match phoenix_sigs::macos::host_allocator(image, alloc_or_oom) {
         Ok((alloc, dealloc)) => {
            found.host_alloc = Some(alloc);
            found.host_dealloc = Some(dealloc);
         },
         Err(err) => log::warn!("discord desktop: {err}, response bodies can't grow"),
      }
   }
   // Discord's API client calls `send` directly rather than through the
   // vtable, so `send` is hooked in place and the detour calls the trampoline.
   // It opens with the same register saves and `sub rsp` as a render frame.
   // SAFETY: runs from `prepare` before Discord's own code, and `send_detour`
   // matches `send`'s Rust ABI.
   let pro = desktop::Prologues::of(phoenix_hook::x86::Abi::of(image)).frame;
   let trampoline = match unsafe {
      image.hook_entry(
         found.send_fn,
         pro.pattern,
         pro.len,
         send_detour as *const () as usize,
      )
   } {
      Ok(trampoline) => trampoline,
      Err(err) => {
         log::warn!("discord desktop: HTTP send not hooked: {err}");
         return;
      },
   };
   // SAFETY: `DesktopHttpTransport::locate` verified every target against
   // `.pdata`, and the trampoline replays `send`'s prologue.
   let installed = Installed {
      send:         unsafe { std::mem::transmute::<usize, SendFn>(trampoline) },
      poll:         unsafe { std::mem::transmute::<usize, PollFn>(found.poll_fn) },
      host_alloc:   found
         .host_alloc
         .map(|addr| unsafe { std::mem::transmute::<usize, HostAllocFn>(addr) }),
      host_dealloc: found
         .host_dealloc
         .map(|addr| unsafe { std::mem::transmute::<usize, HostDeallocFn>(addr) }),
   };
   if INSTALLED.set(installed).is_err() {
      return;
   }

   let detour = if crate::X86_CODE {
      poll_detour as *const () as usize
   } else {
      let Some(detour) = arm64_poll::install(found.poll_fn) else {
         log::warn!("discord desktop: no memory for the poll thunks");
         return;
      };
      detour
   };
   let polls = found
      .poll_slots
      .iter()
      .map(|&slot| (slot, detour))
      .collect::<Vec<_>>();
   // SAFETY: every poll slot is an aligned `.rdata` vtable entry pointing to
   // `poll_fn`, and `poll_detour` matches its Rust ABI.
   match unsafe { image.swap_words(&polls) } {
      Ok(_) => {
         log::info!(
            "discord desktop: hooked HTTP send and {} poll vtable slots",
            found.poll_slots.len(),
         );
      },
      Err(err) => log::error!("discord desktop: failed to hook HTTP transport: {err}"),
   }
}

/// # Safety
///
/// Reads a live `RawVec` (Rust `String`) owned by the host.
unsafe fn read_str<'a>(raw: &RawVec) -> Option<&'a str> {
   if raw.len == 0 {
      return Some("");
   }
   if raw.ptr.is_null() {
      return None;
   }
   // SAFETY: host guarantees valid UTF-8 `String` bytes.
   str::from_utf8(unsafe { slice::from_raw_parts(raw.ptr, raw.len) }).ok()
}

/// # Safety
///
/// Reads a live `RawBytes` owned by the host.
const unsafe fn read_bytes<'a>(raw: &RawBytes) -> &'a [u8] {
   if raw.len == 0 || raw.ptr.is_null() {
      return &[];
   }
   // SAFETY: host guarantees `raw.ptr` is valid for `raw.len` bytes.
   unsafe { slice::from_raw_parts(raw.ptr, raw.len) }
}

/// # Safety
///
/// Reads a live `http::Method` owned by the host.
unsafe fn read_method(raw: &RawMethod) -> Cow<'static, str> {
   let tag = raw.bytes[0];
   if let Some(&name) = STANDARD_METHODS.get(usize::from(tag)) {
      return Cow::Borrowed(name);
   }
   if tag == 10 {
      let len = usize::from(raw.bytes[16]).min(15);
      return Cow::Owned(String::from_utf8_lossy(&raw.bytes[1..=len]).into_owned());
   }
   if tag == 11 {
      let ptr = usize::from_le_bytes(raw.bytes[8..16].try_into().unwrap_or([0; 8])) as *const u8;
      let len = usize::from_le_bytes(raw.bytes[16..24].try_into().unwrap_or([0; 8]));
      if !ptr.is_null() && len <= 64 {
         // SAFETY: `ExtensionAllocated` stores a valid UTF-8 `Box<str>`.
         let bytes = unsafe { slice::from_raw_parts(ptr, len) };
         return Cow::Owned(String::from_utf8_lossy(bytes).into_owned());
      }
   }
   Cow::Borrowed("GET")
}

/// # Safety
///
/// Reads header `(name, value)` pairs from the host's `http::HeaderMap`.
unsafe fn read_headers(map: &RawHeaderMap) -> Vec<(String, String)> {
   if map.entries_ptr.is_null() || map.entries_len == 0 || map.entries_len > 256 {
      return Vec::new();
   }
   // SAFETY: `entries_ptr` holds `entries_len` initialized `RawHeaderBucket`s.
   let buckets = unsafe { slice::from_raw_parts(map.entries_ptr, map.entries_len) };
   let mut out = Vec::with_capacity(buckets.len());
   for bucket in buckets {
      // `Option<Links>` stores its discriminant in the low byte; upper bytes
      // may be padding.
      if (bucket.tag & 0xFF) == 2 {
         continue;
      }
      let name = if bucket.name.vtable.is_null() {
         let idx = (bucket.name.ptr as usize) & 0xFF;
         let Some(&std_name) = STANDARD_HEADERS.get(idx) else {
            continue;
         };
         std_name.to_owned()
      } else {
         // SAFETY: non-null vtable means `Custom(Bytes)` holding valid ASCII
         // header name.
         let bytes = unsafe { read_bytes(&bucket.name) };
         let Ok(text) = str::from_utf8(bytes) else {
            continue;
         };
         text.to_owned()
      };
      // SAFETY: `bucket.value` is a live `HeaderValue` starting with `Bytes`.
      let val_bytes = unsafe { read_bytes(&bucket.value) };
      if let Ok(value) = str::from_utf8(val_bytes) {
         out.push((name, value.to_owned()));
      }
   }
   out
}

/// Where `TransportRequest` keeps each field. Rust reorders a struct's fields
/// from one Discord build to the next, so the layout is found from the
/// requests themselves: every read checks memory first, and a field is used
/// only once one offset has held it on every request seen.
#[derive(Clone, Copy, Debug, Default)]
struct RequestLayout {
   url:     Option<usize>,
   headers: Option<usize>,
   body:    Option<usize>,
   method:  Option<usize>,
}

/// The bytes of a request searched for its fields; the struct is 0xF0 on the
/// builds seen.
const REQUEST_SPAN: usize = 0x100;
/// Requests checked before the weaker fields (body, method) are trusted.
const LAYOUT_SAMPLES: usize = 8;

struct LayoutSearch {
   layout:   RequestLayout,
   seen:     usize,
   bodies:   Vec<usize>,
   /// Each candidate method offset, with the tags it has held.
   methods:  Vec<(usize, std::collections::HashSet<u8>)>,
   saw_body: bool,
}

static LAYOUT: std::sync::Mutex<Option<LayoutSearch>> = std::sync::Mutex::new(None);

fn peek(at: usize, len: usize) -> Option<Vec<u8>> {
   phoenix_hook::x86::read_memory(at, len).filter(|bytes| bytes.len() == len)
}

fn word(bytes: &[u8], at: usize) -> usize {
   bytes
      .get(at..at + 8)
      .and_then(|word| word.try_into().ok())
      .map_or(0, usize::from_le_bytes)
}

fn is_url(bytes: &[u8], at: usize) -> bool {
   let (cap, ptr, len) = (word(bytes, at), word(bytes, at + 8), word(bytes, at + 16));
   (7..=1 << 16).contains(&len)
      && cap >= len
      && cap < 1 << 24
      && peek(ptr, 7).is_some_and(|head| head.starts_with(b"http"))
}

fn is_headers(bytes: &[u8], at: usize) -> bool {
   let (cap, ptr, len) = (
      word(bytes, at + 0x18),
      word(bytes, at + 0x20),
      word(bytes, at + 0x28),
   );
   if !(1..=256).contains(&len) || cap < len || cap > 1024 {
      return false;
   }
   let Some(bucket) = peek(ptr, size_of::<RawHeaderBucket>()) else {
      return false;
   };
   let (vtable, name, name_len) = (
      word(&bucket, 0x40),
      word(&bucket, 0x48),
      word(&bucket, 0x50),
   );
   bucket[0] <= 2
      && if vtable == 0 {
         name < 0x80
      } else {
         (1..=64).contains(&name_len)
            && peek(name, name_len).is_some_and(|name| {
               name
                  .iter()
                  .all(|&byte| byte.is_ascii_lowercase() || byte == b'-' || byte.is_ascii_digit())
            })
      }
}

fn is_body(bytes: &[u8], at: usize) -> Option<bool> {
   match word(bytes, at) {
      0 => Some(false),
      1 => {
         let (vtable, ptr, len) = (
            word(bytes, at + 8),
            word(bytes, at + 16),
            word(bytes, at + 24),
         );
         let vtable_ok = peek(vtable, size_of::<RawBytesVtable>())
            .is_some_and(|table| (0..5).all(|slot| word(&table, slot * 8) != 0));
         (vtable_ok && len < 1 << 26 && (len == 0 || peek(ptr, 1).is_some())).then_some(true)
      },
      _ => None,
   }
}

fn method_tag(bytes: &[u8], at: usize) -> Option<u8> {
   let tag = *bytes.get(at)?;
   match tag {
      0..=8 => Some(tag),
      10 => {
         (bytes
            .get(at + 16)
            .is_some_and(|&len| (1..=15).contains(&len)))
         .then_some(tag)
      },
      11 => (peek(word(bytes, at + 8), 1).is_some() && word(bytes, at + 16) <= 64).then_some(tag),
      _ => None,
   }
}

impl LayoutSearch {
   fn new() -> Self {
      Self {
         layout:   RequestLayout::default(),
         seen:     0,
         bodies:   (0..=REQUEST_SPAN - size_of::<RawBody>())
            .step_by(8)
            .collect(),
         methods:  (0..=REQUEST_SPAN - size_of::<RawMethod>())
            .step_by(8)
            .map(|at| (at, std::collections::HashSet::new()))
            .collect(),
         saw_body: false,
      }
   }

   fn learn(&mut self, bytes: &[u8]) {
      let only = |found: Vec<usize>| {
         match found.as_slice() {
            [one] => Some(*one),
            _ => None,
         }
      };
      if self.layout.url.is_none() {
         self.layout.url = only(
            (0..=REQUEST_SPAN - 24)
               .step_by(8)
               .filter(|&at| is_url(bytes, at))
               .collect(),
         );
      }
      if self.layout.headers.is_none() {
         self.layout.headers = only(
            (0..=REQUEST_SPAN - size_of::<RawHeaderMap>())
               .step_by(8)
               .filter(|&at| is_headers(bytes, at))
               .collect(),
         );
      }
      let (Some(url), Some(headers)) = (self.layout.url, self.layout.headers) else {
         return;
      };
      let free = |at: usize, len: usize| {
         let overlaps = |start: usize, size: usize| at < start + size && start < at + len;
         !overlaps(url, 24) && !overlaps(headers, size_of::<RawHeaderMap>())
      };
      self.seen += 1;
      self
         .bodies
         .retain(|&at| free(at, size_of::<RawBody>()) && is_body(bytes, at).is_some());
      if let [at] = self.bodies.as_slice() {
         self.saw_body |= is_body(bytes, *at) == Some(true);
      }
      self.methods.retain_mut(|(at, tags)| {
         let at = *at;
         let fits = free(at, size_of::<RawMethod>());
         match method_tag(bytes, at) {
            Some(tag) if fits => {
               tags.insert(tag);
               true
            },
            _ => false,
         }
      });
      if self.seen >= LAYOUT_SAMPLES {
         if self.layout.body.is_none() && self.saw_body {
            self.layout.body = only(self.bodies.clone());
         }
         // Zeroed words read as `OPTIONS`; the method is the one offset
         // that has held more than one method.
         if self.layout.method.is_none() {
            // Clear of the body once that is known.
            let body = self.layout.body;
            let clear = |at: usize| {
               body.is_none_or(|body| {
                  at + size_of::<RawMethod>() <= body || body + size_of::<RawBody>() <= at
               })
            };
            self.layout.method = only(
               self
                  .methods
                  .iter()
                  .filter(|&&(at, ref tags)| tags.len() >= 2 && clear(at))
                  .map(|&(at, _)| at)
                  .collect(),
            );
         }
      }
   }
}

/// The request's layout so far, after learning from `req`.
fn request_layout(req: *const u8) -> Option<RequestLayout> {
   let bytes = peek(req as usize, REQUEST_SPAN)?;
   let (before, layout) = {
      let mut guard = LAYOUT
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      let search = guard.get_or_insert_with(LayoutSearch::new);
      let before = search.layout;
      search.learn(&bytes);
      let after = search.layout;
      drop(guard);
      (before, after)
   };
   if format!("{before:?}") != format!("{layout:?}") {
      log::info!("discord desktop: request layout {layout:x?}");
   }
   // A request that doesn't fit the learned layout is passed through.
   let fits = layout.url.is_some_and(|at| is_url(&bytes, at))
      && layout.headers.is_some_and(|at| is_headers(&bytes, at))
      && layout.body.is_none_or(|at| is_body(&bytes, at).is_some())
      && layout
         .method
         .is_none_or(|at| method_tag(&bytes, at).is_some());
   fits.then_some(layout)
}

#[expect(
   clippy::cast_ptr_alignment,
   reason = "the request is 8-aligned and every learned offset is a multiple of 8"
)]
unsafe fn send_detour(self_ptr: *const c_void, req: *mut RawTransportRequest) -> RawPinnedFuture {
   let installed = INSTALLED
      .get()
      .expect("send_detour only runs after INSTALLED is set");

   let mut watched = None;

   if !req.is_null()
      && let Some(layout) = request_layout(req.cast())
      && panic::catch_unwind(AssertUnwindSafe(|| {
         let base = req.cast::<u8>();
         let (Some(url_at), Some(headers_at)) = (layout.url, layout.headers) else {
            return;
         };
         // SAFETY: each offset held its field's shape in this live request,
         // checked just now.
         let url_field = unsafe { &mut *base.add(url_at).cast::<RawVec>() };
         let url = unsafe { read_str(url_field) }
            .unwrap_or_default()
            .to_owned();
         let headers = unsafe { read_headers(&*base.add(headers_at).cast::<RawHeaderMap>()) };
         let method = layout.method.map_or(Cow::Borrowed(""), |at| {
            // SAFETY: as above.
            unsafe { read_method(&*base.add(at).cast::<RawMethod>()) }
         });
         let method = method.into_owned();
         let body_field = layout
            .body
            // SAFETY: as above.
            .map(|at| unsafe { &mut *base.add(at).cast::<RawBody>() });
         let body = match &body_field {
            // SAFETY: `tag == 1` is `Body::Bytes(RawBytes)`.
            Some(body) if body.tag == 1 => unsafe { read_bytes(&body.bytes) },
            _ => &[],
         };

         match observe(&method, &url, &headers, body) {
            RequestAction::Pass => {},
            RequestAction::Drop => {
               // Zeroing `url.len` keeps the host's `String` capacity/pointer
               // intact so `Url::parse("")` fails cleanly with zero network I/O
               // and the host drops every owned field with its own allocator.
               url_field.len = 0;
               return;
            },
            RequestAction::Replace(new_body) => {
               let Some(body) = body_field else {
                  log::warn!("discord desktop: body layout not learned yet, request kept");
                  return;
               };
               if body.tag == 1 && !body.bytes.vtable.is_null() {
                  let old_vtable = body.bytes.vtable;
                  let old_ptr = body.bytes.ptr;
                  let old_len = body.bytes.len;
                  let old_data = body.bytes.data.load(Ordering::Relaxed);
                  // SAFETY: drops the old `Bytes` via its own vtable.
                  unsafe { ((*old_vtable).drop)(old_data, old_ptr, old_len) };
                  body.bytes = make_owned_bytes(new_body);
               } else if body.tag == 0 {
                  body.tag = 1;
                  body.bytes = make_owned_bytes(new_body);
               }
            },
         }

         if layout.method.is_some() {
            watched = watch_response(&method, &url);
         }
      }))
      .is_err()
   {
      log::error!("discord desktop: send_detour panicked");
   }

   // SAFETY: forward directly to the original `ReqwestTransport::send`.
   let future = unsafe { (installed.send)(self_ptr, req) };

   if let Some(in_flight) = watched
      && !future.data.is_null()
   {
      track_response(future.data.addr() as u64, in_flight);
   }

   future
}

/// Whether a ready response reads as one: a status code and a body `Vec`.
fn response_fits(result: &RawPollResult) -> bool {
   (100..=599).contains(&result.status)
      && result.body.cap >= result.body.len
      && result.body.len < 1 << 28
      && (result.body.len == 0 || peek(result.body.ptr as usize, 1).is_some())
}

unsafe fn poll_detour(future: *mut c_void, cx: *mut c_void) -> RawPollResult {
   let installed = INSTALLED
      .get()
      .expect("poll_detour only runs after INSTALLED is set");
   // SAFETY: forward to original `SendFuture::poll`.
   let mut result = unsafe { (installed.poll)(future, cx) };

   if result.is_pending() {
      return result;
   }

   if let Some(in_flight) = take_response(future.addr() as u64)
      && result.is_ok()
      && response_fits(&result)
      && panic::catch_unwind(AssertUnwindSafe(|| {
         let old_body = if result.body.len == 0 || result.body.ptr.is_null() {
            Vec::new()
         } else {
            // SAFETY: `Poll::Ready(Ok(resp)).body` is a live `Vec<u8>`.
            unsafe { slice::from_raw_parts(result.body.ptr, result.body.len) }.to_vec()
         };
         let orig_len = old_body.len();
         let (new_status, new_body) =
            run_response_hooks(in_flight, i32::from(result.status), old_body);
         if let Ok(status) = u16::try_from(new_status) {
            result.status = status;
         }
         // SAFETY: `result.body` is owned by the Ready response being returned.
         unsafe {
            replace_host_vec(&mut result.body, orig_len, &new_body, installed);
         }
      }))
      .is_err()
   {
      log::error!("discord desktop: poll_detour panicked");
   }

   result
}

/// `SendFuture::poll` on arm64, without copying its result.
///
/// The result comes back through `x8`, and its size is the host's: Rust may
/// grow or reorder it in any build. The detour gets the caller's slot through
/// an `sret_callee` thunk, the original writes straight into it through an
/// `sret_caller` thunk, and a response is only rewritten in place while it
/// still matches [`RawPollResult`]'s fields.
#[cfg(target_os = "macos")]
mod arm64_poll {
   use std::{
      ffi::c_void,
      panic::{
         self,
         AssertUnwindSafe,
      },
      sync::{
         OnceLock,
         atomic::{
            AtomicBool,
            Ordering,
         },
      },
   };

   use super::{
      INSTALLED,
      RawPollResult,
      peek,
      replace_host_vec,
      run_response_hooks,
      take_response,
      word,
   };

   type PollThunk = unsafe extern "C" fn(*mut u8, *mut c_void, *mut c_void) -> *mut u8;
   static ORIG: OnceLock<PollThunk> = OnceLock::new();

   pub fn install(poll_fn: usize) -> Option<usize> {
      let orig = phoenix_hook::image::sret_caller(poll_fn)?;
      // SAFETY: the thunk calls `poll` the x86 way, slot first.
      let _ = ORIG.set(unsafe { std::mem::transmute::<usize, PollThunk>(orig) });
      phoenix_hook::image::sret_callee(detour as *const () as usize)
   }

   unsafe extern "C" fn detour(slot: *mut u8, future: *mut c_void, cx: *mut c_void) -> *mut u8 {
      let orig = *ORIG.get().expect("the detour only runs once ORIG is set");
      // SAFETY: forwards the caller's own slot and arguments.
      unsafe { orig(slot, future, cx) };
      let _ = panic::catch_unwind(AssertUnwindSafe(|| inspect(slot, future)));
      slot
   }

   /// The bytes of a result searched for its fields; the old layout is 0x80.
   const SPAN: usize = 0x100;
   /// Ready responses checked before a field's offset is trusted.
   const SAMPLES: usize = 4;

   /// Where a ready `Response` keeps its status and body, learned like
   /// [`super::RequestLayout`]: an offset is used once it alone held its
   /// field in every ready response seen.
   struct Search {
      statuses:  Vec<usize>,
      bodies:    Vec<usize>,
      body_full: bool,
      seen:      usize,
   }

   static SEARCH: std::sync::Mutex<Option<Search>> = std::sync::Mutex::new(None);

   fn status_at(bytes: &[u8], at: usize) -> Option<u16> {
      let status = u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?);
      (100..=599).contains(&status).then_some(status)
   }

   fn body_at(bytes: &[u8], at: usize) -> Option<usize> {
      let (cap, ptr, len) = (word(bytes, at), word(bytes, at + 8), word(bytes, at + 16));
      (cap >= len && cap < 1 << 28 && (len == 0 || peek(ptr, 1).is_some())).then_some(len)
   }

   /// `(status, body)` offsets once known, after learning from `bytes`.
   fn learn(bytes: &[u8]) -> Option<(usize, usize)> {
      let mut guard = SEARCH
         .lock()
         .unwrap_or_else(std::sync::PoisonError::into_inner);
      let search = guard.get_or_insert_with(|| {
         Search {
            statuses:  (0..SPAN - 2).step_by(2).collect(),
            bodies:    (0..=SPAN - 24).step_by(8).collect(),
            body_full: false,
            seen:      0,
         }
      });
      search.seen += 1;
      search.statuses.retain(|&at| status_at(bytes, at).is_some());
      search.bodies.retain(|&at| body_at(bytes, at).is_some());
      if let [at] = search.bodies.as_slice() {
         search.body_full |= body_at(bytes, *at).is_some_and(|len| len > 0);
      }
      let found = match (search.statuses.as_slice(), search.bodies.as_slice()) {
         (&[status], &[body]) if search.seen >= SAMPLES && search.body_full => Some((status, body)),
         _ => None,
      };
      drop(guard);
      found
   }

   #[expect(
      clippy::cast_ptr_alignment,
      reason = "the result slot is the host's 8-aligned value, and learned offsets fit their \
                fields"
   )]
   fn inspect(slot: *mut u8, future: *mut c_void) {
      static LEARNED: AtomicBool = AtomicBool::new(false);
      let Some(bytes) = peek(slot as usize, SPAN) else {
         return;
      };
      // `Poll::Pending` and `Err` are niches in one of the result's words;
      // which word is the build's, so any word holding either one counts.
      let marked = |tag: u64| (0..SPAN / 8).any(|index| word(&bytes, index * 8) as u64 == tag);
      if marked(RawPollResult::PENDING_TAG) {
         return;
      }
      let Some(in_flight) = take_response(future.addr() as u64) else {
         return;
      };
      if marked(RawPollResult::ERR_TAG) {
         return;
      }
      let Some((status_at, body_at)) = learn(&bytes) else {
         return;
      };
      if !LEARNED.swap(true, Ordering::Relaxed) {
         log::info!("discord desktop: response layout: status +{status_at:#x}, body +{body_at:#x}");
      }
      let (Some(status), Some(_)) = (
         self::status_at(&bytes, status_at),
         self::body_at(&bytes, body_at),
      ) else {
         return;
      };
      let Some(installed) = INSTALLED.get() else {
         return;
      };
      // SAFETY: both offsets held their fields in this live result just now.
      let (status_field, body) = unsafe {
         (
            &mut *slot.add(status_at).cast::<u16>(),
            &mut *slot.add(body_at).cast::<super::RawVec>(),
         )
      };
      let old_body = peek(body.ptr as usize, body.len).unwrap_or_default();
      let orig_len = old_body.len();
      let (new_status, new_body) = run_response_hooks(in_flight, i32::from(status), old_body);
      if let Ok(status) = u16::try_from(new_status) {
         *status_field = status;
      }
      // SAFETY: `body` is the ready response's own body.
      unsafe { replace_host_vec(body, orig_len, &new_body, installed) };
   }
}

/// Replaces `vec`'s contents with `new_body` while staying 100% compatible
/// with `Discord.exe`'s custom `#[global_allocator]`.
///
/// # Safety
///
/// `vec` is an owned host `Vec<u8>`.
unsafe fn replace_host_vec(
   vec: &mut RawVec,
   orig_len: usize,
   new_body: &[u8],
   installed: &Installed,
) {
   // Fast path: unchanged length and identical bytes.
   if new_body.len() == orig_len
      && (orig_len == 0
         || (!vec.ptr.is_null()
            // SAFETY: `vec.ptr` is valid for `orig_len` bytes.
            && unsafe { slice::from_raw_parts(vec.ptr, orig_len) } == new_body))
   {
      return;
   }
   // Fits inside existing host capacity: overwrite in place with zero
   // alloc/dealloc.
   if new_body.len() <= vec.cap && !vec.ptr.is_null() {
      // SAFETY: `vec.ptr` has capacity >= `new_body.len()`.
      unsafe { ptr::copy_nonoverlapping(new_body.as_ptr(), vec.ptr, new_body.len()) };
      vec.len = new_body.len();
      return;
   }
   // Needs growth: use the host's own `__rust_alloc` and `__rust_dealloc`.
   let (Some(alloc), Some(dealloc)) = (installed.host_alloc, installed.host_dealloc) else {
      log::warn!("discord onResponse: cannot grow response body without host allocator");
      return;
   };
   let new_len = new_body.len();
   // SAFETY: calls host's `__rust_alloc(new_len, 1)`.
   let new_ptr = unsafe { alloc(new_len, 1) };
   if new_ptr.is_null() {
      return;
   }
   // SAFETY: copies `new_len` bytes into freshly allocated host buffer.
   unsafe { ptr::copy_nonoverlapping(new_body.as_ptr(), new_ptr, new_len) };
   if vec.cap > 0 && !vec.ptr.is_null() {
      // SAFETY: frees old host buffer via host's `__rust_dealloc(ptr, cap, 1)`.
      unsafe { dealloc(vec.ptr, vec.cap, 1) };
   }
   vec.cap = new_len;
   vec.ptr = new_ptr;
   vec.len = new_len;
}

// ---------------------------------------------------------------------------
// High-level session capture, hook dispatch & `phoenix.discord.*` transport
// ---------------------------------------------------------------------------

/// Extracts the channel id from a send-message API path such as
/// `/channels/123456789/messages` (ignoring any query string).
#[must_use]
pub fn send_channel_id(path: &str) -> Option<&str> {
   let clean = path.split(['?', '#']).next().unwrap_or(path);
   let rest = clean.strip_prefix("/channels/")?;
   let id = rest.strip_suffix("/messages")?;
   (!id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())).then_some(id)
}

/// Desktop has no composer hook, so `phoenix.messages.onSend` runs on the
/// request that posts a message, before the shared request hooks.
fn observe(method: &str, url: &str, headers: &[(String, String)], body: &[u8]) -> RequestAction {
   let channel = api_path(url)
      .filter(|_| method.eq_ignore_ascii_case("POST"))
      .and_then(send_channel_id);
   let sent = channel.map_or(RequestAction::Pass, |channel| {
      phoenix_runtime::engine().map_or(RequestAction::Pass, |engine| {
         crate::js::ui::intercept_send_body(&engine, channel, body)
      })
   });
   match sent {
      RequestAction::Pass => observe_request(method, url, headers, body),
      RequestAction::Drop => RequestAction::Drop,
      RequestAction::Replace(sent) => {
         match observe_request(method, url, headers, &sent) {
            RequestAction::Pass => RequestAction::Replace(sent),
            hooked => hooked,
         }
      },
   }
}

pub fn send(
   method: &str,
   path: &str,
   headers: Vec<(String, String)>,
   body: Vec<u8>,
) -> Result<Response, DiscordError> {
   let (url, merged) = session_request(path, headers)?;
   let request = Request {
      url,
      method: method.to_owned(),
      headers: merged,
      body: (!body.is_empty()).then_some(body),
   };
   fetch::send(&request).map_err(|err| {
      DiscordError::Network {
         path:    path.to_owned(),
         message: err.to_string(),
      }
   })
}

pub const fn authorize(_request: &Authorization) -> Result<String, DiscordError> {
   Err(DiscordError::NoBridge)
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn extracts_send_channel_id() {
      assert_eq!(
         send_channel_id("/channels/123456789012345678/messages"),
         Some("123456789012345678")
      );
      assert_eq!(send_channel_id("/channels/42/messages?nonce=1"), Some("42"));
      assert_eq!(send_channel_id("/channels/abc/messages"), None);
      assert_eq!(send_channel_id("/channels/42/typing"), None);
      assert_eq!(send_channel_id("/users/@me"), None);
   }

   #[test]
   fn rejects_relative_path_without_leading_slash() {
      let err = send("GET", "users/@me", Vec::new(), Vec::new());
      assert!(matches!(err, Err(DiscordError::Path { .. })));
   }

   #[test]
   fn standard_header_indices_match_http_crate() {
      assert_eq!(STANDARD_HEADERS[0], "accept");
      assert_eq!(STANDARD_HEADERS[14], "allow");
      assert_eq!(STANDARD_HEADERS[16], "authorization");
      assert_eq!(STANDARD_HEADERS[29], "content-type");
      assert_eq!(STANDARD_HEADERS[30], "cookie");
      assert_eq!(STANDARD_HEADERS[46], "location");
      assert_eq!(STANDARD_HEADERS[70], "user-agent");
      assert_eq!(STANDARD_HEADERS[80], "x-xss-protection");
   }

   #[test]
   fn owned_bytes_clone_and_drop_roundtrip() {
      let raw = make_owned_bytes(b"hello sunbird".to_vec());
      assert_eq!(raw.len, 13);
      // SAFETY: testing our own vtable clone + double drop.
      unsafe {
         let cloned = ((*raw.vtable).clone)(&raw.data, raw.ptr, raw.len);
         assert_eq!(read_bytes(&cloned), b"hello sunbird");
         ((*raw.vtable).drop)(raw.data.load(Ordering::Relaxed), raw.ptr, raw.len);
         ((*cloned.vtable).drop)(cloned.data.load(Ordering::Relaxed), cloned.ptr, cloned.len);
      }
   }
}
