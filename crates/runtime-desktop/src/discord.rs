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
   panic::{self, AssertUnwindSafe},
   ptr, slice, str,
   sync::{
      Arc, OnceLock,
      atomic::{AtomicPtr, Ordering},
   },
};

use phoenix_hook::image::Image;
#[cfg(target_os = "macos")]
use phoenix_runtime::discord::InFlight;
use phoenix_runtime::{
   discord::{
      Authorization, DiscordError, RequestAction, api_path, observe_request, run_response_hooks,
      session_request, take_response, track_response, watch_response,
   },
   fetch::{self, Request, Response},
};
use phoenix_sigs::{
   desktop,
   http::{self, DesktopHttpTransport},
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
   clone: unsafe extern "C" fn(&AtomicPtr<()>, *const u8, usize) -> RawBytes,
   to_vec: unsafe extern "C" fn(*mut (), *const u8, usize) -> RawVec,
   to_mut: unsafe extern "C" fn(*mut (), *const u8, usize) -> RawBytes,
   is_unique: unsafe extern "C" fn(&AtomicPtr<()>) -> bool,
   drop: unsafe extern "C" fn(*mut (), *const u8, usize),
}

#[repr(C)]
struct RawBytes {
   vtable: *const RawBytesVtable,
   ptr: *const u8,
   len: usize,
   data: AtomicPtr<()>,
}

#[repr(C)]
struct RawHeaderBucket {
   tag: u64,
   _pad0: [u64; 2],
   value: RawBytes,
   _sens: u64,
   name: RawBytes,
   _pad1: u64,
}
const _: () = assert!(size_of::<RawHeaderBucket>() == 0x68);

#[repr(C)]
struct RawHeaderMap {
   _head: [u64; 3],
   entries_cap: usize,
   entries_ptr: *const RawHeaderBucket,
   entries_len: usize,
   _tail: [u64; 6],
}

#[repr(C)]
struct RawBody {
   tag: u64,
   bytes: RawBytes,
   _rest: [u64; 2],
}

#[repr(C)]
struct RawMethod {
   bytes: [u8; 24],
}

const _: () = assert!(
   size_of::<RawHeaderMap>() == http::HEADER_MAP_SIZE
      && size_of::<RawBody>() == http::BODY_SIZE
      && size_of::<RawVec>() == http::STRING_SIZE
      && size_of::<RawMethod>() == http::STRING_SIZE
);

/// `send`'s request, at the offsets its build keeps the fields at.
struct HostRequest<'a> {
   headers: &'a RawHeaderMap,
   body: &'a mut RawBody,
   url: &'a mut RawVec,
   method: &'a RawMethod,
}

impl HostRequest<'_> {
   /// # Safety
   ///
   /// `req` is a live request laid out as `layout` says, which
   /// `DesktopHttpTransport::locate` checked has no overlapping fields.
   unsafe fn at(req: *mut c_void, layout: http::RequestLayout) -> Self {
      // SAFETY: forwarded from the caller.
      unsafe {
         Self {
            headers: &*req.cast(),
            body: &mut *req.byte_add(layout.body).cast(),
            url: &mut *req.byte_add(layout.url).cast(),
            method: &*req.byte_add(layout.method).cast(),
         }
      }
   }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPinnedFuture {
   data: *mut c_void,
   vtable: *const c_void,
}

#[repr(C)]
struct RawPollResult {
   headers: [u64; 12],
   body: RawVec,
   status: u16,
   _pad: [u8; 6],
}
const _: () = assert!(size_of::<RawPollResult>() == http::POLL_RESULT_SIZE);

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
type SendFn = unsafe fn(*const c_void, *mut c_void) -> RawPinnedFuture;
type PollFn = unsafe fn(*mut c_void, *mut c_void) -> RawPollResult;
#[cfg(target_os = "macos")]
type PollSretFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void;
type HostAllocFn = unsafe extern "C" fn(usize, usize) -> *mut u8;
type HostDeallocFn = unsafe extern "C" fn(*mut u8, usize, usize);

#[cfg(target_os = "macos")]
#[repr(C)]
struct StreamPollResult {
   tag: u64,
   payload: [u64; 4],
}

#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<StreamPollResult>() == 40);

#[cfg(target_os = "macos")]
impl StreamPollResult {
   const CHUNK: u64 = 0;
   const ERR: u64 = 1;
   const EOF: u64 = 2;
   const PENDING: u64 = u64::MAX;

   const fn pending() -> Self {
      Self {
         tag: Self::PENDING,
         payload: [0; 4],
      }
   }

   const fn eof() -> Self {
      Self {
         tag: Self::EOF,
         payload: [0; 4],
      }
   }

   fn chunk(bytes: RawBytes) -> Self {
      // SAFETY: `RawBytes` is 32 bytes (`[u64; 4]`) and repr(C).
      let payload = unsafe { std::mem::transmute::<RawBytes, [u64; 4]>(bytes) };
      Self {
         tag: Self::CHUNK,
         payload,
      }
   }
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct RawSizeHint {
   lower: usize,
   upper_tag: usize,
   upper_val: usize,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct StreamVtable {
   drop: unsafe fn(*mut c_void),
   size: usize,
   align: usize,
   poll_next: unsafe fn(*mut c_void, *mut c_void) -> StreamPollResult,
   size_hint: unsafe fn(*const c_void) -> RawSizeHint,
}

struct Installed {
   send: SendFn,
   response: Option<http::ResponseLayout>,
   request: http::RequestLayout,
   poll: PollFn,
   #[cfg(target_os = "macos")]
   poll_sret: Option<PollSretFn>,
   host_alloc: Option<HostAllocFn>,
   host_dealloc: Option<HostDeallocFn>,
}

static INSTALLED: OnceLock<Installed> = OnceLock::new();

// ---------------------------------------------------------------------------
// Allocator-isolated `bytes::Bytes` vtable for replaced request bodies.
// ---------------------------------------------------------------------------

static OWNED_BYTES_VTABLE: RawBytesVtable = RawBytesVtable {
   clone: owned_bytes_clone,
   to_vec: owned_bytes_to_vec,
   to_mut: owned_bytes_to_mut,
   is_unique: owned_bytes_is_unique,
   drop: owned_bytes_drop,
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

#[cfg(target_os = "macos")]
fn prepare_poll_hook(
   found: &DesktopHttpTransport,
) -> (
   Option<http::ResponseLayout>,
   Option<PollSretFn>,
   Option<usize>,
) {
   match found.response {
      Some(http::ResponseLayout::Legacy) => (
         Some(http::ResponseLayout::Legacy),
         None,
         Some(poll_detour as *const () as usize),
      ),
      Some(layout @ http::ResponseLayout::Stream { .. }) => {
         if let (Some(orig_thunk), Some(detour_thunk)) = (
            phoenix_hook::image::sret_caller(found.poll_fn),
            phoenix_hook::image::sret_callee(poll_stream_detour as *const () as usize),
         ) {
            // SAFETY: `sret_caller` adapts `poll_fn`'s arm64 `x8` sret to first arg.
            let poll_sret = unsafe { std::mem::transmute::<usize, PollSretFn>(orig_thunk) };
            (Some(layout), Some(poll_sret), Some(detour_thunk))
         } else {
            log::warn!("discord desktop: could not allocate sret thunks for streaming poll");
            (None, None, None)
         }
      },
      None => (None, None, None),
   }
}

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
   #[cfg(target_os = "macos")]
   let (response, poll_sret, poll_hook_target) = prepare_poll_hook(&found);
   #[cfg(not(target_os = "macos"))]
   let (response, poll_hook_target) = match found.response {
      Some(http::ResponseLayout::Legacy) => (
         Some(http::ResponseLayout::Legacy),
         Some(poll_detour as *const () as usize),
      ),
      _ => (None, None),
   };

   // SAFETY: `DesktopHttpTransport::locate` verified every target against
   // `.pdata`, and the trampoline replays `send`'s prologue.
   let installed = Installed {
      send: unsafe { std::mem::transmute::<usize, SendFn>(trampoline) },
      response,
      request: found.request,
      poll: unsafe { std::mem::transmute::<usize, PollFn>(found.poll_fn) },
      #[cfg(target_os = "macos")]
      poll_sret,
      host_alloc: found
         .host_alloc
         .map(|addr| unsafe { std::mem::transmute::<usize, HostAllocFn>(addr) }),
      host_dealloc: found
         .host_dealloc
         .map(|addr| unsafe { std::mem::transmute::<usize, HostDeallocFn>(addr) }),
   };
   if INSTALLED.set(installed).is_err() {
      return;
   }
   let Some(poll_hook_target) = poll_hook_target else {
      log::warn!(
         "discord desktop: hooked HTTP send, but poll writes {:#x} bytes of its result, so \
          responses are left alone",
         found.poll_result
      );
      return;
   };

   let polls = found
      .poll_slots
      .iter()
      .map(|&slot| (slot, poll_hook_target))
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

unsafe fn send_detour(self_ptr: *const c_void, req: *mut c_void) -> RawPinnedFuture {
   let installed = INSTALLED
      .get()
      .expect("send_detour only runs after INSTALLED is set");

   let mut watched = None;

   if !req.is_null()
      && panic::catch_unwind(AssertUnwindSafe(|| {
         // SAFETY: `req` is a live owned `TransportRequest` passed by
         // `libdiscord_http`, laid out as the locator found.
         let req_ref = unsafe { HostRequest::at(req, installed.request) };
         // SAFETY: reading live fields of `req_ref`.
         let url = unsafe { read_str(req_ref.url) }
            .unwrap_or_default()
            .to_owned();
         let method = unsafe { read_method(req_ref.method) }.into_owned();
         let headers = unsafe { read_headers(req_ref.headers) };
         let body = if req_ref.body.tag == 1 {
            // SAFETY: `tag == 1` is `Body::Bytes(RawBytes)`.
            unsafe { read_bytes(&req_ref.body.bytes) }
         } else {
            &[]
         };

         match observe(&method, &url, &headers, body) {
            RequestAction::Pass => {},
            RequestAction::Drop => {
               // Zeroing `url.len` keeps the host's `String` capacity/pointer
               // intact so `Url::parse("")` fails cleanly with zero network I/O
               // and the host drops every owned field with its own allocator.
               req_ref.url.len = 0;
               return;
            },
            RequestAction::Replace(new_body) => {
               if req_ref.body.tag == 1 && !req_ref.body.bytes.vtable.is_null() {
                  let old_vtable = req_ref.body.bytes.vtable;
                  let old_ptr = req_ref.body.bytes.ptr;
                  let old_len = req_ref.body.bytes.len;
                  let old_data = req_ref.body.bytes.data.load(Ordering::Relaxed);
                  // SAFETY: drops the old `Bytes` via its own vtable.
                  unsafe { ((*old_vtable).drop)(old_data, old_ptr, old_len) };
                  req_ref.body.bytes = make_owned_bytes(new_body);
               } else if req_ref.body.tag == 0 {
                  req_ref.body.tag = 1;
                  req_ref.body.bytes = make_owned_bytes(new_body);
               }
            },
         }

         if installed.response.is_some() {
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

#[cfg(target_os = "macos")]
struct InterceptStream {
   inner_data: *mut c_void,
   inner_vtable: *const StreamVtable,
   in_flight: Option<InFlight>,
   status: i32,
   buf: Vec<u8>,
   yielded: bool,
}

#[cfg(target_os = "macos")]
impl Drop for InterceptStream {
   fn drop(&mut self) {
      if self.inner_data.is_null() || self.inner_vtable.is_null() {
         return;
      }
      // SAFETY: `inner_data`/`inner_vtable` came from Discord's `Pin<Box<dyn Stream>>`.
      unsafe {
         let vtable = &*self.inner_vtable;
         (vtable.drop)(self.inner_data);
         if vtable.size > 0
            && let Some(dealloc) = INSTALLED.get().and_then(|i| i.host_dealloc)
         {
            dealloc(self.inner_data.cast(), vtable.size, vtable.align);
         }
      }
      self.inner_data = ptr::null_mut();
      self.inner_vtable = ptr::null();
   }
}

#[cfg(target_os = "macos")]
unsafe fn intercept_stream_drop(ptr: *mut c_void) {
   if !ptr.is_null() {
      // SAFETY: `ptr` points to a live `InterceptStream` allocated via `host_alloc`.
      unsafe { ptr::drop_in_place(ptr.cast::<InterceptStream>()) };
   }
}

#[cfg(target_os = "macos")]
const unsafe fn intercept_stream_size_hint(_ptr: *const c_void) -> RawSizeHint {
   RawSizeHint {
      lower: 0,
      upper_tag: 0,
      upper_val: 0,
   }
}

#[cfg(target_os = "macos")]
unsafe fn intercept_stream_poll_next(ptr: *mut c_void, cx: *mut c_void) -> StreamPollResult {
   const MAX_BUFFERED: usize = 16 * 1024 * 1024;
   if ptr.is_null() {
      return StreamPollResult::eof();
   }
   panic::catch_unwind(AssertUnwindSafe(|| {
      // SAFETY: `ptr` is a pinned `InterceptStream` owned by Discord's `ResponseBody::Stream`.
      let stream = unsafe { &mut *ptr.cast::<InterceptStream>() };
      if stream.yielded {
         return StreamPollResult::eof();
      }
      loop {
         if stream.inner_data.is_null() || stream.inner_vtable.is_null() {
            stream.yielded = true;
            return StreamPollResult::eof();
         }
         // SAFETY: `inner_vtable` is the original stream vtable from `SendFuture::poll`.
         let inner_res = unsafe { ((*stream.inner_vtable).poll_next)(stream.inner_data, cx) };
         match inner_res.tag {
            StreamPollResult::PENDING => return StreamPollResult::pending(),
            StreamPollResult::CHUNK => {
               // SAFETY: `tag == 0` holds a live `RawBytes` in `payload`.
               let raw = unsafe { std::mem::transmute::<[u64; 4], RawBytes>(inner_res.payload) };
               let chunk = unsafe { read_bytes(&raw) };
               if stream.buf.len().saturating_add(chunk.len()) <= MAX_BUFFERED {
                  stream.buf.extend_from_slice(chunk);
               }
               if !raw.vtable.is_null() {
                  let data = raw.data.load(Ordering::Relaxed);
                  unsafe { ((*raw.vtable).drop)(data, raw.ptr, raw.len) };
               }
            },
            StreamPollResult::ERR => {
               stream.yielded = true;
               return inner_res;
            },
            StreamPollResult::EOF => {
               stream.yielded = true;
               let body = std::mem::take(&mut stream.buf);
               let final_body = match stream.in_flight.take() {
                  Some(in_flight) => run_response_hooks(in_flight, stream.status, body).1,
                  None => body,
               };
               return StreamPollResult::chunk(make_owned_bytes(final_body));
            },
            _ => {
               stream.yielded = true;
               return StreamPollResult::eof();
            },
         }
      }
   }))
   .unwrap_or_else(|_| {
      log::error!("discord desktop: intercept_stream_poll_next panicked");
      StreamPollResult::eof()
   })
}

#[cfg(target_os = "macos")]
static INTERCEPT_STREAM_VTABLE: StreamVtable = StreamVtable {
   drop: intercept_stream_drop,
   size: size_of::<InterceptStream>(),
   align: align_of::<InterceptStream>(),
   poll_next: intercept_stream_poll_next,
   size_hint: intercept_stream_size_hint,
};

#[cfg(target_os = "macos")]
unsafe extern "C" fn poll_stream_detour(
   sret: *mut c_void,
   future: *mut c_void,
   cx: *mut c_void,
) -> *mut c_void {
   let installed = INSTALLED
      .get()
      .expect("poll_stream_detour only runs after INSTALLED is set");
   let Some(poll_sret) = installed.poll_sret else {
      return sret;
   };
   // SAFETY: forwards to original `SendFuture::poll` writing directly into `sret`.
   unsafe { poll_sret(sret, future, cx) };

   let Some(http::ResponseLayout::Stream {
      err_tag,
      pending_tag,
      body,
      status,
      ..
   }) = installed.response
   else {
      return sret;
   };

   // SAFETY: `sret` holds the live `Poll<Result<Response, NetError>>` written by `poll_sret`.
   let tag = unsafe { sret.cast::<u64>().read() };
   if tag == pending_tag {
      return sret;
   }

   if let Some(in_flight) = take_response(future.addr() as u64)
      && tag != err_tag
      && panic::catch_unwind(AssertUnwindSafe(|| {
         // SAFETY: `body` and `status` offsets were validated against `poll`'s return size.
         unsafe {
            let status_ptr = sret.byte_add(status).cast::<u16>();
            let resp_status = status_ptr.read();
            let body_ptr = sret.byte_add(body);
            let body_tag = body_ptr.cast::<u64>().read();
            match body_tag {
               // `ResponseBody::Buffered(Bytes)`
               0 => {
                  let raw_ptr = body_ptr.byte_add(8).cast::<RawBytes>();
                  let raw = &mut *raw_ptr;
                  let old_body = read_bytes(raw).to_vec();
                  let (new_status, new_body) =
                     run_response_hooks(in_flight, i32::from(resp_status), old_body);
                  if let Ok(code) = u16::try_from(new_status) {
                     status_ptr.write(code);
                  }
                  if !raw.vtable.is_null() {
                     let data = raw.data.load(Ordering::Relaxed);
                     ((*raw.vtable).drop)(data, raw.ptr, raw.len);
                  }
                  *raw = make_owned_bytes(new_body);
               },
               // `ResponseBody::Stream(Pin<Box<dyn Stream>>)`
               1 => {
                  let (Some(alloc), Some(_)) = (installed.host_alloc, installed.host_dealloc)
                  else {
                     return;
                  };
                  let data_slot = body_ptr.byte_add(8).cast::<*mut c_void>();
                  let vtbl_slot = body_ptr.byte_add(16).cast::<*const StreamVtable>();
                  let inner_data = data_slot.read();
                  let inner_vtable = vtbl_slot.read();
                  if inner_data.is_null() || inner_vtable.is_null() {
                     return;
                  }
                  // allocate via Discord's allocator so Box::drop frees cleanly
                  let wrapper = alloc(size_of::<InterceptStream>(), align_of::<InterceptStream>());
                  if wrapper.is_null() {
                     return;
                  }
                  wrapper.cast::<InterceptStream>().write(InterceptStream {
                     inner_data,
                     inner_vtable,
                     in_flight: Some(in_flight),
                     status: i32::from(resp_status),
                     buf: Vec::new(),
                     yielded: false,
                  });
                  data_slot.write(wrapper.cast());
                  vtbl_slot.write(&raw const INTERCEPT_STREAM_VTABLE);
               },
               _ => {},
            }
         }
      }))
      .is_err()
   {
      log::error!("discord desktop: poll_stream_detour panicked");
   }

   sret
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
      RequestAction::Replace(sent) => match observe_request(method, url, headers, &sent) {
         RequestAction::Pass => RequestAction::Replace(sent),
         hooked => hooked,
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
   fetch::send(&request).map_err(|err| DiscordError::Network {
      path: path.to_owned(),
      message: err.to_string(),
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
