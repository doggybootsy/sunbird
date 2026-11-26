//! A message's JSON from Discord's own memory, through the
//! `serde_json::to_value::<Message>` Phoenix runs to store it, so a plugin
//! sees the message it clicked even when Phoenix has not cached it yet.
//!
//! The `serde_json::Value` that returns is read in place: Discord's
//! `serde_json` keeps object keys in insertion order (`IndexMap`), so the JSON
//! keeps Phoenix's field order, and Discord's own drop glue frees it.

use std::{
   fmt::Write as _,
   panic::{
      self,
      AssertUnwindSafe,
   },
   sync::OnceLock,
};

use phoenix_hook::{
   image::Image,
   x86,
};
use phoenix_sigs::desktop;

/// `Result<Value, Error>` is 9 words; the slack covers a larger build.
type Slot = [u64; 16];
type ToValueFn = unsafe extern "C" fn(*mut Slot, *const u8);
type DropFn = unsafe extern "C" fn(*mut Slot);

static FNS: OnceLock<(ToValueFn, DropFn)> = OnceLock::new();
/// Where a map entry keeps its key and value, decoded from the first message.
static BUCKET: OnceLock<Bucket> = OnceLock::new();

/// `Value`'s first word holds an object's entry capacity, or past `isize::MAX`
/// the tags of its five other variants; `Result` puts `Err` on the next niche.
const NICHE: u64 = 0x8000_0000_0000_0000;
const LAST_TAG: u64 = NICHE + 4;
const VALUE_SIZE: usize = 0x48;
/// `Bucket { hash: usize, key: String, value: Value }`.
const BUCKET_SIZE: usize = 8 + 24 + VALUE_SIZE;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Copy)]
struct Bucket {
   key:   usize,
   value: usize,
}

/// Locates `to_value` and the drop glue from `prepare`.
pub fn install(image: &Image<'static>) {
   let found = if crate::X86_CODE {
      desktop::message_json(image)
   } else {
      arm64_json(image)
   };
   match found {
      Ok(found) => {
         // SAFETY: shape-checked by `sigs`; both take their pointers in the
         // first argument registers, as the C ABI passes them (arm64's
         // `to_value` through its `sret_caller` thunk).
         let _ = FNS.set(unsafe {
            (
               std::mem::transmute::<usize, ToValueFn>(found.to_value),
               std::mem::transmute::<usize, DropFn>(found.drop_value),
            )
         });
         log::info!("message json: to_value @ {:#x}", found.to_value);
      },
      Err(err) => log::warn!("message json: {err}, message actions read the cache"),
   }
}

/// Where a `Message` keeps its id and channel id, which arm64's menu checks a
/// pointer against before serializing it.
static IDS: OnceLock<(usize, usize)> = OnceLock::new();

/// arm64's `to_value` returns through `x8`, so it is called through a thunk.
fn arm64_json(image: &Image<'_>) -> Result<desktop::MessageJson, String> {
   let found = phoenix_sigs::macos::message_json(image)?;
   let to_value =
      phoenix_hook::image::sret_caller(found.json.to_value).ok_or("no memory for a thunk")?;
   let _ = IDS.set((found.id, found.channel_id));
   Ok(desktop::MessageJson {
      to_value,
      ..found.json
   })
}

/// The `Message` among `words` whose id and channel id are `id` and
/// `channel`: one of them is `&Message` or `Rc<Message>`. Each candidate is
/// read with [`peek`], so a word that isn't a pointer is skipped.
pub fn find_message(words: &[usize], id: u64, channel: u64) -> Option<*const u8> {
   /// An `Rc`'s value follows its two counts.
   const RC_VALUE: usize = 16;
   let &(id_at, channel_at) = IDS.get()?;
   words
      .iter()
      .filter(|&&word| word != 0 && word % 8 == 0)
      .flat_map(|&word| [word, word.wrapping_add(RC_VALUE)])
      .find(|&message| {
         let at = message as *const u8;
         peek_word(at.wrapping_add(id_at)) == Some(id)
            && peek_word(at.wrapping_add(channel_at)) == Some(channel)
      })
      .map(|message| message as *const u8)
}

/// The JSON of the `Message` at `message`, whose id is `id`, or `None` when
/// what Discord returns does not decode as that message.
///
/// # Safety
///
/// `message` points to a live `Message` for the whole call.
pub unsafe fn json(message: *const u8, id: u64) -> Option<String> {
   let &(to_value, drop_value) = FNS.get()?;
   let mut slot: Slot = [0; 16];
   // SAFETY: `slot` is larger than `Result<Value, Error>`, `message` is live.
   unsafe { to_value(&raw mut slot, message) };
   if slot[0] > LAST_TAG {
      // ponytail: leaks the boxed error, a malformed message is rare.
      return None;
   }
   let out = panic::catch_unwind(AssertUnwindSafe(|| {
      let value = slot.as_ptr().cast::<u8>();
      let id = id.to_string();
      let bucket = BUCKET
         .get()
         .copied()
         .or_else(|| decode_bucket(value, &id).map(|bucket| *BUCKET.get_or_init(|| bucket)))?;
      if !first_is_id(value, bucket, &id) {
         return None;
      }
      let mut out = String::new();
      write_value(&mut out, value, bucket, 0)?;
      Some(out)
   }))
   .ok()
   .flatten();
   // SAFETY: `slot` holds the `Ok(Value)` `to_value` built.
   unsafe { drop_value(&raw mut slot) };
   out
}

const fn word(at: *const u8) -> u64 {
   // SAFETY: callers pass addresses inside a `Value` Discord built.
   unsafe { at.cast::<u64>().read_unaligned() }
}

/// A `String` or `Vec`, `{cap, ptr, len}`, as its pointer and length.
fn vec(at: *const u8) -> Option<(*const u8, usize)> {
   checked_vec(
      word(at),
      word(at.wrapping_add(8)),
      word(at.wrapping_add(16)),
   )
}

fn checked_vec(cap: u64, ptr: u64, len: u64) -> Option<(*const u8, usize)> {
   (cap < NICHE && len <= cap && (ptr != 0 || len == 0))
      .then(|| usize::try_from(len).ok())
      .flatten()
      .map(|len| (ptr as *const u8, len))
}

/// `len` bytes at `at`, or `None` where they are not mapped: checking a guessed
/// layout may follow a word that is not a pointer.
fn peek(at: *const u8, len: usize) -> Option<Vec<u8>> {
   x86::read_memory(at as usize, len).filter(|bytes| bytes.len() == len)
}

fn peek_word(at: *const u8) -> Option<u64> {
   Some(u64::from_le_bytes(peek(at, 8)?.try_into().ok()?))
}

/// Whether the `String` at `at` reads `want`, without trusting its pointer.
fn peek_text_is(at: *const u8, want: &str) -> bool {
   let Some(raw) = peek(at, 24) else {
      return false;
   };
   let field =
      |index: usize| u64::from_le_bytes(raw[index * 8..index * 8 + 8].try_into().unwrap_or([0; 8]));
   checked_vec(field(0), field(1), field(2)).is_some_and(|(ptr, len)| {
      len == want.len() && peek(ptr, len).is_some_and(|bytes| bytes == want.as_bytes())
   })
}

fn text<'a>(at: *const u8) -> Option<&'a str> {
   let (ptr, len) = vec(at)?;
   if len == 0 {
      return Some("");
   }
   // SAFETY: a `String`'s buffer holds `len` initialized bytes.
   str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) }).ok()
}

/// Whether `value` is an object whose first entry is `"id": "<id>"`.
fn first_is_id(value: *const u8, bucket: Bucket, id: &str) -> bool {
   if word(value) >= NICHE {
      return false;
   }
   let Some((entries, len)) = vec(value) else {
      return false;
   };
   let first = entries.wrapping_add(bucket.value);
   len > 0
      && peek_text_is(entries.wrapping_add(bucket.key), "id")
      && peek_word(first) == Some(NICHE + 3)
      && peek_text_is(first.wrapping_add(8), id)
}

/// Tries each order rustc may give an entry's `hash` (8 bytes), `key` (24)
/// and `value` (72) until the first entry reads as the message's `id`.
fn decode_bucket(value: *const u8, id: &str) -> Option<Bucket> {
   [(8, 32), (80, 8), (0, 32), (0, 24), (80, 0), (72, 0)]
      .into_iter()
      .map(|(key, value)| Bucket { key, value })
      .find(|&bucket| first_is_id(value, bucket, id))
}

fn write_value(out: &mut String, value: *const u8, bucket: Bucket, depth: usize) -> Option<()> {
   if depth > MAX_DEPTH {
      return None;
   }
   let tag = word(value);
   let body = value.wrapping_add(8);
   match tag.checked_sub(NICHE) {
      Some(0) => out.push_str("null"),
      // SAFETY: a `Bool` keeps its byte right after the tag.
      Some(1) => {
         out.push_str(if unsafe { *body } == 0 {
            "false"
         } else {
            "true"
         });
      },
      Some(2) => {
         let payload = word(body.wrapping_add(8));
         // SAFETY: `N`'s tag is a byte at the start of the `Number`; the
         // bytes after it are padding.
         match unsafe { *body } {
            0 => write!(out, "{payload}").ok()?,
            #[expect(clippy::cast_possible_wrap, reason = "NegInt holds an i64")]
            1 => write!(out, "{}", payload as i64).ok()?,
            2 => out.push_str(&serde_json::Number::from_f64(f64::from_bits(payload))?.to_string()),
            _ => return None,
         }
      },
      Some(3) => out.push_str(&serde_json::to_string(text(body)?).ok()?),
      Some(4) => {
         let (items, len) = vec(body)?;
         out.push('[');
         for index in 0..len {
            if index > 0 {
               out.push(',');
            }
            write_value(
               out,
               items.wrapping_add(index * VALUE_SIZE),
               bucket,
               depth + 1,
            )?;
         }
         out.push(']');
      },
      Some(_) => return None,
      None => {
         let (entries, len) = vec(value)?;
         out.push('{');
         for index in 0..len {
            let entry = entries.wrapping_add(index * BUCKET_SIZE);
            if index > 0 {
               out.push(',');
            }
            out.push_str(&serde_json::to_string(text(entry.wrapping_add(bucket.key))?).ok()?);
            out.push(':');
            write_value(out, entry.wrapping_add(bucket.value), bucket, depth + 1)?;
         }
         out.push('}');
      },
   }
   Some(())
}
