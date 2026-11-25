//! Locators for macOS Phoenix, the arm64 desktop client.

use phoenix_hook::{
   arm64::{
      self,
      Insn,
   },
   image::Image,
};

use crate::{
   Found,
   one,
};

/// The function `ClientAccessGate` reads through (1 blocked, 2 no gate).
///
/// The runtime makes it answer "no gate", as on x86. Its small caller is
/// `signed_in && access(..) != 2`, with the comparison outlined into a stub:
///
/// ```text
/// ldr   x8, [x0, #state]
/// cmp   x8, #3              ; signed in
/// b.ne  no
/// stp   x29, x30, [sp, #-0x10]!
/// mov   x29, sp
/// bl    access
/// bl    stub                ; and w8, w0, #0xff; cmp w8, #2; ret
/// cset  w0, ne
/// ```
///
/// The comparison may also be inline, `and w8, w0, #0xff; cmp w8, #2`.
pub fn access_gate(image: &Image<'_>) -> Found<usize> {
   /// `cmp x8, #3`.
   const CMP_X8_3: u32 = 0xF100_0D1F;
   /// `and w8, w0, #0xff`, then `cmp w8, #2`.
   const AND_W8_W0_FF: u32 = 0x1200_1C08;
   const CMP_W8_2: u32 = 0x7100_091F;
   /// How far after the `cmp` the call is looked for.
   const REACH: usize = 8;

   let word_at = |addr: usize| image.read_u32(addr);
   let compares_with_2 = |stub: usize| {
      matches!(
         (
            word_at(stub),
            word_at(stub + 4),
            word_at(stub + 8).map(|word| arm64::decode(word, stub + 8))
         ),
         (Some(AND_W8_W0_FF), Some(CMP_W8_2), Some(Insn::Ret))
      )
   };
   let mut found = Vec::new();
   for segment in image.segments.iter().filter(|segment| segment.executable) {
      for (index, &word) in segment.bytes.as_chunks::<4>().0.iter().enumerate() {
         if u32::from_le_bytes(word) != CMP_X8_3 {
            continue;
         }
         let cmp = segment.addr + index * 4;
         let insns = arm64::decode_all(image.read(cmp, (REACH + 4) * 4).unwrap_or_default(), cmp)
            .map(|(_, insn)| insn)
            .collect::<Vec<_>>();
         if !matches!(
            insns.get(1),
            Some(Insn::BCond {
               cond: arm64::cond::NE,
               ..
            })
         ) {
            continue;
         }
         for at in 2..insns.len().saturating_sub(2) {
            let Insn::Bl { target: access } = insns[at] else {
               continue;
            };
            let checked = match (insns[at + 1], insns.get(at + 2), insns.get(at + 3)) {
               (Insn::Bl { target: stub }, Some(&cset), _) if compares_with_2(stub) => Some(cset),
               (
                  Insn::Other(AND_W8_W0_FF),
                  Some(&Insn::CmpImm {
                     rn: 8,
                     imm: 2,
                     wide: false,
                  }),
                  Some(&cset),
               ) => Some(cset),
               _ => None,
            };
            if checked
               == Some(Insn::Cset {
                  rd:   0,
                  cond: arm64::cond::NE,
               })
               && image.is_function(access)
               && !found.contains(&access)
            {
               found.push(access);
            }
            break;
         }
      }
   }
   one("access gate", &found)
}

/// `mov w0, #2; ret`: the access function's "no gate".
pub const NO_GATE: [u8; 8] = [0x40, 0x00, 0x80, 0x52, 0xC0, 0x03, 0x5F, 0xD6];

/// [`crate::http::DesktopHttpTransport::locate`] for arm64.
///
/// It finds `send` by the anchor string it loads, its `dyn Transport` slots by
/// value, and the `SendFuture` vtable by the `adrp` pair that loads it in
/// `send` or a small callee that boxes the future. The host allocator is not
/// located, so response bodies keep Discord's own buffers.
pub fn http_transport(image: &Image<'_>) -> Found<crate::http::DesktopHttpTransport> {
   let anchor = one(
      "transport anchor",
      &image.find_bytes(crate::http::HOST_FILE_ANCHOR),
   )?;
   let sites = arm64::code_refs(image, anchor..anchor + 1)
      .into_iter()
      .filter_map(|(site, _)| image.function_containing(site))
      .collect::<Vec<_>>();
   let send_fn = one("transport anchor load", &sites)?;
   let send_slots = crate::http::find_vtable_method_slots(image, send_fn, 1..=0x2000);
   if send_slots.is_empty() {
      return Err("no Transport vtable holds ReqwestTransport::send".to_owned());
   }
   let (_, body) = arm64::function(image, send_fn).ok_or("send has no bounds")?;
   let boxers = body
      .iter()
      .filter_map(|&(_, insn)| {
         match insn {
            Insn::Bl { target } => {
               image
                  .function_bounds(target)
                  .filter(|&(start, end)| start == target && end - start <= 0x80)
            },
            _ => None,
         }
      })
      .collect::<Vec<_>>();
   let send_bounds = image.function_bounds(send_fn).ok_or("send has no bounds")?;
   for group in [boxers, vec![send_bounds]] {
      let mut found = group
         .into_iter()
         .flat_map(|(start, end)| future_vtables(image, start, end))
         .collect::<Vec<_>>();
      found.sort_unstable();
      found.dedup();
      match found[..] {
         [] => {},
         [(vtable, poll_fn)] => {
            let mut poll_slots =
               crate::http::find_vtable_method_slots(image, poll_fn, 0x100..=0x4000);
            if !poll_slots.contains(&(vtable + 24)) {
               poll_slots.push(vtable + 24);
            }
            return Ok(crate::http::DesktopHttpTransport {
               send_slots,
               send_fn,
               poll_slots,
               poll_fn,
               host_alloc: None,
               host_dealloc: None,
            });
         },
         _ => return Err(format!("{} SendFuture vtable candidates", found.len())),
      }
   }
   Err("SendFuture vtable not found".to_owned())
}

/// `(vtable, poll_fn)` for each address `[start, end)` builds that reads as a
/// boxed future's vtable: `[drop, size, align 8, poll]`.
fn future_vtables(image: &Image<'_>, start: usize, end: usize) -> Vec<(usize, usize)> {
   let mut pages = [None; 32];
   let mut found = Vec::new();
   let code = image.read(start, end - start).unwrap_or_default();
   for (_, insn) in arm64::decode_all(code, start) {
      let target = match insn {
         Insn::Adrp { rd, page } => {
            pages[usize::from(rd)] = Some(page);
            continue;
         },
         Insn::AddImm { rn, imm, .. } => pages[usize::from(rn)].map(|page| page + imm),
         _ => None,
      };
      let Some(vtable) = target else {
         continue;
      };
      let read = |at: usize| image.read_usize(vtable + at);
      if let (Some(drop_fn), Some(size), Some(8), Some(poll_fn)) =
         (read(0), read(8), read(16), read(24))
         && image.is_function(drop_fn)
         && image.is_function(poll_fn)
         && (0x100..=0x4000).contains(&size)
      {
         found.push((vtable, poll_fn));
      }
   }
   found
}

/// [`crate::desktop::settings_label_parts`] for arm64: the packed literal
/// `PhoenixDESKTOP_PHOENIX` whose name and id one function loads.
pub fn settings_label_parts(image: &Image<'_>) -> Found<crate::desktop::SettingsLabel> {
   const NAME: usize = b"Phoenix".len();
   let mut found = image
      .find_bytes(b"PhoenixDESKTOP_PHOENIX")
      .into_iter()
      .filter(|&name| {
         let loader = |target: usize| {
            arm64::code_refs(image, target..target + 1)
               .into_iter()
               .filter_map(|(site, _)| image.function_containing(site))
               .collect::<Vec<_>>()
         };
         let names = loader(name);
         loader(name + NAME).iter().any(|func| names.contains(func))
      })
      .collect::<Vec<_>>();
   found.dedup();
   let name = one("settings label loader", &found)?;
   Ok(crate::desktop::SettingsLabel {
      name,
      id: name + NAME,
   })
}

/// Every copy of `is_page_visible`'s page-range guard, which the runtime
/// lowers so page 24 is always shown.
///
/// Pages 9 to 24 take a switch on flags and the rest are visible. The function
/// is also inlined, into the sidebar among others, so each copy is matched by
/// what it does: `sub wA, wB, #9; cmp wA, #0xf; b.hi visible`, where `visible`
/// is `cmp wB, #0; cset wN, ne`. The `cmp` addresses are returned.
pub fn settings_visibility(image: &Image<'_>) -> Found<Vec<usize>> {
   let mut found = Vec::new();
   for segment in image.segments.iter().filter(|segment| segment.executable) {
      let words = segment.bytes.as_chunks::<4>().0;
      for (index, window) in words.windows(3).enumerate() {
         let at = |offset: usize| segment.addr + (index + offset) * 4;
         let sub = u32::from_le_bytes(window[0]);
         // `sub wA, wB, #9`.
         if sub & 0xFFFF_FC00 != 0x5100_2400 {
            continue;
         }
         let (page, range) = (((sub >> 5) & 0x1F) as u8, (sub & 0x1F) as u8);
         let (
            Insn::CmpImm {
               rn,
               imm: 0xF,
               wide: false,
            },
            Insn::BCond {
               cond: arm64::cond::HI,
               target: visible,
            },
         ) = (
            arm64::decode(u32::from_le_bytes(window[1]), at(1)),
            arm64::decode(u32::from_le_bytes(window[2]), at(2)),
         )
         else {
            continue;
         };
         let returns_nonzero = image.read(visible, 8).is_some_and(|code| {
            let mut insns = arm64::decode_all(code, visible).map(|(_, insn)| insn);
            matches!(
               (insns.next(), insns.next()),
               (
                  Some(Insn::CmpImm { rn, imm: 0, wide: false }),
                  Some(Insn::Cset { cond: arm64::cond::NE, .. })
               ) if rn == page
            )
         });
         if rn == range && returns_nonzero {
            found.push(at(1));
         }
      }
   }
   match found.len() {
      1..=4 => Ok(found),
      count => Err(format!("settings visibility guard matched {count} times")),
   }
}

/// `cmp wN, #0xe`, written over the visibility guard's `cmp wN, #0xf`.
#[must_use]
pub const fn lowered_guard(cmp: u32) -> u32 {
   (cmp & !(0xFFF << 10)) | (0xE << 10)
}

/// [`crate::desktop::settings_section`] for arm64.
///
/// `host::section` loads `account-loading`, and early on reads the active page
/// off its first argument, through whichever register it copied that into:
/// `mov xS, x0 ... ldrb wN, [xS, #page]`.
pub fn settings_section(image: &Image<'_>) -> Found<crate::desktop::Section> {
   let anchor = one("account-loading", &image.find_bytes(b"account-loading"))?;
   let mut funcs = arm64::code_refs(image, anchor..anchor + 1)
      .into_iter()
      .filter_map(|(site, _)| image.function_containing(site))
      .collect::<Vec<_>>();
   funcs.dedup();
   let func = one("account-loading load", &funcs)?;
   let (_, body) = arm64::function(image, func).ok_or("settings section has no bounds")?;
   let mut state = vec![0];
   let page_offset = body
      .iter()
      .take(0x60)
      .find_map(|&(_, insn)| {
         match insn {
            Insn::MovReg {
               rd,
               rm: 0,
               wide: true,
            } => {
               state.push(rd);
               None
            },
            Insn::Load {
               rn,
               offset,
               size: 1,
               ..
            } if state.contains(&rn) && (0x100..0x2000).contains(&offset) => Some(offset),
            _ => None,
         }
      })
      .ok_or("settings section active page load not found")?;
   Ok(crate::desktop::Section { func, page_offset })
}

/// What a register holds while a function body is read: an offset into the
/// function's first argument, an absolute address, or a constant.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Held {
   SelfAt(usize),
   Addr(usize),
   Imm(u64),
}

/// Registers while a body is read, per path.
type Regs = [Option<Held>; 32];

/// What `insn` does to `regs`.
fn step(regs: &mut Regs, insn: Insn) {
   match insn {
      Insn::Adrp { rd, page } => regs[usize::from(rd)] = Some(Held::Addr(page)),
      Insn::AddImm { rd, rn, imm } => {
         regs[usize::from(rd)] = match regs[usize::from(rn)] {
            Some(Held::SelfAt(at)) => Some(Held::SelfAt(at + imm)),
            Some(Held::Addr(at)) => Some(Held::Addr(at + imm)),
            _ => None,
         };
      },
      Insn::MovReg { rd, rm, wide: true } => regs[usize::from(rd)] = regs[usize::from(rm)],
      Insn::MovZ { rd, imm, .. } => regs[usize::from(rd)] = Some(Held::Imm(imm)),
      // Calls keep only the callee-saved registers.
      Insn::Bl { .. } | Insn::Blr { .. } => regs[..19].fill(None),
      Insn::Load { rt, .. } | Insn::Cset { rd: rt, .. } | Insn::MovN { rd: rt, .. } => {
         regs[usize::from(rt)] = None;
      },
      Insn::MovReg { rd, .. } => regs[usize::from(rd)] = None,
      Insn::Writeback { rt, rn, imm, load } => {
         regs[usize::from(rn)] = match regs[usize::from(rn)] {
            Some(Held::SelfAt(at)) => at.checked_add_signed(imm).map(Held::SelfAt),
            _ => None,
         };
         if load {
            regs[usize::from(rt)] = None;
         }
      },
      // Anything else that writes a register forgets it.
      Insn::Other(word) => regs[(word & 0x1F) as usize] = None,
      _ => {},
   }
}

/// Every call in `body` with the registers that reach it on every path, from
/// `entry` at the start. Branches are followed, and where paths meet a
/// register keeps a value only when they agree.
fn calls_with_regs(body: &[(usize, Insn)], entry: &Regs) -> Vec<(usize, usize, Regs)> {
   use std::collections::HashMap;

   let index_of = body
      .iter()
      .enumerate()
      .map(|(index, &(pc, _))| (pc, index))
      .collect::<HashMap<usize, usize>>();
   let mut seen: HashMap<usize, Regs> = HashMap::new();
   let mut calls: HashMap<usize, (usize, Regs)> = HashMap::new();
   let mut work = vec![(0usize, *entry)];
   // Bounded, since each revisit only forgets registers.
   let mut budget = body.len() * 8;
   while let Some((mut index, mut regs)) = work.pop() {
      loop {
         if budget == 0 {
            return Vec::new();
         }
         budget -= 1;
         let Some(&(pc, insn)) = body.get(index) else {
            break;
         };
         if let Some(known) = seen.get(&index) {
            let merged =
               std::array::from_fn(|at| (known[at] == regs[at]).then_some(known[at]).flatten());
            if merged == *known {
               break;
            }
            regs = merged;
         }
         seen.insert(index, regs);
         if let Insn::Bl { target } = insn {
            calls.insert(pc, (target, regs));
         }
         let branch = match insn {
            Insn::BCond { target, .. } | Insn::Cbz { target, .. } | Insn::Tbz { target, .. } => {
               Some((target, true))
            },
            Insn::B { target } => Some((target, false)),
            Insn::Ret | Insn::Br { .. } => break,
            _ => None,
         };
         step(&mut regs, insn);
         if let Some((target, falls_through)) = branch {
            if let Some(&to) = index_of.get(&target) {
               work.push((to, regs));
            }
            if !falls_through {
               break;
            }
         }
         index += 1;
      }
   }
   let mut calls = calls
      .into_iter()
      .map(|(pc, (target, regs))| (pc, target, regs))
      .collect::<Vec<_>>();
   calls.sort_unstable_by_key(|&(pc, ..)| pc);
   calls
}

/// Field name to offset in a `Debug::fmt` that calls `DebugStruct::field`
/// with `x1`/`w2` the name, `x3` `self + offset` and `x4` the field's `Debug`
/// vtable, with nested structs as `outer.inner`, followed through the
/// vtable's `fmt` `depth` deep. The `field` call is the one most calls in
/// the function go to with that shape.
pub(crate) fn debug_offsets(
   image: &Image<'_>,
   func: usize,
   depth: usize,
) -> std::collections::HashMap<String, usize> {
   use std::collections::HashMap;

   let mut out = HashMap::new();
   let Some((_, body)) = arm64::function(image, func) else {
      return out;
   };
   let mut entry: Regs = [None; 32];
   entry[0] = Some(Held::SelfAt(0));
   let calls = calls_with_regs(&body, &entry)
      .into_iter()
      .filter_map(|(_, target, regs)| {
         let (Some(Held::Addr(name)), Some(Held::Imm(len)), Some(Held::SelfAt(offset))) =
            (regs[1], regs[2], regs[3])
         else {
            return None;
         };
         let len = usize::try_from(len)
            .ok()
            .filter(|len| (1..64).contains(len))?;
         let vtable = match regs[4] {
            Some(Held::Addr(vtable)) => Some(vtable),
            _ => None,
         };
         Some((target, name, len, offset, vtable))
      })
      .collect::<Vec<_>>();
   let mut counts: HashMap<usize, usize> = HashMap::new();
   for &(target, ..) in &calls {
      *counts.entry(target).or_default() += 1;
   }
   let Some((&field_fn, _)) = counts.iter().max_by_key(|&(_, count)| *count) else {
      return out;
   };
   for (target, name, len, offset, vtable) in calls {
      if target != field_fn {
         continue;
      }
      let Some(name) = image
         .read(name, len)
         .and_then(|name| std::str::from_utf8(name).ok())
      else {
         continue;
      };
      if out.contains_key(name) {
         continue;
      }
      out.insert(name.to_owned(), offset);
      let fmt = vtable.and_then(|vtable| image.read_usize(vtable + 0x18));
      if depth > 0
         && let Some(fmt) = fmt.filter(|&fmt| image.is_function(fmt))
      {
         for (inner, at) in debug_offsets(image, fmt, depth - 1) {
            out.entry(format!("{name}.{inner}")).or_insert(offset + at);
         }
      }
   }
   out
}

/// `<StyleRefinement as Debug>::fmt`'s fields, from the one function that
/// loads the bare name and prints `padding` and `gap`.
pub fn style_fields(image: &Image<'_>) -> Found<std::collections::HashMap<String, usize>> {
   const NAME: &[u8] = b"StyleRefinement";
   let mut funcs = image
      .find_bytes(NAME)
      .into_iter()
      .flat_map(|name| arm64::code_refs(image, name..name + 1))
      .filter_map(|(site, _)| image.function_containing(site))
      .collect::<Vec<_>>();
   funcs.sort_unstable();
   funcs.dedup();
   let mut found = funcs
      .into_iter()
      .map(|func| debug_offsets(image, func, 1))
      .filter(|fields| {
         ["padding.top", "gap.width"]
            .iter()
            .all(|name| fields.contains_key(*name))
      })
      .collect::<Vec<_>>();
   match found.len() {
      1 => Ok(found.remove(0)),
      count => Err(format!("StyleRefinement Debug matched {count} functions")),
   }
}

/// [`crate::desktop::StyleOffsets`] for arm64, from `StyleRefinement`'s
/// `Debug`, checked against `bytes`, the struct's size.
pub fn style_offsets(image: &Image<'_>, bytes: usize) -> Found<crate::desktop::StyleOffsets> {
   crate::desktop::style_from_fields(&style_fields(image)?, bytes)
}

/// `Option<u64>` reads `ORed` into flags and tested for bit 0:
/// `ldr wT, [xB, #tag]; tbz wT, #0`, `ldr xV, [xB, #tag + 8]` close by, then
/// `orr` and a bit-0 test. Returns `(offset, site)`, the offset counted from
/// before an `add xB, xS, #page` that sets the base.
fn option_u64_reads(image: &Image<'_>) -> Vec<(usize, usize)> {
   let mut found = Vec::new();
   for segment in image.segments.iter().filter(|segment| segment.executable) {
      let words = segment.bytes.as_chunks::<4>().0;
      let insn = |index: usize| {
         words
            .get(index)
            .map(|&word| arm64::decode(u32::from_le_bytes(word), segment.addr + index * 4))
      };
      for index in 0..words.len().saturating_sub(24) {
         let Some(Insn::Load {
            rt,
            rn,
            offset: tag,
            size: 4,
         }) = insn(index)
         else {
            continue;
         };
         if rn == 31 || tag < 0x100 {
            continue;
         }
         // `Some` is tag 1, tested as `tbz/tbnz wT, #0` straight after.
         if !matches!(insn(index + 1), Some(Insn::Tbz { rt: tested, bit: 0, .. }) if tested == rt) {
            continue;
         }
         let value = (index.saturating_sub(6)..index + 6).find_map(|at| {
            match insn(at) {
               Some(Insn::Load {
                  rt: value,
                  rn: base,
                  offset,
                  size: 8,
               }) if base == rn && offset == tag + 8 => Some((at, value)),
               _ => None,
            }
         });
         let Some((value_at, value)) = value else {
            continue;
         };
         // `(flags | override) & 1`: an `orr` of 64-bit registers, then a
         // bit-0 test or mask, shortly after.
         let ors_then_tests_bit0 = (value_at + 1..value_at + 16).any(|at| {
            // `orr xD, xN, xM` with the value as an operand; `mov` is the
            // same encoding from `xzr`, which is not an OR of two values.
            words.get(at).is_some_and(|&word| {
               let word = u32::from_le_bytes(word);
               let (rn, rm) = ((word >> 5) & 0x1F, (word >> 16) & 0x1F);
               word & 0xFF20_0000 == 0xAA00_0000
                  && rn != 31
                  && (rn == u32::from(value) || rm == u32::from(value))
            }) && (at + 1..at + 6).any(|next| {
               let Some(&raw) = words.get(next) else {
                  return false;
               };
               let test = u32::from_le_bytes(raw);
               matches!(insn(next), Some(Insn::Tbz { bit: 0, .. }))
                  || test & 0xFFFF_FC00 == 0x9240_0000
                  || test & 0xFFFF_FC1F == 0xF240_001F
            })
         });
         if !ors_then_tests_bit0 {
            continue;
         }
         // The state is huge, so the base is often `add xB, xS, #page, lsl #12`
         // just before; the offset counts from `xS`.
         let base = (index.saturating_sub(8)..index).rev().find_map(|at| {
            match insn(at) {
               Some(Insn::AddImm {
                  rd,
                  rn: source,
                  imm,
               }) if rd == rn && source != 31 => Some(imm),
               _ => None,
            }
         });
         found.push((base.unwrap_or(0) + tag, segment.addr + index * 4));
      }
   }
   found
}

/// [`crate::desktop::staff`] for arm64.
///
/// `flag_override: Option<u64>` in the store state, read by the staff check
/// `(user.flags | override) & 1` as
/// `ldr wT, [state, #tag]; tbz wT, #0; ldr xV, [state, #tag + 8]; ...; orr;
/// tbnz #0`. Every reader must agree on the offset.
pub fn staff(image: &Image<'_>) -> Found<crate::StaffField> {
   let mut tags = option_u64_reads(image)
      .into_iter()
      .map(|(tag, _)| tag)
      .collect::<Vec<_>>();
   tags.sort_unstable();
   tags.dedup();
   match tags[..] {
      [tag] => {
         Ok(crate::StaffField {
            tag,
            value: tag + 8,
         })
      },
      _ => Err(format!("staff flag reads disagree: {tags:#x?}")),
   }
}

/// What `phoenix.ui.addMessageAction` needs from `MessageContextMenu` on
/// arm64: the builder, where its input holds the message and channel ids,
/// and the `MenuItem` constructors its items are made with.
#[derive(Debug, Clone, Copy)]
pub struct MessageMenu {
   /// `fn(x0 input, x1 cx, x2..x5, d0) -> Vec<MenuItem>` through `x8`.
   pub build_fn:          usize,
   pub message_id_offset: usize,
   pub channel_id_offset: usize,
   /// `props_new(x8 out, x0 &SharedString, w1, w2)`.
   pub props_new:         usize,
   /// `with_id(x8 out, x0 item, x1 ptr, x2 len)`.
   pub with_id:           usize,
   /// `with_icon(x8 out, x0 item, w1 icon)`.
   pub with_icon:         usize,
   /// `Vec<MenuItem>::push(x0 vec, x1 item)`.
   pub vec_push:          usize,
   pub layout:            crate::desktop::MenuLayout,
}

/// `fn`'s instructions with each outlined stub inlined: a `bl` to a short
/// frameless stub becomes the stub's instructions, and its tail `b T` a `bl T`.
fn flattened(image: &Image<'_>, func: usize) -> Vec<Insn> {
   flattened_at(image, func)
      .into_iter()
      .map(|(_, insn)| insn)
      .collect()
}

/// [`flattened`] with each instruction's address, a stub's being its call's.
#[must_use]
pub fn flattened_at(image: &Image<'_>, func: usize) -> Vec<(usize, Insn)> {
   let Some((_, body)) = arm64::function(image, func) else {
      return Vec::new();
   };
   let mut out = Vec::with_capacity(body.len());
   for (pc, insn) in body {
      let Insn::Bl { target } = insn else {
         out.push((pc, insn));
         continue;
      };
      match stub(image, target) {
         Some((prefix, tail)) => {
            out.extend(prefix.into_iter().map(|insn| (pc, insn)));
            if let Some(tail) = tail {
               out.push((pc, Insn::Bl { target: tail }));
            }
         },
         None => out.push((pc, insn)),
      }
   }
   out
}

/// A stub's instructions before its `b T` (with `T`) or `ret` (without).
fn stub(image: &Image<'_>, at: usize) -> Option<(Vec<Insn>, Option<usize>)> {
   const MOST: usize = 6;
   let code = image.read(at, MOST * 4)?;
   let mut prefix = Vec::new();
   for (_, insn) in arm64::decode_all(code, at) {
      match insn {
         Insn::B { target } => return Some((prefix, Some(target))),
         Insn::Ret => return Some((prefix, None)),
         Insn::Bl { .. }
         | Insn::BCond { .. }
         | Insn::Cbz { .. }
         | Insn::Tbz { .. }
         | Insn::Br { .. }
         | Insn::Blr { .. }
         | Insn::Writeback { .. } => return None,
         other => prefix.push(other),
      }
   }
   None
}

/// `stp`/`ldp` of 64-bit registers at a signed offset: `(load, rt, rt2, rn,
/// offset)`.
fn pair(insn: Insn) -> Option<(bool, u8, u8, u8, isize)> {
   let Insn::Other(word) = insn else {
      return None;
   };
   let load = match word & 0xFFC0_0000 {
      0xA900_0000 => false,
      0xA940_0000 => true,
      _ => return None,
   };
   let field = |shift: u32| ((word >> shift) & 31) as u8;
   let imm = (((word >> 15) & 0x7F) << 25).cast_signed() >> 25;
   Some((load, field(0), field(10), field(5), imm as isize * 8))
}

/// The most common value, if it occurs at least `least` times.
fn most_common(values: impl IntoIterator<Item = usize>, least: usize) -> Option<usize> {
   let mut counts = std::collections::HashMap::<usize, usize>::new();
   for value in values {
      *counts.entry(value).or_default() += 1;
   }
   counts
      .into_iter()
      .filter(|&(_, count)| count >= least)
      .max_by_key(|&(value, count)| (count, std::cmp::Reverse(value)))
      .map(|(value, _)| value)
}

/// [`MessageMenu`], from the builder that loads the bare `MessageContextMenu`
/// name.
///
/// Its items are built `i18n label -> MenuItem::new::<F> -> with_id ->
/// [with_icon] -> push`, every step behind outlined stubs, and each
/// `MenuItem::new::<F>` ends in a core that runs `props_new`, boxes the
/// closure in an `Rc`, copies the props in and writes the variant tag.
#[expect(
   clippy::too_many_lines,
   reason = "one pass per located part, each checked"
)]
pub fn message_context_menu(image: &Image<'_>) -> Found<MessageMenu> {
   const NAME: &[u8] = b"MessageContextMenu";
   let mut builders = image
      .find_bytes(NAME)
      .into_iter()
      .flat_map(|name| arm64::code_refs(image, name..name + 1))
      .filter_map(|(site, _)| image.function_containing(site))
      .collect::<Vec<_>>();
   builders.sort_unstable();
   builders.dedup();
   let build_fn = one("MessageContextMenu builder", &builders)?;
   let body = flattened(image, build_fn);

   // The input arrives in `x0`, is kept in a callee-saved register, and its
   // message id and channel id are loaded as one pair.
   let head = &body[..body.len().min(48)];
   let input = head
      .iter()
      .find_map(|insn| {
         match *insn {
            Insn::MovReg {
               rd,
               rm: 0,
               wide: true,
            } if rd >= 19 => Some(rd),
            _ => None,
         }
      })
      .ok_or("MessageContextMenu input register not found")?;
   let message_id_offset = head
      .iter()
      .find_map(|&insn| {
         match pair(insn) {
            Some((true, _, _, rn, offset)) if rn == input && (0x20..=0x400).contains(&offset) => {
               usize::try_from(offset).ok()
            },
            _ => None,
         }
      })
      .ok_or("MessageContextMenu message id load not found")?;

   let calls_after = |want: fn(&Insn) -> bool| {
      body
         .windows(2)
         .filter_map(|pair| {
            match pair {
               [before, Insn::Bl { target }] if want(before) => Some(*target),
               _ => None,
            }
         })
         .collect::<Vec<_>>()
   };
   let with_id = most_common(
      calls_after(|insn| matches!(insn, Insn::MovZ { rd: 2, .. })),
      3,
   )
   .ok_or("MenuItem::with_id not found")?;

   // `with_icon` keeps the icon as a `u16` on its stack: `sturh w1, [..]`.
   let stores_icon = |func: usize| {
      image.read(func, 8 * 4).is_some_and(|code| {
         code
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .any(|word| word & 0xFFE0_0C1F == 0x7800_0001)
      })
   };
   let with_icon = most_common(
      calls_after(|insn| matches!(insn, Insn::MovZ { rd: 1, .. }))
         .into_iter()
         .filter(|&target| stores_icon(target)),
      2,
   )
   .ok_or("MenuItem::with_icon not found")?;

   // `push` strides by the item size: `mov w9, #size; madd x0, len, x9, ptr`.
   let push_stride = |func: usize| {
      let code = flattened(image, func);
      code.windows(2).find_map(|pair| {
         match pair {
            [Insn::MovZ { rd: 9, imm, .. }, Insn::Other(word)]
               if word & 0xFFE0_8000 == 0x9B00_0000 && (word >> 16) & 31 == 9 =>
            {
               usize::try_from(*imm).ok()
            },
            _ => None,
         }
      })
   };
   let mut pushes = body
      .iter()
      .filter_map(|insn| {
         match *insn {
            Insn::Bl { target } => push_stride(target).map(|size| (target, size)),
            _ => None,
         }
      })
      .collect::<Vec<_>>();
   let vec_push = most_common(pushes.iter().map(|&(target, _)| target), 3)
      .ok_or("Vec<MenuItem>::push not found")?;
   pushes.retain(|&(target, _)| target == vec_push);
   let size = pushes[0].1;

   // Each `MenuItem::new::<F>` reaches its core through
   // `mov x3, x1; mov w1, #0; b core`.
   let mut targets = body
      .iter()
      .filter_map(|insn| {
         match *insn {
            Insn::Bl { target } => Some(target),
            _ => None,
         }
      })
      .collect::<Vec<_>>();
   targets.sort_unstable();
   targets.dedup();
   let mut cores = targets
      .into_iter()
      .flat_map(|ctor| {
         flattened(image, ctor)
            .windows(3)
            .filter_map(|window| {
               match window {
                  [
                     Insn::MovReg { rd: 3, rm: 1, .. },
                     Insn::MovZ { rd: 1, imm: 0, .. },
                     Insn::Bl { target },
                  ] => Some(*target),
                  _ => None,
               }
            })
            .collect::<Vec<_>>()
      })
      .collect::<Vec<_>>();
   cores.sort_unstable();
   cores.dedup();
   let read_core = |core: usize| -> Option<(usize, crate::desktop::MenuLayout)> {
      let code = flattened(image, core);
      let props_new = code.windows(2).find_map(|pair| {
         match pair {
            [Insn::AddImm { rd: 8, rn: 31, .. }, Insn::Bl { target }] => Some(*target),
            _ => None,
         }
      })?;
      let (props, props_size) = code.windows(4).find_map(|window| {
         match window {
            [
               Insn::AddImm {
                  rd: 0,
                  rn,
                  imm: props,
               },
               Insn::AddImm { rd: 1, rn: 31, .. },
               Insn::MovZ {
                  rd: 2,
                  imm: props_size,
                  ..
               },
               Insn::Bl { .. },
            ] if *rn != 31 => Some((*props, usize::try_from(*props_size).ok()?)),
            _ => None,
         }
      })?;
      let (on_click, action_tag) = code.windows(3).find_map(|window| {
         let [
            handler,
            Insn::MovZ {
               rd: 8, imm: tag, ..
            },
            variant,
         ] = window
         else {
            return None;
         };
         let (false, _, 8, base, on_click) = pair(*handler)? else {
            return None;
         };
         let (false, 8, 31, base2, 0) = pair(*variant)? else {
            return None;
         };
         (base == base2).then_some((usize::try_from(on_click).ok()?, *tag))
      })?;
      Some((props_new, crate::desktop::MenuLayout {
         size,
         props,
         props_size,
         action_tag,
         on_click,
         on_click_tag: on_click.checked_sub(8)?,
      }))
   };
   let decoded = cores.into_iter().filter_map(read_core).collect::<Vec<_>>();
   let Some(&(props_new, layout)) = decoded.first() else {
      return Err("no MenuItem::new core decodes".to_owned());
   };
   if decoded.len() < 2
      || decoded.iter().any(|&(other, at)| {
         other != props_new
            || (at.props, at.props_size, at.action_tag, at.on_click)
               != (
                  layout.props,
                  layout.props_size,
                  layout.action_tag,
                  layout.on_click,
               )
      })
   {
      return Err(format!("{} MenuItem::new cores disagree", decoded.len()));
   }
   if layout.props + layout.props_size > layout.size
      || layout.on_click + 16 > layout.props
      || layout.size > crate::desktop::layout::SCRATCH_CAP
   {
      return Err(format!("MenuItem layout doesn't fit: {layout:x?}"));
   }
   Ok(MessageMenu {
      build_fn,
      message_id_offset,
      channel_id_offset: message_id_offset + 8,
      props_new,
      with_id,
      with_icon,
      vec_push,
      layout,
   })
}

/// An address loaded by an `adrp`/`add` pair, at each instruction that
/// completes one, in a [`flattened_at`] stream.
fn loaded(insns: &[(usize, Insn)]) -> Vec<Option<(u8, usize)>> {
   let mut pages = [None::<usize>; 32];
   insns
      .iter()
      .map(|&(_, insn)| {
         match insn {
            Insn::Adrp { rd, page } => {
               pages[usize::from(rd)] = Some(page);
               None
            },
            Insn::AddImm { rd, rn, imm } if rn != 31 => {
               pages[usize::from(rn)].map(|page| (rd, page + imm))
            },
            _ => None,
         }
      })
      .collect()
}

/// A call that returns a value through a stack slot: `x8` was pointed at the
/// stack since the call before.
#[derive(Clone, Copy, Debug)]
struct Built {
   at:     usize,
   target: usize,
}

/// The [`Built`] calls of a [`flattened_at`] stream, besides the i18n lookups,
/// which load a 64-bit key hash into `x2` first.
fn built(insns: &[(usize, Insn)]) -> Vec<Built> {
   let mut out = Vec::new();
   let (mut sret, mut hashed) = (false, false);
   for (index, &(_, insn)) in insns.iter().enumerate() {
      match insn {
         Insn::AddImm { rd: 8, rn: 31, .. } => sret = true,
         Insn::MovZ {
            rd: 2, wide: true, ..
         } => hashed = true,
         Insn::Bl { target } => {
            if sret && !hashed {
               out.push(Built { at: index, target });
            }
            (sret, hashed) = (false, false);
         },
         _ => {},
      }
   }
   out
}

/// The function holding the one code reference to the exact bytes `name`,
/// flattened, and the index the reference completes at.
fn anchored(image: &Image<'_>, name: &[u8], what: &str) -> Found<(Vec<(usize, Insn)>, usize)> {
   let mut sites = image
      .find_bytes(name)
      .into_iter()
      .flat_map(|at| arm64::code_refs(image, at..at + 1))
      .filter_map(|(site, target)| Some((image.function_containing(site)?, target)))
      .collect::<Vec<_>>();
   sites.sort_unstable();
   sites.dedup();
   let (func, target) = *sites
      .first()
      .filter(|_| sites.len() == 1)
      .ok_or_else(|| format!("{what}: {} references", sites.len()))?;
   let insns = flattened_at(image, func);
   let index = loaded(&insns)
      .iter()
      .position(|load| load.is_some_and(|(_, addr)| addr == target))
      .ok_or_else(|| format!("{what} load not found"))?;
   Ok((insns, index))
}

/// The first call `func` makes, through its stubs.
fn first_call(image: &Image<'_>, func: usize) -> Option<usize> {
   flattened(image, func).into_iter().find_map(|insn| {
      match insn {
         Insn::Bl { target } => Some(target),
         _ => None,
      }
   })
}

/// [`crate::desktop::Gpui`] for arm64, from the same two call sites as x86.
///
/// They are the Developer Mode switch row of `host::section`, and the
/// `TesterUpdates` sign-in button and the `ActionRow` it goes into. The
/// order of calls holds once i18n lookups, copies and getters, the calls that
/// return nothing through a stack slot, are left out.
#[expect(clippy::too_many_lines, reason = "one block per builder, as on x86")]
pub fn gpui(image: &Image<'_>) -> Found<crate::desktop::Gpui> {
   let (dev, anchor) = anchored(image, b"set-devmodeDeveloper Mode", "set-devmode")?;
   let loads = loaded(&dev);
   let calls = built(&dev);
   let before = calls
      .iter()
      .filter(|call| call.at < anchor)
      .collect::<Vec<_>>();
   let after = calls
      .iter()
      .filter(|call| call.at > anchor)
      .collect::<Vec<_>>();
   let [.., new_call, flex, flex_col] = before[..] else {
      return Err("Developer Mode row has no Div before it".to_owned());
   };
   let caller_loc = loads[..new_call.at]
      .iter()
      .rev()
      .take(8)
      .find_map(|load| load.and_then(|(rd, addr)| (rd == 0).then_some(addr)))
      .ok_or("div_new Location not found")?;
   let [
      switch_new,
      switch_label,
      switch_desc,
      switch_on_change,
      switch_into_div,
      ..,
   ] = after[..]
   else {
      return Err(format!(
         "Developer Mode row makes {} builder calls",
         after.len()
      ));
   };
   let alloc_or_oom = flattened(image, switch_on_change.target)
      .windows(3)
      .find_map(|window| {
         match window {
            [
               Insn::MovZ { rd: 0, .. },
               Insn::MovZ { rd: 1, .. },
               Insn::Bl { target },
            ] => Some(*target),
            _ => None,
         }
      })
      .ok_or("alloc_or_oom not found in Switch::on_change")?;

   let (tester, anchor) = anchored(image, b"tester-updates-sign-in", "tester-updates-sign-in")?;
   let after_btn = built(&tester)
      .into_iter()
      .filter(|call| call.at > anchor)
      .collect::<Vec<_>>();
   let button_new = after_btn.first().ok_or("Button::new not found")?.target;
   // `ActionRow` opens with `div_new` and `flex`.
   let row_at = after_btn
      .iter()
      .position(|call| {
         let inner = built(&flattened_at(image, call.target));
         inner.first().map(|first| first.target) == Some(new_call.target)
            && inner
               .iter()
               .take(4)
               .any(|inner| inner.target == flex.target)
      })
      .filter(|&at| at >= 1)
      .ok_or("ActionRow no longer calls div_new and flex first")?;
   let action_row = after_btn[row_at].target;
   let button_on_click = after_btn[row_at - 1].target;
   let div_into_any = after_btn
      .get(row_at + 1)
      .ok_or("Div::into_any_element not found after ActionRow")?
      .target;

   let row = flattened_at(image, action_row);
   let row_built = built(&row);
   let second = row_built[1..]
      .iter()
      .position(|call| call.target == new_call.target)
      .ok_or("ActionRow builds one Div")?
      + 1;
   if second < 4 {
      return Err("ActionRow's text column moved".to_owned());
   }
   let div_child_div = row_built[second - 1].target;
   let text_block = row_built[second - 4].target;
   // Copies (`mov w2, #size; bl memcpy`) aside, the child added before the
   // last `div_child_div` is the button.
   let row_calls = row
      .iter()
      .map(|&(_, insn)| insn)
      .collect::<Vec<_>>()
      .windows(2)
      .filter_map(|pair| {
         match pair {
            [
               Insn::MovZ {
                  rd: 2, wide: false, ..
               },
               Insn::Bl { .. },
            ] => None,
            [_, Insn::Bl { target }] => Some(*target),
            _ => None,
         }
      })
      .collect::<Vec<_>>();
   let last_child = row_calls
      .iter()
      .rposition(|&target| target == div_child_div)
      .filter(|&at| at >= 1)
      .ok_or("ActionRow no longer adds its children with div_child_div")?;
   let div_child_button = row_calls[last_child - 1];
   let div_style_mut = most_common(
      row_built[..second]
         .iter()
         .filter(|call| call.target != new_call.target)
         .filter_map(|call| first_call(image, call.target)),
      3,
   )
   .ok_or("div_style_mut not found")?;
   let div_push_any = children_push(&flattened(image, div_child_div)).map(|(_, push)| push);
   let str_into_any = shared_string_into_any(image, div_child_div);

   Ok(crate::desktop::Gpui {
      caller_loc,
      div_new: new_call.target,
      div_flex: flex.target,
      div_flex_col: flex_col.target,
      div_style_mut,
      div_child_div,
      div_child_button,
      div_into_any,
      div_push_any,
      str_into_any,
      text_block,
      switch_new: switch_new.target,
      switch_into_div: switch_into_div.target,
      button_new,
      action_row,
      alloc_or_oom,
      switch_label: switch_label.target,
      switch_desc: switch_desc.target,
      switch_on_change: switch_on_change.target,
      button_on_click,
   })
}

/// `<SharedString as IntoElement>::into_any_element`, which `Div::child` for
/// a `SharedString` (a neighbour of `div_child_div`) calls. It drops the
/// string it moved: `cmp w8, #0xff` (`None`), then `cmp w8, #0x19` (`Arc`).
fn shared_string_into_any(image: &Image<'_>, div_child_div: usize) -> Option<usize> {
   let drops_string = |func: usize| {
      flattened(image, func).windows(3).any(|window| {
         matches!(window, [Insn::CmpImm { imm: 0xFF, .. }, _, Insn::CmpImm {
            imm: 0x19,
            ..
         }])
      })
   };
   let mut at = image.function_bounds(div_child_div)?.1;
   for _ in 0..6 {
      let (start, end) = image.function_bounds(at)?;
      let found = flattened(image, start)
         .into_iter()
         .filter_map(|insn| {
            match insn {
               Insn::Bl { target } => Some(target),
               _ => None,
            }
         })
         .find(|&target| drops_string(target));
      if found.is_some() {
         return found;
      }
      at = end;
   }
   None
}

/// `div_child_div`'s push of the child onto `self.children`: `add x0, xS,
/// #children`, the element into `x1`, then the call. The offset and `push`.
fn children_push(code: &[Insn]) -> Option<(usize, usize)> {
   code.windows(3).find_map(|window| {
      match window {
         [Insn::AddImm { rd: 0, rn, imm }, Insn::Bl { target }, ..]
         | [Insn::AddImm { rd: 0, rn, imm }, _, Insn::Bl { target }]
            if *rn != 31 =>
         {
            Some((*imm, *target))
         },
         _ => None,
      }
   })
}

/// The `Rc<dyn Fn>` a handler setter stores, and the size of what it returns:
/// it allocates the `Rc` (`mov w0, #8; mov w1, #size; bl alloc`), stores it
/// into its copy of `self`, and copies that out (`mov w2, #size; b memcpy`).
fn handler_store(image: &Image<'_>, setter: usize) -> Option<(usize, usize)> {
   let code = flattened(image, setter);
   let alloc = code.windows(3).position(|window| {
      matches!(window, [
         Insn::MovZ { rd: 0, imm: 8, .. },
         Insn::MovZ { rd: 1, .. },
         Insn::Bl { .. }
      ])
   })? + 3;
   let boxed = code[alloc..].iter().find_map(|insn| {
      match *insn {
         Insn::MovReg { rd, rm: 0, .. } => Some(rd),
         _ => None,
      }
   })?;
   let offset = code[alloc..].iter().find_map(|insn| {
      match *insn {
         Insn::Store {
            rt,
            offset,
            size: 8,
            ..
         } if rt == boxed => Some(offset),
         _ => None,
      }
   })?;
   // An epilogue `ldp` may sit between the size and the tail call.
   let size = code[alloc..].windows(3).find_map(|window| {
      match window {
         [
            Insn::MovZ { rd: 2, imm, .. },
            Insn::B { .. } | Insn::Bl { .. },
            _,
         ]
         | [
            Insn::MovZ { rd: 2, imm, .. },
            _,
            Insn::B { .. } | Insn::Bl { .. },
         ] => usize::try_from(*imm).ok(),
         _ => None,
      }
   })?;
   Some((offset, size))
}

/// Where a `Switch` setter keeps its `Option<SharedString>`: it reads the tag
/// with a writeback load off `self` (`ldrb w8, [x23, #off]!`) and checks it for
/// `None` (`cmp w8, #0xff`).
fn option_string_field(image: &Image<'_>, setter: usize) -> Option<usize> {
   let code = flattened(image, setter);
   let mut selves = vec![0u8];
   for (index, &insn) in code.iter().enumerate() {
      match insn {
         Insn::MovReg { rd, rm, .. } if selves.contains(&rm) => selves.push(rd),
         Insn::Writeback {
            rt,
            rn,
            imm,
            load: true,
         } if selves.contains(&rn) && imm > 0 => {
            let checked = code[index + 1..]
               .iter()
               .take(2)
               .any(|next| matches!(*next, Insn::CmpImm { rn, imm: 0xff, .. } if rn == rt));
            if checked {
               return usize::try_from(imm).ok();
            }
         },
         _ => {},
      }
   }
   None
}

/// [`crate::desktop::GpuiLayout`] for arm64, from the builders [`gpui`] found.
///
/// The `Button`'s variant and size fields are left past its end, so the
/// runtime never writes them and buttons keep Discord's default look.
#[expect(
   clippy::too_many_lines,
   reason = "one block per decoded struct, as on x86"
)]
pub fn gpui_layouts(
   image: &Image<'_>,
   gpui: &crate::desktop::Gpui,
) -> Found<crate::desktop::GpuiLayout> {
   use crate::desktop::{
      ButtonLayout,
      DivLayout,
      GpuiLayout,
      SwitchLayout,
      layout,
   };

   // `div_child_div` pushes the child at `self + children`, then copies `self`
   // out through its `x8` copy field by field; the last store is the end.
   let child = flattened(image, gpui.div_child_div);
   let (children, _) = children_push(&child).ok_or("Div children SmallVec offset not found")?;
   let out = child
      .iter()
      .find_map(|insn| {
         match *insn {
            Insn::MovReg { rd, rm: 8, .. } => Some(rd),
            _ => None,
         }
      })
      .ok_or("div_child_div result register not found")?;
   let div_size = child
      .iter()
      .filter_map(|&insn| {
         match insn {
            Insn::Store {
               rn, offset, size, ..
            } if rn == out => Some(offset + size),
            Insn::Other(word)
               if word & 0xFFC0_0000 == 0xAD00_0000 && (word >> 5) & 31 == u32::from(out) =>
            {
               let imm = (((word >> 15) & 0x7F) << 25).cast_signed() >> 25;
               usize::try_from(imm * 16 + 32).ok()
            },
            _ => None,
         }
      })
      .max()
      .ok_or("Div size not found")?;

   // `div_new` boxes `Interactivity` (`mov w0, #size; mov w1, #8; bl`) and
   // stores the box in its result with an `stp`.
   let new = flattened(image, gpui.div_new);
   let (interactivity_size, boxed_at) = new
      .windows(3)
      .enumerate()
      .find_map(|(at, window)| {
         match window {
            [
               Insn::MovZ { rd: 0, imm, .. },
               Insn::MovZ { rd: 1, imm: 8, .. },
               Insn::Bl { .. },
            ] if (0x100..0x2000).contains(imm) => Some((usize::try_from(*imm).ok()?, at + 3)),
            _ => None,
         }
      })
      .ok_or("Div::new Interactivity allocation not found")?;
   let boxed = new[boxed_at..]
      .iter()
      .find_map(|insn| {
         match *insn {
            Insn::MovReg { rd, rm: 0, .. } => Some(rd),
            _ => None,
         }
      })
      .ok_or("Div::new Interactivity register not found")?;
   let interactivity = new[boxed_at..]
      .iter()
      .find_map(|&insn| {
         match pair(insn) {
            Some((false, rt, _, _, offset)) if rt == boxed => usize::try_from(offset).ok(),
            Some((false, _, rt2, _, offset)) if rt2 == boxed => usize::try_from(offset + 8).ok(),
            _ => None,
         }
      })
      .ok_or("Div::new Interactivity store not found")?;
   if children + 0x48 > div_size || interactivity + 8 > div_size || div_size > layout::DIV_CAP {
      return Err(format!(
         "Div fields don't fit (size {div_size:#x}, children {children:#x})"
      ));
   }

   // `Interactivity::default` boxes the `StyleRefinement`.
   let style_bytes = new
      .iter()
      .filter_map(|insn| {
         match *insn {
            Insn::Bl { target } => Some(target),
            _ => None,
         }
      })
      .find_map(|callee| {
         flattened(image, callee)
            .into_iter()
            .take(40)
            .collect::<Vec<_>>()
            .windows(3)
            .find_map(|window| {
               match window {
                  [
                     Insn::MovZ { rd: 0, imm, .. },
                     Insn::MovZ { rd: 1, imm: 8, .. },
                     Insn::Bl { .. },
                  ] if (0x200..=0x400).contains(imm) => usize::try_from(*imm).ok(),
                  _ => None,
               }
            })
      })
      .ok_or("Interactivity::default StyleRefinement allocation not found")?;
   let style = style_offsets(image, style_bytes)?;

   let (on_change, switch_size) =
      handler_store(image, gpui.switch_on_change).ok_or("Switch::on_change Rc store not found")?;
   let label = option_string_field(image, gpui.switch_label).ok_or("Switch::label not found")?;
   let description =
      option_string_field(image, gpui.switch_desc).ok_or("Switch::description not found")?;
   if label.max(description) + 24 > switch_size
      || on_change + 16 > switch_size
      || switch_size > layout::SCRATCH_CAP
   {
      return Err("Switch fields sit past the Switch".to_owned());
   }

   let (on_click, button_size) =
      handler_store(image, gpui.button_on_click).ok_or("Button::on_click Rc store not found")?;
   if on_click + 16 > button_size || button_size > layout::SCRATCH_CAP {
      return Err("Button on_click sits past the Button".to_owned());
   }

   Ok(GpuiLayout {
      style,
      div: DivLayout {
         size: div_size,
         children,
         interactivity,
         interactivity_size,
      },
      switch: SwitchLayout {
         size: switch_size,
         label,
         description,
         on_change,
      },
      button: ButtonLayout {
         size: button_size,
         on_click,
         variant: layout::SCRATCH_CAP,
         scale: layout::SCRATCH_CAP,
      },
   })
}

/// `MessageRow::render` on arm64, and the path from its row to the message id.
#[derive(Debug, Clone, Copy)]
pub struct MessageRow {
   /// `fn(x0 row, x1..x7, d0, one stack word) -> AnyElement` through `x8`.
   pub func:       usize,
   /// `row + rc` holds the message's `Rc`.
   pub rc:         usize,
   /// The message inside the `Rc` allocation.
   pub value:      usize,
   /// The id inside the message.
   pub message_id: usize,
}

/// [`MessageRow`], the one caller of both `message-content-` helpers.
///
/// The helper takes the message in `x0`, and
/// formats `&message.id` (`ldr x8, [sp, #msg]; add x8, x8, #id`). The render
/// passes `ldr x9, [sp, #slot]; add x0, x9, #value`, with the slot filled
/// from `ldr x8, [row, #rc]`.
#[expect(
   clippy::too_many_lines,
   reason = "the helper, then the render's path to it"
)]
pub fn message_row(image: &Image<'_>) -> Found<MessageRow> {
   // A format piece: its length byte, then the text.
   const TEMPLATE: &[u8] = b"\x10message-content-";
   let mut refs = image
      .find_bytes(TEMPLATE)
      .into_iter()
      .flat_map(|at| arm64::code_refs(image, at..at + 1))
      .filter_map(|(site, target)| Some((image.function_containing(site)?, site, target)))
      .collect::<Vec<_>>();
   refs.sort_unstable();
   refs.dedup_by_key(|&mut (func, ..)| func);
   if refs.len() < 2 {
      return Err(format!(
         "{} functions load the message-content template",
         refs.len()
      ));
   }
   let callers_of = |helper: usize| {
      arm64::code_refs(image, helper..helper + 1)
         .into_iter()
         .filter_map(|(site, _)| Some((image.function_containing(site)?, site)))
         .collect::<Vec<_>>()
   };
   let mut common: Option<Vec<usize>> = None;
   for &(helper, ..) in &refs {
      let mut parents = callers_of(helper)
         .into_iter()
         .map(|(func, _)| func)
         .collect::<Vec<_>>();
      parents.sort_unstable();
      parents.dedup();
      common = Some(match common {
         None => parents,
         Some(common) => {
            common
               .into_iter()
               .filter(|func| parents.contains(func))
               .collect()
         },
      });
   }
   let func = one("MessageRow::render", &common.unwrap_or_default())?;

   // A helper whose template load is preceded by `add x8, xM, #id`, and
   // whose call in the render builds `x0` from a stack slot.
   let render = flattened_at(image, func);
   let (message_id, slot, value) = refs
      .iter()
      .find_map(|&(helper, site, _)| {
         let insns = flattened_at(image, helper);
         let at = insns.iter().position(|&(pc, _)| pc >= site)?;
         let id = insns[at.saturating_sub(40)..at]
            .iter()
            .rev()
            .find_map(|&(_, insn)| {
               match insn {
                  Insn::AddImm { rd: 8, rn, imm } if rn != 31 && (0x100..=0x800).contains(&imm) => {
                     Some(imm)
                  },
                  _ => None,
               }
            })?;
         let call = render
            .iter()
            .position(|&(_, insn)| insn == Insn::Bl { target: helper })?;
         let (slot, value) = render[call.saturating_sub(24)..call]
            .windows(2)
            .rev()
            .find_map(|pair| {
               match *pair {
                  [
                     (
                        _,
                        Insn::Load {
                           rt,
                           rn: 31,
                           offset: slot,
                           size: 8,
                        },
                     ),
                     (_, Insn::AddImm { rd: 0, rn, imm }),
                  ] if rn == rt && imm < 0x40 => Some((slot, imm)),
                  _ => None,
               }
            })?;
         Some((id, slot, value))
      })
      .ok_or("no message-content helper's message argument decodes")?;
   let rc = render
      .windows(2)
      .find_map(|pair| {
         match *pair {
            [
               (
                  _,
                  Insn::Load {
                     rt,
                     offset: rc,
                     size: 8,
                     rn,
                  },
               ),
               (
                  _,
                  Insn::Store {
                     rt: stored,
                     rn: 31,
                     offset,
                     size: 8,
                  },
               ),
            ] if stored == rt && offset == slot && rn != 31 => Some(rc),
            _ => None,
         }
      })
      .ok_or("the row's message Rc not found")?;
   Ok(MessageRow {
      func,
      rc,
      value,
      message_id,
   })
}
