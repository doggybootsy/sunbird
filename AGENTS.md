# AGENTS.md

Phoenix Unlock patches Phoenix, Discord's native Rust Android client, and runs TypeScript plugins
inside it. Target build is 356.7 Alpha, versionCode 356207. "Phoenix" is Discord's client. The
runtime, the crates and the plugin global are all named `phoenix`.

Read this file before changing code. Every fact here cost someone hours to learn.

## Hard rules

- Credentials. Phoenix's HTTP requests cross `GuestHost.invoke` carrying the user's
  `authorization` header. Never log, print or save invoke frames, dispatch frames or request
  headers. Filter before writing anything to disk, and delete any capture that holds a token.
  `discord.rs` keeps the session headers in memory only.
- Secrets in logs. Plugin settings of `type: "secret"` are scrubbed from every console line by
  `console.rs`. A new credential-bearing setting must use that type.
- Privacy. Screenshots and logs from the owners' phones show private chats, emails and accounts.
  Never quote them in commits or replies, never commit them, delete them after use.
- Real accounts. Never send account-mutating requests (friend adds, settings PATCHes, guild
  joins) to test something. Test `phoenix.discord` writes against paths that return 404.
  Never inject fake messages into real channels.
- Signing. Every APK, from the patcher CLI, the site or the in-app updater, is signed with
  `crates/patcher/keys/`, which the runtime links through the patcher crate. v3 only, with
  the rotation proof from the old Valenced test key, so builds install over each other and keep
  the login. Never add the old private key. Read `keys/README.md` before touching signing.
- Plugin API lives in Rust. UI ops, patch targets, settings pages, stores and HTTP live in the
  crates and reach plugins through the `phoenix` object. Plugins are thin TypeScript. No JS
  prelude in the runtime.
- Typed boundaries. Plugins get opaque handles (`phoenix.gateway.messageCreate`), not strings
  like `"MESSAGE_CREATE"`. Read lists of events, props and handlers live from the binary. Never
  add a hand-maintained list file.
- No committed build output. `web/plugins/lib*.so` and `web/pkg/` are built by
  `scripts/site.nu`, plugin bundles by `web/tools/bundle-plugins.ts`.
  The Frida gadgets in `web/plugins/frida-*` are the one exception, kept for x86 WSA debugging.
- Test on a device before pushing. A clean build proves nothing about the bridge.

## Layout

| Path | What |
|---|---|
| `crates/loader` | `libphoenix.so`, injected into the APK as `libplm.so`. Its constructor starts the runtime. |
| `crates/runtime` | QuickJS plugin runtime and the `phoenix` API every platform shares. `phoenix.d.ts` is the plugin API reference. `platform.rs` is the `Platform` trait the platform crates implement. |
| `crates/runtime/src/gateway.rs` | Gateway event hooks by swapping handler pointers in Phoenix's event registry. |
| `crates/runtime/src/discord.rs` | `phoenix.discord`, Discord's API with Phoenix's own session. The platforms carry the requests. |
| `crates/runtime/src/update.rs` | Update checks against the site and one-tap plugin updates. |
| `crates/runtime/src/remote.rs` | The debug shell on `127.0.0.1:4242`, off by default on Android, switched on in Settings, Phoenix Unlocker, Debug. The platforms add their own endpoints. |
| `crates/runtime-mobile` | phoenix on Phoenix's Android and iOS clients, started by the loader there. iOS has no installer or staff hook, and uses Foundation HTTP and a bundled SQLite. |
| `crates/runtime-mobile/src/bridge/` | The sinks every guest/host frame passes, returning `Action::{Pass, Drop, Replace}`. `jni.rs` patches the JNI table on `GuestHost.invoke`/`applyOps` and rebinds `nativeDispatch`. `ios.rs` swaps the dispatch slot in the guest's vtable and the call slot in the host callbacks' vtable. |
| `crates/runtime-mobile/src/settings/` | The Phoenix Unlock settings pages, built from UI ops. |
| `crates/runtime-mobile/src/patches/` | UI patch targets, slash commands, profile tabs, emoji picker. |
| `crates/runtime-mobile/src/discord.rs` | Plugin requests to Discord through Phoenix's own `Networking` module. |
| `crates/runtime-mobile/src/host.rs` | Phoenix's host call, event and field numbers, read at startup from the name table in the installed APK's dex, or the host's Swift name table on iOS. `host::send` and `host::ask` call host modules. |
| `crates/runtime-mobile/src/picker.rs` | File picker, toasts, clipboard and links through Phoenix's host modules. |
| `crates/runtime-mobile/src/install.rs`, `loader.rs` | The APK self-update, and Android's installer opened on it through Discord's `FileProvider`. |
| `crates/runtime-desktop` | phoenix on Desktop Phoenix (`Discord.exe`, Linux `discord-phoenix`, macOS `Discord`): the access gate, the HTTP transport hooks, the Sunbird pages in User Settings, message accessories and the tray. `os.rs` holds what differs per OS. On macOS, which is arm64, the access gate, `phoenix.discord`, plugins, gateway hooks, fetch, storage, the debug shell and the tray run; everything else is x86-located and off (see Host facts). |
| `crates/ui-mobile` | Typed codec for mobile (Android/iOS) Phoenix UI-op batches. `src/props.in` is Phoenix's prop table, `templates.json` holds captured layouts, `motion.rs` drives native springs, `mirror.rs` keeps a live copy of the view tree that host tests can drive. |
| `crates/ui-desktop` | Desktop UI host primitives (clipboard, URLs, notifications, the tray, GPUI surface hooks), one file per OS. |
| `crates/wire` | Tagged values and bridge frames (`HostCall`, `DispatchEvent`). |
| `crates/hook` | Image scanner, `swap_words`, ShadowHook through `sunhook-sys` on Android ARM. |
| `crates/sigs`, `crates/sigscan` | The gateway registry walk and handler ABI, and every other locator the runtime patches from (`desktop.rs`, `mobile.rs`). `sigscan` dumps a library's registry, runs `check` (every locator for that platform, exit 1 on a miss) and looks up strings, references and disassembly in `Discord.exe`. |
| `crates/patcher` | Patches the split APKs and signs them, as a library with a CLI. One APK merged from the splits or each split signed on its own. |
| `crates/patcher-web` | `crates/patcher` as wasm for the site. |
| `crates/stand-in*` | A fake gateway library and a demo, to test hooks without Discord. |
| `plugins/*/src/index.ts` | Bundled plugins. Leading `// @` lines are the bundle banner and metadata, `// @warning` shows a warning on the site, and `// @unlisted` keeps a plugin out of the site and its updates. |
| `docs/phoenix-356207.*` | Phoenix's schema pulled from the APK by `scripts/extract-schema.py`: 29 view kinds, 855 props, 79 host modules with 433 methods, 109 events, 286 `ic_mana_*` icons and the accessibility ids. Read it before decompiling. |
| `web/` | What CI deploys to assets.sunbird.tools, with a `site.tar.gz` of it that sunbird-tools/site builds from: patcher wasm, loader libraries, plugin bundles, `version.json`. Builds before 76bc0d7 fetch the last three from sunbird.tools, so the site keeps serving them at the same paths. |
| `frida/` | Optional Frida gadget bootstrap, for debugging on x86. |
| `scripts/*.nu` | `phoenix.nu` builds, patches and installs on a phone. `site.nu` builds the site's native libs and wasm. |
| `scripts/sunbird-{linux,macos}.sh` | The Desktop installers the site serves. Each makes a launcher that fetches the loader before every start and leaves Discord's own files untouched. |
| `scripts/dev.ps1` | The Windows dev loop, described below. |

## Building

- Linux. `nix develop`, then
  `nu scripts/phoenix.nu base.apk config.<abi>.apk config.<dpi>.apk config.<lang>.apk`, where the
  ABI split is `config.arm64_v8a` or `config.armeabi_v7a` and picks the loader's target.
  The devshell provides the SDK, NDK and JDK.
  `phoenix.nu` ends in a blocking `adb logcat` tail, so run it in the background from a tool.
- Windows, without Nix.
  - Rust `stable-x86_64-pc-windows-gnu` with the `aarch64-linux-android` target, `cargo-ndk`, an
    NDK, a JDK and an Android SDK with a platform and build-tools in `ANDROID_SDK_ROOT`.
  - Cargo fetches ShadowHook as `sunhook-sys`.
  - Set `LIBCLANG_PATH` to an LLVM `bin` holding `libclang.dll`, and set
    `BINDGEN_EXTRA_CLANG_ARGS_aarch64-linux-android="--target=aarch64-linux-android28 --sysroot=<ndk>/toolchains/llvm/prebuilt/windows-x86_64/sysroot -isystem <ndk>/.../lib/clang/<ver>/include"`
    with `env`, since the name has hyphens.
  - Git for Windows' MinGW (gcc 12) cannot link the host build scripts. Take it off `PATH` and put
    a directory with only `dlltool.exe` (from the toolchain's `self-contained`) and `as.exe` with
    its DLLs on `PATH`.
  - `cargo +stable-x86_64-pc-windows-gnu ndk -t arm64-v8a -P 28 --link-builtins build --release -p phoenix-loader`,
    then `cargo build --release -p patcher`.
- iOS. `.github/workflows/ios.yml` builds `libphoenix.dylib` for `aarch64-apple-ios` on macOS,
  since the SDK ships only with Xcode.
- macOS. `cargo build --release -p phoenix-loader` builds `target/release/libphoenix.dylib` for
  Desktop Phoenix. Install it with `SUNBIRD_SITE=http://127.0.0.1:<port> sh scripts/sunbird-macos.sh`
  against a local folder serving `version.json` and `plugins/libphoenix-macos-arm64.dylib`, or start
  the copy it makes by hand (below). `sigscan` builds natively on Apple silicon.
- Site. `nu scripts/site.nu web` and `node web/tools/bundle-plugins.ts` (set `ESBUILD`
  if esbuild is not on `PATH`), then `nu scripts/fetch.nu <this checkout>` in sunbird-tools/site.
  CI deploys the same files to assets.sunbird.tools on pushes to `main`, and the site picks them up within 10 minutes.

## Fast loop

1. Look up Phoenix internals in `docs/phoenix-356207.md` or `.json` first. After a Discord update,
   regenerate them with `python scripts/extract-schema.py <dir with the splits>`.
2. `.\scripts\dev.ps1 -Test` runs `cargo test -p phoenix-ui-mobile -p phoenix-ui-desktop -p phoenix-wire` on the host in
   under a second.
3. Turn on the debug shell once on the phone. `dev.ps1` forwards port 4242. Then:
   - `-HotReload <plugin>` reloads a plugin in about 200 ms without rebuilding the APK.
   - `-Eval "<js>"` runs a snippet, like `phoenix.ui.root()`.
   - `phoenix.ui.mount`, `phoenix.bridge.invoke`, `phoenix.discord.onRequest` and `onResponse`
     let a UI or API patch be prototyped in JS. Move the finished primitive into Rust.
   - `-Logs`, `-Ops [filter]`, `-Events [filter]` and `-Tree [node]` show the console, decoded
     UI-op batches, view and host events, and the mirrored view tree. `-Clear` empties the ring
     buffers before reproducing something.
4. `.\scripts\dev.ps1` builds with the `dev-fast` profile (about 15 s incremental), patches,
   installs and launches. `-SkipBuild` only rebundles plugins and repatches. `-Release` makes a
   release build.
5. Desktop Phoenix. `.\scripts\dev.ps1 -Desktop` builds the DLL, copies the plugins and restarts
   Discord through the injector. Every debug-shell switch above takes `-Desktop` and skips adb.
   Desktop has no UI-op stream, so `-Ops` and `-Tree` stay Android-only. Reverse it with:
   - `.\scripts\dev.ps1 -Sigscan check|strings|refs|dis ...` on the `Discord.exe` file. A panic
     message or event name usually leads to the function that uses it.
   - `phoenix.native` in `-Eval` (the console only, never plugins): `strings`, `refs`, `fn`, `dis`,
     `scan`, `read`, `readU64`, `readStr`, and `hook(addr, limit)` / `unhook(id)` / `hooks()`.
     A hook logs each call's `rcx rdx r8 r9`, the bytes behind them and the caller to `-Events`.
     Addresses print as RVAs like `+0x7711630`, the same `sigscan` prints.
   - `-Events` also shows every gateway event by name and size and Discord's API requests by path.
6. Keep agent/subagent turns fast:
   - Iterate with `dev-fast` (`.\scripts\dev.ps1 -Desktop`, no `-Release`). Only run `-Release` once at the end before committing or shipping.
   - Batch reads, edits, and shell commands (`test && build && launch` in one command); avoid one-off `grep`/`sed`/`fmt` turns.
   - Use compiled `sigscan.exe` (`check`, `strings`, `refs`, `dis`) or `phoenix.native` for binary lookups — never scan the 515 MB `Discord.exe` `.text` section with Python loops/regexes.
   - Reserve high-effort subagents for hard reverse-engineering only; use `medium` effort / `fastMode` for routine edits and debugging, and pass exact file paths + build env in the brief.

The debug shell answers anyone on the phone's loopback, and `/eval` runs JS with the Discord
session. Leave it off outside development.

## Code style

- Rust is edition 2024, three-space indent, width 100, pinned in `.rustfmt.toml`. Run
  `rustfmt --edition 2024 <files you touched>`. Never run `cargo fmt`, it reformats the whole tree.
- Clippy must stay clean on the host, `aarch64-linux-android` and `armv7-linux-androideabi`.
  Never widen the workspace lint list. Scope an `#[expect(lint, reason = "...")]` to the one function that needs it.
- Errors use `flub` in libraries and `misstep` in binaries. Untrusted input, including anything
  read from Phoenix, returns an error and never panics. A panic inside Discord's process kills the
  app.
- Code that finds something in Discord's binaries lives in `crates/sigs` and returns `Found`, so
  `sigscan check` and the `check` workflow cover it on every new build. Never fall back to an
  offset seen on one build: when it does not decode, leave that feature off.
- Return named enums over nested `Option`s. Use serde structs over raw `serde_json::Value`.
- Comments say why, and only when the reason is not in the code: a host quirk, a measured number,
  a version. No comments that restate the code or narrate history.
- Commit subjects read `area: lowercase imperative`, like `runtime: add select settings`. Bodies
  are optional and explain why.

## Testing on a phone

- Install over the existing `com.discord` with `adb install-multiple -r` so the login survives.
- Logs: `adb logcat -s phoenix` (`-s FridaPlugins` for Frida). Fail fast. When waiting on a build
  or a launch, match `error[E`, `error:` and panics as well as the success line, and never block
  minutes on log lines that need live chat traffic.
- Open settings with
  `adb shell am start -a android.intent.action.VIEW -d discord://app/settings com.discord`.
- Find views with `uiautomator dump` by resource id, which is Phoenix's accessibility id. Ours are
  `phoenix-<title>`. Tap by the dumped bounds, never by guessed coordinates. A blind tap once
  opened a reply draft in a real channel.
- Owners deploy to the same phone while you work. When expected logs vanish, check the pid and the
  startup log to see whose build runs before debugging. Ask before installing over theirs.
- Never enter passwords. Remove test plugins and files you add.
- Git Bash on Windows turns `/word` into a path in adb arguments. Set `MSYS_NO_PATHCONV=1` and
  pass local paths through `cygpath -w`.

## Host facts

Read the decompiled host before guessing or bisecting.
`jadx -q -j 16 --no-res -d out <base apk>` decompiles the Java side. The native host is
`lib/arm64-v8a/liblibdiscord_wasm_host.so`, 97 MB and stripped, with JNI exports visible to
`nm -D`. The armeabi-v7a split's copy is 68 MB of Thumb-2, and inlines differently, so an arm64
byte pattern says nothing about arm32.

- Inline hooks. ShadowHook comes from the `sunhook-sys` crate of sunbird-tools/sunhook. On arm32
  no island fits inside the host library, so a hook rewrites the first 8 or 10 bytes of its
  target in place. Install hooks from the loader's constructor, before any thread can be inside
  the target, and pass Thumb targets with bit 0 set or ShadowHook writes an ARM jump.
- Update risks. `crates/ui-mobile/src/props.in` (props are named by index, so a new prop shifts them),
  `GuestHost.d(byte[], Function0)` (an obfuscated name) and `templates.json`. Host module,
  method, event and field numbers are read at startup by `host.rs`, so the numbers below are
  for reading frames by hand. Everything else is found by names, strings and patterns.
- Threads. Never send UI ops from the main thread, since Rust may hold the UI lock while it waits
  on Java. The settings worker sends them. Java only honors `WasmRuntime.nativeDispatch` on the
  `wasm-guest` HandlerThread, and a call from another thread is silently ignored. Queue a frame
  from any thread with `GuestHost.d([B, Function0)`, which takes the frame without its 4 zero
  header bytes. Queued frames come back through the dispatch sinks, so mark re-sent frames or they
  loop.
- Invoke frames. 16-byte header: kind u8 (1 call, 3 event, 4 batch), a zero byte, module u16,
  method u16, u16 0, call i32, args length u32. Then a tagged args record and the raw body.
  Module, method and field numbers index the name table in `hh/jb.java` (strings like
  `"Networking.request 168"`). Host events return as kind-3 frames inside kind-4 batches through
  `nativeDispatch`.
- Networking. Module 43, request 168, cancel 167, upload 169, reply event `@http` 321. Request
  fields are id 417, method 421, url 422, headers 423 (array of `[name, value]`), responseHeaders
  424. Reply fields are id 417, status 430, headers 423 (map), error 403. Java's side is a plain
  OkHttp executor and the guest sets every header, `authorization` included.
- `READY` never passes through the gateway registry on 356207. Patches that rewrite READY do not
  apply. `LIBDISCORD_REDUCERS_TABLE` is an exported second registry with 86 more events and no
  overlap.
- Motion. The host has 65536 animation slots. Ids at or above that are dropped silently. Phoenix
  allocates upward from 0, so ours come down from 65535. A reused slot keeps a dead view's spring
  until something re-springs it. Channel numbers are the cases of `mh/e0.d`. The `animate` prop
  only applies to images.
- UI text. Text and inputs take `spans` and `valueSpans`, arrays of `{text, color, weight,
  italic, bg}` pieces that concatenate to the text. Set an input with
  `forceValue {seq, text, start, end}`, applied when `seq` changes. `value` is ignored while the
  keyboard has edits in flight.
- Message list. It is virtualized. A row event's `index` is absolute, the list's `first` prop is
  the index of its first mounted child, so the row is `kids[index - first]`.
- Stores. Phoenix keeps state in `files/store/<account>/cache.sqlite`, tables of `k` and a JSON
  BLOB `v`. Message keys end in the id zero-padded to 20 digits.
- Edits. Phoenix fills the edit box from the stored message, so a hook that rewrites your own
  MESSAGE_CREATE changes what an edit posts. The runtime restores the original text in the
  composer.
- QuickJS has no `URLSearchParams`. Check any other web global before a plugin uses it.
- Discord payload shapes are documented at https://docs.discord.food/.

### macOS Desktop

- `Discord Phoenix.app` is a thin arm64 Mach-O with the hardened runtime, so dyld ignores
  `DYLD_INSERT_LIBRARIES`. `sunbird-macos.sh` clones the app (`cp -c`, free on APFS) into
  `~/Library/Application Support/Sunbird/Sunbird.app`, renames it and gives it Sunbird's icon in its
  Info.plist (the bundle id stays Discord's), and signs it ad hoc without the runtime or
  Discord's restricted entitlements. The launcher, `/Applications/Sunbird.app` (or
  `~/Applications` without admin rights), starts it with
  `open -a <copy> --env DYLD_INSERT_LIBRARIES=<dylib>`, and rebuilds the copy when Discord's
  executable changes. A second Discord hands off to a running one, so the launcher first quits
  any Discord Phoenix or copy process without `libphoenix` mapped (`lsof -p`). `SIGTERM` exits it
  within about a second.
- Patching Discord Phoenix in place (Vencord-style: `DYLD_INSERT_LIBRARIES` in Info.plist's
  `LSEnvironment`, re-signed ad hoc) works, but was rejected for the launcher. Writing into the
  bundle needs App Management on macOS 13+ with SIP on. dyld refuses to start the app when the
  inserted library is missing. Discord's updater swaps in a whole new bundle, so the first start
  after each update runs without Sunbird. A Developer ID wouldn't help either way: Discord's
  keychain and App Group entitlements are bound to its team id.
- Phoenix re-execs itself once, under the same pid, with its malloc settings and
  `DISCORD_DESKTOP_MALLOC_REEXEC=1`, unless they are already set. Launch Services sets them from
  Info.plist's `LSEnvironment`, so a copy started through `open` never re-execs, while one exec'd
  from a shell always does. The loader stays idle in an image that has neither, and starts only in
  the last one, then drops itself from `DYLD_INSERT_LIBRARIES`. With SIP off, dyld kills any arm64e
  child (`osascript`, `nohup`) that inherits an arm64 library. `sigscan check` reports a build without
  the marker.
- Data lives in `~/Library/Application Support/libdiscord` (or `LIBDISCORD_DATA_DIR`), Sunbird's
  home in its `sunbird/`. Tokens are in the login keychain, not the data directory, so a copy with
  `LIBDISCORD_DATA_DIR` pointed elsewhere still logs in to the owner's accounts. Keep such runs
  short and delete the directory after.
- To test by hand, start the copy's executable directly with `DYLD_INSERT_LIBRARIES` and
  `LIBDISCORD_DATA_DIR` set, never through `nohup` or another platform binary. Logs go to the unified
  log: `/usr/bin/log stream --predicate 'eventMessage CONTAINS "phoenix:"'` (zsh's builtin `log`
  shadows it). The debug shell is on and needs `debug-shell-token` from Sunbird's home.
- `__TEXT` never takes `PROT_WRITE`. `Image::write_code` copies the page with
  `vm_protect(VM_PROT_COPY)`, which drops its execute bit until it is restored, so the patcher must
  not share the page. Verified with SIP off only.
- arm64 locators live in `crates/sigs/src/macos.rs`, on the decoder in `crates/hook/src/arm64.rs`.
  `sigscan strings`/`refs` resolve `adrp` pairs on Mach-O, and function bounds come from
  `LC_FUNCTION_STARTS`. The code is heavily outlined (`bl` to tiny shared stubs), so static
  reading stalls fast. Attach `lldb -p` to a running copy and break on a view's render function
  for the backtrace instead. A copy lldb launches runs without ASLR, and keeps running after
  `--batch` ends.
- The access gate is the same function as on x86, `access()` returning 1 (blocked) or 2 (no gate),
  and `access_gate` makes it `mov w0, #2; ret`. Its caller is `ldr x8,[x0,#0x78]; cmp x8,#3; b.ne;
  ...; bl access; bl stub; cset w0,ne`, with `cmp w0,#2` outlined into the stub. The root view
  switches on that same state word, and its case 3 holds the gate. Don't patch the account checks
  after it: both of their paths still draw the gate through a stored hook. Verified live: the gate
  renderer is never hit, and the signed-in view is.
- lldb on a live copy: `kill -INT` quits Discord, and `process handle SIGTRAP -p true` kills it on
  the `global-keys` thread's trap. End a wait with
  `script ...; threading.Timer(n, process.SendAsyncInterrupt).start()`, then `detach`. A render
  function only runs on a redraw, so wait on input or count hits over a fixed window.
- `phoenix.discord` works. `macos::http_transport` finds `send` by its anchor string, and the
  `SendFuture` vtable by an `adrp` pair in `send`. The host allocator isn't located. `send` is hooked
  with the arm64 `hook_entry`: it overwrites the first 4 instructions with
  `ldr x16,#8; br x16; .quad`, relocates them into a `MAP_JIT` trampoline, and refuses
  literal loads and branches back into those 4 instructions. Outlined prologues
  (`mov x2,x30; bl stub; mov x30,x2`) relocate fine. A debug shell token is only written by the
  instance owning port 4242, so test a second instance with a plugin in its own
  `LIBDISCORD_DATA_DIR`, triggered from `phoenix.discord.onResponse` (no timers, and no session
  until Discord's first request).
- Calling convention. x86 passes a large return's slot as the first argument and returns it, arm64
  passes it in `x8`. gpui.rs and the settings detour are written the x86 way, so on arm64 calls out
  go through `image::sret_caller` (slot into `x8`, arguments shifted down, slot back in `x0`).
  Detours are entered through `image::sret_callee`, which does the reverse. Up to seven register
  arguments; floats are untouched. Rust lays out the structs the same on both.
- Settings. `macos::settings_label_parts` finds the packed `PhoenixDESKTOP_PHOENIX`, and
  `settings_visibility` finds every copy of `sub wA,wB,#9; cmp wA,#0xf; b.hi T`
  where `T` is `cmp wB,#0; cset ne`. That is the out-of-line `is_page_visible` and the copy inlined
  into the sidebar; the sidebar uses only the inlined one. The runtime lowers each `cmp` to `#0xe`. `settings_section` finds
  `host::section` (x8 return, x0-x4 args, active page `ldrb [copy of x0, #0x61f]` on this build).
  `settings::install_arm64` relabels page 24 to Sunbird, unhides it and hooks the section through
  the thunks. Until the GPUI builders exist it renders Discord's own page 24 and opens the
  dashboard window once per visit. Verified: the entry shows above Log Out (window screenshot), and 26
  section renders went through the hook with no crash. Clicking the entry is untested.
- `Pattern::new` panics without a literal byte, and a panic in the loader's constructor aborts
  Discord. Pass the x86 frame prologue to the arm64 `hook_entry`, which ignores it.
- Struct layouts. `macos::debug_offsets` reads a `Debug::fmt` that calls `DebugStruct::field`
  (`x1`/`w2` name, `x3` = self + offset, `x4` vtable, nested through vtable + 0x18). It follows
  branches with per-path register state, because fields on different paths move the same base
  with writeback loads (`ldr w8, [x19, #8]!`); read in a straight line, one path's writeback
  leaks into the next. `style_offsets` finds every `StyleRefinement` field this way. The size
  check needs the Div layout, which is still to do.
- Outlined stubs. A `bl` to a tiny frameless stub ending in `b T` is a call to `T`, with the
  stub setting arguments from the caller's frame (`add x8, sp, #0x400; b div_new`). A stub
  ending in `ret` only sets arguments. On this build: `div_new` 0x10803cf20 (x8 out, x0
  `&Location`), `Switch::new` 0x106859a98 (x8 out, x0/x1 id, w2 checked), `switch_label`
  0x106e6ec7c and `switch_desc` 0x106eb61b0 (store at +0x98/+0xb0). `Switch` is 0x1d8 bytes
  (the memcpy size), and `on_change` is generic, monomorphized per closure.
- Gateway registry. macOS keeps `MESSAGE_UPDATE`, `MESSAGE_DELETE`, reactions, presence, typing
  and more in a flat table apart from the domain tables. `registry.rs` walks it from
  `MESSAGE_UPDATE` when the other walks miss that event, which takes macOS from 87 to 175 events.
  Platforms that already have the event are unchanged. Verified: a hook on `messageDelete`, which
  is only in that table, fires.
- Staff. `macos::staff` finds `flag_override` from its readers (`ldr wT,[b,#t]; tbz wT,#0;
  ldr xV,[b,#t+8]; orr; tbnz #0`), folding in the `add b, s, #0x8, lsl #12` page base. On this
  build that's `+0x8f30`/`+0x8f38`, with 3 readers agreeing. A `mov` is an `orr` from `xzr`, so
  require a real second operand. The user tag before it (`+0x8e98`) is compared only against 1 and
  2; other values, like `u64::MAX`, are valid, so it is no sanity check. Verified: the Staff Only
  section (Experiments, Build Overrides, Developer Options) shows.
- Shortcuts. `ui-desktop/src/macos.rs` installs an `NSEvent` local key monitor (a hand-built global
  block): Control-Shift-U opens settings, Control-Shift-I DevTools. Command-Shift-U is Discord's
  Upload File, and Discord's own DevTools stay on Command-Option-I. The monitor only sees keys while
  Discord is focused. When testing with System Events, confirm focus first; a window opened by the
  previous shortcut takes it.
- `Image` gained `function_starts`. Every constructor needs it, Windows' included: cross-check
  with `cargo clippy --target x86_64-pc-windows-gnu -p phoenix-hook -p phoenix-sigs`, which
  needs no C toolchain.
- GPUI builders. `macos::gpui` reads the same two call sites as x86 (the Developer Mode row,
  the `TesterUpdates` button and its `ActionRow`), but by role: in a stub-flattened stream
  (`sigscan <bin> flat <from> <to>` prints one) it keeps only calls that return through a stack
  slot (`add x8, sp` since the last call), minus i18n lookups (a 64-bit hash in `x2`). Every
  builder that returns a value goes through an `sret_caller` thunk in `gpui::arm64_builders`.
  `macos::gpui_layouts` reads the Div (0x88, children +0x40 from `div_child_div`'s push,
  `Interactivity` boxed at +8 by `div_new`), the `StyleRefinement` size from
  `Interactivity::default`'s box, `Switch` (0x248; label +0x98 and description +0xb0 from the
  setters' `ldrb w8, [x, #off]!; cmp w8, #0xff`; the 0x1d8 copies are its leading field
  struct) and `Button` (0x328, `on_click` +0x298). Handler setters allocate the `Rc` (`mov w0,
  #8; mov w1, #size; bl alloc`), store it, then copy out. The Button's variant and size aren't
  decoded; their offsets are past the scratch buffer, so the runtime skips them.
  `SharedString::into_any_element` (beside `div_child_div`) checks tags 0xff and 0x19, the
  same as x86.
- Accessories. `macos::message_row` is the common caller of the `\x10message-content-`
  helpers (the code refs point at the length byte). The row holds the message's `Rc` at +0x7c0,
  the message is at +0x10 in it, and the id at +0x1d8. The render takes `x0` row, `x1`..`x7`,
  `d0` and one stack word, and returns the 0x20-byte `AnyElement` through `x8`; the detour is
  native and passes four stack words through. A tint also gets a faint background now, on every
  platform. The x86 body-text recolor (`message_body`) has no arm64 locator.
- Plugin pages and dialogs (`openPage`, `choose`, `showSheet`) are `AppKit` windows on macOS
  (`ui-desktop/src/macos/panel.rs`), routed from `modal::open_page`/`open_choice`/`close_page`: a
  vertical `NSStackView` of headings, button rows, wrapping labels and `scrollableTextView`s. One
  target object answers every button by tag and is each window's delegate, so closing a dialog
  answers -1. Verified: both render and size correctly.
- Message actions. `macos::message_context_menu` finds the builder by its `MessageContextMenu`
  string and flattens its stubs (a `bl` to a stub ending `b T` becomes `bl T`). Items are built
  `i18n -> MenuItem::new::<F> -> with_id -> [with_icon] -> push`; every `MenuItem::new::<F>` ends
  in `mov x3,x1; mov w1,#0; b core`, and each core runs `props_new` (`add x8,sp,#k; bl`), boxes
  the closure, copies the props (`add x0,x19,#0x20; add x1,sp; mov w2,#0x1c8; bl memcpy`) and
  writes `stp rc,vtable,[x19,#0x10]; mov w8,#2; stp x8,xzr,[x19]`. `push` strides by `mov w9,
  #0x1f8; madd`. The input holds the message id at +0x80 and the channel id at +0x88 (one `ldp`;
  the channel goes to the permission check). The detour is a native `extern "C"` function (a
  24-byte return goes through `x8`), and the constructors are called through `sret_caller`.
  `SharedString` keeps x86's tags (0x18 static). Discord's Rust heap may be its own malloc zone, so
  our `Rc` handlers are pinned (`gpui::pinned_rc_u64`) and never freed by Discord. The separator
  tag isn't verified, so arm64 items follow Discord's without one, and there's no `with_color`.
- Test a second instance with `open -n -a <copy> --env DYLD_INSERT_LIBRARIES=... --env
  LIBDISCORD_DATA_DIR=...`. Exec'd from a shell it re-execs, and the loader in the last image
  hooks but `start` never logs and the window shows the access gate; through Launch Services it
  starts normally. Under lldb, the debugger's `MallocNanoZone=0` makes the first image claim, so
  the re-exec runs without Sunbird.
- Still x86-only: badges, message JSON, optimistic delete and the message body recolor. `X86_CODE` in `runtime-desktop` keeps them from
  running on arm64. Handlers keep the desktop result ABI: 96 bytes, `Ok` is `u64::MAX - 1`,
  returned through `x8`.
