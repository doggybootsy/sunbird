#!/bin/sh
# Installs Sunbird for Desktop Phoenix on macOS: a Sunbird app in
# /Applications (~/Applications for accounts that can't write there) that starts a re-signed copy of Discord Phoenix with the
# loader inserted. Discord's own app stays untouched, so its updates never undo
# Sunbird, and the copy is rebuilt whenever Discord changes.
#
#   curl -fsSL https://assets.sunbird.tools/plugins/sunbird-macos.sh | sh
#   curl -fsSL https://assets.sunbird.tools/plugins/sunbird-macos.sh | sh -s -- "/path/to/Discord Phoenix.app"
#   curl -fsSL https://assets.sunbird.tools/plugins/sunbird-macos.sh | sh -s -- --no-runtime
#   curl -fsSL https://assets.sunbird.tools/plugins/sunbird-macos.sh | sh -s -- --uninstall
#
# SUNBIRD_SITE points it at a local server for testing.
#
# Phoenix is signed with the hardened runtime, which ignores
# DYLD_INSERT_LIBRARIES and refuses libraries Discord did not sign. The copy is
# signed ad hoc without it. Its restricted entitlements (keychain and app
# groups) can't come along, so the copy may ask you to log in once.
set -eu

site=${SUNBIRD_SITE:-https://assets.sunbird.tools}
home="$HOME/Library/Application Support/Sunbird"
# /Applications is writable by admin accounts only.
if [ -w /Applications ]; then
   apps=/Applications
else
   apps="$HOME/Applications"
fi
app="$apps/Sunbird.app"
gate_app="$apps/Sunbird (access gate only).app"
bundle_id=com.discord.DesktopGpui

if [ "${1:-}" = --uninstall ]; then
   rm -rf "$home" \
      /Applications/Sunbird.app "$HOME/Applications/Sunbird.app" \
      "/Applications/Sunbird (access gate only).app" "$HOME/Applications/Sunbird (access gate only).app"
   echo "Sunbird is uninstalled. Discord itself was not changed."
   exit 0
fi

# Opens the access gate only, without plugins.
no_runtime=
while [ "${1:-}" = --no-runtime ] || [ "${1:-}" = --gate-only ]; do
   no_runtime=1
   shift
done

if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
   echo "Discord Phoenix for macOS runs on Apple silicon only." >&2
   exit 1
fi

# What the site serves is loaded into Discord, so only https, or plain http to
# this machine for testing.
case $site in
   https://*) proto==https ;;
   http://127.0.0.1 | http://127.0.0.1[:/]* | http://localhost | http://localhost[:/]*) proto==http ;;
   *)
      echo "SUNBIRD_SITE must be https:// or a localhost server, not $site" >&2
      exit 1
      ;;
esac

# DYLD_INSERT_LIBRARIES splits on colons, and the launcher quotes the rest.
case $home in
   *[:\"\$\`\\\']*)
      echo "Sunbird can't be installed under $home: it has a colon or quote." >&2
      exit 1
      ;;
esac

is_phoenix() {
   [ -f "$1/Contents/Info.plist" ] &&
      [ "$(/usr/bin/plutil -extract CFBundleIdentifier raw "$1/Contents/Info.plist" 2>/dev/null)" = $bundle_id ]
}

script="curl -fsSL $site/plugins/sunbird-macos.sh | sh -s --"
discord=${1:-}
if [ -n "$discord" ] && ! is_phoenix "$discord"; then
   echo "$discord is not Discord Phoenix. Pass the path of Discord Phoenix's app:" >&2
   echo "  $script \"/Applications/Discord Phoenix.app\"" >&2
   exit 1
fi
if [ -z "$discord" ]; then
   for candidate in "/Applications/Discord Phoenix.app" "$HOME/Applications/Discord Phoenix.app"; do
      if is_phoenix "$candidate"; then
         discord=$candidate
         break
      fi
   done
fi
if [ -z "$discord" ]; then
   # Spotlight finds it wherever it was moved or renamed.
   discord=$(/usr/bin/mdfind "kMDItemCFBundleIdentifier == '$bundle_id'" 2>/dev/null |
      while read -r found; do
         # Not Sunbird's own copy.
         [ "${found#"$home"/}" = "$found" ] || continue
         if is_phoenix "$found"; then
            echo "$found"
            break
         fi
      done)
fi
if [ -z "$discord" ]; then
   cat >&2 <<EOF
Couldn't find Discord Phoenix in /Applications, ~/Applications or Spotlight.

Install Discord Phoenix, then run this again, with its path if it lives
somewhere else:
  $script "/path/to/Discord Phoenix.app"
EOF
   exit 1
fi
discord=$(cd "$discord" && pwd -P)
echo "Using Discord Phoenix at $discord"

# Single-quotes a value for the generated launcher.
q() { printf "'%s'" "$(printf %s "$1" | sed "s/'/'\\\\''/g")"; }

# An earlier install may have used the other folder.
for other_dir in /Applications "$HOME/Applications"; do
   [ "$other_dir" = "$apps" ] || rm -rf "$other_dir/Sunbird.app" "$other_dir/Sunbird (access gate only).app"
done
mkdir -p "$home" "$app/Contents/MacOS" "$app/Contents/Resources" \
   "$gate_app/Contents/MacOS" "$gate_app/Contents/Resources"

# The launcher brings the loader up to the site's version and the copy up to
# Discord's before each start, and keeps what it has when offline. Each run
# downloads and copies to its own name, so two starts at once never use a
# half-written file.
cat >"$app/Contents/MacOS/sunbird" <<EOF
#!/bin/sh
home=$(q "$home")
site=$(q "$site")
discord=$(q "$discord")
copy="\$home/Sunbird.app"
gate_only=$no_runtime
# Bumped when the copy's Info.plist changes, so existing copies are rebuilt.
brand=2
fetch() { /usr/bin/curl -fsSL --proto $proto --proto-redir =https "\$@" 2>/dev/null; }
fail() {
   /usr/bin/osascript -e 'on run argv' -e 'display alert "Sunbird" message (item 1 of argv)' \\
      -e 'end run' -- "\$1" >/dev/null 2>&1
   echo "\$1" >&2
   exit 1
}

# A \`pin\` file keeps the loader in place, for a build installed by hand.
version=
[ -f "\$home/pin" ] || version=\$(fetch --max-time 5 "\$site/version.json" |
   sed -n 's/.*"loader": *"\([^"]*\)".*/\1/p')
if [ -n "\$version" ] && [ "\$version" != "\$(cat "\$home/version" 2>/dev/null)" ]; then
   tmp=\$(mktemp "\$home/libphoenix.dylib.XXXXXX")
   if fetch --max-time 60 -o "\$tmp" "\$site/plugins/libphoenix-macos-arm64.dylib" &&
      /usr/bin/file -b "\$tmp" 2>/dev/null | grep -q 'Mach-O 64-bit dynamically linked shared library arm64' &&
      LC_ALL=C /usr/bin/grep -q 'phoenix-version:' "\$tmp" &&
      (/usr/bin/codesign -v "\$tmp" >/dev/null 2>&1 || /usr/bin/codesign --force --sign - "\$tmp" >/dev/null 2>&1); then
      mv "\$tmp" "\$home/libphoenix.dylib"
      echo "\$version" >"\$home/version"
   else
      rm -f "\$tmp"
   fi
fi
[ "\${1:-}" = --update ] && exit 0
while [ "\${1:-}" = --no-runtime ] || [ "\${1:-}" = --gate-only ]; do
   gate_only=1
   shift
done
[ -d "\$discord" ] || fail "Discord Phoenix is gone from \$discord. Run the Sunbird installer again."

stamp="\$(/usr/bin/stat -f '%m %z' "\$discord/Contents/MacOS/Discord") brand \$brand"
needs_rebuild=
if [ "\$stamp" != "\$(cat "\$home/stamp" 2>/dev/null)" ] ||
   ! /usr/bin/codesign -dv "\$copy" 2>&1 | grep -q 'Signature=adhoc'; then
   needs_rebuild=1
fi

ask() {
   /usr/bin/osascript -e 'on run argv' \\
      -e 'display dialog (item 1 of argv) with title "Sunbird" buttons {"Cancel", "Restart"} default button "Restart"' \\
      -e 'end run' -- "\$1" >/dev/null 2>&1
}

# check running instances before rebuilding so we don't swap the bundle under a live process
pids= sunbird= running_gate=
for pid in \$(/bin/ps -axo pid=,comm= | /usr/bin/awk \\
   -v phoenix="\$discord/Contents/MacOS/Discord" -v copy="\$copy/Contents/MacOS/Discord" \\
   '{ pid = \$1; sub(/^ *[0-9]+ /, ""); if (\$0 == phoenix || \$0 == copy) print pid }'); do
   pids="\$pids \$pid"
   /usr/sbin/lsof -p "\$pid" 2>/dev/null | grep -q libphoenix && sunbird=1
   /bin/ps eww -p "\$pid" 2>/dev/null | grep -q 'SUNBIRD_GATE_ONLY=1' && running_gate=1
done

if [ -n "\$pids" ]; then
   prompt=
   if [ -z "\$sunbird" ]; then
      if [ -n "\$gate_only" ]; then
         prompt="Discord is already running without Sunbird. Restart it with the access gate only? A call you are in will end."
      else
         prompt="Discord is already running without Sunbird. Restart it with Sunbird? A call you are in will end."
      fi
   elif [ -n "\$gate_only" ] && [ -z "\$running_gate" ]; then
      prompt="Discord is already running with plugins. Restart it without the Sunbird plugin runtime? A call you are in will end."
   elif [ -z "\$gate_only" ] && [ -n "\$running_gate" ]; then
      prompt="Discord is running in access gate only mode. Restart it with the full Sunbird runtime? A call you are in will end."
   elif [ -n "\$needs_rebuild" ]; then
      prompt="Discord Phoenix was updated. Restart Sunbird to apply the update? A call you are in will end."
   fi
   if [ -n "\$prompt" ]; then
      ask "\$prompt" || exit 0
      kill \$pids 2>/dev/null
      for _ in 1 2 3 4 5 6 7 8 9 10; do
         alive=
         for pid in \$pids; do kill -0 "\$pid" 2>/dev/null && alive=1; done
         [ -z "\$alive" ] && break
         sleep 0.5
      done
   else
      exec /usr/bin/open -a "\$copy" --args "\$@"
   fi
fi

# Rebuilt when Discord's executable changed, or when the copy lost its ad hoc
# signature, which Discord's updater would put back.
if [ -n "\$needs_rebuild" ]; then
   tmp=\$(mktemp -d "\$home/Sunbird.XXXXXX")
   new="\$tmp/Sunbird.app"
   # A clone on APFS, so the copy takes no space until Discord updates.
   if ! /bin/cp -cR "\$discord" "\$new" 2>/dev/null; then
      /usr/bin/ditto "\$discord" "\$new" || { rm -rf "\$tmp"; fail "Couldn't copy Discord Phoenix."; }
   fi
   /usr/bin/xattr -cr "\$new"
   # Named and drawn as Sunbird in the Dock, the app switcher and the menu
   # bar. The bundle id stays Discord's, which its data and login go by. The
   # asset catalog's icon outranks CFBundleIconFile, so its name goes.
   plist="\$new/Contents/Info.plist"
   /usr/bin/plutil -replace CFBundleName -string Sunbird "\$plist"
   /usr/bin/plutil -replace CFBundleDisplayName -string Sunbird "\$plist"
   if [ -f "\$home/Sunbird.icns" ]; then
      cp "\$home/Sunbird.icns" "\$new/Contents/Resources/Sunbird.icns"
      /usr/bin/plutil -remove CFBundleIconName "\$plist" 2>/dev/null || true
      /usr/bin/plutil -replace CFBundleIconFile -string Sunbird "\$plist"
   fi
   # Discord relaunches itself through Launch Services (Command-R, updates)
   # with its own environment, which the loader has taken itself out of. The
   # copy's LSEnvironment puts it back for every start, the Dock's included.
   /usr/bin/plutil -replace LSEnvironment.DYLD_INSERT_LIBRARIES \\
      -string "\$home/libphoenix.dylib" "\$plist"
   # Ad hoc, without the hardened runtime or Discord's entitlements; the
   # helpers and frameworks inside keep Discord's own signatures.
   if ! /usr/bin/codesign --force --sign - "\$new" >/dev/null 2>&1; then
      rm -rf "\$tmp"
      fail "Couldn't sign the copy of Discord Phoenix."
   fi
   rm -rf "\$copy" "\$home/Discord.app"
   mv "\$new" "\$copy"
   rmdir "\$tmp"
   echo "\$stamp" >"\$home/stamp"
   # The Dock and Finder cache icons by path until told the bundle changed.
   /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "\$copy" 2>/dev/null || true
fi

[ -f "\$home/libphoenix.dylib" ] ||
   fail "Sunbird hasn't been downloaded yet. Check your connection and open Sunbird again."

set -- --env "DYLD_INSERT_LIBRARIES=\$home/libphoenix.dylib" --args "\$@"
[ -n "\$gate_only" ] && set -- --env SUNBIRD_GATE_ONLY=1 "\$@"
exec /usr/bin/open -a "\$copy" "\$@"
EOF
chmod +x "$app/Contents/MacOS/sunbird"

# Sunbird's mark, the dashboard's sun, drawn with AppKit so no image ships.
make_icon() {
   work=$(mktemp -d)
   /usr/bin/osascript -l JavaScript - "$work/icon.png" >/dev/null 2>&1 <<'JS' || { rm -rf "$work"; return 1; }
function run(argv) {
   ObjC.import('AppKit');
   const size = 1024, center = size / 2, unit = (size / 32) * 0.86;
   const rep = $.NSBitmapImageRep.alloc.initWithBitmapDataPlanesPixelsWidePixelsHighBitsPerSampleSamplesPerPixelHasAlphaIsPlanarColorSpaceNameBytesPerRowBitsPerPixel(
      null, size, size, 8, 4, true, false, $.NSDeviceRGBColorSpace, 0, 0);
   $.NSGraphicsContext.saveGraphicsState;
   $.NSGraphicsContext.setCurrentContext($.NSGraphicsContext.graphicsContextWithBitmapImageRep(rep));
   [[14, 0x1e1f22], [12, 0xf59e0b], [5, 0xfff3b0]].forEach(([r, rgb]) => {
      $.NSColor.colorWithSRGBRedGreenBlueAlpha((rgb >> 16 & 255) / 255, (rgb >> 8 & 255) / 255, (rgb & 255) / 255, 1).setFill;
      $.NSBezierPath.bezierPathWithOvalInRect($.NSMakeRect(center - r * unit, center - r * unit, 2 * r * unit, 2 * r * unit)).fill;
   });
   $.NSGraphicsContext.restoreGraphicsState;
   rep.representationUsingTypeProperties($.NSBitmapImageFileTypePNG, $()).writeToFileAtomically(argv[0], true);
}
JS
   mkdir "$work/Sunbird.iconset"
   for size in 16 32 128 256 512; do
      /usr/bin/sips -z $size $size "$work/icon.png" --out "$work/Sunbird.iconset/icon_${size}x${size}.png" >/dev/null &&
         /usr/bin/sips -z $((size * 2)) $((size * 2)) "$work/icon.png" \
            --out "$work/Sunbird.iconset/icon_${size}x${size}@2x.png" >/dev/null || { rm -rf "$work"; return 1; }
   done
   /usr/bin/iconutil -c icns "$work/Sunbird.iconset" -o "$1"
   status=$?
   rm -rf "$work"
   return $status
}
if make_icon "$home/Sunbird.icns"; then
   cp "$home/Sunbird.icns" "$app/Contents/Resources/Sunbird.icns"
   cp "$home/Sunbird.icns" "$gate_app/Contents/Resources/Sunbird.icns"
else
   echo "Couldn't draw Sunbird's icon; it keeps a plain one." >&2
fi
cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
   <key>CFBundleExecutable</key><string>sunbird</string>
   <key>CFBundleIdentifier</key><string>tools.sunbird.launcher</string>
   <key>CFBundleName</key><string>Sunbird</string>
   <key>CFBundleDisplayName</key><string>Sunbird</string>
   <key>CFBundleIconFile</key><string>Sunbird</string>
   <key>CFBundlePackageType</key><string>APPL</string>
   <key>CFBundleShortVersionString</key><string>1.0</string>
   <key>LSMinimumSystemVersion</key><string>13.0</string>
   <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
# For when the plugin runtime crashes on a Discord build it doesn't know yet.
cat >"$gate_app/Contents/MacOS/sunbird-gate-only" <<EOF
#!/bin/sh
exec $(q "$app/Contents/MacOS/sunbird") --no-runtime "\$@"
EOF
chmod +x "$gate_app/Contents/MacOS/sunbird-gate-only"
cat >"$gate_app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
   <key>CFBundleExecutable</key><string>sunbird-gate-only</string>
   <key>CFBundleIdentifier</key><string>tools.sunbird.launcher.gate-only</string>
   <key>CFBundleName</key><string>Sunbird (access gate only)</string>
   <key>CFBundleDisplayName</key><string>Sunbird (access gate only)</string>
   <key>CFBundleIconFile</key><string>Sunbird</string>
   <key>CFBundlePackageType</key><string>APPL</string>
   <key>CFBundleShortVersionString</key><string>1.0</string>
   <key>LSMinimumSystemVersion</key><string>13.0</string>
   <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
/usr/bin/codesign --force --sign - "$app" >/dev/null 2>&1 || true
/usr/bin/codesign --force --sign - "$gate_app" >/dev/null 2>&1 || true
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$app" 2>/dev/null || true
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$gate_app" 2>/dev/null || true

# First download now, so a missing network shows up here rather than as a
# Discord without Sunbird.
echo "Downloading Sunbird..."
rm -f "$home/version"
"$app/Contents/MacOS/sunbird" --update
if [ -f "$home/libphoenix.dylib" ]; then
   echo "Sunbird is installed at $app. Quit Discord, then open Sunbird from there or Spotlight."
else
   echo "Installed, but downloading Sunbird failed. It will retry each time you open it." >&2
fi
echo "It runs a copy of Discord Phoenix from $discord: if you move that app, run this again."
