#!/bin/sh
# macOS dev loop for Desktop Phoenix (mirrors scripts/dev.ps1).
#
#   ./scripts/dev-macos.sh                  build dev-fast, sign, install dylib, launch Sunbird
#   ./scripts/dev-macos.sh --release        build release instead of dev-fast
#   ./scripts/dev-macos.sh --no-runtime     launch with access gate only
#   ./scripts/dev-macos.sh --test           run host unit tests
#   ./scripts/dev-macos.sh --clippy         run clippy on macOS crates
#   ./scripts/dev-macos.sh --sigscan [args] run sigscan on Discord Phoenix (default: check)
#   ./scripts/dev-macos.sh --logs [secs]    show recent phoenix unified logs (default: 30s)
#   ./scripts/dev-macos.sh --eval "<js>"    evaluate JS in the running debug shell
set -eu

root=$(cd "$(dirname "$0")/.." && pwd -P)
home="$HOME/Library/Application Support/Sunbird"
data="$HOME/Library/Application Support/libdiscord/sunbird"
discord="/Applications/Discord Phoenix.app"
profile=dev-fast
gate_only=

case "${1:-}" in
   --test)
      cd "$root"
      exec cargo test -p phoenix-hook -p phoenix-sigs -p phoenix-ui-desktop -p phoenix-ui-mobile -p phoenix-wire -p phoenix-loader
      ;;
   --clippy)
      cd "$root"
      exec cargo clippy --no-deps -p phoenix-hook -p phoenix-sigs -p sigscan -p phoenix-ui-desktop -p stand-in --all-targets -- -D warnings
      ;;
   --sigscan)
      shift
      cd "$root"
      cargo build --profile dev-fast -p sigscan
      [ $# -gt 0 ] || set -- check
      exec "$root/target/dev-fast/sigscan" "$discord/Contents/MacOS/Discord" "$@"
      ;;
   --logs)
      window="${2:-30s}"
      exec /usr/bin/log show --last "$window" --style compact \
         --predicate 'process == "Discord" AND eventMessage CONTAINS "phoenix:"'
      ;;
   --eval)
      shift
      [ $# -gt 0 ] || { echo "usage: $0 --eval \"<js>\"" >&2; exit 1; }
      token=$(cat "$data/debug-shell-token" 2>/dev/null || true)
      [ -n "$token" ] || { echo "no debug-shell-token at $data/debug-shell-token" >&2; exit 1; }
      exec /usr/bin/curl -fsS -H "Authorization: Bearer $token" --data-binary "$1" http://127.0.0.1:4242/eval
      ;;
esac

while [ $# -gt 0 ]; do
   case "$1" in
      --release) profile=release ;;
      --no-runtime | --gate-only) gate_only=1 ;;
      *) echo "unknown option: $1" >&2; exit 1 ;;
   esac
   shift
done

cd "$root"
if [ "$profile" = release ]; then
   cargo build --release -p phoenix-loader
   built="$root/target/release/libphoenix.dylib"
else
   cargo build --profile dev-fast -p phoenix-loader
   built="$root/target/dev-fast/libphoenix.dylib"
fi

if [ ! -d /Applications/Sunbird.app ] && [ ! -d "$HOME/Applications/Sunbird.app" ]; then
   sh "$root/scripts/sunbird-macos.sh"
fi

mkdir -p "$home"
cp "$built" "$home/libphoenix.dylib"
/usr/bin/codesign --force --sign - "$home/libphoenix.dylib" >/dev/null
echo "local-$profile" >"$home/version"

pkill -f "Sunbird.app/Contents/MacOS/Discord" 2>/dev/null || true
sleep 1
if [ -n "$gate_only" ]; then
   exec /usr/bin/open -a "/Applications/Sunbird (access gate only).app"
else
   exec /usr/bin/open -a /Applications/Sunbird.app
fi
