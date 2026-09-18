#!/bin/sh
# Picks the binary for this machine. An MCP Bundle carries every platform in one
# file, and neither the manifest's platform_overrides (darwin/linux/win32) nor
# server.json can express a CPU architecture, so the choice happens here.
set -eu
d=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
case "$(uname -s)/$(uname -m)" in
	Darwin/arm64)              bin=klarion-darwin-arm64 ;;
	Darwin/*)                  bin=klarion-darwin-amd64 ;;
	Linux/aarch64|Linux/arm64) bin=klarion-linux-arm64 ;;
	Linux/*)                   bin=klarion-linux-amd64 ;;
	*) echo "klarion: no bundled binary for $(uname -s)/$(uname -m)" >&2; exit 2 ;;
esac
# A host that unpacks the bundle without preserving the executable bit would
# otherwise leave every binary unrunnable.
[ -x "$d/$bin" ] || chmod +x "$d/$bin" 2>/dev/null || true
exec "$d/$bin" "$@"
