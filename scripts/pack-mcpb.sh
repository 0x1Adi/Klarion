#!/bin/sh
# Builds the MCP Bundle the MCP registry lists, plus the server.json that points
# at it: sh scripts/pack-mcpb.sh v1.2.3 [outdir]
#
# One bundle carries every platform. Neither the MCPB manifest nor server.json
# can express a CPU architecture, so all the binaries ship together and
# server/launch.sh picks one at run time.
set -eu

tag="${1:?usage: sh scripts/pack-mcpb.sh vX.Y.Z [outdir]}"
out="${2:-dist}"
version="${tag#v}"
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work="$out/mcpb-build"

rm -rf "$work"
mkdir -p "$work/server" "$out"

for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
	os=${target%/*}
	arch=${target#*/}
	name="klarion-$os-$arch"
	if [ "$os" = windows ]; then name="$name.exe"; fi
	echo "building $name"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
		-ldflags "-s -w -X main.version=$version" \
		-o "$work/server/$name" "$root/cmd/klarion"
done

cp "$root/mcpb/launch.sh" "$work/server/launch.sh"
cp "$root/LICENSE" "$root/README.md" "$work/"
sed "s/__VERSION__/$version/g" "$root/mcpb/manifest.json" > "$work/manifest.json"

bundle="$out/klarion-mcp-$tag.mcpb"
python3 - "$work" "$bundle" <<'PY'
import os, stat, sys, zipfile
src, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
    for dirpath, _, files in os.walk(src):
        for f in sorted(files):
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, src)
            info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = os.stat(full).st_mode
            # Everything under server/ ships executable: hosts may exec the
            # entry point directly, and launch.sh chmods the binaries as a
            # backstop for hosts that unzip without modes.
            if rel.startswith("server/"):
                mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            info.external_attr = (mode & 0xFFFF) << 16
            with open(full, "rb") as fh:
                z.writestr(info, fh.read())
print(dest)
PY

sha=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$bundle")
sed -e "s/__VERSION__/$version/g" -e "s/__SHA256__/$sha/" "$root/mcpb/server.json" > "$out/server.json"

echo "bundle:     $bundle ($(wc -c < "$bundle" | tr -d ' ') bytes)"
echo "sha256:     $sha"
echo "server.json: $out/server.json"
